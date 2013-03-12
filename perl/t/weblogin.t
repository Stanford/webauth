#!/usr/bin/perl -w
#
# Tests for weblogin page handling after login responses.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2010, 2012, 2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

# Ensure we don't pick up the system webkdc.conf.
BEGIN { $ENV{WEBKDC_CONFIG} = '/nonexistent' }

use lib ('t/lib', 'lib', 'blib/arch');
use Util qw (contents get_userinfo getcreds create_keyring);

use CGI;
use CGI::Cookie;
use File::Path qw (rmtree);
use Test::More;
use WebAuth qw(3.00 :const);
use WebKDC ();
use WebKDC::Config;
use WebLogin;

mkdir ('./t/tmp');

# Override the WebKDC package in order to put in our own version of a function
# for testing.
our ($TEST_STATUS, $TEST_ERROR);
package WebKDC;
no warnings 'redefine';
sub make_request_token_request {
    return ($TEST_STATUS, $TEST_ERROR);
}
use warnings 'redefine';
package main;

# Add some configuration subs for testing purposes.
our $USE_AUTHENTICATE;
package WebKDC::Config;
sub authenticate {
    return unless $main::USE_AUTHENTICATE;
    return ('authtest', 'p', 'k', 2);
}
sub remuser_factors ($) {
    return ('o1', 'c', 1);
}
package main;

# Whether we've found a valid kerberos config.
my $kerberos_config = 0;

# Check for a valid kerberos config.
if (! -f 't/data/test.principal' || ! -f 't/data/test.password'
    || ! -f 't/data/test.keytab' || ! -d 't/data/templates') {
    plan skip_all => 'Kerberos tests not configured';
} else {
    plan tests => 391;
}

# Set our method to not have password tests complain.
$ENV{REQUEST_METHOD} = 'POST';

#############################################################################
# Wrapper functions
#############################################################################

# Initialize the weblogin object, as we'll have to keep touching this over
# and again.
sub init_weblogin {
    my ($username, $password, $st_base64, $rt_base64, $pages) = @_;

    my $query = CGI->new ({});
    $query->request_method ('POST');
    $query->param ('username', $username);
    $query->param ('password', $password);
    $query->param ('ST', $st_base64);
    $query->param ('RT', $rt_base64);

    $WebKDC::Config::TEMPLATE_PATH         = 't/data/templates';
    $WebKDC::Config::TEMPLATE_COMPILE_PATH = 't/tmp/ttc';

    my $weblogin = WebLogin->new (QUERY  => $query,
                                  PARAMS => { pages => $pages });
    $weblogin->cgiapp_prerun;
    $weblogin->param ('debug', 0);
    $weblogin->param ('logging', 0);
    $weblogin->param ('script_name', '/login');

    # Normally set during WebKDC::request_token_request.
    $weblogin->{response}->return_url ('https://test.example.org/');
    $weblogin->{response}->subject ($username);
    $weblogin->{response}->requester_subject ('webauth/test3.testrealm.org@testrealm.org');
    $weblogin->{response}->response_token ('TestResponse');
    $weblogin->{response}->response_token_type ('id');

    # Set the password expiration time depending on the user.
    if ($username eq 'testuser1') {
        # Expires in-range for a warning.
        $weblogin->{response}->password_expiration (time + 60 * 60 * 24);
    } elsif ($username eq 'testuser2') {
        # Expires out of range for a warning.
        $weblogin->{response}->password_expiration (time +
                                                    60 * 60 * 24 * 356);
    } elsif ($username eq 'testuser3') {
        # Do nothing here, we want non-existing pw expiration.
    } else {
        # Expires in-range for a warning..
        $weblogin->{response}->password_expiration (time + 60 * 60 * 24);
    }

    return $weblogin;
}

# Wrapper around WebLogin::index to grab the page output into a string and
# return that output.  To make all the index runmode tests look cleaner.
sub index_wrapper {
    my ($weblogin, $status, $error) = @_;

    $TEST_STATUS = $status;
    $TEST_ERROR = $error;
    my $page = $weblogin->index;
    return split (/[\r\n]+/, $$page);
}

#############################################################################
# Environment setup
#############################################################################

# Get the username and password to log in with.
my $fname_passwd = 't/data/test.password';
my ($user, $pass) = get_userinfo ($fname_passwd) if -f $fname_passwd;

# Miscellaneous config settings.
$WebKDC::Config::EXPIRING_PW_URL = '/pwchange';
$WebKDC::Config::EXPIRING_PW_WARNING = 60 * 60 * 24 * 7;
$WebKDC::Config::EXPIRING_PW_RESEND_PASSWORD = 0;
$WebKDC::Config::REMUSER_REDIRECT = 0;
@WebKDC::Config::REMUSER_LOCAL_REALMS = ();
@WebKDC::Config::REMUSER_PERMITTED_REALMS = ();
$WebKDC::Config::BYPASS_CONFIRM = '';

# Disable all the memcached stuff for now.
@WebKDC::Config::MEMCACHED_SERVERS = ();

# If the username is fully qualified, set a default realm.
if ($user =~ /\@(\S+)/) {
    $WebKDC::Config::DEFAULT_REALM = $1;
    @WebKDC::Config::REMUSER_PERMITTED_REALMS = ($1);
    @WebKDC::Config::REMUSER_LOCAL_REALMS = ($1);
}

# Load a version of the page templates that just prints out the vars sent.
my %PAGES = (pwchange => 'pwchange.tmpl',
             login    => 'login.tmpl',
             confirm  => 'confirm.tmpl',
             error    => 'error.tmpl');

# Set up various ENV variables later used for logging.
$ENV{SERVER_ADDR} = 'localhost';
$ENV{SERVER_PORT} = '443';
$ENV{REMOTE_ADDR} = '127.0.0.1';
$ENV{REMOTE_PORT} = '443';
$ENV{REMOTE_USER} = $user;
$ENV{SCRIPT_NAME} = '/login';

# Create a keyring to test with.
my $wa = WebAuth->new;
unlink ('t/data/test.keyring', 'krb5cc_test');
$WebKDC::Config::KEYRING_PATH = 't/data/test.keyring';
create_keyring ($WebKDC::Config::KEYRING_PATH);
my $keyring = $wa->keyring_read ($WebKDC::Config::KEYRING_PATH);

# Create the ST for testing.
my $principal = contents ('t/data/test.principal');
my $random = 'b' x WebAuth::WA_AES_128;
my $st = WebAuth::Token::WebKDCService->new ($wa);
$st->subject ("krb5:$principal");
$st->session_key ($random);
$st->creation (time);
$st->expiration (time + 3600);
my $st_base64 = $st->encode ($keyring);

# Create the RT for testing.
my $key = $wa->key_create (WebAuth::WA_KEY_AES, WebAuth::WA_AES_128, $random);
my $client_keyring = $wa->keyring_new ($key);
my $rt = WebAuth::Token::Request->new ($wa);
$rt->type ('id');
$rt->auth ('webkdc');
$rt->return_url ('https://test.example.org/');
$rt->creation (time);
my $rt_base64 = $st->encode ($client_keyring);

#############################################################################
# Tests
#############################################################################

# Create the weblogin object and make sure it looks as it should.
my $weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
ok ($weblogin, 'getting Weblogin object works');
is ($weblogin->param ('debug'), 0, ' and debug is not set');
is ($weblogin->param ('logging'), 0, ' and logging is not set');
ok (defined $weblogin->{request}, ' and we got a WebRequest');
ok (defined $weblogin->{response}, ' and we got a WebResponse');

# Set up the KDC request and test that things were set up correctly.
my ($status, $error);
$status = $weblogin->setup_kdc_request;
ok (!$status, 'setup_kdc_request works');
is ($weblogin->{request}->user, $user, ' and username set');
is ($weblogin->{request}->pass, $pass, ' and password set');
is ($weblogin->{request}->local_ip_addr, $ENV{SERVER_ADDR},
   ' and SERVER_ADDR set');
is ($weblogin->{request}->local_ip_port, $ENV{SERVER_PORT},
   ' and SERVER_PORT set');
is ($weblogin->{request}->remote_ip_addr, $ENV{REMOTE_ADDR},
   ' and REMOTE_ADDR set');
is ($weblogin->{request}->remote_ip_port, $ENV{REMOTE_PORT},
   ' and REMOTE_PORT set');
is ($weblogin->{request}->remote_user, $ENV{REMOTE_USER},
   ' and REMOTE_USER set');

# Success with user having a pending password change.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
($status, $error) = (WebKDC::WK_SUCCESS, '');
my @output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'success page with pending password expiration was printed');
is ($output[0], "username $user", ' and username was set');
is ($output[1],
    'return_url https://test.example.org/?WEBAUTHR=TestResponse;',
    ' and return_url was set');
is ($output[2], 'pretty_return_url https://test.example.org',
    ' and pretty_return_url was set');
is ($output[3], 'login_cancel ', ' and login_cancel was not set');
is ($output[4], 'cancel_url ', ' and cancel_url was not set');
is ($output[5], 'show_remuser ', ' and show_remuser was not set');
is ($output[6], 'remuser ', ' and remuser was not set');
is ($output[7], 'script_name ', ' and script name was not set');

is ($output[8], 'warn_expire 1', ' and warn_expire was set');
ok ($output[9] =~ /^expire_timestamp \S+/, ' and expire_timestamp was set');
is ($output[10], 'pwchange_url /pwchange', ' and pwchange_url was set');
ok ($output[11] =~ /^CPT \S+/, ' and CPT was set');
is ($output[12], 'public_computer ', ' and public_computer was not set');
is ($output[13], 'device_expiring ', ' and device_expiring was not set');

# Success with no password expiration time.
$weblogin = init_weblogin ('testuser3', $pass, $st_base64, $rt_base64,
                           \%PAGES);
($status, $error) = (WebKDC::WK_SUCCESS, '');
@output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'success page was printed');
is ($output[0], "username testuser3", ' and username was set');
is ($output[1],
    'return_url https://test.example.org/?WEBAUTHR=TestResponse;',
    ' and return_url was set');
is ($output[2], 'pretty_return_url https://test.example.org',
    ' and pretty_return_url was set');
is ($output[3], 'login_cancel ', ' and login_cancel was not set');
is ($output[4], 'cancel_url ', ' and cancel_url was not set');
is ($output[5], 'show_remuser ', ' and show_remuser was not set');
is ($output[6], 'remuser ', ' and remuser was not set');
is ($output[7], 'script_name ', ' and script name was not set');
is ($output[8], 'warn_expire ', ' and warn_expire was not set');
is ($output[9], 'expire_timestamp ', ' and expire_timestamp was not set');
is ($output[10], 'pwchange_url ', ' and pwchange_url was not set');
is ($output[11], 'CPT ', ' and CPT was not set');
is ($output[12], 'public_computer ', ' and public_computer was not set');
is ($output[13], 'device_expiring ', ' and device_expiring was not set');

# FIXME: Testing remuser requires us to fake a cookie, which we'll do in
#        a later revision.
# Successful password, with showing the checkbox for REMOTE_USER.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
$WebKDC::Config::REMUSER_REDIRECT = '/login-spnego';
$ENV{REMOTE_USER} = $user;
($status, $error) = (WebKDC::WK_SUCCESS, '');
@output = index_wrapper ($weblogin, $status, $error);
$WebKDC::Config::REMUSER_REDIRECT = '';
ok (@output, 'success page with remuser redirect checkbox was printed');
is ($output[0], "username $user", ' and username was set');
is ($output[1],
    'return_url https://test.example.org/?WEBAUTHR=TestResponse;',
    ' and return_url was set');
is ($output[2], 'pretty_return_url https://test.example.org',
    ' and pretty_return_url was set');
is ($output[3], 'login_cancel ', ' and login_cancel was set');
is ($output[4], 'cancel_url ', ' and cancel_url was set');
is ($output[5], 'show_remuser 1', ' and show_remuser was set');
is ($output[6], 'remuser ', ' and remuser was set');
is ($output[7], 'script_name /login', ' and script name was set');
is ($output[8], 'warn_expire 1', ' and warn_expire was set');
ok ($output[9] =~ /^expire_timestamp \S+/, ' and expire_timestamp was set');
is ($output[10], 'pwchange_url /pwchange', ' and pwchange_url was set');
ok ($output[11] =~ /^CPT \S+/, ' and CPT was set');
is ($output[12], 'public_computer ', ' and public_computer was not set');
is ($output[13], 'device_expiring ', ' and device_expiring was not set');

# Bad return URL (set it to be http rather than https).
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
$weblogin->{response}->return_url ('test.example.org/');
($status, $error) = (WebKDC::WK_SUCCESS, '');
@output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'error page for bad return URL');
is ($output[0], 'err_bad_method ', ' and err_bad_method was not set');
is ($output[1], 'err_cookies_disabled ',
    ' and err_cookies_disabled was not set');
is ($output[2], 'err_no_request_token ',
    ' and err_no_request_token was not set');
is ($output[3], 'err_webkdc 1', ' and err_webkdc was set');
is ($output[4], 'err_msg there is most likely a configuration problem '
    .'with the server that redirected you. Please contact its '
    .'administrator.', ' with correct error message');
is ($output[5], 'err_confirm ', ' and err_confirm was not set');
is ($output[6], 'script_name ', ' and script_name was not set');

# Expired password.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
($status, $error) = (WebKDC::WK_ERR_CREDS_EXPIRED, '');
@output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'success page with remuser redirect checkbox was printed');
is ($output[0], 'error ', ' and error was not set');
is ($output[1], 'err_username ', ' and err_username was not set');
is ($output[2], 'err_password ', ' and err_password was not set');
is ($output[3], 'err_newpassword ', ' and err_newpassword was not set');
is ($output[4], 'err_newpassword_match ',
    ' and err_newpassword_match was not set');
is ($output[5], 'err_loginfailed ', ' and err_loginfailed was not set');
is ($output[6], 'err_rejected ', ' and err_rejected was not set');
is ($output[7], 'err_pwweak ', ' and err_pwweak was not set');
is ($output[8], 'err_pwchange ', ' and err_pwchange was not set');
is ($output[9], 'err_msg ', ' and err_msg was not set');
ok ($output[10] =~ /RT \S+/, ' and RT was set');
ok ($output[11] =~ /ST \S+/, ' and ST was set');
ok ($output[12] =~ /CPT \S+/, ' and CPT was set');
is ($output[13], "username $user", ' and username was set');
is ($output[14], 'password ', ' and password was not set');
is ($output[15], 'new_passwd1 ', ' and new_passwd1 was not set');
is ($output[16], 'new_passwd2 ', ' and new_passwd2 was not set');
is ($output[17], 'changepw ', ' and changepw was not set');
is ($output[18], 'expired 1', ' and expired was set');
is ($output[19], 'skip_username 1', ' and skip_username was set');
is ($output[20], 'skip_password 1', ' and skip_password was set');
is ($output[21], 'script_name /pwchange', ' and script_name was set');

# FIXME: Requires us to fake cookies, which we'll do in a later pass.
# Other authentication methods can be used, REMOTE_USER support is
# requested by cookie, we're not already at the REMOTE_USER-authenticated
# URL, and we're not an error handler (meaning that we haven't tried
# REMOTE_USER and failed).  Redirect to the REMOTE_USER URL.
#($status, $error) = (WebKDC::WK_ERR_USER_AND_PASS_REQUIRED, '');
#$ENV{REMOTE_USER} = '';
#$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
#$weblogin->query->cookie ($self->{remuser_cookie}, 'foo');
#$weblogin->param ('is_error', 0);
#$weblogin->query->param ('login', 0);
#$WebKDC::Config::REMUSER_REDIRECT = 'https://test.example.org/login';
#@output = index_wrapper ($weblogin, $status, $error);
# Check print_remuser_redirect.

# The user didn't already ask for REMOTE_USER.  However, we just need
# authentication (not forced login) and we haven't already tried
# REMOTE_USER and failed, so give them the login screen with the choice.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
($status, $error) = (WebKDC::WK_ERR_USER_AND_PASS_REQUIRED, '');
$weblogin->param ('is_error', 0);
$WebKDC::Config::REMUSER_REDIRECT = 'https://test.example.org/login';
@output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'login page with choice for REMOTE_USER');
is ($output[0], 'error ', ' and error was not set');
is ($output[1], 'err_missinginput ', ' and err_missinginput was not set');
is ($output[2], 'err_username ', ' and err_username was not set');
is ($output[3], 'err_password ', ' and err_password was not set');
is ($output[4], 'err_loginfailed ', ' and err_loginfailed was not set');
is ($output[5], 'err_forced ', ' and err_forced was not set');
is ($output[6], 'err_rejected ', ' and err_rejected was not set');
ok ($output[7] =~ /RT \S+/, ' and RT was set');
ok ($output[8] =~ /ST \S+/, ' and ST was set');
is ($output[9], 'LC ', ' and LC was not set');
is ($output[10], "username $user", ' and username was set');
is ($output[11], 'login_cancel ', ' and login_cancel was not set');
is ($output[12], 'cancel_url ', ' and cancel_url was not set');
is ($output[13], 'show_remuser 1', ' and show_remuser was set');
is ($output[14], 'remuser_url https://test.example.org/login',
    ' and remuser_url was set');
is ($output[15], 'remuser_failed ', ' and remuser_failed was not set');
is ($output[16], 'script_name /login', ' and script_name was set');

# Test failed login with remuser_redirect set, and the flag that shows
# we were called as an error handler set.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
($status, $error) = (WebKDC::WK_ERR_USER_AND_PASS_REQUIRED, '');
$WebKDC::Config::REMUSER_REDIRECT = 'https://test.example.org/login';
$weblogin->param ('is_error', 1);
@output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'login page with WK_ERR_USER_AND_PASS_REQUIRED, '
    .'REMUSER_REDIRECT set, as error handler');
is ($output[0], 'error ', ' and error was not set');
is ($output[1], 'err_missinginput ', ' and err_missinginput was not set');
is ($output[2], 'err_username ', ' and err_username was not set');
is ($output[3], 'err_password ', ' and err_password was not set');
is ($output[4], 'err_loginfailed ', ' and err_loginfailed was not set');
is ($output[5], 'err_forced ', ' and err_forced was not set');
is ($output[6], 'err_rejected ', ' and err_rejected was not set');
ok ($output[7] =~ /RT \S+/, ' and RT was set');
ok ($output[8] =~ /ST \S+/, ' and ST was set');
is ($output[9], 'LC ', ' and LC was not set');
is ($output[10], "username $user", ' and username was set');
is ($output[11], 'login_cancel ', ' and login_cancel was not set');
is ($output[12], 'cancel_url ', ' and cancel_url was not set');
is ($output[13], 'show_remuser ', ' and show_remuser was not set');
is ($output[14], 'remuser_url ', ' and remuser_url was not set');
is ($output[15], 'remuser_failed 1', ' and remuser_failed was set');
is ($output[16], 'script_name /login', ' and script_name was set');

# Test failed login with remuser_redirect set, and the flag that shows
# we were called as an error handler not set.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
($status, $error) = (WebKDC::WK_ERR_USER_AND_PASS_REQUIRED, '');
$WebKDC::Config::REMUSER_REDIRECT = 'https://test.example.org/login';
$weblogin->param ('is_error', 0);
@output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'login page with WK_ERR_USER_AND_PASS_REQUIRED, '
    .'REMUSER_REDIRECT set, not as error handler');
is ($output[0], 'error ', ' and error was not set');
is ($output[1], 'err_missinginput ', ' and err_missinginput was not set');
is ($output[2], 'err_username ', ' and err_username was not set');
is ($output[3], 'err_password ', ' and err_password was not set');
is ($output[4], 'err_loginfailed ', ' and err_loginfailed was not set');
is ($output[5], 'err_forced ', ' and err_forced was not set');
is ($output[6], 'err_rejected ', ' and err_rejected was not set');
ok ($output[7] =~ /RT \S+/, ' and RT was set');
ok ($output[8] =~ /ST \S+/, ' and ST was set');
is ($output[9], 'LC ', ' and LC was not set');
is ($output[10], "username $user", ' and username was set');
is ($output[11], 'login_cancel ', ' and login_cancel was not set');
is ($output[12], 'cancel_url ', ' and cancel_url was not set');
is ($output[13], 'show_remuser 1', ' and show_remuser was set');
is ($output[14], 'remuser_url https://test.example.org/login',
    ' and remuser_url was set');
is ($output[15], 'remuser_failed ', ' and remuser_failed was not set');
is ($output[16], 'script_name /login', ' and script_name was set');

# Test the same error case without remuser_redirect at all.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
($status, $error) = (WebKDC::WK_ERR_USER_AND_PASS_REQUIRED, '');
$WebKDC::Config::REMUSER_REDIRECT = '';
@output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'login page with WK_ERR_USER_AND_PASS_REQUIRED, '
    .'REMUSER_REDIRECT not set, not as an error handler');
is ($output[0], 'error ', ' and error was not set');
is ($output[1], 'err_missinginput ', ' and err_missinginput was not set');
is ($output[2], 'err_username ', ' and err_username was not set');
is ($output[3], 'err_password ', ' and err_password was not set');
is ($output[4], 'err_loginfailed ', ' and err_loginfailed was not set');
is ($output[5], 'err_forced ', ' and err_forced was not set');
is ($output[6], 'err_rejected ', ' and err_rejected was not set');
ok ($output[7] =~ /RT \S+/, ' and RT was set');
ok ($output[8] =~ /ST \S+/, ' and ST was set');
is ($output[9], 'LC ', ' and LC was not set');
is ($output[10], "username $user", ' and username was set');
is ($output[11], 'login_cancel ', ' and login_cancel was not set');
is ($output[12], 'cancel_url ', ' and cancel_url was not set');
is ($output[13], 'show_remuser ', ' and show_remuser was not set');
is ($output[14], 'remuser_url ', ' and remuser_url was not set');
is ($output[15], 'remuser_failed ', ' and remuser_failed was not set');
is ($output[16], 'script_name /login', ' and script_name was set');

# Test missing username and password.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
$weblogin->query->param ('login', 'yes');
$weblogin->query->delete ('username', 'password');
($status, $error) = (WebKDC::WK_ERR_USER_AND_PASS_REQUIRED, '');
$WebKDC::Config::REMUSER_REDIRECT = '';
@output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'login page with WK_ERR_USER_AND_PASS_REQUIRED, '
    .'REMUSER_REDIRECT not set, not as an error handler');
is ($output[0], 'error 1', ' and error is set');
is ($output[1], 'err_missinginput 1', ' and err_missinginput is set');
is ($output[2], 'err_username 1', ' and err_username is set');
is ($output[3], 'err_password 1', ' and err_password is set');
is ($output[4], 'err_loginfailed ', ' and err_loginfailed was not set');
is ($output[5], 'err_forced ', ' and err_forced was not set');
is ($output[6], 'err_rejected ', ' and err_rejected was not set');
ok ($output[7] =~ /RT \S+/, ' and RT was set');
ok ($output[8] =~ /ST \S+/, ' and ST was set');
is ($output[9], 'LC ', ' and LC was not set');
is ($output[10], 'username ', ' and username was not set');
is ($output[11], 'login_cancel ', ' and login_cancel was not set');
is ($output[12], 'cancel_url ', ' and cancel_url was not set');
is ($output[13], 'show_remuser ', ' and show_remuser was not set');
is ($output[14], 'remuser_url ', ' and remuser_url was not set');
is ($output[15], 'remuser_failed ', ' and remuser_failed was not set');
is ($output[16], 'script_name /login', ' and script_name was set');

# Test missing username.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
$weblogin->query->param ('login', 'yes');
$weblogin->query->delete ('username');
($status, $error) = (WebKDC::WK_ERR_USER_AND_PASS_REQUIRED, '');
$WebKDC::Config::REMUSER_REDIRECT = '';
@output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'login page with WK_ERR_USER_AND_PASS_REQUIRED, '
    .'REMUSER_REDIRECT not set, not as an error handler');
is ($output[0], 'error 1', ' and error is set');
is ($output[1], 'err_missinginput 1', ' and err_missinginput is set');
is ($output[2], 'err_username 1', ' and err_username is set');
is ($output[3], 'err_password ', ' and err_password is not set');
is ($output[4], 'err_loginfailed ', ' and err_loginfailed was not set');
is ($output[5], 'err_forced ', ' and err_forced was not set');
is ($output[6], 'err_rejected ', ' and err_rejected was not set');
ok ($output[7] =~ /RT \S+/, ' and RT was set');
ok ($output[8] =~ /ST \S+/, ' and ST was set');
is ($output[9], 'LC ', ' and LC was not set');
is ($output[10], 'username ', ' and username was not set');
is ($output[11], 'login_cancel ', ' and login_cancel was not set');
is ($output[12], 'cancel_url ', ' and cancel_url was not set');
is ($output[13], 'show_remuser ', ' and show_remuser was not set');
is ($output[14], 'remuser_url ', ' and remuser_url was not set');
is ($output[15], 'remuser_failed ', ' and remuser_failed was not set');
is ($output[16], 'script_name /login', ' and script_name was set');

# Test empty username.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
$weblogin->query->param ('login', 'yes');
$weblogin->query->param ('username', '');
($status, $error) = (WebKDC::WK_ERR_USER_AND_PASS_REQUIRED, '');
$WebKDC::Config::REMUSER_REDIRECT = '';
@output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'login page with WK_ERR_USER_AND_PASS_REQUIRED, '
    .'REMUSER_REDIRECT not set, not as an error handler');
is ($output[0], 'error 1', ' and error is set');
is ($output[1], 'err_missinginput 1', ' and err_missinginput is set');
is ($output[2], 'err_username 1', ' and err_username is set');
is ($output[3], 'err_password ', ' and err_password is not set');
is ($output[4], 'err_loginfailed ', ' and err_loginfailed was not set');
is ($output[5], 'err_forced ', ' and err_forced was not set');
is ($output[6], 'err_rejected ', ' and err_rejected was not set');
ok ($output[7] =~ /RT \S+/, ' and RT was set');
ok ($output[8] =~ /ST \S+/, ' and ST was set');
is ($output[9], 'LC ', ' and LC was not set');
is ($output[10], 'username ', ' and username was not set');
is ($output[11], 'login_cancel ', ' and login_cancel was not set');
is ($output[12], 'cancel_url ', ' and cancel_url was not set');
is ($output[13], 'show_remuser ', ' and show_remuser was not set');
is ($output[14], 'remuser_url ', ' and remuser_url was not set');
is ($output[15], 'remuser_failed ', ' and remuser_failed was not set');
is ($output[16], 'script_name /login', ' and script_name was set');

# Test missing password.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
$weblogin->query->param ('login', 'yes');
$weblogin->query->delete ('password');
($status, $error) = (WebKDC::WK_ERR_USER_AND_PASS_REQUIRED, '');
$WebKDC::Config::REMUSER_REDIRECT = '';
@output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'login page with WK_ERR_USER_AND_PASS_REQUIRED, '
    .'REMUSER_REDIRECT not set, not as an error handler');
is ($output[0], 'error 1', ' and error is set');
is ($output[1], 'err_missinginput 1', ' and err_missinginput is set');
is ($output[2], 'err_username ', ' and err_username is not set');
is ($output[3], 'err_password 1', ' and err_password is set');
is ($output[4], 'err_loginfailed ', ' and err_loginfailed was not set');
is ($output[5], 'err_forced ', ' and err_forced was not set');
is ($output[6], 'err_rejected ', ' and err_rejected was not set');
ok ($output[7] =~ /RT \S+/, ' and RT was set');
ok ($output[8] =~ /ST \S+/, ' and ST was set');
is ($output[9], 'LC ', ' and LC was not set');
is ($output[10], "username $user", ' and username was set');
is ($output[11], 'login_cancel ', ' and login_cancel was not set');
is ($output[12], 'cancel_url ', ' and cancel_url was not set');
is ($output[13], 'show_remuser ', ' and show_remuser was not set');
is ($output[14], 'remuser_url ', ' and remuser_url was not set');
is ($output[15], 'remuser_failed ', ' and remuser_failed was not set');
is ($output[16], 'script_name /login', ' and script_name was set');

# Login has failed for some reason, print the login page again.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
($status, $error) = (WebKDC::WK_ERR_LOGIN_FAILED, '');
@output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'login page with WK_ERR_LOGIN_FAILED, '
    .'REMUSER_REDIRECT not set, not as an error handler');
is ($output[0], 'error ', ' and error was not set');
is ($output[1], 'err_missinginput ', ' and err_missinginput was not set');
is ($output[2], 'err_username ', ' and err_username was not set');
is ($output[3], 'err_password ', ' and err_password was not set');
is ($output[4], 'err_loginfailed ', ' and err_loginfailed was not set');
is ($output[5], 'err_forced ', ' and err_forced was not set');
is ($output[6], 'err_rejected ', ' and err_rejected was not set');
ok ($output[7] =~ /RT \S+/, ' and RT was set');
ok ($output[8] =~ /ST \S+/, ' and ST was set');
is ($output[9], 'LC ', ' and LC was not set');
is ($output[10], "username $user", ' and username was set');
is ($output[11], 'login_cancel ', ' and login_cancel was not set');
is ($output[12], 'cancel_url ', ' and cancel_url was not set');
is ($output[13], 'show_remuser ', ' and show_remuser was not set');
is ($output[14], 'remuser_url ', ' and remuser_url was not set');
is ($output[15], 'remuser_failed ', ' and remuser_failed was not set');
is ($output[16], 'script_name /login', ' and script_name was set');

# User rejected for some reason, print the login page again.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
($status, $error) = (WebKDC::WK_ERR_USER_REJECTED, '');
@output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'login page with WK_ERR_USER_REJECTED, '
    .'REMUSER_REDIRECT not set, not as an error handler');
is ($output[0], 'error ', ' and error was not set');
is ($output[1], 'err_missinginput ', ' and err_missinginput was not set');
is ($output[2], 'err_username ', ' and err_username was not set');
is ($output[3], 'err_password ', ' and err_password was not set');
is ($output[4], 'err_loginfailed ', ' and err_loginfailed was not set');
is ($output[5], 'err_forced ', ' and err_forced was not set');
is ($output[6], 'err_rejected ', ' and err_rejected was not set');
ok ($output[7] =~ /RT \S+/, ' and RT was set');
ok ($output[8] =~ /ST \S+/, ' and ST was set');
is ($output[9], 'LC ', ' and LC was not set');
is ($output[10], "username $user", ' and username was set');
is ($output[11], 'login_cancel ', ' and login_cancel was not set');
is ($output[12], 'cancel_url ', ' and cancel_url was not set');
is ($output[13], 'show_remuser ', ' and show_remuser was not set');
is ($output[14], 'remuser_url ', ' and remuser_url was not set');
is ($output[15], 'remuser_failed ', ' and remuser_failed was not set');
is ($output[16], 'script_name /login', ' and script_name was set');

# Logins were forced but neither wpt_cookie is set nor is the
# remuser_cookie set.  Just show the login page normally.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
($status, $error) = (WebKDC::WK_ERR_LOGIN_FORCED, '');
@output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'login page with WK_ERR_LOGIN_FORCED, '
    .'REMUSER_REDIRECT not set, not as an error handler, neither '
    .'wpt_cookie nor remuser_cookie set');
is ($output[0], 'error ', ' and error was not set');
is ($output[1], 'err_missinginput ', ' and err_missinginput was not set');
is ($output[2], 'err_username ', ' and err_username was not set');
is ($output[3], 'err_password ', ' and err_password was not set');
is ($output[4], 'err_loginfailed ', ' and err_loginfailed was not set');
is ($output[5], 'err_forced ', ' and err_forced was not set');
is ($output[6], 'err_rejected ', ' and err_rejected was not set');
ok ($output[7] =~ /RT \S+/, ' and RT was set');
ok ($output[8] =~ /ST \S+/, ' and ST was set');
is ($output[9], 'LC ', ' and LC was not set');
is ($output[10], "username $user", ' and username was set');
is ($output[11], 'login_cancel ', ' and login_cancel was not set');
is ($output[12], 'cancel_url ', ' and cancel_url was not set');
is ($output[13], 'show_remuser ', ' and show_remuser was not set');
is ($output[14], 'remuser_url ', ' and remuser_url was not set');
is ($output[15], 'remuser_failed ', ' and remuser_failed was not set');
is ($output[16], 'script_name /login', ' and script_name was set');
# Check print_login_page (forced_login = 0)

# Logins were forced, and the wpt_cookie is set (we've already got a
# SSO).  Warn the user about forced login.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
$weblogin->param ('wpt_cookie', 1);
my $cookie = CGI::Cookie->new (-name => 'webauth_wpt', -value => 'test');
$ENV{HTTP_COOKIE} = "$cookie";
($status, $error) = (WebKDC::WK_ERR_LOGIN_FORCED, '');
@output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'login page with WK_ERR_LOGIN_FORCED, '
    .'REMUSER_REDIRECT not set, not as an error handler, wpt_cookie set');
is ($output[0], 'error 1', ' and error was set');
is ($output[1], 'err_missinginput ', ' and err_missinginput was not set');
is ($output[2], 'err_username ', ' and err_username was not set');
is ($output[3], 'err_password ', ' and err_password was not set');
is ($output[4], 'err_loginfailed ', ' and err_loginfailed was not set');
is ($output[5], 'err_forced 1', ' and err_forced was set');
is ($output[6], 'err_rejected ', ' and err_rejected was not set');
ok ($output[7] =~ /RT \S+/, ' and RT was set');
ok ($output[8] =~ /ST \S+/, ' and ST was set');
is ($output[9], 'LC ', ' and LC was not set');
is ($output[10], "username $user", ' and username was set');
is ($output[11], 'login_cancel ', ' and login_cancel was not set');
is ($output[12], 'cancel_url ', ' and cancel_url was not set');
is ($output[13], 'show_remuser ', ' and show_remuser was not set');
is ($output[14], 'remuser_url ', ' and remuser_url was not set');
is ($output[15], 'remuser_failed ', ' and remuser_failed was not set');
is ($output[16], 'script_name /login', ' and script_name was set');
# Check print_login_page (forced_login = 1)

# FIXME: Requires us to fake cookies, which we'll do in a later pass.
# Logins were forced, and the remuser_cookie is set, which means the
# user hasn't logged in yet but wants to try using REMUSER.  Since login
# is forced, warn the user about forced login.
#$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
#($status, $error) = (WebKDC::WK_ERR_LOGIN_FORCED, '');
#$weblogin->query->cookie ($weblogin->param ('remuser_cookie'), 1);
#$WebKDC::Config::REMUSER_REDIRECT = '';
#@output = index_wrapper ($weblogin, $status, $error);
# Check print_login_page (forced_login = 1)

# Unrecoverable error - check the error page.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
($status, $error) = (WebKDC::WK_ERR_UNRECOVERABLE_ERROR, 'unrecoverable');
my $errmsg = 'unrecoverable error occured. Try again later.';
@output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'error page for unrecoverable error');
is ($output[0], 'err_bad_method ', ' and err_bad_method was not set');
is ($output[1], 'err_cookies_disabled ',
    ' and err_cookies_disabled was not set');
is ($output[2], 'err_no_request_token ',
    ' and err_no_request_token was not set');
is ($output[3], 'err_webkdc 1', ' and err_webkdc was set');
is ($output[4], "err_msg $errmsg", ' with correct error message');
is ($output[5], 'err_confirm ', ' and err_confirm was not set');
is ($output[6], 'script_name ', ' and script_name was not set');
# Check print_error_page (err_webkdc = 1, err_msg = $errmsg: $error)

# Token is stale - check the error page.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
($status, $error) = (WebKDC::WK_ERR_REQUEST_TOKEN_STALE, 'stale');
$errmsg = 'you took too long to login.';
@output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'error page for stale token error');
is ($output[0], 'err_bad_method ', ' and err_bad_method was not set');
is ($output[1], 'err_cookies_disabled ',
    ' and err_cookies_disabled was not set');
is ($output[2], 'err_no_request_token ',
    ' and err_no_request_token was not set');
is ($output[3], 'err_webkdc 1', ' and err_webkdc was set');
is ($output[4], "err_msg $errmsg", ' with correct error message');
is ($output[5], 'err_confirm ', ' and err_confirm was not set');
is ($output[6], 'script_name ', ' and script_name was not set');
# Check print_error_page (err_webkdc = 1, err_msg = $errmsg: $error)

# Unrecoverable WebAuth server error - check the error page.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
($status, $error) = (WebKDC::WK_ERR_WEBAUTH_SERVER_ERROR, 'webautherr');
$errmsg = 'there is most likely a configuration problem with'
    . ' the server that redirected you. Please contact its'
    . ' administrator.';
@output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'error page for unrecoverable webauth server error');
is ($output[0], 'err_bad_method ', ' and err_bad_method was not set');
is ($output[1], 'err_cookies_disabled ',
    ' and err_cookies_disabled was not set');
is ($output[2], 'err_no_request_token ',
    ' and err_no_request_token was not set');
is ($output[3], 'err_webkdc 1', ' and err_webkdc was set');
is ($output[4], "err_msg $errmsg", ' with correct error message');
is ($output[5], 'err_confirm ', ' and err_confirm was not set');
is ($output[6], 'script_name ', ' and script_name was not set');
is ($output[7], 'err_html ', ' and err_html was not set');
# Check print_error_page (err_webkdc = 1, err_msg = $errmsg: $error)

# Public computer setting passed along to confirmation page.
$weblogin = init_weblogin ('testuser3', $pass, $st_base64, $rt_base64,
                           \%PAGES);
($status, $error) = (WebKDC::WK_SUCCESS, '');
$weblogin->query->param (public_computer => 1);
@output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'success page was printed for login from public computer');
is ($output[0], "username testuser3", '...and username was set');
is ($output[1],
    'return_url https://test.example.org/?WEBAUTHR=TestResponse;',
    '...and return_url was set');
is ($output[2], 'pretty_return_url https://test.example.org',
    '...and pretty_return_url was set');
is ($output[3], 'login_cancel ', '...and login_cancel was not set');
is ($output[4], 'cancel_url ', '...and cancel_url was not set');
is ($output[5], 'show_remuser ', '...and show_remuser was not set');
is ($output[6], 'remuser ', '...and remuser was not set');
is ($output[7], 'script_name ', '...and script name was not set');
is ($output[8], 'warn_expire ', '...and warn_expire was not set');
is ($output[9], 'expire_timestamp ', '...and expire_timestamp was not set');
is ($output[10], 'pwchange_url ', '...and pwchange_url was not set');
is ($output[11], 'CPT ', '...and CPT was not set');
is ($output[12], 'public_computer 1', '...and public_computer was set');
is ($output[13], 'device_expiring ', '...and device_expiring was not set');
# Check print_confirm_page (public_computer = 1)

# Device factor expiring setting passed along to confirmation page.
my $default_factor_warning = $WebKDC::Config::FACTOR_WARNING;
$WebKDC::Config::FACTOR_WARNING = 60;
$weblogin = init_weblogin ('testuser3', $pass, $st_base64, $rt_base64,
                           \%PAGES);
$weblogin->{response}->cookie('webauth_wft', 1, time + 30);
($status, $error) = (WebKDC::WK_SUCCESS, '');
@output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'success page was printed for login from public computer');
is ($output[0], "username testuser3", '...and username was set');
is ($output[1],
    'return_url https://test.example.org/?WEBAUTHR=TestResponse;',
    '...and return_url was set');
is ($output[2], 'pretty_return_url https://test.example.org',
    '...and pretty_return_url was set');
is ($output[3], 'login_cancel ', '...and login_cancel was not set');
is ($output[4], 'cancel_url ', '...and cancel_url was not set');
is ($output[5], 'show_remuser ', '...and show_remuser was not set');
is ($output[6], 'remuser ', '...and remuser was not set');
is ($output[7], 'script_name ', '...and script name was not set');
is ($output[8], 'warn_expire ', '...and warn_expire was not set');
is ($output[9], 'expire_timestamp ', '...and expire_timestamp was not set');
is ($output[10], 'pwchange_url ', '...and pwchange_url was not set');
is ($output[11], 'CPT ', '...and CPT was not set');
is ($output[12], 'public_computer ', '...and public_computer was not set');
like ($output[13], qr{^device_expiring \d+$},
      '...and device_expiring was set');
$WebKDC::Config::FACTOR_WARNING = $default_factor_warning;
# Check print_confirm_page (device_expiring = 1)

# Authentication rejected by the user information service.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
$error = WebKDC::WebKDCException->new (WebKDC::WK_ERR_AUTH_REJECTED,
                                       'authentication rejected',
                                       WA_PEC_AUTH_REJECTED,
                                       '<strong>go away</strong>');
($status, $error) = (WebKDC::WK_ERR_AUTH_REJECTED, $error);
@output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'error page for authentication rejected error');
is ($output[0], 'err_bad_method ', ' and err_bad_method was not set');
is ($output[1], 'err_cookies_disabled ',
    ' and err_cookies_disabled was not set');
is ($output[2], 'err_no_request_token ',
    ' and err_no_request_token was not set');
is ($output[3], 'err_webkdc ', ' and err_webkdc was not set');
is ($output[4], 'err_msg ', ' and err_msg was not set');
is ($output[5], 'err_confirm ', ' and err_confirm was not set');
is ($output[6], 'script_name ', ' and script_name was not set');
is ($output[7], 'err_html <strong>go away</strong>',
    ' and err_html was set to the correct value');

# Test REMOTE_USER cookie creation and the remuser_factors callback.
package WebKDC::Config;
package main;
$weblogin->{request}->proxy_cookies ({});
$ENV{REMOTE_USER} = 'remauth@EXAMPLE.ORG';
$WebKDC::Config::REMUSER_ENABLED          = 1;
@WebKDC::Config::REMUSER_LOCAL_REALMS     = qw(EXAMPLE.ORG);
@WebKDC::Config::REMUSER_PERMITTED_REALMS = qw(EXAMPLE.ORG);
$status = $weblogin->setup_kdc_request;
is ($status, 0, 'setup_kdc_request with authenticate sub works');
my %cookies = %{ $weblogin->{request}->proxy_cookies };
is (scalar (keys %cookies), 1, '...and there is one cookie set');
my @types = keys %cookies;
is ($types[0], 'remuser', '...which is a remuser cookie');
# FIXME: We can't test the session factor since there's no way to get at it.
my $token_string = $cookies{remuser};
my $token = WebAuth::Token->new ($wa, $token_string, $keyring);
isa_ok ($token, 'WebAuth::Token::WebKDCProxy', 'token');
is ($token->subject, 'remauth', '...with correct subject');
is ($token->proxy_type, 'remuser', '...and proxy type');
is ($token->proxy_subject, 'WEBKDC:remuser', '...and proxy subject');
is ($token->data, 'remauth', '...and data');
is ($token->initial_factors, 'o1', '...and initial factors');
is ($token->loa, 1, '...and LoA');
ok (abs ($token->expiration - time - $WebKDC::Config::REMUSER_EXPIRES) < 2,
    '...and expiration is in the right range');

# Test the user-defined authenticate callback.  We'll set a callback that will
# generate a token with some particular parameters, call setup_kdc_request,
# and then extract the proxy token from the request and verify it contains the
# correct data.
$USE_AUTHENTICATE = 1;
$weblogin->{request}->proxy_cookies ({});
$status = $weblogin->setup_kdc_request;
is ($status, 0, 'setup_kdc_request with authenticate sub works');
%cookies = %{ $weblogin->{request}->proxy_cookies };
is (scalar (keys %cookies), 1, '...and there is one cookie set');
@types = keys %cookies;
is ($types[0], 'remuser', '...which is a remuser cookie');
# FIXME: We can't test the session factor since there's no way to get at it.
$token_string = $cookies{remuser};
$token = WebAuth::Token->new ($wa, $token_string, $keyring);
isa_ok ($token, 'WebAuth::Token::WebKDCProxy', 'token');
is ($token->subject, 'authtest', '...with correct subject');
is ($token->proxy_type, 'remuser', '...and proxy type');
is ($token->proxy_subject, 'WEBKDC:remuser', '...and proxy subject');
is ($token->data, 'authtest', '...and data');
is ($token->initial_factors, 'p', '...and initial factors');
is ($token->loa, 2, '...and LoA');
ok (abs ($token->expiration - time - $WebKDC::Config::REMUSER_EXPIRES) < 2,
    '...and expiration is in the right range');

unlink ('krb5cc_test', 't/data/test.keyring');
rmtree ('./t/tmp');
