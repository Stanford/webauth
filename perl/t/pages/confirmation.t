#!/usr/bin/perl
#
# Tests for weblogin confirmation page
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
use Util qw (contents get_userinfo getcreds create_keyring init_weblogin);

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
    plan tests => 111;
}

# Set our method to not have password tests complain.
$ENV{REQUEST_METHOD} = 'POST';

#############################################################################
# Environment setup
#############################################################################

# Wrapper around WebLogin::index to grab the page output into a string and
# return that output.  To make all the index runmode tests look cleaner.
sub index_wrapper {
    my ($weblogin, $status, $error) = @_;

    $TEST_STATUS = $status;
    $TEST_ERROR = $error;
    my $page = $weblogin->index;
    return split (/[\r\n]+/, $$page);
}

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

unlink ('krb5cc_test', 't/data/test.keyring');
rmtree ('./t/tmp');
