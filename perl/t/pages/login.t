#!/usr/bin/perl
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
    plan tests => 229;
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

# The user didn't already ask for REMOTE_USER.  However, we just need
# authentication (not forced login) and we haven't already tried
# REMOTE_USER and failed, so give them the login screen with the choice.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
($status, $error) = (WebKDC::WK_ERR_USER_AND_PASS_REQUIRED, '');
$weblogin->param ('is_error', 0);
$WebKDC::Config::REMUSER_REDIRECT = 'https://test.example.org/login';
my @output = index_wrapper ($weblogin, $status, $error);
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

unlink ('krb5cc_test', 't/data/test.keyring');
rmtree ('./t/tmp');
