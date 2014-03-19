#!/usr/bin/perl
#
# Tests for weblogin page handling after login responses.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2010, 2012, 2013, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

# Ensure we don't pick up the system webkdc.conf.
BEGIN { $ENV{WEBKDC_CONFIG} = '/nonexistent' }

use lib ('t/lib', 'lib', 'blib/arch');
use Util qw (contents get_userinfo getcreds create_keyring init_weblogin
    read_outputfile index_wrapper compare_fields  create_test_keyring
    create_test_st create_test_rt page_configuration);

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

# Check for a valid kerberos config.
if (! -f 't/data/test.principal' || ! -f 't/data/test.password'
    || ! -f 't/data/test.keytab' || ! -d 't/data/templates') {
    plan skip_all => 'Kerberos tests not configured';
} else {
    plan tests => 229;
}

#############################################################################
# Environment setup
#############################################################################

# Get the username and password to log in with.
my $fname_passwd = 't/data/test.password';
my ($user, $pass) = get_userinfo ($fname_passwd) if -f $fname_passwd;

# Set up various configuration values for WebAuth::Config and environment.
page_configuration ($user);

# Create keyring, ST, and RT for testing.
my $wa = WebAuth->new;
my $keyring          = create_test_keyring ($wa);
my ($st, $st_base64) = create_test_st ($wa, $keyring);
my $rt_base64        = create_test_rt ($wa, $st);

my @fields = qw(
    LC
    RT
    ST
    cancel_url
    err_forced
    err_loginfailed
    err_missinginput
    err_password
    err_rejected
    err_username
    error
    login_cancel
    remuser_failed
    remuser_url
    script_name
    show_remuser
    username
);

#############################################################################
# Tests
#############################################################################

# Create the weblogin object and make sure it looks as it should.
my $weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64);
ok ($weblogin, 'getting Weblogin object works');
is ($weblogin->param ('debug'), 0, '... and debug is not set');
is ($weblogin->param ('logging'), 0, '... and logging is not set');
ok (defined $weblogin->{request}, '... and we got a WebRequest');
ok (defined $weblogin->{response}, '... and we got a WebResponse');

# Set up the KDC request and test that things were set up correctly.
my $status = $weblogin->setup_kdc_request;
ok (!$status, 'setup_kdc_request works');
is ($weblogin->{request}->user, $user, '... and username set');
is ($weblogin->{request}->pass, $pass, '... and password set');
is ($weblogin->{request}->local_ip_addr, $ENV{SERVER_ADDR},
   '... and SERVER_ADDR set');
is ($weblogin->{request}->local_ip_port, $ENV{SERVER_PORT},
   '... and SERVER_PORT set');
is ($weblogin->{request}->remote_ip_addr, $ENV{REMOTE_ADDR},
   '... and REMOTE_ADDR set');
is ($weblogin->{request}->remote_ip_port, $ENV{REMOTE_PORT},
   '... and REMOTE_PORT set');
is ($weblogin->{request}->remote_user, $ENV{REMOTE_USER},
   '... and REMOTE_USER set');

# The user didn't already ask for REMOTE_USER.  However, we just need
# authentication (not forced login) and we haven't already tried
# REMOTE_USER and failed, so give them the login screen with the choice.
$WebKDC::Config::REMUSER_REDIRECT = 'https://test.example.org/login';
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64);
($TEST_STATUS, $TEST_ERROR) = (WebKDC::WK_ERR_USER_AND_PASS_REQUIRED, '');
$weblogin->param ('is_error', 0);
my %output = index_wrapper ($weblogin);
my %check = read_outputfile ('t/data/pages/login/remote-user');
ok (%output, 'login page with choice for REMOTE_USER printed');
compare_fields (\%output, \%check, @fields);

# Test failed login with remuser_redirect set, and the flag that shows
# we were called as an error handler set.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64);
($TEST_STATUS, $TEST_ERROR) = (WebKDC::WK_ERR_USER_AND_PASS_REQUIRED, '');
$weblogin->param ('is_error', 1);
%output = index_wrapper ($weblogin);
%check = read_outputfile ('t/data/pages/login/pass-required');
ok (%output, 'login page with WK_ERR_USER_AND_PASS_REQUIRED, '
    .'REMUSER_REDIRECT set, as error handler');
compare_fields (\%output, \%check, @fields);

# Test failed login with remuser_redirect set, and the flag that shows
# we were called as an error handler not set.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64);
($TEST_STATUS, $TEST_ERROR) = (WebKDC::WK_ERR_USER_AND_PASS_REQUIRED, '');
$WebKDC::Config::REMUSER_REDIRECT = 'https://test.example.org/login';
$weblogin->param ('is_error', 0);
%output = index_wrapper ($weblogin);
%check = read_outputfile ('t/data/pages/login/pass-required-not-error');
ok (%output, 'login page with WK_ERR_USER_AND_PASS_REQUIRED, '
    .'REMUSER_REDIRECT set, not as error handler');
compare_fields (\%output, \%check, @fields);

# Test the same error case without remuser_redirect at all.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64);
($TEST_STATUS, $TEST_ERROR) = (WebKDC::WK_ERR_USER_AND_PASS_REQUIRED, '');
$WebKDC::Config::REMUSER_REDIRECT = '';
%output = index_wrapper ($weblogin);
%check = read_outputfile ('t/data/pages/login/pass-required-no-remuser');
ok (%output, 'login page with WK_ERR_USER_AND_PASS_REQUIRED, '
    .'REMUSER_REDIRECT not set, not as an error handler');
compare_fields (\%output, \%check, @fields);

# Test missing username and password.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64);
$weblogin->query->param ('login', 'yes');
$weblogin->query->delete ('username', 'password');
($TEST_STATUS, $TEST_ERROR) = (WebKDC::WK_ERR_USER_AND_PASS_REQUIRED, '');
$WebKDC::Config::REMUSER_REDIRECT = '';
%output = index_wrapper ($weblogin);
%check = read_outputfile ('t/data/pages/login/no-username-password');
ok (%output, 'login page with WK_ERR_USER_AND_PASS_REQUIRED, '
    .'REMUSER_REDIRECT not set, not as an error handler, missing both '
    .'username and password');
compare_fields (\%output, \%check, @fields);

# Test missing username.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64);
$weblogin->query->param ('login', 'yes');
$weblogin->query->delete ('username');
($TEST_STATUS, $TEST_ERROR) = (WebKDC::WK_ERR_USER_AND_PASS_REQUIRED, '');
$WebKDC::Config::REMUSER_REDIRECT = '';
%output = index_wrapper ($weblogin);
%check = read_outputfile ('t/data/pages/login/no-username');
ok (%output, 'login page with WK_ERR_USER_AND_PASS_REQUIRED, '
    .'REMUSER_REDIRECT not set, not as an error handler, missing username');
compare_fields (\%output, \%check, @fields);

# Test empty username.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64);
$weblogin->query->param ('login', 'yes');
$weblogin->query->param ('username', '');
($TEST_STATUS, $TEST_ERROR) = (WebKDC::WK_ERR_USER_AND_PASS_REQUIRED, '');
$WebKDC::Config::REMUSER_REDIRECT = '';
%output = index_wrapper ($weblogin);
%check = read_outputfile ('t/data/pages/login/no-username');
ok (%output, 'login page with WK_ERR_USER_AND_PASS_REQUIRED, '
    .'REMUSER_REDIRECT not set, not as an error handler, empty username');
compare_fields (\%output, \%check, @fields);

# Test missing password.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64);
$weblogin->query->param ('login', 'yes');
$weblogin->query->delete ('password');
($TEST_STATUS, $TEST_ERROR) = (WebKDC::WK_ERR_USER_AND_PASS_REQUIRED, '');
$WebKDC::Config::REMUSER_REDIRECT = '';
%output = index_wrapper ($weblogin);
%check = read_outputfile ('t/data/pages/login/no-password');
ok (%output, 'login page with WK_ERR_USER_AND_PASS_REQUIRED, '
    .'REMUSER_REDIRECT not set, not as an error handler');
compare_fields (\%output, \%check, @fields);

# Login has failed for some reason, print the login page again.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64);
($TEST_STATUS, $TEST_ERROR) = (WebKDC::WK_ERR_LOGIN_FAILED, '');
%output = index_wrapper ($weblogin);
%check = read_outputfile ('t/data/pages/login/failed');
ok (%output, 'login page with WK_ERR_LOGIN_FAILED, '
    .'REMUSER_REDIRECT not set, not as an error handler');
compare_fields (\%output, \%check, @fields);

# User rejected for some reason, print the login page again.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64);
($TEST_STATUS, $TEST_ERROR) = (WebKDC::WK_ERR_USER_REJECTED, '');
%output = index_wrapper ($weblogin);
%check = read_outputfile ('t/data/pages/login/rejected');
ok (%output, 'login page with WK_ERR_USER_REJECTED, '
    .'REMUSER_REDIRECT not set, not as an error handler');
compare_fields (\%output, \%check, @fields);

# Logins were forced but neither wpt_cookie is set nor is the
# remuser_cookie set.  Just show the login page normally.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64);
($TEST_STATUS, $TEST_ERROR) = (WebKDC::WK_ERR_LOGIN_FORCED, '');
%output = index_wrapper ($weblogin);
%check = read_outputfile ('t/data/pages/login/forced-no-wpt');
ok (%output, 'login page with WK_ERR_LOGIN_FORCED, '
    .'REMUSER_REDIRECT not set, not as an error handler, neither '
    .'wpt_cookie nor remuser_cookie set');
compare_fields (\%output, \%check, @fields);
# Check print_login_page (forced_login = 0)

# Logins were forced, and the wpt_cookie is set (we've already got a
# SSO).  Warn the user about forced login.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64);
$weblogin->param ('wpt_cookie', 1);
my $cookie = CGI::Cookie->new (-name => 'webauth_wpt', -value => 'test');
$ENV{HTTP_COOKIE} = "$cookie";
($TEST_STATUS, $TEST_ERROR) = (WebKDC::WK_ERR_LOGIN_FORCED, '');
%output = index_wrapper ($weblogin);
%check = read_outputfile ('t/data/pages/login/forced');
ok (%output, 'login page with WK_ERR_LOGIN_FORCED, '
    .'REMUSER_REDIRECT not set, not as an error handler, wpt_cookie set');
compare_fields (\%output, \%check, @fields);
# Check print_login_page (forced_login = 1)

# FIXME: Requires us to fake cookies, which we'll do in a later pass.
# Logins were forced, and the remuser_cookie is set, which means the
# user hasn't logged in yet but wants to try using REMUSER.  Since login
# is forced, warn the user about forced login.
#$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64);
#($TEST_STATUS, $TEST_ERROR) = (WebKDC::WK_ERR_LOGIN_FORCED, '');
#$weblogin->query->cookie ($weblogin->param ('remuser_cookie'), 1);
#$WebKDC::Config::REMUSER_REDIRECT = '';
#@output = index_wrapper ($weblogin);
# Check print_login_page (forced_login = 1)

unlink ('krb5cc_test', 't/data/test.keyring', 't/data/test.keyring.lock');
rmtree ('./t/tmp');
