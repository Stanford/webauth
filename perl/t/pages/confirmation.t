#!/usr/bin/perl
#
# Tests for weblogin confirmation page
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
    index_wrapper read_outputfile compare_fields create_test_keyring
    create_test_st create_test_rt page_configuration);

use CGI;
use CGI::Cookie;
use File::Path qw (rmtree);
use Test::More;
use WebAuth qw(3.00 :const);
use WebKDC ();
use WebKDC::Config;
use WebLogin;

#############################################################################
# Environment setup
#############################################################################

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
    plan tests => 106;
}

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

# Page fields to compare to the ones in test files.
my @fields = qw(username return_url pretty_return_url login_cancel cancel_url
    show_remuser script_name warn_expire expire_timestamp pwchange_url
    CPT remember_login device_expiring);
my @fields_login = qw(error err_username err_password err_newpassword
    err_newpassword_match err_loginfailed err_rejected err_pwweak
    err_pwchange err_msg RT ST CPT username password new_passwd1 new_passwd2
    changepw expired skip_username skip_password script_name);

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
my ($status, $error);
$status = $weblogin->setup_kdc_request;
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

# Success with user having a pending password change.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64);
($TEST_STATUS, $TEST_ERROR) = (WebKDC::WK_SUCCESS, '');
my %output = index_wrapper ($weblogin);
my %check = read_outputfile ('t/data/pages/confirm/pending-pwchange');
ok (%output, 'success page with pending password expiration was printed');
compare_fields (\%output, \%check, @fields);

# Success with no password expiration time.
$weblogin = init_weblogin ('testuser3', $pass, $st_base64, $rt_base64);
($TEST_STATUS, $TEST_ERROR) = (WebKDC::WK_SUCCESS, '');
%output = index_wrapper ($weblogin);
%check = read_outputfile ('t/data/pages/confirm/no-pwexpiration');
ok (%output, 'success page without pwexpiration was printed');
compare_fields (\%output, \%check, @fields);

# FIXME: Testing remuser requires us to fake a cookie, which we'll do in
#        a later revision.
# Successful password, with showing the checkbox for REMOTE_USER.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64);
$WebKDC::Config::REMUSER_REDIRECT = '/login-spnego';
$ENV{REMOTE_USER} = $user;
($TEST_STATUS, $TEST_ERROR) = (WebKDC::WK_SUCCESS, '');
%output = index_wrapper ($weblogin);
%check = read_outputfile ('t/data/pages/confirm/remote-user-checkbox');
$WebKDC::Config::REMUSER_REDIRECT = '';
ok (%output, 'success page with remuser redirect checkbox was printed');
compare_fields (\%output, \%check, @fields);

# Expired password.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64);
($TEST_STATUS, $TEST_ERROR) = (WebKDC::WK_ERR_CREDS_EXPIRED, '');
%output = index_wrapper ($weblogin);
%check = read_outputfile ('t/data/pages/confirm/expired-password');
ok (%output, 'page with expired password field checked was printed');
compare_fields (\%output, \%check, @fields_login);

# Public computer setting passed along to confirmation page.
$weblogin = init_weblogin ('testuser3', $pass, $st_base64, $rt_base64);
($TEST_STATUS, $TEST_ERROR) = (WebKDC::WK_SUCCESS, '');
$weblogin->query->param (remember_login => 'no');
%output = index_wrapper ($weblogin);
%check = read_outputfile ('t/data/pages/confirm/public-computer');
ok (%output, 'success page was printed for login from public computer');
compare_fields (\%output, \%check, @fields);
# Check print_confirm_page (remember_login = 'no')

# Device factor expiring setting passed along to confirmation page.
my $default_factor_warning = $WebKDC::Config::FACTOR_WARNING;
$WebKDC::Config::FACTOR_WARNING = 60;
$weblogin = init_weblogin ('testuser3', $pass, $st_base64, $rt_base64);
$weblogin->{response}->cookie('webauth_wft', 1, time + 30);
($TEST_STATUS, $TEST_ERROR) = (WebKDC::WK_SUCCESS, '');
%output = index_wrapper ($weblogin);
%check = read_outputfile ('t/data/pages/confirm/device-expiring');
ok (%output, 'success page was printed for device factor expiring');
compare_fields (\%output, \%check, @fields);
$WebKDC::Config::FACTOR_WARNING = $default_factor_warning;
# Check print_confirm_page (device_expiring = 1)

unlink ('krb5cc_test', 't/data/test.keyring', 't/data/test.keyring.lock');
rmtree ('./t/tmp');
