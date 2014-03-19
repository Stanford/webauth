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
    read_outputfile index_wrapper create_test_keyring create_test_st
    create_test_rt page_configuration);

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
    plan tests => 21;
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

# Bad return URL (set it to be http rather than https).
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64);
$weblogin->{response}->return_url ('test.example.org/');
($TEST_STATUS, $TEST_ERROR) = (WebKDC::WK_SUCCESS, '');
my %output = index_wrapper ($weblogin);
my %check = read_outputfile ('t/data/pages/error/return-url');
ok (%output, 'error page for bad return URL');
is_deeply (\%output, \%check, '... and the output matches what is expected');

# Unrecoverable error - check the error page.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64);
($TEST_STATUS, $TEST_ERROR) = (WebKDC::WK_ERR_UNRECOVERABLE_ERROR,
                               'unrecoverable');
my $errmsg = 'unrecoverable error occured. Try again later.';
%output = index_wrapper ($weblogin);
%check = read_outputfile ('t/data/pages/error/unrecoverable');
ok (%output, 'error page for unrecoverable error');
is_deeply (\%output, \%check, '... and the output matches what is expected');
# Check print_error_page (err_webkdc = 1, err_msg = $errmsg: $TEST_ERROR)

# Token is stale - check the error page.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64);
($TEST_STATUS, $TEST_ERROR) = (WebKDC::WK_ERR_REQUEST_TOKEN_STALE, 'stale');
%output = index_wrapper ($weblogin);
%check = read_outputfile ('t/data/pages/error/stale-token');
ok (%output, 'error page for stale token error');
is_deeply (\%output, \%check, '... and the output matches what is expected');
# Check print_error_page (err_webkdc = 1, err_msg = $errmsg: $TEST_ERROR)

# Unrecoverable WebAuth server error - check the error page.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64);
($TEST_STATUS, $TEST_ERROR) = (WebKDC::WK_ERR_WEBAUTH_SERVER_ERROR,
                               'webautherr');
%output = index_wrapper ($weblogin);
%check = read_outputfile ('t/data/pages/error/unrecoverable-webauth');
ok (%output, 'error page for unrecoverable webauth server error');
is_deeply (\%output, \%check, '... and the output matches what is expected');
# Check print_error_page (err_webkdc = 1, err_msg = $errmsg: $TEST_ERROR)

unlink ('krb5cc_test', 't/data/test.keyring', 't/data/test.keyring.lock');
rmtree ('./t/tmp');
