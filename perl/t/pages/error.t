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
    plan tests => 46;
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
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
$weblogin->{response}->return_url ('test.example.org/');
($status, $error) = (WebKDC::WK_SUCCESS, '');
my @output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'error page for bad return URL');
is ($output[0], 'err_bad_method ', '... and err_bad_method was not set');
is ($output[1], 'err_cookies_disabled ',
    '... and err_cookies_disabled was not set');
is ($output[2], 'err_no_request_token ',
    '... and err_no_request_token was not set');
is ($output[3], 'err_webkdc 1', '... and err_webkdc was set');
is ($output[4], 'err_msg there is most likely a configuration problem '
    .'with the server that redirected you. Please contact its '
    .'administrator.', '... with correct error message');
is ($output[5], 'err_confirm ', '... and err_confirm was not set');
is ($output[6], 'script_name ', '... and script_name was not set');

# Unrecoverable error - check the error page.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
($status, $error) = (WebKDC::WK_ERR_UNRECOVERABLE_ERROR, 'unrecoverable');
my $errmsg = 'unrecoverable error occured. Try again later.';
@output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'error page for unrecoverable error');
is ($output[0], 'err_bad_method ', '... and err_bad_method was not set');
is ($output[1], 'err_cookies_disabled ',
    '... and err_cookies_disabled was not set');
is ($output[2], 'err_no_request_token ',
    '... and err_no_request_token was not set');
is ($output[3], 'err_webkdc 1', '... and err_webkdc was set');
is ($output[4], "err_msg $errmsg", '... with correct error message');
is ($output[5], 'err_confirm ', '... and err_confirm was not set');
is ($output[6], 'script_name ', '... and script_name was not set');
# Check print_error_page (err_webkdc = 1, err_msg = $errmsg: $error)

# Token is stale - check the error page.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
($status, $error) = (WebKDC::WK_ERR_REQUEST_TOKEN_STALE, 'stale');
$errmsg = 'you took too long to login.';
@output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'error page for stale token error');
is ($output[0], 'err_bad_method ', '... and err_bad_method was not set');
is ($output[1], 'err_cookies_disabled ',
    '... and err_cookies_disabled was not set');
is ($output[2], 'err_no_request_token ',
    '... and err_no_request_token was not set');
is ($output[3], 'err_webkdc 1', '... and err_webkdc was set');
is ($output[4], "err_msg $errmsg", '... with correct error message');
is ($output[5], 'err_confirm ', '... and err_confirm was not set');
is ($output[6], 'script_name ', '... and script_name was not set');
# Check print_error_page (err_webkdc = 1, err_msg = $errmsg: $error)

# Unrecoverable WebAuth server error - check the error page.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
($status, $error) = (WebKDC::WK_ERR_WEBAUTH_SERVER_ERROR, 'webautherr');
$errmsg = 'there is most likely a configuration problem with'
    . ' the server that redirected you. Please contact its'
    . ' administrator.';
@output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'error page for unrecoverable webauth server error');
is ($output[0], 'err_bad_method ', '... and err_bad_method was not set');
is ($output[1], 'err_cookies_disabled ',
    '... and err_cookies_disabled was not set');
is ($output[2], 'err_no_request_token ',
    '... and err_no_request_token was not set');
is ($output[3], 'err_webkdc 1', '... and err_webkdc was set');
is ($output[4], "err_msg $errmsg", '... with correct error message');
is ($output[5], 'err_confirm ', '... and err_confirm was not set');
is ($output[6], 'script_name ', '... and script_name was not set');
is ($output[7], 'err_html ', '... and err_html was not set');
# Check print_error_page (err_webkdc = 1, err_msg = $errmsg: $error)

unlink ('krb5cc_test', 't/data/test.keyring');
rmtree ('./t/tmp');
