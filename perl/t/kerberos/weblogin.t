#!/usr/bin/perl -w
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
    plan tests => 45;
}

# Set our method to not have password tests complain.
$ENV{REQUEST_METHOD} = 'POST';

#############################################################################
# Wrapper functions
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
unlink ('t/data/test.keyring', 't/data/test.keyring.lock', 'krb5cc_test');
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

# Authentication rejected by the user information service.
$weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%PAGES);
$error = WebKDC::WebKDCException->new (WebKDC::WK_ERR_AUTH_REJECTED,
                                       'authentication rejected',
                                       WA_PEC_AUTH_REJECTED,
                                       '<strong>go away</strong>');
($status, $error) = (WebKDC::WK_ERR_AUTH_REJECTED, $error);
my @output = index_wrapper ($weblogin, $status, $error);
ok (@output, 'error page for authentication rejected error');
is ($output[0], 'err_bad_method ', '... and err_bad_method was not set');
is ($output[1], 'err_cookies_disabled ',
    '... and err_cookies_disabled was not set');
is ($output[2], 'err_no_request_token ',
    '... and err_no_request_token was not set');
is ($output[3], 'err_webkdc ', '... and err_webkdc was not set');
is ($output[4], 'err_msg ', '... and err_msg was not set');
is ($output[5], 'err_confirm ', '... and err_confirm was not set');
is ($output[6], 'script_name ', '... and script_name was not set');
is ($output[7], 'err_html <strong>go away</strong>',
    '... and err_html was set to the correct value');

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
is (scalar (keys %cookies), 1, '... and there is one cookie set');
my @types = keys %cookies;
is ($types[0], 'remuser', '... which is a remuser cookie');
# FIXME: We can't test the session factor since there's no way to get at it.
my $token_string = $cookies{remuser};
my $token = WebAuth::Token->new ($wa, $token_string, $keyring);
isa_ok ($token, 'WebAuth::Token::WebKDCProxy', 'token');
is ($token->subject, 'remauth', '... with correct subject');
is ($token->proxy_type, 'remuser', '... and proxy type');
is ($token->proxy_subject, 'WEBKDC:remuser', '... and proxy subject');
is ($token->data, 'remauth', '... and data');
is ($token->initial_factors, 'o1', '... and initial factors');
is ($token->loa, 1, '... and LoA');
ok (abs ($token->creation - time) < 2,
    '... and creation is in the right range');
ok (abs ($token->expiration - time - $WebKDC::Config::REMUSER_EXPIRES) < 2,
    '... and expiration is in the right range');

# Test the user-defined authenticate callback.  We'll set a callback that will
# generate a token with some particular parameters, call setup_kdc_request,
# and then extract the proxy token from the request and verify it contains the
# correct data.
$USE_AUTHENTICATE = 1;
$weblogin->{request}->proxy_cookies ({});
$status = $weblogin->setup_kdc_request;
is ($status, 0, 'setup_kdc_request with authenticate sub works');
%cookies = %{ $weblogin->{request}->proxy_cookies };
is (scalar (keys %cookies), 1, '... and there is one cookie set');
@types = keys %cookies;
is ($types[0], 'remuser', '... which is a remuser cookie');
# FIXME: We can't test the session factor since there's no way to get at it.
$token_string = $cookies{remuser};
$token = WebAuth::Token->new ($wa, $token_string, $keyring);
isa_ok ($token, 'WebAuth::Token::WebKDCProxy', 'token');
is ($token->subject, 'authtest', '... with correct subject');
is ($token->proxy_type, 'remuser', '... and proxy type');
is ($token->proxy_subject, 'WEBKDC:remuser', '... and proxy subject');
is ($token->data, 'authtest', '... and data');
is ($token->initial_factors, 'p', '... and initial factors');
is ($token->loa, 2, '... and LoA');
ok (abs ($token->expiration - time - $WebKDC::Config::REMUSER_EXPIRES) < 2,
    '... and expiration is in the right range');

unlink ('krb5cc_test', 't/data/test.keyring', 't/data/test.keyring.lock');
rmtree ('./t/tmp');
