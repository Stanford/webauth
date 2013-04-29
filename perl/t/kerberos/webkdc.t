#!/usr/bin/perl -w
#
# Tests for WebKDC.pm, currently meant only for login tests.
#
# This test is performed against a running WebKDC and therefore currently
# requires huge amounts of setup, including a copy of the WebKDC keyring.  It
# also tests authentication with expired passwords, which requires access to
# remctl commands to set password expiration on an account using the
# kadmin-remctl package.  Accordingly, we will almost always skip this test.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2010, 2012
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

use lib ('t/lib', 'lib', 'blib/arch');
use Util qw (contents get_userinfo);

use POSIX qw(strftime);
use WebAuth qw(3.00);
use WebKDC ();
use WebKDC::Config;
use WebLogin;

use Test::More;

# We need a user account and password.
plan skip_all => 'Kerberos tests not configured'
    unless -f 't/data/test.password';

# We need a keyring path and a principal suitable for use as a WebAuth client.
plan skip_all => 'no WebKDC configuration found'
    unless (-f 't/data/test.keyring.path'
            && -f 't/data/test.principal-webauth');

# Apparently we can actually test, at least somewhat.
plan tests => 3;

#############################################################################
# Wrapper functions
#############################################################################

# Initialize the weblogin object, as we'll have to keep touching this over
# and again.
sub init_weblogin {
    my ($username, $password, $st_base64, $rt_base64, $pages) = @_;

    my $query = CGI->new;
    $query->param ('username', $username);
    $query->param ('password', $password);
    $query->param ('ST', $st_base64);
    $query->param ('RT', $rt_base64);

    # Load the weblogin object, with undefined template (we don't do output).
    my $weblogin = WebLogin->new (PARAMS => { pages => $pages });
    $weblogin->param ('debug', 0);
    $weblogin->param ('logging', 0);
    $weblogin->param ('script_name', '/login');
    $weblogin->query ($query);

    # Normally set during WebKDC::request_token_request.
    $weblogin->{response}->return_url ('https://test.example.org/');
    $weblogin->{response}->subject ($username);
    $weblogin->{response}->response_token ('TestResponse');
    $weblogin->{response}->response_token_type ('id');

    return $weblogin;
}

#############################################################################
# Environment setup
#############################################################################

# Get the username and password to log in with.
my $fname_passwd = 't/data/test.password';
my ($user, $pass) = get_userinfo ($fname_passwd) if -f $fname_passwd;
unless ($user && $pass) {
    die "no test user configuration\n";
}
my $realm = $user;
$realm =~ s/^[^\@]+\@//;

# Miscellaneous config settings.
my $principal = contents ('t/data/test.principal-webauth');
@WebKDC::Config::REMUSER_REALMS = ($realm);

# Set up various ENV variables later used for logging.
$ENV{SERVER_ADDR} = 'localhost';
$ENV{SERVER_PORT} = '443';
$ENV{REMOTE_ADDR} = '127.0.0.1';
$ENV{REMOTE_PORT} = '443';
$ENV{REMOTE_USER} = $user;
$ENV{SCRIPT_NAME} = '/login';

# Make sure we have the path to the actual KDC keyring.  Required since these
# tests must be run on a working KDC.
my $wa = WebAuth->new;
$WebKDC::Config::KEYRING_PATH = contents ('t/data/test.keyring.path');
unless (-r $WebKDC::Config::KEYRING_PATH) {
    die "cannot read $WebKDC::Config::KEYRING_PATH\n";
}
my $keyring = $wa->keyring_read ($WebKDC::Config::KEYRING_PATH);

# Create the ST for testing.
my $random = 'b' x WebAuth::WA_AES_128;
my $key = $wa->key_create (WebAuth::WA_KEY_AES, WebAuth::WA_AES_128, $random);
my $st = WebAuth::Token::WebKDCService->new ($wa);
$st->subject ("krb5:$principal");
$st->session_key ($random);
$st->creation (time);
$st->expiration (time + 3600);
my $st_base64 = $st->encode ($keyring);

# Create the RT for testing.
my $client_keyring = $wa->keyring_new ($key);
my $rt = WebAuth::Token::Request->new ($wa);
$rt->type ('id');
$rt->auth ('webkdc');
$rt->return_url ('https://test.example.org/');
$rt->creation (time);
my $rt_base64 = $rt->encode ($client_keyring);

#############################################################################
# Actual tests
#############################################################################

# Get and set up a WebLogin object.  Actual testing of this is done in
# weblogin.t.
my ($status, $error);
my %pages = ();
my $weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%pages);
$status = $weblogin->setup_kdc_request;

# Test working username/password.
($status, $error)
    = WebKDC::make_request_token_request ($weblogin->{request},
                                          $weblogin->{response});
is ($status, WebKDC::WK_SUCCESS, 'Creating token for valid user works');

# Test username and bad password (append a letter to known good password).
$weblogin = init_weblogin ($user, $pass.'a', $st_base64, $rt_base64, \%pages);
$status = $weblogin->setup_kdc_request;
($status, $error)
    = WebKDC::make_request_token_request ($weblogin->{request},
                                          $weblogin->{response});
is ($status, WebKDC::WK_ERR_LOGIN_FAILED, 'Failing on invalid password works');

# Test for handling of an expired password.
SKIP: {
    eval { require Net::Remctl };
    skip 'Net::Remctl not available', 1 if $@;
    skip 'no kadmin-remctl configuration found', 1
        unless -r 't/data/test.kadmin-remctl.server';

    # Set the password expiration to yesterday, in order to test a user with
    # expired password.  We have to strip the realm from the user since the
    # kadmin-remctl interface doesn't support realms.
    my $yesterday = strftime ('%Y-%m-%d %T', localtime (time - 60 * 60 * 24));
    my $server = contents ('t/data/test.kadmin-remctl.server');
    my $short = $user;
    $short =~ s/\@.*//;
    my $result = Net::Remctl::remctl ($server, 0, '', 'kadmin',
                                      'pwexpiration', $short, $yesterday);
    skip "cannot set $short to expired", 1
        if (defined ($result->error) || $result->status != 0);

    # Authenticate.  We should get back an expired credential error.
    $weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%pages);
    $status = $weblogin->setup_kdc_request;
    ($status, $error)
        = WebKDC::make_request_token_request ($weblogin->{request},
                                              $weblogin->{response});
    is ($status, WebKDC::WK_ERR_CREDS_EXPIRED,
        'Failing on expired password works');

    # Disable password expiration for this user again.  Only do so if the
    # first change succeeded.
    if (!$result->error) {
        my $result = Net::Remctl::remctl ($server, 0, '', 'kadmin',
                                          'pwexpiration', $short, 'never');
        if ($result->error) {
            warn $result->error, "\n";
        } elsif ($result->stderr) {
            warn $result->stderr;
        }
    }
}
