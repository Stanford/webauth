#!/usr/bin/perl -w
#
# Tests for WebKDC.pm, currently meant only for login tests.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2010
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

use lib ('t/lib', 'lib', 'blib/arch');
use Util qw (contents get_userinfo);

use WebAuth qw(:base64 :const :krb5 :key);
use WebKDC ();
use WebKDC::Config;
use WebLogin;

use Test::More;

# We need remctld and Net::Remctl.
my $no_remctl = 0;
my @path = (split (':', $ENV{PATH}), '/usr/local/sbin', '/usr/sbin');
my ($remctld) = grep { -x $_ } map { "$_/remctld" } @path;
$no_remctl = 1 unless $remctld;
eval { require Net::Remctl };
$no_remctl = 1 if $@;

# Check for a valid kerberos config.
if (! -f 't/data/test.keyring.path' || ! -f 't/data/test.password'
    || ! -f 't/data/test.principal') {

    plan skip_all => 'no kerberos configuration found';
} elsif ($no_remctl) {
    plan skip_all => 'Net::Remctl not available';
} else {
    plan tests => 3;
}

#############################################################################
# Wrapper functions
#############################################################################

# Initialize the weblogin object, as we'll have to keep touching this over
# and again.
sub init_weblogin {
    my ($username, $password, $st_base64, $rt_base64, $pages) = @_;
    for (keys %{$pages}) {
        $pages->{$_}->clear_params;
    }

    my $query = CGI->new;
    $query->param ('username', $username);
    $query->param ('password', $password);
    $query->param ('ST', $st_base64);
    $query->param ('RT', $rt_base64);

    my $weblogin = WebLogin->new ($query, $pages);
    $weblogin->{debug} = 0;
    $weblogin->{logging} = 0;
    $weblogin->{script_name} = '/login';

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

# Miscellaneous config settings.
my $principal = contents ('t/data/test.principal');
@WebKDC::Config::REMUSER_REALMS   = ();

# Set up various ENV variables later used for logging.
$ENV{SERVER_ADDR} = 'localhost';
$ENV{SERVER_PORT} = '443';
$ENV{REMOTE_ADDR} = '127.0.0.1';
$ENV{REMOTE_PORT} = '443';
$ENV{REMOTE_USER} = $user;
$ENV{SCRIPT_NAME} = '/login';

# Make sure we have the path to the actual KDC keyring.  Required since these
# tests must be run on a working KDC.
if (-e 't/data/test.keyring.path') {
    $WebKDC::Config::KEYRING_PATH = contents ('t/data/test.keyring.path');
}
if (!$WebKDC::Config::KEYRING_PATH) {
    die "could not find server keyring path\n";
}
my $keyring = keyring_read_file ($WebKDC::Config::KEYRING_PATH);

# Create the ST for testing.
my $random = WebAuth::random_key (WebAuth::WA_AES_128);
my $key = WebAuth::key_create (WebAuth::WA_AES_KEY, $random);
my $st = WebKDC::WebKDCServiceToken->new;
$st->session_key ($random);
$st->subject ("krb5:$principal");
$st->creation_time (time);
$st->expiration_time (time + 3600);
my $st_base64 = base64_encode ($st->to_token ($keyring));

# Create the RT for testing.
my $rt = WebKDC::RequestToken->new;
$rt->creation_time (time);
$rt->subject_auth ('webkdc');
$rt->requested_token_type ('id');
$rt->return_url ('https://test.example.org/');
my $rt_base64 = base64_encode ($rt->to_token ($key));

#############################################################################
# Actual tests
#############################################################################

# Pass the information along to the WebKDC and get the response.
TODO: {
    todo_skip 'WebKDC tests not yet debugged, also require working KDC for '
        .'the tests to run on, and a kadmin-remctl server for testing '
        .'password expiration', 3;

    # Get and set up a WebLogin object.  Actual testing of this is done in
    # weblogin.t.
    my ($status, $error);
    my %pages = ();
    my $weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64,
                                  \%pages);
    $status = $weblogin->setup_kdc_request;

    # Test working username/password.
    ($status, $error)
        = WebKDC::make_request_token_request ($weblogin->{request},
                                              $weblogin->{response});
    is ($status, WebKDC::WK_SUCCESS, 'Creating token for valid user works');

    # Test username and bad password (append a letter to known good password).
    $weblogin = init_weblogin ($user, $pass.'a', $st_base64, $rt_base64,
                               \%pages);
    $status = $weblogin->setup_kdc_request;
    ($status, $error)
        = WebKDC::make_request_token_request ($weblogin->{request},
                                              $weblogin->{response});
    is ($status, WebKDC::WK_ERR_LOGIN_FAILED,
        'Failing on invalid password works');

    # Set the password expiration to yesterday, in order to test a user with
    # expired password.
    my $yesterday = time - 60 * 60 * 24;
    my $remctl_server = contents ('t/data/test.kadmin-remctl.server');
    my $result = remctl ($remctl_server, 0, '', 'kadmin', 'pwexpiration',
                         $user, $yesterday);
    skip 'could not contact remctl server', 1 if $result->error;

    # Test user with expired password.
    $weblogin = init_weblogin ($user, $pass, $st_base64, $rt_base64, \%pages);
    $status = $weblogin->setup_kdc_request;
    ($status, $error)
        = WebKDC::make_request_token_request ($weblogin->{request},
                                              $weblogin->{response});
    is ($status, WebKDC::WK_SUCCESS, 'Failing on expired password works');

    # Disable password expiration for this user again.  Only do so if the
    # first change succeeded.
    if (!$result->error) {
        $result = remctl ($remctl_server, 0, '', 'kadmin', 'pwexpiration',
                          $user, 'never');
    }

};
