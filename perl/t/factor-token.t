#!/usr/bin/perl
#
# Tests for factor token handling
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

use Test::More tests => 11;

# Ensure we don't pick up the system webkdc.conf.
BEGIN { $ENV{WEBKDC_CONFIG} = '/nonexistent' }

use lib ('t/lib', 'lib', 'blib/arch');
use Util qw (contents get_userinfo getcreds create_keyring);

use CGI;
use CGI::Cookie;
use Date::Parse;
use WebAuth qw(3.00 :const);
use WebKDC ();
use WebKDC::Config;
use WebLogin;

# Set our method to not have password tests complain.
$ENV{REQUEST_METHOD} = 'POST';

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

#############################################################################
# Wrapper functions
#############################################################################

# Initialize the weblogin object, as we'll have to keep touching this over
# and again.
sub init_weblogin {
    my $query = CGI->new ({});
    $query->request_method ('POST');

    my $weblogin = WebLogin->new (QUERY  => $query);
    $weblogin->cgiapp_prerun;
    $weblogin->param ('debug', 0);
    $weblogin->param ('logging', 0);
    $weblogin->param ('script_name', '/login');

    return $weblogin;
}

#############################################################################
# Environment setup
#############################################################################

# Disable all the memcached stuff for now.
@WebKDC::Config::MEMCACHED_SERVERS = ();

# Expiration to test against, as epoch seconds and text.
my $expires_epoch = 1577865600;
my $expires_text  = 'Wed, 01-Jan-2020 08:00:00 GMT';

#############################################################################
# Tests
#############################################################################

my ($status, $error);

# Set up the KDC request with a factor cookie and verify it was found.
my $weblogin = init_weblogin;
my $cookie = CGI::Cookie->new (-name => 'webauth_wft', -value => 'test');
$ENV{HTTP_COOKIE} = "$cookie";
my %cart = CGI::Cookie->fetch;
$status = $weblogin->setup_kdc_request (%cart);
ok (!$status, 'setup_kdc_request with factor cookie works');
ok ($weblogin->{request}->factor_token, '...and factor_token set');
is ($weblogin->{request}->factor_token, 'test', '...to the right value');

# Check again with no factor cookie.
$weblogin = init_weblogin;
$status = $weblogin->setup_kdc_request;
$ENV{HTTP_COOKIE} = "";
ok (!$status, 'setup_kdc_request without factor cookie works');
is ($weblogin->{request}->factor_token, undef, '...and factor_token not set');

# Check to see if we set a factor cookie when we should.  Requires digging
# into the CGI::Application object a little.
$weblogin = init_weblogin;
$status = $weblogin->setup_kdc_request;
$weblogin->{response}->factor_expiration ($expires_epoch);
%cart = (webauth_wft => 'test');
$weblogin->print_headers (\%cart, '', '');
$cookie = undef;
for my $c (@{ $weblogin->{'__HEADER_PROPS'}{'-cookie'} }) {
    if ($c->name eq 'webauth_wft') {
        $cookie = $c;
    }
}
is ($cookie->name, 'webauth_wft', 'Factor cookie was set');
is ($cookie->expires, $expires_text, '...with the correct expiration time');

# Check clearing the webauth cookie by giving it an empty value.
$weblogin = init_weblogin;
$status = $weblogin->setup_kdc_request;
$weblogin->{response}->factor_expiration ($expires_epoch);
%cart = (webauth_wft => '');
$weblogin->print_headers (\%cart, '', '');
$cookie = undef;
for my $c (@{ $weblogin->{'__HEADER_PROPS'}{'-cookie'} }) {
    if ($c->name eq 'webauth_wft') {
        $cookie = $c;
    }
}
is ($cookie->name, 'webauth_wft', 'Factor cookie was set');
my $expires = str2time ($cookie->expires);
is ($expires, time - 60 * 60 * 24, '...with the correct expiration time');

# Check clearing the webauth cookie by setting the public computer checkbox.
$weblogin = init_weblogin;
$status = $weblogin->setup_kdc_request;
$weblogin->query->param (public_computer => 1);
$weblogin->{response}->factor_expiration ($expires_epoch);
%cart = (webauth_wft => 'test');
$weblogin->print_headers (\%cart, '', '');
$cookie = undef;
for my $c (@{ $weblogin->{'__HEADER_PROPS'}{'-cookie'} }) {
    if ($c->name eq 'webauth_wft') {
        $cookie = $c;
    }
}
is ($cookie->name, 'webauth_wft', 'Factor cookie on public computer was set');
$expires = str2time ($cookie->expires);
is ($expires, time - 60 * 60 * 24, '...and set to expire now');
