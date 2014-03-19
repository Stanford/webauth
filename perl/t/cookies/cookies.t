#!/usr/bin/perl
#
# Tests for cookie setting
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

use Test::More tests => 12;

# Ensure we don't pick up the system webkdc.conf.
BEGIN { $ENV{WEBKDC_CONFIG} = '/nonexistent' }

use lib ('t/lib', 'lib', 'blib/arch');

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

my $cookie_name = 'webauth_wpt_test';

#############################################################################
# Tests
#############################################################################

my ($status, $error);

# Check to see if we set a cookie when we should.  Requires digging into the
# CGI::Application object a little.
my $weblogin = init_weblogin;
$status = $weblogin->setup_kdc_request;
$weblogin->{response}->cookie ($cookie_name, 'test', $expires_epoch);
my %args = (cookies => $weblogin->{response}->cookies);
$weblogin->print_headers (\%args);
my $cookie = undef;
for my $c (@{ $weblogin->{'__HEADER_PROPS'}{'-cookie'} }) {
    if ($c->name eq $cookie_name) {
        $cookie = $c;
    }
}
is ($cookie->name, $cookie_name, 'SSO cookie was set');
is ($cookie->expires, undef, '... with the default lifetime');

# Check clearing an SSO cookie by giving it an empty value.
$weblogin = init_weblogin;
$status = $weblogin->setup_kdc_request;
$weblogin->{response}->cookie ($cookie_name, '', $expires_epoch);
%args = (cookies => $weblogin->{response}->cookies);
$weblogin->print_headers (\%args);
$cookie = undef;
for my $c (@{ $weblogin->{'__HEADER_PROPS'}{'-cookie'} }) {
    if ($c->name eq $cookie_name) {
        $cookie = $c;
    }
}
is ($cookie->name, $cookie_name, 'SSO cookie with no content was set');
my $expires = str2time ($cookie->expires);
ok ($expires >= time - 60 * 60 * 24 - 2 && $expires <= time - 60 * 60 * 24,
    '... and set to expire immediately');

# Check clearing an SSO cookie by setting the public computer checkbox
# and nothing else.  That shouldn't clear it, as it should only be cleared
# when the login proces is over.
$weblogin = init_weblogin;
$status = $weblogin->setup_kdc_request;
$weblogin->query->param (remember_login => 'no');
$weblogin->{response}->cookie ($cookie_name, 'test', $expires_epoch);
%args = (cookies => $weblogin->{response}->cookies);
$weblogin->print_headers (\%args);
$cookie = undef;
for my $c (@{ $weblogin->{'__HEADER_PROPS'}{'-cookie'} }) {
    if ($c->name eq $cookie_name) {
        $cookie = $c;
    }
}
is ($cookie->name, $cookie_name,
    'SSO cookie on public computer during normal login process was set');
is ($cookie->expires, undef, '... with the default lifetime');

# Check clearing an SSO cookie by setting the public computer checkbox
# and a redirect URL.  This simulates a redirect without showing the confirm
# page.
$weblogin = init_weblogin;
$status = $weblogin->setup_kdc_request;
$weblogin->query->param (remember_login => 'no');
$weblogin->{response}->cookie ($cookie_name, 'test', $expires_epoch);
%args = (confirm_page => 1,
         cookies      => $weblogin->{response}->cookies,
         return_url   => 'http://www.test.com');
$weblogin->print_headers (\%args);
$cookie = undef;
for my $c (@{ $weblogin->{'__HEADER_PROPS'}{'-cookie'} }) {
    if ($c->name eq $cookie_name) {
        $cookie = $c;
    }
}
is ($cookie->name, $cookie_name,
    'SSO cookie on public computer redirecting without confirm was set');
$expires = str2time ($cookie->expires);
is ($expires, time - 60 * 60 * 24, '... and set to expire immediately');

# Check clearing an SSO cookie by setting the public computer checkbox,
# and the flag for having come from the confirm page.  This should clear the
# cookie.
$weblogin = init_weblogin;
$status = $weblogin->setup_kdc_request;
$weblogin->query->param (remember_login => 'no');
$weblogin->{response}->cookie ($cookie_name, 'test', $expires_epoch);
%args = (cookies      => $weblogin->{response}->cookies,
         confirm_page => 1);
$weblogin->print_headers (\%args);
$cookie = undef;
for my $c (@{ $weblogin->{'__HEADER_PROPS'}{'-cookie'} }) {
    if ($c->name eq $cookie_name) {
        $cookie = $c;
    }
}
is ($cookie->name, $cookie_name,
    'SSO cookie on public computer on confirm page');
$expires = str2time ($cookie->expires);
is ($expires, time - 60 * 60 * 24, '... and set to expire immediately');

# Check whether a cookie that's set in the browser's cookie jar will be
# correctly cleared even if the response doesn't contain any cookies.
$weblogin = init_weblogin;
$status = $weblogin->setup_kdc_request;
$weblogin->query->param (remember_login => 'no');
%args = (confirm_page => 1);
{
    local $ENV{HTTP_COOKIE} = "$cookie_name=something";
    $weblogin->print_headers (\%args);
}
$cookie = undef;
for my $c (@{ $weblogin->{'__HEADER_PROPS'}{'-cookie'} }) {
    if ($c->name eq $cookie_name) {
        $cookie = $c;
    }
}
is ($cookie->name, $cookie_name, 'Expiring browser cookie not sent by WebKDC');
$expires = str2time ($cookie->expires);
is ($expires, time - 60 * 60 * 24, '... and set to expire immediately');
