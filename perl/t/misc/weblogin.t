#!/usr/bin/perl
#
# Miscellaneous toolkit tests for WebLogin
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use warnings;
use strict;
use Test::More tests => 12;

BEGIN {
    use_ok ('WebLogin', '1.04');
    use_ok ('WebKDC::WebResponse', '1.03');
}

# Test principal escaping.
my $weblogin = WebLogin->new;
my $principal         = 'test\guy@test.org';
my $escaped_principal = 'test\\\guy\@test.org';
is ($weblogin->krb5_escape ($principal), $escaped_principal,
    'krb5_escape works properly');

# Test page name mappings.
my %pages = (test => 'test.tmpl');
$weblogin = WebLogin->new (PARAMS => { pages => \%pages });
$weblogin->param ('logging', 0);
is ($weblogin->get_pagename('test'), 'test.tmpl',
    'Getting a page filename from a defined type works');
is ($weblogin->get_pagename('none'), '',
    '... and getting a page filename from an unknown type fails');

# Test return URL functions.
$weblogin = WebLogin->new;
$weblogin->{response} = WebKDC::WebResponse->new;
$weblogin->{response}->return_url ('https://www.test.org/stuff/foobar.html');
my $retval = $weblogin->parse_uri;
is ($retval, 0, 'Setting the return URL succeeded');
is ($weblogin->param ('pretty_uri'), 'https://www.test.org',
    '... and returned the correct URL');
$weblogin->{response}->return_url ('file:///tmp/foobar.html');
$retval = $weblogin->parse_uri;
is ($retval, 1, '... and failed on a bad URL');

# Test remember_login and fallback functionality.
$WebKDC::Config::REMEMBER_FALLBACK = 'yes';
$weblogin = WebLogin->new;
$retval = $weblogin->remember_login;
is ($retval, 'yes', 'remember_login has correct fallback');
$weblogin->query->param ('remember_login', 'no');
$retval = $weblogin->remember_login;
is ($retval, 'no', '... and continues to when given a value');
$WebKDC::Config::REMEMBER_FALLBACK = 'no';
$weblogin = WebLogin->new;
$retval = $weblogin->remember_login;
is ($retval, 'no', '... and still works when we reverse the fallback');
$weblogin->query->param ('remember_login', 'yes');
$retval = $weblogin->remember_login;
is ($retval, 'yes', '... and continues to when given a value');
