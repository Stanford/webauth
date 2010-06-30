#!/usr/bin/perl -w
#
# Basic tests for WebKDC::Config.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2010 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

use strict;
use Test::More tests => 9;

# Silence warnings since we're not using use.
package WebKDC::Config;
our $BYPASS_CONFIRM;
our $EXPIRING_PW_SERVER;
our $KEYRING_PATH;
our $REMUSER_ENABLED;
our $REMUSER_EXPIRES;
our $REMUSER_REALMS;
our $REMUSER_REDIRECT;
our $TEMPLATE_PATH;
package main;

BEGIN {
    $ENV{WEBKDC_CONFIG} = 't/data/webkdc.conf';
}
use_ok ('WebKDC::Config');

# Compare the values there to the values we know.
is ($WebKDC::Config::KEYRING_PATH, 't/data/test.keyring',
    'KEYRING_PATH correctly set');
is ($WebKDC::Config::TEMPLATE_PATH, 't/data/templates',
    'TEMPLATE_PATH correctly set');
is ($WebKDC::Config::REMUSER_ENABLED, 1,
    'REMUSER_ENABLED correctly set');
is ($WebKDC::Config::REMUSER_EXPIRES, 60 * 60 * 8,
    'REMUSER_EXPIRES correctly set');

my @realms = ('TEST.ORG', 'WIN.TEST.ORG');
is (@WebKDC::Config::REMUSER_REALMS, @realms,
    'REMUSER_REALMS correctly set');
is ($WebKDC::Config::REMUSER_REDIRECT, '/login-spnego',
    'REMUSER_REDIRECT correctly set');
is ($WebKDC::Config::BYPASS_CONFIRM, undef,
    'BYPASS_CONFIRM not set');
is ($WebKDC::Config::EXPIRING_PW_SERVER, 'localhost',
    'EXPIRING_PW_SERVER correctly set');
