#!/usr/bin/perl
#
# Test suite for WebKDC::WebKDCException.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use warnings;
use strict;

use Test::More tests => 9;

BEGIN {
    use_ok ('WebKDC::WebKDCException', '1.05');
}

# Generic test data.
my $status      = WK_ERR_LOGIN_FAILED;
my $mesg        = 'User login failed';
my $pec         = 999;
my $data        = 'Test data';
my $verbose     = "WebKDC::WebKDCException LOGIN_FAILED: $mesg";
my $verbose_pec = $verbose . ": WebKDC errorCode: $pec";

# Create a WebKDC::WebKDCException object with default settings.
my $exception = WebKDC::WebKDCException->new ($status, $mesg, $pec, $data);
isa_ok ($exception, 'WebKDC::WebKDCException', 'Exception object');
is ($exception->status, $status, 'Status');
is ($exception->message, $mesg, 'Error message');
is ($exception->error_code, $pec, 'Proxy error code');
is ($exception->data, $data, 'Data');

is ($exception->verbose_message, $verbose_pec, 'Verbose message');
is ("$exception", $verbose_pec, 'Stringification');

$exception->{pec} = undef;
is ($exception->verbose_message, $verbose, 'Verbose message with no pec');
