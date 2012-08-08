#!/usr/bin/perl -w
#
# Test suite for WebAuth::Exception.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2012
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;

use Test::More tests => 9;

BEGIN {
    use_ok ('WebAuth', '3.02', qw/WA_ERR_INVALID/);
    use_ok ('WebAuth::Exception', '3.01');
}

# Create a WebAuth context and do something that produces an exception.
my $wa = WebAuth->new;
eval { $wa->key_create (42, 1) };
ok ($@, 'key_create produces an exception as expected');
my $exception = $@;
isa_ok ($exception, 'WebAuth::Exception', 'Exception object');
is ($exception->status, WA_ERR_INVALID, 'Status');
my $message = 'invalid argument to function (unsupported key type 42)';
is ($exception->error_message, $message, 'Error message');
is ($exception->detail_message, 'webauth_key_create', 'Detail message');
like ($exception->verbose_message, qr/^webauth_key_create: \Q$message\E at /,
      'Verbose message');
like ("$@", qr/^webauth_key_create: \Q$message\E at /, 'Stringification');
my $string = "$@";
#ok ($@ cmp $string, 'cmp');
