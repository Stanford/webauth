#!/usr/bin/perl
#
# Test suite for webauth token object creation errors
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

use Test::More tests => 4;

BEGIN { use_ok ('WebAuth', 3.06, qw(:const)) }
BEGIN { use_ok ('WebAuth::Token') }

# Check that sending WebAuth::Key different objects than it expect fails.
my $token;
eval {
    $token = WebAuth::Token::new('WebAuth::Token', '', undef);
};
like ($@, qr{^WebAuth::Token cannot be used directly}ms,
    'Trying to use WebAuth::Token directly fails');
eval {
    $token = WebAuth::Token->new('WebAuth::NotKey', 'a');
};
like ($@, qr{^second argument must be a WebAuth object}ms,
    '... as does not giving it a WebAuth object');
