#!/usr/bin/perl
#
# Test token decoding via the Perl API.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2012
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

use lib ('t/lib', 'lib', 'blib/arch');
use RRA::TAP::Automake qw(test_file_path);
use Util qw(contents);

use Test::More tests => 10;

use WebAuth ();
BEGIN {
    use_ok ('WebAuth::Token::App');
}

sub read_token {
    my ($token) = @_;
    my $path = test_file_path ("data/tokens/$token")
        or BAIL_OUT ("cannot find data/tokens/$token");
    return contents ($path);
}

my $wa = WebAuth->new;
my $path = test_file_path ("data/keyring")
    or BAIL_OUT ('cannot find data/keyring');
my $keyring = WebAuth::Keyring->read_file ($path);

# WebAuth::Token::App app-ok
my $data = read_token ('app-ok');
my $object = $wa->token_decode ($data, $keyring);
isa_ok ($object, 'WebAuth::Token::App');
is ($object->subject, 'testuser', '... app-ok subject');
is ($object->last_used, 1308777930, '... app-ok last used');
is ($object->session_key, undef, '... app-ok session key');
is ($object->initial_factors, 'p', '... app-ok initial factors');
is ($object->session_factors, 'c', '... app-ok session factors');
is ($object->loa, 1, '... app-ok loa');
is ($object->creation, 1308777900, '... app-ok creation');
is ($object->expiration, 2147483600, '... app-ok expiration');
