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

use Test::More tests => 130;

use WebAuth ();
BEGIN {
    use_ok ('WebAuth::Token::App');
    use_ok ('WebAuth::Token::Cred');
    use_ok ('WebAuth::Token::Error');
    use_ok ('WebAuth::Token::Id');
    use_ok ('WebAuth::Token::Login');
    use_ok ('WebAuth::Token::Proxy');
    use_ok ('WebAuth::Token::Request');
    use_ok ('WebAuth::Token::WebKDCProxy');
    use_ok ('WebAuth::Token::WebKDCService');
}

# These will be loaded from the configuration file.
our %TOKENS_GOOD;
our %TOKENS_ERROR;
our %TOKENS_BAD;

# Read a token from a test file and return it without the trailing newline.
sub read_token {
    my ($token) = @_;
    my $path = test_file_path ("data/tokens/$token")
        or BAIL_OUT ("cannot find data/tokens/$token");
    return contents ($path);
}

# General setup.
my $wa = WebAuth->new;
my $path = test_file_path ("data/keyring")
    or BAIL_OUT ('cannot find data/keyring');
my $keyring = WebAuth::Keyring->read_file ($path);
$path = test_file_path ("data/tokens.conf");
require $path or BAIL_OUT ("cannot load data/tokens.conf");

# Loop through the good tokens, load the named token, and check its attributes
# against the expected attributes from the configuration file.
for my $name (sort keys %TOKENS_GOOD) {
    my $data = read_token ($name);
    my $object = $wa->token_decode ($data, $keyring);
    isa_ok ($object, $TOKENS_GOOD{$name}[0]);
    my $attrs = $TOKENS_GOOD{$name}[1];
    for my $attr (sort keys %$attrs) {
        is ($object->$attr, $attrs->{$attr}, "... $name $attr");
    }
}
