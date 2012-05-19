#!/usr/bin/perl
#
# Test token encoding via the Perl API.
#
# Unfortunately, we can't just encode a token and then confirm that it matches
# a pre-encoded token, since each encoded token gets a unique random nonce.
# Instead, we'll take the less appealing approach of round-tripping a token
# through an encode and decode process and ensure we get the same information
# out the other end.  We separately test the decoding process against
# pre-constructed tokens, so this will hopefully be sufficient.
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
use Util qw(create_keyring);

use Test::More tests => 208;

use WebAuth qw(3.00 WA_AES_KEY WA_AES_128);
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

# Encode a token and then decode it again and confirm that the resulting
# contents match the original token.  Takes the WebAuth object, the token to
# encode, and a keyring to use for encoding and decoding.
#
# Special-case a creation attribute if it exists.  If it's not set in our
# data, the encoding process should set it to the current time.  Note that the
# time can change while we're running the test, so we check it separately and
# then make it match before calling isa_deeply.
sub encode_decode {
    my ($wa, $token, $keyring) = @_;
    eval {
        my $encoded = $token->encode ($keyring);
        ok (length ($encoded) > 1, 'Encoded ' . ref ($token));
        my $result = $wa->token_decode ($encoded, $keyring);
        isa_ok ($result, ref $token);
        if ($token->can ('creation') && !defined ($token->creation)) {
            my $creation = $result->creation;
            my $delta = time - ($result->creation || 0);
            ok ($delta >= 0 && $delta <= 0, '... generated creation');
            $token->creation ($result->creation);
        }
        is_deeply ($result, $token, '... decoded token matches');
    };
    is ($@, '', '... with no exceptions');
}

# General setup.
my $wa = WebAuth->new;
my $now = time;
my $key = $wa->key_create (WA_AES_KEY, WA_AES_128);
my $keyring = $wa->keyring_from_key ($key);
my $path = test_file_path ("data/tokens.conf");
require $path or BAIL_OUT ("cannot load data/tokens.conf");

# Loop through the good tokens, construct a matching token using the Perl
# class, encode it, decode it, and check that the results match.
for my $name (sort keys %TOKENS_GOOD) {
    my ($class, $attrs) = @{ $TOKENS_GOOD{$name} };
    my $token = $class->new ($wa);
    isa_ok ($token, $class);
    for my $attr (sort keys %$attrs) {
        is ($token->$attr ($attrs->{$attr}), $attrs->{$attr},
            "... setting $name $attr");
    }
    encode_decode ($wa, $token, $keyring);
}
