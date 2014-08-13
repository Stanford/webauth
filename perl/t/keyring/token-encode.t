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
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2012, 2013, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

use lib ('t/lib', 'lib', 'blib/arch');
use Util qw(create_keyring);

use Test::More tests => 278;

use MIME::Base64 qw(decode_base64);
use WebAuth 3.07 qw(WA_KEY_AES WA_AES_128);
BEGIN {
    use_ok ('WebAuth::Token::App');
    use_ok ('WebAuth::Token::Cred');
    use_ok ('WebAuth::Token::Error');
    use_ok ('WebAuth::Token::Id');
    use_ok ('WebAuth::Token::Login');
    use_ok ('WebAuth::Token::Proxy');
    use_ok ('WebAuth::Token::Request');
    use_ok ('WebAuth::Token::WebKDCFactor');
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

# Encode a time in the token encoding format.  This is mostly a wrapper around
# pack, but we may have to double semicolons.
sub encode_time {
    my ($time) = @_;
    my $result = pack ('N', $time);
    $result =~ s/;/;;/g;
    return $result;
}

# General setup.
my $wa = WebAuth->new;
my $now = time;
my $key = $wa->key_create (WA_KEY_AES, WA_AES_128);
my $keyring = $wa->keyring_new ($key);
require 't/data/tokens.conf' or die "cannot load t/data/tokens.conf\n";

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

# Do some additional spot-checking of a single encoded token and test
# token_decrypt at the same time.
my $app = WebAuth::Token::App->new ($wa);
$app->subject ('test');
$app->creation ($now);
$app->expiration ($now + 60);
my $encoded = $app->encode ($keyring);
my $data = eval { $wa->token_decrypt (decode_base64($encoded), $keyring) };
is ($@, '', 'App token decodes without errors');
my $expected = 't=app;s=test;ct=' . encode_time ($now) . ';et='
    . encode_time ($now + 60) . ';';
is ($data, $expected, 'Encoded form is correct');
