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

use Test::More tests => 10;

use WebAuth ();
BEGIN {
    use_ok ('WebAuth::Token::App');
    use_ok ('WebAuth::Token::Cred');
}

# Encode a token and then decode it again and confirm that the resulting
# contents match the original token.  Takes the WebAuth object, the token to
# encode, and a keyring to use for encoding and decoding.
sub encode_decode {
    my ($wa, $token, $keyring) = @_;
    eval {
        my $encoded = $wa->token_encode ($token, $keyring);
        ok (length ($encoded) > 1, 'Encoded ' . ref ($token));
        my $result = $wa->token_decode ($encoded, $keyring);
        isa_ok ($result, ref $token);
        is_deeply ($result, $token, '... and decoded token matches');
    };
    is ($@, '', '... with no exceptions');
}

my $wa = WebAuth->new;
my $now = time;
my $key = $wa->key_create (WebAuth::WA_AES_KEY,
                           $wa->random_key (WebAuth::WA_AES_128));
my $keyring = WebAuth::Keyring->new (1);
$keyring->add ($now, $now, $key);

# WebAuth::Token::App full
my $app = WebAuth::Token::App->new;
$app->subject ('testuser');
$app->last_used ($now);
$app->initial_factors ('p,o3,o,m');
$app->session_factors ('c');
$app->loa (3);
$app->creation ($now - 10);
$app->expiration ($now + 60);
encode_decode ($wa, $app, $keyring);

# WebAuth::Token::Cred full
my $cred = WebAuth::Token::Cred->new;
$cred->subject ('testuser');
$cred->type ('krb5');
$cred->service ('webauth/example.com@EXAMPLE.COM');
$cred->data ("s=ome\0da;;ta");
$cred->creation ($now);
$cred->expiration ($now + 60);
encode_decode ($wa, $cred, $keyring);
