#!/usr/bin/perl -w
#
# Test suite for miscellaneous WebAuth Perl bindings.
#
# Written by Roland Schemers
# Rewritten by Jon Robertson <jonrober@stanford.edu>
# Copyright 2002, 2003, 2005, 2009, 2010, 2012
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;

use Test::More;

use lib ('t/lib', 'lib', 'blib/arch');
use WebAuth qw(3.00 :const);
use WebAuth::Key ();

BEGIN { plan tests => 50 }

# Do all tests in an eval block to catch otherwise-uncaught exceptions.
eval {
    sub compareHashes;
    my ($len, $output);
    my $wa = WebAuth->new;

    # Hardcode a few constant tests
    is (WA_AES_128, 16, 'Check for constant WA_AES_128 works');
    is (WebAuth::WA_AES_192, 24, ' and WA_AES_192');
    is (WebAuth::WA_AES_256, 32, ' and WA_AES_256');
    is ('t', WebAuth::WA_TK_TOKEN_TYPE, ' and WA_TK_TOKEN_TYPE');

    # base64 tests
    is ($wa->base64_encode ('hello'), 'aGVsbG8=',
        'base64 encoding works');
    is ($wa->base64_decode ('aGVsbG8='), 'hello',
        ' as does decoding');
    is ($wa->base64_decode ($wa->base64_encode ('\000\001\002')),
        '\000\001\002', ' and encoding and decoding in turn');

    # Test failure by feeding a bad base64 string.
    eval { $wa->base64_decode ('axc') };
    ok ($@->isa ('WebAuth::Exception'), 'Decoding a bad base64 string fails');
    is ($@->status, WA_ERR_CORRUPT, ' with corrupt string error');

    # Hex tests
    is ($wa->hex_encode ('\000\001\002\003\004\005'),
        '5c3030305c3030315c3030325c3030335c3030345c303035',
        'hex encoding a number works');
    is ($wa->hex_decode ('5c3030305c3030315c3030325c3030335c3030345c303035'),
        '\000\001\002\003\004\005', ' as is decoding');
    is ($wa->hex_encode ('hello'), '68656c6c6f',
        'hex encoding a string works');
    is ($wa->hex_decode ('68656c6c6f'), 'hello', ' as is decoding');

    # Hex failure by giving a bad Hex value.
    eval { $wa->hex_decode ('FOOBAR') };
    ok ($@->isa ('WebAuth::Exception'), 'hex decoding fails');
    is ($@->status, WA_ERR_CORRUPT, ' with the correct error');

    # Attr tests
    is ($wa->attrs_encode ({'x' => '1' }), 'x=1;',
        'encoding an attr works');
    is ($wa->attrs_encode ({'x' => ';' }), 'x=;;;',
        ' and a more difficult attr');
    is ($wa->attrs_encode ({'x' => '1;'}), 'x=1;;;',
        ' and one more difficult still');

    # Try and encode attrs, followed by a decode and compare the hashes.
    my $a = {'x' => '1', 'y' => 'hello', 'z' => 'goodbye'};
    my $ea = 'x=1;y=hello;z=goodbye;';
    $b = $wa->attrs_decode ($ea);
    is (compareHashes ($a, $b), 1, ' and a multi-value hash');

    # Attr failures.
    eval { $b = $wa->attrs_decode ('x=1;y=23') };
    ok ($@->isa ('WebAuth::Exception'), 'decoding an invalid attr fails');
    is ($@->status (), WebAuth::WA_ERR_CORRUPT, ' with the right error');
    eval { $b = $wa->attrs_decode('x=1;zr') };
    ok ($@->isa ('WebAuth::Exception'), ' and another invalid attr fails');
    is ($@->status (), WebAuth::WA_ERR_CORRUPT,
        ' also with the right error');

    # Key tests.
    my $bytes = 'a' x WebAuth::WA_AES_128;
    my $key = $wa->key_create (WebAuth::WA_KEY_AES, WebAuth::WA_AES_128,
                               $bytes);
    ok (defined ($key), 'creating a key works');
    ok ($key->isa ('WebAuth::Key'), ' and is of the right type');
    is ($key->type, WebAuth::WA_KEY_AES, ' and the right key type');
    is ($key->length, WebAuth::WA_AES_128, ' and the right key length');
    is ($key->data, $bytes, ' and the right key data');
    $key = $wa->key_create (WebAuth::WA_KEY_AES, WebAuth::WA_AES_128);
    ok (defined ($key), ' and creating a random key also works');
    ok ($key->isa ('WebAuth::Key'), ' and is of the right type');
    is ($key->type, WebAuth::WA_KEY_AES, ' and the right key type');
    is ($key->length, WebAuth::WA_AES_128, ' and the right key length');

    # Try using the helper constructor instead.
    $key = WebAuth::Key->new ($wa, WebAuth::WA_KEY_AES, WebAuth::WA_AES_128,
                              $bytes);
    ok (defined ($key), 'creating a key works');
    ok ($key->isa ('WebAuth::Key'), ' and is of the right type');
    is ($key->type, WebAuth::WA_KEY_AES, ' and the right key type');
    is ($key->length, WebAuth::WA_AES_128, ' and the right key length');
    is ($key->data, $bytes, ' and the right key data');
    $key = WebAuth::Key->new ($wa, WebAuth::WA_KEY_AES, WebAuth::WA_AES_128);
    ok (defined ($key), 'creating a key works');
    ok ($key->isa ('WebAuth::Key'), ' and is of the right type');
    is ($key->type, WebAuth::WA_KEY_AES, ' and the right key type');
    is ($key->length, WebAuth::WA_AES_128, ' and the right key length');

    # Invalid key material length (and test WebAuth::Exception).
    $key = eval { $wa->key_create (WebAuth::WA_KEY_AES, 2, $bytes) };
    ok ($@->isa ('WebAuth::Exception'),
        ' and creating one of invalid length fails');
    like ($@, qr/^webauth_key_create:\ invalid\ argument\ to\ function
          \ \(unsupported\ key\ size\ 2\)\ at\ /x, ' with correct exception');
    is ($@->status, WebAuth::WA_ERR_INVALID, ' and correct status');
    is ($@->error_message,
        'invalid argument to function (unsupported key size 2)',
        ' and correct error message');
    is ($@->detail_message, 'webauth_key_create', ' and correct detail');

    # Test reading a new keyring file.
    $key = $wa->key_create (WebAuth::WA_KEY_AES, WebAuth::WA_AES_128);
    my $ring = $wa->keyring_new (32);
    ok (defined ($ring), 'creating a keyring works');
    ok ($ring->isa ('WebAuth::Keyring'), ' and is of the right type');
    my $curr = time;
    $ring->add ($curr, $curr, $key);
    $ring->write ('webauth_keyring');
    my $ring2 = $wa->keyring_read ('webauth_keyring');
    ok ($ring2->isa ('WebAuth::Keyring'), 'reading a new keyring works');
    $ring->write ('webauth_keyring2');

    unlink ('webauth_keyring') if -f 'webauth_keyring';
    unlink ('webauth_keyring2') if -f 'webauth_keyring2';
};
is ($@, '', 'No unexpected exceptions');

# A short hash comparison function in order to verify that hash output is as
# expected.
sub compareHashes {
    my $a = shift;
    my $b = shift;

    my @akeys = sort keys %$a;
    my @bkeys = sort keys %$b;

    my $an = scalar @akeys;
    my $bn = scalar @bkeys;

    my ($i, $key);

    if ($an != $bn) {
	return 0;
    }

    # Compare keys
    for ($i=0; $i < $an; $i++) {
	if ($akeys[$i] ne $bkeys[$i]) {
	    return 0;
	}
    }

    # Compare values
    foreach $key (@akeys) {
	if ($$a{$key} ne $$b{$key}) {
	    return 0;
	}
    }
    return 1;
}
