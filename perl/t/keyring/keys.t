#!/usr/bin/perl
#
# Test suite for webauth key functions
#
# Written by Roland Schemers
# Rewritten by Jon Robertson <jonrober@stanford.edu>
# Copyright 2002, 2003, 2005, 2009, 2010, 2012, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

use Test::More tests => 35;

BEGIN { use_ok ('WebAuth', 3.06, qw(:const)) }
BEGIN { use_ok ('WebAuth::Key') }

# Do all tests in an eval block to catch otherwise-uncaught exceptions.
eval {
    my ($len, $output);
    my $wa = WebAuth->new;

    # Hardcode a few constant tests and check with and without importing.
    is (WA_AES_128, 16, 'Check for constant WA_AES_128 works');
    is (WebAuth::WA_AES_192, 24, '... and WA_AES_192');
    is (WebAuth::WA_AES_256, 32, '... and WA_AES_256');

    # Key tests.
    my $bytes = 'a' x WA_AES_128;
    my $key = $wa->key_create (WA_KEY_AES, WA_AES_128, $bytes);
    ok (defined ($key), 'creating a key works');
    ok ($key->isa ('WebAuth::Key'), '... and is of the right type');
    is ($key->type, WA_KEY_AES, '... and the right key type');
    is ($key->length, WA_AES_128, '... and the right key length');
    is ($key->data, $bytes, '... and the right key data');
    $key = $wa->key_create (WA_KEY_AES, WA_AES_128);
    ok (defined ($key), '... and creating a random key also works');
    ok ($key->isa ('WebAuth::Key'), '... and is of the right type');
    is ($key->type, WA_KEY_AES, '... and the right key type');
    is ($key->length, WA_AES_128, '... and the right key length');

    # Try using the helper constructor instead.
    $key = WebAuth::Key->new ($wa, WA_KEY_AES, WA_AES_128, $bytes);
    ok (defined ($key), 'creating a key works');
    ok ($key->isa ('WebAuth::Key'), '... and is of the right type');
    is ($key->type, WA_KEY_AES, '... and the right key type');
    is ($key->length, WA_AES_128, '... and the right key length');
    is ($key->data, $bytes, '... and the right key data');
    $key = WebAuth::Key->new ($wa, WA_KEY_AES, WA_AES_128);
    ok (defined ($key), 'creating a key works');
    ok ($key->isa ('WebAuth::Key'), '... and is of the right type');
    is ($key->type, WA_KEY_AES, '... and the right key type');
    is ($key->length, WA_AES_128, '... and the right key length');

    # Invalid key material length (and test WebAuth::Exception).
    $key = eval { $wa->key_create (WA_KEY_AES, 2, $bytes) };
    ok ($@->isa ('WebAuth::Exception'),
        '... and creating one of invalid length fails');
    like ($@, qr/^webauth_key_create:\ operation\ not\ supported
          \ \(unsupported\ key\ size\ 2\)\ at\ /x,
          '... with correct exception');
    is ($@->status, WA_ERR_UNIMPLEMENTED, '... and correct status');
    is ($@->error_message,
        'operation not supported (unsupported key size 2)',
        '... and correct error message');
    is ($@->detail_message, 'webauth_key_create', '... and correct detail');

    # Test reading a new keyring file.
    $key = $wa->key_create (WA_KEY_AES, WA_AES_128);
    my $ring = $wa->keyring_new (32);
    ok (defined ($ring), 'creating a keyring works');
    ok ($ring->isa ('WebAuth::Keyring'), '... and is of the right type');
    my $curr = time;
    $ring->add ($curr, $curr, $key);
    $ring->write ('webauth_keyring');
    my $ring2 = $wa->keyring_read ('webauth_keyring');
    ok ($ring2->isa ('WebAuth::Keyring'), 'reading a new keyring works');
    $ring->write ('webauth_keyring2');

    unlink ('webauth_keyring', 'webauth_keyring.lock')
        if -f 'webauth_keyring';
    unlink ('webauth_keyring2', 'webauth_keyring2.lock')
        if -f 'webauth_keyring2';
};
is ($@, '', 'No unexpected exceptions');

# Check that Perl throws an error if we call an API function with the wrong
# number of arguments.
my $wa = WebAuth->new;
my $key = eval { $wa->key_create (WA_KEY_AES) };
like ($@, qr{ \A Usage: }xms,
      'Usage exception for insufficient arguments to key_create');

# Check that sending WebAuth::Key different objects than it expect fails.
eval {
    $key = WebAuth::Key::new('WebAuth::NotKey');
};
like ($@, qr{^subclassing of WebAuth::Key is not supported}ms,
    'Trying to subclass WebAuth::Key fails');
eval {
    $key = WebAuth::Key->new('WebAuth::NotKey');
};
like ($@, qr{^second argument must be a WebAuth object}ms,
    '... as does not giving it a WebAuth object');
