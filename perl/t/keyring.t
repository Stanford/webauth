#!/usr/bin/perl -w
#
# Test suite for keyring manipulation.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2011, 2012
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;

use Test::More tests => 48;

use lib ('t/lib', 'lib', 'blib/arch');
use WebAuth qw(:const);
use WebAuth::Keyring;

# Do all tests in an eval block to catch otherwise-uncaught exceptions.
eval {
    my $wa = WebAuth->new;
    my $keyring = $wa->keyring_new (1);
    isa_ok ($keyring, 'WebAuth::Keyring');
    is (scalar ($keyring->entries), 0, ' and contains no keys');
    my @entries = $keyring->entries;
    is (scalar (@entries), 0, ' and no keys are returned');

    # Add a key to the keyring and then make sure the data matches.
    my $key = $wa->key_create (WA_KEY_AES, WA_AES_256);
    my $now = time - 20;
    eval { $keyring->add ($now, $now + 5, $key) };
    is ($@, '', 'Adding a key works');
    is (scalar ($keyring->entries), 1, ' and now there is one key');
    @entries = $keyring->entries;
    is (scalar (@entries), 1, ' which is returned in an array');
    is ($entries[0]->creation, $now, ' with the right creation');
    is ($entries[0]->valid_after, $now + 5, ' and the right valid time');
    is ($entries[0]->key->type, WA_KEY_AES, ' and right key type');
    is ($entries[0]->key->length, WA_AES_256, ' and right key length');
    is ($entries[0]->key->data, $key->data, ' and right key data');

    # Add a second key to test keyring resizing.
    my $key2 = $wa->key_create (WA_KEY_AES, WA_AES_256);
    $now = $now + 10;
    is ($keyring->add ($now, $now + 5, $key2), 1, 'Adding a second key works');
    is (scalar ($keyring->entries), 2, ' and now there are two keys');
    @entries = $keyring->entries;
    is ($entries[1]->creation, $now, 'The second key has the right creation');
    is ($entries[1]->valid_after, $now + 5, ' and the right valid time');
    is ($entries[1]->key->type, WA_KEY_AES, ' and right key type');
    is ($entries[1]->key->length, WA_AES_256, ' and right key length');
    is ($entries[1]->key->data, $key2->data, ' and right key data');

    # Test writing the keyring out and reading it back in again.
    eval { $keyring->write ('webauth_keyring') };
    is ($@, '', 'Writing the key out to a file works');
    ok (-f 'webauth_keyring', ' and the file exists');
    is ((stat 'webauth_keyring')[2] & 07777, 0600,
        ' and has the correct mode');
    my $keyring2 = eval { $wa->keyring_read ('webauth_keyring') };
    is ($@, '', 'Reading the keyring back in works');
    unlink ('webauth_keyring');
    my @entries2 = $keyring2->entries;
    is (scalar (@entries2), scalar (@entries),
        ' and the keyrings are the same size');
    is ($entries2[0]->creation, $entries[0]->creation,
        'Creation of first keys match');
    is ($entries2[0]->valid_after, $entries[0]->valid_after,
        'Valid after of first keys match');
    is ($entries2[0]->key->type, $entries[0]->key->type,
        ' and right key type');
    is ($entries2[0]->key->length, $entries[0]->key->length,
        ' and right key length');
    is ($entries2[0]->key->data, $entries[0]->key->data,
        ' and right key data');
    is ($entries2[1]->creation, $entries[1]->creation,
        'Creation of second keys match');
    is ($entries2[1]->valid_after, $entries[1]->valid_after,
        'Valid after of second keys match');
    is ($entries2[1]->key->type, $entries[1]->key->type,
        ' and right key type');
    is ($entries2[1]->key->length, $entries[1]->key->length,
        ' and right key length');
    is ($entries2[1]->key->data, $entries[1]->key->data,
        ' and right key data');

    # Check whether we get back the correct key when we ask for the best
    # key for the "current" time.  This should be the first key, since the
    # second key wasn't created until five minutes from "now."
    is ($keyring->best_key (0, $now - 5)->data, $entries[0]->key->data,
        'Best key is the first');

    # But if we ask for encryption, we want the one created most recently
    # that's valid, so that's the second key.
    is ($keyring->best_key (1, $now - 5)->data, $entries[1]->key->data,
        'Best encryption key is the second');

    # If we make the timestamp later, after the valid time for the second
    # key, we'll get that one for decryption as well.
    is ($keyring->best_key (0, $now + 10)->data, $entries[1]->key->data,
        'Best future key is the second');

    # Test removing keys from the keyring.
    eval { $keyring->remove (0) };
    is ($@, '', 'Removing the first key of the keyring works');
    is (scalar ($keyring->entries), 1, ' and the entry count is 1');
    @entries2 = $keyring->entries;
    is ($entries2[0]->creation, $entries[1]->creation,
        'The remaining key has the expecte creation');
    is ($entries2[0]->valid_after, $entries[1]->valid_after,
        ' and valid after');

    # Test the alternative constructors for keyrings.
    $keyring = WebAuth::Keyring->new ($wa, 1);
    isa_ok ($keyring, 'WebAuth::Keyring');
    is (scalar ($keyring->entries), 0, ' and contains no keys');
    $key = $wa->key_create (WA_KEY_AES, WA_AES_256);
    $keyring = WebAuth::Keyring->new ($wa, $key);
    isa_ok ($keyring, 'WebAuth::Keyring');
    is (scalar ($keyring->entries), 1, ' and contains one key');

    # Write it to a file and then test reading it back in.
    eval { $keyring->write ('webauth_keyring') };
    is ($@, '', 'Writing the key out to a file works');
    $keyring2 = eval { WebAuth::Keyring->read ($wa, 'webauth_keyring') };
    is ($@, '', 'Reading the keyring back in works');
    unlink ('webauth_keyring');
    is (scalar ($keyring2->entries), 1, ' and contains one key');
};
is ($@, '', 'No unexpected exceptions');
