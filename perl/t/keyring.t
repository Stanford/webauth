#!/usr/bin/perl -w
#
# Test suite for keyring manipulation.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2011
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;

use Test::More tests => 33;

use lib ('t/lib', 'lib', 'blib/arch');
use WebAuth qw (:const);

# Do all tests in an eval block to catch otherwise-uncaught exceptions.
eval {
    my $keyring = WebAuth::Keyring->new;
    isa_ok ($keyring, 'WebAuth::Keyring');
    is ($keyring->capacity, 1, 'New keyring has a capacity of 1');
    is (scalar ($keyring->entries), 0, ' and contains no keys');
    my @entries = $keyring->entries;
    is (scalar (@entries), 0, ' and no keys are returned');

    # Add a key to the keyring and then make sure the data matches.
    #
    # FIXME: We can't compare keys until we have a proper OO interface to keys
    # as well.
    my $bytes = WebAuth::random_key (WA_AES_256);
    my $key = WebAuth::key_create (WA_AES_KEY, $bytes);
    my $now = time - 20;
    eval { $keyring->add ($now, $now + 5, $key) };
    is ($@, '', 'Adding a key works');
    is ($keyring->capacity, 1, ' and capacity is still 1');
    is (scalar ($keyring->entries), 1, ' and now there is one key');
    @entries = $keyring->entries;
    is (scalar (@entries), 1, ' which is returned in an array');
    is ($entries[0]->creation, $now, ' with the right creation');
    is ($entries[0]->valid_after, $now + 5, ' and the right valid time');

    # Add a second key to test keyring resizing.
    #
    # FIXME: We can't compare keys until we have a proper OO interface to keys
    # as well.
    $bytes = WebAuth::random_key (WA_AES_256);
    my $key2 = WebAuth::key_create (WA_AES_KEY, $bytes);
    $now = $now + 10;
    is ($keyring->add ($now, $now + 5, $key), 1, 'Adding a second key works');
    is ($keyring->capacity, 2, ' and capacity is now 2');
    is (scalar ($keyring->entries), 2, ' and now there are two keys');
    @entries = $keyring->entries;
    is ($entries[1]->creation, $now, 'The second key has the right creation');
    is ($entries[1]->valid_after, $now + 5, ' and the right valid time');

    # Test writing the keyring out and reading it back in again.
    #
    # FIXME: We can't test that the keys are the same when we read them back
    # in from the file until we have a better data structure for keys.  Right
    # now, keys are opaque pointers, and the pointer will change.
    eval { $keyring->write_file ('webauth_keyring') };
    is ($@, '', 'Writing the key out to a file works');
    ok (-f 'webauth_keyring', ' and the file exists');
    is ((stat 'webauth_keyring')[2] & 07777, 0600,
        ' and has the correct mode');
    my $keyring2 = eval { WebAuth::Keyring->read_file ('webauth_keyring') };
    is ($@, '', 'Reading the keyring back in works');
    unlink ('webauth_keyring');
    my @entries2 = $keyring2->entries;
    is (scalar (@entries2), scalar (@entries),
        ' and the keyrings are the same size');
    is ($entries2[0]->creation, $entries2[0]->creation,
        'Creation of first keys match');
    is ($entries2[0]->valid_after, $entries2[0]->valid_after,
        'Valid after of first keys match');
    is ($entries2[1]->creation, $entries2[1]->creation,
        'Creation of second keys match');
    is ($entries2[1]->valid_after, $entries2[1]->valid_after,
        'Valid after of second keys match');

    # Tests for best_key().  These cannot be run yet, since we don't have a
    # way of comparing the key.
  TODO: {
        local $TODO = 'Need Perl object modeling keys';

        # Check whether we get back the correct key when we ask for the best
        # key for the "current" time.  This should be the first key, since the
        # second key wasn't created until five minutes from "now."
        is ($keyring->best_key (0, $now - 5), $entries[0]->key,
            'Best key is the first');

        # But if we ask for encryption, we want the one created most recently
        # that's valid, so that's the second key.
        is ($keyring->best_key (1, $now - 5), $entries[1]->key,
            'Best encryption key is the second');

        # If we make the timestamp later, after the valid time for the second
        # key, we'll get that one for decryption as well.
        is ($keyring->best_key (0, $now + 10), $entries[1]->key,
            'Best future key is the second');
    }

    # Test removing keys from the keyring.
    eval { $keyring->remove (0) };
    is ($@, '', 'Removing the first key of the keyring works');
    is ($keyring->capacity, 2, ' and the capacity is still 2');
    is ($keyring->entries, 1, ' but the entry count is 1');
    @entries2 = $keyring->entries;
    is ($entries2[0]->creation, $entries[1]->creation,
        'The remaining key has the expecte creation');
    is ($entries2[0]->valid_after, $entries[1]->valid_after,
        ' and valid after');
};
is ($@, '', 'No unexpected exceptions');
