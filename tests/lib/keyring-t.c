/*
 * Test suite for keyring handling.
 *
 * Written by Roland Schemers
 * Updated for current TAP library support by Russ Allbery
 * Copyright 2002, 2003, 2005, 2006, 2009, 2010, 2012
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/apr.h>
#include <portable/system.h>

#include <fcntl.h>
#include <time.h>

#include <tests/tap/basic.h>
#include <tests/tap/string.h>
#include <webauth/basic.h>
#include <webauth/keys.h>


int
main(void)
{
    struct webauth_context *ctx;
    struct webauth_key *key;
    struct webauth_keyring *ring;
    struct webauth_keyring *ring2;
    struct webauth_keyring_entry *entry;
    char *tmpdir, *keyring;
    int s, fd;
    size_t i;
    time_t now;

    plan(34);

    if (webauth_context_init(&ctx, NULL) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    /* Create a random key and then create a keyring from that key. */
    s = webauth_key_create(ctx, WA_KEY_AES, WA_AES_128, NULL, &key);
    is_int(WA_ERR_NONE, s, "Key created successfully");
    ring = webauth_keyring_from_key(ctx, key);
    ok(ring->entries != NULL, "Keyring created successfully");
    is_int(1, ring->entries->nelts, "... with one entry");
    entry = &APR_ARRAY_IDX(ring->entries, 0, struct webauth_keyring_entry);
    is_int(0, entry->creation, "Key has 0 creation time");
    is_int(0, entry->valid_after, "...and 0 valid after");
    ok(entry->key != key, "Key in the ring is a copy");
    is_int(key->type, entry->key->type, "...with correct type");
    is_int(key->length, entry->key->length, "...and length");
    ok(memcmp(key->data, entry->key->data, key->length) == 0,
       "...and correct data");

    /* Create a ring with a specific capacity and add a couple of keys. */
    ring = webauth_keyring_new(ctx, 1);
    ok(ring != NULL, "Creating a keyring succeeds");
    s = webauth_key_create(ctx, WA_KEY_AES, WA_AES_256, NULL, &key);
    is_int(WA_ERR_NONE, s, "Creating a key succeeds");
    now = time(NULL);
    webauth_keyring_add(ctx, ring, now, now, key);
    ok(ring->entries != NULL, "Keyring created successfully");
    is_int(1, ring->entries->nelts, "... with one entry");
    entry = &APR_ARRAY_IDX(ring->entries, 0, struct webauth_keyring_entry);
    is_int(now, entry->creation, "Key has correct creation time");
    is_int(now, entry->valid_after, "...and correct valid after");
    s = webauth_key_create(ctx, WA_KEY_AES, WA_AES_128, NULL, &key);
    is_int(WA_ERR_NONE, s, "Creating another new random key succeeds");
    webauth_keyring_add(ctx, ring, now, now + 3600, key);
    is_int(2, ring->entries->nelts, "Keyring now has two entries");
    entry = &APR_ARRAY_IDX(ring->entries, 1, struct webauth_keyring_entry);
    is_int(now, entry->creation, "Second key has correct creation time");
    is_int(now + 3600, entry->valid_after, "...and correct valid after");

    /* Write the keyring out and then read it back in. */
    tmpdir = test_tmpdir();
    basprintf(&keyring, "%s/webauth_keyring", tmpdir);
    s = webauth_keyring_write(ctx, ring, keyring);
    is_int(WA_ERR_NONE, s, "Writing the keyring to a file succeeds");
    s = webauth_keyring_read(ctx, keyring, &ring2);
    is_int(WA_ERR_NONE, s, "Reading the keyring back from a file succeeds");
    is_int(ring->entries->nelts, ring2->entries->nelts,
           "...and the key count matches");
    for (i = 0; i < (size_t) ring->entries->nelts; i++) {
        struct webauth_keyring_entry *e1, *e2;

        e1 = &APR_ARRAY_IDX(ring->entries, i, struct webauth_keyring_entry);
        e2 = &APR_ARRAY_IDX(ring2->entries, i, struct webauth_keyring_entry);
        is_int(e1->creation, e2->creation, "Creation of key %lu matches",
               (unsigned long) i);
        is_int(e1->valid_after, e2->valid_after,
               "Valid after of key %lu matches", (unsigned long) i);
        is_int(e1->key->type, e2->key->type, "Type of key %lu matches",
               (unsigned long) i);
        is_int(e1->key->length, e2->key->length, "Length of key %lu matches",
               (unsigned long) i);
        ok(memcmp(e1->key->data, e2->key->data, e1->key->length) == 0,
           "Data of key %lu matches", (unsigned long) i);
    }
    s = webauth_keyring_write(ctx, ring2, keyring);
    is_int(WA_ERR_NONE, s, "Writing the second keyring back out succeeds");

    /* Truncate a keyring and test empty keyrings. */
    fd = open(keyring, O_WRONLY | O_TRUNC, 0644);
    if (fd < 0)
        sysbail("Cannot truncate %s", keyring);
    close(fd);
    s = webauth_keyring_read(ctx, keyring, &ring);
    is_int(WA_ERR_KEYRING_READ, s, "Correct error from reading empty keyring");

    /* Clean up. */
    unlink(keyring);
    free(keyring);
    test_tmpdir_free(tmpdir);
    return 0;
}
