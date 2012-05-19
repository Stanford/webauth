/*
 * Test key and keyring handling.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011, 2012
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/apr.h>
#include <portable/system.h>

#include <time.h>

#include <tests/tap/basic.h>
#include <webauth.h>
#include <webauth/basic.h>
#include <webauth/keys.h>


int
main(void)
{
    struct webauth_context *ctx;
    int status;
    struct webauth_key *key;
    struct webauth_keyring *ring;
    struct webauth_keyring_entry *entry;

    plan(9);

    if (webauth_context_init(&ctx, NULL) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    /* Create a key to use for testing. */
    status = webauth_key_create(ctx, WA_AES_KEY, WA_AES_128, NULL, &key);
    is_int(WA_ERR_NONE, status, "Key created successfully");
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

    webauth_context_free(ctx);
    return 0;
}
