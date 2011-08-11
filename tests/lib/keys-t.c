/*
 * Test key and keyring handling.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <tests/tap/basic.h>
#include <webauth.h>
#include <webauth/basic.h>
#include <webauth/keys.h>


int
main(void)
{
    struct webauth_context *ctx;
    int status;
    char bytes[WA_AES_128];
    WEBAUTH_KEY *key;
    WEBAUTH_KEYRING *ring;

    plan(10);

    if (webauth_context_init(&ctx, NULL) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    /* Create a key to use for testing. */
    if (webauth_random_key(bytes, sizeof(bytes)) != WA_ERR_NONE)
        bail("cannot generate random key");
    key = webauth_key_create(WA_AES_KEY, bytes, sizeof(bytes));
    ok(key != NULL, "Key created successfully");
    status = webauth_keyring_from_key(ctx, key, &ring);
    is_int(WA_ERR_NONE, status, "Creating keyring worked");
    is_int(1, ring->num_entries, "...with one entry");
    is_int(1, ring->capacity, "...and one capacity");
    is_int(0, ring->entries->creation_time, "Key has 0 creation time");
    is_int(0, ring->entries->valid_after, "...and 0 valid after");
    ok(ring->entries->key != key, "Key in the ring is a copy");
    is_int(key->type, ring->entries->key->type, "...with correct type");
    is_int(key->length, ring->entries->key->length, "...and length");
    ok(memcmp(key->data, ring->entries->key->data, key->length) == 0,
       "...and correct data");

    webauth_context_free(ctx);
    return 0;
}
