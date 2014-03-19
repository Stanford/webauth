/*
 * Test key handling.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2012, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <time.h>

#include <tests/tap/basic.h>
#include <webauth/basic.h>
#include <webauth/keys.h>


int
main(void)
{
    struct webauth_context *ctx;
    struct webauth_key *key, *copy;
    unsigned char bytes[WA_AES_256];
    int s;
    size_t i;

    plan(20);

    if (webauth_context_init(&ctx, NULL) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    /* Test random key creation. */
    s = webauth_key_create(ctx, WA_KEY_AES, WA_AES_128, NULL, &key);
    is_int(WA_ERR_NONE, s, "Key created successfully");
    is_int(WA_KEY_AES, key->type, "... with correct type");
    is_int(WA_AES_128, key->length, "... and correct length");
    ok(key->data != NULL, "... and data is not NULL");

    /* Test key creation with known material. */
    for (i = 0; i < sizeof(bytes); i++)
        bytes[i] = i;
    s = webauth_key_create(ctx, WA_KEY_AES, WA_AES_256, bytes, &key);
    is_int(WA_ERR_NONE, s, "Creating a key with known key material succeeds");
    is_int(WA_KEY_AES, key->type, "... with correct type");
    is_int(WA_AES_256, key->length, "... and correct length");
    ok(key->data != bytes, "... and the data was copied");
    ok(memcmp(key->data, bytes, sizeof(bytes)) == 0,
       "... and the key data matches");

    /* Test key creation using only part of the material. */
    s = webauth_key_create(ctx, WA_KEY_AES, WA_AES_192, bytes, &key);
    is_int(WA_ERR_NONE, s, "Creating with partial key material succeeds");
    is_int(WA_KEY_AES, key->type, "... with correct type");
    is_int(WA_AES_192, key->length, "... and correct length");
    ok(key->data != bytes, "... and the data was copied");
    ok(memcmp(key->data, bytes, key->length) == 0,
       "... and the first section of key data matches");

    /* Test key copying. */
    copy = webauth_key_copy(ctx, key);
    is_int(key->type, copy->type, "Copied key has correct type");
    is_int(key->length, copy->length, "... and correct length");
    ok(key->data != copy->data, "... and data was copied");
    ok(memcmp(key->data, copy->data, key->length) == 0, "... and matches");

    /* Errors on key creation. */
    s = webauth_key_create(ctx, 2, WA_AES_128, NULL, &key);
    is_int(WA_ERR_UNIMPLEMENTED, s, "Invalid key type fails");
    s = webauth_key_create(ctx, WA_KEY_AES, 14, NULL, &key);
    is_int(WA_ERR_UNIMPLEMENTED, s, "Invalid key size fails");

    webauth_context_free(ctx);
    return 0;
}
