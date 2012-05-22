/*
 * Test suite for libwebauth key and keyring handling.
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
#include <webauth.h>
#include <webauth/basic.h>
#include <webauth/keys.h>


int
main(void)
{
    struct webauth_context *ctx;
    struct webauth_key *key;
    struct webauth_keyring *ring;
    struct webauth_keyring *ring2;
    int s, fd;
    size_t len, i;
    unsigned char key_material[WA_AES_128];
    char hex[2048];
    time_t curr;

    plan(13);

    if (webauth_context_init(&ctx, NULL) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    ring = webauth_keyring_new(ctx, 32);
    ok(ring != NULL, "Creating a keyring succeeds");
    memset(key_material, 2, sizeof(key_material));
    s = webauth_key_create(ctx, WA_AES_KEY, sizeof(key_material),
                           key_material, &key);
    is_int(WA_ERR_NONE, s, "Creating a key with known key material succeeds");
    ok(key != NULL, "... and key is not NULL");
    ok(key->data != key_material, "... and the data was copied");
    ok(memcmp(key->data, key_material, sizeof(key_material)) == 0,
       "... and the key data matches");
    time(&curr);
    webauth_keyring_add(ctx, ring, curr, curr, key);

    s = webauth_key_create(ctx, WA_AES_KEY, WA_AES_128, NULL, &key);
    is_int(WA_ERR_NONE, s, "Creating a new random key succeeds");
    s = webauth_hex_encode((char *) key->data, key->length, hex, &len,
                           sizeof(hex));
    hex[len] = '\0';
    webauth_keyring_add(ctx, ring, curr, curr + 3600, key);

    s = webauth_keyring_write(ctx, ring,"webauth_keyring");
    is_int(WA_ERR_NONE, s, "Writing the keyring to a file succeeds");
    s = webauth_keyring_read(ctx, "webauth_keyring", &ring2);
    is_int(WA_ERR_NONE, s, "Reading the keyring back from a file succeeds");
    is_int(ring->entries->nelts, ring2->entries->nelts,
           "...and the key count matches");
    for (i = 0; i < (size_t) ring->entries->nelts; i++) {
        struct webauth_keyring_entry *e1, *e2;
        int m;

        e1 = &APR_ARRAY_IDX(ring->entries, i, struct webauth_keyring_entry);
        e2 = &APR_ARRAY_IDX(ring2->entries, i, struct webauth_keyring_entry);
        m = ((e1->creation == e2->creation)
             && (e1->valid_after == e2->valid_after)
             && (e1->key->type == e2->key->type)
             && (e1->key->length == e2->key->length)
             && (memcmp(e1->key->data, e2->key->data, e1->key->length) == 0));
        ok(m, "...and entry %lu matches", (unsigned long) i);
    }
    s = webauth_keyring_write(ctx, ring2, "webauth_keyring2");
    is_int(WA_ERR_NONE, s, "Writing the second keyring back out succeeds");

    /* Truncate a keyring and test empty keyrings. */
    fd = open("webauth_keyring", O_WRONLY | O_TRUNC, 0644);
    if (fd < 0)
        sysbail("Cannot truncate webauth_keyring");
    close(fd);
    s = webauth_keyring_read(ctx, "webauth_keyring", &ring);
    is_int(WA_ERR_KEYRING_READ, s,
           "Correct error from reading an empty keyring");

    unlink("webauth_keyring");
    unlink("webauth_keyring2");
    return 0;
}
