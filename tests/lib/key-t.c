/*
 * Test suite for libwebauth key and keyring handling.
 *
 * Written by Roland Schemers
 * Updated for current TAP library support by Russ Allbery
 * Copyright 2002, 2003, 2005, 2006, 2009, 2010
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <tests/tap/basic.h>
#include <webauth.h>
#include <webauth/basic.h>

#define BUFSIZE 4096
#define MAX_ATTRS 128


int
main(void)
{
    WEBAUTH_KEY *key;
    WEBAUTH_KEYRING *ring;
    WEBAUTH_KEYRING *ring2;
    int s, fd;
    size_t len, i;
    char key_material[WA_AES_128];
    char hex[2048];
    time_t curr;

    plan(14);

    ring = webauth_keyring_new(32);
    ok(ring != NULL, "Creating a keyring succeeds");
    s = webauth_random_key(key_material, WA_AES_128);
    is_int(WA_ERR_NONE, s, "Generating random key material succeeds");
    s = webauth_hex_encode(key_material, WA_AES_128, hex, &len, sizeof(hex));
    hex[len] = '\0';
    key = webauth_key_create(WA_AES_KEY, key_material, WA_AES_128);
    ok(key != NULL, "Creating a key succeeds");
    time(&curr);
    s = webauth_keyring_add(ring, curr, curr, key);
    is_int(WA_ERR_NONE, s, "Adding the key to a keyring succeeds");
    webauth_key_free(key);

    s = webauth_random_key(key_material, WA_AES_128);
    is_int(WA_ERR_NONE, s, "Creating more random key material succeeds");
    s = webauth_hex_encode(key_material, WA_AES_128, hex, &len, sizeof(hex));
    hex[len] = '\0';
    key = webauth_key_create(WA_AES_KEY, key_material, WA_AES_128);
    ok(key != NULL, "Creating a key succeeds");
    s = webauth_keyring_add(ring, curr, curr + 3600, key);
    is_int(WA_ERR_NONE, s,
           "Adding the key to a keyring in the future succeeds");
    webauth_key_free(key);

    s = webauth_keyring_write_file(ring,"webauth_keyring");
    is_int(WA_ERR_NONE, s, "Writing the keyring to a file succeeds");
    s = webauth_keyring_read_file("webauth_keyring", &ring2);
    is_int(WA_ERR_NONE, s, "Reading the keyring back from a file succeeds");
    is_int(ring2->num_entries, ring->num_entries,
           "...and the key count matches");
    for (i = 0; i < ring->num_entries; i++) {
        WEBAUTH_KEYRING_ENTRY *e1, *e2;
        int m;

        e1 = &ring->entries[i];
        e2 = &ring2->entries[i];
        m = ((e1->creation_time == e2->creation_time)
             && (e1->valid_after == e2->valid_after)
             && (e1->key->type == e2->key->type)
             && (e1->key->length == e2->key->length)
             && (memcmp(e1->key->data, e2->key->data, e1->key->length) == 0));
        ok(m, "...and entry %i matches", i);
    }
    s = webauth_keyring_write_file(ring2, "webauth_keyring2");
    is_int(WA_ERR_NONE, s, "Writing the second keyring back out succeeds");
    webauth_keyring_free(ring);
    webauth_keyring_free(ring2);

    /* Truncate a keyring and test empty keyrings. */
    fd = open("webauth_keyring", O_WRONLY | O_TRUNC, 0644);
    if (fd < 0)
        sysbail("Cannot truncate webauth_keyring");
    close(fd);
    s = webauth_keyring_read_file("webauth_keyring", &ring);
    is_int(WA_ERR_KEYRING_READ, s,
           "Correct error from reading an empty keyring");

    unlink("webauth_keyring");
    unlink("webauth_keyring2");
    return 0;
}
