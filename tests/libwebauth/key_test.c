/*
 * Test suite for libwebauth key and keyring handling.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2003, 2005, 2006, 2009
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include "config.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <lib/webauth.h>
#include "webauthtest.h"

#define BUFSIZE 4096
#define MAX_ATTRS 128

int main(int argc, char *argv[])
{
    WEBAUTH_KEY *key;
    WEBAUTH_KEYRING *ring;
    WEBAUTH_KEYRING *ring2;

    int s, len, i, fd;
    char key_material[WA_AES_128];
    char hex[2048];
    time_t curr;
    TEST_VARS;

    START_TESTS(14);

    ring = webauth_keyring_new(32);
    TEST_OK(ring != NULL);

    s = webauth_random_key(key_material, WA_AES_128);
    TEST_OK2(WA_ERR_NONE, s);

    s=webauth_hex_encode(key_material, WA_AES_128, hex, &len, sizeof(hex));
    hex[len] = '\0';
    /*printf("key[%s]\n", hex);*/

    key = webauth_key_create(WA_AES_KEY, key_material, WA_AES_128);
    TEST_OK(key != NULL);

    time(&curr);
    s = webauth_keyring_add(ring, curr, curr, key);
    TEST_OK2(WA_ERR_NONE, s);

    webauth_key_free(key);

    s = webauth_random_key(key_material, WA_AES_128);
    TEST_OK2(WA_ERR_NONE, s);

    s = webauth_hex_encode(key_material, WA_AES_128, hex, &len, sizeof(hex));
    hex[len] = '\0';
    /*printf("key[%s]\n", hex);*/

    key = webauth_key_create(WA_AES_KEY, key_material, WA_AES_128);
    TEST_OK(key != NULL);

    s = webauth_keyring_add(ring, curr, curr+3600, key);
    TEST_OK2(WA_ERR_NONE, s);

    webauth_key_free(key);

    s = webauth_keyring_write_file(ring,"webauth_keyring");
    TEST_OK2(WA_ERR_NONE, s);

    s = webauth_keyring_read_file("webauth_keyring", &ring2);
    TEST_OK2(WA_ERR_NONE, s);

    /* FIXME: compare ring2 to ring */
    TEST_OK2(ring->num_entries, ring2->num_entries);
    if (ring->num_entries == ring2->num_entries) {
        for (i=0; i < ring->num_entries; i++) {
            WEBAUTH_KEYRING_ENTRY *e1, *e2;
            int ok;
            e1 = &ring->entries[i];
            e2 = &ring2->entries[i];
            ok = (e1->creation_time == e2->creation_time) &&
                (e1->valid_after == e2->valid_after) &&
                (e1->key->type == e2->key->type) &&
                (e1->key->length == e2->key->length) &&
                (memcmp(e1->key->data, e2->key->data, e1->key->length) == 0);
            TEST_OK(ok);
        }
    }

    s = webauth_keyring_write_file(ring2,"webauth_keyring2");
    TEST_OK2(WA_ERR_NONE, s);

    webauth_keyring_free(ring);
    webauth_keyring_free(ring2);

    /* Truncate a keyring and test empty keyrings. */
    fd = open("webauth_keyring", O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        close(fd);
        s = webauth_keyring_read_file("webauth_keyring", &ring);
        TEST_OK2(WA_ERR_KEYRING_READ, s);
    }

    END_TESTS;
    exit(NUM_FAILED_TESTS ? 1 : 0);
}
