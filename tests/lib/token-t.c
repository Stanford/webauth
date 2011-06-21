/*
 * Test suite for libwebauth token manipulation functions.
 *
 * Written by Roland Schemers
 * Updated for current TAP library support by Russ Allbery
 * Copyright 2002, 2003, 2006, 2009
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tests/tap/basic.h>
#include <webauth.h>

#define BUFSIZE 4096
#define MAX_ATTRS 128


int
main(void)
{
    WEBAUTH_KEY *key;
    WEBAUTH_KEYRING *ring, *ring2;
    char key_material[WA_AES_128];
    WEBAUTH_ATTR_LIST *ain, *aout;
    size_t rlen, len, i;
    int s;
    char *token;
    time_t curr;

    plan(81);

    time(&curr);
    ain = webauth_attr_list_new(32);
    webauth_attr_list_add_str(ain, WA_TK_TOKEN_TYPE, "id", 0, WA_F_NONE);
    webauth_attr_list_add_str(ain, WA_TK_SUBJECT_AUTH, "webkdc", 0, WA_F_NONE);
    webauth_attr_list_add_str(ain, WA_TK_SUBJECT, "krb5:schemers", 0,
                              WA_F_NONE);
    webauth_attr_list_add_time(ain, WA_TK_EXPIRATION_TIME, curr + 3600,
                               WA_F_NONE);

    s = webauth_random_key(key_material, WA_AES_128);
    is_int(WA_ERR_NONE, s, "Getting random key material succeeds");
    key = webauth_key_create(WA_AES_KEY, key_material, WA_AES_128);
    ok(key != NULL, "Creating a key succeeds");
    ring = webauth_keyring_new(32);
    ok(ring != NULL, "Creating a key ring succeeds");
    time(&curr);
    s = webauth_keyring_add(ring, curr, curr, key);
    is_int(WA_ERR_NONE, s, "Adding the key to the keyring succeeds");
    webauth_key_free(key);

    rlen = webauth_token_encoded_length(ain);
    token = malloc(rlen + 1);
    if (token == NULL)
        sysbail("Cannot allocate memory");
    s = webauth_token_create(ain, 0, token, &len, rlen, ring);
    is_int(WA_ERR_NONE, s, "Creating a token succeeds");
    is_int(rlen, len, "...and has the correct length");

    /* Now let's try to decode the token. */
    aout = NULL;
    s = webauth_token_parse(token, len, 0, ring, &aout);
    is_int(WA_ERR_NONE, s, "Parsing the token succeeds");
    is_int(ain->num_attrs, aout->num_attrs,
           "...and the attribute count is correct");
    for (i = 0; i < ain->num_attrs; i++) {
        is_string(ain->attrs[i].name, aout->attrs[i].name,
                  "...attribute name %d is correct", i);
        is_int(ain->attrs[i].length, aout->attrs[i].length,
               "...attribute length %d is correct", i);
        ok(memcmp(aout->attrs[i].value, ain->attrs[i].value,
                  ain->attrs[i].length) == 0,
           "...attribute value %d is correct", i);
    }
    webauth_attr_list_free(aout);
    free(token);

    /*
     * Now let's encrypt a token in a key not on the ring and make sure it
     * doesn't decrypt
     */
    s = webauth_random_key(key_material, WA_AES_128);
    is_int(WA_ERR_NONE, s, "Getting random key material succeeds");
    key = webauth_key_create(WA_AES_KEY, key_material, WA_AES_128);
    ok(key != NULL, "Creating a key succeeds");
    ring2 = webauth_keyring_new(32);
    ok(ring2 != NULL, "Creating a key ring succeeds");
    time(&curr);
    s = webauth_keyring_add(ring2, curr, curr, key);
    is_int(WA_ERR_NONE, s, "Adding the key to the keyring succeeds");
    webauth_key_free(key);
    rlen = webauth_token_encoded_length(ain);
    token = malloc(rlen + 1);
    if (token == NULL)
        sysbail("Cannot allocate memory");
    s = webauth_token_create(ain, 0, token, &len, rlen, ring2);
    is_int(WA_ERR_NONE, s, "Creating a token succeeds");
    is_int(rlen, len, "...and has the correct length");
    aout = NULL;
    s = webauth_token_parse(token, len, 0, ring, &aout);
    ok(s != WA_ERR_NONE, "Decoding with the wrong key correctly fails");
    webauth_attr_list_free(ain);
    free(token);
    webauth_keyring_free(ring);
    webauth_keyring_free(ring2);

    /* Now let's try the {create,parse}_with_key versions. */
    ain = webauth_attr_list_new(32);
    webauth_attr_list_add_str(ain, WA_TK_TOKEN_TYPE, "id", 0, WA_F_NONE);
    webauth_attr_list_add_str(ain, WA_TK_SUBJECT_AUTH, "webkdc", 0, WA_F_NONE);
    webauth_attr_list_add_str(ain, WA_TK_SUBJECT, "krb5:schemers", 0,
                              WA_F_NONE);
    webauth_attr_list_add_time(ain, WA_TK_EXPIRATION_TIME, curr + 3600,
                               WA_F_NONE);
    s = webauth_random_key(key_material, WA_AES_128);
    is_int(WA_ERR_NONE, s, "Getting random key material succeeds");
    key = webauth_key_create(WA_AES_KEY, key_material, WA_AES_128);
    ok(key != NULL, "Creating a key succeeds");
    rlen = webauth_token_encoded_length(ain);
    token = malloc(rlen + 1);
    if (token == NULL)
        sysbail("Cannot allocate memory");
    s = webauth_token_create_with_key(ain, 0, token, &len, rlen, key);
    is_int(WA_ERR_NONE, s, "Creating a token with a key succeeds");
    is_int(rlen, len, "...and has the correct length");
    aout = NULL;
    s = webauth_token_parse_with_key(token, len, 0, key, &aout);
    is_int(WA_ERR_NONE, s, "Parsing the token succeeds");
    is_int(ain->num_attrs, aout->num_attrs,
           "...and the attribute count is correct");
    for (i = 0; i < ain->num_attrs; i++) {
        is_string(ain->attrs[i].name, aout->attrs[i].name,
                  "...attribute name %d is correct", i);
        is_int(ain->attrs[i].length, aout->attrs[i].length,
               "...attribute length %d is correct", i);
        ok(memcmp(aout->attrs[i].value, ain->attrs[i].value,
                  ain->attrs[i].length) == 0,
           "...attribute value %d is correct", i);
    }
    webauth_attr_list_free(aout);
    webauth_attr_list_free(ain);
    free(token);
    webauth_key_free(key);

    /* Let's try to parse an expired token. */
    ain = webauth_attr_list_new(32);
    webauth_attr_list_add_str(ain, WA_TK_TOKEN_TYPE, "id", 0, WA_F_NONE);
    webauth_attr_list_add_str(ain, WA_TK_SUBJECT_AUTH, "webkdc", 0, WA_F_NONE);
    webauth_attr_list_add_str(ain, WA_TK_SUBJECT, "krb5:schemers", 0,
                              WA_F_NONE);
    webauth_attr_list_add_time(ain, WA_TK_EXPIRATION_TIME, curr - 3600,
                               WA_F_NONE);
    s = webauth_random_key(key_material, WA_AES_128);
    is_int(WA_ERR_NONE, s, "Getting random key material succeeds");
    key = webauth_key_create(WA_AES_KEY, key_material, WA_AES_128);
    ok(key != NULL, "Creating a key succeeds");
    rlen = webauth_token_encoded_length(ain);
    token = malloc(rlen + 1);
    if (token == NULL)
        sysbail("Cannot allocate memory");
    s = webauth_token_create_with_key(ain, 0, token, &len, rlen, key);
    is_int(WA_ERR_NONE, s, "Creating a token with a key succeeds");
    is_int(rlen, len, "...and has the correct length");
    aout = NULL;
    s = webauth_token_parse_with_key(token, len, 0, key, &aout);
    is_int(WA_ERR_TOKEN_EXPIRED, s,
           "Parsing an expired token produces the correct error");
    is_int(ain->num_attrs, aout->num_attrs,
           "...and the attribute count is correct");
    for (i = 0; i < ain->num_attrs; i++) {
        is_string(ain->attrs[i].name, aout->attrs[i].name,
                  "...attribute name %d is correct", i);
        is_int(ain->attrs[i].length, aout->attrs[i].length,
               "...attribute length %d is correct", i);
        ok(memcmp(aout->attrs[i].value, ain->attrs[i].value,
                  ain->attrs[i].length) == 0,
           "...attribute value %d is correct", i);
    }
    webauth_attr_list_free(aout);
    webauth_attr_list_free(ain);
    free(token);
    webauth_key_free(key);

    /* let's try to parse a stale token. */
    ain = webauth_attr_list_new(32);
    webauth_attr_list_add_str(ain, WA_TK_TOKEN_TYPE, "id", 0, WA_F_NONE);
    webauth_attr_list_add_str(ain, WA_TK_SUBJECT_AUTH, "webkdc", 0, WA_F_NONE);
    webauth_attr_list_add_str(ain, WA_TK_SUBJECT, "krb5:schemers", 0,
                              WA_F_NONE);
    webauth_attr_list_add_time(ain, WA_TK_CREATION_TIME, curr - 3600,
                               WA_F_NONE);
    s = webauth_random_key(key_material, WA_AES_128);
    is_int(WA_ERR_NONE, s, "Getting random key material succeeds");
    key = webauth_key_create(WA_AES_KEY, key_material, WA_AES_128);
    ok(key != NULL, "Creating a key succeeds");
    rlen = webauth_token_encoded_length(ain);
    token = malloc(rlen + 1);
    if (token == NULL)
        sysbail("Cannot allocate memory");
    s = webauth_token_create_with_key(ain, 0, token, &len, rlen, key);
    is_int(WA_ERR_NONE, s, "Creating a token with a key succeeds");
    is_int(rlen, len, "...and has the correct length");
    aout = NULL;
    s = webauth_token_parse_with_key(token, len, 300, key, &aout);
    is_int(WA_ERR_TOKEN_STALE, s,
           "Parsing a stale token produces the correct error");
    is_int(ain->num_attrs, aout->num_attrs,
           "...and the attribute count is correct");
    for (i = 0; i < ain->num_attrs; i++) {
        is_string(ain->attrs[i].name, aout->attrs[i].name,
                  "...attribute name %d is correct", i);
        is_int(ain->attrs[i].length, aout->attrs[i].length,
               "...attribute length %d is correct", i);
        ok(memcmp(aout->attrs[i].value, ain->attrs[i].value,
                  ain->attrs[i].length) == 0,
           "...attribute value %d is correct", i);
    }
    webauth_attr_list_free(aout);
    webauth_attr_list_free(ain);
    free(token);
    webauth_key_free(key);

    return 0;
}
