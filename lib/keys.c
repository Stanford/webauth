/*
 * Handling of keys and keyrings.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2011, 2013, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/apr.h>
#include <portable/system.h>

#include <openssl/err.h>
#include <openssl/rand.h>

#include <lib/internal.h>
#include <webauth/basic.h>
#include <webauth/keys.h>


/*
 * Construct a new WebAuth key.  Takes the key type and key size and optional
 * key material (which must be at least as long as the key size).  If the key
 * material is given, it's copied into the key.  If it's NULL, a random key
 * will be created.
 *
 * Returns WA_ERR_INVALID if the key type or size are not supported, or
 * WA_ERR_RAND_FAILURE on failure to generate random material.
 */
int
webauth_key_create(struct webauth_context *ctx, enum webauth_key_type type,
                   enum webauth_key_size size,
                   const unsigned char *key_material,
                   struct webauth_key **output)
{
    struct webauth_key *key;
    int s;
    unsigned long err;
    char errbuf[BUFSIZ];

    /* Return NULL on invalid key types and sizes. */
    if (type != WA_KEY_AES) {
        s = WA_ERR_UNIMPLEMENTED;
        return wai_error_set(ctx, s, "unsupported key type %d", type);
    }
    if (size != WA_AES_128 && size != WA_AES_192 && size != WA_AES_256) {
        s = WA_ERR_UNIMPLEMENTED;
        return wai_error_set(ctx, s, "unsupported key size %d", size);
    }

    /* Create the basic key structure. */
    key = apr_palloc(ctx->pool, sizeof(struct webauth_key));
    key->type = type;
    key->length = size;
    key->data = apr_palloc(ctx->pool, size);

    /* Either copy in the given key material or get new random material. */
    if (key_material != NULL)
        memcpy(key->data, key_material, size);
    else {
        s = RAND_bytes(key->data, size);
        if (s < 1) {
            s = WA_ERR_RAND_FAILURE;
            err = ERR_get_error();
            if (err == 0)
                wai_error_set(ctx, s, "cannot generate key");
            else {
                ERR_error_string_n(err, errbuf, sizeof(errbuf));
                wai_error_set(ctx, s, "cannot generate key: %s", errbuf);
            }
            return s;
        }
    }
    *output = key;
    return WA_ERR_NONE;
}


/*
 * Create a deep copy of a key structure.  Returns the newly allocated key.
 */
struct webauth_key *
webauth_key_copy(struct webauth_context *ctx, const struct webauth_key *key)
{
    struct webauth_key *copy;

    copy = apr_palloc(ctx->pool, sizeof(struct webauth_key));
    copy->type = key->type;
    copy->length = key->length;
    copy->data = apr_palloc(ctx->pool, key->length);
    memcpy(copy->data, key->data, key->length);
    return copy;
}
