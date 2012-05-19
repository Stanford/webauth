/*
 * Handling of keys and keyrings.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/apr.h>
#include <portable/system.h>

#include <lib/internal.h>
#include <webauth.h>
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
    int status;

    /* Return NULL on invalid key types and sizes. */
    if (type != WA_AES_KEY) {
        status = WA_ERR_INVALID;
        webauth_error_set(ctx, status, "unsupported key type %d", type);
        return status;
    }
    if (size != WA_AES_128 && size != WA_AES_192 && size != WA_AES_256) {
        status = WA_ERR_INVALID;
        webauth_error_set(ctx, status, "unsupported key size %d", size);
        return status;
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
        status = webauth_random_key(key->data, size);
        if (status != WA_ERR_NONE) {
            webauth_error_set(ctx, status, "cannot generate random key");
            return status;
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
