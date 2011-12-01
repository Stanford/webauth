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
#include <webauth/basic.h>
#include <webauth/keys.h>


/*
 * Given a key, wrap a keyring around it.  The keyring and its data structures
 * are allocated from the pool.
 *
 * FIXME: Resizing this keyring will do horrible things since it's
 * pool-allocated memory that can't be resized without using APR.
 */
int
webauth_keyring_from_key(struct webauth_context *ctx, const WEBAUTH_KEY *key,
                         WEBAUTH_KEYRING **ring)
{
    WEBAUTH_KEY *copy;
    WEBAUTH_KEYRING_ENTRY *entry;

    copy = apr_palloc(ctx->pool, sizeof(WEBAUTH_KEY));
    copy->type = key->type;
    copy->data = apr_palloc(ctx->pool, key->length);
    memcpy(copy->data, key->data, key->length);
    copy->length = key->length;
    entry = apr_palloc(ctx->pool, sizeof(WEBAUTH_KEYRING_ENTRY));
    entry->creation_time = 0;
    entry->valid_after = 0;
    entry->key = copy;
    *ring = apr_palloc(ctx->pool, sizeof(WEBAUTH_KEYRING));
    (*ring)->num_entries = 1;
    (*ring)->capacity = 1;
    (*ring)->entries = entry;
    return WA_ERR_NONE;
}
