/*
 * Interface for the WebAuth Application Server token cache.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2012
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <lib/internal.h>
#include <webauth/basic.h>
#include <webauth/was.h>


/*
 * Read a service token and key from the given token cache.  Takes the WebAuth
 * context and the path and stores the result in the provided struct argument.
 */
int
webauth_was_token_cache_read(struct webauth_context *ctx, const char *path,
                             struct webauth_was_token_cache *cache)
{
    void *data;
    size_t length;
    int s;

    s = wai_file_read(ctx, path, &data, &length);
    if (s != WA_ERR_NONE)
        return s;
    return wai_decode(ctx, wai_was_token_cache_encoding, data, length, cache);
}


/*
 * Write a service token and key to the given token cache.  Takes the WebAuth
 * context, the webauth_was_token_cache struct, and the path.
 */
int
webauth_was_token_cache_write(struct webauth_context *ctx,
                              const struct webauth_was_token_cache *cache,
                              const char *path)
{
    void *data;
    size_t length;
    int s;

    s = wai_encode(ctx, wai_was_token_cache_encoding, cache, &data, &length);
    if (s != WA_ERR_NONE)
        return s;
    return wai_file_write(ctx, data, length, path);
}
