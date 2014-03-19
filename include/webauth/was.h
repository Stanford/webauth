/*
 * WebAuth functions specific to WebAuth Application Servers.
 *
 * These interfaces provide the building blocks of the WebAuth Application
 * Server functionality.  They're normally only used inside the mod_webauth
 * module, but are provided in the shared library for ease of testing and
 * custom development.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2012
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef WEBAUTH_WAS_H
#define WEBAUTH_WAS_H 1

#include <webauth/defines.h>

#include <sys/types.h>

struct webauth_context;

/*
 * A cached webkdc-service token.  These are obtained by the WAS and used for
 * all further communications with the WebKDC.  The cache stores the opaque
 * service token and the private key contained in that token, along with some
 * expiration and renewal times.
 *
 * We don't use the webauth_key struct here for ease of encoding.  Once all
 * service token handling is moved into the library, this interface will
 * become private.
 */
struct webauth_was_token_cache {
    char *token;                /* encode: token */
    uint32_t key_type;          /* encode: key_type, ascii */
    void *key_data;             /* encode: key, ascii */
    size_t key_data_len;
    time_t created;             /* encode: created, ascii */
    time_t expires;             /* encode: expires, ascii */
    time_t last_renewal;        /* encode: last_renewal_attempt, ascii */
    time_t next_renewal;        /* encode: next_renewal_attempt, ascii */
};

BEGIN_DECLS

/*
 * Read a service token and key from the given token cache.  Takes the WebAuth
 * context and the path and stores the result in the provided struct argument.
 */
int webauth_was_token_cache_read(struct webauth_context *, const char *,
                                 struct webauth_was_token_cache *)
    __attribute__((__nonnull__));

/*
 * Write a service token and key to the given token cache.  Takes the WebAuth
 * context, the webauth_was_token_cache struct, and the path.
 */
int webauth_was_token_cache_write(struct webauth_context *,
                                  const struct webauth_was_token_cache *,
                                  const char *)
    __attribute__((__nonnull__));

END_DECLS

#endif /* !WEBAUTH_WEBKDC_H */
