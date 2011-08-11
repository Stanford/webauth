/*
 * WebAuth key and keyring manipulation functions.
 *
 * These interfaces handle WebAuth keys and keyrings.  A key is used for token
 * encryption and decryption.  A keyring is a collection of keys with various
 * use-by dates to allow key rollover while decrypting tokens encrypted with
 * older keys.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011
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

#ifndef WEBAUTH_KEYS_H
#define WEBAUTH_KEYS_H 1

#include <webauth/defines.h>

/* FIXME: Most key functions have not yet been migrated to APR. */
#include <webauth.h>

BEGIN_DECLS

/*
 * Given a key, form a single-element keyring around it.  Used to convert keys
 * to keyrings for functions that want a keyring.  Stores the new keyring in
 * the ring argument and returns a WebAuth error code.  The key will currently
 * be copied into the ring.  On failure, ring will be set to NULL.
 */
int webauth_keyring_from_key(struct webauth_context *, const WEBAUTH_KEY *,
                             WEBAUTH_KEYRING **)
    __attribute__((__nonnull__));

END_DECLS

#endif /* !WEBAUTH_KEYS_H */
