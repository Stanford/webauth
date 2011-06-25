/*
 * WebAuth token manipulation functions.
 *
 * These interfaces parse, unparse, and otherwise manipulate WebAuth tokens.
 * Tokens in WebAuth have two canonical representations: an encrypted wire
 * format, which is encrypted in some key (except for the key hint) and
 * base64-encoded, and a decrypted struct representation that's used
 * internally by WebAuth code.  Each token type has a corresponding encode and
 * decode function to convert between those two representations.
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

#ifndef WEBAUTH_TOKENS_H
#define WEBAUTH_TOKENS_H 1

#include <webauth/defines.h>

#include <sys/types.h>
#include <time.h>

/*
 * Application token, used by a WebAuth Application Server to hold
 * authentication information for its own use.  (Note that applications are
 * not required to use this token format; nothing else in the WebAuth protocol
 * uses it.  It is, however, the token format used by mod_webauth in the
 * standard WebAuth distribution for the application cookie.)
 */
struct webauth_token_app {
    const char *subject;
    time_t last_used;
    const char *initial_factors;
    const char *session_factors;
    unsigned long loa;
    time_t creation;
    time_t expiration;
};

/*
 * Credential token, which holds a credential for some other service (usually
 * a Kerberos service ticket).  It is sent back by the WebKDC to a WebAuth
 * Application Server when requested using a proxy token, and the WAS also
 * uses it to store the credentials in cookies.
 */
struct webauth_token_cred {
    const char *subject;
    const char *type;
    const char *service;
    const void *data;
    size_t data_len;
    time_t creation;
    time_t expiration;
};

/*
 * Id token, which identifies a user to a WebAuth Authentication Server.  This
 * token is sent from the WebKDC to the WAS following a user authentication to
 * communicate the authentication information.
 */
struct webauth_token_id {
    const char *subject;
    const char *auth;
    const void *auth_data;
    size_t auth_data_len;
    const char *initial_factors;
    const char *session_factors;
    unsigned long loa;
    time_t creation;
    time_t expiration;
};

/*
 * Proxy token, returned by the WebKDC to a WebAuth Application Server if the
 * WAS may need to request various tokens (particularly credential tokens).
 * The embedded webkdc-proxy token is stored in an intermediate binary form
 * and used as an opaque blob for creating later requests to the WebKDC.
 */
struct webauth_token_proxy {
    const char *subject;
    const char *type;
    const void *webkdc_proxy;
    size_t webkdc_proxy_len;
    time_t creation;
    time_t expiration;
};

BEGIN_DECLS

/*
 * Decode a token.  Takes a string and a keyring and decodes the token into
 * the corresponding data argument, which will be a newly pool-allocated
 * pointer to the corresponding token struct.  On error, the data argument is
 * set to NULL and an error code is returned.
 */
int webauth_token_decode_app(struct webauth_context *,
                             const char *, const WEBAUTH_KEYRING *,
                             struct webauth_token_app **)
    __attribute__((__nonnull__));
int webauth_token_decode_cred(struct webauth_context *,
                              const char *, const WEBAUTH_KEYRING *,
                              struct webauth_token_cred **)
    __attribute__((__nonnull__));
int webauth_token_decode_id(struct webauth_context *,
                            const char *, const WEBAUTH_KEYRING *,
                            struct webauth_token_id **)
    __attribute__((__nonnull__));
int webauth_token_decode_proxy(struct webauth_context *,
                               const char *, const WEBAUTH_KEYRING *,
                               struct webauth_token_proxy **)
    __attribute__((__nonnull__));

/*
 * Encode a token.  Takes the corresponding struct for that token type and a
 * keyring to use for encryption, and stores in the token argument the newly
 * created token (in pool-allocated memory).  On error, the token argument is
 * set to NULL and an error code is returned.
 */
int webauth_token_encode_app(struct webauth_context *,
                             struct webauth_token_app *,
                             const WEBAUTH_KEYRING *, const char **token)
    __attribute__((__nonnull__));
int webauth_token_encode_cred(struct webauth_context *,
                              struct webauth_token_cred *,
                              const WEBAUTH_KEYRING *, const char **token)
    __attribute__((__nonnull__));
int webauth_token_encode_id(struct webauth_context *,
                            struct webauth_token_id *,
                            const WEBAUTH_KEYRING *, const char **token)
    __attribute__((__nonnull__));
int webauth_token_encode_proxy(struct webauth_context *,
                               struct webauth_token_app *,
                               const WEBAUTH_KEYRING *, const char **token)
    __attribute__((__nonnull__));

END_DECLS

#endif /* !WEBAUTH_TOKENS_H */
