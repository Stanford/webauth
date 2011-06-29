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
 * The types of tokens specified in the protocol, returned by the generic
 * webauth_token_decode function.  WA_TOKEN_UNKNOWN will be returned by that
 * function in the event of an error.
 */
enum webauth_token_type {
    WA_TOKEN_UNKNOWN,
    WA_TOKEN_APP,
    WA_TOKEN_CRED,
    WA_TOKEN_ERROR,
    WA_TOKEN_ID,
    WA_TOKEN_LOGIN,
    WA_TOKEN_PROXY,
    WA_TOKEN_REQUEST,
    WA_TOKEN_WEBKDC_PROXY,
    WA_TOKEN_WEBKDC_SERVICE
};

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
    const void *session_key;
    size_t session_key_len;
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
 * Error token, returned by the WebKDC in response to a request token if some
 * error occurred in processing that request.
 *
 * Note that the error code is a string, not a number, in the WebAuth protocol
 * on the wire.  This cannot be changed in the protocol due to backward
 * compatibility constraints, but the code is presented as a number to users
 * of the library for convenience.
 */
struct webauth_token_error {
    unsigned long code;
    const char *message;
    time_t creation;
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
    const char *initial_factors;
    const char *session_factors;
    unsigned long loa;
    time_t creation;
    time_t expiration;
};

/*
 * Request token, sent by the WebAuth Application Server to the WebKDC.
 *
 * This token has two forms.  The first is sent by the WAS to the WebKDC via a
 * redirect to request either an id or a proxy token for the user, depending
 * on whether the WAS will need credentials.  The second is sent to the WebKDC
 * as part of a request for a service token and contains only the command and
 * creation time.
 */
struct webauth_token_request {
    const char *type;
    const char *auth;
    const char *proxy_type;
    const void *state;
    size_t state_len;
    const char *return_url;
    const char *options;
    const char *initial_factors;
    const char *session_factors;
    unsigned long loa;
    const char *command;
    time_t creation;
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
int webauth_token_decode_error(struct webauth_context *,
                               const char *, const WEBAUTH_KEYRING *,
                               struct webauth_token_error **)
    __attribute__((__nonnull__));
int webauth_token_decode_id(struct webauth_context *,
                            const char *, const WEBAUTH_KEYRING *,
                            struct webauth_token_id **)
    __attribute__((__nonnull__));
int webauth_token_decode_proxy(struct webauth_context *,
                               const char *, const WEBAUTH_KEYRING *,
                               struct webauth_token_proxy **)
    __attribute__((__nonnull__));
int webauth_token_decode_request(struct webauth_context *,
                                 const char *, const WEBAUTH_KEYRING *,
                                 struct webauth_token_request **)
    __attribute__((__nonnull__));

/*
 * Decode an arbitrary token, where the token type is not known in advance.
 * Takes the context, the token, and the keyring to decrypt it.
 *
 * On success, the type of the token is stored in the type argument and a
 * pointer to the corresponding struct is stored in the token argument.  The
 * token is stored in newly-allocated pool memory.  The client is responsible
 * for casting the token pointer to the appropriate type after discovering the
 * type of the token.
 *
 * On error, type is set to WA_TOKEN_UNKNOWN and token is set to NULL, and an
 * error code is returned.
 *
 * This function does not provide as strong of type checking, so should only
 * be used when the caller truly doesn't know what type of token to expect.
 * The caller is responsible for handling and rejecting tokens of entirely
 * inappropriate types.
 */
int webauth_token_decode(struct webauth_context *, const char *,
                         const WEBAUTH_KEYRING *, enum webauth_token_type *,
                         void **token)
    __attribute__((__nonnull__));

/*
 * Encode a token.  Takes the corresponding struct for that token type and a
 * keyring to use for encryption, and stores in the token argument the newly
 * created token (in pool-allocated memory).  On error, the token argument is
 * set to NULL and an error code is returned.
 */
int webauth_token_encode_app(struct webauth_context *,
                             const struct webauth_token_app *,
                             const WEBAUTH_KEYRING *, const char **token)
    __attribute__((__nonnull__));
int webauth_token_encode_cred(struct webauth_context *,
                              const struct webauth_token_cred *,
                              const WEBAUTH_KEYRING *, const char **token)
    __attribute__((__nonnull__));
int webauth_token_encode_proxy(struct webauth_context *,
                               const struct webauth_token_proxy *,
                               const WEBAUTH_KEYRING *, const char **token)
    __attribute__((__nonnull__));
int webauth_token_encode_request(struct webauth_context *,
                                 const struct webauth_token_request *,
                                 const WEBAUTH_KEYRING *, const char **token)
    __attribute__((__nonnull__));

END_DECLS

#endif /* !WEBAUTH_TOKENS_H */
