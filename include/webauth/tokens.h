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

#include <webauth.h>            /* WEBAUTH_KEYRING */

struct webauth_context;

/*
 * Stores a set of factors that we want to perform operations on.  This is a
 * list of authentication methods (like "p", "o1", etc.) plus flags for the
 * presence of "derived" factors, such as "m" (which is present if the user
 * has used two separate factors) or "o" (which is present if the user has
 * used any of the OTP factors).
 */
struct webauth_factors {
    int multifactor;                    /* "m" (two factors in use) */
    WA_APR_ARRAY_HEADER_T *factors;     /* Array of char * factor codes. */
};

/*
 * The types of tokens specified in the protocol, used in the type field of
 * the webauth_token struct.  WA_TOKEN_UNKNOWN will never be returned in that
 * struct but is used internally for errors.  WA_TOKEN_ANY is used as the
 * argument to webauth_token_decode when the caller doesn't know which type of
 * token to expect.
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
    WA_TOKEN_WEBKDC_SERVICE,
    WA_TOKEN_ANY = 255
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
 * Login token, sent from the WebLogin server to the WebKDC and containing the
 * user's username and password or other authentication secret.
 */
struct webauth_token_login {
    const char *username;
    const char *password;
    const char *otp;
    time_t creation;
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

/*
 * WebKDC proxy token, which stores user credentials or authentication
 * information for later use by the WebKDC.  This is the token that's stored
 * as a single sign-on cookie in the user's browser, allowing the user to
 * authenticate to subsequent web sites without reauthenticating.  This token
 * is also returned inside a proxy token to a WAS, which can then present it
 * back to the WebKDC to obtain id or cred tokens.
 *
 * The session_factors data element is special.  It's not included in the wire
 * representation of this token, and therefore will always be NULL when
 * initialized from the wire.  It's used internally to store session
 * information obtained from other sources and used for generating other
 * tokens (particularly id and proxy tokens), and is then discarded when the
 * token is encoded.
 */
struct webauth_token_webkdc_proxy {
    const char *subject;
    const char *proxy_type;
    const char *proxy_subject;
    const void *data;
    size_t data_len;
    const char *initial_factors;
    unsigned long loa;
    time_t creation;
    time_t expiration;

    /* Not included in the wire representation. */
    const char *session_factors;
};

/*
 * WebKDC service token, sent by the WebKDC to a WAS and returned by the WAS
 * to the WebKDC as part of the request token.  The purpose of this token is
 * to store the session key used for encrypting the request token and its
 * responses.  It's encrypted in the WebKDC's long-term key, and is therefore
 * used by the WebKDC to recover the session key without having local state.
 */
struct webauth_token_webkdc_service {
    const char *subject;
    const void *session_key;
    size_t session_key_len;
    time_t creation;
    time_t expiration;
};

/*
 * A generic token.  This wrapper is used by the public interface for token
 * encoding and decoding so that we don't need a separate interface for every
 * token type.
 */
struct webauth_token {
    enum webauth_token_type type;
    union {
        struct webauth_token_app app;
        struct webauth_token_cred cred;
        struct webauth_token_error error;
        struct webauth_token_id id;
        struct webauth_token_login login;
        struct webauth_token_proxy proxy;
        struct webauth_token_request request;
        struct webauth_token_webkdc_proxy webkdc_proxy;
        struct webauth_token_webkdc_service webkdc_service;
    } token;
};


BEGIN_DECLS

/*
 * Given a comma-separated string of factors, parse it into a webauth_factors
 * struct.  If the value of the last argument is not NULL, add the factors to
 * the existing webauth_factors struct rather than allocating a new one.
 * Returns a status code.
 */
int webauth_factors_parse(struct webauth_context *, const char *,
                          struct webauth_factors **)
    __attribute__((__nonnull__));

/*
 * Given a webauth_factors struct, return its value as a comma-separated
 * string suitable for inclusion in a token.  The new string is
 * pool-allocated.
 */
char *webauth_factors_string(struct webauth_context *,
                             struct webauth_factors *)
    __attribute__((__nonnull__));

/*
 * Given two sets of factors (struct webauth_factors), return true if the
 * first set is satisfied by the second set, false otherwise.
 */
int webauth_factors_subset(struct webauth_context *, struct webauth_factors *,
                           struct webauth_factors *)
    __attribute__((__nonnull__));

/*
 * Map a token code to the string name used for the toke type attribute, or
 * vice versa.  webauth_token_type_code returns WA_TOKEN_UNKNOWN when given an
 * unknown token type string.  webauth_token_type_string returns NULL when
 * given WA_TOKEN_UNKNOWN, WA_TOKEN_ANY, or an invalid enumeration value.
 */
enum webauth_token_type webauth_token_type_code(const char *type)
    __attribute__((__nonnull__, __pure__));
const char *webauth_token_type_string(enum webauth_token_type type)
    __attribute__((__pure__));

/*
 * Decode a token.  Takes the expected token type, a string, and a keyring and
 * decodes the token into the corresponding data argument, which will be a
 * newly pool-allocated pointer to a generic token struct.  The expected token
 * type may be WA_TOKEN_ANY to accept any token type.  On error, the data
 * argument is set to NULL and an error code is returned.
 *
 * The raw variant takes a token that is not base64-encoded, such as the
 * webkdc-proxy token embedded inside a proxy token.
 */
int webauth_token_decode(struct webauth_context *, enum webauth_token_type,
                         const char *, const WEBAUTH_KEYRING *,
                         struct webauth_token **)
    __attribute__((__nonnull__));
int webauth_token_decode_raw(struct webauth_context *, enum webauth_token_type,
                             const void *, size_t, const WEBAUTH_KEYRING *,
                             struct webauth_token **)
    __attribute__((__nonnull__));

/*
 * Encode a token.  Takes a token struct and a keyring to use for encryption,
 * and stores in the token argument the newly created token (in pool-allocated
 * memory).  On error, the token argument is set to NULL and an error code is
 * returned.
 *
 * The raw variant generates a token that is not base64-encoded, such as the
 * webkdc-proxy token embedded inside a proxy token, and stores the length of
 * the generated token in length.
 */
int webauth_token_encode(struct webauth_context *,
                         const struct webauth_token *,
                         const WEBAUTH_KEYRING *, const char **token)
    __attribute__((__nonnull__));
int webauth_token_encode_raw(struct webauth_context *,
                             const struct webauth_token *,
                             const WEBAUTH_KEYRING *, const void **token,
                             size_t *length)
    __attribute__((__nonnull__));

END_DECLS

#endif /* !WEBAUTH_TOKENS_H */
