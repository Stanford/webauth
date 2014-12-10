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
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2011, 2012, 2013, 2014
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

struct webauth_context;
struct webauth_keyring;

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
    WA_TOKEN_WEBKDC_FACTOR,
    WA_TOKEN_WEBKDC_PROXY,
    WA_TOKEN_WEBKDC_SERVICE,
    WA_TOKEN_ANY = 255
};

/*
 * In the following token struct definitions, the "encode" comments are used
 * internally by the WebAuth code to generate encoding rules for the wire
 * format of the tokens.
 */

/*
 * Application token, used by a WebAuth Application Server to hold
 * authentication information for its own use.  (Note that applications are
 * not required to use this token format; nothing else in the WebAuth protocol
 * uses it.  It is, however, the token format used by mod_webauth in the
 * standard WebAuth distribution for the application cookie.)
 */
struct webauth_token_app {
    const char *subject;                /* encode: s, optional */
    const char *authz_subject;          /* encode: sz, optional */
    time_t last_used;                   /* encode: lt, optional */
    const void *session_key;            /* encode: k, optional */
    size_t session_key_len;
    const char *initial_factors;        /* encode: ia, optional */
    const char *session_factors;        /* encode: san, optional */
    unsigned long loa;                  /* encode: loa, optional */
    time_t creation;                    /* encode: ct, creation, optional */
    time_t expiration;                  /* encode: et */
};

/*
 * Credential token, which holds a credential for some other service (usually
 * a Kerberos service ticket).  It is sent back by the WebKDC to a WebAuth
 * Application Server when requested using a proxy token, and the WAS also
 * uses it to store the credentials in cookies.
 */
struct webauth_token_cred {
    const char *subject;                /* encode: s */
    const char *type;                   /* encode: crt */
    const char *service;                /* encode: crs */
    const void *data;                   /* encode: crd */
    size_t data_len;
    time_t creation;                    /* encode: ct, creation */
    time_t expiration;                  /* encode: et */
};

/*
 * Error token, returned by the WebKDC in response to a request token if some
 * error occurred in processing that request.
 */
struct webauth_token_error {
    unsigned long code;                 /* encode: ec, ascii */
    const char *message;                /* encode: em */
    time_t creation;                    /* encode: ct, creation */
};

/*
 * Id token, which identifies a user to a WebAuth Authentication Server.  This
 * token is sent from the WebKDC to the WAS following a user authentication to
 * communicate the authentication information.
 */
struct webauth_token_id {
    const char *subject;                /* encode: s, optional */
    const char *authz_subject;          /* encode: sz, optional */
    const char *auth;                   /* encode: sa */
    const void *auth_data;              /* encode: sad, optional */
    size_t auth_data_len;
    const char *initial_factors;        /* encode: ia, optional */
    const char *session_factors;        /* encode: san, optional */
    unsigned long loa;                  /* encode: loa, optional */
    time_t creation;                    /* encode: ct, creation */
    time_t expiration;                  /* encode: et */
};

/*
 * Login token, sent from the WebLogin server to the WebKDC and containing the
 * user's username and password or other authentication secret.
 */
struct webauth_token_login {
    const char *username;               /* encode: u */
    const char *password;               /* encode: p, optional */
    const char *otp;                    /* encode: otp, optional */
    const char *otp_type;               /* encode: ott, optional */
    const char *device_id;              /* encode: did, optional */
    time_t creation;                    /* encode: ct, creation */
};

/*
 * Proxy token, returned by the WebKDC to a WebAuth Application Server if the
 * WAS may need to request various tokens (particularly credential tokens).
 * The embedded webkdc-proxy token is stored in an intermediate binary form
 * and used as an opaque blob for creating later requests to the WebKDC.
 */
struct webauth_token_proxy {
    const char *subject;                /* encode: s */
    const char *authz_subject;          /* encode: sz, optional */
    const char *type;                   /* encode: pt */
    const void *webkdc_proxy;           /* encode: wt */
    size_t webkdc_proxy_len;
    const char *initial_factors;        /* encode: ia, optional */
    const char *session_factors;        /* encode: san, optional */
    unsigned long loa;                  /* encode: loa, optional */
    time_t creation;                    /* encode: ct, creation */
    time_t expiration;                  /* encode: et */
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
    const char *type;                   /* encode: rtt, optional */
    const char *auth;                   /* encode: sa, optional */
    const char *proxy_type;             /* encode: pt, optional */
    const void *state;                  /* encode: as, optional */
    size_t state_len;
    const char *return_url;             /* encode: ru, optional */
    const char *options;                /* encode: ro, optional */
    const char *initial_factors;        /* encode: ia, optional */
    const char *session_factors;        /* encode: san, optional */
    unsigned long loa;                  /* encode: loa, optional */
    const char *command;                /* encode: cmd, optional */
    time_t creation;                    /* encode: ct, creation */
};

/*
 * WebKDC facter token, which adds additional factors that will be combined
 * with valid login or webkdc-proxy tokens but which cannot, by themselves,
 * authenticate the user.  This token is stored as a separate cookie in the
 * user's browser, possibly with a longer lifespan than the single sign-on
 * credentials, and may also be returned by the user information service for
 * certain types of authentications.
 */
struct webauth_token_webkdc_factor {
    const char *subject;                /* encode: s */
    const char *factors;                /* encode: ia */
    time_t creation;                    /* encode: ct, creation */
    time_t expiration;                  /* encode: et */
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
    const char *subject;                /* encode: s */
    const char *proxy_type;             /* encode: pt */
    const char *proxy_subject;          /* encode: ps */
    const void *data;                   /* encode: pd, optional */
    size_t data_len;
    const char *initial_factors;        /* encode: ia, optional */
    unsigned long loa;                  /* encode: loa, optional */
    time_t creation;                    /* encode: ct, creation */
    time_t expiration;                  /* encode: et */

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
    const char *subject;                /* encode: s */
    const void *session_key;            /* encode: k */
    size_t session_key_len;
    time_t creation;                    /* encode: ct, creation */
    time_t expiration;                  /* encode: et */
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
        struct webauth_token_webkdc_factor webkdc_factor;
        struct webauth_token_webkdc_proxy webkdc_proxy;
        struct webauth_token_webkdc_service webkdc_service;
    } token;
};

BEGIN_DECLS

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
                         const char *, const struct webauth_keyring *,
                         struct webauth_token **)
    __attribute__((__nonnull__));
int webauth_token_decode_raw(struct webauth_context *, enum webauth_token_type,
                             const void *, size_t,
                             const struct webauth_keyring *,
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
                         const struct webauth_keyring *, const char **token)
    __attribute__((__nonnull__));
int webauth_token_encode_raw(struct webauth_context *,
                             const struct webauth_token *,
                             const struct webauth_keyring *,
                             const void **token, size_t *length)
    __attribute__((__nonnull__));

/*
 * Decrypts a token.  The best decryption key on the ring will be tried first,
 * and if that fails all the remaining keys will be tried.  Returns the
 * decrypted data in output and its length in output_len.
 *
 * Returns WA_ERR_NONE, WA_ERR_NO_MEM, WA_ERR_CORRUPT, WA_ERR_BAD_HMAC, or
 * WA_ERR_BAD_KEY.
 */
int webauth_token_decrypt(struct webauth_context *, const void *input,
                          size_t input_len, void **output, size_t *output_len,
                          const struct webauth_keyring *)
    __attribute__((__nonnull__));

/*
 * Encrypts an input buffer (normally encoded attributes) into a token, using
 * the key from the keyring that has the most recent valid valid_from time.
 * The encoded token will be stored in newly pool-allocated memory in the
 * provided output argument, with its length stored in output_len.
 *
 * Returns a WebAuth status code, which may be WA_ERR_BAD_KEY if no suitable
 * and valid encryption key could be found in the keyring.
 */
int webauth_token_encrypt(struct webauth_context *, const void *input,
                          size_t len, void **output, size_t *output_len,
                          const struct webauth_keyring *)
    __attribute__((__nonnull__));

END_DECLS

#endif /* !WEBAUTH_TOKENS_H */
