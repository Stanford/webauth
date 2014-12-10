/*
 * High level interface to encoding WebAuth tokens.
 *
 * Interfaces for encoding tokens from internal structs to the encrypted wire
 * tokens representing the same information.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2011, 2012, 2013, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/apr.h>
#include <portable/system.h>

#include <apr_base64.h>
#include <apr_lib.h>
#include <apr_uri.h>
#include <time.h>

#include <lib/internal.h>
#include <util/macros.h>
#include <webauth/basic.h>
#include <webauth/tokens.h>

/*
 * The mapping of token types to token names as used in the token type
 * attribute in the wire encoding.  Note that WA_TOKEN_ANY cannot be used with
 * this array and has to be handled specially so that its value won't be used
 * by any new token type.  This must be kept in sync with the enum
 * webauth_token_type definition in webauth/tokens.h.
 */
static const char * const token_name[] = {
    /* WA_TOKEN_UNKNOWN        = */ "unknown",
    /* WA_TOKEN_APP            = */ "app",
    /* WA_TOKEN_CRED           = */ "cred",
    /* WA_TOKEN_ERROR          = */ "error",
    /* WA_TOKEN_ID             = */ "id",
    /* WA_TOKEN_LOGIN          = */ "login",
    /* WA_TOKEN_PROXY          = */ "proxy",
    /* WA_TOKEN_REQUEST        = */ "req",
    /* WA_TOKEN_WEBKDC_FACTOR  = */ "webkdc-factor",
    /* WA_TOKEN_WEBKDC_PROXY   = */ "webkdc-proxy",
    /* WA_TOKEN_WEBKDC_SERVICE = */ "webkdc-service"
};

/*
 * Whether we are encoding or decoding the token.  Some checks, such as for
 * expired tokens, are only performed when decoding, since it's sometimes
 * useful (such as for testing) to create expired tokens.
 */
enum encode_mode { ENCODE, DECODE };

/*
 * Macros to check whether an attribute is set, used for sanity checks while
 * encoding.  Takes the name of the struct and the struct member, and assumes
 * ctx is the WebAuth context.
 */
#define CHECK_DATA(token, attr)                                         \
    do {                                                                \
        if (token->attr == NULL || token->attr ## _len == 0) {          \
            const char *err;                                            \
            err = (token->attr == NULL) ? "missing" : "empty";          \
            return wai_error_set(ctx, WA_ERR_CORRUPT, "%s %s", err,     \
                                 APR_STRINGIFY(attr));                  \
        }                                                               \
    } while (0)
#define CHECK_NUM(token, attr)                                          \
    do {                                                                \
        if (token->attr == 0)                                           \
            return wai_error_set(ctx, WA_ERR_CORRUPT, "missing %s",     \
                                 APR_STRINGIFY(attr));                  \
    } while (0)
#define CHECK_STR(token, attr)                                          \
    do {                                                                \
        if (token->attr == NULL)                                        \
            return wai_error_set(ctx, WA_ERR_CORRUPT, "missing %s",     \
                                 APR_STRINGIFY(attr));                  \
    } while (0)

/* Check that a pointer that should be NULL is. */
#define CHECK_NULL(token, attr, reason)                                 \
    do {                                                                \
        if (token->attr != NULL) {                                      \
            wai_error_set(ctx, WA_ERR_CORRUPT, "%s not valid with %s",  \
                          APR_STRINGIFY(attr), reason);                 \
            return WA_ERR_CORRUPT;                                      \
        }                                                               \
    } while (0)

/* Check that a value that should be numerically zero is. */
#define CHECK_ZERO(token, attr, reason)                                 \
    do {                                                                \
        if (token->attr != 0) {                                         \
            wai_error_set(ctx, WA_ERR_CORRUPT, "%s not valid with %s",  \
                          APR_STRINGIFY(attr), reason);                 \
            return WA_ERR_CORRUPT;                                      \
        }                                                               \
    } while (0)

/*
 * Macro wrapper around check_expiration that handles control flow similar
 * to the other CHECK_* macros.
 */
#define CHECK_EXP(token, attr, mode)                    \
    do {                                                \
        CHECK_NUM(token, attr);                         \
        if (mode == DECODE) {                           \
            int s;                                      \
            s = check_expiration(ctx, token->attr);     \
            if (s != WA_ERR_NONE)                       \
                return s;                               \
        }                                               \
    } while (0)


/*
 * Map a token type string to one of the enum token_type constants.  Returns
 * WA_TOKEN_UNKNOWN on error.  This would arguably be faster as a binary
 * search, but there aren't enough cases to worry about it.
 */
enum webauth_token_type
webauth_token_type_code(const char *type)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(token_name); i++)
        if (strcmp(type, token_name[i]) == 0)
            return i;
    return WA_TOKEN_UNKNOWN;
}


/*
 * Map a token type code to the corresponding string representation used in
 * tokens.  Returns NULL for an invalid code.
 */
const char *
webauth_token_type_string(enum webauth_token_type type)
{
    if (type >= ARRAY_SIZE(token_name))
        return NULL;
    return token_name[type];
}


/*
 * Map a token type code to the corresponding encoding rule set and data
 * pointer.  Takes the token struct (which must have the type filled out), and
 * stores a pointer to the encoding rules and a pointer to the correct data
 * portion of the token struct in the provided output arguments.  Returns an
 * error code, which will be set to an error if the token type is not
 * recognized.
 */
int
wai_token_encoding(struct webauth_context *ctx,
                   const struct webauth_token *token,
                   const struct wai_encoding **rules, const void **data)
{
    int s;

    switch (token->type) {
    case WA_TOKEN_APP:
        *rules = wai_token_app_encoding;
        *data = &token->token.app;
        break;
    case WA_TOKEN_CRED:
        *rules = wai_token_cred_encoding;
        *data = &token->token.cred;
        break;
    case WA_TOKEN_ERROR:
        *rules = wai_token_error_encoding;
        *data = &token->token.error;
        break;
    case WA_TOKEN_ID:
        *rules = wai_token_id_encoding;
        *data = &token->token.id;
        break;
    case WA_TOKEN_LOGIN:
        *rules = wai_token_login_encoding;
        *data = &token->token.login;
        break;
    case WA_TOKEN_PROXY:
        *rules = wai_token_proxy_encoding;
        *data = &token->token.proxy;
        break;
    case WA_TOKEN_REQUEST:
        *rules = wai_token_request_encoding;
        *data = &token->token.request;
        break;
    case WA_TOKEN_WEBKDC_FACTOR:
        *rules = wai_token_webkdc_factor_encoding;
        *data = &token->token.webkdc_factor;
        break;
    case WA_TOKEN_WEBKDC_PROXY:
        *rules = wai_token_webkdc_proxy_encoding;
        *data = &token->token.webkdc_proxy;
        break;
    case WA_TOKEN_WEBKDC_SERVICE:
        *rules = wai_token_webkdc_service_encoding;
        *data = &token->token.webkdc_service;
        break;
    case WA_TOKEN_UNKNOWN:
    case WA_TOKEN_ANY:
    default:
        s = WA_ERR_INVALID;
        return wai_error_set(ctx, s, "unknown token type %d", token->type);
    }
    return WA_ERR_NONE;
}

/*
 * Check the expiration time of a token and set the appropriate error if the
 * token has expired.  This is only called on token decoding, not on token
 * encoding.  Takes the WebAuth context and the expiration time and returns a
 * WebAuth status code.
 */
static int
check_expiration(struct webauth_context *ctx, time_t expiration)
{
    time_t now;
    int s = WA_ERR_NONE;

    now = time(NULL);
    if (expiration < now) {
        s = WA_ERR_TOKEN_EXPIRED;
        wai_error_set(ctx, s, "expired at %lu", (unsigned long) expiration);
    }
    return s;
}


/*
 * Check the provided value to determine whether it's a valid credential type.
 * Assumes the credential type is non-NULL.  Returns a WebAuth error code and
 * sets the error message if needed.
 */
static int
check_cred_type(struct webauth_context *ctx, const char *cred_type)
{
    int s = WA_ERR_NONE;

    if (strcmp(cred_type, "krb5") != 0) {
        s = WA_ERR_CORRUPT;
        wai_error_set(ctx, s, "unknown credential type %s", cred_type);
    }
    return s;
}


/*
 * Check the provided value to determine whether it's a valid proxy type.
 * Assumes the proxy type is non-NULL.  Returns a WebAuth error code and sets
 * the error message if needed.
 */
static int
check_proxy_type(struct webauth_context *ctx, const char *proxy_type)
{
    int s = WA_ERR_NONE;

    if (strcmp(proxy_type, "krb5") != 0) {
        s = WA_ERR_CORRUPT;
        wai_error_set(ctx, s, "unknown proxy type %s", proxy_type);
    }
    return s;
}


/*
 * Check the provided value to determine whether it's a valid subject auth
 * type.  Assumes the subject auth type is non-NULL.  Returns a WebAuth error
 * code and sets the error message if needed.
 */
static int
check_subject_auth(struct webauth_context *ctx, const char *auth)
{
    int s = WA_ERR_NONE;

    if (strcmp(auth, "krb5") != 0 && strcmp(auth, "webkdc") != 0) {
        s = WA_ERR_CORRUPT;
        wai_error_set(ctx, s, "unknown auth type %s", auth);
    }
    return s;
}


/*
 * Check a given URL for validity.  URLs are required to be absolute and to
 * be composed solely of ASCII characters.  Returns a WebAuth error code and
 * sets the error message if needed.
 */
static int
check_url(struct webauth_context *ctx, const char *url)
{
    const char *p;
    apr_status_t code;
    apr_uri_t uri;

    /*
     * Ensure that the return URL is a valid ASCII string.  Non-ASCII
     * characters in URLs must be encoded according to the protocol and, more
     * practically, will create errors in WebLogin since the WebLogin code
     * doesn't decode and encode strings from the WebKDC response and
     * therefore doesn't properly handle Unicode or other non-ASCII characters
     * in the URL.
     */
    for (p = url; *p != '\0'; p++)
        if (!apr_isascii(*p))
            return wai_error_set(ctx, WA_ERR_CORRUPT,
                                 "non-ASCII characters in URL \"%s\"", url);

    /* Ensure that the return URL is a valid, absolute URL. */
    memset(&uri, 0, sizeof(uri));
    code = apr_uri_parse(ctx->pool, url, &uri);
    if (code != APR_SUCCESS)
        return wai_error_set_apr(ctx, WA_ERR_CORRUPT, code,
                                 "cannot parse URL \"%s\"", url);
    if (uri.scheme == NULL || uri.hostname == NULL || uri.path == NULL)
        return wai_error_set(ctx, WA_ERR_CORRUPT, "invalid URL \"%s\"", url);
    return WA_ERR_NONE;
}


/*
 * Check an application token for valid data.
 */
static int
check_app(struct webauth_context *ctx, const struct webauth_token_app *app,
          enum encode_mode mode)
{
    CHECK_EXP(app, expiration, mode);
    if (app->session_key == NULL)
        CHECK_STR(app, subject);
    else {
        CHECK_NULL(app, subject,         "session key");
        CHECK_NULL(app, authz_subject,   "session key");
        CHECK_ZERO(app, last_used,       "session key");
        CHECK_NULL(app, initial_factors, "session key");
        CHECK_NULL(app, session_factors, "session key");
        CHECK_ZERO(app, loa,             "session key");
    }
    return WA_ERR_NONE;
}


/*
 * Check a cred token for valid data.
 */
static int
check_cred(struct webauth_context *ctx, const struct webauth_token_cred *cred,
           enum encode_mode mode)
{
    CHECK_STR( cred, subject);
    CHECK_STR( cred, type);
    CHECK_STR( cred, service);
    CHECK_DATA(cred, data);
    CHECK_EXP( cred, expiration, mode);
    return check_cred_type(ctx, cred->type);
}


/*
 * Check an error token for valid data.
 */
static int
check_error(struct webauth_context *ctx,
            const struct webauth_token_error *error,
            enum encode_mode mode UNUSED)
{
    CHECK_NUM(error, code);
    CHECK_STR(error, message);
    return WA_ERR_NONE;
}


/*
 * Check an id token for valid data.
 */
static int
check_id(struct webauth_context *ctx, const struct webauth_token_id *id,
         enum encode_mode mode)
{
    CHECK_STR(id, auth);
    CHECK_EXP(id, expiration, mode);
    if (strcmp(id->auth, "webkdc") == 0)
        CHECK_STR(id, subject);
    if (strcmp(id->auth, "krb5") == 0)
        CHECK_DATA(id, auth_data);
    return check_subject_auth(ctx, id->auth);
}


/*
 * Check a login token for valid data.
 */
static int
check_login(struct webauth_context *ctx,
            const struct webauth_token_login *login,
            enum encode_mode mode UNUSED)
{
    CHECK_STR(login, username);
    if (login->password == NULL)
        if (login->otp == NULL && login->device_id == NULL) {
            wai_error_set(ctx, WA_ERR_CORRUPT,
                          "password, otp, or device_id required");
            return WA_ERR_CORRUPT;
        }
    if (login->password != NULL && login->otp != NULL)
        return wai_error_set(ctx, WA_ERR_CORRUPT, "both password and otp set");
    if (login->password != NULL) {
        CHECK_NULL(login, otp_type, "password");
        CHECK_NULL(login, device_id, "password");
    }
    return WA_ERR_NONE;
}


/*
 * Check a proxy token for valid data.
 */
static int
check_proxy(struct webauth_context *ctx,
            const struct webauth_token_proxy *proxy, enum encode_mode mode)
{
    CHECK_STR( proxy, subject);
    CHECK_STR( proxy, type);
    CHECK_DATA(proxy, webkdc_proxy);
    CHECK_EXP( proxy, expiration, mode);
    return check_proxy_type(ctx, proxy->type);
}


/*
 * Check a request token for valid data.
 */
static int
check_request(struct webauth_context *ctx,
              const struct webauth_token_request *request,
              enum encode_mode mode UNUSED)
{
    int s;

    /*
     * There are two entirely different types of data represented here, so we
     * have to do checks based on what type of request token it is.
     */
    if (request->command != NULL) {
        CHECK_NULL(request, type,            "command");
        CHECK_NULL(request, auth,            "command");
        CHECK_NULL(request, proxy_type,      "command");
        CHECK_NULL(request, state,           "command");
        CHECK_NULL(request, return_url,      "command");
        CHECK_NULL(request, options,         "command");
        CHECK_NULL(request, initial_factors, "command");
        CHECK_NULL(request, session_factors, "command");
    } else {
        CHECK_STR(request, type);
        CHECK_STR(request, return_url);
        s = check_url(ctx, request->return_url);
        if (s != WA_ERR_NONE)
            return s;
        if (strcmp(request->type, "id") == 0) {
            CHECK_STR(request, auth);
            s = check_subject_auth(ctx, request->auth);
            if (s != WA_ERR_NONE)
                return s;
        } else if (strcmp(request->type, "proxy") == 0) {
            CHECK_STR(request, proxy_type);
            s = check_proxy_type(ctx, request->proxy_type);
            if (s != WA_ERR_NONE)
                return s;
        } else {
            wai_error_set(ctx, WA_ERR_CORRUPT,
                          "unknown requested token type %s", request->type);
            return WA_ERR_CORRUPT;
        }
    }
    return WA_ERR_NONE;
}


/*
 * Check a webkdc-factor token for valid data.
 */
static int
check_webkdc_factor(struct webauth_context *ctx,
                    const struct webauth_token_webkdc_factor *webkdc_factor,
                    enum encode_mode mode)
{
    CHECK_STR(webkdc_factor, subject);
    CHECK_STR(webkdc_factor, factors);
    CHECK_EXP(webkdc_factor, expiration, mode);
    return WA_ERR_NONE;
}


/*
 * Check a webkdc-proxy token for valid data.
 */
static int
check_webkdc_proxy(struct webauth_context *ctx,
                   const struct webauth_token_webkdc_proxy *webkdc_proxy,
                   enum encode_mode mode)
{
    CHECK_STR(webkdc_proxy, subject);
    CHECK_STR(webkdc_proxy, proxy_type);
    CHECK_STR(webkdc_proxy, proxy_subject);
    CHECK_EXP(webkdc_proxy, expiration, mode);
    if (strcmp(webkdc_proxy->proxy_type, "krb5") != 0
        && strcmp(webkdc_proxy->proxy_type, "remuser") != 0
        && strcmp(webkdc_proxy->proxy_type, "otp") != 0)
        return wai_error_set(ctx, WA_ERR_CORRUPT, "unknown proxy type %s",
                             webkdc_proxy->proxy_type);
    return WA_ERR_NONE;
}


/*
 * Check a webkdc-service token for valid data.
 */
static int
check_webkdc_service(struct webauth_context *ctx,
                     const struct webauth_token_webkdc_service *webkdc_service,
                     enum encode_mode mode)
{
    CHECK_STR( webkdc_service, subject);
    CHECK_DATA(webkdc_service, session_key);
    CHECK_EXP( webkdc_service, expiration, mode);
    return WA_ERR_NONE;
}


/*
 * Check a token.  Takes the context, the generic token struct, and the enum
 * saying whether we're encoding or decoding the token.  Returns a WebAuth
 * status.
 */
static int
check_token(struct webauth_context *ctx, const struct webauth_token *token,
            enum encode_mode mode)
{
    switch (token->type) {
    case WA_TOKEN_APP:
        return check_app(ctx, &token->token.app, mode);
    case WA_TOKEN_CRED:
        return check_cred(ctx, &token->token.cred, mode);
    case WA_TOKEN_ERROR:
        return check_error(ctx, &token->token.error, mode);
    case WA_TOKEN_ID:
        return check_id(ctx, &token->token.id, mode);
    case WA_TOKEN_LOGIN:
        return check_login(ctx, &token->token.login, mode);
    case WA_TOKEN_PROXY:
        return check_proxy(ctx, &token->token.proxy, mode);
    case WA_TOKEN_REQUEST:
        return check_request(ctx, &token->token.request, mode);
    case WA_TOKEN_WEBKDC_FACTOR:
        return check_webkdc_factor(ctx, &token->token.webkdc_factor, mode);
    case WA_TOKEN_WEBKDC_PROXY:
        return check_webkdc_proxy(ctx, &token->token.webkdc_proxy, mode);
    case WA_TOKEN_WEBKDC_SERVICE:
        return check_webkdc_service(ctx, &token->token.webkdc_service, mode);
    case WA_TOKEN_UNKNOWN:
    case WA_TOKEN_ANY:
    default:
        return wai_error_set(ctx, WA_ERR_INVALID, "unknown token type %d",
                             token->type);
    }
}


/*
 * Decode an arbitrary raw token (one that is not base64-encoded).  Takes the
 * context, the expected token type (which may be WA_TOKEN_ANY), the token,
 * its length, and the keyring to decrypt it, and stores the newly-allocated
 * generic token struct in the decoded argument.  On error, decoded is set to
 * NULL and an error code is returned.
 */
int
webauth_token_decode_raw(struct webauth_context *ctx,
                         enum webauth_token_type type, const void *token,
                         size_t length, const struct webauth_keyring *ring,
                         struct webauth_token **decoded)
{
    void *attrs;
    size_t alen;
    const char *type_string = NULL;
    struct webauth_token *out;
    int s;

    /* Allocate some space to store the decoded token. */
    *decoded = NULL;
    out = apr_palloc(ctx->pool, sizeof(struct webauth_token));

    /* Do some initial sanity checking. */
    type_string = webauth_token_type_string(type);
    if (type_string == NULL && type != WA_TOKEN_ANY) {
        s = WA_ERR_INVALID;
        wai_error_set(ctx, s, "unknown token type %d", type);
        goto fail;
    }

    /* Decrypt the token. */
    s = webauth_token_decrypt(ctx, token, length, &attrs, &alen, ring);
    if (s != WA_ERR_NONE)
        goto fail;

    /* Decode the attributes. */
    s = wai_decode_token(ctx, attrs, alen, out);
    if (s != WA_ERR_NONE)
        goto fail;

    /* Check the token type to see if it's what we expect. */
    if (type != WA_TOKEN_ANY && type != out->type) {
        s = WA_ERR_CORRUPT;
        wai_error_set(ctx, s, "wrong token type %s",
                      webauth_token_type_string(out->type));
        goto fail;
    }
    type_string = webauth_token_type_string(out->type);

    /* Check the token data for consistency. */
    s = check_token(ctx, out, DECODE);
    if (s != WA_ERR_NONE)
        goto fail;

    /* Success. */
    *decoded = out;
    return WA_ERR_NONE;

fail:
    if (type_string == NULL)
        wai_error_context(ctx, "decoding token");
    else
        wai_error_context(ctx, "decoding %s token", type_string);
    return s;
}


/*
 * Decode an arbitrary (base64-encoded) token.  Takes the context, the
 * expected token type (which may be WA_TOKEN_ANY), the token, and the keyring
 * to decrypt it, and stores the newly-allocated generic token struct in the
 * decoded argument.  On error, decoded is set to NULL and an error code is
 * returned.
 */
int
webauth_token_decode(struct webauth_context *ctx,
                     enum webauth_token_type type, const char *token,
                     const struct webauth_keyring *ring,
                     struct webauth_token **decoded)
{
    size_t length;
    void *input;

    if (token == NULL)
        return wai_error_set(ctx, WA_ERR_INVALID, "token is NULL");
    length = apr_base64_decode_len(token);
    input = apr_palloc(ctx->pool, length);
    length = apr_base64_decode(input, token);
    return webauth_token_decode_raw(ctx, type, input, length, ring, decoded);
}


/*
 * Encode a raw token (one that is not base64-encoded.  Takes a token struct
 * and a keyring to use for encryption, and stores in the token argument the
 * newly created token (in pool-allocated memory), with the length stored in
 * length.  On error, the token argument is set to NULL and an error code is
 * returned.
 */
int
webauth_token_encode_raw(struct webauth_context *ctx,
                         const struct webauth_token *data,
                         const struct webauth_keyring *ring,
                         const void **token, size_t *length)
{
    const char *type;
    void *attrs, *output;
    size_t alen;
    int s;

    /* Get the token type for error context reporting. */
    type = webauth_token_type_string(data->type);
    if (type == NULL)
        type = "unknown";

    /* Sanity check the arguments. */
    if (ring == NULL) {
        s = WA_ERR_BAD_KEY;
        wai_error_set(ctx, s, "keyring is NULL");
        goto fail;
    }
    s = check_token(ctx, data, ENCODE);
    if (s != WA_ERR_NONE)
        goto fail;

    /* Encode and encrypt the token. */
    s = wai_encode_token(ctx, data, &attrs, &alen);
    if (s != WA_ERR_NONE)
        goto fail;
    s = webauth_token_encrypt(ctx, attrs, alen, &output, length, ring);
    if (s != WA_ERR_NONE)
        goto fail;
    *token = output;
    return WA_ERR_NONE;

fail:
    wai_error_context(ctx, "encoding %s token", type);
    return s;
}


/*
 * Encode a token.  Takes a token struct and a keyring to use for encryption,
 * and stores in the token argument the newly created token (in pool-allocated
 * memory).  On error, the token argument is set to NULL and an error code is
 * returned.
 */
int
webauth_token_encode(struct webauth_context *ctx,
                     const struct webauth_token *data,
                     const struct webauth_keyring *ring, const char **token)
{
    int s;
    const void *raw;
    char *btoken;
    size_t length;

    /*
     * First, we encode the binary form into newly allocated memory, and then
     * we allocate an additional block of memory for the base64-encoded form.
     * The first block is temporary memory that we could reclaim faster if it
     * ever looks worthwhile.
     */
    *token = NULL;
    s = webauth_token_encode_raw(ctx, data, ring, &raw, &length);
    if (s != WA_ERR_NONE)
        return s;
    btoken = apr_palloc(ctx->pool, apr_base64_encode_len(length));
    apr_base64_encode(btoken, raw, length);
    *token = btoken;
    return WA_ERR_NONE;
}
