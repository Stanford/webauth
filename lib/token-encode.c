/*
 * High level interface to encoding WebAuth tokens.
 *
 * Interfaces for encoding tokens from internal structs to the encrypted wire
 * tokens representing the same information.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011, 2012
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/apr.h>
#include <portable/system.h>

#include <apr_base64.h>
#include <time.h>

#include <lib/internal.h>
#include <util/macros.h>
#include <webauth.h>
#include <webauth/basic.h>
#include <webauth/tokens.h>

/*
 * Macros to check whether an attribute is set, used for sanity checks while
 * encoding.  Takes the name of the struct and the struct member, and assumes
 * ctx is the WebAuth context.
 */
#define CHECK_DATA(token, attr)                                         \
    do {                                                                \
        if (token->attr == NULL || token->attr ## _len == 0) {          \
            const char *err                                             \
                = (token->attr == NULL) ? "missing" : "empty";          \
            webauth_error_set(ctx, WA_ERR_CORRUPT,                      \
                              "%s %s for %s token", err,                \
                              APR_STRINGIFY(attr),                      \
                              APR_STRINGIFY(token));                    \
            return WA_ERR_CORRUPT;                                      \
        }                                                               \
    } while (0)
#define CHECK_NUM(token, attr)                                  \
    do {                                                        \
        if (token->attr == 0) {                                 \
            webauth_error_set(ctx, WA_ERR_CORRUPT,              \
                              "missing %s for %s token",        \
                              APR_STRINGIFY(attr),              \
                              APR_STRINGIFY(token));            \
            return WA_ERR_CORRUPT;                              \
        }                                                       \
    } while (0)
#define CHECK_STR(token, attr)                                          \
    do {                                                                \
        if (token->attr == NULL) {                                      \
            webauth_error_set(ctx, WA_ERR_CORRUPT,                      \
                              "missing %s for %s token",                \
                              APR_STRINGIFY(attr),                      \
                              APR_STRINGIFY(token));                    \
            return WA_ERR_CORRUPT;                                      \
        }                                                               \
    } while (0)

/* Check that a pointer that should be NULL is. */
#define CHECK_NULL(token, attr, reason)                                 \
    do {                                                                \
        if (token->attr != NULL) {                                      \
            webauth_error_set(ctx, WA_ERR_CORRUPT,                      \
                              "%s not valid with %s in %s token",       \
                              APR_STRINGIFY(attr), reason,              \
                              APR_STRINGIFY(token));                    \
            return WA_ERR_CORRUPT;                                      \
        }                                                               \
    } while (0)

/* Check that a value that should be numerically zero is. */
#define CHECK_ZERO(token, attr, reason)                                 \
    do {                                                                \
        if (token->attr != 0) {                                         \
            webauth_error_set(ctx, WA_ERR_CORRUPT,                      \
                              "%s not valid with %s in %s token",       \
                              APR_STRINGIFY(attr), reason,              \
                              APR_STRINGIFY(token));                    \
            return WA_ERR_CORRUPT;                                      \
        }                                                               \
    } while (0)


/*
 * Check an application token for valid data.
 */
static int
check_app(struct webauth_context *ctx, const struct webauth_token_app *app)
{
    CHECK_NUM(app, expiration);
    if (app->session_key == NULL)
        CHECK_STR(app, subject);
    else {
        CHECK_NULL(app, subject,         "session key");
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
check_cred(struct webauth_context *ctx, const struct webauth_token_cred *cred)
{
    CHECK_STR( cred, subject);
    CHECK_STR( cred, type);
    CHECK_STR( cred, service);
    CHECK_DATA(cred, data);
    CHECK_NUM( cred, expiration);
    if (strcmp(cred->type, "krb5") != 0) {
        webauth_error_set(ctx, WA_ERR_CORRUPT,
                          "unknown type %s for cred token", cred->type);
        return WA_ERR_CORRUPT;
    }
    return WA_ERR_NONE;
}


/*
 * Check an error token for valid data.
 */
static int
check_error(struct webauth_context *ctx,
            const struct webauth_token_error *error)
{
    CHECK_NUM(error, code);
    CHECK_STR(error, message);
    return WA_ERR_NONE;
}


/*
 * Check an id token for valid data.
 */
static int
check_id(struct webauth_context *ctx, const struct webauth_token_id *id)
{
    CHECK_STR(id, auth);
    CHECK_NUM(id, expiration);
    if (strcmp(id->auth, "krb5") != 0 && strcmp(id->auth, "webkdc") != 0) {
        webauth_error_set(ctx, WA_ERR_CORRUPT,
                          "unknown subject auth %s for id token", id->auth);
        return WA_ERR_CORRUPT;
    }
    if (strcmp(id->auth, "webkdc") == 0)
        CHECK_STR(id, subject);
    if (strcmp(id->auth, "krb5") == 0)
        CHECK_DATA(id, auth_data);
    return WA_ERR_NONE;
}


/*
 * Check a login token for valid data.
 */
static int
check_login(struct webauth_context *ctx,
            const struct webauth_token_login *login)
{
    CHECK_STR(login, username);
    if (login->password == NULL && login->otp == NULL) {
        webauth_error_set(ctx, WA_ERR_CORRUPT,
                          "either password or otp required for login token");
        return WA_ERR_CORRUPT;
    }
    if (login->password != NULL && login->otp != NULL) {
        webauth_error_set(ctx, WA_ERR_CORRUPT,
                          "both password and otp set in login token");
        return WA_ERR_CORRUPT;
    }
    return WA_ERR_NONE;
}


/*
 * Check a proxy token for valid data.
 */
static int
check_proxy(struct webauth_context *ctx,
            const struct webauth_token_proxy *proxy)
{
    CHECK_STR( proxy, subject);
    CHECK_STR( proxy, type);
    CHECK_DATA(proxy, webkdc_proxy);
    CHECK_NUM( proxy, expiration);
    if (strcmp(proxy->type, "krb5") != 0) {
        webauth_error_set(ctx, WA_ERR_CORRUPT,
                          "unknown type %s for proxy token", proxy->type);
        return WA_ERR_CORRUPT;
    }
    return WA_ERR_NONE;
}


/*
 * Check a request token for valid data.
 */
static int
check_request(struct webauth_context *ctx,
              const struct webauth_token_request *request)
{
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
        CHECK_STR( request, type);
        CHECK_STR( request, return_url);
        if (strcmp(request->type, "id") == 0) {
            CHECK_STR( request, auth);
            if (strcmp(request->auth, "krb5") != 0
                && strcmp(request->auth, "webkdc") != 0) {
                webauth_error_set(ctx, WA_ERR_CORRUPT,
                                  "unknown subject auth %s for request token",
                                  request->auth);
                return WA_ERR_CORRUPT;
            }
        } else if (strcmp(request->type, "proxy") == 0) {
            CHECK_STR( request, proxy_type);
            if (strcmp(request->proxy_type, "krb5") != 0) {
                webauth_error_set(ctx, WA_ERR_CORRUPT,
                                  "unknown proxy type %s for request token",
                                  request->proxy_type);
                return WA_ERR_CORRUPT;
            }
        } else {
            webauth_error_set(ctx, WA_ERR_CORRUPT,
                              "unknown requested token type %s for request"
                              " token", request->type);
            return WA_ERR_CORRUPT;
        }
    }
    return WA_ERR_NONE;
}


/*
 * Check a webkdc-proxy token for valid data.
 */
static int
check_webkdc_proxy(struct webauth_context *ctx,
                   const struct webauth_token_webkdc_proxy *webkdc_proxy)
{
    CHECK_STR(webkdc_proxy, subject);
    CHECK_STR(webkdc_proxy, proxy_type);
    CHECK_STR(webkdc_proxy, proxy_subject);
    CHECK_NUM(webkdc_proxy, expiration);
    if (strcmp(webkdc_proxy->proxy_type, "krb5") != 0
        && strcmp(webkdc_proxy->proxy_type, "remuser") != 0
        && strcmp(webkdc_proxy->proxy_type, "otp") != 0) {
        webauth_error_set(ctx, WA_ERR_CORRUPT,
                          "unknown proxy type %s for webkdc-proxy token",
                          webkdc_proxy->proxy_type);
        return WA_ERR_CORRUPT;
    }
    return WA_ERR_NONE;
}


/*
 * Check a webkdc-service token for valid data.
 */
static int
check_webkdc_service(struct webauth_context *ctx,
                     const struct webauth_token_webkdc_service *webkdc_service)
{
    CHECK_STR( webkdc_service, subject);
    CHECK_DATA(webkdc_service, session_key);
    CHECK_NUM( webkdc_service, expiration);
    return WA_ERR_NONE;
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
    void *attrs, *output;
    size_t alen;
    int status;

    if (ring == NULL) {
        webauth_error_set(ctx, WA_ERR_BAD_KEY,
                          "keyring is NULL while encoding token");
        return WA_ERR_BAD_KEY;
    }
    switch (data->type) {
    case WA_TOKEN_APP:
        status = check_app(ctx, &data->token.app);
        break;
    case WA_TOKEN_CRED:
        status = check_cred(ctx, &data->token.cred);
        break;
    case WA_TOKEN_ERROR:
        status = check_error(ctx, &data->token.error);
        break;
    case WA_TOKEN_ID:
        status = check_id(ctx, &data->token.id);
        break;
    case WA_TOKEN_LOGIN:
        status = check_login(ctx, &data->token.login);
        break;
    case WA_TOKEN_PROXY:
        status = check_proxy(ctx, &data->token.proxy);
        break;
    case WA_TOKEN_REQUEST:
        status = check_request(ctx, &data->token.request);
        break;
    case WA_TOKEN_WEBKDC_PROXY:
        status = check_webkdc_proxy(ctx, &data->token.webkdc_proxy);
        break;
    case WA_TOKEN_WEBKDC_SERVICE:
        status = check_webkdc_service(ctx, &data->token.webkdc_service);
        break;
    case WA_TOKEN_UNKNOWN:
        status = WA_ERR_UNIMPLEMENTED;
        webauth_error_set(ctx, status, "encoding unknown token");
        break;
    case WA_TOKEN_ANY:
    default:
        status = WA_ERR_INVALID;
        webauth_error_set(ctx, status, "invalid token type %d in encode",
                          data->type);
        break;
    }
    if (status != WA_ERR_NONE)
        return status;
    status = webauth_encode_token(ctx, data, &attrs, &alen);
    if (status != WA_ERR_NONE)
        return status;
    status = webauth_token_encrypt(ctx, attrs, alen, &output, length, ring);
    if (status != WA_ERR_NONE)
        return status;
    *token = output;
    return WA_ERR_NONE;
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
    int status;
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
    status = webauth_token_encode_raw(ctx, data, ring, &raw, &length);
    if (status != WA_ERR_NONE)
        goto done;
    btoken = apr_palloc(ctx->pool, apr_base64_encode_len(length));
    apr_base64_encode(btoken, raw, length);
    *token = btoken;

done:
    return status;
}
