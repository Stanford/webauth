/*
 * High level interface to encoding WebAuth tokens.
 *
 * Interfaces for encoding tokens from internal structs to the encrypted wire
 * tokens representing the same information.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011
 *     The Board of Trustees of the Leland Stanford Junior Univerity
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <apr_base64.h>
#include <apr_general.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <time.h>

#include <lib/internal.h>
#include <util/macros.h>
#include <webauth.h>
#include <webauth/basic.h>
#include <webauth/tokens.h>

/*
 * Attribute list macros to make code easier to read and audit.  We don't need
 * to check error codes since we are using WA_F_NONE, which doesn't allocate
 * any memory.
 */
#define ADD_DATA(name, value, len) \
    webauth_attr_list_add(alist, name, (void *) value, len, WA_F_NONE)
#define ADD_STR(name, value) \
    webauth_attr_list_add_str(alist, name, value, 0, WA_F_NONE)
#define ADD_TIME(name, value) \
    webauth_attr_list_add_time(alist, name, value, WA_F_NONE)
#define ADD_UINT(name, value) \
    webauth_attr_list_add_uint32(alist, name, value, WA_F_NONE)

/*
 * Macros to check whether an attribute is set, used for sanity checks while
 * encoding.  Takes the name of the struct and the struct member, and assumes
 * ctx is the WebAuth context and the right thing to do on failure is to go to
 * the corrupt label.
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
            goto corrupt;                                               \
        }                                                               \
    } while (0)
#define CHECK_NUM(token, attr)                                  \
    do {                                                        \
        if (token->attr == 0) {                                 \
            webauth_error_set(ctx, WA_ERR_CORRUPT,              \
                              "missing %s for %s token",        \
                              APR_STRINGIFY(attr),              \
                              APR_STRINGIFY(token));            \
            goto corrupt;                                       \
        }                                                       \
    } while (0)
#define CHECK_STR(token, attr)                                          \
    do {                                                                \
        if (token->attr == NULL) {                                      \
            webauth_error_set(ctx, WA_ERR_CORRUPT,                      \
                              "missing %s for %s token",                \
                              APR_STRINGIFY(attr),                      \
                              APR_STRINGIFY(token));                    \
            goto corrupt;                                               \
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
            goto corrupt;                                               \
        }                                                               \
    } while (0)


/*
 * Prepare for token encoding.  This function handles the common setup for all
 * token encoding: sets token to NULL, verifies that the keyring isn't NULL,
 * allocates a new attribute list.  It returns an error code on failure and
 * sets the WebAuth error.
 */
static int
prep_encode(struct webauth_context *ctx, const WEBAUTH_KEYRING *keyring,
            const char **token, WEBAUTH_ATTR_LIST **alist)
{
    *token = NULL;
    if (keyring == NULL) {
        webauth_error_set(ctx, WA_ERR_BAD_KEY,
                          "keyring is NULL when encoding token");
        return WA_ERR_BAD_KEY;
    }
    *alist = webauth_attr_list_new(10);
    if (*alist == NULL) {
        webauth_error_set(ctx, WA_ERR_NO_MEM,
                          "error allocating attribute list");
        return WA_ERR_NO_MEM;
    }
    return WA_ERR_NONE;
}


/*
 * Finish encoding a token.  This function handles the common token encoding
 * steps of generating the raw token and then base64-encoding it, storing it
 * in token.  It returns an error code on failure and sets the WebAuth error.
 * token is not set on error.
 */
static int
finish_encode(struct webauth_context *ctx, const WEBAUTH_KEYRING *keyring,
              const WEBAUTH_ATTR_LIST *alist, const char **token)
{
    char *rtoken, *btoken;
    int status;
    size_t length;

    /*
     * Encode the token.  First, we encode the binary form into newly
     * allocated memory, and then we allocate an additional block of memory
     * for the base64-encoded form.  The first block is temporary memory that
     * we could reclaim faster if it ever looks worthwhile.
     */
    length = webauth_token_encoded_length(alist);
    rtoken = apr_palloc(ctx->pool, length);
    status = webauth_token_create(alist, 0, rtoken, &length, length, keyring);
    if (status != WA_ERR_NONE) {
        webauth_error_set(ctx, status, "error encoding app token");
        return status;
    }
    btoken = apr_palloc(ctx->pool, apr_base64_encode_len(length));
    apr_base64_encode(btoken, rtoken, length);
    *token = btoken;
    return WA_ERR_NONE;
}


/*
 * Encode an application token.  Takes the struct representing the token
 * contents and the keyring to use for encryption.  Stores the pointer to the
 * newly-allocated token (created from pool-allocated memory) in the token
 * parameter.  On error, token is set to NULL and an error code is returned.
 */
int
webauth_token_encode_app(struct webauth_context *ctx,
                         const struct webauth_token_app *app,
                         const WEBAUTH_KEYRING *keyring,
                         const char **token)
{
    WEBAUTH_ATTR_LIST *alist;
    int status;
    time_t creation;

    status = prep_encode(ctx, keyring, token, &alist);
    if (status != WA_ERR_NONE)
        return status;

    /* Sanity-check the token attributes. */
    CHECK_STR(app, subject);
    CHECK_NUM(app, expiration);

    /* Encode the token attributes into the attribute list. */
    creation = (app->creation > 0) ? app->creation : time(NULL);
    ADD_STR( WA_TK_TOKEN_TYPE,      WA_TT_APP);
    ADD_STR( WA_TK_SUBJECT,         app->subject);
    ADD_TIME(WA_TK_CREATION_TIME,   creation);
    ADD_TIME(WA_TK_EXPIRATION_TIME, app->expiration);
    if (app->last_used > 0)
        ADD_TIME(WA_TK_LASTUSED_TIME,   app->last_used);
    if (app->initial_factors != NULL)
        ADD_STR( WA_TK_INITIAL_FACTORS, app->initial_factors);
    if (app->session_factors != NULL)
        ADD_STR( WA_TK_SESSION_FACTORS, app->session_factors);
    if (app->loa > 0)
        ADD_UINT(WA_TK_LOA,             app->loa);

    /* Finish encoding the token. */
    status = finish_encode(ctx, keyring, alist, token);
    webauth_attr_list_free(alist);
    return status;

corrupt:
    webauth_attr_list_free(alist);
    return WA_ERR_CORRUPT;
}


/*
 * Encode a credential token.  Takes the struct representing the token
 * contents and the keyring to use for encryption.  Stores the pointer to the
 * newly-allocated token (created from pool-allocated memory) in the token
 * parameter.  On error, token is set to NULL and an error code is returned.
 */
int
webauth_token_encode_cred(struct webauth_context *ctx,
                          const struct webauth_token_cred *cred,
                          const WEBAUTH_KEYRING *keyring,
                          const char **token)
{
    WEBAUTH_ATTR_LIST *alist;
    int status;
    time_t creation;

    status = prep_encode(ctx, keyring, token, &alist);
    if (status != WA_ERR_NONE)
        return status;

    /* Sanity-check the token attributes. */
    CHECK_STR( cred, subject);
    CHECK_STR( cred, type);
    CHECK_STR( cred, service);
    CHECK_DATA(cred, data);
    CHECK_NUM( cred, expiration);
    if (strcmp(cred->type, "krb5") != 0) {
        webauth_error_set(ctx, WA_ERR_CORRUPT,
                          "unknown type %s for cred token", cred->type);
        goto corrupt;
    }

    /* Encode the token attributes into the attribute list. */
    creation = (cred->creation > 0) ? cred->creation : time(NULL);
    ADD_STR( WA_TK_TOKEN_TYPE,      WA_TT_CRED);
    ADD_STR( WA_TK_SUBJECT,         cred->subject);
    ADD_STR( WA_TK_CRED_TYPE,       cred->type);
    ADD_STR( WA_TK_CRED_SERVICE,    cred->service);
    ADD_DATA(WA_TK_CRED_DATA,       cred->data, cred->data_len);
    ADD_TIME(WA_TK_CREATION_TIME,   creation);
    ADD_TIME(WA_TK_EXPIRATION_TIME, cred->expiration);

    /* Finish encoding the token. */
    status = finish_encode(ctx, keyring, alist, token);
    webauth_attr_list_free(alist);
    return status;

corrupt:
    webauth_attr_list_free(alist);
    return WA_ERR_CORRUPT;
}


/*
 * Encode a proxy token.  Takes the struct representing the token contents and
 * the keyring to use for encryption.  Stores the pointer to the
 * newly-allocated token (created from pool-allocated memory) in the token
 * parameter.  On error, token is set to NULL and an error code is returned.
 */
int
webauth_token_encode_proxy(struct webauth_context *ctx,
                           const struct webauth_token_proxy *proxy,
                           const WEBAUTH_KEYRING *keyring,
                           const char **token)
{
    WEBAUTH_ATTR_LIST *alist;
    int status;
    time_t creation;

    status = prep_encode(ctx, keyring, token, &alist);
    if (status != WA_ERR_NONE)
        return status;

    /* Sanity-check the token attributes. */
    CHECK_STR( proxy, subject);
    CHECK_STR( proxy, type);
    CHECK_DATA(proxy, webkdc_proxy);
    CHECK_NUM( proxy, expiration);
    if (strcmp(proxy->type, "krb5") != 0) {
        webauth_error_set(ctx, WA_ERR_CORRUPT,
                          "unknown type %s for proxy token", proxy->type);
        goto corrupt;
    }

    /* Encode the token attributes into the attribute list. */
    creation = (proxy->creation > 0) ? proxy->creation : time(NULL);
    ADD_STR( WA_TK_TOKEN_TYPE,      WA_TT_PROXY);
    ADD_STR( WA_TK_SUBJECT,         proxy->subject);
    ADD_STR( WA_TK_PROXY_TYPE,      proxy->type);
    ADD_DATA(WA_TK_WEBKDC_TOKEN,    proxy->webkdc_proxy,
             proxy->webkdc_proxy_len);
    ADD_TIME(WA_TK_CREATION_TIME,   creation);
    ADD_TIME(WA_TK_EXPIRATION_TIME, proxy->expiration);
    if (proxy->initial_factors != NULL)
        ADD_STR(WA_TK_INITIAL_FACTORS, proxy->initial_factors);
    if (proxy->session_factors != NULL)
        ADD_STR(WA_TK_SESSION_FACTORS, proxy->session_factors);
    if (proxy->loa > 0)
        ADD_UINT(WA_TK_LOA, proxy->loa);

    /* Finish encoding the token. */
    status = finish_encode(ctx, keyring, alist, token);
    webauth_attr_list_free(alist);
    return status;

corrupt:
    webauth_attr_list_free(alist);
    return WA_ERR_CORRUPT;
}


/*
 * Encode a request token.  Takes the struct representing the token contents
 * and the keyring to use for encryption.  Stores the pointer to the
 * newly-allocated token (created from pool-allocated memory) in the token
 * parameter.  On error, token is set to NULL and an error code is returned.
 */
int
webauth_token_encode_request(struct webauth_context *ctx,
                             const struct webauth_token_request *request,
                             const WEBAUTH_KEYRING *keyring,
                             const char **token)
{
    WEBAUTH_ATTR_LIST *alist;
    int status;
    time_t creation;

    status = prep_encode(ctx, keyring, token, &alist);
    if (status != WA_ERR_NONE)
        return status;

    /*
     * Sanity-check the token attributes.  There are two entirely different
     * types of data represented here, so we have to do checks based on what
     * type of request token it is.
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
                goto corrupt;
            }
        } else if (strcmp(request->type, "proxy") == 0) {
            CHECK_STR( request, proxy_type);
            if (strcmp(request->proxy_type, "krb5") != 0) {
                webauth_error_set(ctx, WA_ERR_CORRUPT,
                                  "unknown proxy type %s for request token",
                                  request->proxy_type);
                goto corrupt;
            }
        } else {
            webauth_error_set(ctx, WA_ERR_CORRUPT,
                              "unknown requested token type %s for request"
                              " token", request->type);
            goto corrupt;
        }
    }

    /* Encode the token attributes into the attribute list. */
    creation = (request->creation > 0) ? request->creation : time(NULL);
    ADD_STR(WA_TK_TOKEN_TYPE, WA_TT_REQUEST);
    if (request->command != NULL)
        ADD_STR(WA_TK_COMMAND, request->command);
    else {
        ADD_STR(WA_TK_REQUESTED_TOKEN_TYPE, request->type);
        ADD_STR(WA_TK_RETURN_URL,           request->return_url);
        if (request->auth != NULL)
            ADD_STR( WA_TK_SUBJECT_AUTH, request->auth);
        if (request->proxy_type != NULL)
            ADD_STR( WA_TK_PROXY_TYPE, request->proxy_type);
        if (request->state != NULL)
            ADD_DATA(WA_TK_APP_STATE, request->state, request->state_len);
        if (request->options != NULL)
            ADD_STR(WA_TK_REQUEST_OPTIONS, request->options);
        if (request->initial_factors != NULL)
            ADD_STR(WA_TK_INITIAL_FACTORS, request->initial_factors);
        if (request->session_factors != NULL)
            ADD_STR(WA_TK_SESSION_FACTORS, request->session_factors);
        if (request->loa > 0)
            ADD_UINT(WA_TK_LOA, request->loa);
    }
    ADD_TIME(WA_TK_CREATION_TIME, creation);

    /* Finish encoding the token. */
    status = finish_encode(ctx, keyring, alist, token);
    webauth_attr_list_free(alist);
    return status;

corrupt:
    webauth_attr_list_free(alist);
    return WA_ERR_CORRUPT;
}
