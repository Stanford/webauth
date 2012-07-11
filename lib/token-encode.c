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

/* Check that a value that should be numerically zero is. */
#define CHECK_ZERO(token, attr, reason)                                 \
    do {                                                                \
        if (token->attr != 0) {                                         \
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
prep_encode(struct webauth_context *ctx, const struct webauth_keyring *ring,
            const void **token, WEBAUTH_ATTR_LIST **alist)
{
    *token = NULL;
    if (ring == NULL) {
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
 * steps of generating the raw token, storing it in token and its length in
 * length.  It returns an error code on failure and sets the WebAuth error.
 * token is not set on error.
 */
static int
finish_encode(struct webauth_context *ctx, const struct webauth_keyring *ring,
              const WEBAUTH_ATTR_LIST *alist, const void **token,
              size_t *length)
{
    size_t alen;
    char *attrs;
    void *rtoken;
    int status;

    alen = webauth_attrs_encoded_length(alist);
    attrs = apr_palloc(ctx->pool, alen);
    status = webauth_attrs_encode(alist, attrs, &alen, alen);
    if (status != WA_ERR_NONE) {
        webauth_error_set(ctx, status, "error encoding attributes");
        return status;
    }
    status = webauth_token_encrypt(ctx, attrs, alen, &rtoken, length, ring);
    if (status != WA_ERR_NONE)
        return status;
    *token = rtoken;
    return WA_ERR_NONE;
}


/*
 * Encode an application token into an attribute list.
 */
static int
encode_app(struct webauth_context *ctx, const struct webauth_token_app *app,
           WEBAUTH_ATTR_LIST *alist)
{
    time_t creation;

    /* Sanity-check the token attributes. */
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

    /* Encode the token attributes into the attribute list. */
    creation = (app->creation > 0) ? app->creation : time(NULL);
    ADD_STR( WA_TK_TOKEN_TYPE,      WA_TT_APP);
    ADD_TIME(WA_TK_CREATION_TIME,   creation);
    ADD_TIME(WA_TK_EXPIRATION_TIME, app->expiration);
    if (app->subject != NULL)
        ADD_STR(WA_TK_SUBJECT, app->subject);
    if (app->session_key != NULL)
        ADD_DATA(WA_TK_SESSION_KEY, app->session_key, app->session_key_len);
    if (app->last_used > 0)
        ADD_TIME(WA_TK_LASTUSED_TIME, app->last_used);
    if (app->initial_factors != NULL)
        ADD_STR( WA_TK_INITIAL_FACTORS, app->initial_factors);
    if (app->session_factors != NULL)
        ADD_STR( WA_TK_SESSION_FACTORS, app->session_factors);
    if (app->loa > 0)
        ADD_UINT(WA_TK_LOA, app->loa);
    return WA_ERR_NONE;

corrupt:
    return WA_ERR_CORRUPT;
}


/*
 * Encode a credential token into an attribute list.
 */
static int
encode_cred(struct webauth_context *ctx,
            const struct webauth_token_cred *cred,
            WEBAUTH_ATTR_LIST *alist)
{
    time_t creation;

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
    return WA_ERR_NONE;

corrupt:
    return WA_ERR_CORRUPT;
}


/*
 * Encode an error token into an attribute list.
 */
static int
encode_error(struct webauth_context *ctx,
             const struct webauth_token_error *error,
             WEBAUTH_ATTR_LIST *alist)
{
    const char *code_string;
    time_t creation;

    /* Sanity-check the token attributes. */
    CHECK_NUM(error, code);
    CHECK_STR(error, message);

    /* Encode the token attributes into the attribute list. */
    creation = (error->creation > 0) ? error->creation : time(NULL);
    code_string = apr_psprintf(ctx->pool, "%lu", error->code);
    ADD_STR( WA_TK_TOKEN_TYPE,    WA_TT_ERROR);
    ADD_STR( WA_TK_ERROR_CODE,    code_string);
    ADD_STR( WA_TK_ERROR_MESSAGE, error->message);
    ADD_TIME(WA_TK_CREATION_TIME, creation);
    return WA_ERR_NONE;

corrupt:
    return WA_ERR_CORRUPT;
}


/*
 * Encode an id token into an attribute list.
 */
static int
encode_id(struct webauth_context *ctx, const struct webauth_token_id *id,
          WEBAUTH_ATTR_LIST *alist)
{
    time_t creation;

    /* Sanity-check the token attributes. */
    CHECK_STR(id, auth);
    CHECK_NUM(id, expiration);
    if (strcmp(id->auth, "krb5") != 0 && strcmp(id->auth, "webkdc") != 0) {
        webauth_error_set(ctx, WA_ERR_CORRUPT,
                          "unknown subject auth %s for id token", id->auth);
        goto corrupt;
    }
    if (strcmp(id->auth, "webkdc") == 0)
        CHECK_STR(id, subject);
    if (strcmp(id->auth, "krb5") == 0)
        CHECK_DATA(id, auth_data);

    /* Encode the token attributes into the attribute list. */
    creation = (id->creation > 0) ? id->creation : time(NULL);
    ADD_STR( WA_TK_TOKEN_TYPE,      WA_TT_ID);
    ADD_STR( WA_TK_SUBJECT_AUTH,    id->auth);
    ADD_TIME(WA_TK_CREATION_TIME,   creation);
    ADD_TIME(WA_TK_EXPIRATION_TIME, id->expiration);
    if (id->subject != NULL)
        ADD_STR(WA_TK_SUBJECT, id->subject);
    if (id->auth_data != NULL)
        ADD_DATA(WA_TK_SUBJECT_AUTH_DATA, id->auth_data, id->auth_data_len);
    if (id->initial_factors != NULL)
        ADD_STR(WA_TK_INITIAL_FACTORS, id->initial_factors);
    if (id->session_factors != NULL)
        ADD_STR(WA_TK_SESSION_FACTORS, id->session_factors);
    if (id->loa > 0)
        ADD_UINT(WA_TK_LOA, id->loa);
    return WA_ERR_NONE;

corrupt:
    return WA_ERR_CORRUPT;
}


/*
 * Encode a login token into an attribute list.
 */
static int
encode_login(struct webauth_context *ctx,
             const struct webauth_token_login *login,
             WEBAUTH_ATTR_LIST *alist)
{
    time_t creation;

    /* Sanity-check the token attributes. */
    CHECK_STR(login, username);
    if (login->password == NULL && login->otp == NULL) {
        webauth_error_set(ctx, WA_ERR_CORRUPT,
                          "either password or otp required for login token");
        goto corrupt;
    }
    if (login->password != NULL && login->otp != NULL) {
        webauth_error_set(ctx, WA_ERR_CORRUPT,
                          "both password and otp set in login token");
        goto corrupt;
    }

    /* Encode the token attributes into the attribute list. */
    creation = (login->creation > 0) ? login->creation : time(NULL);
    ADD_STR( WA_TK_TOKEN_TYPE,    WA_TT_LOGIN);
    ADD_STR( WA_TK_USERNAME,      login->username);
    ADD_TIME(WA_TK_CREATION_TIME, creation);
    if (login->password != NULL)
        ADD_STR(WA_TK_PASSWORD, login->password);
    if (login->otp != NULL)
        ADD_STR(WA_TK_OTP, login->otp);
    return WA_ERR_NONE;

corrupt:
    return WA_ERR_CORRUPT;
}


/*
 * Encode a proxy token into an attribute list.
 */
static int
encode_proxy(struct webauth_context *ctx,
             const struct webauth_token_proxy *proxy,
             WEBAUTH_ATTR_LIST *alist)
{
    time_t creation;

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
    return WA_ERR_NONE;

corrupt:
    return WA_ERR_CORRUPT;
}


/*
 * Encode a request token into an attribute list.
 */
static int
encode_request(struct webauth_context *ctx,
               const struct webauth_token_request *request,
               WEBAUTH_ATTR_LIST *alist)
{
    time_t creation;

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
    return WA_ERR_NONE;

corrupt:
    return WA_ERR_CORRUPT;
}


/*
 * Encode a webkdc-proxy token into an attribute list.
 */
static int
encode_webkdc_proxy(struct webauth_context *ctx,
                    const struct webauth_token_webkdc_proxy *webkdc_proxy,
                    WEBAUTH_ATTR_LIST *alist)
{
    time_t creation;

    /* Sanity-check the token attributes. */
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
        goto corrupt;
    }

    /* Encode the token attributes into the attribute list. */
    creation
        = (webkdc_proxy->creation > 0) ? webkdc_proxy->creation : time(NULL);
    ADD_STR( WA_TK_TOKEN_TYPE,      WA_TT_WEBKDC_PROXY);
    ADD_STR( WA_TK_SUBJECT,         webkdc_proxy->subject);
    ADD_STR( WA_TK_PROXY_TYPE,      webkdc_proxy->proxy_type);
    ADD_STR( WA_TK_PROXY_SUBJECT,   webkdc_proxy->proxy_subject);
    ADD_TIME(WA_TK_CREATION_TIME,   creation);
    ADD_TIME(WA_TK_EXPIRATION_TIME, webkdc_proxy->expiration);
    if (webkdc_proxy->data != NULL)
        ADD_DATA(WA_TK_PROXY_DATA, webkdc_proxy->data, webkdc_proxy->data_len);
    if (webkdc_proxy->initial_factors != NULL)
        ADD_STR(WA_TK_INITIAL_FACTORS, webkdc_proxy->initial_factors);
    if (webkdc_proxy->loa > 0)
        ADD_UINT(WA_TK_LOA, webkdc_proxy->loa);
    return WA_ERR_NONE;

corrupt:
    return WA_ERR_CORRUPT;
}


/*
 * Encode a webkdc-service token into an attribute list.
 */
static int
encode_webkdc_service(struct webauth_context *ctx,
                      const struct webauth_token_webkdc_service
                          *webkdc_service,
                      WEBAUTH_ATTR_LIST *alist)
{
    time_t creation;

    /* Sanity-check the token attributes. */
    CHECK_STR( webkdc_service, subject);
    CHECK_DATA(webkdc_service, session_key);
    CHECK_NUM( webkdc_service, expiration);

    /* Encode the token attributes into the attribute list. */
    if (webkdc_service->creation > 0)
        creation = webkdc_service->creation;
    else
        creation = time(NULL);
    ADD_STR( WA_TK_TOKEN_TYPE,      WA_TT_WEBKDC_SERVICE);
    ADD_STR( WA_TK_SUBJECT,         webkdc_service->subject);
    ADD_DATA(WA_TK_SESSION_KEY,     webkdc_service->session_key,
             webkdc_service->session_key_len);
    ADD_TIME(WA_TK_CREATION_TIME,   creation);
    ADD_TIME(WA_TK_EXPIRATION_TIME, webkdc_service->expiration);
    return WA_ERR_NONE;

corrupt:
    return WA_ERR_CORRUPT;
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
    WEBAUTH_ATTR_LIST *alist;
    int status;

    status = prep_encode(ctx, ring, token, &alist);
    if (status != WA_ERR_NONE)
        return status;
    switch (data->type) {
    case WA_TOKEN_APP:
        status = encode_app(ctx, &data->token.app, alist);
        break;
    case WA_TOKEN_CRED:
        status = encode_cred(ctx, &data->token.cred, alist);
        break;
    case WA_TOKEN_ERROR:
        status = encode_error(ctx, &data->token.error, alist);
        break;
    case WA_TOKEN_ID:
        status = encode_id(ctx, &data->token.id, alist);
        break;
    case WA_TOKEN_LOGIN:
        status = encode_login(ctx, &data->token.login, alist);
        break;
    case WA_TOKEN_PROXY:
        status = encode_proxy(ctx, &data->token.proxy, alist);
        break;
    case WA_TOKEN_REQUEST:
        status = encode_request(ctx, &data->token.request, alist);
        break;
    case WA_TOKEN_WEBKDC_PROXY:
        status = encode_webkdc_proxy(ctx, &data->token.webkdc_proxy, alist);
        break;
    case WA_TOKEN_WEBKDC_SERVICE:
        status = encode_webkdc_service(ctx, &data->token.webkdc_service,
                                       alist);
        break;
    case WA_TOKEN_UNKNOWN:
        status = WA_ERR_UNIMPLEMENTED;
        webauth_error_set(ctx, status, "encoding unknown token");
        break;
    case WA_TOKEN_ANY:
    default:
        status = WA_ERR_INVALID;
        webauth_error_set(ctx, status, "invalid token type in encode");
        break;
    }
    if (status != WA_ERR_NONE)
        goto fail;
    status = finish_encode(ctx, ring, alist, token, length);
    webauth_attr_list_free(alist);
    return status;

fail:
    webauth_attr_list_free(alist);
    return status;
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
