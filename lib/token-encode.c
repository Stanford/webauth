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
#define ADD_STR(name, value) \
       webauth_attr_list_add_str(alist, name, value, 0, WA_F_NONE)
#define ADD_PTR(name, value, len) \
       webauth_attr_list_add(alist, name, value, len, WA_F_NONE)
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
    char *rtoken, *btoken;
    int status;
    time_t creation;
    size_t length;

    *token = NULL;
    if (keyring == NULL) {
        webauth_error_set(ctx, WA_ERR_BAD_KEY,
                          "keyring is NULL when encoding app token");
        return WA_ERR_BAD_KEY;
    }
    alist = webauth_attr_list_new(10);
    if (alist == NULL) {
        webauth_error_set(ctx, WA_ERR_NO_MEM,
                          "error allocating attribute list");
        return WA_ERR_NO_MEM;
    }

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

    /*
     * Encode the token.  First, we encode the binary form into newly
     * allocated memory, and then we allocate an additional block of memory
     * for the base64-encoded form.  The first block is temporary memory that
     * we could reclaim faster if it ever looks worthwhile.
     */
    length = webauth_token_encoded_length(alist);
    rtoken = apr_palloc(ctx->pool, length);
    status = webauth_token_create(alist, 0, rtoken, &length, length, keyring);
    webauth_attr_list_free(alist);
    if (status != WA_ERR_NONE) {
        webauth_error_set(ctx, status, "error encoding app token");
        return status;
    }
    btoken = apr_palloc(ctx->pool, apr_base64_encode_len(length));
    apr_base64_encode(btoken, rtoken, length);
    *token = btoken;
    return WA_ERR_NONE;

corrupt:
    webauth_attr_list_free(alist);
    return WA_ERR_CORRUPT;
}
