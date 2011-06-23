/*
 * High level interface to WebAuth tokens.
 *
 * Interfaces for encoding and decoding tokens from the encrypted wire tokens
 * into structs representing the same information.
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
#include <apr_pools.h>
#include <apr_strings.h>
#include <time.h>

#include <lib/internal.h>
#include <webauth.h>
#include <webauth/basic.h>
#include <webauth/tokens.h>

/*
 * Attribute list macros to add attributes, which make code easier to read and
 * audit.  We don't need to check error codes since we are using WA_F_NONE,
 * which doesn't allocate any memory.  For strings and pointers, this means
 * that the value must already be in pool-allocated memory.
 *
 * These require that alist be the attribute list.
 */
#define ADD_STR(name, value) \
       webauth_attr_list_add_str(alist, name, value, 0, WA_F_NONE)
#define ADD_PTR(name, value, len) \
       webauth_attr_list_add(alist, name, value, len, WA_F_NONE)
#define ADD_TIME(name, value) \
       webauth_attr_list_add_time(alist, name, value, WA_F_NONE)
#define ADD_UINT(name, value) \
       webauth_attr_list_add_uint32(alist, name, value, WA_F_NONE)

/* Attribute list addition macros for each token attribute. */
#define SET_APP_STATE(state, len)    ADD_PTR(WA_TK_APP_STATE, state, len)
#define SET_COMMAND(cmd)             ADD_STR(WA_TK_COMMAND, cmd)
#define SET_CRED_DATA(data, len)     ADD_PTR(WA_TK_CRED_DATA, data, len)
#define SET_CRED_SERVER(type)        ADD_STR(WA_TK_CRED_SERVER, type)
#define SET_CRED_TYPE(type)          ADD_STR(WA_TK_CRED_TYPE, type)
#define SET_CREATION_TIME(time)      ADD_TIME(WA_TK_CREATION_TIME, time)
#define SET_ERROR_CODE(code)         ADD_STR(WA_TK_ERROR_CODE, code)
#define SET_ERROR_MESSAGE(msg)       ADD_STR(WA_TK_ERROR_MESSAGE, msg)
#define SET_EXPIRATION_TIME(time)    ADD_TIME(WA_TK_EXPIRATION_TIME, time)
#define SET_INITIAL_FACTORS(list)    ADD_STR(WA_TK_INITIAL_FACTORS, list)
#define SET_SESSION_KEY(key, len)    ADD_PTR(WA_TK_SESSION_KEY, key, len)
#define SET_LOA(loa)                 ADD_UINT(WA_TK_LOA, loa)
#define SET_LASTUSED_TIME(time)      ADD_TIME(WA_TK_LASTUSED_TIME, time)
#define SET_PROXY_DATA(data, len)    ADD_PTR(WA_TK_PROXY_DATA, data, len)
#define SET_PROXY_SUBJECT(sub)       ADD_STR(WA_TK_PROXY_SUBJECT, sub)
#define SET_PROXY_TYPE(type)         ADD_STR(WA_TK_PROXY_TYPE, type)
#define SET_REQUEST_OPTIONS(ro)      ADD_STR(WA_TK_REQUEST_OPTIONS, ro)
#define SET_REQUESTED_TOKEN_TYPE(t)  ADD_STR(WA_TK_REQUESTED_TOKEN_TYPE, t)
#define SET_RETURN_URL(url)          ADD_STR(WA_TK_RETURN_URL, url)
#define SET_SUBJECT(s)               ADD_STR(WA_TK_SUBJECT, s)
#define SET_SUBJECT_AUTH(sa)         ADD_STR(WA_TK_SUBJECT_AUTH, sa)
#define SET_SUBJECT_AUTH_DATA(d, l)  ADD_PTR(WA_TK_SUBJECT_AUTH_DATA, d, l)
#define SET_SESSION_FACTORS(list)    ADD_STR(WA_TK_SESSION_FACTORS, list)
#define SET_TOKEN_TYPE(type)         ADD_STR(WA_TK_TOKEN_TYPE, type)
#define SET_WEBKDC_TOKEN(d, l)       ADD_PTR(WA_TK_WEBKDC_TOKEN, d, l)

/*
 * Macros for decoding attributes, which make code easier to read and audit.
 * These macros require that ctx be the context, alist be the attribute list,
 * token be the token struct we're writing things to, status be available to
 * store the result in, and that the correct thing to do on an error is to
 * return immediately.
 */
#define DECODE_STR(a, m, r)                                             \
    do {                                                                \
        status = decode_string(ctx, alist, (a), &token->m, (r));        \
        if (status != WA_ERR_NONE)                                      \
            return status;                                              \
    } while (0)
#define DECODE_TIME(a, m, r)                                            \
    do {                                                                \
        status = decode_time(ctx, alist, (a), &token->m, (r));          \
        if (status != WA_ERR_NONE)                                      \
            return status;                                              \
    } while (0)
#define DECODE_UINT(a, m, r)                                            \
    do {                                                                \
        status = decode_uint(ctx, alist, (a), &token->m, (r));          \
        if (status != WA_ERR_NONE)                                      \
            return status;                                              \
    } while (0)


/*
 * Extract a string attribute from a token and copy it into pool-allocated
 * memory, storing it into the value argument.  The last argument determines
 * whether the attribute is required or optional.  If it's required, return an
 * error if it's missing.  If it's not required, return success if it's
 * missing.  Return a status and set the internal error message if needed, and
 * set the value to NULL on an error.
 */
static int
decode_string(struct webauth_context *ctx, WEBAUTH_ATTR_LIST *alist,
              const char *attr, const char **value, bool required)
{
    int status;
    char *v, *output;
    size_t len;

    status = webauth_attr_list_get_str(alist, attr, &v, &len, WA_F_NONE);
    if (status != WA_ERR_NONE) {
        *value = NULL;
        if (status == WA_ERR_NOT_FOUND && !required)
            return WA_ERR_NONE;
        webauth_error_set(ctx, status, "decoding attribute %s failed", attr);
    }
    output = apr_palloc(ctx->pool, len + 1);
    memcpy(output, v, len);
    output[len] = '\0';
    *value = output;
    return status;
}


/*
 * Extract a time attribute from a token, storing it into the value argument.
 * The last argument determines whether the attribute is required or optional.
 * If it's required, return an error if it's missing.  If it's not required,
 * return success if it's missing.  Return a status and set the internal error
 * message if needed, and set the value to 0 on an error.
 */
static int
decode_time(struct webauth_context *ctx, WEBAUTH_ATTR_LIST *alist,
            const char *attr, time_t *value, bool required)
{
    int status;

    status = webauth_attr_list_get_time(alist, attr, value, WA_F_NONE);
    if (status != WA_ERR_NONE) {
        *value = 0;
        if (status == WA_ERR_NOT_FOUND && !required)
            return WA_ERR_NONE;
        webauth_error_set(ctx, status, "decoding attribute %s failed", attr);
    }
    return status;
}


/*
 * Extract an unsigned integer attribute from a token, storing it into the
 * value argument.  The last argument determines whether the attribute is
 * required or optional.  If it's required, return an error if it's missing.
 * If it's not required, return success if it's missing.  Return a status and
 * set the internal error message if needed, and set the value to 0 on an
 * error.
 */
static int
decode_uint(struct webauth_context *ctx, WEBAUTH_ATTR_LIST *alist,
            const char *attr, unsigned long *value, bool required)
{
    int status;
    uint32_t v;

    status = webauth_attr_list_get_uint32(alist, attr, &v, WA_F_NONE);
    if (status != WA_ERR_NONE) {
        *value = 0;
        if (status == WA_ERR_NOT_FOUND && !required)
            return WA_ERR_NONE;
        webauth_error_set(ctx, status, "decoding attribute %s failed", attr);
    }
    *value = v;
    return status;
}


/*
 * Decode an application token from the encrypted base64 wire format and store
 * a newly allocated webauth_token_app struct in token with the contents.
 * Returns a WebAuth status code.  On failure, sets token to NULL.
 */
int
webauth_token_decode_app(struct webauth_context *ctx, const char *encoded,
                         const WEBAUTH_KEYRING *keyring,
                         struct webauth_token_app **decoded)
{
    char *input;
    size_t length;
    WEBAUTH_ATTR_LIST *alist;
    char *type;
    struct webauth_token_app *token;
    int status;

    *decoded = NULL;
    input = apr_pstrdup(ctx->pool, encoded);
    length = apr_base64_decode(input, input);
    status = webauth_token_parse(input, length, 0, keyring, &alist);
    if (status != WA_ERR_NONE)
        return status;
    status = webauth_attr_list_get_str(alist, WA_TK_TOKEN_TYPE, &type,
                                       &length, WA_F_NONE);
    if (status != WA_ERR_NONE) {
        webauth_error_set(ctx, status, "bad application token");
        return status;
    } else if (length != strlen(WA_TT_APP)
               || strncmp(type, WA_TT_APP, length) != 0) {
        webauth_error_set(ctx, WA_ERR_CORRUPT, "wrong token type %s while"
                          " decoding app token", type);
        return WA_ERR_CORRUPT;
    }

    /* We have a valid app token.  Pull out the attributes. */
    token = apr_palloc(ctx->pool, sizeof(struct webauth_token_app));
    DECODE_STR( WA_TK_SUBJECT,         subject,         true);
    DECODE_STR( WA_TK_INITIAL_FACTORS, initial_factors, false);
    DECODE_STR( WA_TK_SESSION_FACTORS, session_factors, false);
    DECODE_TIME(WA_TK_LASTUSED_TIME,   last_used,       false);
    DECODE_TIME(WA_TK_CREATION_TIME,   creation,        false);
    DECODE_TIME(WA_TK_EXPIRATION_TIME, expiration,      true);
    DECODE_UINT(WA_TK_LOA,             loa,             false);

    *decoded = token;
    return WA_ERR_NONE;
}
