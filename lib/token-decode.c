/*
 * High level interface to decoding WebAuth tokens.
 *
 * Interfaces for decoding tokens from the encrypted wire tokens into structs
 * representing the same information.
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
 * Macros for decoding attributes, which make code easier to read and audit.
 * These macros require that ctx be the context, alist be the attribute list,
 * token be the token struct we're writing things to, status be available to
 * store the result in, and that the correct thing to do on an error is to
 * go to the fail label.
 */
#define DECODE_DATA(a, m, r)                                            \
    do {                                                                \
        status = decode_data(ctx, alist, (a), &token->m,                \
                             &token->m ## _len, (r));                   \
        if (status != WA_ERR_NONE)                                      \
            goto fail;                                                  \
    } while (0)
#define DECODE_STR(a, m, r)                                             \
    do {                                                                \
        status = decode_string(ctx, alist, (a), &token->m, (r));        \
        if (status != WA_ERR_NONE)                                      \
            goto fail;                                                  \
    } while (0)
#define DECODE_TIME(a, m, r)                                            \
    do {                                                                \
        status = decode_time(ctx, alist, (a), &token->m, (r));          \
        if (status != WA_ERR_NONE)                                      \
            goto fail;                                                  \
    } while (0)
#define DECODE_UINT(a, m, r)                                            \
    do {                                                                \
        status = decode_uint(ctx, alist, (a), &token->m, (r));          \
        if (status != WA_ERR_NONE)                                      \
            goto fail;                                                  \
    } while (0)


/*
 * Parse a base64-encoded token into an attribute list and check whether it's
 * the token type that we expected.  Returns a webauth status.  On success,
 * stores the attribute list in the provided parameter; on failure, sets the
 * attribute list pointer to NULL.
 */
static int
parse_token(struct webauth_context *ctx, const char *type, const char *token,
            const WEBAUTH_KEYRING *keyring, WEBAUTH_ATTR_LIST **alist)
{
    char *input, *value;
    size_t length;
    int status;

    *alist = NULL;
    input = apr_pstrdup(ctx->pool, token);
    length = apr_base64_decode(input, input);
    status = webauth_token_parse(input, length, 0, keyring, alist);
    if (status != WA_ERR_NONE)
        goto fail;
    status = webauth_attr_list_get_str(*alist, WA_TK_TOKEN_TYPE, &value,
                                       &length, WA_F_NONE);
    if (status != WA_ERR_NONE)
        goto fail;
    else if (length != strlen(type) || strncmp(value, type, length) != 0) {
        webauth_attr_list_free(*alist);
        *alist = NULL;
        webauth_error_set(ctx, WA_ERR_CORRUPT, "wrong token type %s while"
                          " decoding %s token", value, type);
        return WA_ERR_CORRUPT;
    }
    return WA_ERR_NONE;

fail:
    if (*alist != NULL) {
        webauth_attr_list_free(*alist);
        *alist = NULL;
    }
    webauth_error_set(ctx, status, "bad %s token", type);
    return status;
}


/*
 * Extract a data attribute from a token and copy it into pool-allocated
 * memory, storing it into the value argument and its length into the length
 * argument.  The last argument determines whether the attribute is required
 * or optional.  If it's required, return an error if it's missing.  If it's
 * not required, return success if it's missing.  Return a status and set the
 * internal error message if needed, and set the value to NULL and the length
 * to 0 on an error.
 */
static int
decode_data(struct webauth_context *ctx, WEBAUTH_ATTR_LIST *alist,
            const char *attr, const void **value, size_t *length,
            bool required)
{
    int status;
    void *v, *output;
    size_t len;

    status = webauth_attr_list_get(alist, attr, &v, &len, WA_F_NONE);
    if (status != WA_ERR_NONE) {
        *value = NULL;
        *length = 0;
        if (status == WA_ERR_NOT_FOUND && !required)
            return WA_ERR_NONE;
        if (status == WA_ERR_NOT_FOUND)
            status = WA_ERR_CORRUPT;
        webauth_error_set(ctx, status, "decoding attribute %s failed", attr);
        return status;
    }
    output = apr_palloc(ctx->pool, len);
    memcpy(output, v, len);
    *value = output;
    *length = len;
    return status;
}


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
        if (status == WA_ERR_NOT_FOUND)
            status = WA_ERR_CORRUPT;
        webauth_error_set(ctx, status, "decoding attribute %s failed", attr);
        return status;
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
        if (status == WA_ERR_NOT_FOUND)
            status = WA_ERR_CORRUPT;
        webauth_error_set(ctx, status, "decoding attribute %s failed", attr);
        return status;
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
        if (status == WA_ERR_NOT_FOUND)
            status = WA_ERR_CORRUPT;
        webauth_error_set(ctx, status, "decoding attribute %s failed", attr);
        return status;
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
    WEBAUTH_ATTR_LIST *alist = NULL;
    struct webauth_token_app *token;
    int status;

    *decoded = NULL;
    status = parse_token(ctx, WA_TT_APP, encoded, keyring, &alist);
    if (status != WA_ERR_NONE)
        return status;

    /* We have a valid app token.  Pull out the attributes. */
    token = apr_palloc(ctx->pool, sizeof(struct webauth_token_app));
    DECODE_STR( WA_TK_SUBJECT,         subject,         true);
    DECODE_STR( WA_TK_INITIAL_FACTORS, initial_factors, false);
    DECODE_STR( WA_TK_SESSION_FACTORS, session_factors, false);
    DECODE_TIME(WA_TK_LASTUSED_TIME,   last_used,       false);
    DECODE_TIME(WA_TK_CREATION_TIME,   creation,        false);
    DECODE_TIME(WA_TK_EXPIRATION_TIME, expiration,      true);
    DECODE_UINT(WA_TK_LOA,             loa,             false);

    webauth_attr_list_free(alist);
    *decoded = token;
    return WA_ERR_NONE;

fail:
    if (alist != NULL)
        webauth_attr_list_free(alist);
    return status;
}


/*
 * Decode a credential token from the encrypted base64 wire format and store a
 * newly allocated webauth_token_cred struct in token with the contents.
 * Returns a WebAuth status code.  On failure, sets token to NULL.
 */
int
webauth_token_decode_cred(struct webauth_context *ctx, const char *encoded,
                          const WEBAUTH_KEYRING *keyring,
                          struct webauth_token_cred **decoded)
{
    WEBAUTH_ATTR_LIST *alist = NULL;
    struct webauth_token_cred *token;
    int status;

    *decoded = NULL;
    status = parse_token(ctx, WA_TT_CRED, encoded, keyring, &alist);
    if (status != WA_ERR_NONE)
        return status;

    /* We have a valid cred token.  Pull out the attributes. */
    token = apr_palloc(ctx->pool, sizeof(struct webauth_token_cred));
    DECODE_STR( WA_TK_SUBJECT,         subject,    true);
    DECODE_STR( WA_TK_CRED_TYPE,       type,       true);
    DECODE_STR( WA_TK_CRED_SERVICE,    service,    true);
    DECODE_DATA(WA_TK_CRED_DATA,       data,       true);
    DECODE_TIME(WA_TK_CREATION_TIME,   creation,   true);
    DECODE_TIME(WA_TK_EXPIRATION_TIME, expiration, true);

    webauth_attr_list_free(alist);
    *decoded = token;
    return WA_ERR_NONE;

fail:
    if (alist != NULL)
        webauth_attr_list_free(alist);
    return status;
}


/*
 * Decode an id token from the encrypted base64 wire format and store a newly
 * allocated webauth_token_id struct in token with the contents.  Returns a
 * WebAuth status code.  On failure, sets token to NULL.
 */
int
webauth_token_decode_id(struct webauth_context *ctx, const char *encoded,
                        const WEBAUTH_KEYRING *keyring,
                        struct webauth_token_id **decoded)
{
    WEBAUTH_ATTR_LIST *alist = NULL;
    struct webauth_token_id *token;
    int status;

    *decoded = NULL;
    status = parse_token(ctx, WA_TT_ID, encoded, keyring, &alist);
    if (status != WA_ERR_NONE)
        return status;

    /* We have a valid app token.  Pull out the attributes. */
    token = apr_palloc(ctx->pool, sizeof(struct webauth_token_id));
    DECODE_STR( WA_TK_SUBJECT,           subject,         false);
    DECODE_STR( WA_TK_SUBJECT_AUTH,      auth,            true);
    DECODE_DATA(WA_TK_SUBJECT_AUTH_DATA, auth_data,       false);
    DECODE_STR( WA_TK_INITIAL_FACTORS,   initial_factors, false);
    DECODE_STR( WA_TK_SESSION_FACTORS,   session_factors, false);
    DECODE_UINT(WA_TK_LOA,               loa,             false);
    DECODE_TIME(WA_TK_CREATION_TIME,     creation,        false);
    DECODE_TIME(WA_TK_EXPIRATION_TIME,   expiration,      true);

    /*
     * Depending on the authenticator type, either subject or auth_data are
     * mandatory attributes.  The authenticator type must be either krb5 or
     * webkdc.
     */
    if (strcmp(token->auth, "krb5") == 0) {
        if (token->auth_data == NULL || token->auth_data_len == 0) {
            status = WA_ERR_CORRUPT;
            webauth_error_set(ctx, status, "missing krb5 authentication data");
            goto fail;
        }
    } else if (strcmp(token->auth, "webkdc") == 0) {
        if (token->subject == NULL) {
            status = WA_ERR_CORRUPT;
            webauth_error_set(ctx, status, "missing webkdc subject");
            goto fail;
        }
    } else {
        status = WA_ERR_CORRUPT;
        webauth_error_set(ctx, status, "unknown auth type %s", token->auth);
        goto fail;
    }

    webauth_attr_list_free(alist);
    *decoded = token;
    return WA_ERR_NONE;

fail:
    if (alist != NULL)
        webauth_attr_list_free(alist);
    return status;
}


/*
 * Decode an error token from the encrypted base64 wire format and store a
 * newly allocated webauth_token_error struct in token with the contents.
 * Returns a WebAuth status code.  On failure, sets token to NULL.
 */
int
webauth_token_decode_error(struct webauth_context *ctx, const char *encoded,
                           const WEBAUTH_KEYRING *keyring,
                           struct webauth_token_error **decoded)
{
    WEBAUTH_ATTR_LIST *alist = NULL;
    struct webauth_token_error *token;
    const char *code;
    char *end;
    int status;

    *decoded = NULL;
    status = parse_token(ctx, WA_TT_ERROR, encoded, keyring, &alist);
    if (status != WA_ERR_NONE)
        return status;

    /* We have a valid error token.  Pull out the attributes. */
    token = apr_palloc(ctx->pool, sizeof(struct webauth_token_error));
    DECODE_STR( WA_TK_ERROR_MESSAGE, message,  true);
    DECODE_TIME(WA_TK_CREATION_TIME, creation, true);

    /*
     * The error code is a string in the protocol.  Convert it to a number
     * for the convenience of library callers.
     */
    status = decode_string(ctx, alist, WA_TK_ERROR_CODE, &code, true);
    if (status != WA_ERR_NONE)
        goto fail;
    errno = 0;
    token->code = strtoul(code, &end, 10);
    if (*end != '\0' || (token->code == ULONG_MAX && errno != 0)) {
        status = WA_ERR_CORRUPT;
        webauth_error_set(ctx, status, "error code %s is not a number", code);
        goto fail;
    }

    webauth_attr_list_free(alist);
    *decoded = token;
    return WA_ERR_NONE;

fail:
    if (alist != NULL)
        webauth_attr_list_free(alist);
    return status;
}


/*
 * Decode a proxy token from the encrypted base64 wire format and store a
 * newly allocated webauth_token_proxy struct in token with the contents.
 * Returns a WebAuth status code.  On failure, sets token to NULL.
 */
int
webauth_token_decode_proxy(struct webauth_context *ctx, const char *encoded,
                           const WEBAUTH_KEYRING *keyring,
                           struct webauth_token_proxy **decoded)
{
    WEBAUTH_ATTR_LIST *alist = NULL;
    struct webauth_token_proxy *token;
    int status;

    *decoded = NULL;
    status = parse_token(ctx, WA_TT_PROXY, encoded, keyring, &alist);
    if (status != WA_ERR_NONE)
        return status;

    /* We have a valid cred token.  Pull out the attributes. */
    token = apr_palloc(ctx->pool, sizeof(struct webauth_token_proxy));
    DECODE_STR( WA_TK_SUBJECT,         subject,      true);
    DECODE_STR( WA_TK_PROXY_TYPE,      type,         true);
    DECODE_DATA(WA_TK_WEBKDC_TOKEN,    webkdc_proxy, true);
    DECODE_TIME(WA_TK_CREATION_TIME,   creation,     true);
    DECODE_TIME(WA_TK_EXPIRATION_TIME, expiration,   true);

    webauth_attr_list_free(alist);
    *decoded = token;
    return WA_ERR_NONE;

fail:
    if (alist != NULL)
        webauth_attr_list_free(alist);
    return status;
}
