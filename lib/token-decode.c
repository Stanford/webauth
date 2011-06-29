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

/* Abbreviates some long chains of string comparisons. */
#define EQn(a, b, n) (strlen(b) == (n) && strncmp((a), (b), (n)) == 0)


/*
 * Map a token type string to one of the enum token_type constants.  Returns
 * WA_TOKEN_UNKNOWN on error.
 */
static enum webauth_token_type
token_type_code(const char *t, size_t l)
{
    if      (EQn(t, WA_TT_APP,            l)) return WA_TOKEN_APP;
    else if (EQn(t, WA_TT_CRED,           l)) return WA_TOKEN_CRED;
    else if (EQn(t, WA_TT_ERROR,          l)) return WA_TOKEN_ERROR;
    else if (EQn(t, WA_TT_ID,             l)) return WA_TOKEN_ID;
    else if (EQn(t, WA_TT_LOGIN,          l)) return WA_TOKEN_LOGIN;
    else if (EQn(t, WA_TT_PROXY,          l)) return WA_TOKEN_PROXY;
    else if (EQn(t, WA_TT_REQUEST,        l)) return WA_TOKEN_REQUEST;
    else if (EQn(t, WA_TT_WEBKDC_PROXY,   l)) return WA_TOKEN_WEBKDC_PROXY;
    else if (EQn(t, WA_TT_WEBKDC_SERVICE, l)) return WA_TOKEN_WEBKDC_SERVICE;
    else return WA_TOKEN_UNKNOWN;
}


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
        webauth_error_set(ctx, WA_ERR_CORRUPT, "wrong token type %.*s while"
                          " decoding %s token", length, value, type);
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
 * Similar to parse_token, but allows the token type to be anything.  On a
 * successful decode of the token to an attribute list, stores the token type
 * in the type argument.  Requires the token be of a known type or returns an
 * error.
 */
static int
parse_token_any(struct webauth_context *ctx, const char *token,
                const WEBAUTH_KEYRING *keyring, enum webauth_token_type *type,
                WEBAUTH_ATTR_LIST **alist)
{
    char *input, *value;
    size_t length;
    int status;

    *type = WA_TOKEN_UNKNOWN;
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
    *type = token_type_code(value, length);
    if (*type == WA_TOKEN_UNKNOWN) {
        webauth_attr_list_free(*alist);
        *alist = NULL;
        webauth_error_set(ctx, WA_ERR_CORRUPT, "unknown token type %.*s",
                          length, value);
        return WA_ERR_CORRUPT;
    }
    return WA_ERR_NONE;

fail:
    if (*alist != NULL) {
        webauth_attr_list_free(*alist);
        *alist = NULL;
    }
    webauth_error_set(ctx, status, "bad token during generic decoding");
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
 * Check the provided value to determine whether it's a valid credential type.
 * Takes the token type as well as the credential type.  Assumes the
 * credential type is non-NULL.  Returns a WebAuth error code and sets the
 * error message if needed.
 */
static int
check_cred_type(struct webauth_context *ctx, const char *cred_type,
                 const char *type)
{
    int status = WA_ERR_NONE;

    if (strcmp(cred_type, "krb5") != 0) {
        status = WA_ERR_CORRUPT;
        webauth_error_set(ctx, status, "unknown credential type %s in %s"
                          " token", cred_type, type);
    }
    return status;
}


/*
 * Check the provided value to determine whether it's a valid proxy type.
 * Takes the token type as well as the proxy type.  Assumes the proxy type is
 * non-NULL.  Returns a WebAuth error code and sets the error message if
 * needed.
 */
static int
check_proxy_type(struct webauth_context *ctx, const char *proxy_type,
                 const char *type)
{
    int status = WA_ERR_NONE;

    if (strcmp(proxy_type, "krb5") != 0) {
        status = WA_ERR_CORRUPT;
        webauth_error_set(ctx, status, "unknown proxy type %s in %s token",
                          proxy_type, type);
    }
    return status;
}


/*
 * Check the provided value to determine whether it's a valid subject auth
 * type.  Takes the token type as well as the subject auth type.  Assumes the
 * subject auth type is non-NULL.  Returns a WebAuth error code and sets the
 * error message if needed.
 */
static int
check_subject_auth(struct webauth_context *ctx, const char *auth,
                   const char *type)
{
    int status = WA_ERR_NONE;

    if (strcmp(auth, "krb5") != 0 && strcmp(auth, "webkdc") != 0) {
        status = WA_ERR_CORRUPT;
        webauth_error_set(ctx, status, "unknown auth type %s in %s token",
                          auth, type);
    }
    return status;
}


/*
 * Given the attribute list of an app token, decode it and store the results
 * in decoded, using newly-allocated pool memory.  On failure, sets decoded to
 * NULL and sets the error message.
 */
static int
decode_app_alist(struct webauth_context *ctx, WEBAUTH_ATTR_LIST *alist,
                 struct webauth_token_app **decoded)
{
    struct webauth_token_app *token;
    int status;

    *decoded = NULL;
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

fail:
    return status;
}


/*
 * Decode an application token from the encrypted base64 wire format.  Store
 * the results in decoded, using newly-allocated pool memory.  On failure,
 * sets decoded to NULL and sets the error message.
 */
int
webauth_token_decode_app(struct webauth_context *ctx, const char *encoded,
                         const WEBAUTH_KEYRING *keyring,
                         struct webauth_token_app **decoded)
{
    WEBAUTH_ATTR_LIST *alist;
    int status;

    *decoded = NULL;
    status = parse_token(ctx, WA_TT_APP, encoded, keyring, &alist);
    if (status != WA_ERR_NONE)
        return status;
    status = decode_app_alist(ctx, alist, decoded);
    webauth_attr_list_free(alist);
    return status;
}


/*
 * Given the attribute list of a cred token, decode it and store the results
 * in decoded, using newly-allocated pool memory.  On failure, sets deocded to
 * NULL and sets the error message.
 */
static int
decode_cred_alist(struct webauth_context *ctx, WEBAUTH_ATTR_LIST *alist,
                  struct webauth_token_cred **decoded)
{
    struct webauth_token_cred *token;
    int status;

    *decoded = NULL;
    token = apr_palloc(ctx->pool, sizeof(struct webauth_token_cred));
    DECODE_STR( WA_TK_SUBJECT,         subject,    true);
    DECODE_STR( WA_TK_CRED_TYPE,       type,       true);
    DECODE_STR( WA_TK_CRED_SERVICE,    service,    true);
    DECODE_DATA(WA_TK_CRED_DATA,       data,       true);
    DECODE_TIME(WA_TK_CREATION_TIME,   creation,   true);
    DECODE_TIME(WA_TK_EXPIRATION_TIME, expiration, true);
    status = check_cred_type(ctx, token->type, "cred");
    if (status != WA_ERR_NONE)
        goto fail;
    *decoded = token;
    return WA_ERR_NONE;

fail:
    return status;
}


/*
 * Decode a credential token from the encrypted base64 wire format.  Store the
 * results in decoded, using newly-allocated pool memory.  On failure, sets
 * decoded to NULL and sets the error message.
 */
int
webauth_token_decode_cred(struct webauth_context *ctx, const char *encoded,
                          const WEBAUTH_KEYRING *keyring,
                          struct webauth_token_cred **decoded)
{
    WEBAUTH_ATTR_LIST *alist;
    int status;

    *decoded = NULL;
    status = parse_token(ctx, WA_TT_CRED, encoded, keyring, &alist);
    if (status != WA_ERR_NONE)
        return status;
    status = decode_cred_alist(ctx, alist, decoded);
    webauth_attr_list_free(alist);
    return status;
}


/*
 * Given the attribute list of an error token, decode it and store the results
 * in decoded, using newly-allocated pool memory.  On failure, sets decoded to
 * NULL and sets the error message.
 */
static int
decode_error_alist(struct webauth_context *ctx, WEBAUTH_ATTR_LIST *alist,
                   struct webauth_token_error **decoded)
{
    struct webauth_token_error *token;
    int status;
    const char *code;
    char *end;

    *decoded = NULL;
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

    *decoded = token;
    return WA_ERR_NONE;

fail:
    return status;
}


/*
 * Decode an error token from the encrypted base64 wire format.  Store the
 * results in decoded, using newly-allocated pool memory.  On failure, sets
 * decoded to NULL and sets the error message.
 */
int
webauth_token_decode_error(struct webauth_context *ctx, const char *encoded,
                           const WEBAUTH_KEYRING *keyring,
                           struct webauth_token_error **decoded)
{
    WEBAUTH_ATTR_LIST *alist = NULL;
    int status;

    *decoded = NULL;
    status = parse_token(ctx, WA_TT_ERROR, encoded, keyring, &alist);
    if (status != WA_ERR_NONE)
        return status;
    status = decode_error_alist(ctx, alist, decoded);
    webauth_attr_list_free(alist);
    return status;
}


/*
 * Given the attribute list of an id token, decode it and store the results in
 * decoded, using newly-allocated pool memory.  On failure, sets decoded to
 * NULL and sets the error message.
 */
static int
decode_id_alist(struct webauth_context *ctx, WEBAUTH_ATTR_LIST *alist,
                struct webauth_token_id **decoded)
{
    struct webauth_token_id *token;
    int status;
    bool need_data = false;

    /*
     * Depending on the authenticator type, either subject or auth_data are
     * mandatory attributes.
     */
    *decoded = NULL;
    token = apr_palloc(ctx->pool, sizeof(struct webauth_token_id));
    DECODE_STR( WA_TK_SUBJECT_AUTH,      auth,            true);
    if (strcmp(token->auth, "krb5") == 0)
        need_data = true;
    DECODE_STR( WA_TK_SUBJECT,           subject,         !need_data);
    DECODE_DATA(WA_TK_SUBJECT_AUTH_DATA, auth_data,       need_data);
    DECODE_STR( WA_TK_INITIAL_FACTORS,   initial_factors, false);
    DECODE_STR( WA_TK_SESSION_FACTORS,   session_factors, false);
    DECODE_UINT(WA_TK_LOA,               loa,             false);
    DECODE_TIME(WA_TK_CREATION_TIME,     creation,        false);
    DECODE_TIME(WA_TK_EXPIRATION_TIME,   expiration,      true);
    status = check_subject_auth(ctx, token->auth, "id");
    if (status != WA_ERR_NONE)
        goto fail;
    *decoded = token;
    return WA_ERR_NONE;

fail:
    return status;
}


/*
 * Decode an id token from the encrypted base64 wire format.  Store the
 * results in decoded, using newly-allocated pool memory.  On failure, sets
 * decoded to NULL and sets the error message.
 */
int
webauth_token_decode_id(struct webauth_context *ctx, const char *encoded,
                        const WEBAUTH_KEYRING *keyring,
                        struct webauth_token_id **decoded)
{
    WEBAUTH_ATTR_LIST *alist = NULL;
    int status;

    *decoded = NULL;
    status = parse_token(ctx, WA_TT_ID, encoded, keyring, &alist);
    if (status != WA_ERR_NONE)
        return status;
    status = decode_id_alist(ctx, alist, decoded);
    webauth_attr_list_free(alist);
    return status;
}


/*
 * Given the attribute list of a proxy token, decode it and store the results
 * in decoded, using newly-allocated pool memory.  On failure, sets decoded to
 * NULL and sets the error message.
 */
static int
decode_proxy_alist(struct webauth_context *ctx, WEBAUTH_ATTR_LIST *alist,
                   struct webauth_token_proxy **decoded)
{
    struct webauth_token_proxy *token;
    int status;

    *decoded = NULL;
    token = apr_palloc(ctx->pool, sizeof(struct webauth_token_proxy));
    DECODE_STR( WA_TK_SUBJECT,           subject,         true);
    DECODE_STR( WA_TK_PROXY_TYPE,        type,            true);
    DECODE_DATA(WA_TK_WEBKDC_TOKEN,      webkdc_proxy,    true);
    DECODE_STR( WA_TK_INITIAL_FACTORS,   initial_factors, false);
    DECODE_STR( WA_TK_SESSION_FACTORS,   session_factors, false);
    DECODE_UINT(WA_TK_LOA,               loa,             false);
    DECODE_TIME(WA_TK_CREATION_TIME,     creation,        true);
    DECODE_TIME(WA_TK_EXPIRATION_TIME,   expiration,      true);
    status = check_proxy_type(ctx, token->type, "proxy");
    if (status != WA_ERR_NONE)
        goto fail;
    *decoded = token;
    return WA_ERR_NONE;

fail:
    return status;
}


/*
 * Decode a proxy token from the encrypted base64 wire format.  Store the
 * results in decoded, using newly-allocated pool memory.  On failure, sets
 * decoded to NULL, and sets the error message.
 */
int
webauth_token_decode_proxy(struct webauth_context *ctx, const char *encoded,
                           const WEBAUTH_KEYRING *keyring,
                           struct webauth_token_proxy **decoded)
{
    WEBAUTH_ATTR_LIST *alist = NULL;
    int status;

    *decoded = NULL;
    status = parse_token(ctx, WA_TT_PROXY, encoded, keyring, &alist);
    if (status != WA_ERR_NONE)
        return status;
    status = decode_proxy_alist(ctx, alist, decoded);
    webauth_attr_list_free(alist);
    return status;
}


/*
 * Given the attribute list of a request token, decode it and store the
 * results in decoded, using newly-allocated pool memory.  On failure, sets
 * decoded to NULL and sets the error message.
 */
static int
decode_request_alist(struct webauth_context *ctx, WEBAUTH_ATTR_LIST *alist,
                     struct webauth_token_request **decoded)
{
    struct webauth_token_request *token;
    int status;
    bool required = true;
    bool need_auth = false;
    bool need_proxy;

    /*
     * Required attributes vary depending on whether there's a command,
     * and then further on whether the requested token type is id or proxy.
     */
    *decoded = NULL;
    token = apr_palloc(ctx->pool, sizeof(struct webauth_token_request));
    DECODE_STR(WA_TK_COMMAND, command, false);
    if (token->command != NULL)
        required = false;
    DECODE_STR(WA_TK_REQUESTED_TOKEN_TYPE, type, required);
    if (token->type != NULL && strcmp(token->type, "id") == 0)
        need_auth = true;
    need_proxy = (!need_auth && required);
    DECODE_STR( WA_TK_SUBJECT_AUTH,         auth,            need_auth);
    DECODE_STR( WA_TK_PROXY_TYPE,           proxy_type,      need_proxy);
    DECODE_DATA(WA_TK_APP_STATE,            state,           false);
    DECODE_STR( WA_TK_RETURN_URL,           return_url,      required);
    DECODE_STR( WA_TK_REQUEST_OPTIONS,      options,         false);
    DECODE_STR( WA_TK_INITIAL_FACTORS,      initial_factors, false);
    DECODE_STR( WA_TK_SESSION_FACTORS,      session_factors, false);
    DECODE_UINT(WA_TK_LOA,                  loa,             false);
    DECODE_TIME(WA_TK_CREATION_TIME,        creation,        true);

    /* We can now do some additional sanity checks for consistency. */
    if (token->command != NULL
        && (token->type != NULL || token->auth != NULL
            || token->proxy_type != NULL || token->state != NULL
            || token->return_url != NULL || token->options != NULL)) {
        status = WA_ERR_CORRUPT;
        webauth_error_set(ctx, status, "command request tokens may not have"
                          " other attributes");
        goto fail;
    }

    /* Check the attributes of a non-command token for consistency. */
    if (token->command != NULL)
        ; /* Nothing to do. */
    else if (strcmp(token->type, "id") == 0)
        status = check_subject_auth(ctx, token->auth, "request");
    else if (strcmp(token->type, "proxy") == 0)
        status = check_proxy_type(ctx, token->proxy_type, "request");
    else {
        status = WA_ERR_CORRUPT;
        webauth_error_set(ctx, status, "unknown requested token type %s"
                          " in request token", token->type);
    }
    if (status != WA_ERR_NONE)
        goto fail;
    *decoded = token;
    return WA_ERR_NONE;

fail:
    return status;
}


/*
 * Decode a request token from the encrypted base64 wire format.  Store the
 * results in decoded, using newly-allocated pool memory.  On failure, sets
 * decoded to NULL, and sets the error message.
 */
int
webauth_token_decode_request(struct webauth_context *ctx, const char *encoded,
                             const WEBAUTH_KEYRING *keyring,
                             struct webauth_token_request **decoded)
{
    WEBAUTH_ATTR_LIST *alist = NULL;
    int status;

    *decoded = NULL;
    status = parse_token(ctx, WA_TT_REQUEST, encoded, keyring, &alist);
    if (status != WA_ERR_NONE)
        return status;
    status = decode_request_alist(ctx, alist, decoded);
    webauth_attr_list_free(alist);
    return status;
}


/*
 * Decode an arbitrary token, where the token type is not known in advance.
 * Takes the context, the token, and the keyring to decrypt it, and stores the
 * token type and newly-allocated struct in the remaining arguments.  On
 * error, type is set to WA_TOKEN_UNKNOWN and decoded is set to NULL, and an
 * error code is returned.
 */
int
webauth_token_decode(struct webauth_context *ctx, const char *encoded,
                     const WEBAUTH_KEYRING *keyring,
                     enum webauth_token_type *type, void **decoded)
{
    WEBAUTH_ATTR_LIST *alist = NULL;
    int status;
    struct webauth_token_app *app;
    struct webauth_token_cred *cred;
    struct webauth_token_error *err;
    struct webauth_token_id *id;
    struct webauth_token_proxy *proxy;
    struct webauth_token_request *req;

    *decoded = NULL;
    status = parse_token_any(ctx, encoded, keyring, type, &alist);
    if (status != WA_ERR_NONE)
        return status;
    switch (*type) {
    case WA_TOKEN_APP:
        status = webauth_token_decode_app(ctx, encoded, keyring, &app);
        *decoded = app;
        break;
    case WA_TOKEN_CRED:
        status = webauth_token_decode_cred(ctx, encoded, keyring, &cred);
        *decoded = cred;
        break;
    case WA_TOKEN_ERROR:
        status = webauth_token_decode_error(ctx, encoded, keyring, &err);
        *decoded = err;
        break;
    case WA_TOKEN_ID:
        status = webauth_token_decode_id(ctx, encoded, keyring, &id);
        *decoded = id;
        break;
    case WA_TOKEN_PROXY:
        status = webauth_token_decode_proxy(ctx, encoded, keyring, &proxy);
        *decoded = proxy;
        break;
    case WA_TOKEN_REQUEST:
        status = webauth_token_decode_request(ctx, encoded, keyring, &req);
        *decoded = req;
        break;
    case WA_TOKEN_UNKNOWN:
    case WA_TOKEN_LOGIN:
    case WA_TOKEN_WEBKDC_PROXY:
    case WA_TOKEN_WEBKDC_SERVICE:
    default:
        status = WA_ERR_UNIMPLEMENTED;
        webauth_error_set(ctx, WA_ERR_UNIMPLEMENTED,
                          "unsupported token type %d while decoding", *type);
        break;
    }
    return status;
}
