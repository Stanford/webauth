/*
 * High level interface to decoding WebAuth tokens.
 *
 * Interfaces for decoding tokens from the encrypted wire tokens into structs
 * representing the same information.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011, 2012
 *     The Board of Trustees of the Leland Stanford Junior Univerity
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
 * The mapping of token types to token names.  Note that WA_TOKEN_ANY cannot
 * be used with this array and has to be handled specially so that its value
 * won't be used by any new token type.  This must be kept in sync with the
 * enum webauth_token_type definition in webauth/tokens.h.
 */
static const char * const token_name[] = {
    "unknown",
    WA_TT_APP,
    WA_TT_CRED,
    WA_TT_ERROR,
    WA_TT_ID,
    WA_TT_LOGIN,
    WA_TT_PROXY,
    WA_TT_REQUEST,
    WA_TT_WEBKDC_PROXY,
    WA_TT_WEBKDC_SERVICE
};

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
 * Parse a raw token into an attribute list and check whether it's the token
 * type that we expected.  type may be set to WA_TOKEN_ANY to accept any token
 * type, in which case it will be changed to match the actual token type on
 * success.  Returns a webauth status.  On success, stores the attribute list
 * in the provided parameter; on failure, sets the attribute list pointer to
 * NULL.
 */
static int
parse_token(struct webauth_context *ctx, enum webauth_token_type *type,
            const void *token, size_t length,
            const struct webauth_keyring *keyring, WEBAUTH_ATTR_LIST **alist)
{
    void *attrs;
    char *value;
    size_t alen;
    const char *type_string = NULL;
    time_t expiration, now;
    int status;

    /* Do some initial sanity checking. */
    *alist = NULL;
    type_string = webauth_token_type_string(*type);
    if (type_string == NULL && *type != WA_TOKEN_ANY) {
        webauth_error_set(ctx, WA_ERR_INVALID, "unknown token type %d", *type);
        return WA_ERR_INVALID;
    }

    /* Decrypt the token. */
    status = webauth_token_decrypt(ctx, token, length, &attrs, &alen, keyring);
    if (status != WA_ERR_NONE)
        return status;

    /* Decode the attributes. */
    status = webauth_attrs_decode(attrs, alen, alist);
    if (status != WA_ERR_NONE) {
        webauth_error_set(ctx, status, "error decoding token attributes");
        return status;
    }

    /* Check the token type to see if it's what we expect. */
    status = webauth_attr_list_get_str(*alist, WA_TK_TOKEN_TYPE, &value,
                                       &length, WA_F_NONE);
    if (status != WA_ERR_NONE)
        goto error;
    if (*type == WA_TOKEN_ANY) {
        *type = webauth_token_type_code(value);
        if (*type == WA_TOKEN_UNKNOWN) {
            status = WA_ERR_UNIMPLEMENTED;
            webauth_error_set(ctx, status, "unsupported token type %s while"
                              " decoding", value);
            goto fail;
        }
    } else if (strcmp(value, type_string) != 0) {
        status = WA_ERR_CORRUPT;
        webauth_error_set(ctx, status, "wrong token type %s while decoding"
                          " %s token", value, type_string);
        goto fail;
    }

    /* See if the token has an explicit expiration. */
    status = webauth_attr_list_get_time(*alist, WA_TK_EXPIRATION_TIME,
                                        &expiration, WA_F_NONE);
    if (status == WA_ERR_NONE) {
        now = time(NULL);
        if (expiration < now) {
            status = WA_ERR_TOKEN_EXPIRED;
            webauth_error_set(ctx, status, "token expired at %lu",
                              (unsigned long) expiration);
            goto fail;
        }
    } else if (status != WA_ERR_NOT_FOUND) {
        webauth_error_set(ctx, status, "error retrieving expiration time");
        return status;
    }

    return WA_ERR_NONE;

error:
    if (status == WA_ERR_NOT_FOUND) {
        status = WA_ERR_CORRUPT;
        webauth_error_set(ctx, status, "token has no type attribute");
    } else if (type_string != NULL)
        webauth_error_set(ctx, status, "bad %s token", type_string);
    else
        webauth_error_set(ctx, status, "bad token");

fail:
    if (*alist != NULL) {
        webauth_attr_list_free(*alist);
        *alist = NULL;
    }
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
 * in decoded.  On failure, sets the error message and returns an error code.
 */
static int
decode_app(struct webauth_context *ctx, WEBAUTH_ATTR_LIST *alist,
           struct webauth_token_app *token)
{
    int status;
    bool need_subject = true;

    /*
     * There are two major different uses of app tokens: one to hold
     * authentication information for a user, and the other to hold a session
     * key that needs to be returned to the WAS because it may be another pool
     * member without access to the original key.  Subject is required for the
     * former and not for the latter.
     */
    DECODE_DATA(WA_TK_SESSION_KEY,     session_key,     false);
    if (token->session_key != NULL)
        need_subject = false;
    DECODE_STR( WA_TK_SUBJECT,         subject,         need_subject);
    DECODE_TIME(WA_TK_LASTUSED_TIME,   last_used,       false);
    DECODE_STR( WA_TK_INITIAL_FACTORS, initial_factors, false);
    DECODE_STR( WA_TK_SESSION_FACTORS, session_factors, false);
    DECODE_TIME(WA_TK_CREATION_TIME,   creation,        false);
    DECODE_TIME(WA_TK_EXPIRATION_TIME, expiration,      true);
    DECODE_UINT(WA_TK_LOA,             loa,             false);
    return WA_ERR_NONE;

fail:
    return status;
}


/*
 * Given the attribute list of a cred token, decode it and store the results
 * in decoded.  On failure, sets the error message and returns an error code.
 */
static int
decode_cred(struct webauth_context *ctx, WEBAUTH_ATTR_LIST *alist,
            struct webauth_token_cred *token)
{
    int status;

    DECODE_STR( WA_TK_SUBJECT,         subject,    true);
    DECODE_STR( WA_TK_CRED_TYPE,       type,       true);
    DECODE_STR( WA_TK_CRED_SERVICE,    service,    true);
    DECODE_DATA(WA_TK_CRED_DATA,       data,       true);
    DECODE_TIME(WA_TK_CREATION_TIME,   creation,   true);
    DECODE_TIME(WA_TK_EXPIRATION_TIME, expiration, true);
    status = check_cred_type(ctx, token->type, "cred");
    if (status != WA_ERR_NONE)
        goto fail;
    return WA_ERR_NONE;

fail:
    return status;
}


/*
 * Given the attribute list of an error token, decode it and store the results
 * in decoded.  On failure, sets the error message and returns an error code.
 */
static int
decode_error(struct webauth_context *ctx, WEBAUTH_ATTR_LIST *alist,
             struct webauth_token_error *token)
{
    int status;
    const char *code;
    char *end;

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
    return WA_ERR_NONE;

fail:
    return status;
}


/*
 * Given the attribute list of an id token, decode it and store the results in
 * decoded.  On failure, sets the error message and returns an error code.
 */
static int
decode_id(struct webauth_context *ctx, WEBAUTH_ATTR_LIST *alist,
          struct webauth_token_id *token)
{
    int status;
    bool need_data = false;

    /*
     * Depending on the authenticator type, either subject or auth_data are
     * mandatory attributes.
     */
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
    return WA_ERR_NONE;

fail:
    return status;
}


/*
 * Given the attribute list of a login token, decode it and store the results
 * in decoded.  On failure, sets the error message and returns an error code.
 */
static int
decode_login(struct webauth_context *ctx, WEBAUTH_ATTR_LIST *alist,
             struct webauth_token_login *token)
{
    int status;
    bool need_otp = false;

    /* One of password or otp must be provided. */
    DECODE_STR( WA_TK_USERNAME,      username, true);
    DECODE_STR( WA_TK_PASSWORD,      password, false);
    if (token->password == NULL)
        need_otp = true;
    DECODE_STR( WA_TK_OTP,           otp,      need_otp);
    DECODE_TIME(WA_TK_CREATION_TIME, creation, true);
    return WA_ERR_NONE;

fail:
    return status;
}


/*
 * Given the attribute list of a proxy token, decode it and store the results
 * in decoded.  On failure, sets the error message and returns an error code.
 */
static int
decode_proxy(struct webauth_context *ctx, WEBAUTH_ATTR_LIST *alist,
             struct webauth_token_proxy *token)
{
    int status;

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
    return WA_ERR_NONE;

fail:
    return status;
}


/*
 * Given the attribute list of a request token, decode it and store the
 * results in decoded.  On failure, sets the error message and returns an
 * error code.
 */
static int
decode_request(struct webauth_context *ctx, WEBAUTH_ATTR_LIST *alist,
               struct webauth_token_request *token)
{
    int status;
    bool required = true;
    bool need_auth = false;
    bool need_proxy;

    /*
     * Required attributes vary depending on whether there's a command,
     * and then further on whether the requested token type is id or proxy.
     */
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
    if (token->command == NULL) {
        if (strcmp(token->type, "id") == 0)
            status = check_subject_auth(ctx, token->auth, "request");
        else if (strcmp(token->type, "proxy") == 0)
            status = check_proxy_type(ctx, token->proxy_type, "request");
        else {
            status = WA_ERR_CORRUPT;
            webauth_error_set(ctx, status, "unknown requested token type %s"
                              " in request token", token->type);
        }
    }
    if (status != WA_ERR_NONE)
        goto fail;
    return WA_ERR_NONE;

fail:
    return status;
}


/*
 * Given the attribute list of a webkdc-proxy token, decode it and store the
 * results in decoded.  On failure, sets the error message and returns an
 * error code.
 */
static int
decode_webkdc_proxy(struct webauth_context *ctx,
                    WEBAUTH_ATTR_LIST *alist,
                    struct webauth_token_webkdc_proxy *token)
{
    int status;

    DECODE_STR( WA_TK_SUBJECT,         subject,         true);
    DECODE_STR( WA_TK_PROXY_TYPE,      proxy_type,      true);
    DECODE_STR( WA_TK_PROXY_SUBJECT,   proxy_subject,   true);
    DECODE_DATA(WA_TK_PROXY_DATA,      data,            false);
    DECODE_STR( WA_TK_INITIAL_FACTORS, initial_factors, false);
    DECODE_UINT(WA_TK_LOA,             loa,             false);
    DECODE_TIME(WA_TK_CREATION_TIME,   creation,        true);
    DECODE_TIME(WA_TK_EXPIRATION_TIME, expiration,      true);
    return WA_ERR_NONE;

fail:
    return status;
}


/*
 * Given the attribute list of a webkdc-service token, decode it and store the
 * results in decoded.  On failure, sets the error message and returns an
 * error code.
 */
static int
decode_webkdc_service(struct webauth_context *ctx,
                      WEBAUTH_ATTR_LIST *alist,
                      struct webauth_token_webkdc_service *token)
{
    int status;

    DECODE_STR( WA_TK_SUBJECT,         subject,     true);
    DECODE_DATA(WA_TK_SESSION_KEY,     session_key, true);
    DECODE_TIME(WA_TK_CREATION_TIME,   creation,    true);
    DECODE_TIME(WA_TK_EXPIRATION_TIME, expiration,  true);
    return WA_ERR_NONE;

fail:
    return status;
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
    WEBAUTH_ATTR_LIST *alist = NULL;
    int status;
    struct webauth_token *out;

    *decoded = NULL;
    status = parse_token(ctx, &type, token, length, ring, &alist);
    if (status != WA_ERR_NONE)
        return status;
    out = apr_palloc(ctx->pool, sizeof(struct webauth_token));
    out->type = type;
    switch (type) {
    case WA_TOKEN_APP:
        status = decode_app(ctx, alist, &out->token.app);
        break;
    case WA_TOKEN_CRED:
        status = decode_cred(ctx, alist, &out->token.cred);
        break;
    case WA_TOKEN_ERROR:
        status = decode_error(ctx, alist, &out->token.error);
        break;
    case WA_TOKEN_ID:
        status = decode_id(ctx, alist, &out->token.id);
        break;
    case WA_TOKEN_LOGIN:
        status = decode_login(ctx, alist, &out->token.login);
        break;
    case WA_TOKEN_PROXY:
        status = decode_proxy(ctx, alist, &out->token.proxy);
        break;
    case WA_TOKEN_REQUEST:
        status = decode_request(ctx, alist, &out->token.request);
        break;
    case WA_TOKEN_WEBKDC_PROXY:
        status = decode_webkdc_proxy(ctx, alist, &out->token.webkdc_proxy);
        break;
    case WA_TOKEN_WEBKDC_SERVICE:
        status = decode_webkdc_service(ctx, alist, &out->token.webkdc_service);
        break;
    case WA_TOKEN_UNKNOWN:
    case WA_TOKEN_ANY:
    default:
        status = WA_ERR_UNIMPLEMENTED;
        webauth_error_set(ctx, WA_ERR_UNIMPLEMENTED,
                          "unsupported token type %u while decoding", type);
        break;
    }
    webauth_attr_list_free(alist);
    if (status == WA_ERR_NONE)
        *decoded = out;
    return status;
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

    if (token == NULL) {
        webauth_error_set(ctx, WA_ERR_CORRUPT, "decoding null token");
        return WA_ERR_CORRUPT;
    }
    length = apr_base64_decode_len(token);
    input = apr_palloc(ctx->pool, length);
    length = apr_base64_decode(input, token);
    return webauth_token_decode_raw(ctx, type, input, length, ring, decoded);
}
