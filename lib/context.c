/*
 * WebAuth context creation and destruction.
 *
 * Interfaces for creating and destroying the WebAuth context, which holds any
 * state required by the WebAuth APIs.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011
 *     The Board of Trustees of the Leland Stanford Junior Univerity
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <apr_general.h>
#include <apr_pools.h>
#include <apr_strings.h>

#include <lib/internal.h>
#include <webauth.h>
#include <webauth/basic.h>


/*
 * Initialize a WebAuth context.  This allocates the internal webauth_context
 * struct and does any necessary initialization, including setting up an APR
 * memory pool to use for any required allocations.
 */
int
webauth_context_init(struct webauth_context **context, apr_pool_t *parent)
{
    apr_pool_t *pool;
    struct webauth_context *ctx;

    if (apr_initialize() != APR_SUCCESS)
        return WA_ERR_APR;
    if (apr_pool_create(&pool, parent) != APR_SUCCESS)
        return WA_ERR_APR;
    ctx = apr_palloc(pool, sizeof(struct webauth_context));
    ctx->pool = pool;
    ctx->error = NULL;
    *context = ctx;
    return WA_ERR_NONE;
}


/*
 * Free the WebAuth context and its corresponding subpool, which will free all
 * memory that was allocated from that context.
 */
void
webauth_context_free(struct webauth_context *ctx)
{
    apr_pool_destroy(ctx->pool);
    apr_terminate();
}


/*
 * Map an error code to a string.  This is used as the fallback error message,
 * and is prepended with a colon to whatever additional error information is
 * provided.
 */
static const char *
error_string(struct webauth_context *ctx, int code)
{
    switch (code) {
    case WA_ERR_NONE:              return "no error occurred";
    case WA_ERR_NO_ROOM:           return "supplied buffer too small";
    case WA_ERR_CORRUPT:           return "data is incorrectly formatted";
    case WA_ERR_NO_MEM:            return "no memory";
    case WA_ERR_BAD_HMAC:          return "HMAC check failed";
    case WA_ERR_RAND_FAILURE:      return "unable to get random data";
    case WA_ERR_BAD_KEY:           return "unable to use key";
    case WA_ERR_KEYRING_OPENWRITE: return "unable to open keyring for writing";
    case WA_ERR_KEYRING_WRITE:     return "error writing key ring";
    case WA_ERR_KEYRING_OPENREAD:  return "unable to open keyring for reading";
    case WA_ERR_KEYRING_READ:      return "error reading from keyring file";
    case WA_ERR_KEYRING_VERSION:   return "bad keyring version";
    case WA_ERR_NOT_FOUND:         return "item not found while searching";
    case WA_ERR_KRB5:              return "Kerberos error";
    case WA_ERR_INVALID_CONTEXT:   return "invalid context passed to function";
    case WA_ERR_LOGIN_FAILED:      return "login failed";
    case WA_ERR_TOKEN_EXPIRED:     return "token has expired";
    case WA_ERR_TOKEN_STALE:       return "token is stale";
    case WA_ERR_CREDS_EXPIRED:     return "password has expired";
    case WA_ERR_APR:               return "APR error";
    case WA_ERR_UNIMPLEMENTED:     return "operation not supported";
    default:
        if (ctx != NULL)
            return apr_psprintf(ctx->pool, "unknown error code %d", code);
        else
            return "unknown error code";
        break;
    }
}


/*
 * Map an error code to an error message.  If there's an error message stored
 * in the context and the error code matches the one that's passed in, return
 * that error message.  Otherwise, and if the context is NULL, map the error
 * code to a static error string and return it.
 */
const char *
webauth_error_message(struct webauth_context *ctx, int err)
{
    if (ctx != NULL && ctx->error != NULL && ctx->code == err)
        return ctx->error;
    return error_string(ctx, err);
}


/*
 * Set the error message and code to the provided values, supporting
 * printf-style formatting.  This function is internal to the WebAuth library
 * and is not exposed to external consumers.
 */
void
webauth_error_set(struct webauth_context *ctx, int err, const char *format,
                  ...)
{
    va_list args;
    char *string;

    va_start(args, format);
    string = apr_pvsprintf(ctx->pool, format, args);
    va_end(args);
    ctx->error = apr_pstrcat(ctx->pool, error_string(ctx, err),
                             " (", string, ")", NULL);
    ctx->code = err;
}
