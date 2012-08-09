/*
 * WebAuth context creation and destruction.
 *
 * Interfaces for creating and destroying the WebAuth context, which holds any
 * state required by the WebAuth APIs.
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

#include <lib/internal.h>
#include <webauth/basic.h>
#include <util/macros.h>


/*
 * Given a pool, allocate a WebAuth context from that pool and return it.
 */
static struct webauth_context *
init_context(apr_pool_t *pool)
{
    struct webauth_context *ctx;

    ctx = apr_pcalloc(pool, sizeof(struct webauth_context));
    ctx->pool = pool;
    ctx->error = NULL;
    ctx->user = NULL;
    return ctx;
}


/*
 * The abort function called by APR on any memory allocation failure.  By
 * default, APR just returns NULL, which will probably cause segfaults but
 * might cause some strange issue.  Instead, always abort immediately after
 * attempting to report an error.
 */
static int
pool_failure(int retcode)
{
    fprintf(stderr, "libwebauth: APR pool allocation failure (%d)", retcode);
    abort();

    /* Not reached. */
    return retcode;
}


/*
 * Initialize a WebAuth context.  This allocates the internal webauth_context
 * struct and does any necessary initialization, including setting up an APR
 * memory pool to use for any required allocations.  This is the entry point
 * for non-APR-aware applications, which hides the APR initialization.  Any
 * call to this function must be matched one-to-one with a call to
 * webauth_context_free.
 */
int
webauth_context_init(struct webauth_context **context, apr_pool_t *parent)
{
    apr_pool_t *pool;

    if (apr_initialize() != APR_SUCCESS)
        return WA_ERR_APR;
    if (apr_pool_create(&pool, parent) != APR_SUCCESS)
        return WA_ERR_APR;
    apr_pool_abort_set(pool_failure, pool);
    *context = init_context(pool);
    return WA_ERR_NONE;
}


/*
 * Initialize a WebAuth context from inside an APR-aware application.  This
 * allocates the internal webauth_context struct and does any necessary
 * initialization, including setting up an APR memory pool to use for any
 * required allocations.
 *
 * This is identical to webauth_context_init except that it doesn't call
 * apr_initialize and therefore doesn't have to be matched with a call to
 * webauth_context_free.  A parent pool must be provided.
 */
int
webauth_context_init_apr(struct webauth_context **context, apr_pool_t *parent)
{
    apr_pool_t *pool;

    if (parent == NULL)
        return WA_ERR_APR;
    if (apr_pool_create(&pool, parent) != APR_SUCCESS)
        return WA_ERR_APR;
    apr_pool_abort_set(pool_failure, pool);
    *context = init_context(pool);
    return WA_ERR_NONE;
}


/*
 * Free the WebAuth context and its corresponding subpool, which will free all
 * memory that was allocated from that context.  This should only be called by
 * applications that use webauth_context_init, not by anything that called
 * webauth_context_init_apr.
 */
void
webauth_context_free(struct webauth_context *ctx UNUSED)
{
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
    case WA_ERR_KEYRING_WRITE:     return "error writing to keyring file";
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
    case WA_ERR_INVALID:           return "invalid argument to function";
    case WA_ERR_REMOTE_FAILURE:    return "a remote service call failed";
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


/*
 * Set the error message and code to the provided values, supporting
 * printf-style formatting and including the string explanation of an APR
 * status.  This function is internal to the WebAuth library and is not
 * exposed to external consumers.
 */
void
webauth_error_set_apr(struct webauth_context *ctx, int err,
                      apr_status_t status, const char *format, ...)
{
    va_list args;
    char *string;
    char buf[BUFSIZ];

    va_start(args, format);
    string = apr_pvsprintf(ctx->pool, format, args);
    va_end(args);
    ctx->error = apr_psprintf(ctx->pool, "%s (%s: %s)", error_string(ctx, err),
                              string, apr_strerror(status, buf, sizeof(buf)));
    ctx->code = err;
}
