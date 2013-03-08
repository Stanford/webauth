/*
 * WebAuth context creation and destruction.
 *
 * Interfaces for creating and destroying the WebAuth context, which holds any
 * state required by the WebAuth APIs.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011, 2012, 2013
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
    case WA_ERR_FILE_OPENWRITE:    return "unable to open file for writing";
    case WA_ERR_FILE_WRITE:        return "error writing to file";
    case WA_ERR_FILE_OPENREAD:     return "unable to open file for reading";
    case WA_ERR_FILE_READ:         return "error reading from file";
    case WA_ERR_FILE_VERSION:      return "bad file data version";
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
    case WA_ERR_FILE_NOT_FOUND:    return "file does not exist";
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
 * Add context to the existing error message.  This appends a string starting
 * with "while" followed by the results of formatting the provided printf
 * string.  If there is no current error, this silently fails (possibly not
 * ideal, but that can only happen with an internal coding error, the results
 * are innocuous, and we don't want to clutter code with error checking of
 * error reporting routines).
 */
void
wai_error_add_context(struct webauth_context *ctx, const char *format, ...)
{
    va_list args;
    char *string;

    if (ctx == NULL || ctx->error == NULL)
        return;
    va_start(args, format);
    string = apr_pvsprintf(ctx->pool, format, args);
    va_end(args);
    ctx->error = apr_pstrcat(ctx->pool, ctx->error, " while ", string, NULL);
}


/*
 * Set the error message and code to the provided values, supporting
 * printf-style formatting.  This function is internal to the WebAuth library
 * and is not exposed to external consumers.
 */
void
wai_error_set(struct webauth_context *ctx, int err, const char *format, ...)
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
wai_error_set_apr(struct webauth_context *ctx, int err, apr_status_t status,
                  const char *format, ...)
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


/*
 * Set the error message and code to the provided values, supporting
 * printf-style formatting and including the string explanation of an errno.
 * This function is internal to the WebAuth library and is not exposed to
 * external consumers.
 */
void
wai_error_set_system(struct webauth_context *ctx, int err, int syserr,
                     const char *format, ...)
{
    va_list args;
    char *string;

    va_start(args, format);
    string = apr_pvsprintf(ctx->pool, format, args);
    va_end(args);
    ctx->error = apr_psprintf(ctx->pool, "%s (%s: %s)", error_string(ctx, err),
                              string, strerror(syserr));
    ctx->code = err;
}


/*
 * Given a logging level, return a pointer to the callback configuration for
 * that logging level or NULL if the logging level is unknown.
 */
static struct wai_log_callback *
callback_for_level(struct webauth_context *ctx, enum webauth_log_level level)
{
    switch (level) {
    case WA_LOG_WARN:   return &ctx->warn;
    case WA_LOG_NOTICE: return &ctx->notice;
    case WA_LOG_INFO:   return &ctx->info;
    case WA_LOG_TRACE:  return &ctx->trace;
    default:            return NULL;
    }
}


/*
 * Set a logging callback for a particular log level.  This is used by the
 * client to direct non-error messages to a function of the client's choice,
 * and then used by the internal wai_log_* family of functions.  The data
 * element is stored and passed back to the callback.  Any existing callback
 * for that log level is overwritten.
 *
 * callback may be NULL, in which case the callback for that log level is
 * cleared.  If a callback is set and then later removed or overwritten, the
 * data pointer will be discarded but will not be freed.  The caller is
 * responsible for freeing the data in that situation.
 *
 * Returns a WebAuth error code, which will only ever not be WA_ERR_NONE if an
 * invalid log level was passed in.
 */
int
webauth_log_callback(struct webauth_context *ctx, enum webauth_log_level level,
                     webauth_log_func callback, void *data)
{
    struct wai_log_callback *config;

    /* Find the appropriate place to store the callback. */
    config = callback_for_level(ctx, level);
    if (config == NULL) {
        wai_error_set(ctx, WA_ERR_INVALID, "unknown log level %d", level);
        return WA_ERR_INVALID;
    }

    /* Set the new callback. */
    config->callback = callback;
    config->data = (callback != NULL) ? data : NULL;
    return WA_ERR_NONE;
}


/*
 * Log a message at a particular logging level.  The public interface is one
 * function per logging level to keep code concise, but factor out the
 * internal implementation into one function that does the logging and four
 * functions that call it with an appropriate argument.
 */
static void
log_message(struct webauth_context *ctx, enum webauth_log_level level,
            const char *message)
{
    struct wai_log_callback *config;

    /* Find the appropriate log callback. */
    config = callback_for_level(ctx, level);
    if (config == NULL) {
        wai_log_warn(ctx, "internal error: unknown log level %d (message: %s)",
                     level, message);
        return;
    }

    /* Format and log the message if there is a callback for that level. */
    if (config->callback != NULL)
        config->callback(ctx, config->data, message);
}


/* Wrappers around log_message for different log levels. */
#define LOG_FUNCTION(level, code)                               \
    void                                                        \
    wai_log_ ## level(struct webauth_context *ctx,              \
                      const char *format, ...)                  \
    {                                                           \
        va_list args;                                           \
        char *message;                                          \
                                                                \
        va_start(args, format);                                 \
        message = apr_pvsprintf(ctx->pool, format, args);       \
        log_message(ctx, (code), message);                      \
        va_end(args);                                           \
    }
LOG_FUNCTION(info,   WA_LOG_INFO)
LOG_FUNCTION(notice, WA_LOG_NOTICE)
LOG_FUNCTION(trace,  WA_LOG_TRACE)
LOG_FUNCTION(warn,   WA_LOG_WARN)


/*
 * Convert an existing error message into a log message, log it, and then
 * clear the error message inside the WebAuth context.
 */
void
wai_log_error(struct webauth_context *ctx, enum webauth_log_level level,
              int code)
{
    const char *message;

    message = webauth_error_message(ctx, code);
    log_message(ctx, level, message);
    ctx->error = NULL;
    ctx->code = 0;
}
