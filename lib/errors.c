/*
 * WebAuth error handling.
 *
 * The only public interfaces exposed here are webauth_error_message, which
 * translates an error return status into a full error message using
 * information from the context, and interfaces to set the handlers for
 * various log levels.  But included here are all the internal interfaces for
 * managing that error message, plus internal interfaces to log at various log
 * levels.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2011, 2012, 2013, 2014
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
 * Map a WebAuth status code to a string.  This is used as the basis for the
 * error message and is always present at the beginning of the error message.
 */
static const char *
error_string(struct webauth_context *ctx, int s)
{
    switch (s) {
    case WA_ERR_NONE:              return "no error occurred";

    /* Protocol errors. */
    case WA_PEC_SERVICE_TOKEN_EXPIRED: return "expired webkdc-service token";
    case WA_PEC_SERVICE_TOKEN_INVALID: return "invalid webkdc-service token";
    case WA_PEC_PROXY_TOKEN_EXPIRED:   return "expired webkdc-proxy token";
    case WA_PEC_PROXY_TOKEN_INVALID:   return "invalid webkdc-proxy token";
    case WA_PEC_INVALID_REQUEST:       return "request was invalid";
    case WA_PEC_UNAUTHORIZED:          return "authorization denied";
    case WA_PEC_SERVER_FAILURE:        return "internal server failure";
    case WA_PEC_REQUEST_TOKEN_STALE:   return "stale request token";
    case WA_PEC_REQUEST_TOKEN_INVALID: return "invalid request token";
    case WA_PEC_GET_CRED_FAILURE:
        return "cannot obtain requested credential";
    case WA_PEC_REQUESTER_KRB5_CRED_INVALID:
        return "invalid Kerberos authenticator";
    case WA_PEC_LOGIN_TOKEN_STALE:     return "stale login token";
    case WA_PEC_LOGIN_TOKEN_INVALID:   return "invalid login token";
    case WA_PEC_LOGIN_FAILED:          return "login failed";
    case WA_PEC_PROXY_TOKEN_REQUIRED:  return "webkdc-proxy token required";
    case WA_PEC_LOGIN_CANCELED:        return "user canceled login";
    case WA_PEC_LOGIN_FORCED:
        return "forced authentication, must reauthenticate";
    case WA_PEC_USER_REJECTED:         return "username rejected";
    case WA_PEC_CREDS_EXPIRED:         return "user credentials expired";
    case WA_PEC_MULTIFACTOR_REQUIRED:  return "multifactor login required";
    case WA_PEC_MULTIFACTOR_UNAVAILABLE:
        return "multifactor required but not configured";
    case WA_PEC_LOGIN_REJECTED:        return "user may not authenticate";
    case WA_PEC_LOA_UNAVAILABLE:
        return "insufficient level of assurance";
    case WA_PEC_AUTH_REJECTED:         return "authentication rejected";
    case WA_PEC_AUTH_REPLAY:
        return "authentication appears to be a replay";
    case WA_PEC_AUTH_LOCKOUT:          return "too many failed attempts";
    case WA_PEC_LOGIN_TIMEOUT:         return "timeout during login";

    /* Internal errors. */
    case WA_ERR_INTERNAL:          return "internal error";
    case WA_ERR_APR:               return "APR error";
    case WA_ERR_BAD_HMAC:          return "HMAC check failed";
    case WA_ERR_BAD_KEY:           return "unable to use key";
    case WA_ERR_CORRUPT:           return "data is incorrectly formatted";
    case WA_ERR_FILE_NOT_FOUND:    return "file does not exist";
    case WA_ERR_FILE_OPENREAD:     return "unable to open file for reading";
    case WA_ERR_FILE_OPENWRITE:    return "unable to open file for writing";
    case WA_ERR_FILE_READ:         return "error reading from file";
    case WA_ERR_FILE_VERSION:      return "bad file data version";
    case WA_ERR_FILE_WRITE:        return "error writing to file";
    case WA_ERR_INVALID:           return "invalid argument to function";
    case WA_ERR_INVALID_CONTEXT:   return "invalid context passed to function";
    case WA_ERR_KRB5:              return "Kerberos error";
    case WA_ERR_NOT_FOUND:         return "item not found while searching";
    case WA_ERR_NO_MEM:            return "no memory";
    case WA_ERR_NO_ROOM:           return "supplied buffer too small";
    case WA_ERR_RAND_FAILURE:      return "unable to get random data";
    case WA_ERR_REMOTE_FAILURE:    return "remote call failed";
    case WA_ERR_REMOTE_TIMEOUT:    return "remote call timed out";
    case WA_ERR_TOKEN_EXPIRED:     return "token has expired";
    case WA_ERR_TOKEN_REJECTED:    return "token used in invalid context";
    case WA_ERR_TOKEN_STALE:       return "token is stale";
    case WA_ERR_UNIMPLEMENTED:     return "operation not supported";
    case WA_ERR_FILE_LOCK:         return "error locking file";
    default:
        if (ctx != NULL)
            return apr_psprintf(ctx->pool, "unknown status code %d", s);
        else
            return "unknown status code";
        break;
    }
}


/*
 * Map a WebAuth status code to an error message.  If there's an error message
 * stored in the context and the status code matches the one that's passed in,
 * return that error message.  Otherwise, and if the context is NULL, map the
 * error code to a static error string and return it.
 */
const char *
webauth_error_message(struct webauth_context *ctx, int s)
{
    if (ctx != NULL && ctx->error != NULL && ctx->status == s)
        return ctx->error;
    return error_string(ctx, s);
}


/*
 * Change the saved status code for the current error to a new value, keeping
 * the message.  Return the new status code for convenience.
 */
int
wai_error_change(struct webauth_context *ctx, int old, int s)
{
    if (ctx->status != old)
        return ctx->status;
    ctx->status = s;
    return s;
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
wai_error_context(struct webauth_context *ctx, const char *format, ...)
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
 * Given a WebAuth status code, convert it to a status code that can be used
 * in protocol elements such as error tokens and XML.  Most internal errors
 * will be mapped to WA_PEC_INVALID_REQUEST or WA_PEC_SERVER_FAILURE.
 */
int
wai_error_protocol(struct webauth_context *ctx UNUSED, int s)
{
    if (s < WA_ERR_INTERNAL)
        return s;
    else if (   s == WA_ERR_BAD_HMAC
             || s == WA_ERR_BAD_KEY
             || s == WA_ERR_CORRUPT
             || s == WA_ERR_TOKEN_EXPIRED
             || s == WA_ERR_TOKEN_REJECTED
             || s == WA_ERR_TOKEN_STALE)
        return WA_PEC_INVALID_REQUEST;
    else
        return WA_PEC_SERVER_FAILURE;
}


/*
 * Set the error message and code to the provided values, supporting
 * printf-style formatting.  If format is NULL, that indicates the generic
 * error string is sufficient.  Returns the new error code.  This function is
 * internal to the WebAuth library and is not exposed to external consumers.
 */
int
wai_error_set(struct webauth_context *ctx, int s, const char *format, ...)
{
    va_list args;
    char *string, *message;

    if (format == NULL) {
        ctx->error  = error_string(ctx, s);
        ctx->status = s;
        return s;
    }
    va_start(args, format);
    string = apr_pvsprintf(ctx->pool, format, args);
    va_end(args);
    message = apr_psprintf(ctx->pool, "%s (%s)", error_string(ctx, s), string);
    ctx->error  = message;
    ctx->status = s;
    return s;
}


/*
 * Set the error message and code to the provided values, supporting
 * printf-style formatting and including the string explanation of an APR
 * status.  Returns the new error code.  This function is internal to the
 * WebAuth library and is not exposed to external consumers.
 */
int
wai_error_set_apr(struct webauth_context *ctx, int s, apr_status_t code,
                  const char *format, ...)
{
    va_list args;
    char *string;
    char buf[BUFSIZ];

    if (format == NULL) {
        ctx->error = apr_psprintf(ctx->pool, "%s (%s)", error_string(ctx, s),
                                  apr_strerror(code, buf, sizeof(buf)));
        ctx->status = s;
        return s;
    }
    va_start(args, format);
    string = apr_pvsprintf(ctx->pool, format, args);
    va_end(args);
    ctx->error = apr_psprintf(ctx->pool, "%s (%s: %s)", error_string(ctx, s),
                              string, apr_strerror(code, buf, sizeof(buf)));
    ctx->status = s;
    return s;
}


/*
 * Set the error message and code to the provided values, supporting
 * printf-style formatting and including the string explanation of an errno.
 * Returns the new error code.  This function is internal to the WebAuth
 * library and is not exposed to external consumers.
 */
int
wai_error_set_system(struct webauth_context *ctx, int s, int syserr,
                     const char *format, ...)
{
    va_list args;
    char *string;

    if (format == NULL) {
        ctx->error = apr_psprintf(ctx->pool, "%s (%s)", error_string(ctx, s),
                                  strerror(syserr));
        ctx->status = s;
        return s;
    }
    va_start(args, format);
    string = apr_pvsprintf(ctx->pool, format, args);
    va_end(args);
    ctx->error = apr_psprintf(ctx->pool, "%s (%s: %s)", error_string(ctx, s),
                              string, strerror(syserr));
    ctx->status = s;
    return s;
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
              int s, const char *format, ...)
{
    const char *message;
    char *extra;
    va_list args;

    message = webauth_error_message(ctx, s);
    if (format != NULL) {
        va_start(args, format);
        extra = apr_pvsprintf(ctx->pool, format, args);
        message = apr_pstrcat(ctx->pool, extra, ": ", message, (char *) 0);
        va_end(args);
    }
    log_message(ctx, level, message);
    ctx->error  = NULL;
    ctx->status = 0;
}
