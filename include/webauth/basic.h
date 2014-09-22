/*
 * Basic WebAuth API.
 *
 * This interface provides the basic WebAuth context used by all other WebAuth
 * library interfaces and the functions to create and destroy it, basic error
 * handling and error reporting, and the WebAuth error codes.  Any software
 * wanting to use the WebAuth library needs to call webauth_context_init()
 * before any other function and pass the returned context as the first
 * argument to other functions.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2011, 2013, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef WEBAUTH_BASIC_H
#define WEBAUTH_BASIC_H 1

#include <webauth/defines.h>

/* Internal struct used to track WebAuth library state. */
struct webauth_context;

/*
 * webauth_context_init optionally takes an APR pool.  If we have the APR
 * headers included, it's nice to get strong type checking.  But one of the
 * goals of the APR usage in the WebAuth library is for it to be entirely
 * self-contained and transparent to the user.  So we switch to void * if the
 * relevant APR pool header hasn't previously been included.
 */
#ifdef APR_POOLS_H
# define WA_APR_POOL_T apr_pool_t
#else
# define WA_APR_POOL_T void
#endif

/*
 * Many WebAuth functions return an error status, or 0 on success.  For those
 * functions, the error codes are chosen from the following enum.  Additional
 * details about the error are stored in the context, but may be disposed of
 * if another WebAuth function is called before retrieving the error.
 *
 * Use webauth_error_message() to get the corresponding error message and any
 * additional information, if available.
 *
 * These error messages are in two blocks.  WA_ERR_* status codes are used
 * internally in the WebAuth code, and WA_PEC_* status codes are valid in
 * protocol elements (the code attribute of error tokens, the <errorCode>
 * element of an <errorResponse>, and the <loginErrorCode> element of a
 * <requestTokenResponse>).  Most WebAuth functions only return the internal
 * status codes, but webauth_krb5_* calls and webauth_webkdc_login may return
 * either type.
 *
 * The numeric values of the protocol status codes are fixed in the protocol
 * and must not change for interoperability reasons.  The WA_ERR_* status
 * codes are internal to the library API and may change with the API.
 */
enum webauth_status {
    WA_ERR_NONE = 0,

    /* Protocol status codes. */
    WA_PEC_SERVICE_TOKEN_EXPIRED       =  1, /* Past expiration time */
    WA_PEC_SERVICE_TOKEN_INVALID       =  2, /* Can't decrypt / bad format */
    WA_PEC_PROXY_TOKEN_EXPIRED         =  3, /* Past expiration time */
    WA_PEC_PROXY_TOKEN_INVALID         =  4, /* Can't decrypt / bad format */
    WA_PEC_INVALID_REQUEST             =  5, /* Missing/incorrect data, etc */
    WA_PEC_UNAUTHORIZED                =  6, /* Access denied */
    WA_PEC_SERVER_FAILURE              =  7, /* Server failure, try again */
    WA_PEC_REQUEST_TOKEN_STALE         =  8, /* Too old */
    WA_PEC_REQUEST_TOKEN_INVALID       =  9, /* Can't decrypt / bad format */
    WA_PEC_GET_CRED_FAILURE            = 10, /* Can't get credential */
    WA_PEC_REQUESTER_KRB5_CRED_INVALID = 11, /* <requesterCredential> was bad */
    WA_PEC_LOGIN_TOKEN_STALE           = 12, /* Too old */
    WA_PEC_LOGIN_TOKEN_INVALID         = 13, /* Can't decrypt / bad format */
    WA_PEC_LOGIN_FAILED                = 14, /* Username/password failed */
    WA_PEC_PROXY_TOKEN_REQUIRED        = 15, /* Missing required proxy-token */
    WA_PEC_LOGIN_CANCELED              = 16, /* User cancelled login */
    WA_PEC_LOGIN_FORCED                = 17, /* User must re-login */
    WA_PEC_USER_REJECTED               = 18, /* Principal not permitted */
    WA_PEC_CREDS_EXPIRED               = 19, /* User password expired */
    WA_PEC_MULTIFACTOR_REQUIRED        = 20, /* Multifactor login required */
    WA_PEC_MULTIFACTOR_UNAVAILABLE     = 21, /* MF required, not available */
    WA_PEC_LOGIN_REJECTED              = 22, /* User may not log on now */
    WA_PEC_LOA_UNAVAILABLE             = 23, /* Requested LoA not available */
    WA_PEC_AUTH_REJECTED               = 24, /* Auth to this site rejected */
    WA_PEC_AUTH_REPLAY                 = 25, /* Auth was a replay */
    WA_PEC_AUTH_LOCKOUT                = 26, /* Too many failed attempts */
    WA_PEC_LOGIN_TIMEOUT               = 27, /* Timeout during login */

    /* Internal status codes. */
    WA_ERR_INTERNAL = 1000,  /* Internal error */
    WA_ERR_APR,              /* An APR error occurred */
    WA_ERR_BAD_HMAC,         /* HMAC check failed */
    WA_ERR_BAD_KEY,          /* Unable to use key */
    WA_ERR_CORRUPT,          /* Data is incorrectly formatted */
    WA_ERR_FILE_NOT_FOUND,   /* File does not exist */
    WA_ERR_FILE_OPENREAD,    /* Unable to open file for reading */
    WA_ERR_FILE_OPENWRITE,   /* Unable to open file for writing */
    WA_ERR_FILE_READ,        /* Unable to read file file */
    WA_ERR_FILE_VERSION,     /* Bad file data version */
    WA_ERR_FILE_WRITE,       /* Unable to write to file */
    WA_ERR_INVALID,          /* Invalid argument to function */
    WA_ERR_INVALID_CONTEXT,  /* Invalid context passed to function */
    WA_ERR_KRB5,             /* A Kerberos error occured */
    WA_ERR_NOT_FOUND,        /* Item not found while searching */
    WA_ERR_NO_MEM,           /* No memory */
    WA_ERR_NO_ROOM,          /* Supplied buffer too small */
    WA_ERR_RAND_FAILURE,     /* Unable to get random data */
    WA_ERR_REMOTE_FAILURE,   /* A remote service call failed */
    WA_ERR_REMOTE_TIMEOUT,   /* A remote service call timed out */
    WA_ERR_TOKEN_EXPIRED,    /* Token has expired */
    WA_ERR_TOKEN_REJECTED,   /* Token used in invalid context */
    WA_ERR_TOKEN_STALE,      /* Token is stale */
    WA_ERR_UNIMPLEMENTED,    /* Operation not supported */
    WA_ERR_FILE_LOCK,        /* Unable to lock file */

    /* Update webauth_error_message when adding more codes. */
};

/*
 * When setting logging callbacks, this enum identifies the log level for
 * which to set a callback.  The level is akin to syslog levels.
 */
enum webauth_log_level {
    WA_LOG_TRACE,
    WA_LOG_INFO,
    WA_LOG_NOTICE,
    WA_LOG_WARN,
};

/* Data type for a logging callback. */
typedef void (*webauth_log_func)(struct webauth_context *, void *,
                                 const char *);

BEGIN_DECLS

/*
 * Initialize a new WebAuth context.  Takes a pointer to a webauth_context
 * struct as its first argument.  The contents of that struct will be
 * overwritten without freeing, so it does not have to be initialized (but
 * should be freed if being reused).
 *
 * An APR pool may be optionally provided, in which case WebAuth will use a
 * subpool of that pool for all memory allocation.  If the provided pointer is
 * NULL, a new root pool will be created.  If you want control over what
 * function is called on memory allocation failure, provide a pool; otherwise,
 * WebAuth will use the default APR behavior, which is likely to be unfriendly
 * to your application.
 *
 * The initialized context must be freed with webauth_context_free.  Be sure
 * to do this during application shutdown or APR will not be closed properly.
 */
int webauth_context_init(struct webauth_context **, WA_APR_POOL_T *)
    __attribute__((__nonnull__(1)));

/*
 * A variant of of webauth_context_init for APR-aware applications.  The only
 * difference in this function is that it does not call apr_initialize and
 * therefore does not have to be (and should not be) paired with
 * webauth_context_free.  The pool argument is mandatory, and the WebAuth
 * library will use a sub-pool of that pool.
 */
int webauth_context_init_apr(struct webauth_context **, WA_APR_POOL_T *)
    __attribute__((__nonnull__));

/*
 * Free a WebAuth context.  After this call, the contents of the provided
 * webauth_context struct will be invalid and should not be reused without
 * calling webauth_init_context on that struct again.
 *
 * This function must not be called if webauth_context_init_apr was used.
 * Instead, just destroy the parent pool.
 */
void webauth_context_free(struct webauth_context *)
    __attribute__((__nonnull__));

/*
 * Returns the error message for the most recent WebAuth error.  This call
 * should be made before any additional WebAuth call if a WebAuth call fails,
 * or the error message may not be accurate.  The returned string is
 * pool-allocated and should not be modified or freed.
 */
const char *webauth_error_message(struct webauth_context *, int code);

/*
 * Set a logging callback for a particular log level.  The void * data is
 * passed through to the log function when it is called.  callback may be
 * NULL, in which case the callback for that log level is cleared.  Returns
 * a WebAuth error code, but the only error case is an invalid log level.
 *
 * If a callback is set and then later removed or overwritten, the data
 * pointer will be discarded but will not be freed.  The caller is responsible
 * for freeing the data in that situation.
 */
int webauth_log_callback(struct webauth_context *, enum webauth_log_level,
                          webauth_log_func callback, void *data)
    __attribute__((__nonnull__(1)));

END_DECLS

#endif /* !WEBAUTH_BASIC_H */
