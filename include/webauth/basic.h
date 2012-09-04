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
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011
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
 */
enum webauth_status {
    WA_ERR_NONE = 0,         /* No error occured. */
    WA_ERR_NO_ROOM,          /* Supplied buffer too small. */
    WA_ERR_CORRUPT,          /* Data is incorrectly formatted. */
    WA_ERR_NO_MEM,           /* No memory. */
    WA_ERR_BAD_HMAC,         /* HMAC check failed. */
    WA_ERR_RAND_FAILURE,     /* Unable to get random data. */
    WA_ERR_BAD_KEY,          /* Unable to use key. */
    WA_ERR_FILE_OPENWRITE,   /* Unable to open file for writing. */
    WA_ERR_FILE_WRITE,       /* Unable to write to file. */
    WA_ERR_FILE_OPENREAD,    /* Unable to open file for reading. */
    WA_ERR_FILE_READ,        /* Unable to read file file. */
    WA_ERR_FILE_VERSION,     /* Bad file data version. */
    WA_ERR_NOT_FOUND,        /* Item not found while searching. */
    WA_ERR_KRB5,             /* A Kerberos error occured. */
    WA_ERR_INVALID_CONTEXT,  /* Invalid context passed to function. */
    WA_ERR_LOGIN_FAILED,     /* Bad username/password. */
    WA_ERR_TOKEN_EXPIRED,    /* Token has expired. */
    WA_ERR_TOKEN_STALE,      /* Token is stale. */
    WA_ERR_CREDS_EXPIRED,    /* Password has expired. */
    WA_ERR_USER_REJECTED,    /* User not permitted to authenticate. */
    WA_ERR_APR,              /* An APR error occurred. */
    WA_ERR_UNIMPLEMENTED,    /* Operation not supported. */
    WA_ERR_INVALID,          /* Invalid argument to function. */
    WA_ERR_REMOTE_FAILURE,   /* A remote service call failed. */

    /* Update webauth_error_message when adding more codes. */
};

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

END_DECLS

#endif /* !WEBAUTH_BASIC_H */
