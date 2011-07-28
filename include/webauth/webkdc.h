/*
 * WebAuth functions specific to WebKDC services.
 *
 * These interfaces provide the building blocks of the WebKDC functionality.
 * They're normally only used inside the mod_webkdc module, but are provided
 * in the shared library for ease of testing and custom development.
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

#ifndef WEBAUTH_WEBKDC_H
#define WEBAUTH_WEBKDC_H 1

#include <webauth/defines.h>

#include <sys/types.h>

struct webauth_context;

/*
 * Supported protocols for contacting the user metadata and multifactor
 * authentication services.  Currently, only remctl is supported.
 */
enum webauth_user_protocol {
    WA_PROTOCOL_NONE   = 0,
    WA_PROTOCOL_REMCTL = 1
};

/*
 * Configuration information for the user metadata service.  This is used to
 * bundle together the configuration parameters and pass them into
 * webauth_user_config.  The port may be 0, which indicates the standard port
 * should be used.  identity is the identity of the metadata service for
 * authentication purposes and may be NULL to use the default.  command is
 * protocol-specific command information, such as a partial URL or a remctl
 * command.
 */
struct webauth_user_config {
    enum webauth_user_protocol protocol;
    const char *host;
    unsigned short port;        /* May be 0 to use the standard port. */
    const char *identity;       /* Metadata service identity (may be NULL). */
    const char *command;        /* Protocol-specific command. */
};

/*
 * The webauth_userinfo struct and its supporting data structures stores
 * metadata about a user, returned from the site-local user management
 * middleware.
 */
struct webauth_user_info {
    WA_APR_ARRAY_HEADER_T *factors;     /* Array of char * factor codes. */
    int multifactor_required;           /* Whether multifactor is forced. */
    unsigned long max_loa;              /* Maximum level of assurance. */
    time_t password_expires;            /* Password expiration time or 0. */
    WA_APR_ARRAY_HEADER_T *logins;      /* Array of struct webauth_login. */
};

/*
 * Stores a single suspicious or questionable login, or a login that for some
 * other reason the user should be notified about.  Returned in an APR array
 * in the webauth_userinfo struct.
 */
struct webauth_login {
    const char *ip;
    const char *hostname;
    time_t timestamp;
};

BEGIN_DECLS

/*
 * Configure how to access the user metadata service.  Takes the context and
 * the configuration information.  The configuration information is stored in
 * the WebAuth context and used for all subsequent webauth_userinfo queries.
 * Returns a status code, which will be WA_ERR_NONE unless invalid parameters
 * were passed.
 */
int
webauth_user_config(struct webauth_context *ctx, struct webauth_user_config *)
    __attribute__((__nonnull__(1, 2)));

/*
 * Obtain user information for a given user.  The IP address of the user (as a
 * string) is also provided.  The timestamp of the query is assumed to be the
 * current time.  The final flag indicates whether a site requested random
 * multifactor and asks the user metadata service to calculate whether
 * multifactor is forced based on that random multifactor chance.
 *
 * webauth_user_config generally must be called before this function.
 * Depending on the method used, authentication credentials may also need to
 * be set up before calling this function.
 *
 * On success, sets the info parameter to a new webauth_userinfo struct
 * allocated from pool memory and returns WA_ERR_NONE.  On failure, returns an
 * error code and sets the info parameter to NULL.
 */
int
webauth_user_info(struct webauth_context *, const char *user, const char *ip,
                  int, struct webauth_user_info **info)
    __attribute__((__nonnull__));

END_DECLS

#endif /* !WEBAUTH_WEBKDC_H */
