/*
 * WebKDC interface to retrieving user information.
 *
 * These interfaces are used by the WebKDC implementation to retrieve data
 * about a user from the user information service.
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

#ifdef HAVE_JANSSON
# include <jansson.h>
#endif

#include <lib/internal.h>
#include <webauth/basic.h>
#include <webauth/webkdc.h>
#include <util/macros.h>


/*
 * Helper function to apr_pstrdup a string if non-NULL or return NULL if the
 * string is NULL.
 */
static const char *
pstrdup_null(apr_pool_t *pool, const char *string)
{
    if (string == NULL)
        return string;
    else
        return apr_pstrdup(pool, string);
}


/*
 * Configure how to access the user information service.  Takes the method,
 * the host, an optional port (may be 0 to use the default for that method),
 * an optional authentication identity for the remote service (may be NULL to
 * use the default for that method), and a method-specific command parameter
 * such as a remctl command name or a partial URL.  The configuration
 * information is stored in the WebAuth context and used for all subsequent
 * webauth_userinfo queries.
 */
int
webauth_user_config(struct webauth_context *ctx,
                    const struct webauth_user_config *user)
{
    int s = WA_ERR_NONE;

    /* Verify that the new configuration is sane. */
    if (user->protocol != WA_PROTOCOL_REMCTL) {
        s = WA_ERR_UNIMPLEMENTED;
        wai_error_set(ctx, s, "unknown protocol %d", user->protocol);
        goto done;
    }
    if (user->host == NULL) {
        s = WA_ERR_INVALID;
        wai_error_set(ctx, s, "user information host must be set");
        goto done;
    }
    if (user->protocol == WA_PROTOCOL_REMCTL && user->keytab == NULL) {
        s = WA_ERR_INVALID;
        wai_error_set(ctx, s, "keytab must be configured for remctl protocol");
        goto done;
    }

    /* If JSON is requested, verify that we were built with JSON support. */
#ifndef HAVE_JANSSON
    if (user->json) {
        s = WA_ERR_UNIMPLEMENTED;
        wai_error_set(ctx, s, "not built with JSON support");
        goto done;
    }
#endif

    /* Copy the configuration into the context. */
    ctx->user = apr_pcalloc(ctx->pool, sizeof(struct webauth_user_config));
    ctx->user->protocol       = user->protocol;
    ctx->user->host           = apr_pstrdup(ctx->pool, user->host);
    ctx->user->port           = user->port;
    ctx->user->identity       = pstrdup_null(ctx->pool, user->identity);
    ctx->user->command        = pstrdup_null(ctx->pool, user->command);
    ctx->user->keytab         = pstrdup_null(ctx->pool, user->keytab);
    ctx->user->principal      = pstrdup_null(ctx->pool, user->principal);
    ctx->user->timeout        = user->timeout;
    ctx->user->ignore_failure = user->ignore_failure;
    ctx->user->json           = user->json;

done:
    return s;
}


/*
 * Common code to sanity-check the environment for a user information call.
 * On any error, sets the WebAuth error message and returns an error code.
 */
static int
check_config(struct webauth_context *ctx)
{
    int s;

    if (ctx->user == NULL) {
        s = WA_ERR_INVALID;
        wai_error_set(ctx, s, "user information service not configured");
        return s;
    }
    if (ctx->user->command == NULL) {
        s = WA_ERR_INVALID;
        return wai_error_set(ctx, s, "no remctl command specified");
    }
    if (ctx->user->protocol == WA_PROTOCOL_REMCTL) {
        if (ctx->user->keytab == NULL) {
            wai_error_set(ctx, WA_ERR_INVALID,
                          "keytab must be configured for remctl protocol");
            return WA_ERR_INVALID;
        }
#ifndef HAVE_REMCTL
        s = WA_ERR_UNIMPLEMENTED;
        return wai_error_set(ctx, s, "not built with remctl support");
#endif
    } else {
        wai_error_set(ctx, WA_ERR_INVALID, "invalid user info protocol");
        return WA_ERR_INVALID;
    }
#ifndef HAVE_JANSSON
    if (ctx->user->json) {
        s = WA_ERR_UNIMPLEMENTED;
        return wai_error_set(ctx, s, "not built with JSON support");
    }
#endif
    return WA_ERR_NONE;
}


/*
 * Obtain user information for a given user.  The IP address of the user (as a
 * string) is also provided, defaulting to 127.0.0.1.  The final flag
 * indicates whether a site requested random multifactor and asks the user
 * information service to calculate whether multifactor is forced based on
 * that random multifactor chance.
 *
 * On success, sets the info parameter to a new webauth_userinfo struct
 * allocated from pool memory, sets random multifactor if we were asked to
 * attempt it, and returns WA_ERR_NONE.  On failure, returns an error code and
 * sets the info parameter to NULL, unless ignore_failure is set.  If
 * ignore_failure was set and the failure was due to failure to contact the
 * remote service, it instead returns an empty information struct.
 */
int
webauth_user_info(struct webauth_context *ctx, const char *user,
                  const char *ip, int random_mf, const char *url,
                  const char *factors, struct webauth_user_info **info)
{
    int s;

    /* Ensure the output variable is cleared on error. */
    *info = NULL;

    /* Check the configuration for sanity. */
    s = check_config(ctx);
    if (s != WA_ERR_NONE)
        return s;

    /* Call the appropriate implementation for JSON or XML. */
    if (ctx->user->json)
        s = wai_user_info_json(ctx, user, ip, random_mf, url, factors, info);
    else
        s = wai_user_info_xml(ctx, user, ip, random_mf, url, factors, info);

    /* Map a timeout to a general failure for userinfo. */
    if (s == WA_ERR_REMOTE_TIMEOUT)
        s = WA_ERR_REMOTE_FAILURE;

    /*
     * If the call succeeded and random_multifactor was set, say that the
     * random multifactor check passed.  If the call failed but we were told
     * to ignore failures, create a fake return struct.
     */
    if (s == WA_ERR_NONE && random_mf)
        (*info)->random_multifactor = true;
    else if (s == WA_ERR_REMOTE_FAILURE && ctx->user->ignore_failure) {
        wai_log_error(ctx, WA_LOG_WARN, s, "user information service failure");
        s = WA_ERR_NONE;
        *info = apr_pcalloc(ctx->pool, sizeof(struct webauth_user_info));
    }
    return s;
}


/*
 * Validate an authentication code for a given user (generally an OTP code).
 *
 * webauth_user_config must be called before this function.  Depending on the
 * method used, authentication credentials may also need to be set up before
 * calling this function.
 *
 * On success, sets the info parameter to a new webauth_user_info struct
 * allocated from pool memory and returns WA_ERR_NONE.  On failure, returns an
 * error code and sets the info parameter to NULL.  Note that success only
 * means that the call completed, not that the validation was successful.
 */
int
webauth_user_validate(struct webauth_context *ctx, const char *user,
                      const char *ip, const char *code, const char *type,
                      const char *device, const char *state,
                      struct webauth_user_validate **result)
{
    int s;

    /* Ensure the output variable is cleared on error. */
    *result = NULL;

    /* Check the configuration for sanity. */
    s = check_config(ctx);
    if (s != WA_ERR_NONE)
        return s;

    /* Call the appropriate implementation for JSON or XML. */
    if (ctx->user->json)
        s = wai_user_validate_json(ctx, user, ip, code, type, device, state,
                                   result);
    else
        s = wai_user_validate_xml(ctx, user, ip, code, type, state, result);

    /* Map a timeout to a protocol error for validation. */
    if (s == WA_ERR_REMOTE_TIMEOUT)
        s = WA_PEC_LOGIN_TIMEOUT;

    return s;
}
