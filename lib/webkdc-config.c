/*
 * Interface for configuring the WebKDC portion of the library.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/apr.h>
#include <portable/system.h>

#include <lib/internal.h>
#include <webauth/basic.h>
#include <webauth/webkdc.h>


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
 * Configure the WebKDC services.  Takes the context and the configuration
 * information.  The configuration information is stored in the WebAuth
 * context and is used for all subsequent webauth_webkdc functions.  Returns a
 * status code, which will be WA_ERR_NONE unless invalid parameters were
 * passed.
 */
int
webauth_webkdc_config(struct webauth_context *ctx,
                      const struct webauth_webkdc_config *config)
{
    int s;
    struct webauth_webkdc_config *webkdc;

    /* Verify that the new configuration is sane. */
    if (config->local_realms == NULL) {
        s = WA_ERR_INVALID;
        wai_error_set(ctx, s, "local realms must be present");
        return s;
    }
    if (config->permitted_realms == NULL) {
        s = WA_ERR_INVALID;
        wai_error_set(ctx, s, "permitted realms must be present");
        return s;
    }

    /* Copy the configuration into the context. */
    webkdc = apr_pcalloc(ctx->pool, sizeof(struct webauth_webkdc_config));
    webkdc->keytab_path      = pstrdup_null(ctx->pool, config->keytab_path);
    webkdc->id_acl_path      = pstrdup_null(ctx->pool, config->id_acl_path);
    webkdc->principal        = pstrdup_null(ctx->pool, config->principal);
    webkdc->proxy_lifetime   = config->proxy_lifetime;
    webkdc->login_time_limit = config->login_time_limit;
    webkdc->local_realms     = apr_array_copy(ctx->pool, config->local_realms);
    webkdc->permitted_realms
        = apr_array_copy(ctx->pool, config->permitted_realms);
    ctx->webkdc = webkdc;

    /* FIXME: Add more error checking for consistency of configuration. */
    return WA_ERR_NONE;
}
