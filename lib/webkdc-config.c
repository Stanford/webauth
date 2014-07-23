/*
 * Interface for configuring the WebKDC portion of the library.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2011, 2013, 2014
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
                      const struct webauth_webkdc_config *conf)
{
    struct webauth_webkdc_config *webkdc;

    /* Verify that the new configuration is sane. */
    if (conf->local_realms == NULL) {
        wai_error_set(ctx, WA_ERR_INVALID, "local realms must be present");
        return WA_ERR_INVALID;
    }
    if (conf->permitted_realms == NULL) {
        wai_error_set(ctx, WA_ERR_INVALID, "permitted realms must be present");
        return WA_ERR_INVALID;
    }

    /* Copy the configuration into the context. */
    webkdc = apr_pcalloc(ctx->pool, sizeof(struct webauth_webkdc_config));
    webkdc->keytab_path      = pstrdup_null(ctx->pool, conf->keytab_path);
    webkdc->id_acl_path      = pstrdup_null(ctx->pool, conf->id_acl_path);
    webkdc->principal        = pstrdup_null(ctx->pool, conf->principal);
    webkdc->proxy_lifetime   = conf->proxy_lifetime;
    webkdc->login_time_limit = conf->login_time_limit;
    webkdc->fast_armor_path  = pstrdup_null(ctx->pool, conf->fast_armor_path);
    webkdc->local_realms     = apr_array_copy(ctx->pool, conf->local_realms);
    webkdc->permitted_realms
        = apr_array_copy(ctx->pool, conf->permitted_realms);
    ctx->webkdc = webkdc;

    /* FIXME: Add more error checking for consistency of configuration. */
    return WA_ERR_NONE;
}
