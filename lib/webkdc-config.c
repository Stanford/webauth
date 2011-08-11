/*
 * Interface for configuring the WebKDC portion of the library.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <lib/internal.h>
#include <webauth/basic.h>
#include <webauth/webkdc.h>


/*
 * Configure the WebKDC services.  Takes the context and the configuration
 * information.  The configuration information is stored in the WebAuth
 * context and is used for all subsequent webauth_webkdc functions.  Returns a
 * status code, which will be WA_ERR_NONE unless invalid parameters were
 * passed.
 */
int
webauth_webkdc_config(struct webauth_context *ctx,
                      struct webauth_webkdc_config *config)
{
    int status;

    if (config->local_realms == NULL) {
        status = WA_ERR_INVALID;
        webauth_error_set(ctx, status, "local realms must be present");
        return status;
    }
    if (config->permitted_realms == NULL) {
        status = WA_ERR_INVALID;
        webauth_error_set(ctx, status, "permitted realms must be present");
        return status;
    }
    ctx->webkdc = config;

    /* FIXME: Add more error checking for consistency of configuration. */
    return WA_ERR_NONE;
}
