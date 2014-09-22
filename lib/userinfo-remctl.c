/*
 * Generic user information service remctl call support.
 *
 * Implements generic support for making a remctl call to the user information
 * service and returning the reply in a buffer.
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

#include <errno.h>
#ifdef HAVE_REMCTL
# include <remctl.h>
#endif

#include <lib/internal.h>
#include <webauth/basic.h>
#include <webauth/krb5.h>
#include <webauth/webkdc.h>
#include <util/macros.h>

/* If remctl_set_ccache isn't available, pretend it always fails. */
#ifndef HAVE_REMCTL_SET_CCACHE
# define remctl_set_ccache(r, c) 0
#endif

/* If remctl_set_timeout isn't available, quietly do nothing. */
#ifndef HAVE_REMCTL_SET_TIMEOUT
# define remctl_set_timeout(r, t) /* empty */
#endif


#ifndef HAVE_REMCTL

/*
 * Stub out the call to return an error if not built with remctl support.
 */
int
wai_user_remctl(struct webauth_context *ctx, const char **command UNUSED,
                struct wai_buffer *output UNUSED)
{
    return wai_error_set(ctx, WA_ERR_UNIMPLEMENTED,
                         "not built with remctl support");
}

#else /* HAVE_REMCTL */

/*
 * Issue a remctl command to the user information service.  Takes the
 * argv-style vector of the command to execute and a timeout (which may be 0
 * to use no timeout), and stores the resulting output in the provided
 * argument.  On any error, including remote failure to execute the command,
 * sets the WebAuth error and returns a status code.
 */
int
wai_user_remctl(struct webauth_context *ctx, const char **command,
                struct wai_buffer *output)
{
    struct remctl *r = NULL;
    struct remctl_output *out;
    size_t offset;
    struct wai_buffer *errors, *buffer;
    struct webauth_user_config *c = ctx->user;
    struct webauth_krb5 *kc = NULL;
    char *cache;
    int s;

    /* Initialize the remctl context. */
    r = remctl_new();
    if (r == NULL) {
        s = WA_ERR_NO_MEM;
        return wai_error_set_system(ctx, s, errno, "initializing remctl");
    }

    /*
     * Obtain authentication credentials from the configured keytab and
     * principal.
     *
     * This changes the global GSS-API state to point to our ticket cache.
     * Unfortunately, the GSS-API doesn't currently provide any way to avoid
     * this.  When there is some way, it will be implemented in remctl.
     *
     * If remctl_set_ccache fails or doesn't exist, we fall back on just
     * whacking the global KRB5CCNAME variable.
     */
    s = webauth_krb5_new(ctx, &kc);
    if (s != WA_ERR_NONE)
        goto fail;
    s = webauth_krb5_init_via_keytab(ctx, kc, c->keytab, c->principal, NULL);
    if (s != WA_ERR_NONE)
        goto fail;
    s = webauth_krb5_get_cache(ctx, kc, &cache);
    if (s != WA_ERR_NONE)
        goto fail;
    if (!remctl_set_ccache(r, cache)) {
        if (setenv("KRB5CCNAME", cache, 1) < 0) {
            s = WA_ERR_NO_MEM;
            wai_error_set_system(ctx, s, errno,
                                 "setting KRB5CCNAME for remctl");
            goto fail;
        }
    }

    /* Set a timeout if one was given. */
    if (c->timeout > 0)
        remctl_set_timeout(r, c->timeout);

    /* Set up and execute the command. */
    if (!remctl_open(r, c->host, c->port, c->identity)) {
        if (strstr(remctl_error(r), "timed out") != NULL)
            s = WA_ERR_REMOTE_TIMEOUT;
        else
            s = WA_ERR_REMOTE_FAILURE;
        wai_error_set(ctx, s, "%s", remctl_error(r));
        goto fail;
    }
    if (!remctl_command(r, command)) {
        if (strstr(remctl_error(r), "timed out") != NULL)
            s = WA_ERR_REMOTE_TIMEOUT;
        else
            s = WA_ERR_REMOTE_FAILURE;
        wai_error_set(ctx, s, "%s", remctl_error(r));
        goto fail;
    }

    /*
     * Retrieve the results and accumulate output in the output buffer.
     * Accumulate errors in the errors variable, although we ignore that
     * stream unless the exit status is non-zero.
     */
    errors = wai_buffer_new(ctx->pool);
    do {
        out = remctl_output(r);
        if (out == NULL) {
            if (strstr(remctl_error(r), "timed out") != NULL)
                s = WA_ERR_REMOTE_TIMEOUT;
            else
                s = WA_ERR_REMOTE_FAILURE;
            wai_error_set(ctx, s, "%s", remctl_error(r));
            goto fail;
        }
        switch (out->type) {
        case REMCTL_OUT_OUTPUT:
            buffer = (out->stream == 1) ? output : errors;
            wai_buffer_append(buffer, out->data, out->length);
            break;
        case REMCTL_OUT_ERROR:
            if (strstr(remctl_error(r), "timed out") != NULL)
                s = WA_ERR_REMOTE_TIMEOUT;
            else
                s = WA_ERR_REMOTE_FAILURE;
            wai_buffer_set(errors, out->data, out->length);
            wai_error_set(ctx, s, "%s", errors->data);
            goto fail;
        case REMCTL_OUT_STATUS:
            if (out->status != 0) {
                if (errors->data == NULL)
                    wai_buffer_append_sprintf(errors,
                                              "program exited with status %d",
                                              out->status);
                if (wai_buffer_find_string(errors, "\n", 0, &offset))
                    errors->data[offset] = '\0';
                if (strstr(remctl_error(r), "timed out") != NULL)
                    s = WA_ERR_REMOTE_TIMEOUT;
                else
                    s = WA_ERR_REMOTE_FAILURE;
                wai_error_set(ctx, s, "%s", errors->data);
                goto fail;
            }
        case REMCTL_OUT_DONE:
        default:
            break;
        }
    } while (out->type == REMCTL_OUT_OUTPUT);
    remctl_close(r);
    r = NULL;
    return WA_ERR_NONE;

fail:
    if (r != NULL)
        remctl_close(r);
    return s;
}

#endif /* HAVE_REMCTL */
