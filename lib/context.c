/*
 * WebAuth context creation and destruction.
 *
 * Interfaces for creating and destroying the WebAuth context, which holds any
 * state required by the WebAuth APIs.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
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
