/*
 * Tests for WebAuth context management functions.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <apr_errno.h>
#include <errno.h>
#include <limits.h>

#include <lib/internal.h>
#include <tests/tap/basic.h>
#include <tests/tap/string.h>
#include <webauth/basic.h>


int
main(void)
{
    struct webauth_context *ctx;
    char *expected;
    char buf[BUFSIZ];

    plan(12);

    if (webauth_context_init(&ctx, NULL) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    /* Check a few error translations with a NULL context. */
    is_string("no error occurred", webauth_error_message(NULL, WA_ERR_NONE),
              "bare error for WA_ERR_NONE");
    is_string("unable to use key", webauth_error_message(NULL, WA_ERR_BAD_KEY),
              "bare error for WA_ERR_BAD_KEY");
    is_string("unknown error code", webauth_error_message(NULL, INT_MAX),
              "bare error for INT_MAX");

    /*
     * The same, but with a valid context.  The error will be NULL, so we'll
     * get the same generic translation, but with a better error message for
     * the unknown code.
     */
    is_string("no error occurred", webauth_error_message(ctx, WA_ERR_NONE),
              "unset error for WA_ERR_NONE");
    is_string("unable to use key", webauth_error_message(ctx, WA_ERR_BAD_KEY),
              "unset error for WA_ERR_BAD_KEY");
    basprintf(&expected, "unknown error code %d", INT_MAX);
    is_string(expected, webauth_error_message(ctx, INT_MAX),
              "unset error for INT_MAX");
    free(expected);

    /* Set an error and make sure we get the expected message back. */
    wai_error_set(ctx, WA_ERR_BAD_HMAC, "test error %d", 1);
    is_string("HMAC check failed (test error 1)",
              webauth_error_message(ctx, WA_ERR_BAD_HMAC),
              "set error for WA_ERR_BAD_HMAC");

    /* If we try to get some other error, we'll get the bare string. */
    is_string("unable to get random data",
              webauth_error_message(ctx, WA_ERR_RAND_FAILURE),
              "mismatch of error and code");
    basprintf(&expected, "unknown error code %d", INT_MAX);
    is_string(expected, webauth_error_message(ctx, INT_MAX),
              "mismatch with unknown error code");
    free(expected);

    /* Set an error from errno. */
    wai_error_set_system(ctx, WA_ERR_NOT_FOUND, ENOMEM, "error %d", 2);
    basprintf(&expected, "item not found while searching (error 2: %s)",
              strerror(ENOMEM));
    is_string(expected, webauth_error_message(ctx, WA_ERR_NOT_FOUND),
              "wai_error_set_system");
    free(expected);

    /* Set an error from APR. */
    wai_error_set_apr(ctx, WA_ERR_APR, APR_ENOSTAT, "foo %s", "bar");
    basprintf(&expected, "APR error (foo bar: %s)",
              apr_strerror(APR_ENOSTAT, buf, sizeof(buf)));
    is_string(expected, webauth_error_message(ctx, WA_ERR_APR),
              "wai_error_set_apr");
    free(expected);

    /* Add additional context to an existing error message. */
    wai_error_add_context(ctx, "testing add %s", "context");
    basprintf(&expected, "APR error (foo bar: %s) while testing add context",
              apr_strerror(APR_ENOSTAT, buf, sizeof(buf)));
    is_string(expected, webauth_error_message(ctx, WA_ERR_APR),
              "wai_error_add_context");
    free(expected);

    /* Clean up. */
    apr_terminate();
    return 0;
}
