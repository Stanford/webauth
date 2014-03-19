/*
 * Tests for WebAuth error handling functions.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
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

/*
 * A callback for log function testing.  Takes a char ** and stores the
 * message in newly-allocated memory at that address.
 */
static void
log_callback(struct webauth_context *ctx UNUSED, void *data,
             const char *message)
{
    char **buffer = data;

    free(*buffer);
    *buffer = bstrdup(message);
}


/*
 * Test a wai_log_* function.  Takes the enum constant for that log level and
 * a pointer to the function.  Set up a log handler for that log level, call
 * the function and be sure the results are logged appropriately, set an
 * internal error message and test wai_log_error, and then clear the log
 * handler, and then ensure that calling the function again doesn't change the
 * result buffer.
 */
static void
test_wai_log(struct webauth_context *ctx, enum webauth_log_level level,
             void (*log_func)(struct webauth_context *, const char *, ...))
{
    char *output = NULL;

    /* Try logging with a callback. */
    is_int(WA_ERR_NONE,
           webauth_log_callback(ctx, level, log_callback, &output),
           "setting callback for log level %d", level);
    log_func(ctx, "%d", 42);
    is_string("42", output, "log output for level %d", level);
    wai_error_set(ctx, WA_ERR_BAD_HMAC, "test error %d", 42);
    wai_log_error(ctx, level, WA_ERR_BAD_HMAC, NULL);
    is_string("HMAC check failed (test error 42)", output,
              "wai_log_error output for level %d", level);

    /* Now try wai_log_error with extra information. */
    free(output);
    output = NULL;
    wai_error_set(ctx, WA_ERR_BAD_HMAC, "test error %d", 42);
    wai_log_error(ctx, level, WA_ERR_BAD_HMAC, "failure %d", 19);
    is_string("failure 19: HMAC check failed (test error 42)", output,
              "wai_log_error output for level %d", level);

    /* Clear the output and try logging with no callback. */
    free(output);
    output = NULL;
    is_int(WA_ERR_NONE, webauth_log_callback(ctx, level, NULL, NULL),
           "clearing callback for log level %d", level);
    log_func(ctx, "%d", 42);
    is_string(NULL, output, "...and wai_log_* is affected");
    wai_error_set(ctx, WA_ERR_BAD_HMAC, "test error %d", 42);
    wai_log_error(ctx, level, WA_ERR_BAD_HMAC, NULL);
    is_string(NULL, output, "...and wai_log_error is affected");
}


int
main(void)
{
    struct webauth_context *ctx;
    char *expected;
    char *output = NULL;
    char buf[BUFSIZ];

    plan(49);

    if (webauth_context_init(&ctx, NULL) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    /* Check a few error translations with a NULL context. */
    is_string("no error occurred", webauth_error_message(NULL, WA_ERR_NONE),
              "bare error for WA_ERR_NONE");
    is_string("unable to use key", webauth_error_message(NULL, WA_ERR_BAD_KEY),
              "bare error for WA_ERR_BAD_KEY");
    is_string("unknown status code", webauth_error_message(NULL, INT_MAX),
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
    basprintf(&expected, "unknown status code %d", INT_MAX);
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
    basprintf(&expected, "unknown status code %d", INT_MAX);
    is_string(expected, webauth_error_message(ctx, INT_MAX),
              "mismatch with unknown error code");
    free(expected);

    /* Test changing the error. */
    is_int(WA_ERR_RAND_FAILURE,
           wai_error_change(ctx, WA_ERR_BAD_HMAC, WA_ERR_RAND_FAILURE),
           "changing error code returns expected value");
    is_string("HMAC check failed (test error 1)",
              webauth_error_message(ctx, WA_ERR_RAND_FAILURE),
              "error string is still the same");
    is_string("HMAC check failed",
              webauth_error_message(ctx, WA_ERR_BAD_HMAC),
              "webauth_error_message with old code returns generic string");

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
    wai_error_context(ctx, "testing add %s", "context");
    basprintf(&expected, "APR error (foo bar: %s) while testing add context",
              apr_strerror(APR_ENOSTAT, buf, sizeof(buf)));
    is_string(expected, webauth_error_message(ctx, WA_ERR_APR),
              "wai_error_context");
    free(expected);

    /*
     * Test all of the warning functions with no callbacks.  This should do
     * nothing; we're mostly checking that we don't segfault or have memory
     * reads that show up in valgrind.
     */
    wai_log_info(ctx, "%d", 1);
    wai_log_notice(ctx, "%d", 1);
    wai_log_trace(ctx, "%d", 1);
    wai_log_warn(ctx, "%d", 1);
    wai_log_error(ctx, WA_LOG_INFO, WA_ERR_APR, NULL);
    wai_error_set_apr(ctx, WA_ERR_APR, APR_ENOSTAT, "%d", 1);
    wai_log_error(ctx, WA_LOG_NOTICE, WA_ERR_APR, NULL);
    wai_error_set_apr(ctx, WA_ERR_APR, APR_ENOSTAT, "%d", 1);
    wai_log_error(ctx, WA_LOG_TRACE, WA_ERR_APR, NULL);
    wai_error_set_apr(ctx, WA_ERR_APR, APR_ENOSTAT, "%d", 1);
    wai_log_error(ctx, WA_LOG_WARN, WA_ERR_APR, NULL);

    /* Now do some real testing for each log level. */
    test_wai_log(ctx, WA_LOG_INFO, wai_log_info);
    test_wai_log(ctx, WA_LOG_NOTICE, wai_log_notice);
    test_wai_log(ctx, WA_LOG_TRACE, wai_log_trace);
    test_wai_log(ctx, WA_LOG_WARN, wai_log_warn);

    /* Test setting a callback for an unknown log level. */
    is_int(WA_ERR_INVALID,
           webauth_log_callback(ctx, INT_MAX, log_callback, &output),
           "webauth_log_callback with invalid level");

    /* Test wa_log_error to an unknown level. */
    is_int(WA_ERR_NONE,
           webauth_log_callback(ctx, WA_LOG_WARN, log_callback, &output),
           "setting log callback for WA_LOG_WARN");
    wai_error_set(ctx, WA_ERR_BAD_HMAC, "test error %d", 42);
    wai_log_error(ctx, INT_MAX, WA_ERR_BAD_HMAC, NULL);
    basprintf(&expected, "internal error: unknown log level %d (message: %s)",
              INT_MAX, "HMAC check failed (test error 42)");
    is_string(expected, output,
              "wa_log_error with unknown level logged to warn");
    free(expected);
    free(output);

    /* Test a few cases of translation of status codes to protocol codes. */
    is_int(WA_PEC_LOGIN_FAILED, wai_error_protocol(ctx, WA_PEC_LOGIN_FAILED),
           "no translation of a protocol code");
    is_int(WA_PEC_INVALID_REQUEST, wai_error_protocol(ctx, WA_ERR_BAD_HMAC),
           "WA_ERR_BAD_HMAC translates to WA_PEC_INVALID_REQUEST");
    is_int(WA_PEC_SERVER_FAILURE, wai_error_protocol(ctx, WA_ERR_NO_ROOM),
           "WA_ERR_NO_ROOM translates to WA_PEC_SERVER_FAILURE");

    /* Clean up. */
    apr_terminate();
    return 0;
}
