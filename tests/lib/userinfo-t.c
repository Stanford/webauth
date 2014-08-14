/*
 * Test user information service retrieval.
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

#include <time.h>

#include <tests/tap/basic.h>
#include <tests/tap/kerberos.h>
#include <tests/tap/remctl.h>
#include <webauth/basic.h>
#include <webauth/factors.h>
#include <webauth/webkdc.h>


/*
 * A callback to test logging of warnings.  Takes a char ** and stores the
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
 * Check a user OTP validation.  Takes the OTP code and a flag indicating
 * whether the validation will be successful or not.  Always attempts with the
 * user "full" and verifies that the standard data is returned if validation
 * was successful.
 */
static void
test_validate(struct webauth_context *ctx, const char *code, bool success)
{
    struct webauth_user_validate *validate;
    int s;

    s = webauth_user_validate(ctx, "full", "127.0.0.1", code, "o1",
                              "DEVICEID", "BQcDAAAAAgoHYUJjRGVGZwAAAAlzZXNzaW"
                              "9uSUQKDVdBUk5fTE9DQVRJT04AAAAFc3RhdGU=",
                              &validate);
    is_int(WA_ERR_NONE, s, "Validate for full succeeded");
    ok(validate != NULL, "...full is not NULL");
    if (validate == NULL) {
        diag("error: %s", webauth_error_message(ctx, s));
        ok_block(9, 0, "Validate failed");
    } else {
        is_int(success, validate->success, "...validation correct");
        is_string(validate->success ? "o,o3" : NULL,
                  webauth_factors_string(ctx, validate->factors),
                  "...result factors are correct");
        is_int(validate->success ? 1893484800 : 0,
               validate->factors_expiration, "...factors expiration");
        is_string(validate->success ? "d,u" : NULL,
                  webauth_factors_string(ctx, validate->persistent),
                  "...persistent factors are correct");
        is_int(validate->success ? 1893484802 : 0,
               validate->persistent_expiration, "...persistent expiration");
        is_int(validate->success ? 1365630519 : 0,
               validate->valid_threshold, "...valid threshold");
        is_int(validate->success ? 3 : 0, validate->loa, "...LoA is correct");
        is_string("<em>OTP3</em> down.  &lt;_&lt;;",
                  validate->user_message, "...user message");
        is_string("RESET_PIN",
                  validate->login_state, "...login state");
    }
}


/*
 * Run a set of tests against the user information service and check the
 * results.  This is broken out into a function so that it can be called
 * twice, once for the XML format and once for the JSON format.
 *
 * Takes the current userinfo configuration so that it can test timeout
 * handling.  Other fields aren't touched.
 */
static void
test_userinfo_calls(struct webauth_context *ctx,
                    struct webauth_user_config *config)
{
    struct webauth_user_info *info;
    struct webauth_user_validate *validate;
    struct webauth_login *login;
    const char url[] = "https://example.com/";
    const char restrict_url[] = "https://example.com/restrict/";
    char *warnings = NULL;
    int s;

    /* Do a query for a full user. */
    s = webauth_user_info(ctx, "full", "127.0.0.1", 0, url, NULL, &info);
    is_int(WA_ERR_NONE, s, "Metadata for full succeeded");
    ok(info != NULL, "...info is not NULL");
    if (info == NULL) {
        is_string("", webauth_error_message(ctx, s), "...no error");
        ok_block(16, 0, "...info is not NULL");
    } else {
        is_int(0, info->random_multifactor, "...random multifactor");
        is_int(3, info->max_loa, "...max LoA");
        is_int(1310675733, info->password_expires, "...password expires");
        is_int(1365630519, info->valid_threshold,
               "...valid threshold is correct");
        is_string("p,m,o,o3", webauth_factors_string(ctx, info->factors),
                  "...factors are correct");
        is_string("p,m,o,o3", webauth_factors_string(ctx, info->required),
                  "...required factors are correct");
        ok(info->additional == NULL, "...additional is NULL");
        ok(info->logins != NULL, "...logins is not NULL");
        if (info->logins == NULL)
            ok_block(7, 0, "...logins is not NULL");
        else {
            is_int(2, info->logins->nelts, "...two logins");
            login = &APR_ARRAY_IDX(info->logins, 0, struct webauth_login);
            is_string("127.0.0.2", login->ip, "...first IP is correct");
            is_string("example.com", login->hostname,
                      "...first hostname is correct");
            is_int(1335373919, login->timestamp,
                   "...first timestamp is correct");
            login = &APR_ARRAY_IDX(info->logins, 1, struct webauth_login);
            is_string("127.0.0.3", login->ip, "...second IP is correct");
            is_string("www.example.com", login->hostname,
                      "...second hostname is correct");
            is_int(0, login->timestamp, "...second timestamp is correct");
        }
        is_string(NULL, info->login_state, "...login state is NULL");
    }

    /* Do a query for a minimal user. */
    s = webauth_user_info(ctx, "mini", NULL, 0, url, NULL, &info);
    is_int(WA_ERR_NONE, s, "Metadata for mini succeeded");
    ok(info != NULL, "...mini is not NULL");
    if (info == NULL) {
        diag("error: %s", webauth_error_message(ctx, s));
        ok_block(10, 0, "Metadata failed");
    } else {
        is_int(0, info->random_multifactor, "...random multifactor");
        is_int(1, info->max_loa, "...max LoA");
        is_int(0, info->password_expires, "...password expires");
        is_int(0, info->valid_threshold, "...valid threshold");
        ok(info->factors == NULL, "...factors is NULL");
        ok(info->required == NULL, "...required is NULL");
        ok(info->additional == NULL, "...additional is NULL");
        ok(info->logins == NULL, "...logins is NULL");
        is_string(NULL, info->user_message, "...user message is NULL");
        is_string(NULL, info->login_state, "...login state is NULL");
    }

    /* The same query, but with random multifactor. */
    s = webauth_user_info(ctx, "mini", NULL, 1, url, NULL, &info);
    is_int(WA_ERR_NONE, s, "Metadata for mini w/random succeeded");
    ok(info != NULL, "...mini is not NULL");
    if (info == NULL) {
        diag("error: %s", webauth_error_message(ctx, s));
        ok_block(9, 0, "Metadata failed");
    } else {
        is_int(1, info->random_multifactor, "...random multifactor");
        is_int(1, info->max_loa, "...max LoA");
        is_int(0, info->password_expires, "...password expires");
        is_int(0, info->valid_threshold, "...valid threshold");
        ok(info->factors == NULL, "...factors is NULL");
        ok(info->required == NULL, "...required is NULL");
        ok(info->additional == NULL, "...additional is NULL");
        ok(info->logins == NULL, "...logins is NULL");
        is_string(NULL, info->login_state, "...login state is NULL");
    }

    /* Query information for factor, without any authentication factors. */
    s = webauth_user_info(ctx, "factor", NULL, 0, url, NULL, &info);
    is_int(WA_ERR_NONE, s, "Metadata for factor succeeded");
    ok(info != NULL, "...factor is not NULL");
    if (info == NULL) {
        diag("error: %s", webauth_error_message(ctx, s));
        ok_block(10, 0, "Metadata failed");
    } else {
        is_int(0, info->random_multifactor, "...random multifactor");
        is_int(1, info->max_loa, "...max LoA");
        is_int(0, info->password_expires, "...password expires");
        is_int(0, info->valid_threshold, "...valid threshold");
        is_string("p,m,o,o2", webauth_factors_string(ctx, info->factors),
                  "...factors are correct");
        is_string("m", webauth_factors_string(ctx, info->required),
                  "...required factors are correct");
        ok(info->additional == NULL, "...additional is NULL");
        ok(info->logins == NULL, "...logins is NULL");
        is_string(NULL, info->user_message, "...user message is NULL");
        is_string(NULL, info->login_state, "...login state is NULL");
    }

    /* Query information for a user with a device factor. */
    s = webauth_user_info(ctx, "factor", NULL, 0, url, "d", &info);
    is_int(WA_ERR_NONE, s, "Metadata for factor with d succeeded");
    ok(info != NULL, "...factor is not NULL");
    if (info == NULL) {
        diag("error: %s", webauth_error_message(ctx, s));
        ok_block(10, 0, "Metadata failed");
    } else {
        is_int(0, info->random_multifactor, "...random multifactor");
        is_int(1, info->max_loa, "...max LoA");
        is_int(0, info->password_expires, "...password expires");
        is_int(0, info->valid_threshold, "...valid threshold");
        is_string("p,m,o,o2", webauth_factors_string(ctx, info->factors),
                  "...factors are correct");
        ok(info->required == NULL, "...required is NULL");
        ok(info->additional == NULL, "...additional is NULL");
        ok(info->logins == NULL, "...logins is NULL");
        is_string(NULL, info->user_message, "...user message is NULL");
        is_string(NULL, info->login_state, "...login state is NULL");
    }

    /* Query information for a user with additional factors. */
    s = webauth_user_info(ctx, "additional", NULL, 0, url, NULL, &info);
    is_int(WA_ERR_NONE, s, "Metadata for additional succeeded");
    ok(info != NULL, "...factor is not NULL");
    if (info == NULL) {
        diag("error: %s", webauth_error_message(ctx, s));
        ok_block(10, 0, "Metadata failed");
    } else {
        is_int(0, info->random_multifactor, "...random multifactor");
        is_int(0, info->max_loa, "...max LoA");
        is_int(0, info->password_expires, "...password expires");
        is_int(0, info->valid_threshold, "...valid threshold");
        is_string("h,m,p,o", webauth_factors_string(ctx, info->factors),
                  "...factors are correct");
        ok(info->required == NULL, "...required is NULL");
        is_string("h", webauth_factors_string(ctx, info->additional),
                  "...additional factors are correct");
        ok(info->logins == NULL, "...logins is NULL");
        is_string(NULL, info->user_message, "...user message is NULL");
        is_string(NULL, info->login_state, "...login state is NULL");
    }

    /* Query information for a user with a user message. */
    s = webauth_user_info(ctx, "message", NULL, 0, url, NULL, &info);
    is_int(WA_ERR_NONE, s, "Metadata for message succeeded");
    ok(info != NULL, "...factor is not NULL");
    if (info == NULL) {
        diag("error: %s", webauth_error_message(ctx, s));
        ok_block(7, 0, "Metadata failed");
    } else {
        is_int(0, info->random_multifactor, "...random multifactor");
        is_int(0, info->max_loa, "...max LoA");
        is_int(0, info->password_expires, "...password expires");
        is_int(0, info->valid_threshold, "...valid threshold");
        is_string("p,m,o,o3", webauth_factors_string(ctx, info->factors),
                  "...factors are correct");
        is_string("o3", webauth_factors_string(ctx, info->required),
                  "...required factors are correct");
        is_string("Hi <strong>you</strong>. &lt;_&lt;;", info->user_message,
                  "...user message is correct");
    }

    /* Query information for a user with a login state. */
    s = webauth_user_info(ctx, "loginstate", NULL, 0, url, NULL, &info);
    is_int(WA_ERR_NONE, s, "Metadata for message succeeded");
    ok(info != NULL, "...factor is not NULL");
    if (info == NULL) {
        diag("error: %s", webauth_error_message(ctx, s));
        ok_block(7, 0, "Metadata failed");
    } else {
        is_int(0, info->random_multifactor, "...random multifactor");
        is_int(0, info->max_loa, "...max LoA");
        is_int(0, info->password_expires, "...password expires");
        is_int(0, info->valid_threshold, "...valid threshold");
        is_string("p,m,o,o3", webauth_factors_string(ctx, info->factors),
                  "...factors are correct");
        is_string("o3", webauth_factors_string(ctx, info->required),
                  "...required factors are correct");
        is_string("BQcDAAAAAgoHYUJjRGVGZwAAAAlzZXNzaW9uSUQKDVdBUk5fTE9DQVRJT0"
                  "4AAAAFc3RhdGU=", info->login_state,
                  "...login state is correct");
    }

    /* Attempt a login for the full user using the wrong code. */
    test_validate(ctx, "654321", false);

    /* Attempt a login for the full user with the correct code. */
    test_validate(ctx, "123456", true);

    /* Attempt a login for a user who doesn't have multifactor configured. */
    s = webauth_user_validate(ctx, "mini", NULL, "123456", "o1", "DEVICEID",
                              "BQcDAAAAAgoHYUJjRGVGZwAAAAlzZXNzaW9uSUQKDV"
                              "dBUk5fTE9DQVRJT04AAAAFc3RhdGU=", &validate);
    is_int(WA_ERR_REMOTE_FAILURE, s, "Validate for invalid user fails");
    is_string("remote call failed (unknown user mini)",
              webauth_error_message(ctx, s), "...with correct error");

    /* Do a query for a user that should time out. */
    config->timeout = 1;
    s = webauth_user_config(ctx, config);
    is_int(WA_ERR_NONE, s, "Config with timeout");
    s = webauth_user_info(ctx, "delay", NULL, 0, url, NULL, &info);
    is_int(WA_ERR_REMOTE_FAILURE, s, "Metadata for delay fails");
    is_string("remote call failed (error receiving token: timed out)",
              webauth_error_message(ctx, s), "...with correct error");

    /* Attempt a login for a user that should time out. */
    s = webauth_user_validate(ctx, "delay", NULL, "123456", "o1", "DEVICEID",
                              "BQcDAAAAAgoHYUJjRGVGZwAAAAlzZXNzaW9uSUQKDV"
                              "dBUk5fTE9DQVRJT04AAAAFc3RhdGU=", &validate);
    is_int(WA_ERR_REMOTE_FAILURE, s, "Validate for delay fails");
    is_string("remote call failed (error receiving token: timed out)",
              webauth_error_message(ctx, s), "...with correct error");

    /* Try the query again with ignore_failure set and capture warnings. */
    webauth_log_callback(ctx, WA_LOG_WARN, log_callback, &warnings);
    config->ignore_failure = true;
    s = webauth_user_config(ctx, config);
    is_int(WA_ERR_NONE, s, "Config with timeout and ignore failure");
    s = webauth_user_info(ctx, "delay", NULL, 0, url, NULL, &info);
    is_int(WA_ERR_NONE, s, "Metadata for delay now succeeds");
    if (info == NULL) {
        diag("error: %s", webauth_error_message(ctx, s));
        ok_block(7, 0, "Metadata failed");
    } else {
        is_int(0, info->random_multifactor, "...random multifactor");
        is_int(0, info->max_loa, "...max LoA");
        is_int(0, info->password_expires, "...password expires");
        is_int(0, info->valid_threshold, "...valid threshold");
        ok(info->factors == NULL, "...factors is NULL");
        ok(info->required == NULL, "...required is NULL");
        ok(info->logins == NULL, "...logins is NULL");
    }
    is_string("user information service failure: remote call failed"
              " (error receiving token: timed out)", warnings,
              "...and logged warning is correct");

    /* Try the query again with ignore_failure and random multifactor. */
    is_int(WA_ERR_NONE, s, "Config with timeout, ignore, random");
    s = webauth_user_info(ctx, "delay", NULL, 1, url, NULL, &info);
    is_int(WA_ERR_NONE, s, "Metadata for delay w/random succeeds");
    if (info == NULL) {
        diag("error: %s", webauth_error_message(ctx, s));
        ok_block(6, 0, "Metadata failed");
    } else {
        is_int(0, info->random_multifactor, "...random multifactor");
        is_int(0, info->max_loa, "...max LoA");
        is_int(0, info->password_expires, "...password expires");
        is_int(0, info->valid_threshold, "...valid threshold");
        ok(info->factors == NULL, "...factors is NULL");
        ok(info->required == NULL, "...required is NULL");
        ok(info->logins == NULL, "...logins is NULL");
    }
    is_string("user information service failure: remote call failed"
              " (error receiving token: timed out)", warnings,
              "...and logged warning is correct");

    /* Attempt a login again, which should still fail. */
    free(warnings);
    warnings = NULL;
    s = webauth_user_validate(ctx, "delay", NULL, "123456", "o1", NULL,
                              "BQcDAAAAAgoHYUJjRGVGZwAAAAlzZXNzaW9uSUQKDV"
                              "dBUk5fTE9DQVRJT04AAAAFc3RhdGU=", &validate);
    is_int(WA_ERR_REMOTE_FAILURE, s, "Validate for delay fails");
    is_string("remote call failed (error receiving token: timed out)",
              webauth_error_message(ctx, s), "...with correct error");
    is_string(NULL, warnings, "...and there are no warnings");

    /* Attempt a login to a restricted site.  This should return an error. */
    config->ignore_failure = false;
    config->timeout = 0;
    s = webauth_user_config(ctx, config);
    is_int(WA_ERR_NONE, s, "Config back to normal");
    s = webauth_user_info(ctx, "normal", NULL, 0, restrict_url, NULL, &info);
    is_int(WA_ERR_NONE, s, "Metadata for restricted URL succeeds");
    if (info == NULL) {
        diag("error: %s", webauth_error_message(ctx, s));
        ok_block(7, 0, "Metadata failed");
    } else {
        is_string("<strong>You are restricted!</strong>  &lt;_&lt;;",
                  info->error, "...error string");
        is_int(0, info->random_multifactor, "...random multifactor");
        is_int(0, info->max_loa, "...max LoA");
        is_int(0, info->password_expires, "...password expires");
        is_int(0, info->valid_threshold, "...valid threshold");
        ok(info->factors == NULL, "...factors is NULL");
        ok(info->required == NULL, "...required is NULL");
        ok(info->logins == NULL, "...logins is NULL");
    }
    is_string(NULL, warnings, "...and there are no warnings");
}


int
main(void)
{
    struct kerberos_config *krbconf;
    struct webauth_context *ctx;
    struct webauth_user_config config;
    struct webauth_user_info *info;
    const char url[] = "https://example.com/";
    int s;

    /* Skip this test if built without remctl support. */
#ifndef HAVE_REMCTL
    skip_all("built without remctl support");
#endif

    /* Load test configuration and start remctl. */
    krbconf = kerberos_setup(TAP_KRB_NEEDS_KEYTAB);
    remctld_start(krbconf, "data/conf-webkdc", (char *) 0);
    if (webauth_context_init(&ctx, NULL) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    plan(15 + 158 * 2);

    /* Empty the KRB5CCNAME environment variable and make the library cope. */
    putenv((char *) "KRB5CCNAME=");

    /*
     * Set up the user information service configuration, testing error cases.
     */
    memset(&config, 0, sizeof(config));
    s = webauth_user_info(ctx, "test", "127.0.0.1", 0, url, NULL, &info);
    is_int(WA_ERR_INVALID, s, "Info without configuration");
    is_string("invalid argument to function (user information service not"
              " configured)", webauth_error_message(ctx, s),
              "...with correct error");
    ok(info == NULL, "...and info is NULL");
    s = webauth_user_config(ctx, &config);
    is_int(WA_ERR_UNIMPLEMENTED, s, "Config with bad protocol");
    is_string("operation not supported (unknown protocol 0)",
              webauth_error_message(ctx, s), "...with correct error");
    config.protocol = WA_PROTOCOL_REMCTL;
    s = webauth_user_config(ctx, &config);
    is_int(WA_ERR_INVALID, s, "Config without host");
    is_string("invalid argument to function (user information host must be"
              " set)",
              webauth_error_message(ctx, s), "...with correct error");
    config.host = "localhost";
    config.port = 14373;
    config.identity = krbconf->principal;
    s = webauth_user_config(ctx, &config);
    is_int(WA_ERR_INVALID, s, "remctl config without keytab");
    is_string("invalid argument to function (keytab must be configured for"
              " remctl protocol)", webauth_error_message(ctx, s),
              "...with correct error");
    config.keytab = krbconf->keytab;
    config.principal = krbconf->principal;
    s = webauth_user_config(ctx, &config);
    is_int(WA_ERR_NONE, s, "Config with only host and protocol");
    s = webauth_user_info(ctx, "test", "127.0.0.1", 0, url, NULL, &info);
    is_int(WA_ERR_INVALID, s, "remctl info call without command");
    is_string("invalid argument to function (no remctl command specified)",
              webauth_error_message(ctx, s), "...with correct error");
    ok(info == NULL, "...and info is NULL");
    config.command = "test";
    s = webauth_user_config(ctx, &config);
    is_int(WA_ERR_NONE, s, "Complete config");

    /* Now, query the user information service for a bunch of cases. */
    test_userinfo_calls(ctx, &config);

    /* Run the tests again, but use the JSON configuration. */
#ifdef HAVE_JANSSON
    config.command = "test-json";
    config.json = true;
    s = webauth_user_config(ctx, &config);
    is_int(WA_ERR_NONE, s, "Configuration with JSON");
    test_userinfo_calls(ctx, &config);
#else
    skip_block(159, "not built with JSON support");
#endif

    /* Clean up. */
    webauth_context_free(ctx);
    return 0;
}
