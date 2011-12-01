/*
 * Test WebKDC user metadata retrieval.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011
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
#include <util/concat.h>
#include <webauth/basic.h>
#include <webauth/webkdc.h>


/*
 * Check a user OTP validation.  Takes the OTP code and a flag indicating
 * whether the validation will be successful or not.  Always attempts with the
 * user "full" and verifies that the standard data is returned.
 */
static void
test_validate(struct webauth_context *ctx, const char *code, bool success)
{
    struct webauth_user_validate *validate;
    int status;

    status = webauth_user_validate(ctx, "full", "127.0.0.1", code, &validate);
    is_int(WA_ERR_NONE, status, "Validate for full succeeded");
    ok(validate != NULL, "...full is not NULL");
    if (validate == NULL)
        ok_block(6, 0, "Validate failed");
    else {
        is_int(success, validate->success, "...validation correct");
        ok(validate->factors != NULL, "...factors is not NULL");
        if (validate->factors == NULL)
            ok_block(3, 0, "...factors is not NULL");
        else {
            is_int(2, validate->factors->nelts, "...two factors");
            is_string("o", APR_ARRAY_IDX(validate->factors, 0, char *),
                      "...first is correct");
            is_string("o3", APR_ARRAY_IDX(validate->factors, 1, char *),
                      "...second is correct");
        }
        is_int(3, validate->loa, "...LoA is correct");
    }        
}    


int
main(void)
{
    const char *principal;
    char *keytab, *conf;
    pid_t remctld;
    struct webauth_context *ctx;
    struct webauth_user_config config;
    struct webauth_user_info *info;
    struct webauth_user_validate *validate;
    struct webauth_login *login;
    int status;

#ifndef HAVE_REMCTL
    skip_all("built without remctl support");
#endif
#ifndef PATH_REMCTLD
    skip_all("remctld not found");
#endif
    if (chdir(getenv("SOURCE")) < 0)
        bail("can't chdir to SOURCE");
    principal = kerberos_setup();
    if (principal == NULL)
        skip_all("Kerberos tests not configured");
    keytab = test_file_path("data/test.keytab");
    if (keytab == NULL)
        skip_all("Kerberos tests not configured");

    plan(58);

    /* Set up the user metadata service configuration, testing error cases. */
    if (webauth_context_init(&ctx, NULL) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");
    conf = concatpath(getenv("SOURCE"), "data/conf-webkdc");
    remctld = remctld_start(PATH_REMCTLD, principal, conf, NULL);

    /* Empty the KRB5CCNAME environment variable and make the library cope. */
    putenv((char *) "KRB5CCNAME=");

    memset(&config, 0, sizeof(config));
    status = webauth_user_info(ctx, "test", "127.0.0.1", 0, &info);
    is_int(WA_ERR_INVALID, status, "Info without configuration");
    is_string("invalid argument to function (user metadata service not"
              " configured)", webauth_error_message(ctx, status),
              "...with correct error");
    ok(info == NULL, "...and info is NULL");
    status = webauth_user_config(ctx, &config);
    is_int(WA_ERR_UNIMPLEMENTED, status, "Config with bad protocol");
    is_string("operation not supported (unknown protocol 0)",
              webauth_error_message(ctx, status), "...with correct error");
    config.protocol = WA_PROTOCOL_REMCTL;
    status = webauth_user_config(ctx, &config);
    is_int(WA_ERR_INVALID, status, "Config without host");
    is_string("invalid argument to function (user metadata host must be set)",
              webauth_error_message(ctx, status), "...with correct error");
    config.host = "localhost";
    config.port = 14373;
    config.identity = principal;
    status = webauth_user_config(ctx, &config);
    is_int(WA_ERR_INVALID, status, "remctl config without keytab");
    is_string("invalid argument to function (keytab must be configured for"
              " remctl protocol)", webauth_error_message(ctx, status),
              "...with correct error");
    config.keytab = keytab;
    config.principal = principal;
    status = webauth_user_config(ctx, &config);
    is_int(WA_ERR_NONE, status, "Config with only host and protocol");
    status = webauth_user_info(ctx, "test", "127.0.0.1", 0, &info);
    is_int(WA_ERR_INVALID, status, "remctl info call without command");
    is_string("invalid argument to function (no remctl command specified)",
              webauth_error_message(ctx, status), "...with correct error");
    ok(info == NULL, "...and info is NULL");
    config.command = "test";
    status = webauth_user_config(ctx, &config);
    is_int(WA_ERR_NONE, status, "Complete config");

    /* Do a query for a full user. */
    status = webauth_user_info(ctx, "full", "127.0.0.1", 0, &info);
    is_int(WA_ERR_NONE, status, "Metadata for full succeeded");
    ok(info != NULL, "...info is not NULL");
    if (info == NULL) {
        is_string("", webauth_error_message(ctx, status), "...no error");
        ok_block(16, 0, "...info is not NULL");
    } else {
        is_int(1, info->multifactor_required, "...multifactor required");
        is_int(3, info->max_loa, "...max LoA");
        is_int(1310675733, info->password_expires, "...password expires");
        ok(info->factors != NULL, "...factors is not NULL");
        if (info->factors == NULL)
            ok_block(5, 0, "...factors is not NULL");
        else {
            is_int(4, info->factors->nelts, "...five factors");
            is_string("p", APR_ARRAY_IDX(info->factors, 0, char *),
                      "...first is correct");
            is_string("m", APR_ARRAY_IDX(info->factors, 1, char *),
                      "...second is correct");
            is_string("o", APR_ARRAY_IDX(info->factors, 2, char *),
                      "...third is correct");
            is_string("o3", APR_ARRAY_IDX(info->factors, 3, char *),
                      "...fourth is correct");
        }
        ok(info->logins != NULL, "...logins is not NULL");
        if (info->logins == NULL)
            ok_block(7, 0, "...logins is not NULL");
        else {
            is_int(2, info->logins->nelts, "...two logins");
            login = &APR_ARRAY_IDX(info->logins, 0, struct webauth_login);
            is_string("127.0.0.2", login->ip, "...first IP is correct");
            is_string("example.com", login->hostname,
                      "...first hostname is correct");
            is_int(0, login->timestamp, "...first timestamp is correct");
            login = &APR_ARRAY_IDX(info->logins, 1, struct webauth_login);
            is_string("127.0.0.3", login->ip, "...second IP is correct");
            is_string("www.example.com", login->hostname,
                      "...second hostname is correct");
            is_int(0, login->timestamp, "...second timestamp is correct");
        }
    }

    /* Do a query for a minimal user. */
    status = webauth_user_info(ctx, "mini", NULL, 0, &info);
    is_int(WA_ERR_NONE, status, "Metadata for mini succeeded");
    ok(info != NULL, "...mini is not NULL");
    if (info == NULL)
        ok_block(5, 0, "Metadata failed");
    else {
        is_int(0, info->multifactor_required, "...multifactor required");
        is_int(1, info->max_loa, "...max LoA");
        is_int(0, info->password_expires, "...password expires");
        ok(info->factors == NULL, "...factors is NULL");
        ok(info->logins == NULL, "...logins is NULL");
    }

    /* Attempt a login for the full user using the wrong code. */
    test_validate(ctx, "654321", false);

    /* Attempt a login for the full user with the correct code. */
    test_validate(ctx, "123456", true);

    /* Attempt a login for a user who doesn't have multifactor configured. */
    status = webauth_user_validate(ctx, "mini", NULL, "123456", &validate);
    is_int(status, WA_ERR_REMOTE_FAILURE, "Validate for invalid user fails");
    is_string("a remote service call failed (unknown user mini)",
              webauth_error_message(ctx, status), "...with correct error");

    /* Clean up. */
    remctld_stop(remctld);
    return 0;
}
