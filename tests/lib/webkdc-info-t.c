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
#include <portable/system.h>

#include <apr_tables.h>
#include <time.h>

#include <tests/tap/basic.h>
#include <tests/tap/kerberos.h>
#include <tests/tap/remctl.h>
#include <util/concat.h>
#include <webauth/basic.h>
#include <webauth/webkdc.h>


int
main(void)
{
    char *principal, *conf;
    pid_t remctld;
    struct webauth_context *ctx;
    struct webauth_user_config config;
    struct webauth_user_info *info;
    struct webauth_login *login;
    int status;

#ifndef PATH_REMCTLD
    skip_all("remctld not found");
#endif
    if (chdir(getenv("SOURCE")) < 0)
        bail("can't chdir to SOURCE");
    principal = kerberos_setup();
    if (principal == NULL)
        skip_all("Kerberos tests not configured");

    plan(36);

    /* Set up the user metadata service configuration, testing error cases. */
    if (webauth_context_init(&ctx, NULL) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");
    conf = concatpath(getenv("SOURCE"), "data/conf-webkdc");
    remctld = remctld_start(PATH_REMCTLD, principal, conf, NULL);

    memset(&config, 0, sizeof(config));
    status = webauth_user_info(ctx, "test", "127.0.0.1", time(NULL), 0, &info);
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
    status = webauth_user_config(ctx, &config);
    is_int(WA_ERR_NONE, status, "Config with only host and protocol");
    status = webauth_user_info(ctx, "test", "127.0.0.1", time(NULL), 0, &info);
    is_int(WA_ERR_INVALID, status, "remctl info call without command");
    is_string("invalid argument to function (no remctl command specified)",
              webauth_error_message(ctx, status), "...with correct error");
    ok(info == NULL, "...and info is NULL");
    config.port = 14373;
    config.identity = principal;
    config.command = "test";
    status = webauth_user_config(ctx, &config);
    is_int(WA_ERR_NONE, status, "Complete config");

    /* Do a query for a full user. */
    status = webauth_user_info(ctx, "full", "127.0.0.1", time(NULL), 0, &info);
    is_int(WA_ERR_NONE, status, "Metadata for full succeeded");
    ok(info != NULL, "...info is not NULL");
    if (info == NULL) {
        is_string("", webauth_error_message(ctx, status), "...no error");
        ok_block(14, 0, "...info is not NULL");
    } else {
        is_int(1, info->multifactor_required, "...multifactor required");
        is_int(3, info->max_loa, "...max LoA");
        is_int(1310675733, info->password_expires, "...password expires");
        ok(info->factors != NULL, "...factors is not NULL");
        if (info->factors == NULL)
            ok_block(3, 0, "...factors is not NULL");
        else {
            is_int(2, info->factors->nelts, "...two factors");
            is_string("o", APR_ARRAY_IDX(info->factors, 0, char *),
                      "...first is correct");
            is_string("o3", APR_ARRAY_IDX(info->factors, 1, char *),
                      "...second is correct");
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
    status = webauth_user_info(ctx, "mini", "127.0.0.1", time(NULL), 0, &info);
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

    /* Clean up. */
    remctld_stop(remctld);
    kerberos_cleanup();
    return 0;
}
