/*
 * Test basic WebKDC login support without Kerberos.
 *
 * Perform the tests possible on the WebKDC login functionality without any
 * Kerberos test configuration.  This ensures we do some basic functionality
 * tests even if no Kerberos configuration is provided.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011, 2012, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/apr.h>
#include <portable/system.h>

#include <time.h>

#include <tests/tap/basic.h>
#include <tests/tap/webauth.h>
#include <webauth/basic.h>
#include <webauth/keys.h>
#include <webauth/tokens.h>
#include <webauth/webkdc.h>

/* Test cases to run without an identity file. */
static const struct wat_login_test tests_login[] = {

    /* Attempt login with no authentication. */
    {
        "No authentication",
        0,
        NULL,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            NO_TOKENS_WKPROXY,
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            },
            NO_CONNECTION_DATA
        },
        {
            WA_PEC_PROXY_TOKEN_REQUIRED,
            "need a proxy token",
            NULL,
            NO_FACTOR_DATA,
            NO_TOKENS_WKPROXY,
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        },
    },

    /* The same, but with a login cancel token. */
    {
        "No authentication and login cancel",
        0,
        NULL,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            NO_TOKENS_WKPROXY,
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", "lc",
                NULL, NULL, 0, NULL, 0
            },
            NO_CONNECTION_DATA
        },
        {
            WA_PEC_PROXY_TOKEN_REQUIRED,
            "need a proxy token",
            NULL,
            NO_FACTOR_DATA,
            NO_TOKENS_WKPROXY,
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        },
    },

    /* Pass in a webkdc-proxy token and obtain an id token. */
    {
        "webkdc-proxy authentication",
        0,
        NULL,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 1365725079, 1938063600, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, "data", 4, "https://example.com/", "lc",
                NULL, NULL, 0, NULL, 0
            },
            NO_CONNECTION_DATA
        },
        {
            LOGIN_SUCCESS,
            NO_FACTOR_DATA,
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 1365725079, 1938063600, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            {
                "testuser", NULL, "webkdc", NULL, 0, "x,x1", NULL, 3,
                0, 1938063600
            },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        },
    },

    /* The same, but also add a webkdc-factor token. */
    {
        "webkdc-proxy and webkdc-factor authentication",
        0,
        NULL,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 1365725079, 1938063600, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            {
                { "testuser", "d", 0, 1906527600 },
                EMPTY_TOKEN_WKFACTOR,
                EMPTY_TOKEN_WKFACTOR
            },
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", "lc",
                NULL, NULL, 0, NULL, 0
            },
            NO_CONNECTION_DATA
        },
        {
            LOGIN_SUCCESS,
            NO_FACTOR_DATA,
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1,d", 3, 1365725079, 1938063600, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            { "testuser", "d", 0, 1906527600 },
            {
                "testuser", NULL, "webkdc", NULL, 0, "x,x1,d", "d", 3,
                0, 1938063600
            },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        },
    },

    /* Forced login with a proxy token should fail. */
    {
        "Forced login with webkdc-proxy token",
        0,
        NULL,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 10, 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", "fa",
                NULL, NULL, 0, NULL, 0
            },
            NO_CONNECTION_DATA
        },
        {
            WA_PEC_LOGIN_FORCED,
            "forced authentication, need to login",
            NULL,
            NO_FACTOR_DATA,
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 10, 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        },
    },

    /* A proxy token request with a webkdc-proxy token should fail. */
    {
        "Proxy token request with webkdc-proxy token",
        0,
        NULL,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 1365725079, 1938063600, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "proxy", NULL, "krb5", NULL, 0, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            },
            NO_CONNECTION_DATA
        },
        {
            WA_PEC_PROXY_TOKEN_REQUIRED,
            "need a proxy token",
            NULL,
            NO_FACTOR_DATA,
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 1365725079, 1938063600, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        },
    }
};

/* Test cases to run with a login timeout of 15 minutes. */
static const struct wat_login_test tests_time_limit[] = {

    /* Forced login should succeed with a fresh webkdc-proxy token. */
    {
        "Forced login within login timeout",
        0,
        NULL,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 10, 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", "fa",
                NULL, NULL, 0, NULL, 0
            },
            NO_CONNECTION_DATA
        },
        {
            LOGIN_SUCCESS,
            NO_FACTOR_DATA,
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 10, 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            {
                "testuser", NULL, "webkdc", NULL, 0, "x,x1", "x,x1", 3,
                0, 60
            },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        },
    },
};

/* Test cases to run with an identity file. */
static const struct wat_login_test tests_id_acl[] = {

    /* Don't attempt to assert an identity. */
    {
        "Proxy authentication with identity ACL",
        0,
        NULL,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 1365725079, 1938063600, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            },
            NO_CONNECTION_DATA
        },
        {
            LOGIN_SUCCESS,
            NO_FACTOR_DATA,
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 1365725079, 1938063600, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            {
                "testuser", NULL, "webkdc", NULL, 0, "x,x1", NULL, 3,
                0, 1938063600
            },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            { "otheruser", "bar", NULL }
        },
    },

    /* Now assert an authorization identity. */
    {
        "Proxy authentication with authorization identity",
        0,
        NULL,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 1365725079, 1938063600, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            "otheruser",
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            },
            NO_CONNECTION_DATA
        },
        {
            LOGIN_SUCCESS,
            NO_FACTOR_DATA,
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 1365725079, 1938063600, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            {
                "testuser", "otheruser", "webkdc", NULL, 0, "x,x1", NULL, 3,
                0, 1938063600
            },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            { "otheruser", "bar", NULL }
        },
    },

    /* Assert an identity we're not allowed to assert. */
    {
        "Unauthorized authorization identity",
        0,
        NULL,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 1365725079, 1938063600, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            "foo",
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", "lc",
                NULL, NULL, 0, NULL, 0
            },
            NO_CONNECTION_DATA
        },
        {
            WA_PEC_UNAUTHORIZED,
            "not authorized to assert that identity",
            NULL,
            NO_FACTOR_DATA,
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 1365725079, 1938063600, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            { "otheruser", "bar", NULL }
        },
    },

    /* Assert the same identity as the subject. */
    {
        "Authorization identity matching subject",
        0,
        NULL,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            NO_TOKENS_LOGIN,
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 1365725079, 1938063600, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            "testuser",
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            },
            NO_CONNECTION_DATA
        },
        {
            LOGIN_SUCCESS,
            NO_FACTOR_DATA,
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 1365725079, 1938063600, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            {
                "testuser", NULL, "webkdc", NULL, 0, "x,x1", NULL, 3,
                0, 1938063600
            },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            { "otheruser", "bar", NULL }
        },
    }
};


int
main(void)
{
    apr_pool_t *pool = NULL;
    struct webauth_context *ctx;
    struct webauth_keyring *ring;
    struct webauth_webkdc_config config;
    size_t i;
    int status;
    char *keyring;

    /* Use lazy planning so that test counts can vary on some errors. */
    plan_lazy();

    /* Initialize APR and WebAuth. */
    if (apr_initialize() != APR_SUCCESS)
        bail("cannot initialize APR");
    if (apr_pool_create(&pool, NULL) != APR_SUCCESS)
        bail("cannot create memory pool");
    if (webauth_context_init_apr(&ctx, pool) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    /* Load the precreated keyring that we'll use for token encryption. */
    keyring = test_file_path("data/keyring");
    status = webauth_keyring_read(ctx, keyring, &ring);
    if (status != WA_ERR_NONE)
        bail("cannot read %s: %s", keyring,
             webauth_error_message(ctx, status));
    test_file_path_free(keyring);

    /* Provide basic configuration to the WebKDC code. */
    memset(&config, 0, sizeof(config));
    config.local_realms = apr_array_make(pool, 0, sizeof(const char *));
    config.permitted_realms = apr_array_make(pool, 0, sizeof(const char *));
    status = webauth_webkdc_config(ctx, &config);
    if (status != WA_ERR_NONE)
        diag("configuration failed: %s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status, "WebKDC configuration succeeded");

    /* Run the first set of tests. */
    for (i = 0; i < ARRAY_SIZE(tests_login); i++)
        run_login_test(ctx, &tests_login[i], ring);

    /*
     * Set a login time limit of 15 minutes.  Since the webkdc-proxy tokens
     * are dated 10 minutes ago, this will make them considered fresh.
     */
    config.login_time_limit = 15 * 60;
    status = webauth_webkdc_config(ctx, &config);
    if (status != WA_ERR_NONE)
        diag("configuration failed: %s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status, "Setting login timeout succeeded");

    /* Run the batch of tests requiring the login timeout setting. */
    for (i = 0; i < ARRAY_SIZE(tests_time_limit); i++)
        run_login_test(ctx, &tests_time_limit[i], ring);

    /* Set up an identity ACL (and clear the login time limit). */
    config.id_acl_path = test_file_path("data/id.acl");
    config.login_time_limit = 0;
    status = webauth_webkdc_config(ctx, &config);
    if (status != WA_ERR_NONE)
        diag("configuration failed: %s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status, "Identity ACL configuration succeeded");

    /* Run the batch of tests requiring an identity ACL. */
    for (i = 0; i < ARRAY_SIZE(tests_id_acl); i++)
        run_login_test(ctx, &tests_id_acl[i], ring);

    /* Clean up. */
    apr_terminate();
    test_file_path_free((char *) config.id_acl_path);
    return 0;
}
