/*
 * Test WebKDC login support with Kerberos.
 *
 * Perform the full set of WebKDC login tests that we can perform with a
 * keytab, username, and password.  This does not include the multifactor or
 * user information tests.
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
#include <tests/tap/string.h>
#include <tests/tap/webauth.h>
#include <webauth/basic.h>
#include <webauth/keys.h>
#include <webauth/krb5.h>
#include <webauth/webkdc.h>

/* Test cases to run without any local realms. */
static const struct wat_login_test tests_no_local[] = {

    /* Basic test for obtaining an id token with a username and password. */
    {
        "Login with password",
        LOGIN_SUCCESS,
        {
            { "<krb5-principal>", 0, 0 },
            {
                { "<userprinc>", "<password>", NULL, NULL, NULL, 0 },
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            NO_TOKENS_WKPROXY,
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, "data", 4, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "<userprinc>", "krb5", "<webkdc-principal>", NULL, 0,
                    "p", 0, 0, 0, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            { "<userprinc>", NULL, "webkdc", NULL, 0, "p", "p", 0, 0, 0 },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        },
    },

    /* Basic test for login failure with a valid username and bad password. */
    {
        "Login with incorrect password",
        WA_PEC_LOGIN_FAILED,
        "Kerberos error",
        {
            { "<krb5-principal>", 0, 0 },
            {
                { "<userprinc>", "BAD<password>", NULL, NULL, NULL, 0 },
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            NO_TOKENS_WKPROXY,
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, "data", 4, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
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

    /*
     * The same, but with forced authentication and explicitly requesting a
     * Kerberos authenticator.  Also check that multiple request options are
     * accepted and parsed properly.
     */
    {
        "Login with password and forced authentication",
        LOGIN_SUCCESS,
        {
            { "<krb5-principal>", 0, 0 },
            {
                { "<userprinc>", "<password>", NULL, NULL, NULL, 0 },
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            NO_TOKENS_WKPROXY,
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "krb5", NULL, "data", 4, "https://example.com/",
                "lc,fa", NULL, NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "<userprinc>", "krb5", "<webkdc-principal>", NULL, 0,
                    "p", 0, 0, 0, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            { "<userprinc>", NULL, "krb5", NULL, 0, "p", "p", 0, 0, 0 },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        },
    },

    /* Obtain a proxy token instead of an id token. */
    {
        "Login with password, proxy token",
        LOGIN_SUCCESS,
        {
            { "<krb5-principal>", 0, 0 },
            {
                { "<userprinc>", "<password>", NULL, NULL, NULL, 0 },
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            NO_TOKENS_WKPROXY,
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "proxy", NULL, "krb5", NULL, 0, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "<userprinc>", "krb5", "<webkdc-principal>", NULL, 0,
                    "p", 0, 0, 0, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            { "<userprinc>", NULL, "krb5", "p", "p", 0, 0, 0 },
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        },
    },

    /*
     * Test mismatched webkdc-proxy and login tokens.  The webkdc-proxy token
     * should be ignored in favor of the login token.
     */
    {
        "Mismatched webkdc-proxy and login tokens",
        LOGIN_SUCCESS,
        {
            { "<krb5-principal>", 0, 0 },
            {
                { "<userprinc>", "<password>", NULL, NULL, NULL, 0 },
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 10 * 60, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "<userprinc>", "krb5", "<webkdc-principal>", NULL, 0,
                    "p", 0, 0, 0, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            { "<userprinc>", NULL, "webkdc", NULL, 0, "p", "p", 0, 0, 0 },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        },
    },

    /*
     * If we have both a proxy token and a login token, the session factor
     * information from the login token should dominate and we shouldn't get
     * the "c" cookie session information in the resulting id token.
     */
    {
        "Login and webkdc-proxy token with same factors",
        LOGIN_SUCCESS,
        {
            { "<krb5-principal>", 0, 0 },
            {
                { "<userprinc>", "<password>", NULL, NULL, NULL, 0 },
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            {
                {
                    "<userprinc>", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "p", 3, 10 * 60, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "<userprinc>", "krb5", "<webkdc-principal>", NULL, 0,
                    "p", 0, 0, 0, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            { "<userprinc>", NULL, "webkdc", NULL, 0, "p", "p", 0, 0, 0 },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        },
    }
};

/* Test cases to run with the local realm as a permitted realm. */
static const struct wat_login_test tests_permitted[] = {
    {
        "Login with password and a permitted realm",
        LOGIN_SUCCESS,
        {
            { "<krb5-principal>", 0, 0 },
            {
                { "<userprinc>", "<password>", NULL, NULL, NULL, 0 },
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            NO_TOKENS_WKPROXY,
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, "data", 4, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "<userprinc>", "krb5", "<webkdc-principal>", NULL, 0,
                    "p", 0, 0, 0, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            { "<userprinc>", NULL, "webkdc", NULL, 0, "p", "p", 0, 0, 0 },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        },
    },
};

/* Test cases to run with the local realm not listed as a permitted realm. */
static const struct wat_login_test tests_not_permitted[] = {
    {
        "Login with password and a forbidden realm",
        WA_PEC_USER_REJECTED,
        "<realm-error>",
        {
            { "<krb5-principal>", 0, 0 },
            {
                { "<userprinc>", "<password>", NULL, NULL, NULL, 0 },
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            NO_TOKENS_WKPROXY,
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, "data", 4, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
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
};

/* Test cases to run with a matching local realm configured. */
static const struct wat_login_test tests_local[] = {

    /* Pass in the full principal name, which should get canonicalized. */
    {
        "Login with full principal in the local realm",
        LOGIN_SUCCESS,
        {
            { "<krb5-principal>", 0, 0 },
            {
                { "<userprinc>", "<password>", NULL, NULL, NULL, 0 },
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            NO_TOKENS_WKPROXY,
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, "data", 4, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "<username>", "krb5", "<webkdc-principal>", NULL, 0,
                    "p", 0, 0, 0, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            { "<username>", NULL, "webkdc", NULL, 0, "p", "p", 0, 0, 0 },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        },
    },

    /* Pass in just the username portion. */
    {
        "Login with partial principal in the local realm",
        LOGIN_SUCCESS,
        {
            { "<krb5-principal>", 0, 0 },
            {
                { "<username>", "<password>", NULL, NULL, NULL, 0 },
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            NO_TOKENS_WKPROXY,
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, "data", 4, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "<username>", "krb5", "<webkdc-principal>", NULL, 0,
                    "p", 0, 0, 0, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            { "<username>", NULL, "webkdc", NULL, 0, "p", "p", 0, 0, 0 },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        },
    },

    /*
     * A login token with the full username and a webkdc-proxy token with the
     * partial username should match, and the webkdc-proxy token should
     * therefore contribute factors.
     */
    {
        "Login with full principal and webkdc-proxy token",
        LOGIN_SUCCESS,
        {
            { "<krb5-principal>", 0, 0 },
            {
                { "<userprinc>", "<password>", NULL, NULL, NULL, 0 },
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            {
                {
                    "<username>", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 10 * 60, 60 * 60, "c"
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, "data", 4, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "<username>", "krb5", "<webkdc-principal>", NULL, 0,
                    "p,x,x1,m", 3, 10 * 60, 60 * 60, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            {
                "<username>", NULL, "webkdc", NULL, 0, "p,x,x1,m", "p,c",
                3, 0, 60 * 60
            },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        },
    }
};

/* Test cases to run with an identity ACL configured. */
static const struct wat_login_test tests_id_acl[] = {

    /* Now assert an authorization identity. */
    {
        "Login for proxy token with authorization identity",
        LOGIN_SUCCESS,
        {
            { "<krb5-principal>", 0, 0 },
            {
                { "<userprinc>", "<password>", NULL, NULL, NULL, 0 },
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            NO_TOKENS_WKPROXY,
            NO_TOKENS_WKFACTOR,
            "otheruser",
            {
                "proxy", NULL, "krb5", NULL, 0, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            }
        },
        {
            NULL, NULL,
            NO_FACTOR_DATA,
            {
                {
                    "<userprinc>", "krb5", "<webkdc-principal>", NULL, 0,
                    "p", 0, 0, 0, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            { "<userprinc>", "otheruser", "krb5", "p", "p", 0, 0, 0 },
            NO_LOGINS,
            0,
            { "otheruser", NULL, NULL }
        }
    }
};


/*
 * Log callback, used to turn internal warning messages into diagnostics to
 * make test failures easier to understand.
 */
static void
log_callback(struct webauth_context *ctx UNUSED, void *data UNUSED,
             const char *message)
{
    diag("%s", message);
}


int
main(void)
{
    apr_pool_t *pool = NULL;
    apr_array_header_t *local_realms, *permitted_realms;
    struct kerberos_config *krbconf;
    struct webauth_context *ctx;
    struct webauth_krb5 *kc;
    struct webauth_keyring *ring;
    struct webauth_webkdc_config config;
    char *keyring, *tmpdir;
    int s;
    FILE *id_acl;
    size_t i;
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_FAST_CCACHE_NAME
    const char *cache;
#endif

    /* Load the Kerberos configuration. */
    krbconf = kerberos_setup(TAP_KRB_NEEDS_BOTH);

    /* Generate a testing krb5.conf file. */
    kerberos_generate_conf(krbconf->realm);

    /* Use lazy planning so that test counts can vary on some errors. */
    plan_lazy();

    /* Initialize APR and WebAuth. */
    if (apr_initialize() != APR_SUCCESS)
        bail("cannot initialize APR");
    if (apr_pool_create(&pool, NULL) != APR_SUCCESS)
        bail("cannot create memory pool");
    if (webauth_context_init_apr(&ctx, pool) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    /* Set log callbacks for info and higher. */
    webauth_log_callback(ctx, WA_LOG_INFO, log_callback, NULL);
    webauth_log_callback(ctx, WA_LOG_NOTICE, log_callback, NULL);
    webauth_log_callback(ctx, WA_LOG_WARN, log_callback, NULL);

    /* Load the precreated keyring that we'll use for token encryption. */
    keyring = test_file_path("data/keyring");
    s = webauth_keyring_read(ctx, keyring, &ring);
    if (s != WA_ERR_NONE)
        bail("cannot read %s: %s", keyring, webauth_error_message(ctx, s));
    test_file_path_free(keyring);

    /* Provide basic configuration to the WebKDC code. */
    local_realms     = apr_array_make(pool, 1, sizeof(const char *));
    permitted_realms = apr_array_make(pool, 1, sizeof(const char *));
    APR_ARRAY_PUSH(local_realms, const char *) = "none";
    memset(&config, 0, sizeof(config));
    config.local_realms     = local_realms;
    config.permitted_realms = permitted_realms;
    config.keytab_path      = krbconf->keytab;
    config.principal        = krbconf->principal;
    s = webauth_webkdc_config(ctx, &config);
    is_int(WA_ERR_NONE, s, "WebKDC configuration succeeded");

    /* Run the tests that assume no local realm. */
    for (i = 0; i < ARRAY_SIZE(tests_no_local); i++)
        run_login_test(ctx, &tests_no_local[i], ring, krbconf);

    /* Add the Kerberos realm as a permitted realm. */
    APR_ARRAY_PUSH(permitted_realms, const char *) = krbconf->realm;
    s = webauth_webkdc_config(ctx, &config);
    is_int(WA_ERR_NONE, s, "Setting permitted realms succeeds");

    /* Run the tests assuming the Kerberos realm is permitted. */
    for (i = 0; i < ARRAY_SIZE(tests_permitted); i++)
        run_login_test(ctx, &tests_permitted[i], ring, krbconf);

    /* Remove the Kerberos realm and add another permitted realm. */
    apr_array_clear(permitted_realms);
    APR_ARRAY_PUSH(permitted_realms, const char *) = "FOO.EXAMPLE.COM";
    s = webauth_webkdc_config(ctx, &config);
    is_int(WA_ERR_NONE, s, "Setting other permitted realms succeeds");

    /* Run the tests assuming the Kerberos realm is not permitted. */
    for (i = 0; i < ARRAY_SIZE(tests_not_permitted); i++)
        run_login_test(ctx, &tests_not_permitted[i], ring, krbconf);

    /* Clear permitted realms and set the Kerberos realm as the local realm. */
    apr_array_clear(permitted_realms);
    apr_array_clear(local_realms);
    APR_ARRAY_PUSH(local_realms, const char *) = krbconf->realm;
    s = webauth_webkdc_config(ctx, &config);
    is_int(WA_ERR_NONE, s, "Setting local realms succeeds");

    /* Run the tests assuming the Kerberos realm is local. */
    for (i = 0; i < ARRAY_SIZE(tests_local); i++)
        run_login_test(ctx, &tests_local[i], ring, krbconf);

    /* Treat all realms as local. */
    apr_array_clear(local_realms);
    APR_ARRAY_PUSH(local_realms, const char *) = "local";
    s = webauth_webkdc_config(ctx, &config);
    is_int(WA_ERR_NONE, s, "Setting local realms to local succeeds");

    /* Run the same tests, which should behave identically. */
    for (i = 0; i < ARRAY_SIZE(tests_local); i++)
        run_login_test(ctx, &tests_local[i], ring, krbconf);

    /*
     * Set local realms back to none, set an identity ACL file, and then get a
     * proxy token with an authorization identity.
     */
    apr_array_clear(local_realms);
    APR_ARRAY_PUSH(local_realms, const char *) = "none";
    tmpdir = test_tmpdir();
    basprintf((char **) &config.id_acl_path, "%s/id.acl", tmpdir);
    id_acl = fopen(config.id_acl_path, "w");
    if (id_acl == NULL)
        sysbail("cannot create %s", config.id_acl_path);
    fprintf(id_acl, "%s krb5:%s otheruser\n", krbconf->userprinc,
            krbconf->principal);
    fclose(id_acl);
    s = webauth_webkdc_config(ctx, &config);
    if (s != WA_ERR_NONE)
        diag("configuration failed: %s", webauth_error_message(ctx, s));
    is_int(WA_ERR_NONE, s, "WebKDC configuration succeeded");

    /* Run tests that assume an identity ACL is in place. */
    for (i = 0; i < ARRAY_SIZE(tests_id_acl); i++)
        run_login_test(ctx, &tests_id_acl[i], ring, krbconf);

    /* Clean up authorization identity. */
    unlink(config.id_acl_path);
    free((char *) config.id_acl_path);
    config.id_acl_path = NULL;
    s = webauth_webkdc_config(ctx, &config);
    if (s != WA_ERR_NONE)
        diag("configuration failed: %s", webauth_error_message(ctx, s));
    is_int(WA_ERR_NONE, s, "Clearing id_acl_path succeeded");
    test_tmpdir_free(tmpdir);

#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_FAST_CCACHE_NAME
    /*
     * If built with FAST support, check if FAST actually works.  (It might
     * not, even with FAST support in the build, if the KDC doesn't support
     * FAST.)
     */
    cache = getenv("KRB5CCNAME");
    if (cache == NULL)
        bail("KRB5CCNAME not set after Kerberos initialization");
    s = webauth_krb5_new(ctx, &kc);
    if (s != WA_ERR_NONE)
        bail("cannot initialize Kerberos: %s", webauth_error_message(ctx, s));
    s = webauth_krb5_set_fast_armor_path(ctx, kc, cache);
    if (s == WA_ERR_NONE)
        s = webauth_krb5_init_via_password(ctx, kc, krbconf->userprinc,
                                           krbconf->password, NULL,
                                           krbconf->keytab,
                                           krbconf->principal, NULL, NULL);
    webauth_krb5_free(ctx, kc);

    /*
     * If FAST failed, skip the tests.  Otherwise, obtain a credential cache
     * to use for FAST armor and then run the tests that assume no local realm
     * again.  The authentications should then happen using FAST and succeed
     * as before.
     */
    if (s != WA_ERR_NONE)
        skip_block(2, "cannot authenticate with FAST");
    else {
        config.fast_armor_path = cache;
        s = webauth_webkdc_config(ctx, &config);
        if (s != WA_ERR_NONE)
            diag("configuration failed: %s", webauth_error_message(ctx, s));
        is_int(WA_ERR_NONE, s, "Setting fast_armor_path succeeded");
        for (i = 0; i < ARRAY_SIZE(tests_no_local); i++)
            run_login_test(ctx, &tests_no_local[i], ring, krbconf);
    }
#endif

    /* Clean up. */
    apr_terminate();
    return 0;
}
