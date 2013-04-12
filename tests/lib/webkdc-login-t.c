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
            {
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            {
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            {
                EMPTY_TOKEN_WKFACTOR,
                EMPTY_TOKEN_WKFACTOR,
                EMPTY_TOKEN_WKFACTOR
            },
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            },
            NULL, NULL, NULL, NULL, NULL
        },
        {
            WA_PEC_PROXY_TOKEN_REQUIRED,
            "need a proxy token",
            NULL,
            NULL, NULL,
            {
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            { EMPTY_LOGIN, EMPTY_LOGIN, EMPTY_LOGIN },
            0,
            { NULL, NULL, NULL }
        },
    },

    /* The same, but with a login cancel token. */
    {
        "No authentication and login cancel",
        0,
        NULL,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            {
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            {
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            {
                EMPTY_TOKEN_WKFACTOR,
                EMPTY_TOKEN_WKFACTOR,
                EMPTY_TOKEN_WKFACTOR
            },
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", "lc",
                NULL, NULL, 0, NULL, 0
            },
            NULL, NULL, NULL, NULL, NULL
        },
        {
            WA_PEC_PROXY_TOKEN_REQUIRED,
            "need a proxy token",
            NULL,
            NULL, NULL,
            {
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            { EMPTY_LOGIN, EMPTY_LOGIN, EMPTY_LOGIN },
            0,
            { NULL, NULL, NULL }
        },
    },

    /* Pass in a webkdc-proxy token and obtain an id token. */
    {
        "webkdc-proxy authentication",
        0,
        NULL,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            {
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 1365725079, 1938063600, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            {
                EMPTY_TOKEN_WKFACTOR,
                EMPTY_TOKEN_WKFACTOR,
                EMPTY_TOKEN_WKFACTOR
            },
            NULL,
            {
                "id", "webkdc", NULL, "data", 4, "https://example.com/", "lc",
                NULL, NULL, 0, NULL, 0
            },
            NULL, NULL, NULL, NULL, NULL
        },
        {
            0,
            NULL,
            NULL,
            NULL, NULL,
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
            { EMPTY_LOGIN, EMPTY_LOGIN, EMPTY_LOGIN },
            0,
            { NULL, NULL, NULL }
        },
    },

    /* The same, but also add a webkdc-factor token. */
    {
        "webkdc-proxy and webkdc-factor authentication",
        0,
        NULL,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            {
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
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
            NULL, NULL, NULL, NULL, NULL
        },
        {
            0,
            NULL,
            NULL,
            NULL, NULL,
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
            { EMPTY_LOGIN, EMPTY_LOGIN, EMPTY_LOGIN },
            0,
            { NULL, NULL, NULL }
        },
    },

    /* Forced login with a proxy token should fail. */
    {
        "Forced login with webkdc-proxy token",
        0,
        NULL,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            {
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 1365725079, 1938063600, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            {
                EMPTY_TOKEN_WKFACTOR,
                EMPTY_TOKEN_WKFACTOR,
                EMPTY_TOKEN_WKFACTOR
            },
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", "fa",
                NULL, NULL, 0, NULL, 0
            },
            NULL, NULL, NULL, NULL, NULL
        },
        {
            WA_PEC_LOGIN_FORCED,
            "forced authentication, need to login",
            NULL,
            NULL, NULL,
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
            { EMPTY_LOGIN, EMPTY_LOGIN, EMPTY_LOGIN },
            0,
            { NULL, NULL, NULL }
        },
    },

    /* A proxy token request with a webkdc-proxy token should fail. */
    {
        "Proxy token request with webkdc-proxy token",
        0,
        NULL,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            {
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 1365725079, 1938063600, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            {
                EMPTY_TOKEN_WKFACTOR,
                EMPTY_TOKEN_WKFACTOR,
                EMPTY_TOKEN_WKFACTOR
            },
            NULL,
            {
                "proxy", NULL, "krb5", NULL, 0, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            },
            NULL, NULL, NULL, NULL, NULL
        },
        {
            WA_PEC_PROXY_TOKEN_REQUIRED,
            "need a proxy token",
            NULL,
            NULL, NULL,
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
            { EMPTY_LOGIN, EMPTY_LOGIN, EMPTY_LOGIN },
            0,
            { NULL, NULL, NULL }
        },
    }
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
            {
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 1365725079, 1938063600, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            {
                EMPTY_TOKEN_WKFACTOR,
                EMPTY_TOKEN_WKFACTOR,
                EMPTY_TOKEN_WKFACTOR
            },
            NULL,
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            },
            NULL, NULL, NULL, NULL, NULL
        },
        {
            0,
            NULL,
            NULL,
            NULL, NULL,
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
            { EMPTY_LOGIN, EMPTY_LOGIN, EMPTY_LOGIN },
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
            {
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 1365725079, 1938063600, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            {
                EMPTY_TOKEN_WKFACTOR,
                EMPTY_TOKEN_WKFACTOR,
                EMPTY_TOKEN_WKFACTOR
            },
            "otheruser",
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            },
            NULL, NULL, NULL, NULL, NULL
        },
        {
            0,
            NULL,
            NULL,
            NULL, NULL,
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
            { EMPTY_LOGIN, EMPTY_LOGIN, EMPTY_LOGIN },
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
            {
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 1365725079, 1938063600, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            {
                EMPTY_TOKEN_WKFACTOR,
                EMPTY_TOKEN_WKFACTOR,
                EMPTY_TOKEN_WKFACTOR
            },
            "foo",
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", "lc",
                NULL, NULL, 0, NULL, 0
            },
            NULL, NULL, NULL, NULL, NULL
        },
        {
            WA_PEC_UNAUTHORIZED,
            "not authorized to assert that identity",
            NULL,
            NULL, NULL,
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
            { EMPTY_LOGIN, EMPTY_LOGIN, EMPTY_LOGIN },
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
            {
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            {
                {
                    "testuser", "remuser", "WEBKDC:remuser", "testuser", 8,
                    "x,x1", 3, 1365725079, 1938063600, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            {
                EMPTY_TOKEN_WKFACTOR,
                EMPTY_TOKEN_WKFACTOR,
                EMPTY_TOKEN_WKFACTOR
            },
            "testuser",
            {
                "id", "webkdc", NULL, NULL, 0, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            },
            NULL, NULL, NULL, NULL, NULL
        },
        {
            0,
            NULL,
            NULL,
            NULL, NULL,
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
            { EMPTY_LOGIN, EMPTY_LOGIN, EMPTY_LOGIN },
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
    struct webauth_key *session_key;
    struct webauth_keyring *ring, *session;
    struct webauth_token *token, wkproxy;
    struct webauth_token_request req;
    struct webauth_token_webkdc_service service;
    struct webauth_webkdc_config config;
    struct webauth_webkdc_login_request request;
    struct webauth_webkdc_login_response *response;
    size_t i;
    int status;
    char *keyring;
    time_t now;

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

    /* Set up an identity ACL. */
    config.id_acl_path = test_file_path("data/id.acl");
    status = webauth_webkdc_config(ctx, &config);
    if (status != WA_ERR_NONE)
        diag("configuration failed: %s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status, "Identity ACL configuration succeeded");

    /* Run the batch of tests requiring an identity ACL. */
    for (i = 0; i < ARRAY_SIZE(tests_id_acl); i++)
        run_login_test(ctx, &tests_id_acl[i], ring);

    /* Flesh out the absolute minimum required in the request. */
    now = time(NULL);
    memset(&request, 0, sizeof(request));
    memset(&service, 0, sizeof(service));
    service.subject = "krb5:webauth/example.com@EXAMPLE.COM";
    status = webauth_key_create(ctx, WA_KEY_AES, WA_AES_128, NULL,
                                &session_key);
    if (status != WA_ERR_NONE)
        bail("cannot create key: %s", webauth_error_message(ctx, status));
    session = webauth_keyring_from_key(ctx, session_key);
    service.session_key = session_key->data;
    service.session_key_len = session_key->length;
    service.creation = now;
    service.expiration = now + 60;
    request.service = &service;
    memset(&req, 0, sizeof(req));
    req.type = "id";
    req.auth = "webkdc";
    req.return_url = "https://example.com/";
    req.options = "fa";
    req.creation = now;
    request.request = &req;
    request.creds = apr_array_make(pool, 1, sizeof(struct token *));

    /*
     * Retry forced authentication with a 15 minute login timeout.  The
     * webkdc-proxy token is dated 10 minutes ago, so this should succeed.
     */
    config.login_time_limit = 15 * 60;
    status = webauth_webkdc_config(ctx, &config);
    if (status != WA_ERR_NONE)
        diag("configuration failed: %s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status, "Setting login timeout succeeded");
    memset(&wkproxy, 0, sizeof(wkproxy));
    wkproxy.type = WA_TOKEN_WEBKDC_PROXY;
    wkproxy.token.webkdc_proxy.subject = "testuser";
    wkproxy.token.webkdc_proxy.proxy_type = "remuser";
    wkproxy.token.webkdc_proxy.proxy_subject = "WEBKDC:remuser";
    wkproxy.token.webkdc_proxy.data = "testuser";
    wkproxy.token.webkdc_proxy.data_len = strlen("testuser");
    wkproxy.token.webkdc_proxy.initial_factors = "x,x1";
    wkproxy.token.webkdc_proxy.loa = 3;
    wkproxy.token.webkdc_proxy.creation = now - 10 * 60;
    wkproxy.token.webkdc_proxy.expiration = now + 60 * 60;
    request.creds = apr_array_make(pool, 2, sizeof(struct webauth_token *));
    APR_ARRAY_PUSH(request.creds, struct webauth_token *) = &wkproxy;
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status,
           "Auth w/forced login and long timeout returns success");
    is_int(0, response->login_error, "...with no error");
    is_string(NULL, response->login_message, "...and no message");
    ok(response->result != NULL, "...there is a result token");
    is_string("id", response->result_type, "...which is an id token");
    if (response->result == NULL) {
        ok(false, "...no result token");
        token = NULL;
    } else {
        status = webauth_token_decode(ctx, WA_TOKEN_ID, response->result,
                                      session, &token);
        is_int(WA_ERR_NONE, status, "...result token decodes properly");
    }
    if (token == NULL || status != WA_ERR_NONE)
        ok(0, "...no result token: %s",
           webauth_error_message(ctx, status));
    else
        is_string("testuser", token->token.id.subject,
                  "...result subject is right");
    is_string("x,x1", response->initial_factors, "...initial factors");
    is_string("x,x1", response->session_factors, "...session factors");

    /* Clean up. */
    apr_terminate();
    test_file_path_free((char *) config.id_acl_path);
    return 0;
}
