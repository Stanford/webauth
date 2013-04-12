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
#include <tests/tap/kerberos.h>
#include <tests/tap/remctl.h>
#include <tests/tap/webauth.h>
#include <webauth/basic.h>
#include <webauth/keys.h>
#include <webauth/tokens.h>
#include <webauth/webkdc.h>

/* Empty tokens, used in building tests. */
#define EMPTY_TOKEN_ID       { NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, 0, 0 }
#define EMPTY_TOKEN_LOGIN    { NULL, NULL, NULL, NULL, 0 }
#define EMPTY_TOKEN_PROXY    { NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, 0, 0 }
#define EMPTY_TOKEN_WKFACTOR { NULL, NULL, 0, 0 }
#define EMPTY_TOKEN_WKPROXY  { NULL, NULL, NULL, NULL, 0, NULL, 0, 0, 0, NULL }

/* Empty webauth_login struct, used in building tests. */
#define EMPTY_LOGIN { NULL, NULL, 0 }

/*
 * Data for a test service token.  We want to generate the key on the fly, so
 * to build a test case we use the following data instead of the full
 * webkdc-service token data and then build the rest when running the test.
 */
struct test_token_webkdc_service {
    const char *subject;
    time_t creation;
    time_t expiration;
};

/*
 * Login test cases.
 *
 * A test case consists of a name, a login request, and an expected login
 * response.  We can't, however, use the default structs to set up the test,
 * since they contain a bunch of dynamically-allocated arrays.  Instead, we
 * use our own structs with up to three elements, and we'll translate the
 * resulting structure for each test.
 *
 * We also embed the actual token data for things like returned webkdc-proxy,
 * webkdc-factor, id, proxy, and error tokens directly in the expected
 * results, since the encoded form will vary with each run.  We will decrypt
 * the token to compare it.
 */
struct test_case_login {
    const char *name;
    struct {
        struct test_token_webkdc_service service;
        struct webauth_token_login logins[3];
        struct webauth_token_webkdc_proxy wkproxies[3];
        struct webauth_token_webkdc_factor wkfactors[3];
        const char *authz_subject;
        struct webauth_token_request request;
        const char *remote_user;
        const char *local_ip;
        const char *local_port;
        const char *remote_ip;
        const char *remote_port;
    } request;
    struct {
        int login_error;
        const char *login_message;
        const char *user_message;

        /* Represented as strings of comma-separated factors. */
        const char *factors_wanted;
        const char *factors_configured;

        struct webauth_token_webkdc_proxy proxies[3];
        struct webauth_token_webkdc_factor factor_token;
        const char *return_url;
        const char *requester;
        const char *subject;
        const char *authz_subject;

        /* Only one of result_id or result_proxy will be set. */
        struct webauth_token_id result_id;
        struct webauth_token_proxy result_proxy;
        const char *result_type;

        const char *initial_factors;
        const char *session_factors;
        unsigned long loa;
        const char *app_state;
        size_t app_state_len;
        struct webauth_login logins[5];
        time_t password_expires;
        const char *permitted_authz[5];
    } response;
    int status;
    const char *error;
};

/* Test cases to run without an identity file. */
static const struct test_case_login tests_login[] = {

    /* Attempt login with no authentication. */
    {
        "No authentication",
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
            "https://example.com/",
            "krb5:webauth/example.com@EXAMPLE.COM",
            NULL,
            NULL,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NULL,
            NULL, NULL, 0,
            NULL, 0,
            {
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN
            },
            0,
            { NULL, NULL, NULL, NULL, NULL }
        },
        0,
        NULL
    },

    /* The same, but with a login cancel token. */
    {
        "No authentication and login cancel",
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
            "https://example.com/",
            "krb5:webauth/example.com@EXAMPLE.COM",
            NULL,
            NULL,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NULL,
            NULL, NULL, 0,
            NULL, 0,
            {
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN
            },
            0,
            { NULL, NULL, NULL, NULL, NULL }
        },
        0,
        NULL
    },

    /* Pass in a webkdc-proxy token and obtain an id token. */
    {
        "webkdc-proxy authentication",
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
                    "x,x1", 3, 1365725079, 1938063600, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            "https://example.com/",
            "krb5:webauth/example.com@EXAMPLE.COM",
            "testuser",
            NULL,
            {
                "testuser", NULL, "webkdc", NULL, 0, "x,x1", NULL, 3,
                0, 1938063600
            },
            EMPTY_TOKEN_PROXY,
            "id",
            "x,x1", NULL, 3,
            NULL, 0,
            {
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN
            },
            0,
            { NULL, NULL, NULL, NULL, NULL }
        },
        0,
        NULL
    },

    /* The same, but also add a webkdc-factor token. */
    {
        "webkdc-proxy and webkdc-factor authentication",
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
            "https://example.com/",
            "krb5:webauth/example.com@EXAMPLE.COM",
            "testuser",
            NULL,
            {
                "testuser", NULL, "webkdc", NULL, 0, "x,x1,d", "d", 3,
                0, 1938063600
            },
            EMPTY_TOKEN_PROXY,
            "id",
            "x,x1,d", "d", 3,
            NULL, 0,
            {
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN
            },
            0,
            { NULL, NULL, NULL, NULL, NULL }
        },
        0,
        NULL
    },

    /* Forced login with a proxy token should fail. */
    {
        "Forced login with webkdc-proxy token",
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
            "https://example.com/",
            "krb5:webauth/example.com@EXAMPLE.COM",
            "testuser",
            NULL,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NULL,
            NULL, NULL, 0,
            NULL, 0,
            {
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN
            },
            0,
            { NULL, NULL, NULL, NULL, NULL }
        },
        0,
        NULL
    },

    /* A proxy token request with a webkdc-proxy token should fail. */
    {
        "Proxy token request with webkdc-proxy token",
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
            "https://example.com/",
            "krb5:webauth/example.com@EXAMPLE.COM",
            "testuser",
            NULL,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NULL,
            NULL, NULL, 0,
            NULL, 0,
            {
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN
            },
            0,
            { NULL, NULL, NULL, NULL, NULL }
        },
        0,
        NULL
    }
};

/* Test cases to run with an identity file. */
static const struct test_case_login tests_id_acl[] = {

    /* Don't attempt to assert an identity. */
    {
        "Proxy authentication with identity ACL",
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
            "https://example.com/",
            "krb5:webauth/example.com@EXAMPLE.COM",
            "testuser",
            NULL,
            {
                "testuser", NULL, "webkdc", NULL, 0, "x,x1", NULL, 3,
                0, 1938063600
            },
            EMPTY_TOKEN_PROXY,
            "id",
            "x,x1", NULL, 3,
            NULL, 0,
            {
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN
            },
            0,
            { "otheruser", "bar", NULL, NULL, NULL }
        },
        0,
        NULL
    },

    /* Now assert an authorization identity. */
    {
        "Proxy authentication with authorization identity",
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
            "https://example.com/",
            "krb5:webauth/example.com@EXAMPLE.COM",
            "testuser",
            "otheruser",
            {
                "testuser", "otheruser", "webkdc", NULL, 0, "x,x1", NULL, 3,
                0, 1938063600
            },
            EMPTY_TOKEN_PROXY,
            "id",
            "x,x1", NULL, 3,
            NULL, 0,
            {
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN
            },
            0,
            { "otheruser", "bar", NULL, NULL, NULL }
        },
        0,
        NULL
    },

    /* Assert an identity we're not allowed to assert. */
    {
        "Unauthorized authorization identity",
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
            "https://example.com/",
            "krb5:webauth/example.com@EXAMPLE.COM",
            "testuser",
            NULL,
            EMPTY_TOKEN_ID,
            EMPTY_TOKEN_PROXY,
            NULL,
            NULL, NULL, 0,
            NULL, 0,
            {
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN
            },
            0,
            { "otheruser", "bar", NULL, NULL, NULL }
        },
        0,
        NULL
    },

    /* Assert the same identity as the subject. */
    {
        "Authorization identity matching subject",
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
            "https://example.com/",
            "krb5:webauth/example.com@EXAMPLE.COM",
            "testuser",
            NULL,
            {
                "testuser", NULL, "webkdc", NULL, 0, "x,x1", NULL, 3,
                0, 1938063600
            },
            EMPTY_TOKEN_PROXY,
            "id",
            "x,x1", NULL, 3,
            NULL, 0,
            {
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN,
                EMPTY_LOGIN
            },
            0,
            { "otheruser", "bar", NULL, NULL, NULL }
        },
        0,
        NULL
    }
};


/*
 * Validate a WebKDC login response against a struct test_case_login.  Takes a
 * WebAuth context, the wanted and seen data, a pool from which to do
 * ancillary memory allocation during the comparison, and the WebKDC and
 * session keyrings.
 */
static void
check_login_response(struct webauth_context *ctx,
                     const struct test_case_login *test,
                     const struct webauth_webkdc_login_response *response,
                     apr_pool_t *pool,
                     const struct webauth_keyring *ring,
                     const struct webauth_keyring *session)
{
    const char *factors, *options;
    int i, s;
    struct webauth_token *token;
    enum webauth_token_type type;

    /* The contents of the login canceled token. */
    const struct webauth_token_error cancel_token = {
        WA_PEC_LOGIN_CANCELED, "user canceled login", 0
    };

    /* Check the login error code and message. */
    is_int(test->response.login_error, response->login_error,
           "... login error code");
    is_string(test->response.login_message, response->login_message,
              "... login error message");

    /* Check various simple response parameters. */
    is_string(test->response.user_message, response->user_message,
              "... user message");
    is_string(test->response.return_url, response->return_url,
              "... return URL");
    is_string(test->response.requester, response->requester, "... requester");
    is_string(test->response.subject, response->subject, "... subject");
    is_string(test->response.authz_subject, response->authz_subject,
              "... authorization subject");
    is_string(test->response.initial_factors, response->initial_factors,
              "... initial factors");
    is_string(test->response.session_factors, response->session_factors,
              "... session factors");
    is_int(test->response.loa, response->loa, "... level of assurance");
    is_int(test->response.password_expires, response->password_expires,
           "... password expires");

    /* Check wanted and configured factors. */
    if (response->factors_wanted == NULL)
        ok(test->response.factors_wanted == NULL, "... has wanted factors");
    else {
        factors = apr_array_pstrcat(pool, response->factors_wanted, ',');
        is_string(test->response.factors_wanted, factors,
                  "... wanted factors");
    }
    if (response->factors_configured == NULL)
        ok(test->response.factors_configured == NULL,
           "... has configured factors");
    else {
        factors = apr_array_pstrcat(pool, response->factors_configured, ',');
        is_string(test->response.factors_configured, factors,
                  "... configured factors");
    }

    /* Check returned webkdc-proxy tokens. */
    for (i = 0; i < (int) ARRAY_SIZE(test->response.proxies); i++) {
        struct webauth_webkdc_proxy_data *pd;

        if (test->response.proxies[i].subject == NULL)
            break;
        if (response->proxies == NULL || response->proxies->nelts <= i)
            continue;
        pd = &APR_ARRAY_IDX(response->proxies, i,
                            struct webauth_webkdc_proxy_data);
        is_string(test->response.proxies[i].proxy_type, pd->type,
                  "... type of webkdc-proxy token %d", i);
        type = WA_TOKEN_WEBKDC_PROXY;
        s = webauth_token_decode(ctx, type, pd->token, ring, &token);
        is_int(WA_ERR_NONE, s, "... webkdc-proxy %d decodes", i);
        is_token_webkdc_proxy(&test->response.proxies[i],
                              &token->token.webkdc_proxy,
                              "... webkdc-proxy %d", i);
    }
    if (i == 0)
        ok(response->proxies == NULL, "... has no webkdc-proxy tokens");
    else if (response->proxies == NULL)
        is_int(i, 0, "... correct number of webkdc-proxy tokens");
    else
        is_int(i, response->proxies->nelts,
               "... correct number of webkdc-proxy tokens");

    /*
     * Check returned webkdc-factor tokens.  While we return a list for
     * forward-compatibility, the WebKDC will currently only ever return a
     * single token.
     */
    if (test->response.factor_token.subject == NULL)
        ok(response->factor_tokens == NULL, "... has no webkdc-factor tokens");
    else if (response->factor_tokens == NULL)
        ok(false, "... webkdc-factor token");
    else {
        struct webauth_webkdc_factor_data *fd;

        is_int(1, response->factor_tokens->nelts,
               "... one webkdc-factor token");
        fd = &APR_ARRAY_IDX(response->factor_tokens, 0,
                            struct webauth_webkdc_factor_data);
        is_int(test->response.factor_token.expiration, fd->expiration,
               "... expiration of webkdc-factor token");
        type = WA_TOKEN_WEBKDC_FACTOR;
        s = webauth_token_decode(ctx, type, fd->token, ring, &token);
        is_int(WA_ERR_NONE, s, "... webkdc-factor %d decodes", i);
        is_token_webkdc_factor(&test->response.factor_token,
                               &token->token.webkdc_factor,
                               "... webkdc-factor");
    }

    /* Check the result token. */
    is_string(test->response.result_type, response->result_type,
              "... result type");
    if (test->response.result_type == NULL)
        ok(response->result == NULL, "... no result token");
    else if (response->result == NULL)
        ok(false, "... result token");
    else {
        type = webauth_token_type_code(test->response.result_type);
        s = webauth_token_decode(ctx, type, response->result, session, &token);
        is_int(WA_ERR_NONE, s, "... result token decodes");
        if (type == WA_TOKEN_ID)
            is_token_id(&test->response.result_id, &token->token.id,
                        "... result");
        else if (type == WA_TOKEN_PROXY)
            is_token_proxy(&test->response.result_proxy, &token->token.proxy,
                           "... result");
        else
            bail("unknown result token type %s", test->response.result_type);
    }

    /* Check the login cancel token. */
    options = test->request.request.options;
    if (options == NULL || strstr(options, "lc") == NULL)
        ok(response->login_cancel == NULL, "... no login cancel token");
    else if (response->login_cancel == NULL)
        ok(false, "... login cancel token");
    else {
        const char *cancel;

        type = WA_TOKEN_ERROR;
        cancel = response->login_cancel;
        s = webauth_token_decode(ctx, type, cancel, session, &token);
        is_int(WA_ERR_NONE, s, "... login cancel token decodes");
        is_token_error(&cancel_token, &token->token.error,
                       "... login cancel token");
    }

    /* Check the application state. */
    if (test->response.app_state == NULL)
        ok(response->app_state == NULL, "... no application state");
    else {
        is_int(test->response.app_state_len, response->app_state_len,
               "... application state length");
        if (response->app_state == NULL)
            ok(false, "... application state data");
        else
            ok(memcmp(test->response.app_state, response->app_state,
                      test->response.app_state_len) == 0,
               "... application state data");
    }

    /* Check the login data. */
    for (i = 0; i < (int) ARRAY_SIZE(test->response.logins); i++) {
        struct webauth_login *login;

        if (test->response.logins[i].ip == NULL)
            break;
        if (response->logins == NULL || response->logins->nelts <= i)
            continue;
        login = &APR_ARRAY_IDX(response->logins, i, struct webauth_login);
        is_string(test->response.logins[i].ip, login->ip,
                  "... login %d ip", i);
        is_string(test->response.logins[i].hostname, login->hostname,
                  "... login %d hostname", i);
        is_int(test->response.logins[i].timestamp, login->timestamp,
               "... login %d timestamp", i);
    }
    if (i == 0)
        ok(response->logins == NULL, "... has no login information");
    else if (response->logins == NULL)
        is_int(i, 0, "... correct number of login records");
    else
        is_int(i, response->logins->nelts,
               "... correct number of login records");

    /* Check the permitted authorization identities. */
    for (i = 0; i < (int) ARRAY_SIZE(test->response.permitted_authz); i++) {
        const char *authz;

        if (test->response.permitted_authz[i] == NULL)
            break;
        if (response->permitted_authz == NULL)
            continue;
        if (response->permitted_authz->nelts <= i)
            continue;
        authz = APR_ARRAY_IDX(response->permitted_authz, i, const char *);
        is_string(test->response.permitted_authz[i], authz,
                  "... permitted authz %d", i);
    }
    if (i == 0)
        ok(response->permitted_authz == NULL, "... has no permitted authz");
    else if (response->permitted_authz == NULL)
        is_int(i, 0, "... correct number of permitted_authz");
    else
        is_int(i, response->permitted_authz->nelts,
               "... correct number of permitted_authz");
}


/*
 * Given an array of struct test_case_login and the length of that array, run
 * all the tests in that array.  Also takes the WebAuth context, the WebKDC
 * keyring, and a pool to use for memory allocation.
 */
static void
run_login_tests(struct webauth_context *ctx,
                const struct test_case_login *tests, size_t n,
                const struct webauth_keyring *ring, apr_pool_t *pool)
{
    struct webauth_keyring *session;
    struct webauth_key *session_key;
    struct webauth_token_webkdc_service service;
    struct webauth_webkdc_login_request request;
    struct webauth_webkdc_login_response *response;
    int s;
    size_t i, j;
    time_t now;

    /* Use a common time basis for everything that follows. */
    now = time(NULL);

    /*
     * Create a template webkdc-service token with a unique key.  We will
     * modify this for each test case.
     */
    memset(&service, 0, sizeof(service));
    s = webauth_key_create(ctx, WA_KEY_AES, WA_AES_128, NULL, &session_key);
    if (s != WA_ERR_NONE)
        bail("cannot create key: %s", webauth_error_message(ctx, s));
    session = webauth_keyring_from_key(ctx, session_key);
    service.session_key = session_key->data;
    service.session_key_len = session_key->length;

    /* Walk through the test login test cases and run each one. */
    for (i = 0; i < n; i++) {
        size_t size;
        const struct test_case_login *test;
        const char *name;
        struct webauth_token *token;

        test = &tests[i];
        name = test->name;

        /* Set up the request webkdc-service token. */
        memset(&request, 0, sizeof(request));
        request.service = &service;
        request.service->subject = test->request.service.subject;
        request.service->creation = test->request.service.creation;
        request.service->expiration = test->request.service.expiration;
        if (request.service->expiration == 0)
            request.service->expiration = now + 60;

        /* Create an array for credentials. */
        size = sizeof(struct webauth_token *);
        request.creds = apr_array_make(pool, 3, size);

        /* Add the login tokens to the array. */
        for (j = 0; j < ARRAY_SIZE(test->request.logins); j++) {
            if (test->request.logins[j].username == NULL)
                break;
            token = apr_pcalloc(pool, sizeof(struct webauth_token));
            token->type = WA_TOKEN_LOGIN;
            token->token.login = test->request.logins[j];
            APR_ARRAY_PUSH(request.creds, struct webauth_token *) = token;
        }

        /* Add the webkdc-proxy tokens to the array. */
        for (j = 0; j < ARRAY_SIZE(test->request.wkproxies); j++) {
            if (test->request.wkproxies[j].subject == NULL)
                break;
            token = apr_pcalloc(pool, sizeof(struct webauth_token));
            token->type = WA_TOKEN_WEBKDC_PROXY;
            token->token.webkdc_proxy = test->request.wkproxies[j];
            APR_ARRAY_PUSH(request.creds, struct webauth_token *) = token;
        }

        /* Add the webkdc-factor tokens to the array. */
        for (j = 0; j < ARRAY_SIZE(test->request.wkfactors); j++) {
            if (test->request.wkfactors[j].subject == NULL)
                break;
            token = apr_pcalloc(pool, sizeof(struct webauth_token));
            token->type = WA_TOKEN_WEBKDC_FACTOR;
            token->token.webkdc_factor = test->request.wkfactors[j];
            APR_ARRAY_PUSH(request.creds, struct webauth_token *) = token;
        }

        /* Set a pointer to the request token. */
        request.request = &test->request.request;

        /* Copy the remaining data. */
        request.authz_subject = test->request.authz_subject;
        request.remote_user   = test->request.remote_user;
        request.local_ip      = test->request.local_ip;
        request.local_port    = test->request.local_port;
        request.remote_ip     = test->request.remote_ip;
        request.remote_port   = test->request.remote_port;

        /* Make the actual call. */
        s = webauth_webkdc_login(ctx, &request, &response, ring);

        /*
         * Check the WebAuth return code.  If we expect to fail, no other
         * validation is useful, so skip to the next check.
         */
        is_int(test->status, s, "%s (status)", name);
        if (test->status != WA_ERR_NONE) {
            const char *message;

            message = webauth_error_message(ctx, s);
            is_string(test->error, message, "... and error message");
            continue;
        } else if (s != WA_ERR_NONE) {
            diag("%s", webauth_error_message(ctx, s));
        }

        /* Check the response. */
        check_login_response(ctx, test, response, pool, ring, session);
    }
}


int
main(void)
{
    apr_pool_t *pool = NULL;
    struct webauth_keyring *ring, *session;
    struct webauth_key *session_key;
    int status;
    char *keyring;
    time_t now;
    struct webauth_context *ctx;
    struct webauth_webkdc_config config;
    struct webauth_webkdc_login_request request;
    struct webauth_webkdc_login_response *response;
    struct webauth_token *token, wkproxy;
    struct webauth_token_request req;
    struct webauth_token_webkdc_service service;

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
    run_login_tests(ctx, tests_login, ARRAY_SIZE(tests_login), ring, pool);

    /* Set up an identity ACL. */
    config.id_acl_path = test_file_path("data/id.acl");
    status = webauth_webkdc_config(ctx, &config);
    if (status != WA_ERR_NONE)
        diag("configuration failed: %s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status, "Identity ACL configuration succeeded");

    /* Run the batch of tests requiring an identity ACL. */
    run_login_tests(ctx, tests_id_acl, ARRAY_SIZE(tests_id_acl), ring, pool);

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
