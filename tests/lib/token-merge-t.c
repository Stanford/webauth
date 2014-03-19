/*
 * Tests for token merging functions.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <lib/internal.h>
#include <tests/tap/basic.h>
#include <tests/tap/webauth.h>
#include <util/macros.h>
#include <webauth/basic.h>
#include <webauth/tokens.h>

/* The empty webkdc-factor token, used in specifying the tests. */
#define EMPTY_TOKEN_WKFACTOR { NULL, NULL, 0, 0 }
#define EMPTY_TOKEN_WKPROXY  { NULL, NULL, NULL, NULL, 0, NULL, 0, 0, 0, NULL }

/*
 * The webkdc-factor test cases.
 *
 * We are really testing merging of an arbitrary number of webkdc-factor
 * tokens into one, but setting up dynamically-sized arrays is a hassle.
 * Therefore, create an array of three webkdc-factor tokens to use as input,
 * and the ones that we don't want to include in a test we'll fill in with
 * zeroes.
 *
 * Remember when building the expected results of test cases that
 * webkdc-factor tokens merge from the last to the first, so the earlier
 * one of a redundant pair of tokens will be ignored.
 */
static const struct test_case_wkfactor {
    const char *name;
    struct webauth_token_webkdc_factor input[3];
    struct webauth_token_webkdc_factor output;
    const char *message;
} tests_wkfactor[] = {

    /* The identity merge. */
    {
        "one webkdc-factor token",
        {
            { "testuser", "d", 1364943745, 1893484800 },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_WKFACTOR
        },
        { "testuser", "d", 1364943745, 1893484800 },
        NULL
    },

    /* Ignore expired tokens on merge. */
    {
        "expired webkdc-factor token",
        {
            { "testuser", "d",  1364943745, 1893484800 },
            { "testuser", "o1", 1262332800, 1293868800 },
            EMPTY_TOKEN_WKFACTOR
        },
        { "testuser", "d", 1364943745, 1893484800 },
        NULL
    },

    /* If all tokens are expired, we should get back NULL. */
    {
        "all expired webkdc-factor tokens",
        {
            { "testuser", "o1", 1, 1 },
            EMPTY_TOKEN_WKFACTOR,
            EMPTY_TOKEN_WKFACTOR
        },
        EMPTY_TOKEN_WKFACTOR,
        NULL
    },

    /*
     * Merge a bunch of different tokens with different factors and times.
     * The result should combine all the factors and have the oldest creation
     * time and expiration time.
     */
    {
        "multiple webkdc-factor tokens",
        {
            { "testuser", "o1",    1925020800, 1956556800 },
            { "testuser", "d",     1357027200, 1969686000 },
            { "testuser", "m,x,h", 1577865600, 1893484800 },
        },
        { "testuser", "m,x,h,d,o1", 1357027200, 1893484800 },
        NULL
    },

    /* Tokens from a different user should be ignored. */
    {
        "webkdc-factor tokens with mismatched users",
        {
            { "testuser", "d",  1357027200, 1969686000 },
            { "test",     "o1", 1925020800, 1956556800 },
            { "test",     "o",  1925020800, 1956556800 }
        },
        { "test", "o,o1", 1925020800, 1956556800 },
        NULL
    },

    /*
     * Tokens that don't add anything to the factors should also be ignored
     * and therefore won't change the times.
     */
    {
        "duplicate webkdc-factor tokens",
        {
            { "testuser", "d", 1262332800, 1956556800 },
            { "testuser", "d", 1357027200, 1969686000 },
            EMPTY_TOKEN_WKFACTOR
        },
        { "testuser", "d", 1357027200, 1969686000 },
        NULL
    },

    /* 
     * Run the same test but with a separate factor to confirm that the token
     * is merged in that situation.
     */
    {
        "webkdc-factor tokens with different factors",
        {
            { "testuser", "o", 1262332800, 1956556800 },
            { "testuser", "d", 1357027200, 1969686000 },
            EMPTY_TOKEN_WKFACTOR
        },
        { "testuser", "d,o", 1262332800, 1956556800 },
        NULL
    },
};

/*
 * The webkdc-proxy test cases.
 *
 * Use the same trick of an input array as with the webkdc-factor token tests.
 * Remember when building the expected results of test cases that webkdc-proxy
 * tokens merge from the last to the first, so the earlier one of a redundant
 * pair of tokens will be ignored.
 */
static const struct test_case_wkproxy {
    const char *name;
    struct webauth_token_webkdc_proxy input[3];
    struct webauth_token_webkdc_proxy output;
    const char *message;
} tests_wkproxy[] = {

    /* The identity merge. */
    {
        "one webkdc-proxy token",
        {
            {
                "testuser", "otp", "WEBKDC:otp", NULL, 0, "o,o1", 1,
                1365545626, 1896163200, "c"
            },
            EMPTY_TOKEN_WKPROXY,
            EMPTY_TOKEN_WKPROXY
        },
        {
            "testuser", "otp", "WEBKDC:otp", NULL, 0, "o,o1", 1,
            1365545626, 1896163200, "c"
        },
        NULL
    },

    /* Ignore expired tokens on merge. */
    {
        "expired webkdc-proxy token",
        {
            {
                "testuser", "otp", "WEBKDC:otp", NULL, 0, "o,o1", 1,
                1365545626, 1896163200, "c"
            },
            {
                "testuser", "krb5", "WEBKDC:service/webkdc@EXAMPLE.ORG",
                "krb5", 4, "p", 1, 1365545626, 1365548450, "c"
            },
            EMPTY_TOKEN_WKPROXY
        },
        {
            "testuser", "otp", "WEBKDC:otp", NULL, 0, "o,o1", 1,
            1365545626, 1896163200, "c"
        },
        NULL
    },

    /* If all tokens are expired, we should get back NULL. */
    {
        "all expired webkdc-proxy tokens",
        {
            {
                "testuser", "krb5", "WEBKDC:service/webkdc@EXAMPLE.ORG",
                "krb5", 4, "p", 1, 1365545626, 1365548450, "c"
            },
            EMPTY_TOKEN_WKPROXY,
            EMPTY_TOKEN_WKPROXY
        },
        EMPTY_TOKEN_WKPROXY,
        NULL
    },

    /*
     * Merge a bunch of different tokens with different factors and times.
     * The result should combine all the factors, include the proxy data, have
     * the oldest creation time and expiration time, and have the maximum LoA
     * of the various tokens.
     */
    {
        "multiple webkdc-proxy tokens",
        {
            {
                "testuser", "otp", "WEBKDC:otp", NULL, 0, "o,o1", 1,
                1365545626, 1896163200, "c"
            },
            {
                "testuser", "krb5", "WEBKDC:service/webkdc@EXAMPLE.ORG",
                "krb5", 4, "p", 3, 1325404800, 1925020800, "c"
            },
            {
                "testuser", "remuser", "WEBKDC:remuser", NULL, 0, "x,x1", 2,
                1262332800, 1895163200, "k"
            },
        },
        {
            "testuser", "krb5", "WEBKDC:service/webkdc@EXAMPLE.ORG",
            "krb5", 4, "x,x1,p,m,o,o1", 3, 1262332800, 1895163200, "k,c"
        },
        NULL
    },

    /* Tokens from a different user should be ignored. */
    {
        "webkdc-proxy tokens with mismatched users",
        {
            {
                "testuser", "otp", "WEBKDC:otp", NULL, 0, "o,o1", 1,
                1365545626, 1896163200, "c"
            },
            {
                "test", "otp", "WEBKDC:otp", NULL, 0, "o,o1", 1,
                1365545626, 1896163200, "c"
            },
            EMPTY_TOKEN_WKPROXY
        },
        {
            "test", "otp", "WEBKDC:otp", NULL, 0, "o,o1", 1, 1365545626,
            1896163200, "c"
        },
        NULL
    },

    /*
     * Tokens that don't add anything to the factors should also be ignored
     * and therefore won't change the times.
     */
    {
        "duplicate webkdc-proxy tokens",
        {
            {
                "testuser", "otp", "WEBKDC:otp", NULL, 0, "o,o1", 1,
                1262332800, 1956556800, "c"
            },
            {
                "testuser", "otp", "WEBKDC:otp", NULL, 0, "o,o1", 1,
                1357027200, 1969686000, "c"
            },
            EMPTY_TOKEN_WKPROXY
        },
        {
            "testuser", "otp", "WEBKDC:otp", NULL, 0, "o,o1", 1,
            1357027200, 1969686000, "c"
        },
        NULL
    },

    /* 
     * Run the same test but with a separate factor to confirm that the token
     * is merged in that situation.
     */
    {
        "webkdc-proxy tokens with different factors",
        {
            {
                "testuser", "otp", "WEBKDC:otp", NULL, 0, "o,o2", 1,
                1262332800, 1956556800, "c"
            },
            {
                "testuser", "otp", "WEBKDC:otp", NULL, 0, "o,o1", 1,
                1357027200, 1969686000, "c"
            },
            EMPTY_TOKEN_WKPROXY
        },
        {
            "testuser", "otp", "WEBKDC:otp", NULL, 0, "o,o1,o2", 1,
            1262332800, 1956556800, "c"
        },
        NULL
    },
};


/*
 * The webkdc-proxy and webkdc-factor merge test cases.
 *
 * Here, we're updating a webkdc-proxy token (given first) with additional
 * factor information from a webkdc-factor token (given second), which should
 * result in a new webkdc-proxy token with the updated factors.
 */
static const struct test_case_wkproxy_wkfactor {
    const char *name;
    struct webauth_token_webkdc_proxy wkproxy;
    struct webauth_token_webkdc_factor wkfactor;
    struct webauth_token_webkdc_proxy output;
} tests_wkproxy_wkfactor[] = {

    /* Simple merge. */
    {
        "simple webkdc-proxy and webkdc-factor",
        {
            "testuser", "otp", "WEBKDC:otp", NULL, 0, "o,o1", 1,
            1365545626, 1896163200, "c"
        },
        { "testuser", "d,p", 1365545626, 1893484800 },
        {
            "testuser", "otp", "WEBKDC:otp", NULL, 0, "o,o1,d,p,m", 1,
            1365545626, 1896163200, "c,d,p"
        }
    },

    /* Merge of NULL token. */
    {
        "NULL webkdc-factor token with webkdc-proxy",
        {
            "testuser", "otp", "WEBKDC:otp", NULL, 0, "o,o1", 1,
            1365545626, 1896163200, "c"
        },
        EMPTY_TOKEN_WKFACTOR,
        {
            "testuser", "otp", "WEBKDC:otp", NULL, 0, "o,o1", 1,
            1365545626, 1896163200, "c"
        }
    },

    /* Merge of a token for a different user. */
    {
        "webkdc-proxy, webkdc-factor with mismatched users",
        {
            "testuser", "otp", "WEBKDC:otp", NULL, 0, "o,o1", 1,
            1365545626, 1896163200, "c"
        },
        { "test", "d,p", 1365545626, 1893484800 },
        {
            "testuser", "otp", "WEBKDC:otp", NULL, 0, "o,o1", 1,
            1365545626, 1896163200, "c"
        }
    },

    /* Merge of a token with no new factors. */
    {
        "webkdc-proxy and webkdc-factor with no new factors",
        {
            "testuser", "krb5", "WEBKDC:service/webkdc@EXAMPLE.ORG",
            "krb5;authent;data", 17, "p,d", 1, 1365545626, 1896163200, "p,d"
        },
        { "test", "d,p", 1365545626, 1893484800 },
        {
            "testuser", "krb5", "WEBKDC:service/webkdc@EXAMPLE.ORG",
            "krb5;authent;data", 17, "p,d", 1, 1365545626, 1896163200, "p,d"
        }
    }
};


int
main(void)
{
    apr_pool_t *pool = NULL;
    struct webauth_context *ctx;
    size_t i, j, size;
    int s;
    apr_array_header_t *tokens;
    struct webauth_token *token, *wkp, *wkf;
    struct webauth_token *result;
    const char *test;

    if (apr_initialize() != APR_SUCCESS)
        bail("cannot initialize APR");
    if (apr_pool_create(&pool, NULL) != APR_SUCCESS)
        bail("cannot create memory pool");
    if (webauth_context_init_apr(&ctx, pool) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    plan(160);

    /*
     * Step through each webkdc-factor merge test in turn, build an array of
     * the tokens, merge the tokens, and check the result.
     */
    size = sizeof(const struct webauth_token *);
    for (i = 0; i < ARRAY_SIZE(tests_wkfactor); i++) {
        test = tests_wkfactor[i].name;
        tokens = apr_array_make(pool, 3, size);
        for (j = 0; j < ARRAY_SIZE(tests_wkfactor[i].input); j++) {
            if (tests_wkfactor[i].input[j].subject == NULL)
                break;
            token = apr_pcalloc(pool, sizeof(struct webauth_token));
            token->type = WA_TOKEN_WEBKDC_FACTOR;
            token->token.webkdc_factor = tests_wkfactor[i].input[j];
            APR_ARRAY_PUSH(tokens, const struct webauth_token *) = token;
        }
        s = wai_token_merge_webkdc_factor(ctx, tokens, &result);
        is_int(WA_ERR_NONE, s, "Merging %s successful", test);
        if (tests_wkfactor[i].output.subject == NULL)
            ok(result == NULL, "... result is NULL as expected");
        else {
            is_int(WA_TOKEN_WEBKDC_FACTOR, result == NULL ? 0 : result->type,
                   "... and returns a webkdc-factor token");
            is_token_webkdc_factor(&tests_wkfactor[i].output,
                                   &result->token.webkdc_factor, "...");
        }
    }

    /* Likewise for the webkdc-proxy merge tests. */
    for (i = 0; i < ARRAY_SIZE(tests_wkproxy); i++) {
        test = tests_wkproxy[i].name;
        tokens = apr_array_make(pool, 3, size);
        for (j = 0; j < ARRAY_SIZE(tests_wkproxy[i].input); j++) {
            if (tests_wkproxy[i].input[j].subject == NULL)
                break;
            token = apr_pcalloc(pool, sizeof(struct webauth_token));
            token->type = WA_TOKEN_WEBKDC_PROXY;
            token->token.webkdc_proxy = tests_wkproxy[i].input[j];
            APR_ARRAY_PUSH(tokens, const struct webauth_token *) = token;
        }
        s = wai_token_merge_webkdc_proxy(ctx, tokens, 0, &result);
        if (tests_wkproxy[i].message == NULL) {
            if (s != WA_ERR_NONE)
                diag("%s", webauth_error_message(ctx, s));
            is_int(WA_ERR_NONE, s, "Merging %s successful", test);
        } else {
            ok(s != WA_ERR_NONE, "Merging %s failed as expected", test);
            is_string(tests_wkproxy[i].message,
                      webauth_error_message(ctx, s), "... with correct error");
        }
        if (tests_wkproxy[i].output.subject == NULL)
            ok(result == NULL, "... result is NULL as expected");
        else {
            is_int(WA_TOKEN_WEBKDC_PROXY, result == NULL ? 0 : result->type,
                   "... and returns a webkdc-proxy token");
            is_token_webkdc_proxy(&tests_wkproxy[i].output,
                                  &result->token.webkdc_proxy, "...");
        }
    }

    /* Likewise for merging webkdc-proxy and webkdc-factor tokens. */
    for (i = 0; i < ARRAY_SIZE(tests_wkproxy_wkfactor); i++) {
        test = tests_wkproxy_wkfactor[i].name;
        wkp = apr_pcalloc(pool, sizeof(struct webauth_token));
        wkp->type = WA_TOKEN_WEBKDC_PROXY;
        wkp->token.webkdc_proxy = tests_wkproxy_wkfactor[i].wkproxy;
        if (tests_wkproxy_wkfactor[i].wkfactor.subject == NULL)
            wkf = NULL;
        else {
            wkf = apr_pcalloc(pool, sizeof(struct webauth_token));
            wkf->type = WA_TOKEN_WEBKDC_FACTOR;
            wkf->token.webkdc_factor = tests_wkproxy_wkfactor[i].wkfactor;
        }
        s = wai_token_merge_webkdc_proxy_factor(ctx, wkp, wkf, &result);
        is_int(WA_ERR_NONE, s, "Merging %s successful", test);
        is_int(WA_TOKEN_WEBKDC_PROXY, result->type,
               "... and returns a webkdc-proxy token");
        is_token_webkdc_proxy(&tests_wkproxy_wkfactor[i].output,
                              &result->token.webkdc_proxy, "...");
    }

    /* Clean up. */
    apr_terminate();
    return 0;
}
