/*
 * Tests for token merging functions.
 *
 * Written by Russ Allbery <rra@stanford.edu>
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
#define EMPTY_TOKEN { NULL, NULL, 0, 0 }

/*
 * The test cases.
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
static const struct test_case {
    const char *name;
    struct webauth_token_webkdc_factor input[3];
    struct webauth_token_webkdc_factor output;
    const char *message;
} test_cases[] = {

    /* The identity merge. */
    {
        "one webkdc-factor token",
        {
            { "testuser", "d", 1364943745, 1893484800 },
            EMPTY_TOKEN,
            EMPTY_TOKEN
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
            EMPTY_TOKEN
        },
        { "testuser", "d", 1364943745, 1893484800 },
        NULL
    },

    /* If all tokens are expired, we should get back NULL. */
    {
        "all expired webkdc-factor tokens",
        {
            { "testuser", "o1", 1, 1 },
            EMPTY_TOKEN,
            EMPTY_TOKEN
        },
        EMPTY_TOKEN,
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
            EMPTY_TOKEN
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
            EMPTY_TOKEN
        },
        { "testuser", "d,o", 1262332800, 1956556800 },
        NULL
    },
};


int
main(void)
{
    apr_pool_t *pool = NULL;
    struct webauth_context *ctx;
    size_t i, j, s, size;
    apr_array_header_t *tokens;
    struct webauth_token *token;
    struct webauth_token *result;
    const char *test;

    if (apr_initialize() != APR_SUCCESS)
        bail("cannot initialize APR");
    if (apr_pool_create(&pool, NULL) != APR_SUCCESS)
        bail("cannot create memory pool");
    if (webauth_context_init_apr(&ctx, pool) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    plan(38);

    /*
     * Step through each test in turn, build an array of the tokens, merge the
     * tokens, and check the result.
     */
    size = sizeof(const struct webauth_token *);
    for (i = 0; i < ARRAY_SIZE(test_cases); i++) {
        test = test_cases[i].name;
        tokens = apr_array_make(pool, 3, size);
        for (j = 0; j < ARRAY_SIZE(test_cases); j++) {
            if (test_cases[i].input[j].subject == NULL)
                break;
            token = apr_pcalloc(pool, sizeof(struct webauth_token));
            token->type = WA_TOKEN_WEBKDC_FACTOR;
            token->token.webkdc_factor = test_cases[i].input[j];
            APR_ARRAY_PUSH(tokens, const struct webauth_token *) = token;
        }
        s = wai_token_merge_webkdc_factor(ctx, tokens, &result);
        is_int(WA_ERR_NONE, s, "Merging %s successful", test);
        if (test_cases[i].output.subject == NULL)
            ok(result == NULL, "... result is NULL as expected");
        else {
            is_int(WA_TOKEN_WEBKDC_FACTOR, result == NULL ? 0 : result->type,
                   "... and returns a webkdc-factor token");
            is_token_webkdc_factor(&test_cases[i].output,
                                   &result->token.webkdc_factor, "...");
        }
    }

    /* Clean up. */
    apr_terminate();
    return 0;
}
