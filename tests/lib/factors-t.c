/*
 * Test suite for factor code manipulation.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/apr.h>
#include <portable/system.h>

#include <tests/tap/basic.h>
#include <webauth/basic.h>
#include <webauth/tokens.h>


int
main(void)
{
    apr_pool_t *pool = NULL;
    struct webauth_context *ctx;
    struct webauth_factors *one, *two, *result;
    apr_array_header_t *factors;

    plan(122);

    if (apr_initialize() != APR_SUCCESS)
        bail("cannot initialize APR");
    if (apr_pool_create(&pool, NULL) != APR_SUCCESS)
        bail("cannot create memory pool");
    if (webauth_context_init_apr(&ctx, pool) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    /* Check basic parsing into a new struct and interactive tests. */
    one = webauth_factors_parse(ctx, "u");
    is_int(1, one->factors->nelts, "Parsed u into one factor");
    is_string("u", APR_ARRAY_IDX(one->factors, 0, const char *),
              "...which is correct");
    is_int(0, one->multifactor, "...and is not multifactor");
    is_int(0, one->random, "...and is not random multifactor");
    is_int(0, webauth_factors_interactive(ctx, one),
           "...and is not interactive");
    is_int(1, webauth_factors_contains(ctx, one, "u"), "...and contains u");
    one = webauth_factors_parse(ctx, "o,o1");
    is_int(2, one->factors->nelts, "Parsed o,o1 into two factors");
    is_string("o", APR_ARRAY_IDX(one->factors, 0, const char *),
              "...first is correct");
    is_string("o1", APR_ARRAY_IDX(one->factors, 1, const char *),
              "...second is correct");
    is_int(0, one->multifactor, "...and is not multifactor");
    is_int(0, one->random, "...and is not random multifactor");
    is_int(1, webauth_factors_interactive(ctx, one), "...and is interactive");
    is_int(1, webauth_factors_contains(ctx, one, "o1"), "...and contains o1");
    is_int(0, webauth_factors_contains(ctx, one, "o2"),
           "...and does not contain o2");
    one = webauth_factors_parse(ctx, "p,m,o,o1");
    is_int(4, one->factors->nelts, "Parsed p,m,o,o1 into four factors");
    is_string("p", APR_ARRAY_IDX(one->factors, 0, const char *),
              "...first is correct");
    is_string("m", APR_ARRAY_IDX(one->factors, 1, const char *),
              "...second is correct");
    is_string("o", APR_ARRAY_IDX(one->factors, 2, const char *),
              "...third is correct");
    is_string("o1", APR_ARRAY_IDX(one->factors, 3, const char *),
              "...fourth is correct");
    is_int(1, one->multifactor, "...and is multifactor");
    is_int(0, one->random, "...and is not random multifactor");
    is_int(1, webauth_factors_interactive(ctx, one), "...and is interactive");

    /* Check that X.509 factors are interactive. */
    one = webauth_factors_parse(ctx, "x1");
    is_int(1, webauth_factors_interactive(ctx, one), "x1 is interactive");

    /* Check synthesizing the multifactor factor. */
    one = webauth_factors_parse(ctx, "p,o,o1");
    is_int(4, one->factors->nelts, "Parsed p,o,o1 into four factors");
    is_string("p", APR_ARRAY_IDX(one->factors, 0, const char *),
              "...first is correct");
    is_string("o", APR_ARRAY_IDX(one->factors, 1, const char *),
              "...second is correct");
    is_string("o1", APR_ARRAY_IDX(one->factors, 2, const char *),
              "...third is correct");
    is_string("m", APR_ARRAY_IDX(one->factors, 3, const char *),
              "...fourth is the added multifactor one");
    is_int(1, one->multifactor, "...and is multifactor");
    is_int(0, one->random, "...and is not random multifactor");
    is_int(0, webauth_factors_contains(ctx, one, "rm"),
           "...and does not contain random multifactor");

    /* Check parsing the empty string. */
    one = webauth_factors_parse(ctx, "");
    is_int(0, one->factors->nelts, "Parsed empty string into no factors");
    is_int(0, one->multifactor, "...and is not multifactor");
    is_int(0, one->random, "...and is not random multifactor");
    is_string(NULL, webauth_factors_string(ctx, one),
              "Resolves to NULL string");
    is_int(0, webauth_factors_interactive(ctx, one),
           "...and is not interactive");
    is_int(0, webauth_factors_contains(ctx, one, "p"),
           "...and does not contain the p factor");

    /* Check parsing a NULL factor string. */
    one = webauth_factors_parse(ctx, NULL);
    is_int(0, one->factors->nelts, "Parsing NULL results in no factors");

    /* Check contains on a NULL factor struct. */
    is_int(0, webauth_factors_contains(ctx, NULL, "p"),
           "webauth_factors_contains doesn't crash with NULL factors");

    /* Check parsing of random multifactor. */
    one = webauth_factors_parse(ctx, "rm");
    is_int(1, one->factors->nelts, "Parsed rm into one factor");
    is_string("rm", APR_ARRAY_IDX(one->factors, 0, const char *),
              "...which is correct");
    is_int(0, one->multifactor, "...and is not multifactor");
    is_int(1, one->random, "...but is random multifactor");
    is_string("rm", webauth_factors_string(ctx, one),
              "...and the stringification is correct");
    is_int(0, webauth_factors_interactive(ctx, one),
           "...and is not interactive");

    /* Check creating a new set of factors from an array. */
    factors = apr_array_make(pool, 3, sizeof(const char *));
    APR_ARRAY_PUSH(factors, const char *) = "p";
    APR_ARRAY_PUSH(factors, const char *) = "m";
    APR_ARRAY_PUSH(factors, const char *) = "rm";
    one = webauth_factors_new(ctx, factors);
    is_int(3, one->factors->nelts, "Created 3 factors from array");
    is_string("p", APR_ARRAY_IDX(one->factors, 0, const char *),
              "...first is correct");
    is_string("m", APR_ARRAY_IDX(one->factors, 1, const char *),
              "...second is correct");
    is_string("rm", APR_ARRAY_IDX(one->factors, 2, const char *),
              "...third is correct");
    is_int(1, one->multifactor, "...and is multifactor");
    is_int(1, one->random, "...and is random multifactor");

    /* Check creating a new set of factors from an empty array. */
    one = webauth_factors_new(ctx, NULL);
    is_int(0, one->factors->nelts, "Created empty factors from NULL array");

    /* Check merging two factor sets. */
    one = webauth_factors_union(ctx, webauth_factors_parse(ctx, "p"),
                                webauth_factors_parse(ctx, "m,o,o1,x,x1"));
    is_int(6, one->factors->nelts, "Parsed factor merge into six factors");
    is_string("p", APR_ARRAY_IDX(one->factors, 0, const char *),
              "...first is correct");
    is_string("m", APR_ARRAY_IDX(one->factors, 1, const char *),
              "...second is correct");
    is_string("o", APR_ARRAY_IDX(one->factors, 2, const char *),
              "...third is correct");
    is_string("o1", APR_ARRAY_IDX(one->factors, 3, const char *),
              "...fourth is correct");
    is_string("x", APR_ARRAY_IDX(one->factors, 4, const char *),
              "...fifth is correct");
    is_string("x1", APR_ARRAY_IDX(one->factors, 5, const char *),
              "...sixth is correct");
    is_int(1, one->multifactor, "...and is multifactor");
    is_int(0, one->random, "...but is not random multifactor");
    is_string("p,m,o,o1,x,x1", webauth_factors_string(ctx, one),
              "Resolves to the correct string");

    /*
     * Adding random multifactor to a set that already has multifactor does
     * nothing.
     */
    one = webauth_factors_union(ctx, one, webauth_factors_parse(ctx, "rm"));
    is_int(7, one->factors->nelts, "Seven factors after merging rm");
    is_int(1, one->multifactor, "...and is multifactor");
    is_int(1, one->random, "...and is random multifactor");

    /* Check merging with multifactor detection. */
    one = webauth_factors_union(ctx, webauth_factors_parse(ctx, "p"),
                                webauth_factors_parse(ctx, "x"));
    is_int(1, one->multifactor, "p and x merged is multifactor");
    is_int(3, one->factors->nelts, "...and saw three factors");
    is_string("p", APR_ARRAY_IDX(one->factors, 0, const char *),
              "...first is correct");
    is_string("x", APR_ARRAY_IDX(one->factors, 1, const char *),
              "...second is correct");
    is_string("m", APR_ARRAY_IDX(one->factors, 2, const char *),
              "...third is synthesized multifactor");

    /* Check that the human factor counts as multifactor. */
    one = webauth_factors_parse(ctx, "h,p");
    is_int(1, one->multifactor, "h and p is multifactor");
    is_int(3, one->factors->nelts, "...and saw three factors");
    is_string("h", APR_ARRAY_IDX(one->factors, 0, const char *),
              "...first is correct");
    is_string("p", APR_ARRAY_IDX(one->factors, 1, const char *),
              "...second is correct");
    is_string("m", APR_ARRAY_IDX(one->factors, 2, const char *),
              "...third is synthesized multifactor");
    is_int(1, webauth_factors_interactive(ctx, one), "...and is interactive");

    /* Likewise with merging. */
    one = webauth_factors_union(ctx, webauth_factors_parse(ctx, "p"),
                                webauth_factors_parse(ctx, "h"));
    is_int(1, one->multifactor, "h and p merged is multifactor");
    is_int(3, one->factors->nelts, "...and saw three factors");
    is_string("p", APR_ARRAY_IDX(one->factors, 0, const char *),
              "...first is correct");
    is_string("h", APR_ARRAY_IDX(one->factors, 1, const char *),
              "...second is correct");
    is_string("m", APR_ARRAY_IDX(one->factors, 2, const char *),
              "...third is synthesized multifactor");

    /* Check simple satisfaction detection. */
    one = webauth_factors_union(ctx, webauth_factors_parse(ctx, "p"),
                                webauth_factors_parse(ctx, "x"));
    two = webauth_factors_parse(ctx, "p");
    is_int(1, webauth_factors_satisfies(ctx, one, two),
           "p,x,m satisfies p");
    is_int(0, webauth_factors_satisfies(ctx, two, one),
           "p does not satisfy p,x,m");
    is_int(1, webauth_factors_satisfies(ctx, one, one),
           "p,x,m satisfies itself");
    two = webauth_factors_union(ctx, two, webauth_factors_parse(ctx, "m,x,p"));
    is_int(1, webauth_factors_satisfies(ctx, one, two),
           "satisfies works out of order");

    /* Multifactor should satisfy random multifactor. */
    one = webauth_factors_parse(ctx, "rm");
    two = webauth_factors_parse(ctx, "p,o,o1,m");
    is_int(1, webauth_factors_satisfies(ctx, two, one),
           "multifactor satisfies random");

    /* Check converting a NULL factors struct to a string. */
    is_string(NULL, webauth_factors_string(ctx, NULL),
              "webauth_factors_string of NULL struct");

    /* Check degenerate cases of subtracting factors. */
    ok(webauth_factors_subtract(ctx, NULL, NULL) == NULL,
       "webauth_factors_subtract NULL from NULL");
    one = webauth_factors_parse(ctx, "p,o,o1,m");
    ok(webauth_factors_subtract(ctx, NULL, one) == NULL,
       "webauth_factors_subtract real from NULL");
    result = webauth_factors_subtract(ctx, one, NULL);
    ok(result != NULL, "webauth_factors_subtract NULL from real");
    if (result == NULL)
        ok_block(false, 7, "...no result returned");
    else {
        is_int(1, result->multifactor, "...and is multifactor");
        is_int(0, result->random, "...but is not random multifactor");
        is_int(4, result->factors->nelts, "...and saw four factors");
        is_string("p", APR_ARRAY_IDX(result->factors, 0, const char *),
                  "...first is correct");
        is_string("o", APR_ARRAY_IDX(result->factors, 1, const char *),
                  "...second is correct");
        is_string("o1", APR_ARRAY_IDX(result->factors, 2, const char *),
                  "...third is correct");
        is_string("m", APR_ARRAY_IDX(result->factors, 3, const char *),
                  "...fourth is correct");
    }

    /* Now do a more interesting case of subtracting factors. */
    two = webauth_factors_parse(ctx, "p,o1,m,x1,u");
    result = webauth_factors_subtract(ctx, one, two);
    ok(result != NULL, "webauth_factors_subtract interesting");
    if (result == NULL)
        ok_block(false, 4, "...no result returned");
    else {
        is_int(0, result->multifactor, "...and is not multifactor");
        is_int(0, result->random, "...and is not random multifactor");
        is_int(1, result->factors->nelts, "...and saw one factor");
        is_string("o", APR_ARRAY_IDX(result->factors, 0, const char *),
                  "...first is correct");
    }
    result = webauth_factors_subtract(ctx, one, one);
    ok(result != NULL, "webauth_factors_subtract identical factors");
    if (result == NULL)
        ok_block(false, 3, "...no result returned");
    else {
        is_int(0, result->multifactor, "...and is not multifactor");
        is_int(0, result->random, "...and is not random multifactor");
        is_int(0, result->factors->nelts, "...and saw no factors");
    }
    two = webauth_factors_parse(ctx, "p");
    result = webauth_factors_subtract(ctx, one, two);
    ok(result != NULL, "webauth_factors_subtract without losing multifactor");
    if (result == NULL)
        ok_block(false, 6, "...no result returned");
    else {
        is_int(1, result->multifactor, "...and is multifactor");
        is_int(0, result->random, "...but is not random multifactor");
        is_int(3, result->factors->nelts, "...and saw three factors");
        is_string("o", APR_ARRAY_IDX(result->factors, 0, const char *),
                  "...second is correct");
        is_string("o1", APR_ARRAY_IDX(result->factors, 1, const char *),
                  "...third is correct");
        is_string("m", APR_ARRAY_IDX(result->factors, 2, const char *),
                  "...fourth is correct");
    }
    one = webauth_factors_parse(ctx, "rm");
    result = webauth_factors_subtract(ctx, one, two);
    ok(result != NULL, "webauth_factors_subtract disjoint with random");
    if (result == NULL)
        ok_block(false, 4, "...no result returned");
    else {
        is_int(0, result->multifactor, "...and is not multifactor");
        is_int(1, result->random, "...and is not random multifactor");
        is_int(1, result->factors->nelts, "...and saw one factor");
        is_string("rm", APR_ARRAY_IDX(result->factors, 0, const char *),
                  "...first is correct");
    }
    two = webauth_factors_parse(ctx, "m");
    result = webauth_factors_subtract(ctx, one, two);
    ok(result != NULL, "webauth_factors_subtract multifactor from random");
    if (result == NULL)
        ok_block(false, 3, "...no result returned");
    else {
        is_int(0, result->multifactor, "...and is not multifactor");
        is_int(0, result->random, "...and is not random multifactor");
        is_int(0, result->factors->nelts, "...and saw no factors");
    }

    /* Clean up. */
    webauth_context_free(ctx);
    return 0;
}
