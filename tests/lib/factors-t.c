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


/*
 * Parse a factor string into a factors struct and sanity-check the results
 * in some standard ways.
 */
static void
parse_factors(struct webauth_context *ctx, const char *factors,
              struct webauth_factors **result)
{
    int status;

    status = webauth_factors_parse(ctx, factors, result);
    is_int(WA_ERR_NONE, status, "Parse of %s succeeded", factors);
    ok(*result != NULL, "...and set a result");
}


int
main(void)
{
    struct webauth_context *ctx;
    struct webauth_factors *one, *two, *result;

    plan(147);

    if (webauth_context_init(&ctx, NULL) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    /* Check basic parsing into a new struct. */
    one = NULL;
    parse_factors(ctx, "u", &one);
    is_int(0, one->multifactor, "...and is not multifactor");
    is_int(0, one->random, "...and is not random multifactor");
    is_int(1, one->factors->nelts, "...and saw one factor");
    is_string("u", APR_ARRAY_IDX(one->factors, 0, const char *),
              "...which is correct");
    one = NULL;
    parse_factors(ctx, "o,o1", &one);
    is_int(0, one->multifactor, "...and is not multifactor");
    is_int(0, one->random, "...and is not random multifactor");
    is_int(2, one->factors->nelts, "...and saw two factors");
    is_string("o", APR_ARRAY_IDX(one->factors, 0, const char *),
              "...first is correct");
    is_string("o1", APR_ARRAY_IDX(one->factors, 1, const char *),
              "...second is correct");
    one = NULL;
    parse_factors(ctx, "p,m,o,o1", &one);
    is_int(1, one->multifactor, "...and is multifactor");
    is_int(0, one->random, "...and is not random multifactor");
    is_int(4, one->factors->nelts, "...and saw four factors");
    is_string("p", APR_ARRAY_IDX(one->factors, 0, const char *),
              "...first is correct");
    is_string("m", APR_ARRAY_IDX(one->factors, 1, const char *),
              "...second is correct");
    is_string("o", APR_ARRAY_IDX(one->factors, 2, const char *),
              "...third is correct");
    is_string("o1", APR_ARRAY_IDX(one->factors, 3, const char *),
              "...fourth is correct");

    /* Check synthesizing the multifactor factor. */
    one = NULL;
    parse_factors(ctx, "p,o,o1", &one);
    is_int(1, one->multifactor, "...and is multifactor");
    is_int(0, one->random, "...and is not random multifactor");
    is_int(4, one->factors->nelts, "...and saw four factors");
    is_string("p", APR_ARRAY_IDX(one->factors, 0, const char *),
              "...first is correct");
    is_string("o", APR_ARRAY_IDX(one->factors, 1, const char *),
              "...second is correct");
    is_string("o1", APR_ARRAY_IDX(one->factors, 2, const char *),
              "...third is correct");
    is_string("m", APR_ARRAY_IDX(one->factors, 3, const char *),
              "...fourth is the added multifactor one");

    /* Check parsing the empty string. */
    one = NULL;
    parse_factors(ctx, "", &one);
    is_int(0, one->multifactor, "...and is not multifactor");
    is_int(0, one->random, "...and is not random multifactor");
    is_int(0, one->factors->nelts, "...and saw no factors");
    is_string(NULL, webauth_factors_string(ctx, one),
              "Resolves to empty string");

    /* Check parsing of random multifactor. */
    one = NULL;
    parse_factors(ctx, "rm", &one);
    is_int(0, one->multifactor, "...and is not multifactor");
    is_int(1, one->random, "...but is random multifactor");
    is_int(1, one->factors->nelts, "...and saw one factor");
    is_string("rm", APR_ARRAY_IDX(one->factors, 0, const char *),
              "...which is correct");
    is_string("rm", webauth_factors_string(ctx, one),
              "...and the stringification is correct");

    /* Check merging two factor sets. */
    one = NULL;
    parse_factors(ctx, "p", &one);
    parse_factors(ctx, "m,o,o1,x,x1", &one);
    is_int(1, one->multifactor, "...and is multifactor");
    is_int(0, one->random, "...but is not random multifactor");
    is_int(6, one->factors->nelts, "...and saw six factors");
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
    is_string("p,m,o,o1,x,x1", webauth_factors_string(ctx, one),
              "Resolves to the correct string");

    /*
     * Adding random multifactor to a set that already has multifactor does
     * nothing.
     */
    parse_factors(ctx, "rm", &one);
    is_int(1, one->multifactor, "...and is multifactor");
    is_int(0, one->random, "...but is not random multifactor");
    is_int(6, one->factors->nelts, "...and saw six factors");

    /* Check merging with multifactor detection. */
    one = NULL;
    parse_factors(ctx, "p", &one);
    parse_factors(ctx, "x", &one);
    is_int(1, one->multifactor, "p and x merged is multifactor");
    is_int(3, one->factors->nelts, "...and saw three factors");
    is_string("p", APR_ARRAY_IDX(one->factors, 0, const char *),
              "...first is correct");
    is_string("x", APR_ARRAY_IDX(one->factors, 1, const char *),
              "...second is correct");
    is_string("m", APR_ARRAY_IDX(one->factors, 2, const char *),
              "...third is synthesized multifactor");

    /* Check that the human factor counts as multifactor. */
    one = NULL;
    parse_factors(ctx, "h,p", &one);
    is_int(1, one->multifactor, "h and p is multifactor");
    is_int(3, one->factors->nelts, "...and saw three factors");
    is_string("h", APR_ARRAY_IDX(one->factors, 0, const char *),
              "...first is correct");
    is_string("p", APR_ARRAY_IDX(one->factors, 1, const char *),
              "...second is correct");
    is_string("m", APR_ARRAY_IDX(one->factors, 2, const char *),
              "...third is synthesized multifactor");

    /* Likewise with merging. */
    one = NULL;
    parse_factors(ctx, "p", &one);
    parse_factors(ctx, "h", &one);
    is_int(1, one->multifactor, "h and p merged is multifactor");
    is_int(3, one->factors->nelts, "...and saw three factors");
    is_string("p", APR_ARRAY_IDX(one->factors, 0, const char *),
              "...first is correct");
    is_string("h", APR_ARRAY_IDX(one->factors, 1, const char *),
              "...second is correct");
    is_string("m", APR_ARRAY_IDX(one->factors, 2, const char *),
              "...third is synthesized multifactor");

    /* Check simple subset detection. */
    one = NULL;
    parse_factors(ctx, "p", &one);
    parse_factors(ctx, "x", &one);
    two = NULL;
    parse_factors(ctx, "p", &two);
    is_int(1, webauth_factors_subset(ctx, two, one),
           "p is subset of p,x,m");
    is_int(0, webauth_factors_subset(ctx, one, two),
           "p,x,m is not subset of p");
    is_int(1, webauth_factors_subset(ctx, one, one),
           "p,x,m is subset of itself");
    parse_factors(ctx, "m,x,p", &two);
    is_int(1, webauth_factors_subset(ctx, two, one),
           "subset works out of order");

    /* Multifactor should satisfy random multifactor. */
    one = NULL;
    two = NULL;
    parse_factors(ctx, "rm", &one);
    parse_factors(ctx, "p,o,o1,m", &two);
    is_int(1, webauth_factors_subset(ctx, one, two),
           "multifactor satisfies random in subset");

    /* Check parsing a NULL factor string. */
    one = NULL;
    parse_factors(ctx, NULL, &one);

    /* Check converting a NULL factors struct to a string. */
    is_string(NULL, webauth_factors_string(ctx, NULL),
              "webauth_factors_string of NULL struct");

    /* Check degenerate cases of subtracting factors. */
    ok(webauth_factors_subtract(ctx, NULL, NULL) == NULL,
       "webauth_factors_subtract NULL from NULL");
    one = NULL;
    parse_factors(ctx, "p,o,o1,m", &one);
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
    two = NULL;
    parse_factors(ctx, "p,o1,m,x1,u", &two);
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
    two = NULL;
    parse_factors(ctx, "p", &two);
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
    one = NULL;
    parse_factors(ctx, "rm", &one);
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

    /* Clean up. */
    webauth_context_free(ctx);
    return 0;
}
