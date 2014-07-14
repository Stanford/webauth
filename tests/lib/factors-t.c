/*
 * Test suite for factor code manipulation.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2011, 2013, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/apr.h>
#include <portable/system.h>

#include <tests/tap/basic.h>
#include <webauth/basic.h>
#include <webauth/factors.h>


int
main(void)
{
    apr_pool_t *pool = NULL;
    struct webauth_context *ctx;
    struct webauth_factors *one, *two, *result;
    apr_array_header_t *factors;

    plan(49);

    if (apr_initialize() != APR_SUCCESS)
        bail("cannot initialize APR");
    if (apr_pool_create(&pool, NULL) != APR_SUCCESS)
        bail("cannot create memory pool");
    if (webauth_context_init_apr(&ctx, pool) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    /* Check basic parsing into a new struct. */
    one = webauth_factors_parse(ctx, "u");
    is_string("u", webauth_factors_string(ctx, one), "Parsed u correctly");
    is_int(1, webauth_factors_contains(ctx, one, "u"), "...and contains u");
    one = webauth_factors_parse(ctx, "o,o1");
    is_string("o,o1", webauth_factors_string(ctx, one),
              "Parsed o,o1 correctly");
    is_int(1, webauth_factors_contains(ctx, one, "o1"), "...and contains o1");
    is_int(0, webauth_factors_contains(ctx, one, "o2"),
           "...and does not contain o2");
    one = webauth_factors_parse(ctx, "p,m,o,o1");
    is_string("p,m,o,o1", webauth_factors_string(ctx, one),
              "Parsed p,m,o,o1 correctly");

    /* Check synthesizing the multifactor factor. */
    one = webauth_factors_parse(ctx, "p,o,o1");
    is_string("p,o,o1,m", webauth_factors_string(ctx, one),
              "Parsed p,o,o1 into p,o,o1,m");
    is_int(1, webauth_factors_contains(ctx, one, "m"),
           "...and contains multifactor");
    is_int(0, webauth_factors_contains(ctx, one, "rm"),
           "...and does not contain random multifactor");

    /* Test the same with the newer mp and v factors. */
    one = webauth_factors_parse(ctx, "p,mp");
    is_string("p,mp,m", webauth_factors_string(ctx, one),
              "Parsed p,mp into p,mp,m");
    is_int(1, webauth_factors_contains(ctx, one, "m"),
           "...and contains multifactor");
    one = webauth_factors_parse(ctx, "v,p");
    is_string("v,p,m", webauth_factors_string(ctx, one),
              "Parsed v,p into v,p,m");
    is_int(1, webauth_factors_contains(ctx, one, "m"),
           "...and contains multifactor");

    /* Check parsing the empty string. */
    one = webauth_factors_parse(ctx, "");
    is_string(NULL, webauth_factors_string(ctx, one),
              "Parsed \"\" to NULL string");
    is_int(0, webauth_factors_contains(ctx, one, "p"),
           "...and does not contain the p factor");

    /* Check parsing a NULL factor string. */
    one = webauth_factors_parse(ctx, NULL);
    ok(one != NULL, "Parsing NULL results in an empty factor struct");
    is_string(NULL, webauth_factors_string(ctx, one),
              "...and that becomes a NULL string");

    /* Check converting a NULL factors struct to a string. */
    is_string(NULL, webauth_factors_string(ctx, NULL),
              "webauth_factors_string of NULL struct");

    /* Check contains on a NULL factor struct. */
    is_int(0, webauth_factors_contains(ctx, NULL, "p"),
           "webauth_factors_contains doesn't crash with NULL factors");

    /* Check parsing of random multifactor. */
    one = webauth_factors_parse(ctx, "rm");
    is_string("rm", webauth_factors_string(ctx, one),
              "Parsed rm correctly");

    /* Check creating a new set of factors from an array. */
    factors = apr_array_make(pool, 3, sizeof(const char *));
    APR_ARRAY_PUSH(factors, const char *) = "p";
    APR_ARRAY_PUSH(factors, const char *) = "m";
    APR_ARRAY_PUSH(factors, const char *) = "rm";
    one = webauth_factors_new(ctx, factors);
    is_string("p,m,rm", webauth_factors_string(ctx, one),
              "Created factors from an array properly");

    /* Check creating a new set of factors from an empty array. */
    one = webauth_factors_new(ctx, NULL);
    ok(one != NULL, "Created empty factors from NULL array");
    is_string(NULL, webauth_factors_string(ctx, one),
              "...and that becomes a NULL string");

    /* Check merging two factor sets. */
    one = webauth_factors_union(ctx, webauth_factors_parse(ctx, "p"),
                                webauth_factors_parse(ctx, "m,o,o1,x,x1"));
    is_string("p,m,o,o1,x,x1", webauth_factors_string(ctx, one),
              "Factors merged into p,m,o,o1,x,x1 correctly");

    /* Check retrieving the value as an array. */
    factors = webauth_factors_array(ctx, one);
    is_int(6, factors->nelts, "webauth_factors_array returns six elements");
    is_string("p", APR_ARRAY_IDX(factors, 0, const char *),
              "...first is correct");
    is_string("m", APR_ARRAY_IDX(factors, 1, const char *),
              "...second is correct");
    is_string("o", APR_ARRAY_IDX(factors, 2, const char *),
              "...third is correct");
    is_string("o1", APR_ARRAY_IDX(factors, 3, const char *),
              "...fourth is correct");
    is_string("x", APR_ARRAY_IDX(factors, 4, const char *),
              "...fifth is correct");
    is_string("x1", APR_ARRAY_IDX(factors, 5, const char *),
              "...sixth is correct");

    /*
     * Adding random multifactor to a set that already has multifactor still
     * adds the factor.
     */
    one = webauth_factors_union(ctx, one, webauth_factors_parse(ctx, "rm"));
    is_string("p,m,o,o1,x,x1,rm", webauth_factors_string(ctx, one),
              "Merging rm adds it to the factors");

    /* Check merging with multifactor detection. */
    one = webauth_factors_union(ctx, webauth_factors_parse(ctx, "p"),
                                webauth_factors_parse(ctx, "x"));
    is_string("p,x,m", webauth_factors_string(ctx, one),
              "Merging p and x synthesizes multifactor");

    /* Check that the human factor counts as multifactor. */
    one = webauth_factors_parse(ctx, "h,p");
    is_string("h,p,m", webauth_factors_string(ctx, one),
              "Parsed h,p into factors with multifactor");

    /* Likewise with merging. */
    one = webauth_factors_union(ctx, webauth_factors_parse(ctx, "p"),
                                webauth_factors_parse(ctx, "h"));
    is_string("p,h,m", webauth_factors_string(ctx, one),
              "Merged p and h into factors with multifactor");

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
    is_int(1, webauth_factors_satisfies(ctx, one, NULL),
           "anything satisfies NULL");
    two = webauth_factors_union(ctx, two, webauth_factors_parse(ctx, "m,x,p"));
    is_int(1, webauth_factors_satisfies(ctx, one, two),
           "satisfies works out of order");

    /* Multifactor should satisfy random multifactor. */
    one = webauth_factors_parse(ctx, "rm");
    two = webauth_factors_parse(ctx, "p,o,o1,m");
    is_int(1, webauth_factors_satisfies(ctx, two, one),
           "multifactor satisfies random");

    /* Check degenerate cases of subtracting factors. */
    ok(webauth_factors_subtract(ctx, NULL, NULL) == NULL,
       "webauth_factors_subtract NULL from NULL");
    one = webauth_factors_parse(ctx, "p,o,o1,m");
    ok(webauth_factors_subtract(ctx, NULL, one) == NULL,
       "webauth_factors_subtract real from NULL");
    result = webauth_factors_subtract(ctx, one, NULL);
    is_string("p,o,o1,m", webauth_factors_string(ctx, result),
              "Subtracting NULL from a factor set changes nothing");

    /* Now do a more interesting case of subtracting factors. */
    two = webauth_factors_parse(ctx, "p,o1,m,x1,u");
    result = webauth_factors_subtract(ctx, one, two);
    is_string("o", webauth_factors_string(ctx, result),
              "Subtracting p,o1,m,x1,u from p,o,o1,m returns o");
    result = webauth_factors_subtract(ctx, one, one);
    is_string(NULL, webauth_factors_string(ctx, result),
              "Subtracting factors from itself returns empty factors");
    two = webauth_factors_parse(ctx, "p");
    result = webauth_factors_subtract(ctx, one, two);
    is_string("o,o1,m", webauth_factors_string(ctx, result),
              "Subtracting p does not remove multifactor");
    one = webauth_factors_parse(ctx, "rm");
    result = webauth_factors_subtract(ctx, one, two);
    is_string("rm", webauth_factors_string(ctx, result),
              "Subtracting rm from p makes no difference");
    two = webauth_factors_parse(ctx, "m");
    result = webauth_factors_subtract(ctx, one, two);
    is_string(NULL, webauth_factors_string(ctx, result),
              "Subtracting m from rm results in the empty set");

    /* Clean up. */
    apr_terminate();
    return 0;
}
