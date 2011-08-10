/*
 * Test suite for factor code manipulation.
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
    struct webauth_factors *one, *two;

    plan(64);

    if (webauth_context_init(&ctx, NULL) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    /* Check basic parsing into a new struct. */
    one = NULL;
    parse_factors(ctx, "u", &one);
    is_int(0, one->multifactor, "...and is not multifactor");
    is_int(1, one->factors->nelts, "...and saw one factor");
    is_string("u", APR_ARRAY_IDX(one->factors, 0, const char *),
              "...which is correct");
    one = NULL;
    parse_factors(ctx, "o,o1", &one);
    is_int(0, one->multifactor, "...and is not multifactor");
    is_int(2, one->factors->nelts, "...and saw two factors");
    is_string("o", APR_ARRAY_IDX(one->factors, 0, const char *),
              "...first is correct");
    is_string("o1", APR_ARRAY_IDX(one->factors, 1, const char *),
              "...second is correct");
    one = NULL;
    parse_factors(ctx, "p,m,o,o1", &one);
    is_int(1, one->multifactor, "...and is multifactor");
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
    is_int(0, one->factors->nelts, "...and saw no factors");
    is_string(NULL, webauth_factors_string(ctx, one),
              "Resolves to empty string");

    /* Check merging two factor sets. */
    one = NULL;
    parse_factors(ctx, "p", &one);
    parse_factors(ctx, "m,o,o1,x,x1", &one);
    is_int(1, one->multifactor, "...and is multifactor");
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

    /* Check merging with multifactor detection. */
    one = NULL;
    parse_factors(ctx, "p", &one);
    parse_factors(ctx, "x", &one);
    is_int(1, one->multifactor, "...and is multifactor");
    is_int(3, one->factors->nelts, "...and saw three factors");
    is_string("p", APR_ARRAY_IDX(one->factors, 0, const char *),
              "...first is correct");
    is_string("x", APR_ARRAY_IDX(one->factors, 1, const char *),
              "...second is correct");
    is_string("m", APR_ARRAY_IDX(one->factors, 2, const char *),
              "...third is synthesized multifactor");

    /* Check simple subset detection. */
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

    /* Check parsing a NULL factor string. */
    one = NULL;
    parse_factors(ctx, NULL, &one);

    /* Clean up. */
    webauth_context_free(ctx);
    return 0;
}
