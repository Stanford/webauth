/*
 * Utilities for manipulating lists of factors.
 *
 * For multifactor authentication, we have to manipulate lists of factors in
 * various ways, such as parsing and combining them and determining whether
 * one is a subset of another.  Those utility functions are collected here.
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

#include <lib/internal.h>
#include <util/macros.h>
#include <webauth/basic.h>
#include <webauth/tokens.h>

/*
 * Stores flags for the authentication types that count towards multifactor.
 * This is used internally to determine whether to synthesize a multifactor
 * factor.
 */
struct auth_types {
    bool human;
    bool password;
    bool otp;
    bool x509;
};


/*
 * Given a webauth_factors struct, fill out an auth_types struct based on the
 * factors it contains.
 */
static void
extract_auth_types(struct webauth_factors *factors, struct auth_types *types)
{
    int i;
    const char *factor;

    memset(types, 0, sizeof(struct auth_types));
    if (factors == NULL)
        return;
    for (i = 0; i < factors->factors->nelts; i++) {
        factor = APR_ARRAY_IDX(factors->factors, i, const char *);
        switch (factor[0]) {
        case 'h': types->human    = true; break;
        case 'o': types->otp      = true; break;
        case 'p': types->password = true; break;
        case 'x': types->x509     = true; break;
        default:                          break;
        }
    }
}


/*
 * Given a struct auth_types, return true if it represents a multifactor
 * authentication and false otherwise.
 */
static bool
is_multifactor(struct auth_types *types)
{
    int factors;

    factors = (int) types->human + types->password + types->otp + types->x509;
    return (factors >= 2);
}


/*
 * Return a copy of a webauth_factors struct in newly-allocated pool memory.
 * This does not deep-copy the factor strings; eventually, webauth_factors
 * will be opaque so this won't be needed.
 */
static struct webauth_factors *
factors_copy(struct webauth_context *ctx, struct webauth_factors *factors)
{
    struct webauth_factors *copy;

    if (factors == NULL) {
        copy = apr_pcalloc(ctx->pool, sizeof(struct webauth_factors));
        copy->factors = apr_array_make(ctx->pool, 1, sizeof(const char *));
    } else {
        copy = apr_pmemdup(ctx->pool, factors, sizeof(*factors));
        copy->factors = apr_array_copy(ctx->pool, factors->factors);
    }
    return copy;
}


/*
 * Returns true if the given webauth_factors struct contains the provided
 * factor, and false otherwise.  As a special case, factor sets containing
 * multifactor are always considered to contain random multifactor as well.
 */
static bool
factors_contains(struct webauth_factors *factors, const char *factor)
{
    int i;
    const char *candidate;

    if (factors == NULL || apr_is_empty_array(factors->factors))
        return false;
    if (strcmp(factor, WA_FA_RANDOM_MULTIFACTOR) == 0 && factors->multifactor)
        return true;
    for (i = 0; i < factors->factors->nelts; i++) {
        candidate = APR_ARRAY_IDX(factors->factors, i, const char *);
        if (strcmp(factor, candidate) == 0)
            return true;
    }
    return false;
}


/*
 * Given a comma-separated string of factors, parse it into a newly-allocated
 * webauth_factors struct and return the new struct.  The result is
 * pool-allocated.
 */
struct webauth_factors *
webauth_factors_parse(struct webauth_context *ctx, const char *input)
{
    struct webauth_factors *factors;
    char *copy;
    char *last = NULL;
    const char *factor;
    struct auth_types types;

    /*
     * Create an empty webauth_factors struct and return it if the string is
     * NULL or empty.
     */
    factors = apr_pcalloc(ctx->pool, sizeof(struct webauth_factors));
    factors->factors = apr_array_make(ctx->pool, 1, sizeof(const char *));
    if (input == NULL || input[0] == '\0')
        return factors;

    /*
     * Always duplicate the input string to isolate the newly-created
     * webkdc_factors struct from the input.
     */
    copy = apr_pstrdup(ctx->pool, input);

    /*
     * Walk through each factor and add it to the array.  In the process, set
     * the booleans for multifactor and random multifactor if we see them.
     */
    copy = apr_pstrdup(ctx->pool, input);
    for (factor = apr_strtok(copy, ",", &last); factor != NULL;
         factor = apr_strtok(NULL, ",", &last)) {

        /* Only add the factor if it's not a duplicate. */
        if (factors_contains(factors, factor))
            continue;

        /* Add the factor and set the multifactor and random flags. */
        APR_ARRAY_PUSH(factors->factors, const char *) = factor;
        if (strcmp(factor, WA_FA_MULTIFACTOR) == 0)
            factors->multifactor = true;
        else if (strcmp(factor, WA_FA_RANDOM_MULTIFACTOR) == 0)
            factors->random = true;
    }

    /* See if we should synthesize a multifactor factor. */
    if (!factors->multifactor) {
        extract_auth_types(factors, &types);
        factors->multifactor = is_multifactor(&types);
        if (factors->multifactor)
            APR_ARRAY_PUSH(factors->factors, const char *) = WA_FA_MULTIFACTOR;
    }

    /* Return the result. */
    return factors;
}


/*
 * Given two webauth_factors structs, create a new one representing the union
 * of both.  Synthesize multifactor if the combined webauth_factors structs
 * represent a multifactor authentication.  Returns the new struct.
 */
struct webauth_factors *
webauth_factors_union(struct webauth_context *ctx, struct webauth_factors *one,
                      struct webauth_factors *two)
{
    struct webauth_factors *result;
    int i;
    const char *factor;
    struct auth_types types;

    /* Handle trivial cases. */
    if (one == NULL || apr_is_empty_array(one->factors))
        return factors_copy(ctx, two);
    else if (two == NULL || apr_is_empty_array(two->factors))
        return factors_copy(ctx, one);

    /* We have to merge. */
    result = factors_copy(ctx, one);
    for (i = 0; i < two->factors->nelts; i++) {
        factor = APR_ARRAY_IDX(two->factors, i, const char *);

        /* Check whether the factor already exists in the result. */
        if (factors_contains(result, factor))
            continue;

        /* Add the new factor to the result. */
        APR_ARRAY_PUSH(result->factors, const char *) = factor;
        if (strcmp(factor, WA_FA_MULTIFACTOR) == 0)
            result->multifactor = true;
        else if (strcmp(factor, WA_FA_RANDOM_MULTIFACTOR) == 0)
            result->random = true;
    }

    /* See if we should synthesize a multifactor factor. */
    if (!result->multifactor) {
        extract_auth_types(result, &types);
        result->multifactor = is_multifactor(&types);
        if (result->multifactor)
            APR_ARRAY_PUSH(result->factors, const char *) = WA_FA_MULTIFACTOR;
    }

    /* Return the result. */
    return result;
}


/*
 * Given a webauth_factors struct, return its value as a comma-separated
 * string suitable for inclusion in a token.  The new string is
 * pool-allocated.  Returns NULL if the factor list is empty.
 */
char *
webauth_factors_string(struct webauth_context *ctx,
                       struct webauth_factors *factors)
{
    if (factors == NULL || apr_is_empty_array(factors->factors))
        return NULL;
    return apr_array_pstrcat(ctx->pool, factors->factors, ',');
}


/*
 * Given two sets of factors (struct webauth_factors), return true if the
 * first set is satisfied by the second set, false otherwise.
 */
int
webauth_factors_subset(struct webauth_context *ctx UNUSED,
                       struct webauth_factors *one,
                       struct webauth_factors *two)
{
    const char *factor;
    int i;

    if (one->multifactor && !two->multifactor)
        return false;
    for (i = 0; i < one->factors->nelts; i++) {
        factor = APR_ARRAY_IDX(one->factors, i, const char *);
        if (!factors_contains(two, factor))
            return false;
    }
    return true;
}


/*
 * Given two sets of factors (struct webauth_factor), return a new set
 * containing all factors present in the first that are not present in the
 * second.  This does not synthesize multifactor in the result.
 */
struct webauth_factors *
webauth_factors_subtract(struct webauth_context *ctx,
                         struct webauth_factors *one,
                         struct webauth_factors *two)
{
    struct webauth_factors *result;
    const char *factor;
    int i;

    /* Handle some trivial cases. */
    if (one == NULL)
        return NULL;
    if (two == NULL) {
        result = apr_pmemdup(ctx->pool, one, sizeof(struct webauth_factors));
        result->factors = apr_array_copy(ctx->pool, one->factors);
        return result;
    }

    /* Create the new set of factors that we will return. */
    result = apr_pcalloc(ctx->pool, sizeof(struct webauth_factors));
    result->factors = apr_array_make(ctx->pool, 2, sizeof(const char *));

    /*
     * Walk the list of factors in one and, for each, check whether it's in
     * two.  This is O(n^2), but factor lists tend to be small.
     */
    for (i = 0; i < one->factors->nelts; i++) {
        factor = APR_ARRAY_IDX(one->factors, i, const char *);
        if (!factors_contains(two, factor)) {
            APR_ARRAY_PUSH(result->factors, const char *) = factor;
            if (strcmp(factor, WA_FA_MULTIFACTOR) == 0)
                result->multifactor = true;
            if (strcmp(factor, WA_FA_RANDOM_MULTIFACTOR) == 0)
                result->random = true;
        }
    }
    return result;
}
