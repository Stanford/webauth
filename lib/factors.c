/*
 * Utilities for manipulating lists of factors.
 *
 * For multifactor authentication, we have to manipulate lists of factors in
 * various ways, such as parsing and combining them and determining whether
 * one is a subset of another.  Those utility functions are collected here.
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

#include <lib/internal.h>
#include <util/macros.h>
#include <webauth/basic.h>
#include <webauth/factors.h>

/*
 * Stores a set of factors that we want to perform operations on.  This is a
 * list of authentication methods (like "p", "o1", etc.) plus flags for
 * multifactor and random multifactor.  Those flags are just optimizations
 * (and may be worth dropping).
 */
struct webauth_factors {
    int multifactor;                    /* "m" (two factors in use) */
    int random;                         /* "rm" (random multifactor) */
    apr_array_header_t *factors;        /* Array of char * factor codes. */
};


/*
 * Scan a set of factors and add a synthesized multifactor factor if it
 * includes authentications from multiple factors.
 */
static void
maybe_synthesize_multifactor(struct webauth_factors *factors)
{
    int types, i;
    const char *factor;
    bool human    = false;
    bool mobile   = false;
    bool otp      = false;
    bool password = false;
    bool voice    = false;
    bool x509     = false;

    /* If this set of factors already includes multifactor, do nothing. */
    if (factors->multifactor)
        return;

    /* Scan the factors and count how many classes we have. */
    for (i = 0; i < factors->factors->nelts; i++) {
        factor = APR_ARRAY_IDX(factors->factors, i, const char *);
        if      (strcmp(factor, WA_FA_HUMAN)       == 0) human    = true;
        else if (strcmp(factor, WA_FA_MOBILE_PUSH) == 0) mobile   = true;
        else if (strcmp(factor, WA_FA_PASSWORD)    == 0) password = true;
        else if (strcmp(factor, WA_FA_VOICE)       == 0) voice    = true;
        else if (factor[0] == 'o')                       otp      = true;
        else if (factor[0] == 'x')                       x509     = true;
    }
    types = (int) human + mobile + password + otp + voice + x509;

    /* If we have factors from more than one class, synthesize multifactor. */
    if (types >= 2) {
        factors->multifactor = true;
        APR_ARRAY_PUSH(factors->factors, const char *) = WA_FA_MULTIFACTOR;
    }
}


/*
 * Return a copy of a webauth_factors struct in newly-allocated pool memory.
 * This does not deep-copy the factor strings; eventually, webauth_factors
 * will be opaque so this won't be needed.
 */
static struct webauth_factors *
factors_copy(struct webauth_context *ctx,
             const struct webauth_factors *factors)
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
 * Returns true if the given webauth_factors struct satisfies the provided
 * factor, and false otherwise.  As a special case, factor sets containing
 * multifactor are always considered to satisfy random multifactor as well.
 */
static bool
factors_satisfies(const struct webauth_factors *factors, const char *factor)
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
 * Return all the factors as a newly pool-allocated array.  We do a deep copy
 * just in case the factors came from a different context.
 */
apr_array_header_t *
webauth_factors_array(struct webauth_context *ctx,
                      const struct webauth_factors *factors)
{
    if (factors == NULL || apr_is_empty_array(factors->factors))
        return apr_array_make(ctx->pool, 1, sizeof(const char *));
    else
        return apr_array_copy(ctx->pool, factors->factors);
}


/*
 * Returns true if the given webauth_factors struct contains the provided
 * factor, and false otherwise.  This does not have special handling of random
 * multifactor.
 */
int
webauth_factors_contains(struct webauth_context *ctx UNUSED,
                         const struct webauth_factors *factors,
                         const char *factor)
{
    int i;
    const char *candidate;

    if (factors == NULL || apr_is_empty_array(factors->factors))
        return false;
    for (i = 0; i < factors->factors->nelts; i++) {
        candidate = APR_ARRAY_IDX(factors->factors, i, const char *);
        if (strcmp(factor, candidate) == 0)
            return true;
    }
    return false;
}


/*
 * Given an array of factor strings (possibly NULL), create a new
 * pool-allocated webauth_factors struct and return it.  This function does
 * not synthesize multifactor.
 */
struct webauth_factors *
webauth_factors_new(struct webauth_context *ctx,
                    const apr_array_header_t *factors)
{
    struct webauth_factors *result;
    int i;
    const char *factor;

    /* Create the new webauth_factors struct and copy the factors. */
    result = apr_pcalloc(ctx->pool, sizeof(struct webauth_factors));
    if (factors != NULL)
        result->factors = apr_array_copy(ctx->pool, factors);
    else
        result->factors = apr_array_make(ctx->pool, 1, sizeof(const char *));

    /* Fill out the multifactor and random multifactor data. */
    for (i = 0; i < result->factors->nelts; i++) {
        factor = APR_ARRAY_IDX(result->factors, i, const char *);
        if (strcmp(factor, WA_FA_MULTIFACTOR) == 0)
            result->multifactor = true;
        else if (strcmp(factor, WA_FA_RANDOM_MULTIFACTOR) == 0)
            result->random = true;
    }

    return result;
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
    for (factor = apr_strtok(copy, ",", &last); factor != NULL;
         factor = apr_strtok(NULL, ",", &last)) {

        /* Only add the factor if it's not a duplicate. */
        if (webauth_factors_contains(ctx, factors, factor))
            continue;

        /* Add the factor and set the multifactor and random flags. */
        APR_ARRAY_PUSH(factors->factors, const char *) = factor;
        if (strcmp(factor, WA_FA_MULTIFACTOR) == 0)
            factors->multifactor = true;
        else if (strcmp(factor, WA_FA_RANDOM_MULTIFACTOR) == 0)
            factors->random = true;
    }

    /* See if we should synthesize a multifactor factor. */
    maybe_synthesize_multifactor(factors);

    /* Return the result. */
    return factors;
}


/*
 * Given two webauth_factors structs, create a new one representing the union
 * of both.  Synthesize multifactor if the combined webauth_factors structs
 * represent a multifactor authentication.  Returns the new struct.
 */
struct webauth_factors *
webauth_factors_union(struct webauth_context *ctx,
                      const struct webauth_factors *one,
                      const struct webauth_factors *two)
{
    struct webauth_factors *result;
    int i;
    const char *factor;

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
        if (webauth_factors_contains(ctx, result, factor))
            continue;

        /* Add the new factor to the result. */
        APR_ARRAY_PUSH(result->factors, const char *) = factor;
        if (strcmp(factor, WA_FA_MULTIFACTOR) == 0)
            result->multifactor = true;
        else if (strcmp(factor, WA_FA_RANDOM_MULTIFACTOR) == 0)
            result->random = true;
    }

    /* See if we should synthesize a multifactor factor. */
    maybe_synthesize_multifactor(result);

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
                       const struct webauth_factors *factors)
{
    if (factors == NULL || apr_is_empty_array(factors->factors))
        return NULL;
    return apr_array_pstrcat(ctx->pool, factors->factors, ',');
}


/*
 * Given two sets of factors (struct webauth_factors), return true if the
 * first set satisfies the second set, false otherwise.
 */
int
webauth_factors_satisfies(struct webauth_context *ctx UNUSED,
                          const struct webauth_factors *one,
                          const struct webauth_factors *two)
{
    const char *factor;
    int i;

    if (two == NULL)
        return true;
    if (!one->multifactor && two->multifactor)
        return false;
    for (i = 0; i < two->factors->nelts; i++) {
        factor = APR_ARRAY_IDX(two->factors, i, const char *);
        if (!factors_satisfies(one, factor))
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
                         const struct webauth_factors *one,
                         const struct webauth_factors *two)
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
     * Walk the list of factors in one and, for each, check whether it's
     * satisifed by two.  This is O(n^2), but factor lists tend to be small.
     */
    for (i = 0; i < one->factors->nelts; i++) {
        factor = APR_ARRAY_IDX(one->factors, i, const char *);
        if (!factors_satisfies(two, factor)) {
            APR_ARRAY_PUSH(result->factors, const char *) = factor;
            if (strcmp(factor, WA_FA_MULTIFACTOR) == 0)
                result->multifactor = true;
            if (strcmp(factor, WA_FA_RANDOM_MULTIFACTOR) == 0)
                result->random = true;
        }
    }
    return result;
}
