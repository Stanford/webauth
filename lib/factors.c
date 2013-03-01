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
 * Given a comma-separated string of factors, parse it into a webauth_factors
 * struct.  If the value of the last argument is not NULL, add the factors to
 * the existing webauth_factors struct rather than allocating a new one.
 * Returns a status code (which currently is always WA_ERR_NONE).
 */
int
webauth_factors_parse(struct webauth_context *ctx, const char *input,
                      struct webauth_factors **result)
{
    struct webauth_factors *factors;
    char *copy;
    char *last = NULL;
    const char *current, *factor;
    int i;
    bool found;
    bool human = false;
    bool password = false;
    bool otp = false;
    bool x509 = false;

    /*
     * If *result is not NULL, we're merging the new factors into the existing
     * ones.  If it is NULL, create a new, empty factors struct.
     */
    if (*result != NULL) {
        factors = *result;
        for (i = 0; i < factors->factors->nelts; i++) {
            factor = APR_ARRAY_IDX(factors->factors, i, const char *);
            if (strncmp(factor, "h", 1) == 0)
                human = true;
            if (strncmp(factor, "p", 1) == 0)
                password = true;
            if (strncmp(factor, "o", 1) == 0)
                otp = true;
            if (strncmp(factor, "x", 1) == 0)
                x509 = true;
        }
    } else {
        factors = apr_pcalloc(ctx->pool, sizeof(struct webauth_factors));
        factors->factors = apr_array_make(ctx->pool, 1, sizeof(const char *));
    }

    /* If there are no input factors, no changes. */
    if (input == NULL) {
        *result = factors;
        return WA_ERR_NONE;
    }

    /*
     * Walk through each factor and add it to the array.  In the process,
     * we also track whether we've seen two factors from different classes of
     * authentication, which synthesizes the multifactor factor.
     */
    copy = apr_pstrdup(ctx->pool, input);
    for (factor = apr_strtok(copy, ",", &last); factor != NULL;
         factor = apr_strtok(NULL, ",", &last)) {
        found = false;
        if (strcmp(factor, "m") == 0) {
            if (!factors->multifactor)
                APR_ARRAY_PUSH(factors->factors, const char *) = "m";
            factors->multifactor = true;
            continue;
        } else if (strcmp(factor, "rm") == 0) {
            if (!factors->random && !factors->multifactor) {
                APR_ARRAY_PUSH(factors->factors, const char *) = "rm";
                factors->random = true;
            }
            continue;
        }
        for (i = 0; i < factors->factors->nelts; i++) {
            current = APR_ARRAY_IDX(factors->factors, i, const char *);
            if (strcmp(factor, current) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            APR_ARRAY_PUSH(factors->factors, const char *) = factor;
            if (strncmp(factor, "h", 1) == 0)
                human = true;
            if (strncmp(factor, "p", 1) == 0)
                password = true;
            if (strncmp(factor, "o", 1) == 0)
                otp = true;
            if (strncmp(factor, "x", 1) == 0)
                x509 = true;
        }
    }
    if (!factors->multifactor && (human + password + otp + x509) >= 2) {
        APR_ARRAY_PUSH(factors->factors, const char *) = "m";
        factors->multifactor = true;
    }
    *result = factors;
    return WA_ERR_NONE;
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
    if (factors == NULL)
        return NULL;
    if (factors->factors->nelts == 0)
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
    bool found;
    const char *f1, *f2;
    int i, j;

    if (one->multifactor && !two->multifactor)
        return false;
    for (i = 0; i < one->factors->nelts; i++) {
        f1 = APR_ARRAY_IDX(one->factors, i, const char *);
        if (strcmp(f1, "rm") == 0 && two->multifactor)
            continue;
        found = false;
        for (j = 0; j < two->factors->nelts; j++) {
            f2 = APR_ARRAY_IDX(two->factors, j, const char *);
            if (strcmp(f1, f2) == 0) {
                found = true;
                break;
            }
        }
        if (!found)
            return false;
    }
    return true;
}
