/*
 * WebAuth token merging.
 *
 * Some tokens, particularly webkdc-factor and webkdc-proxy tokens, have a
 * well-defined merge operation that takes multiple tokens and collapses them
 * into a single token.  Here are the implementations of those merge
 * functions.
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

#include <lib/internal.h>
#include <webauth/basic.h>
#include <webauth/factors.h>
#include <webauth/tokens.h>


/*
 * Set an error indicating an invalid token type was passed to the merge
 * function and then return the error code that should be returned by the
 * calling function.
 */
static int
token_type_error(struct webauth_context *ctx, enum webauth_token_type type,
                 const char *expected)
{
    const char *name;

    name = webauth_token_type_string(type);
    if (name == NULL)
        name = apr_psprintf(ctx->pool, "code %d", (int) type);
    wai_error_set(ctx, WA_ERR_INVALID, "token type %s not %s", name, expected);
    return WA_ERR_INVALID;
}


/*
 * Merge an array of webkdc-factor tokens into a single token.  Takes the
 * context, the array of webkdc-factor tokens, and a place to store the newly
 * created webkdc-factor token.
 *
 * We use the following logic to merge webkdc-factor tokens:
 *
 * 1. Expired tokens are discarded.
 * 2. Tokens whose subject do not match the subject of the last webkdc-factor
 *    token in the list are discarded.
 * 3. Tokens whose factors are a subset of the accumulated factors are
 *    discarded.
 * 4. Factors are merged between all webkdc-factor tokens, with the expiration
 *    set to the nearest expiration and the creation time set to the oldest
 *    time of all contributing tokens.
 */
int
wai_token_merge_webkdc_factor(struct webauth_context *ctx,
                              const apr_array_header_t *wkfactors,
                              struct webauth_token **result)
{
    const struct webauth_token_webkdc_factor *wft;
    struct webauth_token *best = NULL;
    struct webauth_token_webkdc_factor *best_wft;
    struct webauth_factors *best_factors = NULL;
    time_t now;
    int i;

    /* Return a NULL webkdc-factor token if we have no tokens. */
    *result = NULL;
    if (apr_is_empty_array(wkfactors))
        return WA_ERR_NONE;

    /* Ensure all time calculations use a consistent basis. */
    now = time(NULL);

    /*
     * We merge the factor tokens in reverse order, since any factor tokens
     * that we created via fresh OTP authentications should take precedence
     * over anything that we had from older cookies.  We added those to the
     * end of the array.
     */
    for (i = wkfactors->nelts - 1; i >= 0; i--) {
        const struct webauth_token *token;
        struct webauth_factors *factors;

        /* Extract and set a pointer to the next webkdc-factor token. */
        token = APR_ARRAY_IDX(wkfactors, i, const struct webauth_token *);
        if (token->type != WA_TOKEN_WEBKDC_FACTOR)
            return token_type_error(ctx, token->type, "webkdc-factor");
        wft = &token->token.webkdc_factor;

        /* Discard all expired tokens. */
        if (wft->expiration <= now)
            continue;

        /* If this is the first token, make it the best. */
        if (best == NULL) {
            best = apr_pmemdup(ctx->pool, token, sizeof(struct webauth_token));
            best_factors = webauth_factors_parse(ctx, wft->factors);
            continue;
        }

        /* Otherwise, ignore it if it has a different subject. */
        if (strcmp(wft->subject, best->token.webkdc_factor.subject) != 0)
            continue;

        /* Ignore it if the accumulated factors satisfy these factors. */
        factors = webauth_factors_parse(ctx, wft->factors);
        if (webauth_factors_satisfies(ctx, best_factors, factors))
            continue;

        /* We're merging.  Add the factors and update times. */
        best_factors = webauth_factors_union(ctx, best_factors, factors);
        if (wft->expiration < best->token.webkdc_factor.expiration)
            best->token.webkdc_factor.expiration = wft->expiration;
        if (wft->creation < best->token.webkdc_factor.creation)
            best->token.webkdc_factor.creation = wft->creation;
    }

    /* Set the result webkdc-proxy factors to our assembled ones. */
    if (best != NULL) {
        best_wft = &best->token.webkdc_factor;
        best_wft->factors = webauth_factors_string(ctx, best_factors);
    }

    /* All done.  Return best. */
    *result = best;
    return WA_ERR_NONE;
}


/*
 * Merge supplemental factors from a webkdc-factor token into a webkdc-proxy
 * token if and only if the subjects match.  The webkdc-factor token may be
 * NULL.  Takes the input tokens and a location to store the new token.
 */
int
wai_token_merge_webkdc_proxy_factor(struct webauth_context *ctx,
                                    struct webauth_token *proxy,
                                    struct webauth_token *factor,
                                    struct webauth_token **result)
{
    struct webauth_token_webkdc_proxy *wkproxy;
    struct webauth_token_webkdc_factor *wft;
    struct webauth_factors *extra, *factors, *sfactors;

    /* Ensure the tokens passed in are the right type. */
    if (proxy->type != WA_TOKEN_WEBKDC_PROXY)
        return token_type_error(ctx, proxy->type, "webkdc-proxy");
    if (factor != NULL && factor->type != WA_TOKEN_WEBKDC_FACTOR)
        return token_type_error(ctx, factor->type, "webkdc-factor");

    /* Always start with a copy of the webkdc-proxy token. */
    *result = apr_pmemdup(ctx->pool, proxy, sizeof(struct webauth_token));

    /* If there is no factor token, just return the copy. */
    if (factor == NULL)
        return WA_ERR_NONE;

    /* Otherwise, check if the subjects match.  If not, return the copy. */
    wkproxy = &proxy->token.webkdc_proxy;
    wft = &factor->token.webkdc_factor;
    if (strcmp(wft->subject, wkproxy->subject) != 0)
        return WA_ERR_NONE;

    /* Subjects match.  Merge factors and update the result. */
    extra = webauth_factors_parse(ctx, wft->factors);
    factors = webauth_factors_parse(ctx, wkproxy->initial_factors);
    sfactors = webauth_factors_parse(ctx, wkproxy->session_factors);
    factors = webauth_factors_union(ctx, factors, extra);
    sfactors = webauth_factors_union(ctx, sfactors, extra);
    wkproxy = &(*result)->token.webkdc_proxy;
    wkproxy->initial_factors = webauth_factors_string(ctx, factors);
    wkproxy->session_factors = webauth_factors_string(ctx, sfactors);
    return WA_ERR_NONE;
}
