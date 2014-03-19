/*
 * WebAuth token merging.
 *
 * Some tokens, particularly webkdc-factor and webkdc-proxy tokens, have a
 * well-defined merge operation that takes multiple tokens and collapses them
 * into a single token.  Here are the implementations of those merge
 * functions.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
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
#include <webauth/webkdc.h>


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
        if (wft->expiration <= now) {
            wai_log_info(ctx, "ignoring expired webkdc-factor token for %s"
                         " (expired at %lu)", wft->subject,
                         (unsigned long) wft->expiration);
            continue;
        }

        /* If this is the first token, make it the best. */
        if (best == NULL) {
            best = apr_pmemdup(ctx->pool, token, sizeof(struct webauth_token));
            best_factors = webauth_factors_parse(ctx, wft->factors);
            continue;
        }

        /* Otherwise, ignore it if it has a different subject. */
        if (strcmp(wft->subject, best->token.webkdc_factor.subject) != 0) {
            wai_log_info(ctx, "ignoring webkdc-factor token for a different"
                         " user (%s != %s)", wft->subject,
                         best->token.webkdc_factor.subject);
            continue;
        }

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
 * Merge an array of webkdc-proxy tokens into a single token, which we'll then
 * use for subsequent operations.  Takes the context, the array of
 * credentials, the maximum age in seconds for tokens to contribute to the
 * session factors, and a place to store the newly created webkdc-proxy token.
 *
 * We use the following logic to merge webkdc-proxy tokens:
 *
 * 1. Expired tokens are discarded.
 * 2. Tokens whose subject do not match the subject of the last webkdc-proxy
 *    token in the list are discarded.
 * 3. Tokens whose initial factors are a subset of the accumulated factors
 *    and which do not add krb5 capability are discarded.
 * 4. The krb5 data is added if not already present, and the expiration is
 *    set to the token with the krb5 data and the proxy type changed to krb5.
 * 5. Initial factors are merged between all webkdc-proxy tokens, with the
 *    expiration set to the nearest expiration of all contributing tokens.
 * 6. Creation time is set to the oldest time of the tokens if we pull from
 *    multiple tokens.  This has to be oldest, not newest or the current time,
 *    to correctly handle when to lift initial factors into session factors.
 * 7. Session factors are merged from a webkdc-proxy token if and only if the
 *    webkdc-proxy token contributes in some way to the result.
 * 8. Initial factors also count as session factors if the contributing
 *    webkdc-proxy token is within its freshness limit as specified in seconds
 *    in the session_limit parameter.  Otherwise, session factors are used
 *    as-is.
 *
 * While processing the webkdc-proxy tokens, we also reject, with an error,
 * the credential merge if there is a subject or proxy subject mismatch
 * between the provided credentials.
 */
int
wai_token_merge_webkdc_proxy(struct webauth_context *ctx,
                             apr_array_header_t *creds,
                             unsigned long session_limit,
                             struct webauth_token **result)
{
    const char *subject = NULL, *proxy_subject = NULL;
    struct webauth_token *token;
    struct webauth_token_webkdc_proxy *wkproxy;
    struct webauth_token_webkdc_proxy *best = NULL;
    struct webauth_factors *extra;
    struct webauth_factors *factors = NULL, *sfactors = NULL;
    time_t now;
    int i, s;

    /* Return a NULL webkdc-proxy token if we have no tokens. */
    *result = NULL;
    if (creds->nelts == 0)
        return WA_ERR_NONE;

    /* Ensure all time calculations use a consistent basis. */
    now = time(NULL);

    /*
     * Grab the last token and use it to determine the subject and proxy
     * subject that all remaining tokens must have to be merged.  The subject
     * must match across all tokens.  The proxy subject must either start with
     * "WEBKDC:" (indicated by a NULL proxy_subject) or must match.
     */
    token = APR_ARRAY_IDX(creds, creds->nelts - 1, struct webauth_token *);
    if (token->type != WA_TOKEN_WEBKDC_PROXY)
        return token_type_error(ctx, token->type, "webkdc-proxy");
    wkproxy = &token->token.webkdc_proxy;
    subject = wkproxy->subject;
    if (strncmp(wkproxy->proxy_subject, "WEBKDC:", 7) != 0)
        proxy_subject = wkproxy->proxy_subject;

    /*
     * We merge the proxy tokens in reverse order, since any proxy tokens that
     * we created via fresh login tokens should take precedence over anything
     * that we had from older cookies.  We added those to the end of the
     * array.
     */
    for (i = creds->nelts - 1; i >= 0; i--) {
        struct webauth_factors *cfactors;

        token = APR_ARRAY_IDX(creds, i, struct webauth_token *);
        if (token->type != WA_TOKEN_WEBKDC_PROXY)
            return token_type_error(ctx, token->type, "webkdc-proxy");
        wkproxy = &token->token.webkdc_proxy;

        /*
         * Check the subject.
         *
         * Don't reject mismatches with an error.  When two users share a
         * device, mismatches can occur if one user goes to a forced login
         * or session factor required page while there are still single
         * sign-on cookies for the other user.  This is arguably user error
         * for not logging out, but aborting the whole authentication doesn't
         * help anything.
         */
        if (strcmp(subject, wkproxy->subject) != 0) {
            wai_log_info(ctx, "ignoring webkdc-proxy token for a different"
                         " user (%s != %s)", wkproxy->subject, subject);
            continue;
        }

        /*
         * Check the proxy subject.  Users only get SSO webkdc-proxy tokens,
         * so there's no reason not to be strict here.
         */
        if (proxy_subject == NULL) {
            if (strncmp(wkproxy->proxy_subject, "WEBKDC:", 7) != 0) {
                s = WA_ERR_TOKEN_REJECTED;
                wai_error_set(ctx, s, "proxy subject mismatch: %s is not SSO",
                              wkproxy->proxy_subject);
                return s;
            }
        } else {
            if (strcmp(proxy_subject, wkproxy->proxy_subject) != 0) {
                s = WA_ERR_TOKEN_REJECTED;
                wai_error_set(ctx, s, "proxy subject mismatch: %s != %s",
                              proxy_subject, wkproxy->proxy_subject);
                return s;
            }
        }

        /* Discard all expired tokens. */
        if (wkproxy->expiration <= now) {
            wai_log_info(ctx, "ignoring expired webkdc-proxy token for %s"
                         " (expired at %lu)", wkproxy->subject,
                         (unsigned long) wkproxy->expiration);
            continue;
        }

        /* best will be NULL if this is the first valid token we see. */
        if (best == NULL) {
            *result = apr_pmemdup(ctx->pool, token, sizeof(**result));
            best = &(*result)->token.webkdc_proxy;
            factors = webauth_factors_parse(ctx, best->initial_factors);
            if ((unsigned long) best->creation >= now - session_limit)
                sfactors = webauth_factors_parse(ctx, best->initial_factors);
            else
                sfactors = webauth_factors_parse(ctx, best->session_factors);
            continue;
        }

        /*
         * We have a best token already and we have seen an additional token.
         * We may be merging in its information.  Parse out its factors.
         */
        cfactors = webauth_factors_parse(ctx, wkproxy->initial_factors);

        /*
         * If there are no new factors and it can't contribute a better
         * authenticator, there's nothing of interest.  Move on.
         */
        if (webauth_factors_satisfies(ctx, factors, cfactors)
            && (strcmp(best->proxy_type, "krb5") == 0
                || strcmp(wkproxy->proxy_type, "krb5") != 0))
            continue;

        /*
         * Grab the krb5 authenticator if that's better than what we have.  If
         * we do this, also update the proxy subject, since it's probably more
         * specific.
         */
        if (strcmp(best->proxy_type, "krb5") != 0
            && strcmp(wkproxy->proxy_type, "krb5") == 0) {
            best->data = wkproxy->data;
            best->data_len = wkproxy->data_len;
            best->proxy_type = wkproxy->proxy_type;
            best->proxy_subject = wkproxy->proxy_subject;
        }

        /* Add on its initial factors to our accumulated ones. */
        factors = webauth_factors_union(ctx, factors, cfactors);

        /*
         * webkdc-proxy tokens contribute their initial factors to session
         * factors if they're still fresh.
         */
        if ((unsigned long) wkproxy->creation >= now - session_limit)
            sfactors = webauth_factors_union(ctx, sfactors, cfactors);
        else {
            extra = webauth_factors_parse(ctx, wkproxy->session_factors);
            sfactors = webauth_factors_union(ctx, sfactors, extra);
        }

        /* Set expiration and creation times to the oldest of the tokens. */
        if (wkproxy->expiration < best->expiration)
            best->expiration = wkproxy->expiration;
        if (wkproxy->creation < best->creation)
            best->creation = wkproxy->creation;

        /* Set LoA to the highest of the tokens. */
        if (wkproxy->loa > best->loa)
            best->loa = wkproxy->loa;
    }

    /* If *result is NULL, all tokens were expired. */
    if (*result == NULL)
        return WA_ERR_NONE;

    /* Set the result webkdc-proxy factors to our assembled ones. */
    best->initial_factors = webauth_factors_string(ctx, factors);
    best->session_factors = webauth_factors_string(ctx, sfactors);

    /* All done.  *result contains the newly-generated token. */
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
    if (strcmp(wft->subject, wkproxy->subject) != 0) {
        wai_log_info(ctx, "ignoring webkdc-factor token for a different user"
                     " (%s != %s)", wft->subject, wkproxy->subject);
        return WA_ERR_NONE;
    }

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
