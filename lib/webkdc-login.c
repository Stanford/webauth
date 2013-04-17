/*
 * WebKDC interface for processing a <requestTokenRequest>.
 *
 * These interfaces are used by the WebKDC implementation to process a
 * <requestTokenRequest> from the WebLogin server, representing a user's
 * attempt to authenticate to a WAS, either with proxy tokens or with a
 * username and authentication credential, or both.
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

#include <apr_lib.h>
#include <assert.h>

#include <lib/internal.h>
#include <webauth/basic.h>
#include <webauth/keys.h>
#include <webauth/krb5.h>
#include <webauth/factors.h>
#include <webauth/tokens.h>
#include <webauth/webkdc.h>


/*
 * Given a Kerberos principal for an authenticated user, derive the WebAuth
 * authenticated subject based on the local_realms parameter of the WebKDC
 * configuration.  The subject may be identical to the Kerberos principal, but
 * often means stripping off the realm or applying Kerberos local name
 * conversion.  Returns the subject in newly allocated pool memory.  Returns a
 * status code on failure.
 *
 * The local_realms array in the WebKDC configuration may either be a single
 * keyword or may be a list of realms.  If it is a keyword, it's one of
 * "local" or "none".  "local" means to apply Kerberos local name conversion.
 * "none" means to use the principal name without modification.  Otherwise,
 * it's taken to be a list of realms, and any of those realms are stripped
 * from the principal.  Any principal not in one of those realms is retained
 * as a fully-qualified principal name.  If local_realms is not set, assume
 * "local", which is the default.
 */
static int
canonicalize_user(struct webauth_context *ctx, struct webauth_krb5 *kc,
                  const char **result)
{
    int status, i;
    char *subject;
    enum webauth_krb5_canon canonicalize = WA_KRB5_CANON_LOCAL;

    *result = NULL;
    if (ctx->webkdc->local_realms->nelts > 0) {
        const char *local;
        char *realm;

        local = APR_ARRAY_IDX(ctx->webkdc->local_realms, 0, const char *);
        if (strcmp(local, "none") == 0)
            canonicalize = WA_KRB5_CANON_NONE;
        else if (strcmp(local, "local") == 0)
            canonicalize = WA_KRB5_CANON_LOCAL;
        else {
            canonicalize = WA_KRB5_CANON_NONE;
            status = webauth_krb5_get_realm(ctx, kc, &realm);
            if (status != WA_ERR_NONE)
                return status;
            for (i = 0; i < ctx->webkdc->local_realms->nelts; i++) {
                local = APR_ARRAY_IDX(ctx->webkdc->local_realms, i,
                                      const char *);
                if (strcmp(local, realm) == 0)
                    canonicalize = WA_KRB5_CANON_STRIP;
            }
        }
    }

    /*
     * We now know the canonicalization method we're using, so we can retrieve
     * the principal from the context.  Move the result into the main WebAuth
     * context pool.
     */
    status = webauth_krb5_get_principal(ctx, kc, &subject, canonicalize);
    if (status != WA_ERR_NONE)
        return status;
    *result = apr_pstrdup(ctx->pool, subject);
    return WA_ERR_NONE;
}


/*
 * Check that the realm of the authenticated principal is in the list of
 * permitted realms, or that the list of realms is empty.  Returns a WebAuth
 * error code on failure to determine the realm.  If the user's realm is not
 * permitted, sets the login error to WA_PEC_USER_REJECTED and the login
 * message appropriately.
 */
static int
realm_permitted(struct webauth_context *ctx, struct webauth_krb5 *kc,
                struct webauth_webkdc_login_response *response)
{
    int status, i;
    char *realm;
    const char *allow;
    bool okay = false;

    /* If we aren't restricting the realms, always return true. */
    if (ctx->webkdc->permitted_realms->nelts == 0)
        return WA_ERR_NONE;

    /* Get the realm. */
    status = webauth_krb5_get_realm(ctx, kc, &realm);
    if (status != WA_ERR_NONE)
        return status;

    /* Check against the configured permitted realms. */
    for (i = 0; i < ctx->webkdc->permitted_realms->nelts; i++) {
        allow = APR_ARRAY_IDX(ctx->webkdc->permitted_realms, i, const char *);
        if (strcmp(allow, realm) == 0) {
            okay = true;
            break;
        }
    }
    if (!okay) {
        response->login_error = WA_PEC_USER_REJECTED;
        response->login_message
            = apr_psprintf(ctx->pool, "realm %s is not permitted", realm);
    }
    return WA_ERR_NONE;
}


/*
 * Attempt an OTP authentication, which is a user authentication validatation
 * via the user information service.  On success, generate a new webkdc-proxy
 * token based on that information and store it in the token argument.  If the
 * validate call returned persistent factors, also create a webkdc-factor
 * token and store that in the wkfactor argument.  On login failure, store the
 * error code and message in the response.  On a more fundamental failure,
 * return an error code.
 */
static int
do_otp(struct webauth_context *ctx,
       struct webauth_webkdc_login_response *response,
       struct webauth_token_login *login,
       const char *ip, const char *login_state,
       struct webauth_token **wkproxy, struct webauth_token **wkfactor)
{
    int status;
    struct webauth_user_validate *validate;
    struct webauth_token_webkdc_factor *ft;
    struct webauth_token_webkdc_proxy *pt;
    time_t max_expiration;

    /* Do the remote validation call. */
    if (ctx->user == NULL) {
        wai_error_set(ctx, WA_ERR_UNIMPLEMENTED, "no OTP configuration");
        return WA_ERR_UNIMPLEMENTED;
    }
    status = webauth_user_validate(ctx, login->username, ip, login->otp,
                                   login->otp_type, login_state, &validate);
    if (status != WA_ERR_NONE)
        return status;

    /*
     * If validation failed, set the login error code and return.  If we have
     * a user message or login state, use WA_PEC_LOGIN_REJECTED instead so that
     * mod_webkdc will pass a <requestTokenResponse> back to the WebLogin
     * server, including the message and/or state.
     */
    if (!validate->success) {
        if (validate->user_message == NULL && validate->login_state == NULL) {
            response->login_error = WA_PEC_LOGIN_FAILED;
            response->login_message = "login incorrect";
        } else {
            response->login_error = WA_PEC_LOGIN_REJECTED;
            response->login_message = "login rejected by validation service";
            response->user_message = validate->user_message;
            response->login_state = validate->login_state;
        }
        return WA_ERR_NONE;
    }

    /*
     * Adjust for old versions of the user information service that don't
     * return an expiration time for factors.
     *
     * FIXME: Arbitrary magic 10 hour expiration time.
     */
    if (validate->factors_expiration == 0)
        validate->factors_expiration = time(NULL) + 60 * 60 * 10;

    /* Create the resulting webkdc-proxy token. */
    *wkproxy = apr_pcalloc(ctx->pool, sizeof(struct webauth_token));
    (*wkproxy)->type = WA_TOKEN_WEBKDC_PROXY;
    pt = &(*wkproxy)->token.webkdc_proxy;
    pt->subject = login->username;
    pt->proxy_type = "otp";
    pt->proxy_subject = "WEBKDC:otp";
    pt->data = login->username;
    pt->data_len = strlen(login->username);
    pt->initial_factors = webauth_factors_string(ctx, validate->factors);
    pt->session_factors = pt->initial_factors;
    pt->loa = validate->loa;
    pt->expiration = validate->factors_expiration;
    if (ctx->webkdc->proxy_lifetime > 0) {
        max_expiration = time(NULL) + ctx->webkdc->proxy_lifetime;
        if (pt->expiration > max_expiration)
            pt->expiration = max_expiration;
    }
    pt->creation = time(NULL);

    /*
     * If there are any persistent-factor tokens, create a webkdc-factor
     * token and add it to the response.
     */
    if (validate->persistent != NULL) {
        *wkfactor = apr_pcalloc(ctx->pool, sizeof(struct webauth_token));
        (*wkfactor)->type = WA_TOKEN_WEBKDC_FACTOR;
        ft = &(*wkfactor)->token.webkdc_factor;
        ft->subject = login->username;
        ft->factors = webauth_factors_string(ctx, validate->persistent);
        ft->expiration = validate->persistent_expiration;
        ft->creation = time(NULL);
    }
    return WA_ERR_NONE;
}


/*
 * Attempt a username and password login.  On success, generate a new
 * webkdc-proxy token based on that information and store it in the token
 * argument.  On login failure, store the error code and message in the
 * response.  On a more fundamental failure, return an error code.
 */
static int
do_login(struct webauth_context *ctx,
         struct webauth_webkdc_login_response *response,
         struct webauth_token_login *login,
         struct webauth_token **wkproxy)
{
    int status;
    struct webauth_krb5 *kc;
    char *webkdc;
    const char *subject;
    void *tgt;
    size_t tgt_len;
    time_t expires;
    struct webauth_token_webkdc_proxy *pt;

    status = webauth_krb5_new(ctx, &kc);
    if (status != WA_ERR_NONE)
        return status;
    status = webauth_krb5_init_via_password(ctx, kc, login->username,
                                            login->password, NULL,
                                            ctx->webkdc->keytab_path,
                                            ctx->webkdc->principal,
                                            NULL, &webkdc);
    switch (status) {
    case WA_ERR_NONE:
        break;
    case WA_ERR_LOGIN_FAILED:
        response->login_error = WA_PEC_LOGIN_FAILED;
        response->login_message = webauth_error_message(ctx, status);
        status = WA_ERR_NONE;
        goto cleanup;
    case WA_ERR_CREDS_EXPIRED:
        response->login_error = WA_PEC_CREDS_EXPIRED;
        response->login_message = webauth_error_message(ctx, status);
        status = WA_ERR_NONE;
        goto cleanup;
    case WA_ERR_USER_REJECTED:
        response->login_error = WA_PEC_USER_REJECTED;
        response->login_message = webauth_error_message(ctx, status);
        status = WA_ERR_NONE;
        goto cleanup;
    default:
        return status;
    }

    /*
     * webauth_krb5_init_via_password determined the principal of the WebKDC
     * service to which we just authenticated and stored that information in
     * webkdc, but we need to add the krb5 prefix.
     */
    webkdc = apr_pstrcat(ctx->pool, "krb5:", webkdc, NULL);

    /*
     * Check if the realm of the authenticated principal is permitted and
     * then canonicalize the user's identity.
     */
    status = realm_permitted(ctx, kc, response);
    if (status != WA_ERR_NONE || response->login_error != 0)
        goto cleanup;
    status = canonicalize_user(ctx, kc, &subject);
    if (status != WA_ERR_NONE)
        goto cleanup;

    /*
     * Export the ticket-granting ticket for the webkdc-proxy token and move
     * it into the context pool from the Kerberos context pool.
     */
    status = webauth_krb5_export_cred(ctx, kc, NULL, &tgt, &tgt_len, &expires);
    if (status != WA_ERR_NONE)
        goto cleanup;
    tgt = apr_pmemdup(ctx->pool, tgt, tgt_len);

    /*
     * We now have everything we need to create the webkdc-proxy token.  We've
     * already copied all this stuff into a pool, so there is no need to copy
     * again.
     */
    *wkproxy = apr_pcalloc(ctx->pool, sizeof(struct webauth_token));
    (*wkproxy)->type = WA_TOKEN_WEBKDC_PROXY;
    pt = &(*wkproxy)->token.webkdc_proxy;
    pt->subject = subject;
    pt->proxy_type = "krb5";
    pt->proxy_subject = apr_pstrcat(ctx->pool, "WEBKDC:", webkdc, NULL);
    pt->data = tgt;
    pt->data_len = tgt_len;
    pt->initial_factors = WA_FA_PASSWORD;
    pt->session_factors = pt->initial_factors;
    if (ctx->webkdc->proxy_lifetime == 0)
        pt->expiration = expires;
    else {
        pt->expiration = time(NULL) + ctx->webkdc->proxy_lifetime;
        if (pt->expiration > expires)
            pt->expiration = expires;
    }
    pt->creation = time(NULL);

cleanup:
    webauth_krb5_free(ctx, kc);
    return status;
}


/*
 * Given a list of webkdc-factor tokens and the subject we're authenticating,
 * walk through the list, finding all unexpired tokens for that subject, and
 * combine their factors.  Return the new factor set as newly-allocated pool
 * memory.
 */
static struct webauth_factors *
combine_webkdc_factors(struct webauth_context *ctx,
                       const apr_array_header_t *wkfactors,
                       const char *subject)
{
    time_t now;
    struct webauth_factors *factors;
    int i;

    /* Create an empty factors set to start with. */
    factors = webauth_factors_new(ctx, NULL);

    /* If the array is empty, we have nothing to do. */
    if (apr_is_empty_array(wkfactors))
        return factors;

    /*
     * Walk through all of the factor tokens and add the factors from any
     * unexpired tokens that match the subject.  We don't diagnose unexpected
     * token types here; that should be done elsewhere.
     */
    now = time(NULL);
    for (i = 0; i < wkfactors->nelts; i++) {
        struct webauth_token *token;
        struct webauth_factors *extra;
        struct webauth_token_webkdc_factor *wkf;

        /* Extract and set a pointer to the next webkdc-factor token. */
        token = APR_ARRAY_IDX(wkfactors, i, struct webauth_token *);
        if (token->type != WA_TOKEN_WEBKDC_FACTOR)
            continue;
        wkf = &token->token.webkdc_factor;

        /* Discard all expired and non-matching tokens. */
        if (wkf->expiration <= now)
            continue;
        if (strcmp(wkf->subject, subject) != 0)
            continue;

        /* Merge in the factor information. */
        extra = webauth_factors_parse(ctx, wkf->factors);
        factors = webauth_factors_union(ctx, factors, extra);
    }
    return factors;
}


/*
 * Given a list of webkdc-factor tokens and a valid threshold time, mark as
 * expired every webkdc-factor token whose creation date lies before the valid
 * threshold time.  Modifies the array and webkdc-factor tokens in place.
 * Returns true if any were invalidated, false otherwise.
 */
static bool
maybe_invalidate_webkdc_factors(struct webauth_context *ctx,
                                apr_array_header_t *wkfactors,
                                time_t valid_threshold)
{
    bool invalidated = false;
    time_t now;
    int i;

    /* Nothing to do if no tokens or valid_threshold time. */
    if (valid_threshold == 0)
        return false;
    if (apr_is_empty_array(wkfactors))
        return false;

    /*
     * Walk the array looking for invalid tokens.  Note that we ignore the
     * subject, since that won't make a difference for our results.  We also
     * don't diagnose incorrect token types, since that will be done
     * elsewhere.
     */
    now = time(NULL);
    for (i = 0; i < wkfactors->nelts; i++) {
        struct webauth_token *token;
        struct webauth_token_webkdc_factor *wkf;

        /* Extract and set a pointer to the next webkdc-factor token. */
        token = APR_ARRAY_IDX(wkfactors, i, struct webauth_token *);
        if (token->type != WA_TOKEN_WEBKDC_FACTOR)
            continue;
        wkf = &token->token.webkdc_factor;

        /* Expire the token if the creation time is too early. */
        if (wkf->creation < valid_threshold) {
            wai_log_notice(ctx, "invalidating webkdc-factor token for %s"
                           " (creation %lu < %lu)", wkf->subject,
                           (unsigned long) wkf->creation,
                           (unsigned long) valid_threshold);
            wkf->expiration = now - 1;
            invalidated = true;
        }
    }
    return invalidated;
}


/*
 * Given the login request token, the remote IP address, the current
 * webkdc-proxy token, and the current list of webkdc-factor tokens, call the
 * user information service and store the results in the provided
 * webauth_user_info struct.  Returns a WebAuth status code.
 *
 * We have to do a bunch of factor math to figure out whether we need to
 * request random multifactor and to construct the current authentication
 * factors for the user information service.  For variables in this function,
 * an initial "i" indicates they're for the initial factors and an initial "s"
 * indicates that they're for the session factors.
 */
static int
get_user_info(struct webauth_context *ctx,
              const struct webauth_token_request *request,
              const char *remote_ip, const struct webauth_token *wkproxy,
              const apr_array_header_t *wkfactors,
              struct webauth_user_info **info)
{
    const struct webauth_token_webkdc_proxy *wkp;
    struct webauth_factors *ifactors, *iwkfactors, *sfactors, *swkfactors;
    struct webauth_factors *random, *extra;
    bool randmf = false;
    const char *factors;

    /* Parse the request factors. */
    ifactors = webauth_factors_parse(ctx, request->initial_factors);
    sfactors = webauth_factors_parse(ctx, request->session_factors);

    /* Create a webauth_factors struct representing random multifactor. */
    random = webauth_factors_parse(ctx, WA_FA_RANDOM_MULTIFACTOR);

    /* Parse the factors from the webkdc-proxy token. */
    wkp = &wkproxy->token.webkdc_proxy;
    iwkfactors = webauth_factors_parse(ctx, wkp->initial_factors);
    swkfactors = webauth_factors_parse(ctx, wkp->session_factors);

    /* Add the factors from the webkdc-factor tokens. */
    extra = combine_webkdc_factors(ctx, wkfactors, wkp->subject);
    iwkfactors = webauth_factors_union(ctx, iwkfactors, extra);
    swkfactors = webauth_factors_union(ctx, swkfactors, extra);

    /*
     * Determine if we're doing random multifactor.
     *
     * We will request random multifactor if either the initial or session
     * requirements in the request include random multifactor and random
     * multifactor is not satisfied by the corresponding factors in the
     * webkdc-proxy token combined with the webkdc-factor tokens.
     */
    if (webauth_factors_contains(ctx, ifactors, WA_FA_RANDOM_MULTIFACTOR))
        if (!webauth_factors_satisfies(ctx, iwkfactors, random))
            randmf = true;
    if (webauth_factors_contains(ctx, sfactors, WA_FA_RANDOM_MULTIFACTOR))
        if (!webauth_factors_satisfies(ctx, swkfactors, random))
            randmf = true;

    /* Call the user information service. */
    factors = webauth_factors_string(ctx, iwkfactors);
    return webauth_user_info(ctx, wkp->subject, remote_ip, randmf,
                             request->return_url, factors, info);
}


/*
 * Given the request, the response, our webkdc-proxy token, any webkdc-factor
 * tokens, a flag saying whether we did a login, and a struct to fill in with
 * the user information, call the user information service and flesh out our
 * response data and webkdc-proxy token with the results.  If the user
 * information service says to invalidate webkdc-factor tokens, do so and then
 * retry the call.
 */
static int
add_user_info(struct webauth_context *ctx,
              const struct webauth_token_request *request,
              const char *remote_ip,
              struct webauth_webkdc_login_response **response,
              struct webauth_token *wkproxy,
              apr_array_header_t *wkfactors,
              bool did_login, struct webauth_user_info **info)
{
    struct webauth_factors *iwkfactors, *swkfactors, *extra;
    time_t valid_threshold;
    int s;
    struct webauth_token_webkdc_proxy *wkp = &wkproxy->token.webkdc_proxy;

    /* Call the user information service. */
    s = get_user_info(ctx, request, remote_ip, wkproxy, wkfactors, info);
    if (s != WA_ERR_NONE)
        return s;

    /*
     * If the user information service provides an invalid_before time, expire
     * any webkdc-factor tokens that were created before that time and then
     * redo the user information service call, since we may now have different
     * authentication factors.
     */
    valid_threshold = (*info)->valid_threshold;
    if (maybe_invalidate_webkdc_factors(ctx, wkfactors, valid_threshold)) {
        s = get_user_info(ctx, request, remote_ip, wkproxy, wkfactors, info);
        if (s != WA_ERR_NONE)
            return s;
    }

    /* Add results from the user information service to the response. */
    if (did_login)
        (*response)->logins = (*info)->logins;
    (*response)->password_expires = (*info)->password_expires;
    (*response)->user_message = (*info)->user_message;
    (*response)->login_state = (*info)->login_state;

    /* Cap the user's LoA at the maximum allowed by the service. */
    if (wkp->loa > (*info)->max_loa)
        wkp->loa = (*info)->max_loa;

    /* Parse the current factors from the webkdc-proxy token. */
    iwkfactors = webauth_factors_parse(ctx, wkp->initial_factors);
    swkfactors = webauth_factors_parse(ctx, wkp->session_factors);

    /* Add the factors from the webkdc-factor tokens. */
    extra = combine_webkdc_factors(ctx, wkfactors, wkp->subject);
    iwkfactors = webauth_factors_union(ctx, iwkfactors, extra);
    swkfactors = webauth_factors_union(ctx, swkfactors, extra);

    /*
     * Add the random multifactor factor to the factors of our webkdc-proxy
     * token if we did random multifactor and random multifactor was not
     * already satisfied by existing factors.
     */
    if ((*info)->random_multifactor) {
        struct webauth_factors *random;

        random = webauth_factors_parse(ctx, WA_FA_RANDOM_MULTIFACTOR);
        iwkfactors = webauth_factors_union(ctx, iwkfactors, random);
        swkfactors = webauth_factors_union(ctx, swkfactors, random);
    }

    /* Add additional factors if we have any and we did a login. */
    if (did_login && (*info)->additional != NULL) {
        const struct webauth_factors *add;

        add = (*info)->additional;
        iwkfactors = webauth_factors_union(ctx, iwkfactors, add);
        swkfactors = webauth_factors_union(ctx, swkfactors, add);
    }

    /* Update our factors in case we changed something. */
    wkp->initial_factors = webauth_factors_string(ctx, iwkfactors);
    wkp->session_factors = webauth_factors_string(ctx, swkfactors);
    return WA_ERR_NONE;
}


/*
 * Given the request from the WebAuth Application Server, the current
 * accumulated response, the current merged webkdc-proxy token, and the user
 * information (which may be NULL if there's no information service
 * configured), check whether multifactor authentication and a level of
 * assurance restriction is already satisfied or unnecessary, required, or
 * impossible.
 *
 * Returns WA_ERR_NONE and leaves request->login_error unchanged if any
 * multifactor requirements are satisfied.  Sets request->login_error if
 * multifactor is required or unavailable.  Returns an error code on errors in
 * processing.
 */
static int
check_multifactor(struct webauth_context *ctx,
                  const struct webauth_token_request *req,
                  struct webauth_webkdc_login_response *response,
                  struct webauth_token_webkdc_proxy *wkproxy,
                  struct webauth_user_info *info)
{
    struct webauth_factors *wanted, *swanted, *have, *shave;
    const struct webauth_factors *configured;

    /* Figure out what factors we want and have. */
    wanted = webauth_factors_parse(ctx, req->initial_factors);
    swanted = webauth_factors_parse(ctx, req->session_factors);
    have = webauth_factors_parse(ctx, wkproxy->initial_factors);
    shave = webauth_factors_parse(ctx, wkproxy->session_factors);

    /*
     * Check if there are factors required by user configuration.  If so, add
     * them to the initial factors that we require.
     */
    if (info != NULL && info->required != NULL)
        wanted = webauth_factors_union(ctx, wanted, info->required);

    /*
     * Second, check the level of assurance required.  If the user cannot
     * establish a sufficient level of assurance, punt immediately; we don't
     * care about the available factors in that case.
     */
    if (req->loa > wkproxy->loa) {
        if (info != NULL && req->loa > info->max_loa) {
            response->login_error = WA_PEC_LOA_UNAVAILABLE;
            response->login_message = "insufficient level of assurance";
            return WA_ERR_NONE;
        } else {
            response->login_error = WA_PEC_MULTIFACTOR_REQUIRED;
            response->login_message = "multifactor login required";
        }
    }

    /*
     * Third, see if the WAS-requested factors are already satisfied by the
     * factors that we have.  If not, choose the error message.  If the user
     * can't satisfy the factors at all, we'll change the error later.  Be
     * careful not to override errors from the LoA check.
     *
     * We assume that if the user needs factors they don't have but are
     * capable of getting, the correct next step is to force a multifactor
     * authentication.  This may not be the correct assumption always, but it
     * works for the most common cases.
     */
    if (webauth_factors_satisfies(ctx, have, wanted)) {
        if (webauth_factors_satisfies(ctx, shave, swanted)) {
            if (response->login_error == 0)
                return WA_ERR_NONE;
        } else if (response->login_error == 0) {
            response->login_error = WA_PEC_LOGIN_FORCED;
            response->login_message = "forced authentication, need to login";
        }
    } else {
        response->login_error = WA_PEC_MULTIFACTOR_REQUIRED;
        response->login_message = "multifactor login required";
    }

    /*
     * Fourth, remove the factors the user already has from the factors that
     * are required.  We do this before checking whether the desired factors
     * are satisfiable since the user may have factors that the user
     * information service doesn't know they can have.  We also only want to
     * report to WebLogin the additional factors the user needs but doesn't
     * have, not the full list that they've partially satisfied.
     */
    wanted = webauth_factors_subtract(ctx, wanted, have);
    swanted = webauth_factors_subtract(ctx, swanted, shave);

    /*
     * Finally, check if the WAS-requested factors can be satisfied by the
     * factors configured by the user.  We have to do a bit of work here to
     * turn the user's configured factors into a webauth_factors struct.
     *
     * Assume we can do password authentication even without user information.
     */
    if (info == NULL || info->factors == NULL)
        configured = webauth_factors_parse(ctx, WA_FA_PASSWORD);
    else
        configured = info->factors;
    response->factors_wanted = webauth_factors_union(ctx, wanted, swanted);
    response->factors_configured = configured;
    if (!webauth_factors_satisfies(ctx, configured, wanted)) {
        response->login_error = WA_PEC_MULTIFACTOR_UNAVAILABLE;
        response->login_message = "multifactor required but not configured";
    } else if (!webauth_factors_satisfies(ctx, configured, swanted)) {
        response->login_error = WA_PEC_MULTIFACTOR_UNAVAILABLE;
        response->login_message = "multifactor required but not configured";
    }
    return WA_ERR_NONE;
}


/*
 * Given the authenticated user and the destination site, determine the
 * permissible authentication identities for that destination site.  Stores
 * that list in a newly-allocated array, which may be set to NULL if there is
 * no identity ACL or if none of its entries apply to the current
 * authentication.  Returns an error code.
 */
static int
build_identity_list(struct webauth_context *ctx, const char *subject,
                    const char *target, const apr_array_header_t **result)
{
    int status;
    unsigned long line;
    apr_file_t *acl;
    apr_int32_t flags;
    apr_status_t code;
    char buf[BUFSIZ];
    char *p, *authn, *was, *authz, *last;
    apr_array_header_t *identities = NULL;

    /* If there is no identity ACL file, there is a NULL array. */
    *result = NULL;
    if (ctx->webkdc->id_acl_path == NULL)
        return WA_ERR_NONE;

    /* Open the identity ACL file. */
    flags = APR_FOPEN_READ | APR_FOPEN_BUFFERED | APR_FOPEN_NOCLEANUP;
    code = apr_file_open(&acl, ctx->webkdc->id_acl_path, flags,
                         APR_FPROT_OS_DEFAULT, ctx->pool);
    if (code != APR_SUCCESS) {
        status = WA_ERR_FILE_OPENREAD;
        wai_error_set_apr(ctx, status, code, "identity ACL %s",
                          ctx->webkdc->id_acl_path);
        return status;
    }

    /*
     * Read the file line by line, and store the relevant potential
     * identities.  The format is:
     *
     *     <authn> <target> <authz>
     *
     * where <authn> is the user's actual authenticated identity, <target> is
     * the identity of the site to which the user is going, and <authz> is an
     * alternate authorization identity the user is allowed to express to that
     * site.
     */
    line = 0;
    while ((code = apr_file_gets(buf, sizeof(buf), acl)) == APR_SUCCESS) {
        line++;
        if (buf[strlen(buf) - 1] != '\n') {
            status = WA_ERR_FILE_READ;
            wai_error_set(ctx, status, "identity ACL %s line %lu too long",
                          ctx->webkdc->id_acl_path, line);
            goto done;
        }
        p = buf;
        while (apr_isspace(*p))
            p++;
        if (*p == '#' || *p == '\0')
            continue;
        authn = apr_strtok(p, " \t\r\n", &last);
        if (authn == NULL)
            continue;
        if (strcmp(subject, authn) != 0)
            continue;
        was = apr_strtok(NULL, " \t\r\n", &last);
        if (was == NULL) {
            status = WA_ERR_FILE_READ;
            wai_error_set(ctx, status, "missing target on identity ACL %s line"
                          " %lu", ctx->webkdc->id_acl_path, line);
            goto done;
        }
        if (strcmp(target, was) != 0)
            continue;
        authz = apr_strtok(NULL, " \t\r\n", &last);
        if (authz == NULL) {
            status = WA_ERR_FILE_READ;
            wai_error_set(ctx, status, "missing identity on identity ACL %s"
                          " line %lu", ctx->webkdc->id_acl_path, line);
            goto done;
        }
        if (identities == NULL)
            identities = apr_array_make(ctx->pool, 1, sizeof(char *));
        APR_ARRAY_PUSH(identities, char *) = apr_pstrdup(ctx->pool, authz);
    }
    if (code != APR_SUCCESS && code != APR_EOF) {
        status = WA_ERR_FILE_READ;
        wai_error_set_apr(ctx, status, code, "identity ACL %s",
                          ctx->webkdc->id_acl_path);
        goto done;
    }
    *result = identities;
    status = WA_ERR_NONE;

done:
    apr_file_close(acl);
    return status;
}


/*
 * Given the identity of a WAS and a webkdc-proxy token identifying the user,
 * obtain a Kerberos authenticator identifying that user to that WAS.  Store
 * it in the provided buffer.  Returns either WA_ERR_NONE on success or a
 * WebAuth error code.  On error, also set the WebAuth error message.
 */
static int
get_krb5_authenticator(struct webauth_context *ctx, const char *server,
                       struct webauth_token_webkdc_proxy *wkproxy,
                       void **auth, size_t *auth_len)
{
    int status;
    struct webauth_krb5 *kc;
    void *data;

    *auth = NULL;
    status = webauth_krb5_new(ctx, &kc);
    if (status != WA_ERR_NONE)
        return status;

    /*
     * FIXME: Probably need to examine errors a little more closely to
     * determine if we should return a proxy-token error or a server-failure.
     */
    status = webauth_krb5_import_cred(ctx, kc, wkproxy->data,
                                      wkproxy->data_len, NULL);
    if (status != WA_ERR_NONE)
        goto done;

    /*
     * Generate the Kerberos authenticator.
     *
     * FIXME: Probably need to examine errors a little more closely to
     * determine if we should return a proxy-token error or a server-failure.
     */
    if (strncmp(server, "krb5:", 5) == 0)
        server += 5;
    status = webauth_krb5_make_auth(ctx, kc, server, &data, auth_len);
    if (status == WA_ERR_NONE)
        *auth = apr_pmemdup(ctx->pool, data, *auth_len);

done:
    webauth_krb5_free(ctx, kc);
    return status;
}


/*
 * Given a WebKDC proxy token and a request token, create the id token
 * requested by the WAS and store it in the response.  At this point, we've
 * already done all required checks and ensured we have a WebKDC proxy token,
 * so this just involves setting the correct fields.  Returns a status code on
 * any sort of internal WebAuth error.
 */
static int
create_id_token(struct webauth_context *ctx,
                const struct webauth_token_request *request,
                const struct webauth_token_webkdc_service *service,
                struct webauth_token_webkdc_proxy *wkproxy,
                struct webauth_webkdc_login_response *response,
                const struct webauth_keyring *ring)
{
    int status;
    void *krb5_auth;
    size_t krb5_auth_len;
    struct webauth_token token;
    struct webauth_token_id *id;

    memset(&token, 0, sizeof(token));
    token.type = WA_TOKEN_ID;
    id = &token.token.id;
    id->subject = wkproxy->subject;
    id->authz_subject = response->authz_subject;
    id->auth = request->auth;
    if (strcmp(request->auth, "krb5") == 0) {
        status = get_krb5_authenticator(ctx, service->subject, wkproxy,
                                        &krb5_auth, &krb5_auth_len);
        if (status == WA_ERR_KRB5) {
            response->login_error = WA_PEC_PROXY_TOKEN_INVALID;
            response->login_message = webauth_error_message(ctx, status);
            return WA_ERR_NONE;
        } else if (status != WA_ERR_NONE)
            return status;
        id->auth_data = krb5_auth;
        id->auth_data_len = krb5_auth_len;
    }
    id->expiration = wkproxy->expiration;
    id->initial_factors = wkproxy->initial_factors;
    id->session_factors = wkproxy->session_factors;
    id->loa = wkproxy->loa;

    /* Encode the token and store the resulting string. */
    response->result_type = "id";
    return webauth_token_encode(ctx, &token, ring, &response->result);
}


/*
 * Given a WebKDC proxy token and a request token, create the proxy token
 * requested by the WAS and store it in the response.  At this point, we've
 * already done all required checks and ensured we have a WebKDC proxy token,
 * so this just involves setting the correct fields.  Returns a status code on
 * any sort of internal WebAuth error.
 *
 * This function needs the WebKDC keyring, since it has to encode the
 * embedded webkdc-proxy token in the WebKDC's private key.  The first keyring
 * is the session keyring for the enclosing proxy token, and the second is the
 * WebKDC's private keyring.
 */
static int
create_proxy_token(struct webauth_context *ctx,
                   const struct webauth_token_request *request,
                   const struct webauth_token_webkdc_service *service,
                   struct webauth_token_webkdc_proxy *wkproxy,
                   struct webauth_webkdc_login_response *response,
                   const struct webauth_keyring *session,
                   const struct webauth_keyring *ring)
{
    int status;
    struct webauth_token token, subtoken;
    struct webauth_token_proxy *proxy;

    /* Create the easy portions of the proxy token. */
    memset(&token, 0, sizeof(token));
    token.type = WA_TOKEN_PROXY;
    proxy = &token.token.proxy;
    proxy->subject = wkproxy->subject;
    proxy->authz_subject = response->authz_subject;
    proxy->type = request->proxy_type;
    proxy->initial_factors = wkproxy->initial_factors;
    proxy->session_factors = wkproxy->session_factors;
    proxy->loa = wkproxy->loa;
    proxy->expiration = wkproxy->expiration;

    /* Create the embedded webkdc-proxy token and limit its scope. */
    memset(&subtoken, 0, sizeof(subtoken));
    subtoken.type = WA_TOKEN_WEBKDC_PROXY;
    subtoken.token.webkdc_proxy = *wkproxy;
    subtoken.token.webkdc_proxy.proxy_subject = service->subject;
    subtoken.token.webkdc_proxy.creation = 0;
    status = webauth_token_encode_raw(ctx, &subtoken, ring,
                                      &proxy->webkdc_proxy,
                                      &proxy->webkdc_proxy_len);
    if (status != WA_ERR_NONE)
        return status;

    /* Encode the token and store the resulting string. */
    response->result_type = "proxy";
    return webauth_token_encode(ctx, &token, session, &response->result);
}


/*
 * Given a message, scan it for whitespace or double quotes.  If there are
 * any, enclose it in double quotes and escape any inner double quotes.
 */
static const char *
log_escape(apr_pool_t *pool, const char *message)
{
    size_t length = 0;
    size_t quotes = 0;
    bool escape = false;
    const char *p;
    char *q, *result;

    /* Convert NULL strings into the empty string for logging. */
    if (message == NULL)
        return "";

    /*
     * Scan the string for whitespace or double quotes.  Count double quotes,
     * since we're going to double each one.
     */
    for (p = message; *p != '\0'; p++) {
        length++;
        if (apr_isspace(*p))
            escape = true;
        else if (*p == '"') {
            escape = true;
            quotes++;
        }
    };

    /* If nothing special is going on, return the string verbatim. */
    if (!escape)
        return message;

    /*
     * Allocate room for the leading and trailing quotes plus an extra
     * character for each quote we're doubling.
     */
    result = apr_palloc(pool, length + quotes + 3);
    result[0] = '"';
    for (p = message, q = result + 1; *p != '\0'; p++, q++) {
        *q = *p;
        if (*p == '"')
            *q++ = '"';
    }
    *q++ = '"';
    *q++ = '\0';
    return result;
}


/*
 * Add a given key/value attribute to the log message (given as a buffer).
 * Escapes the value if necessary, and handles NULL values.
 */
static void
log_attribute(struct buffer *message, const char *key, const char *value)
{
    const char *escaped;

    if (message->used != 0)
        wai_buffer_append(message, " ", 1);
    escaped = log_escape(message->pool, value);
    wai_buffer_append_sprintf(message, "%s=%s", key, escaped);
}


/*
 * Log the login request.  We do this once we determine whether the request
 * will be successful or not, as the last thing that we do before returning to
 * the caller.  This function constructs a general key/value pair log format.
 *
 * Takes the request, the response, the list of login tokens (used to log what
 * login methods were used), and the request token.
 */
static void
log_login(struct webauth_context *ctx,
          const struct webauth_webkdc_login_request *request,
          const struct webauth_webkdc_login_response *response,
          apr_array_header_t *logins,
          const struct webauth_token_request *req)
{
    struct buffer *message;
    const char *subject, *login_type;
    int i;

    /* We're going to accumulate the log message in this buffer. */
    message = wai_buffer_new(ctx->pool);

    /* Add basic information from the request. */
    log_attribute(message, "event",    "requestToken");
    log_attribute(message, "from",     request->client_ip);
    log_attribute(message, "clientIp", request->remote_ip);
    log_attribute(message, "server",   response->requester);
    log_attribute(message, "url",      response->return_url);

    /* If we were unable to authenticate the user, log them as <unknown>. */
    subject = (response->subject == NULL) ? "<unknown>" : response->subject;
    log_attribute(message, "user", subject);

    /* Gather information about the login tokens. */
    login_type = NULL;
    for (i = 0; i < logins->nelts; i++) {
        const struct webauth_token *token;

        token = APR_ARRAY_IDX(logins, i, struct webauth_token *);
        assert(token->type == WA_TOKEN_LOGIN);
        if (token->token.login.password != NULL) {
            if (login_type == NULL)
                login_type = "password";
            else if (strcmp(login_type, "otp") == 0)
                login_type = "password,otp";
        } else if (token->token.login.otp != NULL) {
            if (login_type == NULL)
                login_type = "otp";
            else if (strcmp(login_type, "password") == 0)
                login_type = "password,otp";
        }
    }

    /* Log information about the request. */
    log_attribute(message, "rtt", req->type);
    if (strcmp(req->type, "id") == 0)
        log_attribute(message, "sa", req->auth);
    else if (strcmp(req->type, "proxy") == 0)
        log_attribute(message, "pt", req->proxy_type);
    if (req->initial_factors != NULL)
        log_attribute(message, "wifactors", req->initial_factors);
    if (req->session_factors != NULL)
        log_attribute(message, "wsfactors", req->session_factors);
    if (req->loa > 0)
        wai_buffer_append_sprintf(message, " wloa=%lu", req->loa);
    if (req->options != NULL)
        log_attribute(message, "ro", req->options);
    if (login_type != NULL)
        log_attribute(message, "login", login_type);

    /* Log information about the authentication. */
    if (response->authz_subject != NULL)
        log_attribute(message, "authz", response->authz_subject);
    if (response->initial_factors != NULL)
        log_attribute(message, "ifactors", response->initial_factors);
    if (response->session_factors != NULL)
        log_attribute(message, "sfactors", response->session_factors);
    if (response->loa > 0)
        wai_buffer_append_sprintf(message, " loa=%lu", response->loa);

    /* Finally, log the error code and error message. */
    wai_buffer_append_sprintf(message, " lec=%d", response->login_error);
    if (response->login_message != NULL)
        log_attribute(message, "lem", response->login_message);

    /* Actually log the message. */
    wai_buffer_append(message, "", 1);
    wai_log_notice(ctx, "%s", message->data);
}


/*
 * Given the data from a <requestTokenRequest> login attempt, process that
 * attempted login and return the information for a <requestTokenResponse> in
 * a newly-allocated struct from pool memory.  All of the tokens included in
 * the input and output are the unencrypted struct representations; the caller
 * does the encryption or decryption and base64 conversion.
 *
 * Returns WA_ERR_NONE if the request was successfully processed, which
 * doesn't mean it succeeded; see the login_code attribute of the struct for
 * that.  Returns an error code if we were unable to process the struct even
 * to generate an error response.
 */
int
webauth_webkdc_login(struct webauth_context *ctx,
                     const struct webauth_webkdc_login_request *request,
                     struct webauth_webkdc_login_response **response,
                     const struct webauth_keyring *ring)
{
    apr_array_header_t *wkproxies, *wkfactors, *logins;
    struct webauth_token *newproxy, *token;
    struct webauth_token cancel;
    struct webauth_token *wkfactor = NULL;
    struct webauth_token_request *req;
    struct webauth_token_webkdc_service *service;
    struct webauth_token_webkdc_proxy *wkproxy = NULL;
    int i, status;
    struct webauth_user_info *info = NULL;
    const char *etoken;
    bool did_login = false;
    size_t size;
    const void *key_data;
    struct webauth_key *key;
    struct webauth_keyring *session;
    const char *allowed, *authz_subject;

    /* Basic sanity checking. */
    if (request->service == NULL
        || request->wkproxies == NULL
        || request->wkfactors == NULL
        || request->logins == NULL
        || request->request == NULL) {
        status = WA_ERR_CORRUPT;
        wai_error_set(ctx, status, "incomplete login request data");
        return status;
    }

    /* Decrypt the webkdc-service and request tokens. */
    status = webauth_token_decode(ctx, WA_TOKEN_WEBKDC_SERVICE,
                                  request->service, ring, &token);
    if (status != WA_ERR_NONE) {
        wai_error_add_context(ctx, "parsing webkdc-service token");
        return status;
    }
    service = &token->token.webkdc_service;
    status = webauth_token_decode(ctx, WA_TOKEN_REQUEST, request->request,
                                  ring, &token);
    if (status != WA_ERR_NONE) {
        wai_error_add_context(ctx, "parsing request token");
        return status;
    }
    req = &token->token.request;

    /* Fill in the basics of our response. */
    *response = apr_pcalloc(ctx->pool, sizeof(**response));
    (*response)->return_url = req->return_url;
    (*response)->requester = service->subject;
    (*response)->app_state = req->state;
    (*response)->app_state_len = req->state_len;

    /*
     * Several tokens, such as the login cancel token and the result token,
     * have to be encrypted in the session key rather than in the WebKDC
     * private key, since they're meant to be readable by the WAS.  Create a
     * keyring containing the session key we can use for those.
     */
    size = service->session_key_len;
    key_data = service->session_key;
    status = webauth_key_create(ctx, WA_KEY_AES, size, key_data, &key);
    if (status != WA_ERR_NONE)
        return status;
    session = webauth_keyring_from_key(ctx, key);
    if (status != WA_ERR_NONE)
        return status;

    /*
     * If the WAS requested login cancel support, generate an error token
     * representing a canceled login and store it in the response.  We will
     * return that token to WebLogin, which in turn will pass it (in the URL)
     * back to the WAS if the user clicks on the cancel login link.
     *
     * FIXME: Use something less lame than strstr to see if the option is set.
     */
    if (req->options != NULL && strstr(req->options, "lc") != NULL) {
        cancel.type = WA_TOKEN_ERROR;
        cancel.token.error.code = WA_PEC_LOGIN_CANCELED;
        cancel.token.error.message = "user canceled login";
        cancel.token.error.creation = 0;
        status = webauth_token_encode(ctx, &cancel, session, &etoken);
        if (status != WA_ERR_NONE)
            return status;
        (*response)->login_cancel = etoken;
    }

    /*
     * Process the incoming webkdc-proxy credentials.  We warn about but
     * ignore any webkdc-proxy credentials that fail to decrypt or decode.
     */
    wkproxies = apr_array_make(ctx->pool, 2, sizeof(struct webauth_token *));
    for (i = 0; i < request->wkproxies->nelts; i++) {
        const struct webauth_webkdc_proxy_data *pd;

        pd = &APR_ARRAY_IDX(request->wkproxies, i,
                            const struct webauth_webkdc_proxy_data);
        status = webauth_token_decode(ctx, WA_TOKEN_WEBKDC_PROXY, pd->token,
                                      ring, &token);
        if (status != WA_ERR_NONE) {
            wai_error_add_context(ctx, "parsing webkdc-proxy token"
                                  " (ignoring)");
            wai_log_error(ctx, WA_LOG_INFO, status);
            continue;
        }
        token->token.webkdc_proxy.session_factors = pd->source;
        APR_ARRAY_PUSH(wkproxies, struct webauth_token *) = token;
    }

    /* Likewise for the webkdc-factor credentials. */
    wkfactors = apr_array_make(ctx->pool, 2, sizeof(struct webauth_token *));
    for (i = 0; i < request->wkproxies->nelts; i++) {
        const char *encoded;

        encoded = APR_ARRAY_IDX(request->wkfactors, i, const char *);
        status = webauth_token_decode(ctx, WA_TOKEN_WEBKDC_FACTOR, encoded,
                                      ring, &token);
        if (status != WA_ERR_NONE) {
            wai_error_add_context(ctx, "parsing webkdc-factor token"
                                  " (ignoring)");
            wai_log_error(ctx, WA_LOG_INFO, status);
            continue;
        }
        APR_ARRAY_PUSH(wkfactors, struct webauth_token *) = token;
    }

    /*
     * Process the login credentials.  Report a fatal error if we can't decode
     * these.  We either process a password login or an OTP login depending on
     * the contents, and then add the resulting tokens to the wkproxies and
     * wkfactors structs.
     *
     * Keep the login tokens around since we need them for logging later.
     */
    logins = apr_array_make(ctx->pool, 1, sizeof(struct webauth_token *));
    for (i = 0; i < request->logins->nelts; i++) {
        const char *encoded;

        /* Decode the login token. */
        encoded = APR_ARRAY_IDX(request->logins, i, const char *);
        status = webauth_token_decode(ctx, WA_TOKEN_LOGIN, encoded, ring,
                                      &token);
        if (status != WA_ERR_NONE) {
            wai_error_add_context(ctx, "parsing login token");
            return status;
        }
        APR_ARRAY_PUSH(logins, struct webauth_token *) = token;

        /* Process the login token appropriately. */
        newproxy = NULL;
        wkfactor = NULL;
        if (token->token.login.otp != NULL)
            status = do_otp(ctx, *response, &token->token.login,
                            request->remote_ip, request->login_state,
                            &newproxy, &wkfactor);
        else
            status = do_login(ctx, *response, &token->token.login, &newproxy);

        /* If the login failed, abort. */
        if (status != WA_ERR_NONE)
            return status;
        if ((*response)->login_error != 0)
            goto done;

        /* If we got new tokens, add them to the appropriate arrays. */
        if (newproxy != NULL) {
            APR_ARRAY_PUSH(wkproxies, struct webauth_token *) = newproxy;
            did_login = true;
        }
        if (wkfactor != NULL)
            APR_ARRAY_PUSH(wkfactors, struct webauth_token *) = wkfactor;
    }

    /*
     * We have condensed all the user authentication information at this point
     * to a set of webkdc-proxy tokens and webkdc-factor tokens (plus possibly
     * some login tokens that we can now ignore since we've processed them).
     * However, we want one and only one webkdc-proxy token that has our
     * combined factor information and one webkdc-factor token that will be
     * set as a long-lived cookie in the client.
     *
     * First, merge all the webkdc-factor tokens into a single token that
     * we'll return to the user, or leave it as NULL if there are no
     * webkdc-factor tokens.
     */
    /*
     * Now, merge all the webkdc-proxy tokens into a single new webkdc-proxy
     * token.  If we get the error code WA_ERR_TOKEN_REJECTED back, that means
     * someone tried to use an inconsistent mix of tokens, which should be
     * rejected as unauthorized rather than generating an internal WebAuth
     * error.
     */
    wkproxy = NULL;
    status = wai_token_merge_webkdc_proxy(ctx, wkproxies,
                                          ctx->webkdc->login_time_limit,
                                          &newproxy);
    if (status != WA_ERR_NONE)
        wai_error_add_context(ctx, "merging webkdc-proxy tokens");
    if (status == WA_ERR_TOKEN_REJECTED) {
        wai_log_error(ctx, WA_LOG_WARN, status);
        (*response)->login_error = WA_PEC_UNAUTHORIZED;
        (*response)->login_message = "not authorized to use proxy token";
        goto done;
    } else if (status != WA_ERR_NONE)
        return status;

    /*
     * If we have a new webkdc-proxy token, encode it in the response in case
     * we changed or merged anything.
     *
     * For login purposes, the webkdc-proxy token must have a proxy subject
     * starting with "WEBKDC:" to indicate that it is an SSO token.
     */
    if (newproxy != NULL) {
        wkproxy = &newproxy->token.webkdc_proxy;
        if (strncmp(wkproxy->proxy_subject, "WEBKDC:", 7) != 0) {
            (*response)->login_error = WA_PEC_PROXY_TOKEN_INVALID;
            (*response)->login_message
                = apr_psprintf(ctx->pool, "proxy subject %s not allowed",
                               wkproxy->proxy_subject);
            goto done;
        }
    }

    /*
     * Determine the authenticated user.
     *
     * If we have configuration for a user information service, we now know as
     * much as we're going to know about who the user is and should retrieve
     * that information if possible.  If we did a login, we should return
     * login history if we have any.  Here is also where we tell the user
     * information service to do random multifactor if needed.
     *
     * If we don't have configuration about a user information service, we
     * trust all the webkdc-factor tokens unconditionally.
     */
    if (ctx->user != NULL && wkproxy != NULL) {
        status = add_user_info(ctx, req, request->remote_ip, response,
                               newproxy, wkfactors, did_login, &info);
        if (status != WA_ERR_NONE)
            return status;
        if (info->error != NULL) {
            (*response)->login_error = WA_PEC_AUTH_REJECTED;
            (*response)->login_message
                = "authentication rejected by user information service";
            (*response)->user_message = info->error;
            goto done;
        }

        /*
         * Merge the webkdc-factor tokens into a single token.  We do this
         * after the user information service call, which may have invalidated
         * some of the tokens.
         */
        status = wai_token_merge_webkdc_factor(ctx, wkfactors, &wkfactor);
        if (status != WA_ERR_NONE) {
            wai_error_add_context(ctx, "merging webkdc-factor tokens");
            return status;
        }
    } else if (ctx->user == NULL && wkproxy != NULL) {
        struct webauth_token *oldproxy = newproxy;

        status = wai_token_merge_webkdc_factor(ctx, wkfactors, &wkfactor);
        if (status != WA_ERR_NONE) {
            wai_error_add_context(ctx, "merging webkdc-factor tokens");
            return status;
        }
        status = wai_token_merge_webkdc_proxy_factor(ctx, oldproxy, wkfactor,
                                                     &newproxy);
        wkproxy = &newproxy->token.webkdc_proxy;
        if (status != WA_ERR_NONE) {
            wai_error_add_context(ctx, "merging webkdc-proxy and"
                                  " webkdc-factor tokens");
            return status;
        }
    }

    /* Encode the webkdc-proxy token in the response and set the subject. */
    if (newproxy != NULL) {
        apr_array_header_t *proxies;
        struct webauth_webkdc_proxy_data *data;

        size = sizeof(struct webauth_webkdc_proxy_data);
        proxies = apr_array_make(ctx->pool, 1, size);
        data = apr_array_push(proxies);
        data->type = wkproxy->proxy_type;
        status = webauth_token_encode(ctx, newproxy, ring, &data->token);
        if (status != WA_ERR_NONE)
            return status;
        (*response)->proxies = proxies;
        (*response)->subject = wkproxy->subject;
    }

    /*
     * If we have no webkdc-proxy token, we're done; we can't authenticate the
     * user, so bounce them back to the WebLogin screen with what information
     * we do have.
     */
    if (wkproxy == NULL) {
        (*response)->login_error = WA_PEC_PROXY_TOKEN_REQUIRED;
        (*response)->login_message = "need a proxy token";
        goto done;
    }

    /*
     * If forced login is set, we require an interactive login.  Otherwise,
     * error out with the error code for forced login, instructing WebLogin to
     * put up the login screen.
     *
     * FIXME: strstr is still lame.
     */
    if (req->options != NULL && strstr(req->options, "fa") != NULL) {
        struct webauth_factors *factors;

        factors = webauth_factors_parse(ctx, wkproxy->session_factors);
        if (!webauth_factors_interactive(ctx, factors)) {
            (*response)->login_error = WA_PEC_LOGIN_FORCED;
            (*response)->login_message = "forced authentication, need to login";
            goto done;
        }
    }

    /*
     * If the user information service or the request says that multifactor or
     * some other factor we don't have is required, reject the login with
     * either multifactor required or with multifactor unavailable, depending
     * on whether the user has multifactor configured.
     */
    status = check_multifactor(ctx, req, *response, wkproxy, info);
    if (status != WA_ERR_NONE)
        return status;
    if ((*response)->login_error != 0)
        goto done;

    /*
     * We have to ensure that the webkdc-proxy token we have available is
     * capable of satisfying the request from the WAS.  This is always the
     * case if the WAS just wants an id token of type webkdc (a simple
     * identity assertion), but if the WAS asked for a krb5 id or proxy token,
     * we have to have a krb5 webkdc-proxy token.
     */
    if ((strcmp(req->type, "id") == 0 && strcmp(req->auth, "krb5") == 0)
        || (strcmp(req->type, "proxy") == 0
            && strcmp(req->proxy_type, "krb5") == 0))
        if (strcmp(wkproxy->proxy_type, "krb5") != 0) {
            (*response)->login_error = WA_PEC_PROXY_TOKEN_REQUIRED;
            (*response)->login_message = "need a proxy token";
            goto done;
        }

    /*
     * Protect against an attacker using the WebLogin XML interface and
     * sending, as the webkdc-proxy token, a webkdc-proxy token obtained by a
     * WAS to use to get delegated credentials.  That's only allowed to
     * generate an id token if it's for the WAS that we're talking to.
     */
    if (wkproxy != NULL
        && strncmp(wkproxy->proxy_subject, "WEBKDC:", 7) != 0
        && strcmp(wkproxy->proxy_subject, service->subject) != 0) {
        (*response)->login_error = WA_PEC_UNAUTHORIZED;
        (*response)->login_message = "not authorized to use proxy token";
        goto done;
    }

    /* Determine if the user is allowed to assert alternate identities. */
    status = build_identity_list(ctx, (*response)->subject,
                                 service->subject,
                                 &(*response)->permitted_authz);
    if (status != WA_ERR_NONE)
        return status;

    /*
     * If the user attempts to assert an alternate identity, see if that's
     * allowed.  If so, copy that into the response.  If the requested
     * authorization subject matches the actual subject, just ignore the
     * field.
     */
    authz_subject = request->authz_subject;
    if (authz_subject != NULL)
        if (strcmp(authz_subject, (*response)->subject) == 0)
            authz_subject = NULL;
    if (authz_subject != NULL && (*response)->permitted_authz != NULL)
        for (i = 0; i < (*response)->permitted_authz->nelts; i++) {
            allowed = APR_ARRAY_IDX((*response)->permitted_authz, i, char *);
            if (strcmp(allowed, authz_subject) == 0) {
                (*response)->authz_subject = apr_pstrdup(ctx->pool, allowed);
                break;
            }
        }
    if (authz_subject != NULL && (*response)->authz_subject == NULL) {
        (*response)->login_error = WA_PEC_UNAUTHORIZED;
        (*response)->login_message = "not authorized to assert that identity";
        goto done;
    }

    /*
     * We have a single (or no) webkdc-proxy token that contains everything we
     * know about the user.  Attempt to satisfy their request.
     */
    if (wkproxy != NULL) {
        (*response)->initial_factors = wkproxy->initial_factors;
        (*response)->session_factors = wkproxy->session_factors;
        (*response)->loa = wkproxy->loa;
    }
    if (strcmp(req->type, "id") == 0)
        status = create_id_token(ctx, req, service, wkproxy, *response,
                                 session);
    else if (strcmp(req->type, "proxy") == 0)
        status = create_proxy_token(ctx, req, service, wkproxy, *response,
                                    session, ring);
    else {
        status = WA_ERR_CORRUPT;
        wai_error_set(ctx, status, "unsupported requested token type %s",
                      req->type);
    }
    if (status != WA_ERR_NONE)
        return status;

    /*
     * Set the factor tokens in the response if we have a webkdc-factor token
     * to return.
     */
    if (wkfactor != NULL) {
        apr_array_header_t *factor_tokens;
        struct webauth_webkdc_factor_data *factor;
        const size_t data_size = sizeof(struct webauth_webkdc_factor_data);

        factor_tokens = apr_array_make(ctx->pool, 1, data_size);
        factor = apr_array_push(factor_tokens);
        factor->expiration = wkfactor->token.webkdc_factor.expiration;
        status = webauth_token_encode(ctx, wkfactor, ring, &factor->token);
        if (status != WA_ERR_NONE)
            return status;
        (*response)->factor_tokens = factor_tokens;
    }

done:
    /* For any case where we're not returning a WebAuth error, log. */
    log_login(ctx, request, *response, logins, req);
    return WA_ERR_NONE;
}
