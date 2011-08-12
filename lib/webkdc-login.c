/*
 * WebKDC interface for processing a <requestTokenRequest>.
 *
 * These interfaces are used by the WebKDC implementation to process a
 * <requestTokenRequest> from the WebLogin server, representing a user's
 * attempt to authenticate to a WAS, either with proxy tokens or with a
 * username and authentication credential, or both.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>

#include <lib/internal.h>
#include <webauth/basic.h>
#include <webauth/keys.h>
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
canonicalize_user(struct webauth_context *ctx, WEBAUTH_KRB5_CTXT *kctx,
                  const char **result)
{
    char *subject;
    int status, i;
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
            status = webauth_krb5_get_realm(kctx, &realm);
            if (status != WA_ERR_NONE)
                return status;
            for (i = 0; i < ctx->webkdc->local_realms->nelts; i++) {
                local = APR_ARRAY_IDX(ctx->webkdc->local_realms, i,
                                      const char *);
                if (strcmp(local, realm) == 0)
                    canonicalize = WA_KRB5_CANON_STRIP;
            }
            free(realm);
        }
    }

    /*
     * We now know the canonicalization method we're using, so we can retrieve
     * the principal from the context.
     */
    status = webauth_krb5_get_principal(kctx, &subject, canonicalize);
    if (status != WA_ERR_NONE)
        return status;
    *result = apr_pstrdup(ctx->pool, subject);
    free(subject);
    return WA_ERR_NONE;
}


/*
 * Check that the realm of the authenticated principal is in the list of
 * permitted realms, or that the list of realms is empty.  Returns MWK_OK if
 * the realm is permitted, MWK_ERROR otherwise.  Sets the error on a failure,
 * so the caller doesn't need to do so.
 */
static int
realm_permitted(struct webauth_context *ctx, WEBAUTH_KRB5_CTXT *kctx,
                struct webauth_webkdc_login_response *response)
{
    int status, i;
    char *realm;
    const char *allowed;
    bool okay = false;

    /* If we aren't restricting the realms, always return true. */
    if (ctx->webkdc->permitted_realms->nelts == 0)
        return WA_ERR_NONE;

    /* Get the realm. */
    status = webauth_krb5_get_realm(kctx, &realm);
    if (status != WA_ERR_NONE)
        goto done;

    /*
     * We assume that all realms listed in the configuration are already
     * escaped, as is the realm parameter.
     */
    for (i = 0; i < ctx->webkdc->permitted_realms->nelts; i++) {
        allowed = APR_ARRAY_IDX(ctx->webkdc->permitted_realms, i, const char *);
        if (strcmp(allowed, realm) == 0) {
            okay = true;
            break;
        }
    }
    if (!okay) {
        response->login_error = WA_PEC_USER_REJECTED;
        response->login_message
            = apr_psprintf(ctx->pool, "realm %s is not permitted", realm);
    }
    status = WA_ERR_NONE;

done:
    free(realm);
    return status;
}


/*
 * Attempt an OTP authentication, which is a user authentication validatation
 * via the user metadata service.  On success, generate a new webkdc-proxy
 * token based on that information and store it in the token argument.  On
 * login failure, store the error code and message in the response.  On a more
 * fundamental failure, return an error code.
 */
static int
do_otp(struct webauth_context *ctx,
       struct webauth_webkdc_login_response *response,
       struct webauth_token_login *login, const char *ip,
       struct webauth_token **wkproxy)
{
    int status;
    struct webauth_user_validate *validate;
    struct webauth_token_webkdc_proxy *pt;

    /* Do the remote validation call. */
    if (ctx->user == NULL) {
        webauth_error_set(ctx, WA_ERR_UNIMPLEMENTED, "no OTP configuration");
        return WA_ERR_UNIMPLEMENTED;
    }
    status = webauth_user_validate(ctx, login->username, ip, login->otp,
                                   &validate);
    if (status != WA_ERR_NONE)
        return status;

    /* If validation failed, set the login error code and return. */
    if (!validate->success) {
        response->login_error = WA_PEC_LOGIN_FAILED;
        response->login_message = "login incorrect";
        return WA_ERR_NONE;
    }

    /*
     * Create the resulting webkdc-proxy token.
     *
     * FIXME: Arbitrary magic 10 hour expiration time.
     */
    *wkproxy = apr_pcalloc(ctx->pool, sizeof(struct webauth_token));
    (*wkproxy)->type = WA_TOKEN_WEBKDC_PROXY;
    pt = &(*wkproxy)->token.webkdc_proxy;
    pt->subject = login->username;
    pt->proxy_type = "otp";
    pt->proxy_subject = "WEBKDC:otp";
    pt->data = login->username;
    pt->data_len = strlen(login->username);
    pt->initial_factors = apr_array_pstrcat(ctx->pool, validate->factors, ',');
    pt->session_factors = pt->initial_factors;
    pt->loa = validate->loa;
    if (ctx->webkdc->proxy_lifetime == 0)
        pt->expiration = time(NULL) + 60 * 60 * 10;
    else
        pt->expiration = time(NULL) + ctx->webkdc->proxy_lifetime;
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
    WEBAUTH_KRB5_CTXT *kctx;
    const char *subject;
    char *webkdc, *tmp;
    char *tgt, *tmp_tgt;
    size_t tgt_len;
    time_t expires;
    struct webauth_token_webkdc_proxy *pt;

    status = webauth_krb5_new(&kctx);
    if (status != WA_ERR_NONE) {
        if (status == WA_ERR_KRB5)
            webauth_krb5_free(kctx);
        return status;
    }
    status = webauth_krb5_init_via_password(kctx,
                                            login->username,
                                            login->password,
                                            NULL,
                                            ctx->webkdc->keytab_path,
                                            ctx->webkdc->principal,
                                            NULL,
                                            &webkdc);
    switch (status) {
    case 0:
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
    case WA_ERR_KRB5:
        webauth_error_set(ctx, status, "%s", webauth_krb5_error_message(kctx));
        /* fall through */
    default:
        return status;
    }

    /*
     * webauth_krb5_init_via_password determined the principal of the WebKDC
     * service to which we just authenticated and stored that information in
     * webkdc, but it's not yet poolified, so make a copy in our memory pool
     * so that we can free it.
     */
    tmp = apr_pstrcat(ctx->pool, "krb5:", webkdc, NULL);
    free(webkdc);
    webkdc = tmp;

    /*
     * Check if the realm of the authenticated principal is permitted and
     * then canonicalize the user's identity.
     */
    status = realm_permitted(ctx, kctx, response);
    if (status != WA_ERR_NONE || response->login_error != 0)
        goto cleanup;
    status = canonicalize_user(ctx, kctx, &subject);
    if (status != WA_ERR_NONE)
        goto cleanup;

    /* Export the ticket-granting ticket for the webkdc-proxy token. */
    status = webauth_krb5_export_tgt(kctx, &tgt, &tgt_len, &expires);
    if (status != WA_ERR_NONE)
        goto cleanup;
    tmp_tgt = apr_palloc(ctx->pool, tgt_len);
    memcpy(tmp_tgt, tgt, tgt_len);
    free(tgt);
    tgt = tmp_tgt;

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

cleanup:
    webauth_krb5_free(kctx);
    return status;
}


/*
 * Merge an array of webkdc-proxy tokens into a single token, which we'll then
 * use for subsequent operations.  Takes the context, the array of
 * credentials, a boolean indicating whether we processed a login token, and a
 * place to store the newly created webkdc-proxy token (or return a pointer to
 * one of the ones passed in if there is only one.
 *
 * We use the following logic to merge webkdc-proxy tokens:
 *
 * 1. Expired tokens are discarded.
 * 2. Tokens whose initial factors are a subset of the accumulated factors
 *    and which do not add krb5 capability are discarded.
 * 3. The krb5 data is added if not already present, and the expiration is
 *    set to the token with the krb5 data and the proxy type changed to krb5.
 * 4. Initial factors are merged between all webkdc-proxy tokens, with the
 *    expiration set to the nearest expiration of all contributing tokens.
 * 5. Creation time is set to the current time if we pull from multiple
 *    tokens.
 * 6. Session factors are merged from a webkdc-proxy token if and only if the
 *    webkdc-proxy token contributes in some way to the result.
 * 7. The session factors are used as-is unless the token is less than five
 *    minutes old and we processed a login token, in which case its initial
 *    factors count as session factors.
 */
static int
merge_webkdc_proxy(struct webauth_context *ctx, apr_array_header_t *creds,
                   bool did_login, struct webauth_token **result)
{
    bool created = false;
    struct webauth_token *token, *tmp;
    struct webauth_token *genbest = NULL;
    struct webauth_token_webkdc_proxy *wkproxy;
    struct webauth_token_webkdc_proxy *best = NULL;
    struct webauth_factors *current;
    struct webauth_factors *factors = NULL;
    struct webauth_factors *sfactors = NULL;
    time_t now;
    int i, status;

    *result = NULL;
    if (creds->nelts == 0)
        return WA_ERR_NONE;
    now = time(NULL);

    /*
     * We merge the proxy tokens in reverse order, since any proxy tokens that
     * we created via fresh login tokens should take precedence over anything
     * that we had from older cookies and we added those to the end of the
     * array.
     */
    i = creds->nelts - 1;
    do {
        token = APR_ARRAY_IDX(creds, i, struct webauth_token *);
        if (token->type != WA_TOKEN_WEBKDC_PROXY)
            continue;
        wkproxy = &token->token.webkdc_proxy;
        if (wkproxy->expiration <= now)
            continue;
        if (best == NULL) {
            best = wkproxy;
            genbest = token;
            continue;
        }
        if (factors == NULL) {
            status = webauth_factors_parse(ctx, best->initial_factors,
                                           &factors);
            if (status != WA_ERR_NONE)
                return status;
        }
        if (sfactors == NULL) {
            status = webauth_factors_parse(ctx, best->session_factors,
                                           &sfactors);
            if (status != WA_ERR_NONE)
                return status;
        }
        current = NULL;
        status = webauth_factors_parse(ctx, wkproxy->initial_factors,
                                       &current);
        if (status != WA_ERR_NONE)
            return status;
        if (webauth_factors_subset(ctx, current, factors)
            && (strcmp(best->proxy_type, "krb5") == 0
                || strcmp(wkproxy->proxy_type, "krb5") != 0))
            continue;
        if (!created) {
            tmp = apr_palloc(ctx->pool, sizeof(struct webauth_token));
            *tmp = *genbest;
            genbest = tmp;
            best = &tmp->token.webkdc_proxy;
            created = true;
        }
        if (strcmp(best->proxy_type, "krb5") != 0
            && strcmp(wkproxy->proxy_type, "krb5") == 0) {
            best->data = wkproxy->data;
            best->data_len = wkproxy->data_len;
            best->proxy_type = wkproxy->proxy_type;
        }
        status = webauth_factors_parse(ctx, wkproxy->initial_factors,
                                       &factors);
        if (status != WA_ERR_NONE)
            return status;

        /* FIXME: Hard-coded magic five minute time interval. */
        if (did_login && wkproxy->creation > time(NULL) - 5 * 60)
            status = webauth_factors_parse(ctx, wkproxy->initial_factors,
                                           &sfactors);
        else
            status = webauth_factors_parse(ctx, wkproxy->session_factors,
                                           &sfactors);
        if (status != WA_ERR_NONE)
            return status;
        if (wkproxy->expiration < best->expiration)
            best->expiration = wkproxy->expiration;
        if (wkproxy->loa > best->loa)
            best->loa = wkproxy->loa;
    } while (i-- > 0);
    if (created) {
        best->initial_factors = webauth_factors_string(ctx, factors);
        best->session_factors = webauth_factors_string(ctx, sfactors);
        best->creation = now;
    }
    *result = genbest;
    return WA_ERR_NONE;
}


/*
 * Given the request from the WebAuth Application Server, the current
 * accumulated response, the current merged webkdc-proxy token, and the user
 * metadata information (which may be NULL if there's no metadata configured),
 * check whether multifactor authentication and a level of assurance
 * restriction is already satisfied or unnecessary, required, or impossible.
 *
 * Returns WA_ERR_NONE and leaves request->login_error unchanged if any
 * multifactor requirements are satisfied.  Sets request->login_error if
 * multifactor is required or unavailable.  Returns an error code on errors in
 * processing.
 */
static int
check_multifactor(struct webauth_context *ctx,
                  struct webauth_webkdc_login_request *request,
                  struct webauth_webkdc_login_response *response,
                  struct webauth_token_webkdc_proxy *wkproxy,
                  struct webauth_user_info *info)
{
    int i, status;
    struct webauth_factors *wanted = NULL, *swanted = NULL;
    struct webauth_factors configured;
    struct webauth_factors *have = NULL, *shave = NULL;
    struct webauth_token_request *req;
    const char *factor;

    req = request->request;

    /* Figure out what factors we want and have. */
    status = webauth_factors_parse(ctx, req->initial_factors, &wanted);
    if (status != WA_ERR_NONE)
        return status;
    status = webauth_factors_parse(ctx, req->session_factors, &swanted);
    if (status != WA_ERR_NONE)
        return status;
    status = webauth_factors_parse(ctx, wkproxy->initial_factors, &have);
    if (status != WA_ERR_NONE)
        return status;
    status = webauth_factors_parse(ctx, wkproxy->session_factors, &shave);
    if (status != WA_ERR_NONE)
        return status;

    /*
     * Check if multifactor is forced by user configuration.  If so, add it to
     * the initial factors that we require.
     */
    if (info != NULL && info->multifactor_required) {
        status = webauth_factors_parse(ctx, WA_FA_MULTIFACTOR, &wanted);
        if (status != WA_ERR_NONE)
            return status;
    }

    /*
     * Second, check the level of assurance required.  If the user cannot
     * establish a sufficient level of assurance, punt immediately; we don't
     * care about the available factors in that case.
     */
    if (req->loa > wkproxy->loa) {
        if (req->loa > info->max_loa) {
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
     */
    if (webauth_factors_subset(ctx, wanted, have)) {
        if (webauth_factors_subset(ctx, swanted, shave)) {
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
     * Finally, check if the WAS-requested factors can be satisfied by the
     * factors configured by the user.  We have to do a bit of work here to
     * turn the user's configured factors into a webauth_factors struct.
     *
     * Assume we can do password authentication even without user metadata.
     */
    memset(&configured, 0, sizeof(configured));
    if (info != NULL && info->factors != NULL && info->factors->nelts > 0) {
        configured.factors = apr_array_copy(ctx->pool, info->factors);
        for (i = 0; i < configured.factors->nelts; i++) {
            factor = APR_ARRAY_IDX(configured.factors, i, const char *);
            if (strcmp(factor, WA_FA_MULTIFACTOR) == 0)
                configured.multifactor = true;
        }
    } else {
        configured.factors = apr_array_make(ctx->pool, 1, sizeof(const char *));
        APR_ARRAY_PUSH(configured.factors, const char *) = WA_FA_PASSWORD;
    }
    response->factors_wanted = wanted->factors;
    response->factors_configured = configured.factors;
    if (!webauth_factors_subset(ctx, wanted, &configured)) {
        response->login_error = WA_PEC_MULTIFACTOR_UNAVAILABLE;
        response->login_message = "multifactor required but not configured";
    } else if (!webauth_factors_subset(ctx, swanted, &configured)) {
        response->login_error = WA_PEC_MULTIFACTOR_UNAVAILABLE;
        response->login_message = "multifactor required but not configured";
    }
    return WA_ERR_NONE;
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
                       void **krb5_auth, size_t *krb5_auth_len)
{
    int status;
    WEBAUTH_KRB5_CTXT *kctx;
    char *tmp_auth;

    *krb5_auth = NULL;
    status = webauth_krb5_new(&kctx);
    if (status != WA_ERR_NONE) {
        if (status == WA_ERR_KRB5)
            webauth_krb5_free(kctx);
        return status;
    }

    /*
     * FIXME: Probably need to examine errors a little more closely to
     * determine if we should return a proxy-token error or a server-failure.
     */
    status = webauth_krb5_init_via_cred(kctx, wkproxy->data,
                                        wkproxy->data_len, NULL);
    if (status != WA_ERR_NONE) {
        if (status == WA_ERR_KRB5)
            webauth_error_set(ctx, status, "%s",
                              webauth_krb5_error_message(kctx));
        webauth_krb5_free(kctx);
        return status;
    }

    /*
     * Generate the Kerberos authenticator.
     *
     * FIXME: Probably need to examine errors a little more closely to
     * determine if we should return a proxy-token error or a server-failure.
     */
    if (strncmp(server, "krb5:", 5) == 0)
        server += 5;
    status = webauth_krb5_mk_req(kctx, server, &tmp_auth, krb5_auth_len);
    if (status != WA_ERR_NONE) {
        if (status == WA_ERR_KRB5)
            webauth_error_set(ctx, status, "%s",
                              webauth_krb5_error_message(kctx));
        webauth_krb5_free(kctx);
        return status;
    } else {
        *krb5_auth = apr_palloc(ctx->pool, *krb5_auth_len);
        memcpy(*krb5_auth, tmp_auth, *krb5_auth_len);
        free(tmp_auth);
    }
    webauth_krb5_free(kctx);
    return WA_ERR_NONE;
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
                struct webauth_webkdc_login_request *request,
                struct webauth_token_webkdc_proxy *wkproxy,
                struct webauth_webkdc_login_response *response,
                WEBAUTH_KEYRING *keyring)
{
    int status;
    void *krb5_auth;
    size_t krb5_auth_len;
    struct webauth_token token;
    struct webauth_token_id *id;
    struct webauth_token_request *req;

    req = request->request;
    memset(&token, 0, sizeof(token));
    token.type = WA_TOKEN_ID;
    id = &token.token.id;
    id->subject = wkproxy->subject;
    id->auth = req->auth;
    if (strcmp(req->auth, "krb5") == 0) {
        status = get_krb5_authenticator(ctx, request->service->subject,
                                        wkproxy, &krb5_auth, &krb5_auth_len);
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
    return webauth_token_encode(ctx, &token, keyring, &response->result);
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
                   struct webauth_webkdc_login_request *request,
                   struct webauth_token_webkdc_proxy *wkproxy,
                   struct webauth_webkdc_login_response *response,
                   WEBAUTH_KEYRING *session, WEBAUTH_KEYRING *keyring)
{
    int status;
    struct webauth_token token, subtoken;
    struct webauth_token_proxy *proxy;
    struct webauth_token_request *req;

    /* Create the easy portions of the proxy token. */
    req = request->request;
    memset(&token, 0, sizeof(token));
    token.type = WA_TOKEN_PROXY;
    proxy = &token.token.proxy;
    proxy->subject = wkproxy->subject;
    proxy->type = req->proxy_type;
    proxy->initial_factors = wkproxy->initial_factors;
    proxy->session_factors = wkproxy->session_factors;
    proxy->loa = wkproxy->loa;
    proxy->expiration = wkproxy->expiration;

    /* Create the embedded webkdc-proxy token and limit its scope. */
    memset(&subtoken, 0, sizeof(subtoken));
    subtoken.type = WA_TOKEN_WEBKDC_PROXY;
    subtoken.token.webkdc_proxy = *wkproxy;
    subtoken.token.webkdc_proxy.proxy_subject = request->service->subject;
    subtoken.token.webkdc_proxy.creation = 0;
    status = webauth_token_encode_raw(ctx, &subtoken, keyring,
                                      &proxy->webkdc_proxy,
                                      &proxy->webkdc_proxy_len);
    if (status != WA_ERR_NONE)
        return status;

    /* Encode the token and store the resulting string. */
    response->result_type = "proxy";
    return webauth_token_encode(ctx, &token, session, &response->result);
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
                     struct webauth_webkdc_login_request *request,
                     struct webauth_webkdc_login_response **response,
                     WEBAUTH_KEYRING *keyring)
{
    struct webauth_token *cred, *newproxy;
    struct webauth_token **token;
    struct webauth_token cancel;
    struct webauth_token_request *req;
    struct webauth_token_webkdc_proxy *wkproxy = NULL;
    int i, status;
    struct webauth_user_info *info = NULL;
    const char *ip;
    const char *etoken;
    bool did_login = false;
    size_t size;
    WEBAUTH_KEY key;
    WEBAUTH_KEYRING *session;

    /* Basic sanity checking. */
    if (request->service == NULL || request->creds == NULL
        || request->request == NULL) {
        status = WA_ERR_CORRUPT;
        webauth_error_set(ctx, status, "incomplete login request data");
        return status;
    }

    /* Shorter names for things we'll be referring to often. */
    ip = request->remote_ip;
    req = request->request;

    /* Fill in the basics of our response. */
    *response = apr_pcalloc(ctx->pool, sizeof(**response));
    (*response)->return_url = req->return_url;
    (*response)->requester = request->service->subject;
    (*response)->app_state = req->state;
    (*response)->app_state_len = req->state_len;

    /*
     * Several tokens, such as the login cancel token and the result token,
     * have to be encrypted in the session key rather than in the WebKDC
     * private key, since they're meant to be readable by the WAS.  Create a
     * keyring containing the session key we can use for those.
     *
     * FIXME: The conversion from the webkdc-service token to a key is an ugly
     * hack.
     */
    key.type = WA_AES_KEY;
    key.length = request->service->session_key_len;
    key.data = (void *) request->service->session_key;
    status = webauth_keyring_from_key(ctx, &key, &session);
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
        status = webauth_token_encode(ctx, &cancel, session, &etoken);
        if (status != WA_ERR_NONE)
            return status;
        (*response)->login_cancel = etoken;
    }

    /*
     * Check for a login token in the supplied creds.  If there is one, use it
     * to authenticate and transform it into a webkdc-proxy token.
     *
     * FIXME: Stop modifying the array in place.  This is surprising to the
     * caller and makes the test suite more annoying.
     */
    for (i = 0; i < request->creds->nelts; i++) {
        cred = APR_ARRAY_IDX(request->creds, i, struct webauth_token *);
        if (cred->type != WA_TOKEN_LOGIN)
            continue;
        token = apr_array_push(request->creds);
        if (cred->token.login.otp != NULL)
            status = do_otp(ctx, *response, &cred->token.login,
                            request->remote_ip, token);
        else
            status = do_login(ctx, *response, &cred->token.login, token);
        if (status != WA_ERR_NONE)
            return status;
        if (*token == NULL)
            apr_array_pop(request->creds);
        else
            did_login = true;

        /* If the login failed, return what we have so far. */
        if ((*response)->login_error != 0)
            return WA_ERR_NONE;
    }

    /*
     * All of the supplied credentials, if any, must be for the same
     * authenticated user (the same subject) and must be usable by the same
     * entity (the same proxy_subject).  That proxy_subject must also either
     * match the identity of the service subject or start with WEBKDC.  We can
     * skip login tokens, since we've already turned them into webkdc-proxy
     * tokens above.
     */
    if (request->creds != NULL && request->creds->nelts > 0) {
        const char *subject = NULL;
        const char *proxy_subject = NULL;

        for (i = 0; i < request->creds->nelts; i++) {
            cred = APR_ARRAY_IDX(request->creds, i, struct webauth_token *);
            if (cred->type == WA_TOKEN_LOGIN)
                continue;
            wkproxy = &cred->token.webkdc_proxy;
            if (subject == NULL) {
                subject = wkproxy->subject;
                proxy_subject = wkproxy->proxy_subject;
                if (strncmp(proxy_subject, "WEBKDC:", 7) != 0
                    && strcmp(proxy_subject, request->service->subject) != 0) {
                    (*response)->login_error = WA_PEC_UNAUTHORIZED;
                    (*response)->login_message
                        = "not authorized to use proxy token";
                    return WA_ERR_NONE;
                }
                continue;
            }
            if (strcmp(subject, wkproxy->subject) != 0
                || (strcmp(proxy_subject, wkproxy->proxy_subject) != 0
                    && strncmp(proxy_subject, "WEBKDC:", 7) != 0)) {
                (*response)->login_error = WA_PEC_UNAUTHORIZED;
                (*response)->login_message
                    = "not authorized to use proxy token";
                return WA_ERR_NONE;
            }
        }
    }

    /*
     * If there was a login token, all webkdc-proxy tokens also supplied must
     * be WEBKDC tokens (in other words, global single-sign-on tokens).  A WAS
     * can't send a WAS-scoped webkdc-proxy token from a proxy token combined
     * with a login token.
     */
    if (did_login)
        for (i = 0; i < request->creds->nelts; i++) {
            cred = APR_ARRAY_IDX(request->creds, i, struct webauth_token *);
            if (cred->type != WA_TOKEN_WEBKDC_PROXY)
                continue;
            wkproxy = &cred->token.webkdc_proxy;
            if (strncmp(wkproxy->proxy_subject, "WEBKDC:", 7) != 0) {
                (*response)->login_error = WA_PEC_PROXY_TOKEN_INVALID;
                (*response)->login_message
                    = apr_psprintf(ctx->pool, "proxy subject %s not allowed"
                                   " with login token", wkproxy->proxy_subject);
                return WA_ERR_NONE;
            }
        }

    /*
     * We have condensed all the user authentication information at this point
     * to a set of webkdc-proxy tokens.  However, we want one and only one
     * webkdc-proxy token that has our combined factor information.  If we did
     * a login (meaning that we generated new webkdc-proxy information), we
     * want to copy that new webkdc-proxy token into our output.
     */
    wkproxy = NULL;
    status = merge_webkdc_proxy(ctx, request->creds, did_login, &newproxy);
    if (status != WA_ERR_NONE)
        return status;
    if (newproxy != NULL) {
        struct webauth_webkdc_proxy_data *data;

        wkproxy = &newproxy->token.webkdc_proxy;
        size = sizeof(struct webauth_webkdc_proxy_data);
        (*response)->proxies = apr_array_make(ctx->pool, 1, size);
        data = apr_array_push((*response)->proxies);
        data->type = wkproxy->proxy_type;
        status = webauth_token_encode(ctx, newproxy, keyring, &data->token);
        if (status != WA_ERR_NONE)
            return status;
    }

    /*
     * Determine the authenticated user.
     *
     * If we have configuration for a user metadata service, we now know as
     * much as we're going to know about who the user is and should retrieve
     * that information if possible.  If we did a login, we should return
     * login history if we have any.
     */
    if (wkproxy != NULL)
        (*response)->subject = wkproxy->subject;
    if (ctx->user != NULL && wkproxy != NULL) {
        status = webauth_user_info(ctx, wkproxy->subject, ip, 0, &info);
        if (status != WA_ERR_NONE)
            return status;
        if (did_login)
            (*response)->logins = info->logins;
        if (wkproxy->loa > info->max_loa)
            wkproxy->loa = info->max_loa;
        (*response)->password_expires = info->password_expires;
    }

    /*
     * If we have no webkdc-proxy token, we're done; we can't authenticate the
     * user, so bounce them back to the WebLogin screen with what information
     * we do have.
     */
    if (wkproxy == NULL) {
        (*response)->login_error = WA_PEC_PROXY_TOKEN_REQUIRED;
        (*response)->login_message = "need a proxy token";
        return WA_ERR_NONE;
    }

    /*
     * If forced login is set and we didn't just process a login token, error
     * out with the error code for forced login, instructing WebLogin to put
     * up the login screen.
     *
     * FIXME: strstr is still lame.
     */
    if (!did_login)
        if (req->options != NULL && strstr(req->options, "fa") != NULL) {
            (*response)->login_error = WA_PEC_LOGIN_FORCED;
            (*response)->login_message = "forced authentication, need to login";
            return WA_ERR_NONE;
        }

    /*
     * If the user metadata service says that multifactor is required, reject
     * the login with either multifactor required or with multifactor
     * unavailable, depending on whether the user has multifactor configured.
     */
    status = check_multifactor(ctx, request, *response, wkproxy, info);
    if (status != WA_ERR_NONE)
        return status;
    if ((*response)->login_error != 0)
        return WA_ERR_NONE;

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
            return WA_ERR_NONE;
        }

    /*
     * Protect against an attacker using the WebLogin XML interface and
     * sending, as the webkdc-proxy token, a webkdc-proxy token obtained by a
     * WAS to use to get delegated credentials.  That's only allowed to
     * generate an id token if it's for the WAS that we're talking to.
     */
    if (wkproxy != NULL
        && strncmp(wkproxy->proxy_subject, "WEBKDC:", 7) != 0
        && strcmp(wkproxy->proxy_subject, request->service->subject) != 0) {
        (*response)->login_error = WA_PEC_UNAUTHORIZED;
        (*response)->login_message = "not authorized to use proxy token";
        return WA_ERR_NONE;
    }

    /*
     * We have a single (or no) webkdc-proxy token that contains everything we
     * know about the user.  Attempt to satisfy their request.
     */
    if (strcmp(req->type, "id") == 0)
        status = create_id_token(ctx, request, wkproxy, *response, session);
    else if (strcmp(req->type, "proxy") == 0)
        status = create_proxy_token(ctx, request, wkproxy, *response, session,
                                    keyring);
    else {
        status = WA_ERR_CORRUPT;
        webauth_error_set(ctx, status, "unsupported requested token type %s",
                          req->type);
    }
    return status;
}
