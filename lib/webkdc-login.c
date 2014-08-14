/*
 * WebKDC interface for processing a <requestTokenRequest>.
 *
 * These interfaces are used by the WebKDC implementation to process a
 * <requestTokenRequest> from the WebLogin server, representing a user's
 * attempt to authenticate to a WAS, either with proxy tokens or with a
 * username and authentication credential, or both.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2011, 2012, 2013, 2014
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
 * Default webkdc-proxy lifetime for OTP authentications when the user
 * validation service does not provide a lifetime.  (Implementations of the
 * user information service should provide a lifetime rather than trying to
 * make this configurable.)
 */
static const unsigned long DEFAULT_OTP_LIFETIME = 60 * 60 * 10;


/*
 * Helper function to build an array of webauth_token pointers based on the
 * size of an input array.  This is used for parsing webkdc-proxy,
 * webkdc-factor, and login tokens.  We add one to the array size to hold
 * additional webkdc-proxy or webkdc-factor tokens created by the login
 * process.
 */
static apr_array_header_t *
build_token_array(struct webauth_context *ctx,
                  const apr_array_header_t *source)
{
    size_t n, size;

    n = (source == NULL) ? 0 : source->nelts;
    size = sizeof(struct webauth_token *);
    return apr_array_make(ctx->pool, n + 1, size);
}


/*
 * Decrypt the login tokens in the given array and store them in the login
 * state.  This is a wrapper around webauth_token_decode that does some
 * additional checks and return status mapping.
 */
static int
parse_token_logins(struct webauth_context *ctx,
                   const apr_array_header_t *logins,
                   struct wai_webkdc_login_state *state,
                   const struct webauth_keyring *ring)
{
    struct webauth_token *token;
    const char *encoded;
    int i, s;

    /* Create the array of decoded tokens.  Do this even if empty. */
    state->logins = build_token_array(ctx, logins);

    /* Nothing further to do if we have no input tokens. */
    if (apr_is_empty_array(logins))
        return WA_ERR_NONE;

    /* Walk the array of input tokens and decrypt them. */
    for (i = 0; i < logins->nelts; i++) {
        encoded = APR_ARRAY_IDX(logins, i, const char *);
        s = webauth_token_decode(ctx, WA_TOKEN_LOGIN, encoded, ring, &token);
        if (s != WA_ERR_NONE)
            return wai_error_change(ctx, s, WA_PEC_LOGIN_TOKEN_INVALID);
        APR_ARRAY_PUSH(state->logins, struct webauth_token *) = token;
    }
    return WA_ERR_NONE;
}


/*
 * Decrypt the request token and store it in the login state.  This is a
 * wrapper around webauth_token_decode that does some additional checks, and
 * return status mapping.
 */
static int
parse_token_request(struct webauth_context *ctx, const char *data,
                    struct wai_webkdc_login_state *state)
{
    struct webauth_keyring *ring;
    struct webauth_token *token;
    int s;

    /*
     * Decrypt the request token.
     *
     * FIXME: Move token_max_ttl processing here.
     */
    if (data == NULL) {
        wai_error_set(ctx, WA_ERR_INVALID, "incomplete login request data");
        return WA_ERR_INVALID;
    }
    ring = state->session;
    s = webauth_token_decode(ctx, WA_TOKEN_REQUEST, data, ring, &token);
    if (s != WA_ERR_NONE)
        return wai_error_change(ctx, s, WA_PEC_REQUEST_TOKEN_INVALID);
    state->request = &token->token.request;
    return WA_ERR_NONE;
}


/*
 * Decrypt the webkdc-factor tokens in the given array and store them in the
 * login state.  This is a wrapper around webauth_token_decode that does some
 * additional checks and return status mapping.  We warn about but ignore any
 * webkdc-proxy credentials that fail to decrypt or decode.
 *
 * Currently, this function can never fail since we ignore all errors, but
 * return a WebAuth status code in case we change later behavior around
 * handling invalid webkc-factor tokens.
 */
static int
parse_token_webkdc_factors(struct webauth_context *ctx,
                           const apr_array_header_t *wkfactors,
                           struct wai_webkdc_login_state *state,
                           const struct webauth_keyring *ring)
{
    struct webauth_token *token;
    const char *encoded;
    int i, s;
    const enum webauth_token_type type = WA_TOKEN_WEBKDC_FACTOR;

    /* Create the array of decoded tokens.  Do this even if empty. */
    state->wkfactors = build_token_array(ctx, wkfactors);

    /* Nothing further to do if we have no input tokens. */
    if (apr_is_empty_array(wkfactors))
        return WA_ERR_NONE;

    /* Walk the array of input tokens and decrypt them. */
    for (i = 0; i < wkfactors->nelts; i++) {
        encoded = APR_ARRAY_IDX(wkfactors, i, const char *);
        s = webauth_token_decode(ctx, type, encoded, ring, &token);
        if (s != WA_ERR_NONE) {
            wai_log_error(ctx, WA_LOG_INFO, s, "ignoring webkdc-factor token");
            continue;
        }
        APR_ARRAY_PUSH(state->wkfactors, struct webauth_token *) = token;
    }
    return WA_ERR_NONE;
}


/*
 * Decrypt the webkdc-proxy tokens in the given array and store them in the
 * login state.  This is a wrapper around webauth_token_decode that does some
 * additional checks, fills in the session factors, and maps status codes.  We
 * warn about but ignore any webkdc-proxy credentials that fail to decrypt or
 * decode.
 *
 * Currently, this function can never fail since we ignore all errors, but
 * return a WebAuth status code in case we change later behavior around
 * handling invalid webkc-proxy tokens.
 */
static int
parse_token_webkdc_proxies(struct webauth_context *ctx,
                           const apr_array_header_t *wkproxies,
                           struct wai_webkdc_login_state *state,
                           const struct webauth_keyring *ring)
{
    struct webauth_token *token;
    const struct webauth_webkdc_proxy_data *pd;
    int i, s;
    const enum webauth_token_type type = WA_TOKEN_WEBKDC_PROXY;

    /* Create the array of decoded tokens.  Do this even if empty. */
    state->wkproxies = build_token_array(ctx, wkproxies);

    /* Nothing further to do if we have no input tokens. */
    if (apr_is_empty_array(wkproxies))
        return WA_ERR_NONE;

    /*
     * Walk the array of input tokens, decrypt them, and add session factors
     * from the source data in the proxy data wrapper.
     */
    for (i = 0; i < wkproxies->nelts; i++) {
        pd = &APR_ARRAY_IDX(wkproxies, i,
                            const struct webauth_webkdc_proxy_data);
        s = webauth_token_decode(ctx, type, pd->token, ring, &token);
        if (s != WA_ERR_NONE) {
            wai_log_error(ctx, WA_LOG_INFO, s, "ignoring webkdc-proxy token");
            continue;
        }
        token->token.webkdc_proxy.session_factors = pd->source;
        APR_ARRAY_PUSH(state->wkproxies, struct webauth_token *) = token;
    }
    return WA_ERR_NONE;
}


/*
 * Decrypt the webkdc-service token and store it in the login state.  This is
 * a wrapper around webauth_token_decode that does some additional checks,
 * keyring management, and return status mapping.
 */
static int
parse_token_webkdc_service(struct webauth_context *ctx, const char *data,
                           struct wai_webkdc_login_state *state,
                           const struct webauth_keyring *ring)
{
    struct webauth_key *key;
    struct webauth_token *token;
    const void *key_data;
    size_t size;
    int s;

    /* Decrypt the webkdc-service token. */
    if (data == NULL) {
        wai_error_set(ctx, WA_ERR_INVALID, "incomplete login request data");
        return WA_ERR_INVALID;
    }
    s = webauth_token_decode(ctx, WA_TOKEN_WEBKDC_SERVICE, data, ring, &token);
    if (s == WA_ERR_TOKEN_EXPIRED)
        return wai_error_change(ctx, s, WA_PEC_SERVICE_TOKEN_EXPIRED);
    else if (s != WA_ERR_NONE)
        return wai_error_change(ctx, s, WA_PEC_SERVICE_TOKEN_INVALID);
    state->service = &token->token.webkdc_service;

    /*
     * Several tokens, such as the login cancel token and the result token,
     * have to be encrypted in the session key rather than in the WebKDC
     * private key, since they're meant to be readable by the WAS.  Create a
     * keyring containing the session key we can use for those.
     */
    size = state->service->session_key_len;
    key_data = state->service->session_key;
    s = webauth_key_create(ctx, WA_KEY_AES, size, key_data, &key);
    if (s != WA_ERR_NONE) {
        wai_log_error(ctx, WA_LOG_WARN, s,
                      "invalid session key in webkdc-service token");
        return wai_error_set(ctx, WA_PEC_SERVICE_TOKEN_INVALID, NULL);
    }
    state->session = webauth_keyring_from_key(ctx, key);
    return WA_ERR_NONE;
}


/*
 * Given a webauth_webkdc_login_request, parse the information that we care
 * about into a wai_webkdc_login_state record that we'll use to accumulate the
 * results of the login.  This primarily does token decoding, but also copies
 * some other information.  Returns a WebAuth status.
 */
static int
parse_request(struct webauth_context *ctx,
              const struct webauth_webkdc_login_request *request,
              struct wai_webkdc_login_state *state,
              const struct webauth_keyring *ring)
{
    int s;

    /* Decrypt the webkdc-service token and set up the session keyring. */
    s = parse_token_webkdc_service(ctx, request->service, state, ring);
    if (s != WA_ERR_NONE)
        return s;

    /* Decrypt the request token. */
    s = parse_token_request(ctx, request->request, state);
    if (s != WA_ERR_NONE)
        return s;

    /* Decrypt the webkdc-proxy, webkdc-factor, and login tokens. */
    s = parse_token_logins(ctx, request->logins, state, ring);
    if (s != WA_ERR_NONE)
        return s;
    s = parse_token_webkdc_factors(ctx, request->wkfactors, state, ring);
    if (s != WA_ERR_NONE)
        return s;
    s = parse_token_webkdc_proxies(ctx, request->wkproxies, state, ring);
    if (s != WA_ERR_NONE)
        return s;

    /* Add additional information from the request. */
    state->authz_subject_in = request->authz_subject;
    state->login_state_in   = request->login_state;
    state->client_ip        = request->client_ip;
    state->remote_ip        = request->remote_ip;
    return WA_ERR_NONE;
}


/*
 * Attempt an OTP authentication, which is a user authentication validatation
 * via the user information service.
 *
 * On success, generate a new webkdc-proxy token based on that information and
 * store it in the wkproxies state and note that we had a successful login.
 * If the validate call returned persistent factors, also create a
 * webkdc-factor token and store that in the wkfactors state.
 */
static int
do_login_otp(struct webauth_context *ctx,
             struct wai_webkdc_login_state *state,
             struct webauth_token_login *login)
{
    struct webauth_token *wkfactor, *wkproxy;
    struct webauth_token_webkdc_factor *wft;
    struct webauth_token_webkdc_proxy *wpt;
    struct webauth_user_validate *validate;
    time_t max_expiration;
    int s;

    /* Do the remote validation call. */
    if (ctx->user == NULL)
        return wai_error_set(ctx, WA_PEC_LOGIN_FAILED, "OTP not configured");
    s = webauth_user_validate(ctx, login->username, state->remote_ip,
                              login->otp, login->otp_type,
                              login->device_id, state->login_state_in,
                              &validate);
    if (s != WA_ERR_NONE)
        return s;

    /*
     * If validation failed, set the login error code and return.  If we have
     * a user message or login state, use WA_PEC_LOGIN_REJECTED instead so that
     * mod_webkdc will pass a <requestTokenResponse> back to the WebLogin
     * server and including the user message or login state.
     */
    if (!validate->success) {
        if (validate->user_message == NULL && validate->login_state == NULL) {
            s = WA_PEC_LOGIN_FAILED;
            wai_error_set(ctx, s, NULL);
        } else {
            s = WA_PEC_LOGIN_REJECTED;
            wai_error_set(ctx, s, "rejected by validation service");
            state->login_state_out = validate->login_state;
            state->user_message    = validate->user_message;
        }
        return s;
    }

    /*
     * Adjust for old versions of the user information service that don't
     * return an expiration time for factors.
     */
    if (validate->factors_expiration == 0)
        validate->factors_expiration = time(NULL) + DEFAULT_OTP_LIFETIME;

    /* Create the resulting webkdc-proxy token. */
    wkproxy = apr_pcalloc(ctx->pool, sizeof(struct webauth_token));
    wkproxy->type = WA_TOKEN_WEBKDC_PROXY;
    wpt = &wkproxy->token.webkdc_proxy;
    wpt->subject         = login->username;
    wpt->proxy_type      = "otp";
    wpt->proxy_subject   = "WEBKDC:otp";
    wpt->data            = login->username;
    wpt->data_len        = strlen(login->username);
    wpt->initial_factors = webauth_factors_string(ctx, validate->factors);
    wpt->session_factors = wpt->initial_factors;
    wpt->loa             = validate->loa;
    wpt->expiration      = validate->factors_expiration;
    wpt->creation        = time(NULL);

    /* Cap the proxy token expiration based on our configuration. */
    if (ctx->webkdc->proxy_lifetime > 0) {
        max_expiration = time(NULL) + ctx->webkdc->proxy_lifetime;
        if (wpt->expiration > max_expiration)
            wpt->expiration = max_expiration;
    }

    /* Store this token in the login state and note the successful login. */
    APR_ARRAY_PUSH(state->wkproxies, struct webauth_token *) = wkproxy;
    state->did_login = true;

    /*
     * If there are any persistent-factor tokens, create a webkdc-factor
     * token and add it to the response.
     */
    if (validate->persistent != NULL) {
        wkfactor = apr_pcalloc(ctx->pool, sizeof(struct webauth_token));
        wkfactor->type = WA_TOKEN_WEBKDC_FACTOR;
        wft = &wkfactor->token.webkdc_factor;
        wft->subject    = login->username;
        wft->factors    = webauth_factors_string(ctx, validate->persistent);
        wft->expiration = validate->persistent_expiration;
        wft->creation   = time(NULL);
        APR_ARRAY_PUSH(state->wkfactors, struct webauth_token *) = wkfactor;
    }
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
realm_permitted(struct webauth_context *ctx, struct webauth_krb5 *kc)
{
    int s, i;
    char *realm;
    const char *allow;
    bool okay = false;

    /* If we aren't restricting the realms, always return true. */
    if (apr_is_empty_array(ctx->webkdc->permitted_realms))
        return WA_ERR_NONE;

    /* Get the realm. */
    s = webauth_krb5_get_realm(ctx, kc, &realm);
    if (s != WA_ERR_NONE)
        return s;

    /* Check against the configured permitted realms. */
    for (i = 0; i < ctx->webkdc->permitted_realms->nelts; i++) {
        allow = APR_ARRAY_IDX(ctx->webkdc->permitted_realms, i, const char *);
        if (strcmp(allow, realm) == 0) {
            okay = true;
            break;
        }
    }
    if (!okay) {
        s = WA_PEC_USER_REJECTED;
        return wai_error_set(ctx, s, "realm %s is not permitted", realm);
    }
    return WA_ERR_NONE;
}


/*
 * Helper function to check the realm of a Kerberos context against the list
 * of realms in ctx->webkdc->local_realms.  Returns either WA_KRB5_CANON_STRIP
 * if there is a match or WA_KRB5_CANON_NONE if there isn't.
 */
static enum webauth_krb5_canon
is_local_realm(struct webauth_context *ctx, struct webauth_krb5 *kc)
{
    const char *local;
    char *realm;
    int i, s;

    s = webauth_krb5_get_realm(ctx, kc, &realm);
    if (s != WA_ERR_NONE)
        return s;
    for (i = 0; i < ctx->webkdc->local_realms->nelts; i++) {
        local = APR_ARRAY_IDX(ctx->webkdc->local_realms, i, const char *);
        if (strcmp(local, realm) == 0)
            return WA_KRB5_CANON_STRIP;
    }
    return WA_KRB5_CANON_NONE;
}


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
    enum webauth_krb5_canon canonicalize;
    const char *local;
    char *subject;
    int s;

    /* Set the default result. */
    *result = NULL;

    /*
     * If there is no local_realms configuration, we're going to do local
     * canonicalization.  If there is only one element, check if it's a
     * keyword.
     */
    if (apr_is_empty_array(ctx->webkdc->local_realms))
        canonicalize = WA_KRB5_CANON_LOCAL;
    else {
        local = APR_ARRAY_IDX(ctx->webkdc->local_realms, 0, const char *);
        if (strcmp(local, "none") == 0)
            canonicalize = WA_KRB5_CANON_NONE;
        else if (strcmp(local, "local") == 0)
            canonicalize = WA_KRB5_CANON_LOCAL;
        else
            canonicalize = is_local_realm(ctx, kc);
    }

    /*
     * We now know the canonicalization method we're using, so we can retrieve
     * the principal from the context.  Move the result into the main WebAuth
     * context pool.
     */
    s = webauth_krb5_get_principal(ctx, kc, &subject, canonicalize);
    if (s != WA_ERR_NONE)
        return s;
    *result = apr_pstrdup(ctx->pool, subject);
    return WA_ERR_NONE;
}


/*
 * Attempt a username and password login via Kerberos.  On success, generate a
 * new webkdc-proxy token based on that information and store it in the token
 * argument.
 */
static int
do_login_krb(struct webauth_context *ctx,
             struct wai_webkdc_login_state *state,
             struct webauth_token_login *login)
{
    struct webauth_krb5 *kc;
    struct webauth_token *wkproxy;
    struct webauth_token_webkdc_proxy *wpt;
    const char *subject;
    char *webkdc;
    void *tgt;
    size_t tgt_len;
    time_t expires, max_expiration;
    int s;

    /*
     * Attempt the Kerberos authentication.  webauth_krb5_init_via_password
     * returns protocol error codes except for internal Kerberos errors, so we
     * don't need to do any mapping.
     */
    s = webauth_krb5_new(ctx, &kc);
    if (s != WA_ERR_NONE)
        return s;
    if (ctx->webkdc->fast_armor_path != NULL) {
        const char *path;

        path = ctx->webkdc->fast_armor_path;
        s = webauth_krb5_set_fast_armor_path(ctx, kc, path);
        if (s != WA_ERR_NONE)
            return s;
    }
    s = webauth_krb5_init_via_password(ctx, kc, login->username,
                                       login->password, NULL,
                                       ctx->webkdc->keytab_path,
                                       ctx->webkdc->principal, NULL, &webkdc);
    if (s != WA_ERR_NONE)
        goto done;

    /*
     * Check if the realm of the authenticated principal is permitted and
     * then canonicalize the user's identity.
     */
    s = realm_permitted(ctx, kc);
    if (s != WA_ERR_NONE)
        goto done;
    s = canonicalize_user(ctx, kc, &subject);
    if (s != WA_ERR_NONE)
        goto done;

    /*
     * Export the ticket-granting ticket for the webkdc-proxy token and move
     * it into the context pool from the Kerberos context pool.
     */
    s = webauth_krb5_export_cred(ctx, kc, NULL, &tgt, &tgt_len, &expires);
    if (s != WA_ERR_NONE)
        goto done;
    tgt = apr_pmemdup(ctx->pool, tgt, tgt_len);

    /*
     * We now have everything we need to create the webkdc-proxy token.  We've
     * already copied all this stuff into a pool, so there is no need to copy
     * again.
     */
    wkproxy = apr_pcalloc(ctx->pool, sizeof(struct webauth_token));
    wkproxy->type = WA_TOKEN_WEBKDC_PROXY;
    wpt = &wkproxy->token.webkdc_proxy;
    wpt->subject         = subject;
    wpt->proxy_type      = "krb5";
    wpt->proxy_subject   = apr_psprintf(ctx->pool, "WEBKDC:krb5:%s", webkdc);
    wpt->data            = tgt;
    wpt->data_len        = tgt_len;
    wpt->initial_factors = WA_FA_PASSWORD;
    wpt->session_factors = WA_FA_PASSWORD;
    wpt->creation        = time(NULL);
    wpt->expiration      = expires;

    /* Cap the proxy token expiration based on our configuration. */
    if (ctx->webkdc->proxy_lifetime > 0) {
        max_expiration = time(NULL) + ctx->webkdc->proxy_lifetime;
        if (wpt->expiration > max_expiration)
            wpt->expiration = max_expiration;
    }

    /* Store this token in the login state and note the successful login. */
    APR_ARRAY_PUSH(state->wkproxies, struct webauth_token *) = wkproxy;
    state->did_login = true;

done:
    webauth_krb5_free(ctx, kc);
    return s;
}


/*
 * Process the login credentials.  We either process a password login or an
 * OTP login depending on the contents of the login tokens.  If any logins are
 * unsuccessful, we abort further processing with an error.  The resulting
 * webkdc-proxy or webkdc-factor tokens are added to the login state.  If
 * there are any successful logins, we also set the did_login state.
 */
static int
do_logins(struct webauth_context *ctx, struct wai_webkdc_login_state *state)
{
    struct webauth_token *token;
    int i, s;

    for (i = 0; i < state->logins->nelts; i++) {
        token = APR_ARRAY_IDX(state->logins, i, struct webauth_token *);
        if (token->token.login.otp != NULL)
            s = do_login_otp(ctx, state, &token->token.login);
        else
            s = do_login_krb(ctx, state, &token->token.login);

        /*
         * If the login fails, store the user corresponding to the failed
         * login token in the state struct for logging purposes.
         */
        if (s != WA_ERR_NONE) {
            state->login_subject = token->token.login.username;
            return s;
        }
    }
    return WA_ERR_NONE;
}


/*
 * Merge a set of accumulated webkdc-proxy tokens and perform any needed
 * additional validation checks.
 */
static int
merge_webkdc_proxies(struct webauth_context *ctx,
                     struct wai_webkdc_login_state *state)
{
    struct webauth_token *wkproxy;
    struct webauth_token_webkdc_proxy *wpt;
    time_t limit;
    int s;

    /*
     * Merge the webkdc-proxy tokens.  If we get WA_ERR_TOKEN_REJECTED back,
     * the client tried to use webkdc-proxy tokens with inconsistent subjects
     * or proxy subjects.  Rejected this as unauthorized.
     */
    limit = ctx->webkdc->login_time_limit;
    s = wai_token_merge_webkdc_proxy(ctx, state->wkproxies, limit, &wkproxy);
    if (s == WA_ERR_TOKEN_REJECTED) {
        wai_log_error(ctx, WA_LOG_WARN, s, "rejecting webkdc-proxy tokens");
        s = WA_PEC_UNAUTHORIZED;
        return wai_error_set(ctx, s, "may not use webkdc-proxy token");
    } else if (s != WA_ERR_NONE) {
        wai_error_context(ctx, "merging webkdc-proxy tokens");
        return s;
    }

    /*
     * If there is no result (if, for example, all the tokens are expired or
     * there were no input tokens), we're done.
     */
    if (wkproxy == NULL)
        return WA_ERR_NONE;

    /*
     * For login purposes, the webkdc-proxy token must have a proxy subject
     * starting with "WEBKDC:" to indicate that it is an SSO token.
     */
    wpt = &wkproxy->token.webkdc_proxy;
    if (strncmp(wpt->proxy_subject, "WEBKDC:", 7) != 0) {
        s = WA_PEC_PROXY_TOKEN_INVALID;
        return wai_error_set(ctx, s, "proxy subject %s not allowed",
                             wpt->proxy_subject);
    }
    state->wkproxy = wkproxy;
    return WA_ERR_NONE;
}


/*
 * Merge a set of accumulated webkdc-factor tokens into one and store that in
 * the state struct.  If the webkdc-proxy token pointer isn't NULL, also
 * incorporate their factors into the webkdc-proxy token.
 */
static int
merge_webkdc_factors(struct webauth_context *ctx,
                     struct wai_webkdc_login_state *state,
                     struct webauth_token **wkproxy)
{
    struct webauth_token *old, *wkfactor;
    int s;

    s = wai_token_merge_webkdc_factor(ctx, state->wkfactors, &state->wkfactor);
    if (s != WA_ERR_NONE) {
        wai_error_context(ctx, "merging webkdc-factor tokens");
        return s;
    }
    if (wkproxy != NULL && *wkproxy != NULL) {
        old = *wkproxy;
        wkfactor = state->wkfactor;
        s = wai_token_merge_webkdc_proxy_factor(ctx, old, wkfactor, wkproxy);
        if (s != WA_ERR_NONE)
            return s;
    }
    return WA_ERR_NONE;
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
    struct webauth_factors *factors;
    time_t now;
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
        struct webauth_token_webkdc_factor *wft;

        /* Extract and set a pointer to the next webkdc-factor token. */
        token = APR_ARRAY_IDX(wkfactors, i, struct webauth_token *);
        if (token->type != WA_TOKEN_WEBKDC_FACTOR)
            continue;
        wft = &token->token.webkdc_factor;

        /* Discard all expired and non-matching tokens. */
        if (wft->expiration <= now)
            continue;
        if (strcmp(wft->subject, subject) != 0)
            continue;

        /* Merge in the factor information. */
        extra = webauth_factors_parse(ctx, wft->factors);
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
invalidate_webkdc_factors(struct webauth_context *ctx,
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
        struct webauth_token_webkdc_factor *wft;

        /* Extract and set a pointer to the next webkdc-factor token. */
        token = APR_ARRAY_IDX(wkfactors, i, struct webauth_token *);
        if (token->type != WA_TOKEN_WEBKDC_FACTOR)
            continue;
        wft = &token->token.webkdc_factor;

        /* Expire the token if the creation time is too early. */
        if (wft->creation < valid_threshold) {
            wai_log_notice(ctx, "invalidating webkdc-factor token for %s"
                           " (creation %lu < %lu)", wft->subject,
                           (unsigned long) wft->creation,
                           (unsigned long) valid_threshold);
            wft->expiration = now - 1;
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
              struct wai_webkdc_login_state *state,
              struct webauth_user_info **info)
{
    const struct webauth_token_webkdc_proxy *wkp;
    struct webauth_factors *ifactors, *iwkfactors, *sfactors, *swkfactors;
    struct webauth_factors *random, *extra;
    bool randmf = false;
    const char *factors;
    int s;

    /* Parse the request factors. */
    ifactors = webauth_factors_parse(ctx, state->request->initial_factors);
    sfactors = webauth_factors_parse(ctx, state->request->session_factors);

    /* Create a webauth_factors struct representing random multifactor. */
    random = webauth_factors_parse(ctx, WA_FA_RANDOM_MULTIFACTOR);

    /* Parse the factors from the webkdc-proxy token. */
    wkp = &state->wkproxy->token.webkdc_proxy;
    iwkfactors = webauth_factors_parse(ctx, wkp->initial_factors);
    swkfactors = webauth_factors_parse(ctx, wkp->session_factors);

    /* Add the factors from the webkdc-factor tokens. */
    extra = combine_webkdc_factors(ctx, state->wkfactors, wkp->subject);
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
    s = webauth_user_info(ctx, wkp->subject, state->remote_ip, randmf,
                          state->request->return_url, factors, info);

    /*
     * If the user information service succeeded but returned an error, treat
     * that as a failure and store the error as the user message.
     */
    if (s == WA_ERR_NONE && (*info)->error != NULL) {
        state->user_message = (*info)->error;
        s = WA_PEC_AUTH_REJECTED;
        wai_error_set(ctx, s, "rejected by user information service");
    }
    return s;
}


/*
 * Given the request, the response, our webkdc-proxy token, any webkdc-factor
 * tokens, a flag saying whether we did a login, and a struct to fill in with
 * the user information, call the user information service and flesh out our
 * response data and webkdc-proxy token with the results.  If the user
 * information service says to invalidate webkdc-factor tokens, do so and then
 * retry the call.
 *
 * This function also handles updating the webkdc-proxy token with the full
 * set of factors from the user information service, random multifactor, and
 * the webkdc-factor tokens, and merges the webkdc-factor tokens into one.
 * This isn't directly related, but since we're parsing all the tokens anyway
 * and possibly invalidating some, it's convenient to do it here.
 */
static int
add_user_info(struct webauth_context *ctx,
              struct wai_webkdc_login_state *state,
              struct webauth_user_info **info)
{
    struct webauth_factors *iwkfactors, *swkfactors, *extra;
    struct webauth_token_webkdc_proxy *wkp;
    time_t valid_threshold;
    int s;

    /* Call the user information service. */
    s = get_user_info(ctx, state, info);
    if (s != WA_ERR_NONE)
        return s;

    /*
     * If the user information service provides an invalid_before time, expire
     * any webkdc-factor tokens that were created before that time.  Then,
     * redo the user information service call if any webkdc-factor tokens were
     * invalidated, since we may now have different authentication factors.
     */
    valid_threshold = (*info)->valid_threshold;
    if (invalidate_webkdc_factors(ctx, state->wkfactors, valid_threshold)) {
        s = get_user_info(ctx, state, info);
        if (s != WA_ERR_NONE)
            return s;
    }

    /* Add results from the user information service to our state. */
    if (state->did_login)
        state->login_info = (*info)->logins;
    state->default_device   = (*info)->default_device;
    state->default_factor   = (*info)->default_factor;
    state->device_info      = (*info)->devices;
    state->user_message     = (*info)->user_message;
    state->login_state_out  = (*info)->login_state;
    state->password_expires = (*info)->password_expires;

    /* Cap the user's LoA at the maximum allowed by the service. */
    wkp = &state->wkproxy->token.webkdc_proxy;
    if (wkp->loa > (*info)->max_loa)
        wkp->loa = (*info)->max_loa;

    /* Parse the current factors from the webkdc-proxy token. */
    iwkfactors = webauth_factors_parse(ctx, wkp->initial_factors);
    swkfactors = webauth_factors_parse(ctx, wkp->session_factors);

    /* Add the factors from the webkdc-factor tokens. */
    extra = combine_webkdc_factors(ctx, state->wkfactors, wkp->subject);
    iwkfactors = webauth_factors_union(ctx, iwkfactors, extra);
    swkfactors = webauth_factors_union(ctx, swkfactors, extra);

    /*
     * Add the random multifactor factor to the factors of our webkdc-proxy
     * token if we did random multifactor and our existing factors satisfy all
     * factors required by the user information service.
     */
    if ((*info)->random_multifactor) {
        struct webauth_factors *random;

        random = webauth_factors_parse(ctx, WA_FA_RANDOM_MULTIFACTOR);
        if (webauth_factors_satisfies(ctx, iwkfactors, (*info)->required))
            iwkfactors = webauth_factors_union(ctx, iwkfactors, random);
        if (webauth_factors_satisfies(ctx, swkfactors, (*info)->required))
            swkfactors = webauth_factors_union(ctx, swkfactors, random);
    }

    /* Add additional factors if we have any and we did a login. */
    if (state->did_login && (*info)->additional != NULL) {
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
 * impossible.  If the request asks for a Kerberos authenticator or Kerberos
 * proxy credentials, also check if we can satisfy those with the proxy token
 * we have.
 *
 * Returns a WebAuth status code, and sets the configured and required factors
 * if multifactor is needed and can be met by the user's configured factors.
 */
static int
check_factors_proxy(struct webauth_context *ctx,
                    struct wai_webkdc_login_state *state,
                    struct webauth_user_info *info)
{
    struct webauth_factors *wanted, *swanted, *have, *shave;
    const struct webauth_factors *configured;
    struct webauth_token_webkdc_proxy *wpt;
    bool need_kerberos;
    int s = WA_ERR_NONE;

    /* Figure out what factors we want and have. */
    wpt = &state->wkproxy->token.webkdc_proxy;
    wanted  = webauth_factors_parse(ctx, state->request->initial_factors);
    swanted = webauth_factors_parse(ctx, state->request->session_factors);
    have    = webauth_factors_parse(ctx, wpt->initial_factors);
    shave   = webauth_factors_parse(ctx, wpt->session_factors);

    /*
     * Check if there are factors required by user configuration.  If so, add
     * them to the initial factors that we require.
     */
    if (info != NULL && info->required != NULL)
        wanted = webauth_factors_union(ctx, wanted, info->required);

    /*
     * Check the level of assurance required.  If the user cannot establish a
     * sufficient level of assurance, punt immediately; we don't care about
     * the available factors in that case.
     */
    if (state->request->loa > wpt->loa) {
        if (info != NULL && state->request->loa > info->max_loa)
            return wai_error_set(ctx, WA_PEC_LOA_UNAVAILABLE, NULL);
        s = WA_PEC_MULTIFACTOR_REQUIRED;
    }

    /*
     * If we need Kerberos, check if we have a Kerberos authenticator.  If
     * not, set our initial error code.  We may override that later if the
     * user can't satisfy the required factors.
     */
    need_kerberos = false;
    if (strcmp(state->request->type, "id") == 0) {
        if (strcmp(state->request->auth, "krb5") == 0)
            need_kerberos = true;
    } else if (strcmp(state->request->type, "proxy") == 0) {
        if (strcmp(state->request->proxy_type, "krb5") == 0)
            need_kerberos = true;
    }
    if (need_kerberos && strcmp(wpt->proxy_type, "krb5") != 0)
        s = WA_PEC_PROXY_TOKEN_REQUIRED;

    /*
     * See if the WAS-requested factors are already satisfied by the factors
     * that we have.  If not, choose the error message.  If the user can't
     * satisfy the factors at all, we'll change the error later.  Be careful
     * not to override errors from the LoA or Kerberos authenticator checks.
     *
     * If the user has no password session factor, we need to start them at
     * the beginning of the login process to ensure we get all the required
     * factors and any synthesized multifactor.  But be careful not to loop on
     * the password screen if they do have a password session factor already.
     *
     * We assume that if the user needs factors they don't have but are
     * capable of getting, the correct next step is to force a multifactor
     * authentication.  This may not be the correct assumption always, but it
     * works for the most common cases.
     */
    if (s == WA_ERR_NONE) {
        if (webauth_factors_satisfies(ctx, have, wanted)) {
            if (!webauth_factors_satisfies(ctx, shave, swanted)) {
                if (webauth_factors_contains(ctx, shave, WA_FA_PASSWORD))
                    s = WA_PEC_MULTIFACTOR_REQUIRED;
                else
                    s = WA_PEC_LOGIN_FORCED;
            }
        } else {
            if (webauth_factors_contains(ctx, have, WA_FA_PASSWORD))
                s = WA_PEC_MULTIFACTOR_REQUIRED;
            else
                s = WA_PEC_LOGIN_FORCED;
        }
    }
    if (s == WA_ERR_NONE)
        return WA_ERR_NONE;

    /*
     * Fourth, remove the factors the user already has from the factors that
     * are required.  We do this before checking whether the desired factors
     * are satisfiable since the user may have factors that the user
     * information service doesn't know they can have.  We also only want to
     * report to WebLogin the additional factors the user needs but doesn't
     * have, not the full list that they've partially satisfied.
     */
    wanted  = webauth_factors_subtract(ctx, wanted, have);
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
    state->factors_wanted = webauth_factors_union(ctx, wanted, swanted);
    state->factors_configured = configured;
    if (!webauth_factors_satisfies(ctx, configured, wanted))
        s = WA_PEC_MULTIFACTOR_UNAVAILABLE;
    else if (!webauth_factors_satisfies(ctx, configured, swanted))
        s = WA_PEC_MULTIFACTOR_UNAVAILABLE;

    /* If there was an error, set the error text. */
    if (s != WA_ERR_NONE)
        wai_error_set(ctx, s, NULL);
    return s;
}



/*
 * Check forced authentication.  If this option is requested, we require an
 * interactive login.  This is based on the did_login state, which is present
 * if we successfully processed a login token.
 *
 * Note that this means that forced authentication cannot be used in
 * conjunction with changing authorization identities from the confirmation
 * screen, since the user will be required to reauthenticate.
 */
static int
check_forced_auth(struct webauth_context *ctx,
                  struct wai_webkdc_login_state *state)
{
    const char *options;

    /* FIXME: strstr is lame. */
    options = state->request->options;
    if (options != NULL && strstr(options, "fa") != NULL)
        if (!state->did_login)
            return wai_error_set(ctx, WA_PEC_LOGIN_FORCED, NULL);
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
    int s;
    unsigned long line;
    apr_file_t *acl;
    apr_int32_t flags;
    apr_status_t code;
    char buf[BUFSIZ];
    const char *path;
    char *p, *authn, *was, *authz, *last;
    apr_array_header_t *identities = NULL;

    /* If there is no identity ACL file, there is a NULL array. */
    *result = NULL;
    path = ctx->webkdc->id_acl_path;
    if (path == NULL)
        return WA_ERR_NONE;

    /* Open the identity ACL file. */
    flags = APR_FOPEN_READ | APR_FOPEN_BUFFERED | APR_FOPEN_NOCLEANUP;
    code = apr_file_open(&acl, path, flags, APR_FPROT_OS_DEFAULT, ctx->pool);
    if (code != APR_SUCCESS) {
        s = WA_ERR_FILE_OPENREAD;
        return wai_error_set_apr(ctx, s, code, "identity ACL %s", path);
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
            s = WA_ERR_FILE_READ;
            wai_error_set(ctx, s, "identity ACL %s line %lu too long", path,
                          line);
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
            s = WA_ERR_FILE_READ;
            wai_error_set(ctx, s, "missing target on identity ACL %s line %lu",
                          path, line);
            goto done;
        }
        if (strcmp(target, was) != 0)
            continue;
        authz = apr_strtok(NULL, " \t\r\n", &last);
        if (authz == NULL) {
            s = WA_ERR_FILE_READ;
            wai_error_set(ctx, s, "missing identity on identity ACL %s"
                          " line %lu", path, line);
            goto done;
        }
        if (identities == NULL)
            identities = apr_array_make(ctx->pool, 1, sizeof(char *));
        APR_ARRAY_PUSH(identities, char *) = apr_pstrdup(ctx->pool, authz);
    }
    if (code != APR_SUCCESS && code != APR_EOF) {
        s = WA_ERR_FILE_READ;
        wai_error_set_apr(ctx, s, code, "identity ACL %s", path);
        goto done;
    }
    *result = identities;
    s = WA_ERR_NONE;

done:
    apr_file_close(acl);
    return s;
}


/*
 * If the user attempts to assert an alternate identity, see if that's
 * allowed.  If the requested authorization subject matches the actual
 * subject, just ignore and clear the field in the login state.  Takes the
 * established identity of the subject.
 */
static int
check_authz_identity(struct webauth_context *ctx,
                     struct wai_webkdc_login_state *state,
                     const char *subject)
{
    const apr_array_header_t *permitted;
    const char *authz_subject, *allowed;
    bool okay;
    int i, s;

    /* Obtain the list of identities the user is allowed to assert. */
    s = build_identity_list(ctx, subject, state->service->subject, &permitted);
    if (s != WA_ERR_NONE)
        return s;
    state->permitted_authz = permitted;

    /* Check whether the user tried to assert a different identity. */
    authz_subject = state->authz_subject_in;
    if (authz_subject == NULL)
        return WA_ERR_NONE;
    if (strcmp(authz_subject, subject) == 0)
        return WA_ERR_NONE;

    /* Check whether the requested identity is permitted. */
    if (apr_is_empty_array(permitted))
        goto fail;
    okay = false;
    for (i = 0; i < permitted->nelts; i++) {
        allowed = APR_ARRAY_IDX(permitted, i, const char *);
        if (strcmp(allowed, authz_subject) == 0) {
            okay = true;
            break;
        }
    }
    if (!okay)
        goto fail;
    state->authz_subject_out = authz_subject;
    return WA_ERR_NONE;

fail:
    wai_error_set(ctx, WA_PEC_UNAUTHORIZED, "may not assert that identity");
    return WA_PEC_UNAUTHORIZED;
}


/*
 * Given the identity of a WAS and a webkdc-proxy token identifying the user,
 * obtain a Kerberos authenticator identifying that user to that WAS.  Store
 * it in the provided buffer.  Returns either WA_ERR_NONE on success or a
 * WebAuth error code.  On error, also set the WebAuth error message.
 */
static int
get_krb5_authenticator(struct webauth_context *ctx, const char *server,
                       const struct webauth_token_webkdc_proxy *wpt,
                       void **auth, size_t *auth_len)
{
    struct webauth_krb5 *kc;
    void *data;
    int s;

    /* Clear the output authentication data. */
    *auth = NULL;

    /* Ensure that we have a Kerberos webkdc-proxy token. */
    if (strcmp(wpt->proxy_type, "krb5") != 0)
        return wai_error_set(ctx, WA_PEC_PROXY_TOKEN_REQUIRED, NULL);

    /*
     * FIXME: Probably need to examine errors a little more closely to
     * determine if we should return a proxy-token error or a server-failure.
     */
    s = webauth_krb5_new(ctx, &kc);
    if (s != WA_ERR_NONE)
        return s;
    s = webauth_krb5_import_cred(ctx, kc, wpt->data, wpt->data_len, NULL);
    if (s != WA_ERR_NONE)
        goto done;

    /*
     * Generate the Kerberos authenticator.
     *
     * FIXME: Probably need to examine errors a little more closely to
     * determine if we should return a proxy-token error or a server-failure.
     */
    if (strncmp(server, "krb5:", 5) == 0)
        server += 5;
    s = webauth_krb5_make_auth(ctx, kc, server, &data, auth_len);
    if (s == WA_ERR_NONE)
        *auth = apr_pmemdup(ctx->pool, data, *auth_len);

done:
    webauth_krb5_free(ctx, kc);
    return s;
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
                const struct wai_webkdc_login_state *state,
                const char **result)
{
    struct webauth_token token;
    struct webauth_token_id *id;
    const struct webauth_token_webkdc_proxy *wpt;
    const char *requester;
    void *auth;
    size_t auth_len;
    int s;

    /* Set the basic token data. */
    wpt = &state->wkproxy->token.webkdc_proxy;
    memset(&token, 0, sizeof(token));
    token.type = WA_TOKEN_ID;
    id = &token.token.id;
    id->subject         = wpt->subject;
    id->authz_subject   = state->authz_subject_out;
    id->auth            = state->request->auth;
    id->expiration      = wpt->expiration;
    id->initial_factors = wpt->initial_factors;
    id->session_factors = wpt->session_factors;
    id->loa             = wpt->loa;

    /* If a Kerberos authenticator was requested, obtain one. */
    if (strcmp(state->request->auth, "krb5") == 0) {
        requester = state->service->subject;
        s = get_krb5_authenticator(ctx, requester, wpt, &auth, &auth_len);
        if (s == WA_ERR_KRB5)
            s = wai_error_change(ctx, s, WA_PEC_PROXY_TOKEN_INVALID);
        if (s != WA_ERR_NONE)
            return s;
        id->auth_data     = auth;
        id->auth_data_len = auth_len;
    }

    /* Encode the token and store the resulting string. */
    return webauth_token_encode(ctx, &token, state->session, result);
}


/*
 * Given a WebKDC proxy token and a request token, create the proxy token
 * requested by the WAS and store it in the response.  At this point, we've
 * already done all required checks and ensured we have a WebKDC proxy token,
 * so this just involves setting the correct fields.  Returns a status code on
 * any sort of internal WebAuth error.
 *
 * This function needs the WebKDC keyring, since it has to encode the
 * embedded webkdc-proxy token in the WebKDC's private key.
 */
static int
create_proxy_token(struct webauth_context *ctx,
                   const struct wai_webkdc_login_state *state,
                   const char **result, const struct webauth_keyring *ring)
{
    struct webauth_token token, subtoken;
    struct webauth_token_proxy *proxy;
    const struct webauth_token_webkdc_proxy *wpt;
    const void *data;
    size_t data_len;
    int s;

    /* If the requested proxy type is krb5, check the webkdc-proxy token. */
    wpt = &state->wkproxy->token.webkdc_proxy;
    if (strcmp(state->request->proxy_type, "krb5") == 0)
        if (strcmp(wpt->proxy_type, "krb5") != 0)
            return wai_error_set(ctx, WA_PEC_PROXY_TOKEN_REQUIRED, NULL);

    /* Create the easy portions of the proxy token. */
    memset(&token, 0, sizeof(token));
    token.type = WA_TOKEN_PROXY;
    proxy = &token.token.proxy;
    proxy->subject         = wpt->subject;
    proxy->authz_subject   = state->authz_subject_out;
    proxy->type            = state->request->proxy_type;
    proxy->initial_factors = wpt->initial_factors;
    proxy->session_factors = wpt->session_factors;
    proxy->loa             = wpt->loa;
    proxy->expiration      = wpt->expiration;

    /* Create the embedded webkdc-proxy token and limit its scope. */
    memset(&subtoken, 0, sizeof(subtoken));
    subtoken.type = WA_TOKEN_WEBKDC_PROXY;
    subtoken.token.webkdc_proxy = *wpt;
    subtoken.token.webkdc_proxy.proxy_subject = state->service->subject;
    subtoken.token.webkdc_proxy.creation = 0;
    s = webauth_token_encode_raw(ctx, &subtoken, ring, &data, &data_len);
    if (s != WA_ERR_NONE)
        return s;

    /* Store the embedded webkdc-proxy token. */
    proxy->webkdc_proxy     = data;
    proxy->webkdc_proxy_len = data_len;

    /* Encode the token and store the resulting string. */
    return webauth_token_encode(ctx, &token, state->session, result);
}


/*
 * If the WAS requested login cancel support, generate an error token
 * representing a canceled login and store it in the response.  We will
 * return that token to WebLogin, which in turn will pass it (in the URL)
 * back to the WAS if the user clicks on the cancel login link.
 */
static int
create_login_cancel(struct webauth_context *ctx,
                    const struct wai_webkdc_login_state *state,
                    const char **token)
{
    struct webauth_token cancel;
    const char *options;

    /* FIXME: Use something better than strstr to see if the option is set. */
    options = state->request->options;
    if (options == NULL || strstr(options, "lc") == NULL)
        return WA_ERR_NONE;
    cancel.type = WA_TOKEN_ERROR;
    cancel.token.error.code     = WA_PEC_LOGIN_CANCELED;
    cancel.token.error.message  = "user canceled login";
    cancel.token.error.creation = 0;
    return webauth_token_encode(ctx, &cancel, state->session, token);
}


/*
 * Encode a webkdc-factor token and add it to the response.  We wrap this in a
 * webauth_webkdc_factor_data struct that includes the expiration information.
 */
static int
encode_webkdc_factor(struct webauth_context *ctx,
                     const struct webauth_token *wkfactor,
                     struct webauth_webkdc_login_response *response,
                     const struct webauth_keyring *ring)
{
    apr_array_header_t *factor_tokens;
    struct webauth_webkdc_factor_data *data;
    size_t size;
    int s;

    /* If there is no webkdc-factor token, there's nothing to do. */
    if (wkfactor == NULL)
        return WA_ERR_NONE;

    /* Create a single-element array of webauth_webkdc_factor_data. */
    size = sizeof(struct webauth_webkdc_factor_data);
    factor_tokens = apr_array_make(ctx->pool, 1, size);
    data = apr_array_push(factor_tokens);
    data->expiration = wkfactor->token.webkdc_factor.expiration;
    s = webauth_token_encode(ctx, wkfactor, ring, &data->token);
    if (s != WA_ERR_NONE)
        return s;
    response->factor_tokens = factor_tokens;
    return WA_ERR_NONE;
}


/*
 * Encode a webkdc-proxy token and add it to the response.  We wrap this in a
 * webauth_webkdc_proxy_data struct that includes the type information.
 */
static int
encode_webkdc_proxy(struct webauth_context *ctx,
                    const struct webauth_token *wkproxy,
                    struct webauth_webkdc_login_response *response,
                    const struct webauth_keyring *ring)
{
    apr_array_header_t *wkproxies;
    const struct webauth_token_webkdc_proxy *wpt;
    struct webauth_webkdc_proxy_data *data;
    size_t size;
    int s;

    /* If there is no webkdc-proxy token, there's nothing to do. */
    if (wkproxy == NULL)
        return WA_ERR_NONE;

    /* Create a single-element array of webauth_webkdc_proxy_data. */
    wpt = &wkproxy->token.webkdc_proxy;
    size = sizeof(struct webauth_webkdc_proxy_data);
    wkproxies = apr_array_make(ctx->pool, 1, size);
    data = apr_array_push(wkproxies);
    data->type = wpt->proxy_type;
    s = webauth_token_encode(ctx, wkproxy, ring, &data->token);
    if (s != WA_ERR_NONE)
        return s;

    /* Encode that array and other information in the response. */
    response->proxies = wkproxies;
    response->subject = wpt->subject;
    return WA_ERR_NONE;
}


/*
 * Encode the result token and store it in the response.
 */
static int
encode_result_token(struct webauth_context *ctx,
                    const struct wai_webkdc_login_state *state,
                    struct webauth_webkdc_login_response *response,
                    const struct webauth_keyring *ring)
{
    const char *type;
    int s;

    type = state->request->type;
    if (strcmp(type, "id") == 0)
        s = create_id_token(ctx, state, &response->result);
    else if (strcmp(type, "proxy") == 0)
        s = create_proxy_token(ctx, state, &response->result, ring);
    else {
        s = WA_PEC_REQUEST_TOKEN_INVALID;
        wai_error_set(ctx, s, "unsupported requested token type %s", type);
    }
    if (s == WA_ERR_NONE)
        response->result_type = type;
    return s;
}


/*
 * Take all the accumulated data from the login state and any merged
 * webkdc-proxy or webkdc-factor token and store it in the response.  Also
 * takes the WebKDC keyring to use for encrypting some of the tokens.
 */
static int
encode_response(struct webauth_context *ctx,
                const struct wai_webkdc_login_state *state,
                struct webauth_webkdc_login_response *response,
                const struct webauth_keyring *ring)
{
    int s;

    /* Add simple information to the response. */
    response->login_state        = state->login_state_out;
    response->user_message       = state->user_message;
    response->factors_wanted     = state->factors_wanted;
    response->factors_configured = state->factors_configured;
    response->default_device     = state->default_device;
    response->default_factor     = state->default_factor;
    response->authz_subject      = state->authz_subject_out;
    response->logins             = state->login_info;
    response->devices            = state->device_info;
    response->password_expires   = state->password_expires;
    response->permitted_authz    = state->permitted_authz;

    /* Add information from the webkdc-service token to the response. */
    if (state->service != NULL)
        response->requester = state->service->subject;

    /* Add information from the request to the response. */
    if (state->request != NULL) {
        response->return_url    = state->request->return_url;
        response->app_state     = state->request->state;
        response->app_state_len = state->request->state_len;
        s = create_login_cancel(ctx, state, &response->login_cancel);
        if (s != WA_ERR_NONE)
            return s;
    }

    /* Encode the result tokens into the response. */
    s = encode_webkdc_factor(ctx, state->wkfactor, response, ring);
    if (s != WA_ERR_NONE)
        return s;
    s = encode_webkdc_proxy(ctx, state->wkproxy, response, ring);
    if (s != WA_ERR_NONE)
        return s;

    /*
     * If there were no webkdc-proxy token, but we do have a subject from a
     * failed login token, use that as the response token.  This is primarily
     * for better logging of failures.
     */
    if (state->wkproxy == NULL && state->login_subject != NULL)
        response->subject = state->login_subject;
    return WA_ERR_NONE;
}


/*
 * Given the data from a <requestTokenRequest> login attempt, process that
 * attempted login and return the information for a <requestTokenResponse> in
 * a newly-allocated struct from pool memory.  Returns a protocol-compatible
 * WebAuth status code.
 */
int
webauth_webkdc_login(struct webauth_context *ctx,
                     const struct webauth_webkdc_login_request *request,
                     struct webauth_webkdc_login_response **response,
                     const struct webauth_keyring *ring)
{
    struct wai_webkdc_login_state state;
    struct webauth_user_info *info = NULL;
    const char *subject;
    int s, result;

    /* Set up our data structures. */
    *response = apr_pcalloc(ctx->pool, sizeof(**response));
    memset(&state, 0, sizeof(state));

    /* Parse the request into our login state.  This does token decryption. */
    s = parse_request(ctx, request, &state, ring);
    if (s != WA_ERR_NONE)
        goto done;

    /*
     * Process any login tokens.  This may result in more webkdc-proxy or
     * webkdc-factor tokens.  If there are any valid login tokens, this will
     * also set the did_login state.
     */
    s = do_logins(ctx, &state);
    if (s != WA_ERR_NONE)
        goto done;

    /*
     * We have collected all the user authentication information at this point
     * in a set of webkdc-proxy tokens and webkdc-factor tokens.  We want one
     * and only one webkdc-proxy token that has our combined factor
     * information and one webkdc-factor token that will be set as a
     * long-lived cookie in the client.
     *
     * First, merge all the webkdc-proxy tokens into a single new webkdc-proxy
     * token.  We don't encode this token yet since the user information
     * service call may change the factors.
     */
    s = merge_webkdc_proxies(ctx, &state);
    if (s != WA_ERR_NONE)
        goto done;

    /*
     * If we have no webkdc-proxy token, we're done; we can't authenticate the
     * user, so bounce them back to the WebLogin screen with what information
     * we do have.
     */
    if (state.wkproxy == NULL) {
        s = WA_PEC_PROXY_TOKEN_REQUIRED;
        wai_error_set(ctx, s, NULL);
        goto done;
    }

    /*
     * Retrieve information about the authenticated user and merge factor
     * information from that information and from webkdc-factor tokens.  Also,
     * merge all webkdc-factor tokens into one, which will be the output
     * token.
     *
     * If we don't have configuration about a user information service, we
     * trust all the webkdc-factor tokens unconditionally.
     *
     * If we have configuration for a user information service, we now know as
     * much as we're going to know about who the user is and should retrieve
     * that information if possible and flesh out the response.  Here is also
     * where we tell the user information service to do random multifactor if
     * needed.  The user information service call may update the factors in
     * the webkdc-proxy token and may invalidate webkdc-factor tokens.
     */
    if (ctx->user == NULL)
        s = merge_webkdc_factors(ctx, &state, &state.wkproxy);
    else {
        s = add_user_info(ctx, &state, &info);
        if (s != WA_ERR_NONE)
            goto done;
        s = merge_webkdc_factors(ctx, &state, NULL);
    }
    if (s != WA_ERR_NONE)
        goto done;

    /* Encode the webkdc-proxy token in the response and set the subject. */
    s = encode_webkdc_proxy(ctx, state.wkproxy, *response, ring);
    if (s != WA_ERR_NONE)
        goto done;

    /*
     * If the user information service or the request says that multifactor or
     * some other factor we don't have is required, reject the login with
     * either multifactor required or with multifactor unavailable, depending
     * on whether the user has multifactor configured.
     *
     * We also check here whether we have a Kerberos proxy token if the
     * request asks for a Kerberos authenticator or for Kerberos proxy
     * credentials.
     */
    s = check_factors_proxy(ctx, &state, info);
    if (s != WA_ERR_NONE)
        goto done;

    /* Check for forced authentication. */
    s = check_forced_auth(ctx, &state);
    if (s != WA_ERR_NONE)
        goto done;

    /*
     * Check the requested alternate identity, if any.  This always fills out
     * the permitted_authz member of our state even if the user didn't
     * attempt to assert a different identity.
     */
    subject = state.wkproxy->token.webkdc_proxy.subject;
    s = check_authz_identity(ctx, &state, subject);
    if (s != WA_ERR_NONE)
        goto done;

    /*
     * We have a single (or no) webkdc-proxy token that contains everything we
     * know about the user.  Attempt to satisfy their request.
     */
    s = encode_result_token(ctx, &state, *response, ring);
    if (s != WA_ERR_NONE)
        goto done;

done:
    /* Always encode the response, but save any earlier error. */
    result = s;
    s = encode_response(ctx, &state, *response, ring);
    if (s != WA_ERR_NONE)
        result = s;

    /*
     * On failure, map the status to a protocol status.  If we mapped the
     * status to a new one, log the original error message first so that we
     * don't lose the full context.
     */
    if (result != WA_ERR_NONE) {
        s = result;
        result = wai_error_protocol(ctx, s);
        if (result != s) {
            wai_log_error(ctx, WA_LOG_WARN, s, "cannot handle login request");
            wai_error_set(ctx, result, NULL);
        }
    }

    /* Log the result and return. */
    wai_webkdc_log_login(ctx, &state, result, *response);
    return result;
}
