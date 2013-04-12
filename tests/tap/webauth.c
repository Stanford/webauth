/*
 * Helper functions for testing WebAuth code.
 *
 * Additional functions that are helpful for testing WebAuth code and have
 * knowledge of WebAuth functions and data structures.  In all of the token
 * comparison functions, each component of the tokens is compared as a
 * separate test result, since that makes problem reporting much clearer and
 * more helpful to the developer.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <lib/internal.h>
#include <tests/tap/basic.h>
#include <tests/tap/string.h>
#include <tests/tap/webauth.h>
#include <webauth/keys.h>
#include <webauth/tokens.h>
#include <webauth/webkdc.h>


/*
 * Check a token creation time.  Takes the wanted and seen creation times, and
 * if wanted is 0, expects a creation time within a range of 5 seconds old and
 * 1 second fast compared to the current time.
 */
static void
is_token_creation(time_t wanted, time_t seen, const char *format, ...)
{
    va_list args;
    time_t now;
    bool okay;

    if (wanted == 0) {
        now = time(NULL);
        okay = (seen >= now - 5 && seen <= now + 1);
    } else {
        okay = (wanted == seen);
    }
    if (!okay)
        printf("# wanted: %lu\n#   seen: %lu\n", (unsigned long) wanted,
               (unsigned long) seen);
    va_start(args, format);
    okv(okay, format, args);
    va_end(args);
}


/*
 * Compare two error tokens.
 */
void
is_token_error(const struct webauth_token_error *wanted,
               const struct webauth_token_error *seen,
               const char *format, ...)
{
    va_list args;
    char *message;

    va_start(args, format);
    bvasprintf(&message, format, args);
    va_end(args);
    if (seen == NULL) {
        ok_block(3, false, "%s is NULL", message);
        return;
    }
    is_int(wanted->code, seen->code, "%s code", message);
    is_string(wanted->message, seen->message, "%s subject", message);
    is_token_creation(wanted->creation, seen->creation, "%s creation",
                      message);
    free(message);
}


/*
 * Compare two id tokens.
 */
void
is_token_id(const struct webauth_token_id *wanted,
            const struct webauth_token_id *seen,
            const char *format, ...)
{
    va_list args;
    char *message;

    va_start(args, format);
    bvasprintf(&message, format, args);
    va_end(args);
    if (seen == NULL) {
        ok_block(10, false, "%s is NULL", message);
        return;
    }
    is_string(wanted->subject, seen->subject, "%s subject", message);
    is_string(wanted->authz_subject, seen->authz_subject, "%s authz subject",
              message);
    is_string(wanted->auth, seen->auth, "%s auth type", message);
    if (wanted->auth_data == NULL || seen->auth_data == NULL)
        ok(wanted->auth_data == seen->auth_data, "%s auth data", message);
    else
        ok(memcmp(wanted->auth_data, seen->auth_data,
                  wanted->auth_data_len) == 0, "%s auth data", message);
    is_int(wanted->auth_data_len, seen->auth_data_len, "%s auth data length",
           message);
    is_string(wanted->initial_factors, seen->initial_factors,
              "%s initial factors", message);
    is_string(wanted->session_factors, seen->session_factors,
              "%s session factors", message);
    is_int(wanted->loa, seen->loa, "%s level of assurance", message);
    is_token_creation(wanted->creation, seen->creation, "%s creation",
                      message);
    is_int(wanted->expiration, seen->expiration, "%s expiration", message);
    free(message);
}


/*
 * Compare two proxy tokens.
 */
void
is_token_proxy(const struct webauth_token_proxy *wanted,
               const struct webauth_token_proxy *seen,
               const char *format, ...)
{
    va_list args;
    char *message;

    va_start(args, format);
    bvasprintf(&message, format, args);
    va_end(args);
    if (seen == NULL) {
        ok_block(10, false, "%s is NULL", message);
        return;
    }
    is_string(wanted->subject, seen->subject, "%s subject", message);
    is_string(wanted->authz_subject, seen->authz_subject, "%s authz subject",
              message);
    is_string(wanted->type, seen->type, "%s proxy type", message);
    if (wanted->webkdc_proxy == NULL || seen->webkdc_proxy == NULL)
        ok(wanted->webkdc_proxy == seen->webkdc_proxy, "%s webkdc proxy",
           message);
    else
        ok(memcmp(wanted->webkdc_proxy, seen->webkdc_proxy,
                  wanted->webkdc_proxy_len) == 0, "%s webkdc proxy", message);
    is_int(wanted->webkdc_proxy_len, seen->webkdc_proxy_len,
           "%s webkdc proxy length", message);
    is_string(wanted->initial_factors, seen->initial_factors,
              "%s initial factors", message);
    is_string(wanted->session_factors, seen->session_factors,
              "%s session factors", message);
    is_int(wanted->loa, seen->loa, "%s level of assurance", message);
    is_token_creation(wanted->creation, seen->creation, "%s creation",
                      message);
    is_int(wanted->expiration, seen->expiration, "%s expiration", message);
    free(message);
}


/*
 * Compare two webkdc-factor tokens.
 */
void
is_token_webkdc_factor(const struct webauth_token_webkdc_factor *wanted,
                       const struct webauth_token_webkdc_factor *seen,
                       const char *format, ...)
{
    va_list args;
    char *message;

    va_start(args, format);
    bvasprintf(&message, format, args);
    va_end(args);
    if (seen == NULL) {
        ok_block(4, false, "%s is NULL", message);
        return;
    }
    is_string(wanted->subject, seen->subject, "%s subject", message);
    is_string(wanted->factors, seen->factors, "%s factors", message);
    is_token_creation(wanted->creation, seen->creation, "%s creation",
                      message);
    is_int(wanted->expiration, seen->expiration, "%s expiration", message);
    free(message);
}


/*
 * Compare two webkdc-proxy tokens.
 */
void
is_token_webkdc_proxy(const struct webauth_token_webkdc_proxy *wanted,
                      const struct webauth_token_webkdc_proxy *seen,
                      const char *format, ...)
{
    va_list args;
    char *message;

    va_start(args, format);
    bvasprintf(&message, format, args);
    va_end(args);
    if (seen == NULL) {
        ok_block(9, false, "%s is NULL", message);
        return;
    }
    is_string(wanted->subject, seen->subject, "%s subject", message);
    is_string(wanted->proxy_type, seen->proxy_type, "%s proxy type", message);
    is_string(wanted->proxy_subject, seen->proxy_subject, "%s proxy subject",
              message);
    if (wanted->data == NULL || seen->data == NULL)
        ok(wanted->data == seen->data, "%s proxy data", message);
    else
        ok(memcmp(wanted->data, seen->data, wanted->data_len) == 0,
           "%s proxy data", message);
    is_int(wanted->data_len, seen->data_len, "%s proxy data length", message);
    is_string(wanted->initial_factors, seen->initial_factors,
              "%s initial factors", message);
    is_int(wanted->loa, seen->loa, "%s level of assurance", message);
    is_token_creation(wanted->creation, seen->creation, "%s creation",
                      message);
    is_int(wanted->expiration, seen->expiration, "%s expiration", message);
    is_string(wanted->session_factors, seen->session_factors,
              "%s session factors", message);
    free(message);
}


/*
 * Validate a WebKDC login response against a struct wat_login_test.  Takes a
 * WebAuth context, the test, the response, and the WebKDC and session
 * keyrings.
 */
static void
check_login_response(struct webauth_context *ctx,
                     const struct wat_login_test *test,
                     const struct webauth_webkdc_login_response *response,
                     const struct webauth_keyring *ring,
                     const struct webauth_keyring *session)
{
    const char *factors, *options;
    struct webauth_token *token;
    enum webauth_token_type type;
    size_t i;
    int s;

    /* The contents of any login canceled token. */
    static const struct webauth_token_error cancel_token = {
        WA_PEC_LOGIN_CANCELED, "user canceled login", 0
    };

    /* Check the login error code and message. */
    is_int(test->response.login_error, response->login_error,
           "... login error code");
    is_string(test->response.login_message, response->login_message,
              "... login error message");

    /* Check various simple response parameters. */
    is_string(test->response.user_message, response->user_message,
              "... user message");
    is_int(test->response.password_expires, response->password_expires,
           "... password expires");

    /* Check response parameters derived directly from the request. */
    is_string(test->request.request.return_url, response->return_url,
              "... return URL");
    is_string(test->request.service.subject, response->requester,
              "... requester");

    /* Check wanted and configured factors. */
    if (response->factors_wanted == NULL)
        ok(test->response.factors_wanted == NULL, "... has wanted factors");
    else {
        factors = apr_array_pstrcat(ctx->pool, response->factors_wanted, ',');
        is_string(test->response.factors_wanted, factors,
                  "... wanted factors");
    }
    if (response->factors_configured == NULL)
        ok(test->response.factors_configured == NULL,
           "... has configured factors");
    else {
        factors
            = apr_array_pstrcat(ctx->pool, response->factors_configured, ',');
        is_string(test->response.factors_configured, factors,
                  "... configured factors");
    }

    /*
     * Check returned webkdc-proxy tokens.  If and only if there is at least
     * one webkdc-proxy token, we will know and return the authenticated
     * identity in the subject field, so check that here as well.
     */
    for (i = 0; i < ARRAY_SIZE(test->response.proxies); i++) {
        struct webauth_webkdc_proxy_data *pd;

        if (test->response.proxies[i].subject == NULL)
            break;
        if (response->proxies == NULL || response->proxies->nelts <= (int) i)
            continue;
        pd = &APR_ARRAY_IDX(response->proxies, i,
                            struct webauth_webkdc_proxy_data);
        is_string(test->response.proxies[i].proxy_type, pd->type,
                  "... type of webkdc-proxy token %d", i);
        type = WA_TOKEN_WEBKDC_PROXY;
        s = webauth_token_decode(ctx, type, pd->token, ring, &token);
        is_int(WA_ERR_NONE, s, "... webkdc-proxy %d decodes", i);
        is_token_webkdc_proxy(&test->response.proxies[i],
                              &token->token.webkdc_proxy,
                              "... webkdc-proxy %d", i);
    }
    if (i == 0) {
        ok(response->proxies == NULL, "... has no webkdc-proxy tokens");
        is_string(NULL, response->subject, "... subject");
    } else if (response->proxies == NULL) {
        is_int(i, 0, "... correct number of webkdc-proxy tokens");
        is_string(test->response.proxies[0].subject, response->subject,
                  "... subject");
    } else {
        is_int(i, response->proxies->nelts,
               "... correct number of webkdc-proxy tokens");
        is_string(test->response.proxies[0].subject, response->subject,
                  "... subject");
    }

    /*
     * Check returned webkdc-factor tokens.  While we return a list for
     * forward-compatibility, the WebKDC will currently only ever return a
     * single token, which is reflected in the structure of the test data.
     */
    if (test->response.factor_token.subject == NULL)
        ok(response->factor_tokens == NULL, "... has no webkdc-factor tokens");
    else if (response->factor_tokens == NULL)
        ok(false, "... webkdc-factor token");
    else {
        struct webauth_webkdc_factor_data *fd;

        is_int(1, response->factor_tokens->nelts,
               "... one webkdc-factor token");
        fd = &APR_ARRAY_IDX(response->factor_tokens, 0,
                            struct webauth_webkdc_factor_data);
        is_int(test->response.factor_token.expiration, fd->expiration,
               "... expiration of webkdc-factor token");
        type = WA_TOKEN_WEBKDC_FACTOR;
        s = webauth_token_decode(ctx, type, fd->token, ring, &token);
        is_int(WA_ERR_NONE, s, "... webkdc-factor %d decodes", i);
        is_token_webkdc_factor(&test->response.factor_token,
                               &token->token.webkdc_factor,
                               "... webkdc-factor");
    }

    /*
     * Check the result token.  We determine which result type we're expecting
     * based on whether result_id or result_proxy has a non-NULL subject.  We
     * also check various other information in the response that's based on
     * the result token.
     */
    if (test->response.result_id.subject != NULL) {
        is_string("id", response->result_type, "... result type");
        is_string(test->response.result_id.authz_subject,
                  response->authz_subject, "... authorization subject");
        is_string(test->response.result_id.initial_factors,
                  response->initial_factors, "... initial factors");
        is_string(test->response.result_id.session_factors,
                  response->session_factors, "... session factors");
        is_int(test->response.result_id.loa, response->loa,
               "... level of assurance");
        type = WA_TOKEN_ID;
    } else if (test->response.result_proxy.subject != NULL) {
        is_string("proxy", response->result_type, "... result type");
        is_string(test->response.result_proxy.authz_subject,
                  response->authz_subject, "... authorization subject");
        is_string(test->response.result_proxy.initial_factors,
                  response->initial_factors, "... initial factors");
        is_string(test->response.result_proxy.session_factors,
                  response->session_factors, "... session factors");
        is_int(test->response.result_proxy.loa, response->loa,
               "... level of assurance");
        type = WA_TOKEN_PROXY;
    } else {
        is_string(NULL, response->result_type, "... result type");
        ok(response->result == NULL, "... no result token");
        is_string(NULL, response->authz_subject, "... authorization subject");
        is_string(NULL, response->initial_factors, "... initial factors");
        is_string(NULL, response->session_factors, "... session factors");
        is_int(0, response->loa, "... level of assurance");
        type = WA_TOKEN_UNKNOWN;
    }
    if (type != WA_TOKEN_UNKNOWN && response->result != NULL) {
        s = webauth_token_decode(ctx, type, response->result, session, &token);
        is_int(WA_ERR_NONE, s, "... result token decodes");
        if (type == WA_TOKEN_ID)
            is_token_id(&test->response.result_id, &token->token.id,
                        "... result");
        else if (type == WA_TOKEN_PROXY)
            is_token_proxy(&test->response.result_proxy, &token->token.proxy,
                           "... result");
    }

    /* Check the login cancel token. */
    options = test->request.request.options;
    if (options == NULL || strstr(options, "lc") == NULL)
        ok(response->login_cancel == NULL, "... no login cancel token");
    else if (response->login_cancel == NULL)
        ok(false, "... login cancel token");
    else {
        const char *cancel;

        type = WA_TOKEN_ERROR;
        cancel = response->login_cancel;
        s = webauth_token_decode(ctx, type, cancel, session, &token);
        is_int(WA_ERR_NONE, s, "... login cancel token decodes");
        is_token_error(&cancel_token, &token->token.error,
                       "... login cancel token");
    }

    /* Check the application state. */
    if (test->request.request.state == NULL) {
        ok(response->app_state == NULL, "... no application state");
        is_int(0, response->app_state_len, "... application state length");
    } else {
        ok(memcmp(test->request.request.state, response->app_state,
                  test->request.request.state_len) == 0,
           "... application state data");
        is_int(test->request.request.state_len, response->app_state_len,
               "... application state length");
    }

    /* Check the login data. */
    for (i = 0; i < ARRAY_SIZE(test->response.logins); i++) {
        struct webauth_login *login;

        if (test->response.logins[i].ip == NULL)
            break;
        if (response->logins == NULL || response->logins->nelts <= (int) i)
            continue;
        login = &APR_ARRAY_IDX(response->logins, i, struct webauth_login);
        is_string(test->response.logins[i].ip, login->ip,
                  "... login %d ip", i);
        is_string(test->response.logins[i].hostname, login->hostname,
                  "... login %d hostname", i);
        is_int(test->response.logins[i].timestamp, login->timestamp,
               "... login %d timestamp", i);
    }
    if (i == 0)
        ok(response->logins == NULL, "... has no login information");
    else if (response->logins == NULL)
        is_int(i, 0, "... correct number of login records");
    else
        is_int(i, response->logins->nelts,
               "... correct number of login records");

    /* Check the permitted authorization identities. */
    for (i = 0; i < ARRAY_SIZE(test->response.permitted_authz); i++) {
        const char *authz;

        if (test->response.permitted_authz[i] == NULL)
            break;
        if (response->permitted_authz == NULL)
            continue;
        if (response->permitted_authz->nelts <= (int) i)
            continue;
        authz = APR_ARRAY_IDX(response->permitted_authz, i, const char *);
        is_string(test->response.permitted_authz[i], authz,
                  "... permitted authz %d", i);
    }
    if (i == 0)
        ok(response->permitted_authz == NULL, "... has no permitted authz");
    else if (response->permitted_authz == NULL)
        is_int(i, 0, "... correct number of permitted_authz");
    else
        is_int(i, response->permitted_authz->nelts,
               "... correct number of permitted_authz");
}


/*
 * Run a test of the WebKDC login handling.  Takes the WebAuth context in
 * which to run the tests, the test case description, and the keyring to use
 * for the WebKDC.
 */
void
run_login_test(struct webauth_context *ctx, const struct wat_login_test *test,
               const struct webauth_keyring *ring)
{
    struct webauth_keyring *session;
    struct webauth_key *session_key;
    struct webauth_token *token;
    struct webauth_token_webkdc_service service;
    struct webauth_webkdc_login_request request;
    struct webauth_webkdc_login_response *response;
    const char *message;
    int s;
    size_t size, i;
    time_t now;

    /* Use a common time basis for everything that follows. */
    now = time(NULL);

    /*
     * Create a template webkdc-service token with a unique key.  We will
     * modify this for each test case.
     */
    memset(&service, 0, sizeof(service));
    s = webauth_key_create(ctx, WA_KEY_AES, WA_AES_128, NULL, &session_key);
    if (s != WA_ERR_NONE)
        bail("cannot create key: %s", webauth_error_message(ctx, s));
    session = webauth_keyring_from_key(ctx, session_key);
    service.session_key = session_key->data;
    service.session_key_len = session_key->length;
    service.subject = test->request.service.subject;
    service.creation = test->request.service.creation;
    if (service.creation < 1000 && service.creation > 0)
        service.creation += now;
    service.expiration = test->request.service.expiration;
    if (service.expiration < 1000)
        service.expiration += now;
    request.service = &service;

    /* Create an array for credentials. */
    size = sizeof(struct webauth_token *);
    request.creds = apr_array_make(ctx->pool, 3, size);

    /* Add the login tokens to the array. */
    for (i = 0; i < ARRAY_SIZE(test->request.logins); i++) {
        if (test->request.logins[i].username == NULL)
            break;
        token = apr_pcalloc(ctx->pool, sizeof(struct webauth_token));
        token->type = WA_TOKEN_LOGIN;
        token->token.login = test->request.logins[i];
        APR_ARRAY_PUSH(request.creds, struct webauth_token *) = token;
    }

    /* Add the webkdc-proxy tokens to the array. */
    for (i = 0; i < ARRAY_SIZE(test->request.wkproxies); i++) {
        if (test->request.wkproxies[i].subject == NULL)
            break;
        token = apr_pcalloc(ctx->pool, sizeof(struct webauth_token));
        token->type = WA_TOKEN_WEBKDC_PROXY;
        token->token.webkdc_proxy = test->request.wkproxies[i];
        APR_ARRAY_PUSH(request.creds, struct webauth_token *) = token;
    }

    /* Add the webkdc-factor tokens to the array. */
    for (i = 0; i < ARRAY_SIZE(test->request.wkfactors); i++) {
        if (test->request.wkfactors[i].subject == NULL)
            break;
        token = apr_pcalloc(ctx->pool, sizeof(struct webauth_token));
        token->type = WA_TOKEN_WEBKDC_FACTOR;
        token->token.webkdc_factor = test->request.wkfactors[i];
        APR_ARRAY_PUSH(request.creds, struct webauth_token *) = token;
    }

    /* Set a pointer to the request token. */
    request.request = &test->request.request;

    /* Copy the remaining data. */
    request.authz_subject = test->request.authz_subject;
    request.remote_user   = test->request.remote_user;
    request.local_ip      = test->request.local_ip;
    request.local_port    = test->request.local_port;
    request.remote_ip     = test->request.remote_ip;
    request.remote_port   = test->request.remote_port;

    /* Make the actual call. */
    s = webauth_webkdc_login(ctx, &request, &response, ring);

    /*
     * Check the WebAuth return code.  If we expect to fail, no other
     * validation is useful, so don't do anything further.
     */
    if (s != WA_ERR_NONE && test->status == WA_ERR_NONE)
        diag("%s", webauth_error_message(ctx, s));
    is_int(test->status, s, "%s (status)", test->name);
    if (test->status != WA_ERR_NONE) {
        message = webauth_error_message(ctx, s);
        is_string(test->error, message, "... and error message");
        return;
    }

    /* Check the response. */
    check_login_response(ctx, test, response, ring, session);
}
