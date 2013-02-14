/*
 * Test WebKDC login support with multifactor.
 *
 * WebKDC login tests that use either multifactor or the user information
 * service.
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

#include <time.h>

#include <tests/tap/basic.h>
#include <tests/tap/kerberos.h>
#include <tests/tap/remctl.h>
#include <webauth/basic.h>
#include <webauth/keys.h>
#include <webauth/tokens.h>
#include <webauth/webkdc.h>


int
main(void)
{
    apr_pool_t *pool = NULL;
    struct webauth_keyring *ring, *session;
    struct webauth_key *session_key;
    struct kerberos_config *krbconf;
    int status;
    char *keyring;
    time_t now;
    struct webauth_context *ctx;
    struct webauth_webkdc_config config;
    struct webauth_user_config user_config;
    struct webauth_webkdc_login_request request;
    struct webauth_webkdc_login_response *response;
    struct webauth_token *token, login, wkproxy, wkproxy2;
    struct webauth_token_request req;
    struct webauth_token_webkdc_factor *ft;
    struct webauth_token_webkdc_proxy *pt;
    struct webauth_token_webkdc_service service;
    struct webauth_webkdc_factor_data *fd;
    struct webauth_webkdc_proxy_data *pd;

    /* Skip this test if built without remctl support. */
#ifndef HAVE_REMCTL
    skip_all("built without remctl support");
#endif

    if (apr_initialize() != APR_SUCCESS)
        bail("cannot initialize APR");
    if (apr_pool_create(&pool, NULL) != APR_SUCCESS)
        bail("cannot create memory pool");
    if (webauth_context_init_apr(&ctx, pool) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    /* Load the Kerberos configuration. */
    krbconf = kerberos_setup(TAP_KRB_NEEDS_BOTH);
    memset(&config, 0, sizeof(config));
    config.local_realms = apr_array_make(pool, 1, sizeof(const char *));
    config.permitted_realms = apr_array_make(pool, 1, sizeof(const char *));
    config.keytab_path = krbconf->keytab;
    config.principal = krbconf->principal;
    config.login_time_limit = 5 * 60;

    /* Load the precreated keyring that we'll use for token encryption. */
    keyring = test_file_path("data/keyring");
    status = webauth_keyring_read(ctx, keyring, &ring);
    if (status != WA_ERR_NONE)
        bail("cannot read %s: %s", keyring,
             webauth_error_message(ctx, status));
    test_file_path_free(keyring);

    /* Start remctld. */
    remctld_start(krbconf, "data/conf-webkdc", (char *) 0);

    plan(214);

    /* Provide basic configuration to the WebKDC code. */
    status = webauth_webkdc_config(ctx, &config);
    is_int(WA_ERR_NONE, status, "WebKDC configuration succeeded");

    /* Flesh out the absolute minimum required in the request. */
    now = time(NULL);
    memset(&request, 0, sizeof(request));
    memset(&service, 0, sizeof(service));
    service.subject = "krb5:webauth/example.com@EXAMPLE.COM";
    status = webauth_key_create(ctx, WA_KEY_AES, WA_AES_128, NULL,
                                &session_key);
    if (status != WA_ERR_NONE)
        bail("cannot create key: %s", webauth_error_message(ctx, status));
    session = webauth_keyring_from_key(ctx, session_key);
    service.session_key = session_key->data;
    service.session_key_len = session_key->length;
    service.creation = now;
    service.expiration = now + 60;
    request.service = &service;
    memset(&req, 0, sizeof(req));
    req.type = "id";
    req.auth = "webkdc";
    req.return_url = "https://example.com/";
    req.creation = now;
    request.request = &req;

    /* Create some tokens. */
    memset(&login, 0, sizeof(login));
    login.type = WA_TOKEN_LOGIN;
    login.token.login.username = krbconf->userprinc;
    login.token.login.password = krbconf->password;
    login.token.login.creation = now;
    memset(&wkproxy, 0, sizeof(wkproxy));
    wkproxy.type = WA_TOKEN_WEBKDC_PROXY;
    wkproxy.token.webkdc_proxy.subject = "mini";
    wkproxy.token.webkdc_proxy.proxy_type = "remuser";
    wkproxy.token.webkdc_proxy.proxy_subject = "WEBKDC:remuser";
    wkproxy.token.webkdc_proxy.data = "mini";
    wkproxy.token.webkdc_proxy.data_len = strlen("mini");
    wkproxy.token.webkdc_proxy.initial_factors = "x,x1";
    wkproxy.token.webkdc_proxy.session_factors = "c";
    wkproxy.token.webkdc_proxy.loa = 3;
    wkproxy.token.webkdc_proxy.creation = now - 10 * 60;
    wkproxy.token.webkdc_proxy.expiration = now + 60 * 60;

    /*
     * Add configuration for user information and try authentication with just
     * the proxy token.
     */
    memset(&user_config, 0, sizeof(user_config));
    user_config.protocol = WA_PROTOCOL_REMCTL;
    user_config.host = "localhost";
    user_config.port = 14373;
    user_config.identity = config.principal;
    user_config.command = "test";
    user_config.keytab = config.keytab_path;
    user_config.principal = config.principal;
    status = webauth_user_config(ctx, &user_config);
    is_int(WA_ERR_NONE, status, "User information config accepted");
    request.creds = apr_array_make(pool, 2, sizeof(struct webauth_token *));
    APR_ARRAY_PUSH(request.creds, struct webauth_token *) = &wkproxy;
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    if (status != WA_ERR_NONE)
        diag("error status: %s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status, "Proxy auth w/user config returns success");
    is_int(0, response->login_error, "...with no error");
    is_string(NULL, response->login_message, "...and no message");
    is_string(NULL, response->user_message, "...and no user message");
    ok(response->result != NULL, "...there is a result token");
    is_string("id", response->result_type, "...which is an id token");
    status = webauth_token_decode(ctx, WA_TOKEN_ID, response->result,
                                  session, &token);
    is_int(WA_ERR_NONE, status, "...result token decodes properly");
    if (status != WA_ERR_NONE)
        ok_block(5, 0, "...no result token: %s",
                 webauth_error_message(ctx, status));
    else {
        is_string("mini", token->token.id.subject,
                  "...result subject is right");
        is_string("webkdc", token->token.id.auth,
                  "...result auth type is right");
        is_string("x,x1", token->token.proxy.initial_factors,
                  "...result initial factors is right");
        is_string("c", token->token.proxy.session_factors,
                  "...result session factors is right");
        is_int(1, token->token.id.loa, "...result LoA is right");
    }
    is_int(0, response->password_expires, "...no password expiration");
    ok(response->factor_tokens == NULL, "...no factor tokens");

    /*
     * Attempt to access a restricted URL and try again.  This should fail
     * and return an error message.
     */
    req.return_url = "https://example.com/restrict/";
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    if (status != WA_ERR_NONE)
        diag("error status: %s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status, "Restricted URL returns success");
    is_int(WA_PEC_AUTH_REJECTED, response->login_error,
           "...with the right error");
    is_string("authentication rejected by user information service",
              response->login_message, "...and the right message");
    is_string("<strong>You are restricted!</strong>  &lt;_&lt;;",
              response->user_message, "...and the right user message");
    ok(response->result == NULL, "...and there is no result token");

    /*
     * Request an X.509 factor and try again.  This should still work even
     * though this user doesn't have password listed as a supported factor in
     * their user information.
     */
    req.return_url = "https://example.com/";
    req.initial_factors = "x";
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    if (status != WA_ERR_NONE)
        diag("error status: %s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status, "Multifactor with proxy returns success");
    is_int(0, response->login_error, "...with no error");
    is_string(NULL, response->login_message, "...and no message");
    ok(response->result != NULL, "...there is a result token");
    is_string("id", response->result_type, "...which is an id token");

    /*
     * Request a level of assurance that we can't possibly.  This should
     * result in a specific LoA error code.
     */
    req.loa = 4;
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    if (status != WA_ERR_NONE)
        diag("%s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status, "Multifactor LoA returns success");
    is_int(WA_PEC_LOA_UNAVAILABLE, response->login_error,
           "...with the right error");
    is_string("insufficient level of assurance", response->login_message,
              "...and the right message");

    /*
     * Request a password factor for the session authentication.  This should
     * fail, since we only have a session factor of cookie, returning the
     * error code for forced login.
     */
    req.loa = 0;
    req.initial_factors = NULL;
    req.session_factors = "p";
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Multifactor session returns success");
    is_int(WA_PEC_LOGIN_FORCED, response->login_error,
           "...with the right error");
    is_string("forced authentication, need to login", response->login_message,
              "...and the right message");

    /*
     * If the proxy token is recent enough, this works, since the initial
     * factors are then elevated to session factors, but this still doesn't
     * work since we don't have a password factor.
     */
    wkproxy.token.webkdc_proxy.creation = now;
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Multifactor recent session returns success");
    is_int(WA_PEC_LOGIN_FORCED, response->login_error,
           "...with the right error");
    is_string("forced authentication, need to login", response->login_message,
              "...and the right message");

    /*
     * If instead we request an X.509 session factor, this succeeds, since the
     * proxy token is recent enough to provide session factors.
     */
    req.session_factors = "x";
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Multifactor session returns success");
    is_int(0, response->login_error, "...with no error");
    is_string(NULL, response->login_message, "...and no error message");
    ok(response->result != NULL, "...there is a result token");
    if (response->result == NULL)
        ok(0, "...which is an id token");
    else
        is_string("id", response->result_type, "...which is an id token");
    is_string("x,x1", response->initial_factors, "...initial factors");
    is_string("x,x1", response->session_factors, "...session factors");

    /*
     * Change the WebKDC proxy token to assert just a password factor and ask
     * for an OTP factor, and try again.  This should be rejected with
     * multifactor required.
     */
    wkproxy.token.webkdc_proxy.initial_factors = "p";
    req.initial_factors = "o";
    req.session_factors = NULL;
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Multifactor without config returns success");
    is_int(WA_PEC_MULTIFACTOR_UNAVAILABLE, response->login_error,
           "...with the right error");
    is_string("multifactor required but not configured",
              response->login_message, "...and the right message");
    ok(response->result == NULL, "...and there is no result token");
    is_int(1, response->factors_wanted->nelts, "...and one factor is wanted");
    is_string("o", APR_ARRAY_IDX(response->factors_wanted, 0, const char *),
              "...which is the OTP factor");
    is_int(1, response->factors_configured->nelts,
           "...and one factor is configured");
    is_string("p",
              APR_ARRAY_IDX(response->factors_configured, 0, const char *),
              "...which is the password factor");

    /*
     * Try with the factor user, which should require multifactor since we
     * haven't included a d factor in our initial authentication factors.
     */
    wkproxy.token.webkdc_proxy.subject = "factor";
    wkproxy.token.webkdc_proxy.data = "factor";
    wkproxy.token.webkdc_proxy.data_len = strlen("factor");
    req.initial_factors = NULL;
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    if (status != WA_ERR_NONE)
        diag("error status: %s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status, "Auth as factor user returns success");
    is_int(WA_PEC_MULTIFACTOR_REQUIRED, response->login_error,
           "...with the right error");
    is_string("multifactor login required", response->login_message,
              "...and the right message");
    ok(response->result == NULL, "...and there is no result token");
    is_int(1, response->factors_wanted->nelts,
           "...and one factor is wanted");
    is_string("m", APR_ARRAY_IDX(response->factors_wanted, 0, const char *),
              "...which is the multifactor factor");
    is_int(4, response->factors_configured->nelts,
           "...and four factors are configured");
    is_string("p",
              APR_ARRAY_IDX(response->factors_configured, 0, const char *),
              "...which is the password factor");
    is_string("m",
              APR_ARRAY_IDX(response->factors_configured, 1, const char *),
              "...the generic multifactor factor");
    is_string("o",
              APR_ARRAY_IDX(response->factors_configured, 2, const char *),
              "...the OTP factor");
    is_string("o2",
              APR_ARRAY_IDX(response->factors_configured, 3, const char *),
              "...and the OTP-2 factor");

    /*
     * Add a d factor to our webkdc-proxy token and try again.  This should
     * succeed and give us an id token.
     */
    wkproxy.token.webkdc_proxy.initial_factors = "p,d";
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    if (status != WA_ERR_NONE)
        diag("error status: %s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status, "Auth as factor with device factor succeeds");
    is_int(0, response->login_error, "...with no error");
    is_string(NULL, response->login_message, "...and no message");
    is_string(NULL, response->user_message, "...and no user message");
    ok(response->result != NULL, "...there is a result token");
    is_string("id", response->result_type, "...which is an id token");
    status = webauth_token_decode(ctx, WA_TOKEN_ID, response->result,
                                  session, &token);
    is_int(WA_ERR_NONE, status, "...result token decodes properly");
    if (status != WA_ERR_NONE)
        ok_block(5, 0, "...no result token: %s",
                 webauth_error_message(ctx, status));
    else {
        is_string("factor", token->token.id.subject,
                  "...result subject is right");
        is_string("webkdc", token->token.id.auth,
                  "...result auth type is right");
        is_string("p,d", token->token.proxy.initial_factors,
                  "...result initial factors is right");
        is_string("p,d", token->token.proxy.session_factors,
                  "...result session factors is right");
        is_int(1, token->token.id.loa, "...result LoA is right");
    }
    is_int(0, response->password_expires, "...no password expiration");
    ok(response->factor_tokens == NULL, "...no factor tokens");

    /*
     * Try with a user who has multifactor configuration and forced
     * multifactor.
     */
    wkproxy.token.webkdc_proxy.subject = "full";
    wkproxy.token.webkdc_proxy.data = "full";
    wkproxy.token.webkdc_proxy.data_len = strlen("full");
    wkproxy.token.webkdc_proxy.initial_factors = "p";
    req.initial_factors = "o";
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Multifactor with config returns success");
    is_int(WA_PEC_MULTIFACTOR_REQUIRED, response->login_error,
           "...with the right error");
    is_string("multifactor login required", response->login_message,
              "...and the right message");
    ok(response->result == NULL, "...and there is no result token");
    is_int(2, response->factors_wanted->nelts,
           "...and two factors are wanted");
    is_string("o", APR_ARRAY_IDX(response->factors_wanted, 0, const char *),
              "...which is the OTP factor");
    is_int(4, response->factors_configured->nelts,
           "...and four factors are configured");
    is_string("p",
              APR_ARRAY_IDX(response->factors_configured, 0, const char *),
              "...which is the password factor");
    is_string("m",
              APR_ARRAY_IDX(response->factors_configured, 1, const char *),
              "...the generic multifactor factor");
    is_string("o",
              APR_ARRAY_IDX(response->factors_configured, 2, const char *),
              "...the OTP factor");
    is_string("o3",
              APR_ARRAY_IDX(response->factors_configured, 3, const char *),
              "...and the OTP-3 factor");
    is_int(1310675733, response->password_expires,
           "...password expiration is correct");

    /*
     * Add a second webkdc-proxy token that repesents an OTP login.  This
     * login should then work.
     */
    wkproxy.token.webkdc_proxy.loa = 3;
    wkproxy.token.webkdc_proxy.creation = now - 10 * 60;
    wkproxy.token.webkdc_proxy.session_factors = "c";
    wkproxy2.type = WA_TOKEN_WEBKDC_PROXY;
    wkproxy2.token.webkdc_proxy.subject = "full";
    wkproxy2.token.webkdc_proxy.proxy_type = "remuser";
    wkproxy2.token.webkdc_proxy.proxy_subject = "WEBKDC:remuser";
    wkproxy2.token.webkdc_proxy.data = "full";
    wkproxy2.token.webkdc_proxy.data_len = strlen("full");
    wkproxy2.token.webkdc_proxy.initial_factors = "o,o3";
    wkproxy2.token.webkdc_proxy.session_factors = "c";
    wkproxy2.token.webkdc_proxy.loa = 2;
    wkproxy2.token.webkdc_proxy.creation = now - 2 * 60;
    wkproxy2.token.webkdc_proxy.expiration = now + 30 * 60;
    APR_ARRAY_PUSH(request.creds, struct webauth_token *) = &wkproxy2;
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    if (status != WA_ERR_NONE)
        diag("%s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status,
           "Multifactor with two proxies returns success");
    is_int(0, response->login_error, "...with no error");
    is_string(NULL, response->login_message, "...and no error message");
    ok(response->result != NULL, "...there is a result token");
    if (response->result == NULL)
        ok(0, "...which is an id token");
    else
        is_string("id", response->result_type, "...which is an id token");
    status = webauth_token_decode(ctx, WA_TOKEN_ID, response->result,
                                  session, &token);
    is_int(WA_ERR_NONE, status, "...result token decodes properly");
    if (status != WA_ERR_NONE)
        ok_block(6, 0, "...no result token: %s",
                 webauth_error_message(ctx, status));
    else {
        is_string("full", token->token.id.subject,
                  "...result subject is right");
        is_string("webkdc", token->token.id.auth,
                  "...result auth type is right");
        is_string("o,o3,p,m", token->token.proxy.initial_factors,
                  "...result initial factors is right");
        is_string("o,o3,c", token->token.proxy.session_factors,
                  "...result session factors is right");
        is_int(3, token->token.id.loa, "...result LoA is right");
        is_int(now + 30 * 60, token->token.id.expiration,
               "...and expiration matches the shorter expiration");
    }
    is_int(1310675733, response->password_expires,
           "...password expiration is correct");
    ok(response->proxies != NULL, "...and we have proxy tokens");
    if (response->proxies == NULL)
        ok_block(5, 0, "...no proxy tokens");
    else {
        is_int(1, response->proxies->nelts, "...one proxy token");
        pd = &APR_ARRAY_IDX(response->proxies, 0,
                            struct webauth_webkdc_proxy_data);
        is_string("remuser", pd->type, "...of type remuser");
        status = webauth_token_decode(ctx, WA_TOKEN_WEBKDC_PROXY, pd->token,
                                      ring, &token);
        is_int(WA_ERR_NONE, status, "...which decodes properly");
        pt = &token->token.webkdc_proxy;
        is_string("o,o3,p,m", pt->initial_factors,
                  "...with correct initial factors");
        is_int(now - 10 * 60, pt->creation, "...and oldest creation");
    }
    is_string("o,o3,p,m", response->initial_factors, "...initial factors");
    is_string("o,o3,c", response->session_factors, "...session factors");
    is_int(3, response->loa, "...level of assurance");
    ok(response->factor_tokens == NULL, "...no factor tokens");

    /* Attempt an OTP authentication with an incorrect OTP code. */
    login.token.login.username = "full";
    login.token.login.password = NULL;
    login.token.login.otp = "654321";
    request.creds = apr_array_make(pool, 1, sizeof(struct webauth_token *));
    APR_ARRAY_PUSH(request.creds, struct webauth_token *) = &login;
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Invalid OTP returns success");
    is_int(WA_PEC_LOGIN_FAILED, response->login_error,
           "...with correct error");
    is_string("login incorrect", response->login_message,
              "...and the correct error message");

    /*
     * Switch to the correct OTP code and add back a webkdc-proxy token
     * representing an earlier password authentication.  This combination is
     * the typical case for a multifactor login and should result in
     * satisfying the requirement for multifactor.
     *
     * We should get the full suite of session factors here, since the proxy
     * token is fresh.
     */
    req.initial_factors = "m";
    login.token.login.otp = "123456";
    wkproxy.token.webkdc_proxy.creation = now;
    request.creds = apr_array_make(pool, 2, sizeof(struct webauth_token *));
    APR_ARRAY_PUSH(request.creds, struct webauth_token *) = &login;
    APR_ARRAY_PUSH(request.creds, struct webauth_token *) = &wkproxy;
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status,
           "Multifactor with proxy token and OTP login returns success");
    is_int(0, response->login_error, "...with no error");
    is_string(NULL, response->login_message, "...and no error message");
    ok(response->result != NULL, "...there is a result token");
    is_string("id", response->result_type, "...which is an id token");
    status = webauth_token_decode(ctx, WA_TOKEN_ID, response->result,
                                  session, &token);
    is_int(WA_ERR_NONE, status, "...result token decodes properly");
    if (status != WA_ERR_NONE)
        ok_block(6, 0, "...no result token: %s",
                 webauth_error_message(ctx, status));
    else {
        is_string("full", token->token.id.subject,
                  "...result subject is right");
        is_string("webkdc", token->token.id.auth,
                  "...result auth type is right");
        is_string("o,o3,p,m,d,x1", token->token.proxy.initial_factors,
                  "...result initial factors is right");
        is_string("o,o3,p,m", token->token.proxy.session_factors,
                  "...result session factors is right");
        is_int(3, token->token.id.loa, "...result LoA is right");
        is_int(now + 60 * 60, token->token.id.expiration,
               "...and expiration matches the shorter expiration");
    }
    ok(response->factor_tokens != NULL, "...and we have factor tokens");
    if (response->factor_tokens == NULL)
        ok_block(8, 0, "...no factor tokens");
    else {
        is_int(1, response->factor_tokens->nelts, "...one factor token");
        fd = &APR_ARRAY_IDX(response->factor_tokens, 0,
                            struct webauth_webkdc_factor_data);
        is_int(1893484802, fd->expiration, "...with expiration");
        status = webauth_token_decode(ctx, WA_TOKEN_WEBKDC_FACTOR,
                                      fd->token, ring, &token);
        is_int(WA_ERR_NONE, status, "...which decodes properly");
        ft = &token->token.webkdc_factor;
        is_string("full", ft->subject, "...with correct subject");
        is_string("d,x1", ft->initial_factors,
                  "...and correct initial factors");
        is_string(NULL, ft->session_factors, "...and no session factors");
        is_int(1893484802, ft->expiration, "...and expiration is correct");
        ok(time(NULL) - ft->creation < 2, "...and creation within bounds");
    }

    /*
     * Request multifactor session factors as well.  This won't work because
     * the password webkdc-proxy token is too old and hence can't contribute
     * to the session factors, even though we're logging in.
     */
    req.session_factors = "m";
    wkproxy.token.webkdc_proxy.creation = now - 10 * 60;
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Multifactor OTP session returns success");
    is_int(WA_PEC_LOGIN_FORCED, response->login_error,
           "...with the right error");
    is_string("forced authentication, need to login", response->login_message,
              "...and the right message");

    /* But if the webkdc-proxy token is current, this does work. */
    wkproxy.token.webkdc_proxy.creation = now;
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    if (status != WA_ERR_NONE)
        diag("%s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status,
           "Multifactor OTP recent session returns success");
    is_int(0, response->login_error, "...with no error");
    is_string(NULL, response->login_message, "...and no error message");
    ok(response->result != NULL, "...there is a result token");
    is_string("id", response->result_type, "...which is an id token");
    status = webauth_token_decode(ctx, WA_TOKEN_ID, response->result,
                                  session, &token);
    is_int(WA_ERR_NONE, status, "...result token decodes properly");
    if (status != WA_ERR_NONE)
        ok(0, "...no result token: %s", webauth_error_message(ctx, status));
    else
        is_string("o,o3,p,m", token->token.id.session_factors,
                  "...result session factors is right");

    /*
     * Try requesting only a level of assurance, with a webkdc-proxy token for
     * an insufficient level of assurance, but a level of assurance that the
     * user can meet.  Ensure the correct error message is returned.  Use
     * normal instead of full as the user so that multifactor isn't forced.
     */
    wkproxy.token.webkdc_proxy.subject = "normal";
    wkproxy.token.webkdc_proxy.loa = 1;
    req.initial_factors = NULL;
    req.session_factors = "m";
    req.loa = 2;
    request.creds = apr_array_make(pool, 1, sizeof(struct webauth_token *));
    APR_ARRAY_PUSH(request.creds, struct webauth_token *) = &wkproxy;
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Multifactor for LoA returns success");
    is_int(WA_PEC_MULTIFACTOR_REQUIRED, response->login_error,
           "...with the right error");
    is_string("multifactor login required", response->login_message,
              "...and the right message");
    ok(response->result == NULL, "...and there is no result token");
    is_int(0, response->factors_wanted->nelts,
           "...and no factors are wanted");
    is_int(4, response->factors_configured->nelts,
           "...and four factors are configured");

    /*
     * Request random multifactor for a user who will get lucky and not need
     * to authenticate with multifactor.
     */
    req.type = "id";
    req.auth = "webkdc";
    req.proxy_type = NULL;
    req.initial_factors = "rm";
    req.session_factors = NULL;
    req.loa = 0;
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    if (status != WA_ERR_NONE)
        diag("%s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status, "Random multifactor returns success");
    is_int(0, response->login_error, "...with no error");
    is_string(NULL, response->login_message, "...and no error message");
    ok(response->result != NULL, "...there is a result token");
    is_string("id", response->result_type, "...which is an id token");
    status = webauth_token_decode(ctx, WA_TOKEN_ID, response->result,
                                  session, &token);
    is_int(WA_ERR_NONE, status, "...result token decodes properly");
    if (status != WA_ERR_NONE)
        ok_block(2, 0, "...no result token: %s",
                 webauth_error_message(ctx, status));
    else {
        is_string("p,rm", token->token.id.initial_factors,
                  "...result initial factors is right");
        is_string("p,rm", token->token.id.session_factors,
                  "...result session factors is right");
    }

    /*
     * Change the proxy token to indicate that random multifactor has already
     * been checked for, and then try someone who would not get lucky and
     * confirm that they're still allowed in.  Also make the proxy token older
     * so that it doesn't contribute to session factors.
     */
    wkproxy.token.webkdc_proxy.subject = "random";
    wkproxy.token.webkdc_proxy.initial_factors = "p,rm";
    wkproxy.token.webkdc_proxy.session_factors = "c";
    wkproxy.token.webkdc_proxy.creation = now - 10 * 60;
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    if (status != WA_ERR_NONE)
        diag("%s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status, "Have random multifactor returns success");
    is_int(0, response->login_error, "...with no error");
    is_string(NULL, response->login_message, "...and no error message");
    ok(response->result != NULL, "...there is a result token");
    is_string("id", response->result_type, "...which is an id token");
    status = webauth_token_decode(ctx, WA_TOKEN_ID, response->result,
                                  session, &token);
    is_int(WA_ERR_NONE, status, "...result token decodes properly");
    if (status != WA_ERR_NONE)
        ok_block(2, 0, "...no result token: %s",
                 webauth_error_message(ctx, status));
    else {
        is_string("p,rm", token->token.id.initial_factors,
                  "...result initial factors is right");
        is_string("c", token->token.id.session_factors,
                  "...result session factors is right");
    }

    /*
     * Require random multifactor for the session, which should force a check
     * even though the webkdc-proxy token indicates a check was already done
     * since the webkdc-proxy token is too old to provide session factors.
     * This should fail and indicate multifactor is required.
     */
    wkproxy.token.webkdc_proxy.session_factors = "c";
    req.session_factors = "rm";
    if (status != WA_ERR_NONE)
        diag("%s", webauth_error_message(ctx, status));
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Random multifactor session returns success");
    is_int(WA_PEC_MULTIFACTOR_REQUIRED, response->login_error,
           "...with the right error");
    is_string("multifactor login required", response->login_message,
              "...and the right message");
    ok(response->result == NULL, "...and there is no result token");

    /*
     * Similarly, requiring random multifactor for the initial factors should
     * fail if the webkdc-proxy token doesn't already have random multifactor
     * and we have an unlucky user.
     */
    req.session_factors = NULL;
    wkproxy.token.webkdc_proxy.initial_factors = "p";
    if (status != WA_ERR_NONE)
        diag("%s", webauth_error_message(ctx, status));
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Random multifactor unlucky returns success");
    is_int(WA_PEC_MULTIFACTOR_REQUIRED, response->login_error,
           "...with the right error");
    is_string("multifactor login required", response->login_message,
              "...and the right message");
    ok(response->result == NULL, "...and there is no result token");

    /*
     * But if we have a regular multifactor webkdc-proxy token, that allows
     * random multifactor as well.  The factors for the id and webkdc-proxy
     * tokens should just include multifactor.
     */
    wkproxy.token.webkdc_proxy.initial_factors = "p,o,o3,m";
    wkproxy.token.webkdc_proxy.session_factors = "c";
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    if (status != WA_ERR_NONE)
        diag("%s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status, "Random with multifactor returns success");
    is_int(0, response->login_error, "...with no error");
    is_string(NULL, response->login_message, "...and no error message");
    ok(response->result != NULL, "...there is a result token");
    is_string("id", response->result_type, "...which is an id token");
    status = webauth_token_decode(ctx, WA_TOKEN_ID, response->result,
                                  session, &token);
    is_int(WA_ERR_NONE, status, "...result token decodes properly");
    if (status != WA_ERR_NONE)
        ok_block(2, 0, "...no result token: %s",
                 webauth_error_message(ctx, status));
    else {
        is_string("p,o,o3,m", token->token.id.initial_factors,
                  "...result initial factors is right");
        is_string("c", token->token.id.session_factors,
                  "...result session factors is right");
    }
    ok(response->proxies != NULL, "...and we have proxy tokens");
    if (response->proxies == NULL)
        ok_block(3, 0, "...no proxy tokens");
    else {
        is_int(1, response->proxies->nelts, "...one proxy token");
        pd = &APR_ARRAY_IDX(response->proxies, 0,
                            struct webauth_webkdc_proxy_data);
        status = webauth_token_decode(ctx, WA_TOKEN_WEBKDC_PROXY, pd->token,
                                      ring, &token);
        is_int(WA_ERR_NONE, status, "...which decodes properly");
        pt = &token->token.webkdc_proxy;
        is_string("p,o,o3,m", pt->initial_factors,
                  "...with correct initial factors");
    }

    /* Try that with session multifactor. */
    req.session_factors = "rm";
    wkproxy.token.webkdc_proxy.session_factors = "c";
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    if (status != WA_ERR_NONE)
        diag("%s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status, "Random session multifactor returns success");
    is_int(0, response->login_error, "...with no error");
    is_string(NULL, response->login_message, "...and no error message");
    ok(response->result != NULL, "...there is a result token");
    is_string("id", response->result_type, "...which is an id token");
    status = webauth_token_decode(ctx, WA_TOKEN_ID, response->result,
                                  session, &token);
    is_int(WA_ERR_NONE, status, "...result token decodes properly");
    if (status != WA_ERR_NONE)
        ok_block(2, 0, "...no result token: %s",
                 webauth_error_message(ctx, status));
    else {
        is_string("p,o,o3,m", token->token.id.initial_factors,
                  "...result initial factors is right");
        is_string("c,rm", token->token.id.session_factors,
                  "...result session factors is right");
    }

    /*
     * Add a timeout and then switch users to one for which the user
     * information service won't return in time.  Now, authentication should
     * fail since we can't contact the user information service.
     */
    user_config.timeout = 1;
    status = webauth_user_config(ctx, &user_config);
    is_int(WA_ERR_NONE, status, "Setting user information timeout succeeds");
    req.session_factors = NULL;
    wkproxy.token.webkdc_proxy.subject = "delay";
    wkproxy.token.webkdc_proxy.data = "delay";
    wkproxy.token.webkdc_proxy.data_len = strlen("delay");
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_REMOTE_FAILURE, status, "Random with timeout fails");
    is_string("a remote service call failed (error receiving token:"
              " timed out)", webauth_error_message(ctx, status),
              "...with correct error");

    /*
     * If we say to ignore user information errors, random multifactor should
     * succeed based on the existing proxy information that we have.
     */
    wkproxy.token.webkdc_proxy.session_factors = "c";
    user_config.ignore_failure = true;
    status = webauth_user_config(ctx, &user_config);
    is_int(WA_ERR_NONE, status, "Setting user information ignore succeeds");
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    if (status != WA_ERR_NONE)
        diag("%s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status, "Random with ignored timeout returns success");
    is_int(0, response->login_error, "...with no error");
    is_string(NULL, response->login_message, "...and no error message");
    ok(response->result != NULL, "...there is a result token");
    is_string("id", response->result_type, "...which is an id token");
    status = webauth_token_decode(ctx, WA_TOKEN_ID, response->result,
                                  session, &token);
    is_int(WA_ERR_NONE, status, "...result token decodes properly");
    if (status != WA_ERR_NONE)
        ok_block(2, 0, "...no result token: %s",
                 webauth_error_message(ctx, status));
    else {
        is_string("p,o,o3,m", token->token.id.initial_factors,
                  "...result initial factors is right");
        is_string("c", token->token.id.session_factors,
                  "...result session factors is right");
    }
    ok(response->proxies != NULL, "...and we have proxy tokens");
    if (response->proxies == NULL)
        ok_block(3, 0, "...no proxy tokens");
    else {
        is_int(1, response->proxies->nelts, "...one proxy token");
        pd = &APR_ARRAY_IDX(response->proxies, 0,
                            struct webauth_webkdc_proxy_data);
        status = webauth_token_decode(ctx, WA_TOKEN_WEBKDC_PROXY, pd->token,
                                      ring, &token);
        is_int(WA_ERR_NONE, status, "...which decodes properly");
        pt = &token->token.webkdc_proxy;
        is_string("p,o,o3,m", pt->initial_factors,
                  "...with correct initial factors");
    }

    /*
     * But if we remove multifactor from the proxy token, random multifactor
     * should now fail, since we were unable to contact the user information
     * service.
     */
    wkproxy.token.webkdc_proxy.initial_factors = "p";
    if (status != WA_ERR_NONE)
        diag("%s", webauth_error_message(ctx, status));
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Random multifactor timeout returns success");
    is_int(WA_PEC_MULTIFACTOR_UNAVAILABLE, response->login_error,
           "...with the right error");
    is_string("multifactor required but not configured",
              response->login_message, "...and the right message");
    ok(response->result == NULL, "...and there is no result token");

    /* Clean up. */
    apr_terminate();
    return 0;
}
