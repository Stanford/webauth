/*
 * Test basic WebKDC login support without Kerberos.
 *
 * Perform the tests possible on the WebKDC login functionality without any
 * Kerberos test configuration.  This ensures we do some basic functionality
 * tests even if no Kerberos configuration is provided.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011
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
#include <util/concat.h>
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
    int status;
    char *keyring;
    time_t now;
    struct webauth_context *ctx;
    struct webauth_webkdc_config config;
    struct webauth_webkdc_login_request request;
    struct webauth_webkdc_login_response *response;
    struct webauth_token *token, wkproxy;
    struct webauth_token_request req;
    struct webauth_token_webkdc_proxy *pt;
    struct webauth_token_webkdc_service service;
    struct webauth_webkdc_proxy_data *pd;

    plan(54);

    if (apr_initialize() != APR_SUCCESS)
        bail("cannot initialize APR");
    if (apr_pool_create(&pool, NULL) != APR_SUCCESS)
        bail("cannot create memory pool");
    if (webauth_context_init_apr(&ctx, pool) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    /* Load the precreated keyring that we'll use for token encryption. */
    keyring = test_file_path("data/keyring");
    status = webauth_keyring_read(ctx, keyring, &ring);
    if (status != WA_ERR_NONE)
        bail("cannot read %s: %s", keyring,
             webauth_error_message(ctx, status));
    test_file_path_free(keyring);

    /* Provide basic configuration to the WebKDC code. */
    memset(&config, 0, sizeof(config));
    config.local_realms = apr_array_make(pool, 0, sizeof(const char *));
    config.permitted_realms = apr_array_make(pool, 0, sizeof(const char *));
    status = webauth_webkdc_config(ctx, &config);
    if (status != WA_ERR_NONE)
        diag("configuration failed: %s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status, "WebKDC configuration succeeded");

    /* Flesh out the absolute minimum required in the request. */
    now = time(NULL);
    memset(&request, 0, sizeof(request));
    memset(&service, 0, sizeof(service));
    service.subject = "krb5:webauth/example.com@EXAMPLE.COM";

    status = webauth_key_create(ctx, WA_AES_KEY, WA_AES_128, NULL,
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
    request.creds = apr_array_make(pool, 1, sizeof(struct token *));

    /*
     * Attempted login with no proxy or login tokens.  Should return an error
     * indicating that a proxy token is required.
     */
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Minimal login returns success");
    is_int(WA_PEC_PROXY_TOKEN_REQUIRED, response->login_error,
           "...with correct error code");
    is_string("need a proxy token", response->login_message,
              "...and correct error message");
    ok(response->factors_wanted == NULL, "...no factors wanted");
    ok(response->factors_configured == NULL, "...no factors configured");
    ok(response->proxies == NULL, "...no new webkdc-proxy tokens");
    is_string("https://example.com/", response->return_url,
              "...return URL is correct");
    is_string("krb5:webauth/example.com@EXAMPLE.COM", response->requester,
              "...requester is correct");
    is_string(NULL, response->subject, "...no subject");
    is_string(NULL, response->result, "...no result token");
    is_string(NULL, response->result_type, "...no result type");
    is_string(NULL, response->login_cancel, "...no login cancel token");
    ok(response->app_state == NULL, "...no app state");
    is_int(0, response->app_state_len, "...no app state length");
    ok(response->logins == NULL, "...no login information");

    /* Try again, but with a login cancel token requested. */
    req.options = "lc";
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Login w/cancel returns success");
    is_int(WA_PEC_PROXY_TOKEN_REQUIRED, response->login_error,
           "...with correct error code");
    is_string("need a proxy token", response->login_message,
              "...and correct error message");
    ok(response->login_cancel != NULL, "...and now a cancel token");
    status = webauth_token_decode(ctx, WA_TOKEN_ERROR, response->login_cancel,
                                  session, &token);
    is_int(WA_ERR_NONE, status, "...which decodes properly");
    if (status != WA_ERR_NONE)
        ok_block(3, 0, "...invalid error token");
    else {
        is_int(WA_PEC_LOGIN_CANCELED, token->token.error.code,
               "...with correct code");
        is_string("user canceled login", token->token.error.message,
                  "...and message");
        ok(token->token.error.creation - now < 3, "...and creation time");
    }

    /* Get an id token with a single sign-on webkdc-proxy token. */
    memset(&wkproxy, 0, sizeof(wkproxy));
    wkproxy.type = WA_TOKEN_WEBKDC_PROXY;
    wkproxy.token.webkdc_proxy.subject = "testuser";
    wkproxy.token.webkdc_proxy.proxy_type = "remuser";
    wkproxy.token.webkdc_proxy.proxy_subject = "WEBKDC:remuser";
    wkproxy.token.webkdc_proxy.data = "testuser";
    wkproxy.token.webkdc_proxy.data_len = strlen("testuser");
    wkproxy.token.webkdc_proxy.initial_factors = "x,x1";
    wkproxy.token.webkdc_proxy.loa = 3;
    wkproxy.token.webkdc_proxy.creation = now - 10 * 60;
    wkproxy.token.webkdc_proxy.expiration = now + 60 * 60;
    request.creds = apr_array_make(pool, 2, sizeof(struct webauth_token *));
    APR_ARRAY_PUSH(request.creds, struct webauth_token *) = &wkproxy;
    req.type = "id";
    req.auth = "webkdc";
    req.proxy_type = NULL;
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    if (status != WA_ERR_NONE)
        diag("error status: %s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status, "Proxy auth for webkdc returns success");
    is_int(0, response->login_error, "...with no error");
    is_string(NULL, response->login_message, "...and no message");
    ok(response->proxies != NULL, "...and we have proxy tokens");
    if (response->proxies == NULL)
        ok_block(5, 0, "...no proxy tokens");
    else {
        is_int(1, response->proxies->nelts, "...one proxy token");
        pd = &APR_ARRAY_IDX(response->proxies, 0,
                            struct webauth_webkdc_proxy_data);
        is_string("remuser", pd->type, "...of type webkdc");
        status = webauth_token_decode(ctx, WA_TOKEN_WEBKDC_PROXY, pd->token,
                                      ring, &token);
        is_int(WA_ERR_NONE, status, "...which decodes properly");
        pt = &token->token.webkdc_proxy;
        is_string("testuser", pt->subject, "...with correct subject");
        is_string("x,x1", pt->initial_factors, "...and initial factors");
    }
    ok(response->result != NULL, "...there is a result token");
    is_string("id", response->result_type, "...which is an id token");
    status = webauth_token_decode(ctx, WA_TOKEN_ID, response->result,
                                  session, &token);
    is_int(WA_ERR_NONE, status, "...result token decodes properly");
    if (status != WA_ERR_NONE)
        ok_block(7, 0, "...no result token: %s",
                 webauth_error_message(ctx, status));
    else {
        is_string("testuser", token->token.id.subject,
                  "...result subject is right");
        is_string("webkdc", token->token.id.auth,
                  "...result auth type is right");
        is_string("x,x1", token->token.proxy.initial_factors,
                  "...result initial factors is right");
        is_string(NULL, token->token.proxy.session_factors,
                  "...and there are no session factors");
        is_int(3, token->token.id.loa, "...result LoA is right");
        ok(token->token.id.creation - now < 3, "...and creation is sane");
        is_int(now + 60 * 60, token->token.id.expiration,
               "...and expiration matches the expiration of the proxy token");
    }
    is_string("x,x1", response->initial_factors, "...initial factors");
    is_string(NULL, response->session_factors, "...session factors");
    is_int(3, response->loa, "...level of assurance");

    /* Set forced authentication and try again. */
    req.options = "fa";
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Proxy auth w/forced login returns success");
    is_int(WA_PEC_LOGIN_FORCED, response->login_error,
           "...with the right error");
    is_string("forced authentication, need to login", response->login_message,
              "...and the right message");
    is_string("testuser", response->subject, "...but we do know the subject");

    /* Remove forced authentication but ask for a proxy token. */
    req.options = NULL;
    req.type = "proxy";
    req.auth = NULL;
    req.proxy_type = "krb5";
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Proxy auth for proxy returns success");
    is_int(WA_PEC_PROXY_TOKEN_REQUIRED, response->login_error,
           "...with the right error");
    is_string("need a proxy token", response->login_message,
              "...and the right message");
    is_string("testuser", response->subject, "...but we do know the subject");

    /* Clean up. */
    apr_terminate();
    return 0;
}
