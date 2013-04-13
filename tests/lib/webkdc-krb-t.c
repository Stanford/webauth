/*
 * Test WebKDC login support with Kerberos.
 *
 * Perform the full set of WebKDC login tests that we can perform with a
 * keytab, username, and password.  This does not include the multifactor or
 * user information tests.
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
#include <tests/tap/string.h>
#include <tests/tap/webauth.h>
#include <webauth/basic.h>
#include <webauth/keys.h>
#include <webauth/tokens.h>
#include <webauth/webkdc.h>

/* Test cases to run without any local realms. */
static const struct wat_login_test tests_no_local[] = {

    /* Basic test for obtaining an id token with a username and password. */
    {
        "Login with password",
        0,
        NULL,
        {
            { "krb5:webauth/example.com@EXAMPLE.COM", 0, 0 },
            {
                { "<userprinc>", "<password>", NULL, NULL, 0 },
                EMPTY_TOKEN_LOGIN,
                EMPTY_TOKEN_LOGIN
            },
            NO_TOKENS_WKPROXY,
            NO_TOKENS_WKFACTOR,
            NULL,
            {
                "id", "webkdc", NULL, "data", 4, "https://example.com/", NULL,
                NULL, NULL, 0, NULL, 0
            }
        },
        {
            LOGIN_SUCCESS,
            NO_FACTOR_DATA,
            {
                {
                    "<userprinc>", "krb5", "<webkdc-principal>", NULL, 0,
                    "p", 0, 0, 0, NULL
                },
                EMPTY_TOKEN_WKPROXY,
                EMPTY_TOKEN_WKPROXY
            },
            EMPTY_TOKEN_WKFACTOR,
            { "<userprinc>", NULL, "webkdc", NULL, 0, "p", "p", 0, 0, 0 },
            EMPTY_TOKEN_PROXY,
            NO_LOGINS,
            0,
            NO_AUTHZ_IDS
        },
    }
};


int
main(void)
{
    apr_pool_t *pool = NULL;
    struct kerberos_config *krbconf;
    struct webauth_context *ctx;
    struct webauth_keyring *ring, *session;
    struct webauth_key *session_key;
    struct webauth_token *token, login, wkproxy;
    struct webauth_token_request req;
    struct webauth_token_webkdc_proxy *pt;
    struct webauth_token_webkdc_service service;
    struct webauth_webkdc_config config;
    struct webauth_webkdc_login_request request;
    struct webauth_webkdc_login_response *response;
    struct webauth_webkdc_proxy_data *pd;
    int status;
    char *keyring, *err, *tmpdir;
    time_t now;
    time_t expiration = 0;
    FILE *id_acl;
    size_t i;

    /* Load the Kerberos configuration. */
    krbconf = kerberos_setup(TAP_KRB_NEEDS_BOTH);

    /* Use lazy planning so that test counts can vary on some errors. */
    plan_lazy();

    /* Initialize APR and WebAuth. */
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
    config.local_realms = apr_array_make(pool, 1, sizeof(const char *));
    APR_ARRAY_PUSH(config.local_realms, const char *) = "none";
    config.permitted_realms = apr_array_make(pool, 1, sizeof(const char *));
    config.keytab_path = krbconf->keytab;
    config.principal = krbconf->principal;
    status = webauth_webkdc_config(ctx, &config);
    is_int(WA_ERR_NONE, status, "WebKDC configuration succeeded");

    /* Run the tests that assume no local realm. */
    for (i = 0; i < ARRAY_SIZE(tests_no_local); i++)
        run_login_test(ctx, &tests_no_local[i], ring, krbconf);

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
    request.creds = apr_array_make(pool, 1, sizeof(struct token *));

    /* Get an id token with a Kerberos authenticator and test forced auth. */
    memset(&login, 0, sizeof(login));
    login.type = WA_TOKEN_LOGIN;
    login.token.login.username = krbconf->userprinc;
    login.token.login.password = krbconf->password;
    login.token.login.creation = now;
    APR_ARRAY_PUSH(request.creds, struct webauth_token *) = &login;
    req.options = "lc,fa";
    service.subject = apr_pstrcat(pool, "krb5:", config.principal, NULL);
    req.auth = "krb5";
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Login for krb5 auth returns success");
    is_int(0, response->login_error, "...with no error");
    is_string(NULL, response->login_message, "...and no message");
    ok(response->login_cancel != NULL, "...and there is a cancel token");
    ok(response->result != NULL, "...there is a result token");
    is_string("id", response->result_type, "...which is an id token");
    if (response->result == NULL) {
        ok(false, "...no result token");
        token = NULL;
    } else {
        status = webauth_token_decode(ctx, WA_TOKEN_ID, response->result,
                                      session, &token);
        is_int(WA_ERR_NONE, status, "...result token decodes properly");
    }
    if (token == NULL || status != WA_ERR_NONE)
        ok_block(3, 0, "...no result token: %s",
                 webauth_error_message(ctx, status));
    else {
        is_string(krbconf->userprinc, token->token.id.subject,
                  "...result subject is right");
        is_string("krb5", token->token.id.auth,
                  "...result auth type is right");
        ok(token->token.id.auth_data != NULL, "...and there is auth data");
    }

    /* The login process should not have modified request.creds. */
    is_int(1, request.creds->nelts, "Still one token in request.creds");
    ok(&login == APR_ARRAY_IDX(request.creds, 0, struct webauth_token *),
       "...which is the login token");

    /* Test permitted realm support with a realm that is allowed. */
    APR_ARRAY_PUSH(config.permitted_realms, const char *) = krbconf->realm;
    status = webauth_webkdc_config(ctx, &config);
    is_int(WA_ERR_NONE, status, "Setting permitted realms succeeds");
    req.options = NULL;
    req.auth = "webkdc";
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Login for krb5 auth returns success");
    is_int(0, response->login_error, "...with no error");
    is_string(NULL, response->login_message, "...and no message");
    ok(response->result != NULL, "...there is a result token");
    is_string("id", response->result_type, "...which is an id token");
    if (response->result == NULL) {
        ok(false, "...no result token");
        token = NULL;
    } else {
        status = webauth_token_decode(ctx, WA_TOKEN_ID, response->result,
                                      session, &token);
        is_int(WA_ERR_NONE, status, "...result token decodes properly");
    }
    if (token == NULL || status != WA_ERR_NONE)
        ok_block(2, 0, "...no result token: %s",
                 webauth_error_message(ctx, status));
    else {
        is_string(krbconf->userprinc, token->token.id.subject,
                  "...result subject is right");
        is_string("webkdc", token->token.id.auth,
                  "...result auth type is right");
    }

    /* Test permitted realm support with a realm that is denied. */
    config.permitted_realms = apr_array_make(pool, 1, sizeof(const char *));
    APR_ARRAY_PUSH(config.permitted_realms, const char *) = "FOO.EXAMPLE.COM";
    status = webauth_webkdc_config(ctx, &config);
    is_int(WA_ERR_NONE, status, "Setting permitted realms succeeds");
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Login for krb5 auth returns success");
    is_int(WA_PEC_USER_REJECTED, response->login_error,
           "...with correct login error");
    err = apr_psprintf(pool, "realm %s is not permitted", krbconf->realm);
    is_string(err, response->login_message, "...and no message");
    ok(response->result == NULL, "...and there is no result token");

    /* Get a proxy token instead. */
    config.permitted_realms = apr_array_make(pool, 1, sizeof(const char *));
    status = webauth_webkdc_config(ctx, &config);
    is_int(WA_ERR_NONE, status, "Clearing permitted realms succeeds");
    req.type = "proxy";
    req.auth = NULL;
    req.proxy_type = "krb5";
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Login for proxy token returns success");
    is_int(0, response->login_error, "...with no error");
    is_string(NULL, response->login_message, "...and no message");
    ok(response->login_cancel == NULL, "...and there is no cancel token");
    is_string(krbconf->userprinc, response->subject, "...subject is correct");
    pt = NULL;
    if (response->proxies == NULL)
        ok_block(3, 0, "...no proxy tokens");
    else {
        is_int(1, response->proxies->nelts, "...one proxy token");
        pd = &APR_ARRAY_IDX(response->proxies, 0,
                            struct webauth_webkdc_proxy_data);
        is_string("krb5", pd->type, "...of type krb5");
        status = webauth_token_decode(ctx, WA_TOKEN_WEBKDC_PROXY, pd->token,
                                      ring, &token);
        is_int(WA_ERR_NONE, status, "...which decodes properly");
        expiration = token->token.webkdc_proxy.expiration;
    }
    ok(response->result != NULL, "...there is a result token");
    is_string("proxy", response->result_type, "...which is a proxy token");
    if (response->result == NULL) {
        ok(false, "...no result token");
        token = NULL;
    } else {
        status = webauth_token_decode(ctx, WA_TOKEN_PROXY, response->result,
                                      session, &token);
        is_int(WA_ERR_NONE, status, "...result token decodes properly");
    }
    if (token == NULL || status != WA_ERR_NONE)
        ok_block(16, 0, "...no result token: %s",
                 webauth_error_message(ctx, status));
    else {
        is_string(krbconf->userprinc, token->token.proxy.subject,
                  "...result subject is right");
        is_string(NULL, token->token.proxy.authz_subject,
                  "...and there is no authz subject");
        is_string("krb5", token->token.proxy.type,
                  "...result proxy type is right");
        is_string("p", token->token.proxy.initial_factors,
                  "...result initial factors is right");
        is_string("p", token->token.proxy.session_factors,
                  "...result session factors is right");
        is_int(0, token->token.proxy.loa, "...and no LoA");
        ok(token->token.proxy.creation - now < 10, "...and creation is sane");
        is_int(expiration, token->token.proxy.expiration,
               "...and expiration matches the expiration of the proxy token");
        status = webauth_token_decode_raw(ctx, WA_TOKEN_WEBKDC_PROXY,
                                          token->token.proxy.webkdc_proxy,
                                          token->token.proxy.webkdc_proxy_len,
                                          ring, &token);
        is_int(WA_ERR_NONE, status, "...embedded webkdc-proxy token decodes");
        if (status != WA_ERR_NONE)
            ok_block(7, 0, "...no webkdc-proxy token: %s",
                     webauth_error_message(ctx, status));
        else {
            pt = &token->token.webkdc_proxy;
            is_string(krbconf->userprinc, pt->subject,
                      "...with correct subject");
            is_string("krb5", pt->proxy_type, "...and correct type");
            ok(strcmp(request.service->subject, pt->proxy_subject) == 0,
               "...and correct proxy subject identity");
            ok(pt->data != NULL, "...and data is not NULL");
            is_string("p", pt->initial_factors, "...and factors is password");
            ok(pt->creation - now < 10, "...and creation is okay");
            ok(pt->expiration > now, "...and expiration is sane");
        }
    }

    /*
     * Set an identity ACL file and then get a proxy token with an
     * authorization identity.
     */
    tmpdir = test_tmpdir();
    basprintf((char **) &config.id_acl_path, "%s/id.acl", tmpdir);
    id_acl = fopen(config.id_acl_path, "w");
    if (id_acl == NULL)
        sysbail("cannot create %s", config.id_acl_path);
    fprintf(id_acl, "%s %s otheruser\n", krbconf->userprinc,
            request.service->subject);
    fclose(id_acl);
    status = webauth_webkdc_config(ctx, &config);
    if (status != WA_ERR_NONE)
        diag("configuration failed: %s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status, "WebKDC configuration succeeded");
    request.authz_subject = "otheruser";
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Login with identity ACL returns success");
    is_int(0, response->login_error, "...with no error");
    is_string(NULL, response->login_message, "...and no message");
    is_string(krbconf->userprinc, response->subject, "...subject is correct");
    is_string("otheruser", response->authz_subject,
              "...authz subject is correct");
    ok(response->result != NULL, "...there is a result token");
    is_string("proxy", response->result_type, "...which is a proxy token");
    if (response->result == NULL) {
        ok(false, "...no result token");
        token = NULL;
    } else {
        status = webauth_token_decode(ctx, WA_TOKEN_PROXY, response->result,
                                      session, &token);
        is_int(WA_ERR_NONE, status, "...result token decodes properly");
    }
    if (token == NULL || status != WA_ERR_NONE)
        ok_block(5, 0, "...no result token: %s",
                 webauth_error_message(ctx, status));
    else {
        is_string(krbconf->userprinc, token->token.proxy.subject,
                  "...result subject is right");
        is_string("otheruser", token->token.proxy.authz_subject,
                  "...result authz subject is correct");
        is_string("krb5", token->token.proxy.type,
                  "...result proxy type is right");
        ok(token->token.proxy.creation - now < 10, "...and creation is sane");
        ok(token->token.proxy.expiration > now, "...and expiration is sane");
    }

    /* Clean up authorization identity. */
    unlink(config.id_acl_path);
    free((char *) config.id_acl_path);
    config.id_acl_path = NULL;
    status = webauth_webkdc_config(ctx, &config);
    if (status != WA_ERR_NONE)
        diag("configuration failed: %s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status, "Clearing id_acl_path succeeded");
    test_tmpdir_free(tmpdir);
    request.authz_subject = NULL;

    /*
     * Try a mismatched proxy token and login token for two different users.
     * This should fail.
     */
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
    wkproxy.token.webkdc_proxy.initial_factors = "p";
    wkproxy.token.webkdc_proxy.session_factors = "c";
    request.creds = apr_array_make(pool, 2, sizeof(struct webauth_token *));
    APR_ARRAY_PUSH(request.creds, struct webauth_token *) = &wkproxy;
    APR_ARRAY_PUSH(request.creds, struct webauth_token *) = &login;
    req.type = "id";
    req.auth = "webkdc";
    req.proxy_type = NULL;
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Mismatch proxy and login returns success");
    is_int(WA_PEC_UNAUTHORIZED, response->login_error,
           "...with correct error");
    is_string("not authorized to use proxy token", response->login_message,
              "...and correct message");

    /*
     * If we have both a proxy token and a login token, the session factor
     * information from the login token should dominate and we shouldn't get
     * the "c" cookie session information in the resulting id token.
     */
    wkproxy.token.webkdc_proxy.subject = krbconf->userprinc;
    req.type = "id";
    req.auth = "webkdc";
    req.proxy_type = NULL;
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    if (status != WA_ERR_NONE)
        diag("error status: %s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status, "Proxy and login for webkdc returns success");
    is_int(0, response->login_error, "...with no error");
    is_string(NULL, response->login_message, "...and no message");
    ok(response->result != NULL, "...there is a result token");
    is_string("id", response->result_type, "...which is an id token");
    if (response->result == NULL) {
        ok(false, "...no result token");
        token = NULL;
    } else {
        status = webauth_token_decode(ctx, WA_TOKEN_ID, response->result,
                                      session, &token);
        is_int(WA_ERR_NONE, status, "...result token decodes properly");
    }
    if (token == NULL || status != WA_ERR_NONE)
        ok_block(4, 0, "...no result token: %s",
                 webauth_error_message(ctx, status));
    else {
        is_string(krbconf->userprinc, token->token.id.subject,
                  "...result subject is right");
        is_string("webkdc", token->token.id.auth,
                  "...result auth type is right");
        is_string("p", token->token.proxy.initial_factors,
                  "...result initial factors are right");
        is_string("p", token->token.proxy.session_factors,
                  "...result session factors are right");
    }

    /* Clean up. */
    apr_terminate();
    return 0;
}
