/*
 * Test WebKDC login support with Kerberos.
 *
 * Perform the full set of WebKDC login tests that we can perform with a
 * keytab, username, and password.  This does not include the multifactor or
 * user metadata tests.
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
    WEBAUTH_KEYRING *ring, *session;
    WEBAUTH_KEY *session_key;
    char key_data[WA_AES_128], username[BUFSIZ], password[BUFSIZ];
    int status;
    char *realm, *path, *keyring;
    time_t now;
    FILE *file;
    struct webauth_context *ctx;
    struct webauth_webkdc_config config;
    struct webauth_user_config user_config;
    struct webauth_webkdc_login_request request;
    struct webauth_webkdc_login_response *response;
    struct webauth_token *token, login, wkproxy;
    struct webauth_token_request req;
    struct webauth_token_webkdc_proxy *pt;
    struct webauth_token_webkdc_service service;
    struct webauth_webkdc_proxy_data *pd;
    time_t expiration = 0;

    if (apr_initialize() != APR_SUCCESS)
        bail("cannot initialize APR");
    if (apr_pool_create(&pool, NULL) != APR_SUCCESS)
        bail("cannot create memory pool");
    if (webauth_context_init_apr(&ctx, pool) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    /* Load the precreated keyring that we'll use for token encryption. */
    keyring = test_file_path("data/keyring");
    status = webauth_keyring_read_file(keyring, &ring);
    if (status != WA_ERR_NONE)
        bail("cannot read %s: %s", keyring,
             webauth_error_message(NULL, status));
    test_file_path_free(keyring);

    /* Ensure we have a username and password. */
    path = test_file_path("data/test.password");
    if (path == NULL)
        skip_all("Kerberos tests not configured");
    file = fopen(path, "r");
    if (file == NULL)
        sysbail("cannot open %s", path);
    if (fgets(username, sizeof(username), file) == NULL)
        bail("cannot read %s", path);
    if (fgets(password, sizeof(password), file) == NULL)
        bail("cannot read password from %s", path);
    fclose(file);
    if (username[strlen(username) - 1] != '\n')
        bail("no newline in %s", path);
    username[strlen(username) - 1] = '\0';
    if (password[strlen(password) - 1] != '\n')
        bail("username or password too long in %s", path);
    password[strlen(password) - 1] = '\0';
    test_file_path_free(path);

    /* Ensure we have a basic Kerberos configuration available. */
    memset(&config, 0, sizeof(config));
    config.local_realms = apr_array_make(pool, 1, sizeof(const char *));
    config.permitted_realms = apr_array_make(pool, 1, sizeof(const char *));
    memset(&user_config, 0, sizeof(user_config));
    if (chdir(getenv("SOURCE")) < 0)
        bail("can't chdir to SOURCE");
    config.keytab_path = test_file_path("data/test.keytab");
    if (config.keytab_path == NULL)
        skip_all("Kerberos tests not configured");
    config.principal = kerberos_setup();
    if (config.principal == NULL)
        skip_all("Kerberos tests not configured");
    realm = strchr(config.principal, '@');
    if (realm == NULL)
        bail("Kerberos principal has no realm");
    realm++;

    plan(81);

    /* Provide basic configuration to the WebKDC code. */
    status = webauth_webkdc_config(ctx, &config);
    is_int(WA_ERR_NONE, status, "WebKDC configuration succeeded");

    /* Flesh out the absolute minimum required in the request. */
    now = time(NULL);
    memset(&request, 0, sizeof(request));
    memset(&service, 0, sizeof(service));
    service.subject = "krb5:webauth/example.com@EXAMPLE.COM";
    if (webauth_random_key(key_data, sizeof(key_data)) != WA_ERR_NONE)
        bail("cannot create random key");
    session_key = webauth_key_create(WA_AES_KEY, key_data, sizeof(key_data));
    status = webauth_keyring_from_key(ctx, session_key, &session);
    if (status != WA_ERR_NONE)
        bail("cannot create keyring from session key");
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

    /* Send a login token and see if we can get an id token in response. */
    config.local_realms = apr_array_make(pool, 1, sizeof(const char *));
    APR_ARRAY_PUSH(config.local_realms, const char *) = "none";
    memset(&login, 0, sizeof(login));
    login.type = WA_TOKEN_LOGIN;
    login.token.login.username = username;
    login.token.login.password = password;
    login.token.login.creation = now;
    APR_ARRAY_PUSH(request.creds, struct webauth_token *) = &login;
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Login w/password returns success");
    is_int(0, response->login_error, "...with no error");
    is_string(NULL, response->login_message, "...and no message");
    ok(response->proxies != NULL, "...and now we have proxy tokens");
    pt = NULL;
    if (response->proxies == NULL)
        ok_block(11, 0, "...no proxy tokens");
    else {
        is_int(1, response->proxies->nelts, "...one proxy token");
        pd = &APR_ARRAY_IDX(response->proxies, 0,
                            struct webauth_webkdc_proxy_data);
        is_string("krb5", pd->type, "...of type krb5");
        status = webauth_token_decode(ctx, WA_TOKEN_WEBKDC_PROXY, pd->token,
                                      ring, &token);
        is_int(WA_ERR_NONE, status, "...which decodes properly");
        pt = &token->token.webkdc_proxy;
        is_string(username, pt->subject, "...with correct subject");
        is_string("krb5", pt->proxy_type, "...and correct type");
        ok(strncmp("WEBKDC:krb5:", pt->proxy_subject, 12) == 0,
           "...and correct proxy subject prefix");
        ok(strcmp(config.principal, pt->proxy_subject + 12) == 0,
           "...and correct proxy subject identity");
        ok(pt->data != NULL, "...and data is not NULL");
        is_string("p", pt->initial_factors, "...and factors is password");
        ok(pt->creation - now < 3, "...and creation is okay");
        ok(pt->expiration > now, "...and expiration is sane");
    }
    is_string(username, response->subject, "...subject is correct");
    ok(response->result != NULL, "...there is a result token");
    is_string("id", response->result_type, "...which is an id token");
    status = webauth_token_decode(ctx, WA_TOKEN_ID, response->result,
                                  session, &token);
    is_int(WA_ERR_NONE, status, "...result token decodes properly");
    if (status != WA_ERR_NONE)
        ok_block(8, 0, "...no result token: %s",
                 webauth_error_message(ctx, status));
    else {
        is_string(username, token->token.id.subject,
                  "...result subject is right");
        is_string("webkdc", token->token.id.auth,
                  "...result auth type is right");
        ok(token->token.id.auth_data == NULL, "...and there is no auth data");
        is_string("p", token->token.id.initial_factors,
                  "...result initial factors is right");
        is_string("p", token->token.id.session_factors,
                  "...result session factors is right");
        is_int(0, token->token.id.loa, "...and no LoA");
        ok(token->token.id.creation - now < 3, "...and creation is sane");
        is_int(pt->expiration, token->token.id.expiration,
               "...and expiration matches the expiration of the proxy token");
    }
    is_int(0, response->password_expires, "...and no password expire date");
    is_string("p", response->initial_factors, "...initial factors");
    is_string("p", response->session_factors, "...session factors");
    is_int(0, response->loa, "...level of assurance");

    /* Get an id token with a Kerberos authenticator and test forced auth. */
    req.options = "lc,fa";
    request.creds = apr_array_make(pool, 2, sizeof(struct webauth_token *));
    APR_ARRAY_PUSH(request.creds, struct webauth_token *) = &login;
    service.subject = apr_pstrcat(pool, "krb5:", config.principal, NULL);
    req.auth = "krb5";
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Login for krb5 auth returns success");
    is_int(0, response->login_error, "...with no error");
    is_string(NULL, response->login_message, "...and no message");
    ok(response->login_cancel != NULL, "...and there is a cancel token");
    ok(response->result != NULL, "...there is a result token");
    is_string("id", response->result_type, "...which is an id token");
    status = webauth_token_decode(ctx, WA_TOKEN_ID, response->result,
                                  session, &token);
    is_int(WA_ERR_NONE, status, "...result token decodes properly");
    if (status != WA_ERR_NONE)
        ok_block(3, 0, "...no result token: %s",
                 webauth_error_message(ctx, status));
    else {
        is_string(username, token->token.id.subject,
                  "...result subject is right");
        is_string("krb5", token->token.id.auth,
                  "...result auth type is right");
        ok(token->token.id.auth_data != NULL, "...and there is auth data");
    }

    /* Get a proxy token instead. */
    req.options = NULL;
    request.creds = apr_array_make(pool, 2, sizeof(struct webauth_token *));
    APR_ARRAY_PUSH(request.creds, struct webauth_token *) = &login;
    req.type = "proxy";
    req.auth = NULL;
    req.proxy_type = "krb5";
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Login for proxy token returns success");
    is_int(0, response->login_error, "...with no error");
    is_string(NULL, response->login_message, "...and no message");
    ok(response->login_cancel == NULL, "...and there is no cancel token");
    is_string(username, response->subject, "...subject is correct");
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
    status = webauth_token_decode(ctx, WA_TOKEN_PROXY, response->result,
                                  session, &token);
    is_int(WA_ERR_NONE, status, "...result token decodes properly");
    if (status != WA_ERR_NONE)
        ok_block(7, 0, "...no result token: %s",
                 webauth_error_message(ctx, status));
    else {
        is_string(username, token->token.proxy.subject,
                  "...result subject is right");
        is_string("krb5", token->token.proxy.type,
                  "...result proxy type is right");
        is_string("p", token->token.proxy.initial_factors,
                  "...result initial factors is right");
        is_string("p", token->token.proxy.session_factors,
                  "...result session factors is right");
        is_int(0, token->token.proxy.loa, "...and no LoA");
        ok(token->token.proxy.creation - now < 3, "...and creation is sane");
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
            is_string(username, pt->subject, "...with correct subject");
            is_string("krb5", pt->proxy_type, "...and correct type");
            ok(strcmp(request.service->subject, pt->proxy_subject) == 0,
               "...and correct proxy subject identity");
            ok(pt->data != NULL, "...and data is not NULL");
            is_string("p", pt->initial_factors, "...and factors is password");
            ok(pt->creation - now < 3, "...and creation is okay");
            ok(pt->expiration > now, "...and expiration is sane");
        }
    }

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
    request.creds = apr_array_make(pool, 3, sizeof(struct webauth_token *));
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
    wkproxy.token.webkdc_proxy.subject = username;
    request.creds = apr_array_make(pool, 3, sizeof(struct webauth_token *));
    APR_ARRAY_PUSH(request.creds, struct webauth_token *) = &wkproxy;
    APR_ARRAY_PUSH(request.creds, struct webauth_token *) = &login;
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
    status = webauth_token_decode(ctx, WA_TOKEN_ID, response->result,
                                  session, &token);
    is_int(WA_ERR_NONE, status, "...result token decodes properly");
    if (status != WA_ERR_NONE)
        ok_block(4, 0, "...no result token: %s",
                 webauth_error_message(ctx, status));
    else {
        is_string(username, token->token.id.subject,
                  "...result subject is right");
        is_string("webkdc", token->token.id.auth,
                  "...result auth type is right");
        is_string("p", token->token.proxy.initial_factors,
                  "...result initial factors are right");
        is_string("p", token->token.proxy.session_factors,
                  "...result session factors are right");
    }

    /* Clean up. */
    kerberos_cleanup();
    apr_terminate();
    return 0;
}
