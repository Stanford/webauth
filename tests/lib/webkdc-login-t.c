/*
 * Test WebKDC login support.
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
    char *realm, *path, *keyring, *conf;
    time_t now;
    pid_t remctld;
    FILE *file;
    struct webauth_context *ctx;
    struct webauth_webkdc_config config;
    struct webauth_user_config user_config;
    struct webauth_webkdc_login_request request;
    struct webauth_webkdc_login_response *response;
    struct webauth_token *token, login, wkproxy, wkproxy2;
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

    /* Ensure we have a basic configuration available. */
    memset(&config, 0, sizeof(config));
    config.local_realms = apr_array_make(pool, 1, sizeof(const char *));
    config.permitted_realms = apr_array_make(pool, 1, sizeof(const char *));
    memset(&user_config, 0, sizeof(user_config));
    if (chdir(getenv("SOURCE")) < 0)
        bail("can't chdir to SOURCE");
    config.principal = kerberos_setup();
    if (config.principal == NULL)
        skip_all("Kerberos tests not configured");
    realm = strchr(config.principal, '@');
    if (realm == NULL)
        skip_all("Kerberos principal has no realm");
    realm++;
    config.keytab_path = test_file_path("data/test.keytab");
    if (config.keytab_path == NULL)
        skip_all("Kerberos tests not configured");

    /*
     * Ensure we have a username and password.
     *
     * FIXME: Ideally, we would skip the tests that don't require this and
     * still do the rest.
     */
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

    /*
     * FIXME: Similarly, if we don't have remctl, we should skip tests instead
     * of skipping the whole thing.
     */
#ifndef PATH_REMCTLD
    skip_all("remctld not found");
#endif
    if (chdir(getenv("SOURCE")) < 0)
        bail("can't chdir to SOURCE");
    conf = concatpath(getenv("SOURCE"), "data/conf-webkdc");
    remctld = remctld_start(PATH_REMCTLD, config.principal, conf, NULL);

    plan(214);

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

    /*
     * Attempted login with now proxy or login tokens.  Should return an error
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

    /* Now add a login token and see if we can get an id token in response. */
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

    /*
     * Try a mismatched proxy token and login token for two different users.
     * This should fail.
     */
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

    /*
     * Now, add configuration for user information and add a cookie session
     * factor, and try this again.
     */
    user_config.protocol = WA_PROTOCOL_REMCTL;
    user_config.host = "localhost";
    user_config.port = 14373;
    user_config.identity = config.principal;
    user_config.command = "test";
    status = webauth_user_config(ctx, &user_config);
    is_int(WA_ERR_NONE, status, "User information config accepted");
    wkproxy.token.webkdc_proxy.subject = "mini";
    wkproxy.token.webkdc_proxy.data = "mini";
    wkproxy.token.webkdc_proxy.data_len = strlen("mini");
    wkproxy.token.webkdc_proxy.initial_factors = "x,x1";
    request.creds = apr_array_make(pool, 3, sizeof(struct webauth_token *));
    APR_ARRAY_PUSH(request.creds, struct webauth_token *) = &wkproxy;
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    if (status != WA_ERR_NONE)
        diag("error status: %s", webauth_error_message(ctx, status));
    is_int(WA_ERR_NONE, status, "Proxy auth w/user config returns success");
    is_int(0, response->login_error, "...with no error");
    is_string(NULL, response->login_message, "...and no message");
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

    /*
     * Request an X.509 factor and try again.  This should still work even
     * though this user doesn't have password listed as a supported factor in
     * the metadata.
     */
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
     * Request a password factor for the session authentication.  This should
     * fail, since we only have a session factor of cookie, returning the
     * error code for forced login.
     */
    req.initial_factors = NULL;
    req.session_factors = "p";
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Multifactor session returns success");
    is_int(WA_PEC_LOGIN_FORCED, response->login_error,
           "...with the right error");
    is_string("forced authentication, need to login", response->login_message,
              "...and the right message");

    /*
     * Even if the proxy token is recent enough, its factors aren't session
     * factors unless we did a login.
     */
    wkproxy.token.webkdc_proxy.creation = now;
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Multifactor recent session returns success");
    is_int(WA_PEC_LOGIN_FORCED, response->login_error,
           "...with the right error");
    is_string("forced authentication, need to login", response->login_message,
              "...and the right message");

    /*
     * If instead we request an X.509 session factor, we'll fail with the
     * error saying we have no multifactor configuration, since we have no
     * user metadata service.
     */
    req.session_factors = "x";
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Multifactor session returns success");
    is_int(WA_PEC_MULTIFACTOR_UNAVAILABLE, response->login_error,
           "...with the right error");
    is_string("multifactor required but not configured",
              response->login_message, "...and the right message");

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
     * Try with a user who has multifactor configuration and forced
     * multifactor.
     */
    wkproxy.token.webkdc_proxy.subject = "full";
    wkproxy.token.webkdc_proxy.data = "full";
    wkproxy.token.webkdc_proxy.data_len = strlen("full");
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
    is_int(5, response->factors_configured->nelts,
           "...and five factors are configured");
    is_string("p",
              APR_ARRAY_IDX(response->factors_configured, 0, const char *),
              "...which is the password factor");
    is_string("r",
              APR_ARRAY_IDX(response->factors_configured, 1, const char *),
              "...the random factor");
    is_string("m",
              APR_ARRAY_IDX(response->factors_configured, 2, const char *),
              "...the generic multifactor factor");
    is_string("o",
              APR_ARRAY_IDX(response->factors_configured, 3, const char *),
              "...the OTP factor");
    is_string("o3",
              APR_ARRAY_IDX(response->factors_configured, 4, const char *),
              "...and the OTP-3 factor");
    is_int(1310675733, response->password_expires,
           "...password expiration is correct");

    /*
     * Add a second webkdc-proxy token that repesents an OTP login.  This
     * login should then work.
     */
    wkproxy.token.webkdc_proxy.loa = 3;
    wkproxy2.type = WA_TOKEN_WEBKDC_PROXY;
    wkproxy2.token.webkdc_proxy.subject = "full";
    wkproxy2.token.webkdc_proxy.proxy_type = "remuser";
    wkproxy2.token.webkdc_proxy.proxy_subject = "WEBKDC:remuser";
    wkproxy2.token.webkdc_proxy.data = "full";
    wkproxy2.token.webkdc_proxy.data_len = strlen("full");
    wkproxy2.token.webkdc_proxy.initial_factors = "o,o3";
    wkproxy2.token.webkdc_proxy.session_factors = "c";
    wkproxy2.token.webkdc_proxy.loa = 2;
    wkproxy2.token.webkdc_proxy.creation = now;
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
        is_string("c", token->token.proxy.session_factors,
                  "...result session factors is right");
        is_int(3, token->token.id.loa, "...result LoA is right");
        is_int(now + 30 * 60, token->token.id.expiration,
               "...and expiration matches the shorter expiration");
    }
    is_int(1310675733, response->password_expires,
           "...password expiration is correct");

    /* Attempt an OTP authentication with an incorrect OTP code. */
    login.token.login.username = "full";
    login.token.login.password = NULL;
    login.token.login.otp = "654321";
    request.creds = apr_array_make(pool, 2, sizeof(struct webauth_token *));
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
        is_string("o,o3,p,m", token->token.proxy.initial_factors,
                  "...result initial factors is right");
        is_string("o,o3,p,m", token->token.proxy.session_factors,
                  "...result session factors is right");
        is_int(3, token->token.id.loa, "...result LoA is right");
        is_int(now + 60 * 60, token->token.id.expiration,
               "...and expiration matches the shorter expiration");
    }

    /*
     * Request multifactor session factors as well.  This won't work because
     * the password webkdc-proxy token is too old and hence can't contribute
     * to the session factors, even though we're logging in.
     */
    req.session_factors = "m";
    wkproxy.token.webkdc_proxy.creation = now - 10 * 60;
    request.creds = apr_array_make(pool, 2, sizeof(struct webauth_token *));
    APR_ARRAY_PUSH(request.creds, struct webauth_token *) = &login;
    APR_ARRAY_PUSH(request.creds, struct webauth_token *) = &wkproxy;
    status = webauth_webkdc_login(ctx, &request, &response, ring);
    is_int(WA_ERR_NONE, status, "Multifactor OTP session returns success");
    is_int(WA_PEC_LOGIN_FORCED, response->login_error,
           "...with the right error");
    is_string("forced authentication, need to login", response->login_message,
              "...and the right message");

    /* But if the webkdc-proxy token is current, this does work. */
    wkproxy.token.webkdc_proxy.creation = now;
    request.creds = apr_array_make(pool, 2, sizeof(struct webauth_token *));
    APR_ARRAY_PUSH(request.creds, struct webauth_token *) = &login;
    APR_ARRAY_PUSH(request.creds, struct webauth_token *) = &wkproxy;
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
        is_string("o,o3,p,m", token->token.proxy.session_factors,
                  "...result session factors is right");

    /* Clean up. */
    remctld_stop(remctld);
    kerberos_cleanup();
    apr_terminate();
    return 0;
}
