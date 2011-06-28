/*
 * Test token encoding.
 *
 * Unfortunately, we can't just encode a token and then confirm that it
 * matches a pre-encoded token, since each encoded token gets a unique random
 * nonce.  Instead, we'll take the less appealing approach of round-tripping a
 * token through an encode and decode process and ensure we get the same
 * information out the other end.  We separately test the decoding process
 * against pre-constructed tokens, so this will hopefully be sufficient.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <tests/tap/basic.h>
#include <webauth.h>
#include <webauth/basic.h>
#include <webauth/tokens.h>


/*
 * Check an application token by encoding the struct and then decoding it,
 * ensuring that all attributes in the decoded struct match the encoded one.
 */
static void
check_app_token(struct webauth_context *ctx, struct webauth_token_app *app,
                WEBAUTH_KEYRING *ring, const char *name)
{
    int status;
    struct webauth_token_app *app2;
    const char *token;

    status = webauth_token_encode_app(ctx, app, ring, &token);
    is_int(WA_ERR_NONE, status, "Encoding app %s succeeds", name);
    if (token == NULL) {
        is_string("", webauth_error_message(ctx, status),
                  "...and sets the token pointer");
        ok_block(9, 0, "...encoding failed");
        return;
    }
    ok(token != NULL, "...and sets the token pointer");
    status = webauth_token_decode_app(ctx, token, ring, &app2);
    is_int(WA_ERR_NONE, status, "...and decoding succeeds");
    if (app2 == NULL) {
        is_string("", webauth_error_message(ctx, status),
                  "...and sets the struct pointer");
        ok_block(7, 0, "...decoding failed");
        return;
    }
    ok(app2 != NULL, "...and sets the struct pointer");
    is_string(app->subject, app2->subject, "...subject is right");
    is_int(app->last_used, app2->last_used, "...last used is right");
    is_string(app->initial_factors, app2->initial_factors,
              "...initial factors are right");
    is_string(app->session_factors, app2->session_factors,
              "...session factors are right");
    is_int(app->loa, app2->loa, "...level of assurance is right");
    if (app->creation > 0)
        is_int(app->creation, app2->creation, "...creation is right");
    else
        ok((app2->creation > time(NULL) - 1)
           && (app2->creation < time(NULL) + 1), "...creation is right");
    is_int(app->expiration, app2->expiration, "...expiration is right");
}


/*
 * Check a credential token by encoding the struct and then decoding it,
 * ensuring that all attributes in the decoded struct match the encoded one.
 */
static void
check_cred_token(struct webauth_context *ctx, struct webauth_token_cred *cred,
                 WEBAUTH_KEYRING *ring, const char *name)
{
    int status;
    struct webauth_token_cred *cred2;
    const char *token = NULL;

    status = webauth_token_encode_cred(ctx, cred, ring, &token);
    is_int(WA_ERR_NONE, status, "Encoding cred %s succeeds", name);
    if (token == NULL) {
        is_string("", webauth_error_message(ctx, status),
                  "...and sets the token pointer");
        ok_block(9, 0, "...encoding failed");
        return;
    }
    ok(token != NULL, "...and sets the token pointer");
    status = webauth_token_decode_cred(ctx, token, ring, &cred2);
    is_int(WA_ERR_NONE, status, "...and decoding succeeds");
    if (cred2 == NULL) {
        is_string("", webauth_error_message(ctx, status),
                  "...and sets the struct pointer");
        ok_block(7, 0, "...decoding failed");
        return;
    }
    ok(cred2 != NULL, "...and sets the struct pointer");
    is_string(cred->subject, cred2->subject, "...subject is right");
    is_string(cred->type, cred2->type, "...type is right");
    is_string(cred->service, cred2->service, "...service is right");
    ok(memcmp(cred->data, cred2->data, cred->data_len) == 0,
       "...data is right");
    is_int(cred->data_len, cred2->data_len, "...data length is right");
    if (cred->creation > 0)
        is_int(cred->creation, cred2->creation, "...creation is right");
    else
        ok((cred2->creation > time(NULL) - 1)
           && (cred2->creation < time(NULL) + 1), "...creation is right");
    is_int(cred->expiration, cred2->expiration, "...expiration is right");
}


/*
 * Check a proxy token by encoding the struct and then decoding it, ensuring
 * that all attributes in the decoded struct match the encoded one.
 */
static void
check_proxy_token(struct webauth_context *ctx,
                  struct webauth_token_proxy *proxy,
                 WEBAUTH_KEYRING *ring, const char *name)
{
    int status;
    struct webauth_token_proxy *proxy2;
    const char *token = NULL;

    status = webauth_token_encode_proxy(ctx, proxy, ring, &token);
    is_int(WA_ERR_NONE, status, "Encoding proxy %s succeeds", name);
    if (token == NULL) {
        is_string("", webauth_error_message(ctx, status),
                  "...and sets the token pointer");
        ok_block(8, 0, "...encoding failed");
        return;
    }
    ok(token != NULL, "...and sets the token pointer");
    status = webauth_token_decode_proxy(ctx, token, ring, &proxy2);
    is_int(WA_ERR_NONE, status, "...and decoding succeeds");
    if (proxy2 == NULL) {
        is_string("", webauth_error_message(ctx, status),
                  "...and sets the struct pointer");
        ok_block(6, 0, "...decoding failed");
        return;
    }
    ok(proxy2 != NULL, "...and sets the struct pointer");
    is_string(proxy->subject, proxy2->subject, "...subject is right");
    is_string(proxy->type, proxy2->type, "...type is right");
    ok(memcmp(proxy->webkdc_proxy, proxy2->webkdc_proxy,
              proxy->webkdc_proxy_len) == 0, "...webkdc_proxy is right");
    is_int(proxy->webkdc_proxy_len, proxy2->webkdc_proxy_len,
           "...webkdc_proxy length is right");
    if (proxy->creation > 0)
        is_int(proxy->creation, proxy2->creation, "...creation is right");
    else
        ok((proxy2->creation > time(NULL) - 1)
           && (proxy2->creation < time(NULL) + 1), "...creation is right");
    is_int(proxy->expiration, proxy2->expiration, "...expiration is right");
}


/*
 * Check a request token by encoding the struct and then decoding it, ensuring
 * that all attributes in the decoded struct match the encoded one.
 */
static void
check_request_token(struct webauth_context *ctx,
                    struct webauth_token_request *req,
                    WEBAUTH_KEYRING *ring, const char *name)
{
    int status;
    struct webauth_token_request *req2;
    const char *token = NULL;

    status = webauth_token_encode_request(ctx, req, ring, &token);
    is_int(WA_ERR_NONE, status, "Encoding request %s succeeds", name);
    if (token == NULL) {
        is_string("", webauth_error_message(ctx, status),
                  "...and sets the token pointer");
        ok_block(14, 0, "...encoding failed");
        return;
    }
    ok(token != NULL, "...and sets the token pointer");
    status = webauth_token_decode_request(ctx, token, ring, &req2);
    is_int(WA_ERR_NONE, status, "...and decoding succeeds");
    if (req2 == NULL) {
        is_string("", webauth_error_message(ctx, status),
                  "...and sets the struct pointer");
        ok_block(12, 0, "...decoding failed");
        return;
    }
    ok(req2 != NULL, "...and sets the struct pointer");
    is_string(req->type, req2->type, "...requested token type is right");
    is_string(req->auth, req2->auth, "...subject auth is right");
    is_string(req->proxy_type, req2->proxy_type, "...proxy type is right");
    ok(memcmp(req->state, req2->state, req->state_len) == 0,
       "...state is right");
    is_int(req->state_len, req2->state_len, "...state length is right");
    is_string(req->return_url, req2->return_url, "...return URL is right");
    is_string(req->options, req2->options, "...options is right");
    is_string(req->initial_factors, req2->initial_factors,
              "...initial factors is right");
    is_string(req->session_factors, req2->session_factors,
              "...session factors is right");
    is_int(req->loa, req2->loa, "...level of assurance is right");
    is_string(req->command, req2->command, "...command is right");
    if (req->creation > 0)
        is_int(req->creation, req2->creation, "...creation is right");
    else
        ok((req2->creation > time(NULL) - 1)
           && (req2->creation < time(NULL) + 1), "...creation is right");
}


int
main(void)
{
    WEBAUTH_KEYRING *ring;
    char *keyring;
    const char *token;
    time_t now;
    int status;
    struct webauth_context *ctx;
    struct webauth_token_app app;
    struct webauth_token_cred cred;
    struct webauth_token_proxy proxy;
    struct webauth_token_request req;

    plan(213);

    if (webauth_context_init(&ctx, NULL) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    /* Load the precreated keyring that we'll use for token encryption. */
    keyring = test_file_path("data/keyring");
    status = webauth_keyring_read_file(keyring, &ring);
    if (status != WA_ERR_NONE)
        bail("cannot read %s: %s", keyring,
             webauth_error_message(NULL, status));
    test_file_path_free(keyring);

    /* Now, flesh out a application token, and then encode and decode it. */
    now = time(NULL);
    app.subject = "testuser";
    app.last_used = now;
    app.initial_factors = "p,o3,o,m";
    app.session_factors = "c";
    app.loa = 3;
    app.creation = now - 10;
    app.expiration = now + 60;
    check_app_token(ctx, &app, ring, "full");

    /* Test with a minimal set of attributes. */
    app.last_used = 0;
    app.initial_factors = NULL;
    app.session_factors = NULL;
    app.loa = 0;
    app.creation = 0;
    check_app_token(ctx, &app, ring, "stripped");

    /* Test for error cases for missing data. */
    token = "foo";
    app.subject = NULL;
    status = webauth_token_encode_app(ctx, &app, ring, &token);
    is_int(WA_ERR_CORRUPT, status, "Encoding app without subject fails");
    is_string("missing subject for app token: data is incorrectly formatted",
              webauth_error_message(ctx, status), "...with correct error");
    is_string(NULL, token, "...and token is NULL");
    app.subject = "testuser";
    app.expiration = 0;
    token = "foo";
    status = webauth_token_encode_app(ctx, &app, ring, &token);
    is_int(WA_ERR_CORRUPT, status, "Encoding app without expiration fails");
    is_string("missing expiration for app token: data is incorrectly formatted",
              webauth_error_message(ctx, status), "...with correct error");
    is_string(NULL, token, "...and token is NULL");

    /* Flesh out a credential token, and then encode and decode it. */
    cred.subject = "testuser";
    cred.type = "krb5";
    cred.service = "webauth/example.com@EXAMPLE.COM";
    cred.data = "s=ome\0da;;ta";
    cred.data_len = 12;
    cred.creation = now;
    cred.expiration = now + 60;
    check_cred_token(ctx, &cred, ring, "full");

    /* Test with a minimal set of attributes. */
    cred.creation = 0;
    check_cred_token(ctx, &cred, ring, "minimal");

    /* Test for error cases for missing data. */
    token = "foo";
    cred.subject = NULL;
    status = webauth_token_encode_cred(ctx, &cred, ring, &token);
    is_int(WA_ERR_CORRUPT, status, "Encoding cred without subject fails");
    is_string("missing subject for cred token: data is incorrectly formatted",
              webauth_error_message(ctx, status), "...with correct error");
    is_string(NULL, token, "...and token is NULL");
    cred.subject = "testuser";
    cred.type = NULL;
    token = "foo";
    status = webauth_token_encode_cred(ctx, &cred, ring, &token);
    is_int(WA_ERR_CORRUPT, status, "Encoding cred without type fails");
    is_string("missing type for cred token: data is incorrectly formatted",
              webauth_error_message(ctx, status), "...with correct error");
    is_string(NULL, token, "...and token is NULL");
    cred.type = "random";
    token = "foo";
    status = webauth_token_encode_cred(ctx, &cred, ring, &token);
    is_int(WA_ERR_CORRUPT, status, "Encoding cred with bad type fails");
    is_string("unknown type random for cred token: data is incorrectly"
              " formatted", webauth_error_message(ctx, status),
              "...with correct error");
    is_string(NULL, token, "...and token is NULL");
    cred.type = "krb5";
    cred.service = NULL;
    token = "foo";
    status = webauth_token_encode_cred(ctx, &cred, ring, &token);
    is_int(WA_ERR_CORRUPT, status, "Encoding cred without service fails");
    is_string("missing service for cred token: data is incorrectly formatted",
              webauth_error_message(ctx, status), "...with correct error");
    is_string(NULL, token, "...and token is NULL");
    cred.service = "webauth/example.com@EXAMPLE.COM";
    cred.data = NULL;
    token = "foo";
    status = webauth_token_encode_cred(ctx, &cred, ring, &token);
    is_int(WA_ERR_CORRUPT, status, "Encoding cred without data fails");
    is_string("missing data for cred token: data is incorrectly formatted",
              webauth_error_message(ctx, status), "...with correct error");
    is_string(NULL, token, "...and token is NULL");
    cred.data = "s=ome\0da;;ta";
    cred.data_len = 0;
    token = "foo";
    status = webauth_token_encode_cred(ctx, &cred, ring, &token);
    is_int(WA_ERR_CORRUPT, status, "Encoding cred without data length fails");
    is_string("empty data for cred token: data is incorrectly formatted",
              webauth_error_message(ctx, status), "...with correct error");
    is_string(NULL, token, "...and token is NULL");
    cred.data_len = 12;
    cred.expiration = 0;
    token = "foo";
    status = webauth_token_encode_cred(ctx, &cred, ring, &token);
    is_int(WA_ERR_CORRUPT, status, "Encoding cred without expiration fails");
    is_string("missing expiration for cred token: data is incorrectly"
              " formatted", webauth_error_message(ctx, status),
              "...with correct error");
    is_string(NULL, token, "...and token is NULL");

    /* Flesh out a proxy token, and then encode and decode it. */
    proxy.subject = "testuser";
    proxy.type = "krb5";
    proxy.webkdc_proxy = "s=ome\0da;;ta";
    proxy.webkdc_proxy_len = 12;
    proxy.creation = now;
    proxy.expiration = now + 60;
    check_proxy_token(ctx, &proxy, ring, "full");

    /* Test with a minimal set of attributes. */
    proxy.creation = 0;
    check_proxy_token(ctx, &proxy, ring, "minimal");

    /* Test for error cases for missing data. */
    token = "foo";
    proxy.subject = NULL;
    status = webauth_token_encode_proxy(ctx, &proxy, ring, &token);
    is_int(WA_ERR_CORRUPT, status, "Encoding proxy without subject fails");
    is_string("missing subject for proxy token: data is incorrectly formatted",
              webauth_error_message(ctx, status), "...with correct error");
    is_string(NULL, token, "...and token is NULL");
    proxy.subject = "testuser";
    proxy.type = NULL;
    token = "foo";
    status = webauth_token_encode_proxy(ctx, &proxy, ring, &token);
    is_int(WA_ERR_CORRUPT, status, "Encoding proxy without type fails");
    is_string("missing type for proxy token: data is incorrectly formatted",
              webauth_error_message(ctx, status), "...with correct error");
    is_string(NULL, token, "...and token is NULL");
    proxy.type = "random";
    token = "foo";
    status = webauth_token_encode_proxy(ctx, &proxy, ring, &token);
    is_int(WA_ERR_CORRUPT, status, "Encoding proxy with bad type fails");
    is_string("unknown type random for proxy token: data is incorrectly"
              " formatted", webauth_error_message(ctx, status),
              "...with correct error");
    is_string(NULL, token, "...and token is NULL");
    proxy.type = "krb5";
    proxy.webkdc_proxy = NULL;
    token = "foo";
    status = webauth_token_encode_proxy(ctx, &proxy, ring, &token);
    is_int(WA_ERR_CORRUPT, status,
           "Encoding proxy without webkdc_proxy fails");
    is_string("missing webkdc_proxy for proxy token: data is incorrectly"
              " formatted", webauth_error_message(ctx, status),
              "...with correct error");
    is_string(NULL, token, "...and token is NULL");
    proxy.webkdc_proxy = "s=ome\0da;;ta";
    proxy.webkdc_proxy_len = 0;
    token = "foo";
    status = webauth_token_encode_proxy(ctx, &proxy, ring, &token);
    is_int(WA_ERR_CORRUPT, status,
           "Encoding proxy without webkdc_proxy length fails");
    is_string("empty webkdc_proxy for proxy token: data is incorrectly"
              " formatted", webauth_error_message(ctx, status),
              "...with correct error");
    is_string(NULL, token, "...and token is NULL");
    proxy.webkdc_proxy_len = 12;
    proxy.expiration = 0;
    token = "foo";
    status = webauth_token_encode_proxy(ctx, &proxy, ring, &token);
    is_int(WA_ERR_CORRUPT, status, "Encoding proxy without expiration fails");
    is_string("missing expiration for proxy token: data is incorrectly"
              " formatted", webauth_error_message(ctx, status),
              "...with correct error");
    is_string(NULL, token, "...and token is NULL");

    /*
     * Flesh out a request token, and then encode and decode it.  There are a
     * few different varients that are allowed, so test each one and make sure
     * they're all permitted.
     */
    req.type = "id";
    req.auth = "webkdc";
    req.state = "s=ome\0da;;ta";
    req.state_len = 12;
    req.return_url = "https://example.com/";
    req.options = "fa,lc";
    req.initial_factors = "p";
    req.session_factors = "c";
    req.loa = 1;
    req.command = NULL;
    req.creation = now;
    check_request_token(ctx, &req, ring, "full id");
    req.auth = "krb5";
    check_request_token(ctx, &req, ring, "full id krb5");
    req.type = "proxy";
    req.auth = NULL;
    req.proxy_type = "krb5";
    check_request_token(ctx, &req, ring, "full proxy");
    req.state = NULL;
    req.state_len = 0;
    req.options = NULL;
    req.initial_factors = NULL;
    req.session_factors = NULL;
    req.loa = 0;
    req.creation = 0;
    check_request_token(ctx, &req, ring, "minimal");
    req.type = NULL;
    req.proxy_type = NULL;
    req.return_url = NULL;
    req.command = "getTokens";
    check_request_token(ctx, &req, ring, "command");

    /* Test various error cases. */
    token = "foo";
    req.command = NULL;
    status = webauth_token_encode_request(ctx, &req, ring, &token);
    is_int(WA_ERR_CORRUPT, status,
           "Encoding request without type or command fails");
    is_string("missing type for request token: data is incorrectly formatted",
              webauth_error_message(ctx, status), "...with correct error");
    is_string(NULL, token, "...and token is NULL");
    token = "foo";
    req.type = "random";
    status = webauth_token_encode_request(ctx, &req, ring, &token);
    is_int(WA_ERR_CORRUPT, status,
           "Encoding request without return URL fails");
    is_string("missing return_url for request token: data is incorrectly"
              " formatted", webauth_error_message(ctx, status),
              "...with correct error");
    is_string(NULL, token, "...and token is NULL");
    token = "foo";
    req.return_url = "https://example.com/";
    status = webauth_token_encode_request(ctx, &req, ring, &token);
    is_int(WA_ERR_CORRUPT, status,
           "Encoding request with unknown type fails");
    is_string("unknown requested token type random for request token: data is"
              " incorrectly formatted", webauth_error_message(ctx, status),
              "...with correct error");
    is_string(NULL, token, "...and token is NULL");
    token = "foo";
    req.type = "id";
    status = webauth_token_encode_request(ctx, &req, ring, &token);
    is_int(WA_ERR_CORRUPT, status,
           "Encoding request without auth fails");
    is_string("missing auth for request token: data is incorrectly formatted",
              webauth_error_message(ctx, status), "...with correct error");
    is_string(NULL, token, "...and token is NULL");
    token = "foo";
    req.auth = "random";
    status = webauth_token_encode_request(ctx, &req, ring, &token);
    is_int(WA_ERR_CORRUPT, status,
           "Encoding request with unknown auth fails");
    is_string("unknown subject auth random for request token: data is"
              " incorrectly formatted", webauth_error_message(ctx, status),
              "...with correct error");
    is_string(NULL, token, "...and token is NULL");
    token = "foo";
    req.type = "proxy";
    status = webauth_token_encode_request(ctx, &req, ring, &token);
    is_int(WA_ERR_CORRUPT, status,
           "Encoding request without proxy_type fails");
    is_string("missing proxy_type for request token: data is incorrectly"
              " formatted", webauth_error_message(ctx, status),
              "...with correct error");
    is_string(NULL, token, "...and token is NULL");
    token = "foo";
    req.proxy_type = "random";
    status = webauth_token_encode_request(ctx, &req, ring, &token);
    is_int(WA_ERR_CORRUPT, status,
           "Encoding request with unknown proxy_type fails");
    is_string("unknown proxy type random for request token: data is"
              " incorrectly formatted", webauth_error_message(ctx, status),
              "...with correct error");
    is_string(NULL, token, "...and token is NULL");
    token = "foo";
    req.command = "getTokens";
    status = webauth_token_encode_request(ctx, &req, ring, &token);
    is_int(WA_ERR_CORRUPT, status,
           "Encoding request with command and type fails");
    is_string("type not valid with command in request token: data is"
              " incorrectly formatted", webauth_error_message(ctx, status),
              "...with correct error");
    is_string(NULL, token, "...and token is NULL");

    /* Clean up. */
    webauth_keyring_free(ring);
    webauth_context_free(ctx);
    return 0;
}
