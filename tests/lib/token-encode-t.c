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
    is_string(app->subject, app2->subject, "...subject");
    ok(memcmp(app->session_key, app2->session_key, app->session_key_len) == 0,
       "...session key");
    is_int(app->session_key_len, app2->session_key_len,
           "...session key length");
    is_int(app->last_used, app2->last_used, "...last used");
    is_string(app->initial_factors, app2->initial_factors,
              "...initial factors");
    is_string(app->session_factors, app2->session_factors,
              "...session factors");
    is_int(app->loa, app2->loa, "...level of assurance");
    if (app->creation > 0)
        is_int(app->creation, app2->creation, "...creation");
    else
        ok((app2->creation > time(NULL) - 1)
           && (app2->creation < time(NULL) + 1), "...creation");
    is_int(app->expiration, app2->expiration, "...expiration");
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
    is_string(cred->subject, cred2->subject, "...subject");
    is_string(cred->type, cred2->type, "...type");
    is_string(cred->service, cred2->service, "...service");
    ok(memcmp(cred->data, cred2->data, cred->data_len) == 0, "...data");
    is_int(cred->data_len, cred2->data_len, "...data length");
    if (cred->creation > 0)
        is_int(cred->creation, cred2->creation, "...creation");
    else
        ok((cred2->creation > time(NULL) - 1)
           && (cred2->creation < time(NULL) + 1), "...creation");
    is_int(cred->expiration, cred2->expiration, "...expiration");
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
        ok_block(11, 0, "...encoding failed");
        return;
    }
    ok(token != NULL, "...and sets the token pointer");
    status = webauth_token_decode_proxy(ctx, token, ring, &proxy2);
    is_int(WA_ERR_NONE, status, "...and decoding succeeds");
    if (proxy2 == NULL) {
        is_string("", webauth_error_message(ctx, status),
                  "...and sets the struct pointer");
        ok_block(9, 0, "...decoding failed");
        return;
    }
    ok(proxy2 != NULL, "...and sets the struct pointer");
    is_string(proxy->subject, proxy2->subject, "...subject");
    is_string(proxy->type, proxy2->type, "...type");
    ok(memcmp(proxy->webkdc_proxy, proxy2->webkdc_proxy,
              proxy->webkdc_proxy_len) == 0, "...webkdc_proxy");
    is_int(proxy->webkdc_proxy_len, proxy2->webkdc_proxy_len,
           "...webkdc_proxy length");
    is_string(proxy->initial_factors, proxy2->initial_factors,
              "...initial factors");
    is_string(proxy->session_factors, proxy2->session_factors,
              "...session factors");
    is_int(proxy->loa, proxy2->loa, "...level of assurance");
    if (proxy->creation > 0)
        is_int(proxy->creation, proxy2->creation, "...creation");
    else
        ok((proxy2->creation > time(NULL) - 1)
           && (proxy2->creation < time(NULL) + 1), "...creation");
    is_int(proxy->expiration, proxy2->expiration, "...expiration");
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
    is_string(req->type, req2->type, "...requested token type");
    is_string(req->auth, req2->auth, "...subject auth");
    is_string(req->proxy_type, req2->proxy_type, "...proxy type");
    ok(memcmp(req->state, req2->state, req->state_len) == 0, "...state");
    is_int(req->state_len, req2->state_len, "...state length");
    is_string(req->return_url, req2->return_url, "...return URL");
    is_string(req->options, req2->options, "...options");
    is_string(req->initial_factors, req2->initial_factors,
              "...initial factors");
    is_string(req->session_factors, req2->session_factors,
              "...session factors");
    is_int(req->loa, req2->loa, "...level of assurance");
    is_string(req->command, req2->command, "...command");
    if (req->creation > 0)
        is_int(req->creation, req2->creation, "...creation");
    else
        ok((req2->creation > time(NULL) - 1)
           && (req2->creation < time(NULL) + 1), "...creation");
}


/*
 * Check encoding errors in various tokens.  Each of these function is the
 * same except for the token type, so we generate all the functions with
 * macros.  Each takes the context, the struct to encode, a keyring, a summary
 * of the test, and the expected error message.
 */
#define FUNCTION_NAME(type) #type
#define CHECK_FUNCTION(type)                                            \
    static void                                                         \
    check_ ## type ## _error(struct webauth_context *ctx,               \
                             struct webauth_token_ ## type *type,       \
                             WEBAUTH_KEYRING *ring, const char *summ,   \
                             const char *message)                       \
    {                                                                   \
        const char *token = "foo";                                      \
        int s;                                                          \
        char *err;                                                      \
                                                                        \
        s = webauth_token_encode_ ## type(ctx, type, ring, &token);     \
        is_int(WA_ERR_CORRUPT, s, "Encoding " FUNCTION_NAME(type)       \
               " %s fails", summ);                                      \
        if (asprintf(&err, "data is incorrectly formatted (%s)",        \
                     message) < 0)                                      \
            sysbail("cannot allocate memory");                          \
        is_string(err, webauth_error_message(ctx, s), "...with error"); \
        is_string(NULL, token, "...and token is NULL");                 \
        free(err);                                                      \
    }
CHECK_FUNCTION(app)
CHECK_FUNCTION(cred)
CHECK_FUNCTION(proxy)
CHECK_FUNCTION(request)


int
main(void)
{
    WEBAUTH_KEYRING *ring;
    char *keyring;
    time_t now;
    int status;
    struct webauth_context *ctx;
    struct webauth_token_app app;
    struct webauth_token_cred cred;
    struct webauth_token_proxy proxy;
    struct webauth_token_request req;

    plan(242);

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
    app.session_key = NULL;
    app.session_key_len = 0;
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

    /* Test one containing only a session key. */
    app.subject = NULL;
    app.session_key = "\0\0;s=test;\0";
    app.session_key_len = 11;
    check_app_token(ctx, &app, ring, "session");

    /* Test for error cases for missing or invalid data. */
    app.session_key = NULL;
    app.session_key_len = 0;
    check_app_error(ctx, &app, ring, "without subject",
                    "missing subject for app token");
    app.subject = "testuser";
    app.expiration = 0;
    check_app_error(ctx, &app, ring, "without expiration",
                    "missing expiration for app token");
    app.session_key = "\0\0;s=test;\0";
    app.session_key_len = 11;
    app.expiration = now + 60;
    check_app_error(ctx, &app, ring, "with subject and session key",
                    "subject not valid with session key in app token");
    app.subject = NULL;
    app.last_used = now;
    check_app_error(ctx, &app, ring, "with session key and last used",
                    "last_used not valid with session key in app token");

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
    cred.subject = NULL;
    check_cred_error(ctx, &cred, ring, "without subject",
                     "missing subject for cred token");
    cred.subject = "testuser";
    cred.type = NULL;
    check_cred_error(ctx, &cred, ring, "without type",
                     "missing type for cred token");
    cred.type = "random";
    check_cred_error(ctx, &cred, ring, "with bad type",
                     "unknown type random for cred token");
    cred.type = "krb5";
    cred.service = NULL;
    check_cred_error(ctx, &cred, ring, "without service",
                     "missing service for cred token");
    cred.service = "webauth/example.com@EXAMPLE.COM";
    cred.data = NULL;
    check_cred_error(ctx, &cred, ring, "without data",
                     "missing data for cred token");
    cred.data = "s=ome\0da;;ta";
    cred.data_len = 0;
    check_cred_error(ctx, &cred, ring, "without data length",
                     "empty data for cred token");
    cred.data_len = 12;
    cred.expiration = 0;
    check_cred_error(ctx, &cred, ring, "without expiration",
                     "missing expiration for cred token");

    /* Flesh out a proxy token, and then encode and decode it. */
    proxy.subject = "testuser";
    proxy.type = "krb5";
    proxy.webkdc_proxy = "s=ome\0da;;ta";
    proxy.webkdc_proxy_len = 12;
    proxy.initial_factors = "p,x,m";
    proxy.session_factors = "k";
    proxy.loa = 2;
    proxy.creation = now;
    proxy.expiration = now + 60;
    check_proxy_token(ctx, &proxy, ring, "full");

    /* Test with a minimal set of attributes. */
    proxy.creation = 0;
    check_proxy_token(ctx, &proxy, ring, "minimal");

    /* Test for error cases for missing data. */
    proxy.subject = NULL;
    check_proxy_error(ctx, &proxy, ring, "without subject",
                      "missing subject for proxy token");
    proxy.subject = "testuser";
    proxy.type = NULL;
    check_proxy_error(ctx, &proxy, ring, "without type",
                      "missing type for proxy token");
    proxy.type = "random";
    check_proxy_error(ctx, &proxy, ring, "with bad type",
                      "unknown type random for proxy token");
    proxy.type = "krb5";
    proxy.webkdc_proxy = NULL;
    check_proxy_error(ctx, &proxy, ring, "without webkdc_proxy",
                      "missing webkdc_proxy for proxy token");
    proxy.webkdc_proxy = "s=ome\0da;;ta";
    proxy.webkdc_proxy_len = 0;
    check_proxy_error(ctx, &proxy, ring, "without webkdc_proxy length",
                      "empty webkdc_proxy for proxy token");
    proxy.webkdc_proxy_len = 12;
    proxy.expiration = 0;
    check_proxy_error(ctx, &proxy, ring, "without expiration",
                      "missing expiration for proxy token");

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
    req.command = "getTokensRequest";
    check_request_token(ctx, &req, ring, "command");

    /* Test various error cases. */
    req.command = NULL;
    check_request_error(ctx, &req, ring, "without type or command",
                        "missing type for request token");
    req.type = "random";
    check_request_error(ctx, &req, ring, "without return URL",
                        "missing return_url for request token");
    req.return_url = "https://example.com/";
    check_request_error(ctx, &req, ring, "with unknown type",
                        "unknown requested token type random for request"
                        " token");
    req.type = "id";
    check_request_error(ctx, &req, ring, "without auth",
                        "missing auth for request token");
    req.auth = "random";
    check_request_error(ctx, &req, ring, "with unknown auth",
                        "unknown subject auth random for request token");
    req.type = "proxy";
    check_request_error(ctx, &req, ring, "without proxy_type",
                        "missing proxy_type for request token");
    req.proxy_type = "random";
    check_request_error(ctx, &req, ring, "with unknown proxy_type",
                        "unknown proxy type random for request token");
    req.command = "getTokensRequest";
    check_request_error(ctx, &req, ring, "with command and type",
                        "type not valid with command in request token");

    /* Clean up. */
    webauth_keyring_free(ring);
    webauth_context_free(ctx);
    return 0;
}
