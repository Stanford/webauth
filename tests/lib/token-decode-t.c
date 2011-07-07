/*
 * Test token decoding.
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
#include <util/xmalloc.h>
#include <webauth.h>
#include <webauth/basic.h>
#include <webauth/tokens.h>


/*
 * Read a token from a file name and return it in newly allocated memory.
 */
static char *
read_token(const char *filename)
{
    char buffer[4096];
    char *path;
    FILE *token;
    size_t length;

    path = test_file_path(filename);
    if (path == NULL)
        bail("cannot find test file %s", filename);
    token = fopen(path, "r");
    if (token == NULL)
        sysbail("cannot open %s", path);
    test_file_path_free(path);
    if (fgets(buffer, sizeof(buffer), token) == NULL)
        sysbail("cannot read %s", path);
    length = strlen(buffer);
    if (buffer[length - 1] == '\n')
        buffer[length - 1] = '\0';
    return xstrdup(buffer);
}


/*
 * Check decoding errors in various tokens.  Each of these function is the
 * same except for the token type, so we generate all the functions with
 * macros.  Each takes the context, the name of the token, the keyring, the
 * WebAuth status code, and the expected error message.
 */
#define FUNCTION_NAME(type) #type
#define CHECK_FUNCTION(type)                                            \
    static void                                                         \
    check_ ## type ## _error(struct webauth_context *ctx,               \
                             const char *name, WEBAUTH_KEYRING *ring,   \
                             int code, const char *message)             \
    {                                                                   \
        struct webauth_token_ ## type *type;                            \
        int s;                                                          \
        char *path, *token, *err;                                       \
                                                                        \
        if (asprintf(&path, "data/tokens/%s", name) < 0)                \
            sysbail("cannot allocate memory");                          \
        token = read_token(path);                                       \
        free(path);                                                     \
        s = webauth_token_decode_ ## type(ctx, token, ring, &type);     \
        is_int(code, s, "Fail to decode %s", name);                     \
        if (asprintf(&err, "%s (%s)",                                   \
                     webauth_error_message(NULL, code), message) < 0)   \
            sysbail("cannot allocate memory");                          \
        is_string(err, webauth_error_message(ctx, s), "...with error"); \
        free(err);                                                      \
        free(token);                                                    \
    }
CHECK_FUNCTION(app)
CHECK_FUNCTION(cred)
CHECK_FUNCTION(error)
CHECK_FUNCTION(id)
CHECK_FUNCTION(login)
CHECK_FUNCTION(proxy)
CHECK_FUNCTION(request)
CHECK_FUNCTION(webkdc_proxy)
CHECK_FUNCTION(webkdc_service)


int
main(void)
{
    WEBAUTH_KEYRING *ring;
    char *keyring, *token;
    int status;
    struct webauth_context *ctx;
    struct webauth_token_app *app;
    struct webauth_token_cred *cred;
    struct webauth_token_error *err;
    struct webauth_token_id *id;
    struct webauth_token_login *login;
    struct webauth_token_proxy *proxy;
    struct webauth_token_request *req;
    struct webauth_token_webkdc_proxy *wkproxy;
    struct webauth_token_webkdc_service *service;
    enum webauth_token_type type;
    void *generic;

    plan(268);

    if (webauth_context_init(&ctx, NULL) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    /*
     * We're going to test token decoding and encoding using a set of
     * pre-created tokens in the data directory encrypted with a keyring
     * that's stored in that directory.  So start by loading that keyring.
     */
    keyring = test_file_path("data/keyring");
    status = webauth_keyring_read_file(keyring, &ring);
    if (status != WA_ERR_NONE)
        bail("cannot read %s: %s", keyring,
             webauth_error_message(NULL, status));
    test_file_path_free(keyring);

    /* Test decoding of an app token. */
    token = read_token("data/tokens/app-ok");
    status = webauth_token_decode_app(ctx, token, ring, &app);
    is_int(WA_ERR_NONE, status, "Decode app-ok");
    if (app == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok_block(8, 0, "Decoding failed");
    } else {
        is_string("testuser", app->subject, "...subject");
        ok(app->session_key == NULL, "...session key");
        is_int(0, app->session_key_len, "...session key length");
        is_int(1308777930, app->last_used, "...last used");
        is_string("p", app->initial_factors, "...initial factors");
        is_string("c", app->session_factors, "...session factors");
        is_int(1, app->loa, "...level of assurance");
        is_int(1308777900, app->creation, "...creation");
        is_int(2147483600, app->expiration, "...expiration");
    }
    free(token);

    /* Test decoding of a minimal app token. */
    token = read_token("data/tokens/app-minimal");
    status = webauth_token_decode_app(ctx, token, ring, &app);
    is_int(WA_ERR_NONE, status, "Decode app-minimal");
    if (app == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok_block(8, 0, "Decoding failed");
    } else {
        is_string("testuser", app->subject, "...subject");
        ok(app->session_key == NULL, "...session key");
        is_int(0, app->session_key_len, "...session key length");
        is_int(0, app->last_used, "...last used");
        is_string(NULL, app->initial_factors, "...initial factors");
        is_string(NULL, app->session_factors, "...session factors");
        is_int(0, app->loa, "...level of assurance");
        is_int(0, app->creation, "...creation");
        is_int(2147483600, app->expiration, "...expiration");
    }
    free(token);

    /* Test decoding an app token holding only a session key. */
    token = read_token("data/tokens/app-session");
    status = webauth_token_decode_app(ctx, token, ring, &app);
    is_int(WA_ERR_NONE, status, "Decode app-session");
    if (app == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok_block(8, 0, "Decoding failed");
    } else {
        is_string(NULL, app->subject, "...subject");
        ok(memcmp("\0\0;s=test;\0", app->session_key, 11) == 0,
           "...session key");
        is_int(11, app->session_key_len, "...session key length");
        is_int(0, app->last_used, "...last used");
        is_string(NULL, app->initial_factors, "...initial factors");
        is_string(NULL, app->session_factors, "...session factors");
        is_int(0, app->loa, "...level of assurance");
        is_int(0, app->creation, "...creation");
        is_int(2147483600, app->expiration, "...expiration");
    }
    free(token);

    /* Test decoding error cases for app tokens. */
    check_app_error(ctx, "app-bad-hmac", ring, WA_ERR_BAD_HMAC,
                    "bad app token");
    check_app_error(ctx, "app-empty", ring, WA_ERR_CORRUPT,
                    "decoding attribute s failed");
    check_app_error(ctx, "app-expired", ring, WA_ERR_TOKEN_EXPIRED,
                    "bad app token");
    check_app_error(ctx, "cred-ok", ring, WA_ERR_CORRUPT,
                    "wrong token type cred while decoding app token");

    /* Test decoding of a credential token. */
    token = read_token("data/tokens/cred-ok");
    status = webauth_token_decode_cred(ctx, token, ring, &cred);
    is_int(WA_ERR_NONE, status, "Decode cred-ok");
    if (cred == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok_block(6, 0, "Decoding failed");
    } else {
        is_string("testuser", cred->subject, "...subject");
        is_string("krb5", cred->type, "...type");
        is_string("webauth/example.com@EXAMPLE.COM", cred->service,
                  "...service");
        ok(memcmp("some\0cred;da;;ta", cred->data, 16) == 0, "...data");
        is_int(16, cred->data_len, "...data length");
        is_int(1308777900, cred->creation, "...creation");
        is_int(2147483600, cred->expiration, "...expiration");
    }
    free(token);

    /* Test decoding error cases for cred tokens. */
    check_cred_error(ctx, "app-bad-hmac", ring, WA_ERR_BAD_HMAC,
                     "bad cred token");
    check_cred_error(ctx, "cred-empty", ring, WA_ERR_CORRUPT,
                     "decoding attribute s failed");
    check_cred_error(ctx, "cred-exp", ring, WA_ERR_TOKEN_EXPIRED,
                     "bad cred token");
    check_cred_error(ctx, "app-ok", ring, WA_ERR_CORRUPT,
                     "wrong token type app while decoding cred token");

    /* Test decoding of an error token. */
    token = read_token("data/tokens/error-ok");
    status = webauth_token_decode_error(ctx, token, ring, &err);
    is_int(WA_ERR_NONE, status, "Decode error-ok");
    if (err == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok_block(2, 0, "Decoding failed");
    } else {
        is_int(16, err->code, "...code");
        is_string("user canceled login", err->message, "...message");
        is_int(1308777900, err->creation, "...creation");
    }
    free(token);

    /* Test decoding error cases for error tokens. */
    check_error_error(ctx, "app-bad-hmac", ring, WA_ERR_BAD_HMAC,
                      "bad error token");
    check_error_error(ctx, "error-code", ring, WA_ERR_CORRUPT,
                      "error code foo is not a number");
    check_error_error(ctx, "app-ok", ring, WA_ERR_CORRUPT,
                      "wrong token type app while decoding error token");

    /* Test decoding of an id webkdc token. */
    token = read_token("data/tokens/id-webkdc");
    status = webauth_token_decode_id(ctx, token, ring, &id);
    is_int(WA_ERR_NONE, status, "Decode id-webkdc");
    if (id == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok_block(8, 0, "Decoding failed");
    } else {
        is_string("testuser", id->subject, "...subject");
        is_string("webkdc", id->auth, "...subject auth");
        ok(id->auth_data == NULL, "...subject auth data");
        is_int(0, id->auth_data_len, "...subject auth data length");
        is_string("p", id->initial_factors, "...initial factors");
        is_string("c", id->session_factors, "...session factors");
        is_int(1, id->loa, "...level of assurance");
        is_int(1308777900, id->creation, "...creation");
        is_int(2147483600, id->expiration, "...expiration");
    }
    free(token);

    /* Test decoding of an id krb5 token. */
    token = read_token("data/tokens/id-krb5");
    status = webauth_token_decode_id(ctx, token, ring, &id);
    is_int(WA_ERR_NONE, status, "Decode id-krb5");
    if (id == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok_block(8, 0, "Decoding failed");
    } else {
        is_string(NULL, id->subject, "...subject");
        is_string("krb5", id->auth, "...subject auth");
        ok(memcmp("s=foo\0s=bar;;da", id->auth_data, 15) == 0,
                  "...subject auth data");
        is_int(15, id->auth_data_len, "...subject auth data length");
        is_string("p", id->initial_factors, "...initial factors");
        is_string("c", id->session_factors, "...session factors");
        is_int(1, id->loa, "...level of assurance");
        is_int(1308777900, id->creation, "...creation");
        is_int(2147483600, id->expiration, "...expiration");
    }
    free(token);

    /* Test decoding of a minimal id webkdc token. */
    token = read_token("data/tokens/id-minimal");
    status = webauth_token_decode_id(ctx, token, ring, &id);
    is_int(WA_ERR_NONE, status, "Decode id-minimal");
    if (id == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok_block(8, 0, "Decoding failed");
    } else {
        is_string("testuser", id->subject, "...subject");
        is_string("webkdc", id->auth, "...subject auth");
        ok(id->auth_data == NULL, "...subject auth data");
        is_int(0, id->auth_data_len, "...subject auth data length");
        is_string(NULL, id->initial_factors, "...initial factors");
        is_string(NULL, id->session_factors, "...session factors");
        is_int(0, id->loa, "...level of assurance");
        is_int(1308777900, id->creation, "...creation");
        is_int(2147483600, id->expiration, "...expiration");
    }
    free(token);

    /* Test decoding error cases for id tokens. */
    check_id_error(ctx, "app-bad-hmac", ring, WA_ERR_BAD_HMAC,
                   "bad id token");
    check_id_error(ctx, "id-expired", ring, WA_ERR_TOKEN_EXPIRED,
                   "bad id token");
    check_id_error(ctx, "app-ok", ring, WA_ERR_CORRUPT,
                   "wrong token type app while decoding id token");

    /* Test decoding of a login password token. */
    token = read_token("data/tokens/login-pass");
    status = webauth_token_decode_login(ctx, token, ring, &login);
    is_int(WA_ERR_NONE, status, "Decode login-pass");
    if (login == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok_block(3, 0, "Decoding failed");
    } else {
        is_string("testuser", login->username, "...username");
        is_string("some;s=password", login->password, "...password");
        is_string(NULL, login->otp, "...otp");
        is_int(1308777900, login->creation, "...creation");
    }
    free(token);

    /* Test decoding of a login OTP token. */
    token = read_token("data/tokens/login-otp");
    status = webauth_token_decode_login(ctx, token, ring, &login);
    is_int(WA_ERR_NONE, status, "Decode login-otp");
    if (login == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok_block(3, 0, "Decoding failed");
    } else {
        is_string("testuser", login->username, "...username");
        is_string(NULL, login->password, "...password");
        is_string("489147", login->otp, "...otp");
        is_int(1308777900, login->creation, "...creation");
    }
    free(token);

    /* Test decoding error cases for login tokens. */
    check_login_error(ctx, "app-bad-hmac", ring, WA_ERR_BAD_HMAC,
                      "bad login token");
    check_login_error(ctx, "login-empty", ring, WA_ERR_CORRUPT,
                      "decoding attribute ct failed");
    check_login_error(ctx, "app-ok", ring, WA_ERR_CORRUPT,
                      "wrong token type app while decoding login token");

    /* Test decoding of a proxy token. */
    token = read_token("data/tokens/proxy-ok");
    status = webauth_token_decode_proxy(ctx, token, ring, &proxy);
    is_int(WA_ERR_NONE, status, "Decode proxy-ok");
    if (proxy == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok_block(8, 0, "Decoding failed");
    } else {
        is_string("testuser", proxy->subject, "...subject");
        is_string("krb5", proxy->type, "...type");
        ok(memcmp("s=foo\0s=bar;;da", proxy->webkdc_proxy, 15) == 0,
           "...WebKDC proxy token");
        is_int(15, proxy->webkdc_proxy_len, "...WebKDC proxy token length");
        is_string("p,o1,o,m", proxy->initial_factors, "...initial factors");
        is_string("p,o1,o,m", proxy->session_factors, "...session factors");
        is_int(2, proxy->loa, "...level of assurance");
        is_int(1308777900, proxy->creation, "...creation");
        is_int(2147483600, proxy->expiration, "...expiration");
    }
    free(token);

    /* Test decoding error cases for proxy tokens. */
    check_proxy_error(ctx, "app-bad-hmac", ring, WA_ERR_BAD_HMAC,
                      "bad proxy token");
    check_proxy_error(ctx, "proxy-empty", ring, WA_ERR_CORRUPT,
                      "decoding attribute s failed");
    check_proxy_error(ctx, "proxy-exp", ring, WA_ERR_TOKEN_EXPIRED,
                      "bad proxy token");
    check_proxy_error(ctx, "app-ok", ring, WA_ERR_CORRUPT,
                      "wrong token type app while decoding proxy token");

    /* Test decoding of several types of request tokens. */
    token = read_token("data/tokens/req-id");
    status = webauth_token_decode_request(ctx, token, ring, &req);
    is_int(WA_ERR_NONE, status, "Decode req-id");
    if (req == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok_block(11, 0, "Decoding failed");
    } else {
        is_string("id", req->type, "...type");
        is_string("webkdc", req->auth, "...subject auth");
        is_string(NULL, req->proxy_type, "...proxy type");
        ok(memcmp("s=foo\0s=bar;;da", req->state, 15) == 0, "...state");
        is_int(15, req->state_len, "...state length");
        is_string("https://example.com/", req->return_url, "...return URL");
        is_string("fa", req->options, "...options");
        is_string("p,o3,o,m", req->initial_factors, "...initial factors");
        is_string("p,o3,o,m", req->session_factors, "...session factors");
        is_int(3, req->loa, "...level of assurance");
        is_string(NULL, req->command, "...command");
        is_int(1308777900, req->creation, "...creation");
    }
    free(token);
    token = read_token("data/tokens/req-id-krb5");
    status = webauth_token_decode_request(ctx, token, ring, &req);
    is_int(WA_ERR_NONE, status, "Decode req-id-krb5");
    if (req == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok_block(11, 0, "Decoding failed");
    } else {
        is_string("id", req->type, "...type");
        is_string("krb5", req->auth, "...subject auth");
        is_string(NULL, req->proxy_type, "...proxy type");
        ok(memcmp("s=foo\0s=bar;;da", req->state, 15) == 0, "...state");
        is_int(15, req->state_len, "...state length");
        is_string("https://example.com/", req->return_url, "...return URL");
        is_string("fa", req->options, "...options");
        is_string("p,o3,o,m", req->initial_factors, "...initial factors");
        is_string("p,o3,o,m", req->session_factors, "...session factors");
        is_int(3, req->loa, "...level of assurance");
        is_string(NULL, req->command, "...command");
        is_int(1308777900, req->creation, "...creation");
    }
    free(token);
    token = read_token("data/tokens/req-minimal");
    status = webauth_token_decode_request(ctx, token, ring, &req);
    is_int(WA_ERR_NONE, status, "Decode req-minimal");
    if (req == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok_block(11, 0, "Decoding failed");
    } else {
        is_string("id", req->type, "...type");
        is_string("webkdc", req->auth, "...subject auth");
        is_string(NULL, req->proxy_type, "...proxy type");
        is_string(NULL, req->state, "...state");
        is_int(0, req->state_len, "...state length");
        is_string("https://example.com/", req->return_url, "...return URL");
        is_string(NULL, req->options, "...options");
        is_string(NULL, req->initial_factors, "...initial factors");
        is_string(NULL, req->session_factors, "...session factors");
        is_int(0, req->loa, "...level of assurance");
        is_string(NULL, req->command, "...command");
        is_int(1308777900, req->creation, "...creation");
    }
    free(token);
    token = read_token("data/tokens/req-proxy");
    status = webauth_token_decode_request(ctx, token, ring, &req);
    is_int(WA_ERR_NONE, status, "Decode req-proxy");
    if (req == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok_block(11, 0, "Decoding failed");
    } else {
        is_string("proxy", req->type, "...type");
        is_string(NULL, req->auth, "...subject auth");
        is_string("krb5", req->proxy_type, "...proxy type");
        ok(memcmp("s=foo\0s=bar;;da", req->state, 15) == 0, "...state");
        is_int(15, req->state_len, "...state length");
        is_string("https://example.com/", req->return_url, "...return URL");
        is_string("fa", req->options, "...options");
        is_string("p,o3,o,m", req->initial_factors, "...initial factors");
        is_string("p,o3,o,m", req->session_factors, "...session factors");
        is_int(3, req->loa, "...level of assurance");
        is_string(NULL, req->command, "...command");
        is_int(1308777900, req->creation, "...creation");
    }
    free(token);
    token = read_token("data/tokens/req-command");
    status = webauth_token_decode_request(ctx, token, ring, &req);
    is_int(WA_ERR_NONE, status, "Decode req-command");
    if (req == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok_block(11, 0, "Decoding failed");
    } else {
        is_string(NULL, req->type, "...type");
        is_string(NULL, req->auth, "...subject auth");
        is_string(NULL, req->proxy_type, "...proxy type");
        is_string(NULL, req->state, "...state");
        is_int(0, req->state_len, "...state length");
        is_string(NULL, req->return_url, "...return URL");
        is_string(NULL, req->options, "...options");
        is_string(NULL, req->initial_factors, "...initial factors");
        is_string(NULL, req->session_factors, "...session factors");
        is_int(0, req->loa, "...level of assurance");
        is_string("getTokensRequest", req->command, "...command");
        is_int(1308777900, req->creation, "...creation");
    }
    free(token);

    /* Test decoding error cases for request tokens. */
    check_request_error(ctx, "app-bad-hmac", ring, WA_ERR_BAD_HMAC,
                        "bad req token");
    check_request_error(ctx, "app-ok", ring, WA_ERR_CORRUPT,
                        "wrong token type app while decoding req token");

    /* Test decoding of a webkdc-proxy token. */
    token = read_token("data/tokens/wkproxy-ok");
    status = webauth_token_decode_webkdc_proxy(ctx, token, ring, &wkproxy);
    is_int(WA_ERR_NONE, status, "Decode wkproxy-ok");
    if (wkproxy == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok_block(8, 0, "Decoding failed");
    } else {
        is_string("testuser", wkproxy->subject, "...subject");
        is_string("krb5", wkproxy->proxy_type, "...proxy type");
        is_string("krb5:service/foo@EXAMPLE.COM", wkproxy->proxy_subject,
                  "...proxy subject");
        ok(memcmp("s=foo\0s=bar;;da", wkproxy->data, 15) == 0,
           "...proxy data");
        is_int(15, wkproxy->data_len, "...proxy data length");
        is_string("p,o1,o,m", wkproxy->initial_factors, "...initial factors");
        is_int(2, wkproxy->loa, "...level of assurance");
        is_int(1308777900, wkproxy->creation, "...creation");
        is_int(2147483600, wkproxy->expiration, "...expiration");
    }
    free(token);

    /* Test decoding of a minimal webkdc-proxy token. */
    token = read_token("data/tokens/wkproxy-min");
    status = webauth_token_decode_webkdc_proxy(ctx, token, ring, &wkproxy);
    is_int(WA_ERR_NONE, status, "Decode wkproxy-min");
    if (wkproxy == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok_block(8, 0, "Decoding failed");
    } else {
        is_string("testuser", wkproxy->subject, "...subject");
        is_string("remuser", wkproxy->proxy_type, "...proxy type");
        is_string("WEBKDC:remuser", wkproxy->proxy_subject,
                  "...proxy subject");
        ok(memcmp("testuser", wkproxy->data, 8) == 0, "...proxy data");
        is_int(8, wkproxy->data_len, "...proxy data length");
        is_string(NULL, wkproxy->initial_factors, "...initial factors");
        is_int(0, wkproxy->loa, "...level of assurance");
        is_int(1308777900, wkproxy->creation, "...creation");
        is_int(2147483600, wkproxy->expiration, "...expiration");
    }
    free(token);

    /* Test decoding error cases for webkdc-proxy tokens. */
    check_webkdc_proxy_error(ctx, "app-bad-hmac", ring, WA_ERR_BAD_HMAC,
                             "bad webkdc-proxy token");
    check_webkdc_proxy_error(ctx, "wkproxy-exp", ring, WA_ERR_TOKEN_EXPIRED,
                             "bad webkdc-proxy token");
    check_webkdc_proxy_error(ctx, "app-ok", ring, WA_ERR_CORRUPT,
                             "wrong token type app while decoding"
                             " webkdc-proxy token");

    /* Test decoding of a webkdc-service token. */
    token = read_token("data/tokens/service-ok");
    status = webauth_token_decode_webkdc_service(ctx, token, ring, &service);
    is_int(WA_ERR_NONE, status, "Decode service-ok");
    if (service == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok_block(4, 0, "Decoding failed");
    } else {
        is_string("krb5:service/foo@EXAMPLE.COM", service->subject,
                  "...subject");
        ok(memcmp("s=foo\0s=bar;;da", service->session_key, 15) == 0,
           "...session key");
        is_int(15, service->session_key_len, "...session key length");
        is_int(1308777900, service->creation, "...creation");
        is_int(2147483600, service->expiration, "...expiration");
    }
    free(token);

    /* Test decoding error cases for webkdc-service tokens. */
    check_webkdc_service_error(ctx, "app-bad-hmac", ring, WA_ERR_BAD_HMAC,
                               "bad webkdc-service token");
    check_webkdc_service_error(ctx, "service-exp", ring, WA_ERR_TOKEN_EXPIRED,
                               "bad webkdc-service token");
    check_webkdc_service_error(ctx, "app-ok", ring, WA_ERR_CORRUPT,
                               "wrong token type app while decoding"
                               " webkdc-service token");

    /*
     * Now test for the generic decoding function.  We'll run each of the
     * token types we support through it and make sure that it works
     * properly.  We won't bother checking every data element of the tokens,
     * just something relatively unique to that token.
     */
    token = read_token("data/tokens/app-ok");
    status = webauth_token_decode(ctx, token, ring, &type, &generic);
    is_int(WA_ERR_NONE, status, "Generic decode app-ok");
    is_int(WA_TOKEN_APP, type, "...token type");
    if (generic == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok(0, "Decoding failed");
    } else {
        app = generic;
        ok(app != NULL, "...token struct");
        is_int(1308777930, app->last_used, "...last used");
    }
    free(token);
    token = read_token("data/tokens/cred-ok");
    status = webauth_token_decode(ctx, token, ring, &type, &generic);
    is_int(WA_ERR_NONE, status, "Generic decode cred-ok");
    is_int(WA_TOKEN_CRED, type, "...token type");
    if (generic == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok(0, "Decoding failed");
    } else {
        cred = generic;
        ok(cred != NULL, "...token struct");
        is_string("webauth/example.com@EXAMPLE.COM", cred->service,
                  "...service");
    }
    free(token);
    token = read_token("data/tokens/error-ok");
    status = webauth_token_decode(ctx, token, ring, &type, &generic);
    is_int(WA_ERR_NONE, status, "Generic decode error-ok");
    is_int(WA_TOKEN_ERROR, type, "...token type");
    if (generic == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok(0, "Decoding failed");
    } else {
        err = generic;
        ok(err != NULL, "...token struct");
        is_string("user canceled login", err->message, "...message");
    }
    free(token);
    token = read_token("data/tokens/id-webkdc");
    status = webauth_token_decode(ctx, token, ring, &type, &generic);
    is_int(WA_ERR_NONE, status, "Generic decode id-webkdc");
    is_int(WA_TOKEN_ID, type, "...token type");
    if (generic == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok(0, "Decoding failed");
    } else {
        id = generic;
        ok(id != NULL, "...token struct");
        is_string("webkdc", id->auth, "...subject auth");
    }
    free(token);
    token = read_token("data/tokens/proxy-ok");
    status = webauth_token_decode(ctx, token, ring, &type, &generic);
    is_int(WA_ERR_NONE, status, "Generic decode proxy-ok");
    is_int(WA_TOKEN_PROXY, type, "...token type");
    if (generic == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok(0, "Decoding failed");
    } else {
        proxy = generic;
        ok(proxy != NULL, "...token struct");
        ok(memcmp("s=foo\0s=bar;;da", proxy->webkdc_proxy, 15) == 0,
           "...WebKDC proxy token");
    }
    free(token);
    token = read_token("data/tokens/req-id");
    status = webauth_token_decode(ctx, token, ring, &type, &generic);
    is_int(WA_ERR_NONE, status, "Generic decode req-id");
    is_int(WA_TOKEN_REQUEST, type, "...token type");
    if (generic == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok(0, "Decoding failed");
    } else {
        req = generic;
        ok(id != NULL, "...token struct");
        is_string("https://example.com/", req->return_url, "...return URL");
    }
    free(token);

    /*
     * And test basic error handling with generic decoding.  We won't bother
     * to test the error message; that was previously tested.
     */
    token = read_token("data/tokens/app-bad-hmac");
    status = webauth_token_decode(ctx, token, ring, &type, &generic);
    is_int(WA_ERR_BAD_HMAC, status, "Failed generic decode of app-bad-hmac");
    is_int(WA_TOKEN_UNKNOWN, type, "...token type");
    ok(generic == NULL, "...token struct");
    free(token);

    /* Clean up. */
    webauth_keyring_free(ring);
    webauth_context_free(ctx);
    return 0;
}
