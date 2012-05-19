/*
 * Test token decoding.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011, 2012
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
#include <webauth/keys.h>
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
    fclose(token);
    length = strlen(buffer);
    if (buffer[length - 1] == '\n')
        buffer[length - 1] = '\0';
    return xstrdup(buffer);
}


/*
 * Check a successful decoding of a token.  Takes the context, the token type,
 * the name of the token, and the keyring, and the number of tests to fail if
 * the token decoding fails.  Returns the decoded generic token.
 */
static struct webauth_token *
check_decode(struct webauth_context *ctx, enum webauth_token_type type,
             const char *name, const struct webauth_keyring *ring, int count)
{
    char *path, *token;
    int status;
    struct webauth_token *result;

    if (asprintf(&path, "data/tokens/%s", name) < 0)
        sysbail("cannot allocate memory");
    token = read_token(path);
    free(path);
    status = webauth_token_decode(ctx, type, token, ring, &result);
    free(token);
    is_int(WA_ERR_NONE, status, "%secode %s",
           (type == WA_TOKEN_ANY) ? "Generic d" : "D", name);
    if (result == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok_block(count, 0, "Decoding failed");
    } else {
        ok(result != NULL, "...succeeded");
    }
    return result;
}


/*
 * Check a successful decoding of a raw token.  Takes the context, the token
 * type, the name of the token, and the keyring, and the number of tests to
 * fail if the token decoding fails.  Returns the decoded generic token.
 */
static struct webauth_token *
check_decode_raw(struct webauth_context *ctx, enum webauth_token_type type,
                 const char *name, const struct webauth_keyring *ring,
                 int count)
{
    char *filename, *path;
    FILE *token;
    char buffer[4096];
    size_t len;
    int status;
    struct webauth_token *result;

    if (asprintf(&filename, "data/tokens/%s", name) < 0)
        sysbail("cannot allocate memory");
    path = test_file_path(filename);
    if (path == NULL)
        bail("cannot find test file %s", filename);
    free(filename);
    token = fopen(path, "rb");
    if (token == NULL)
        sysbail("cannot open %s", path);
    len = fread(buffer, 1, sizeof(buffer), token);
    if (len == 0)
        sysbail("cannot read %s", path);
    test_file_path_free(path);
    fclose(token);
    status = webauth_token_decode_raw(ctx, type, buffer, len, ring, &result);
    is_int(WA_ERR_NONE, status, "%secode %s",
           (type == WA_TOKEN_ANY) ? "Generic d" : "D", name);
    if (result == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok_block(count, 0, "Decoding failed");
    } else {
        ok(result != NULL, "...succeeded");
    }
    return result;
}


/*
 * Check decoding errors in various tokens.  Takes the context, the token
 * type, the name of the token, the keyring, the WebAuth status code, and the
 * expected error message.
 */
static void
check_error(struct webauth_context *ctx, enum webauth_token_type type,
            const char *name, const struct webauth_keyring *ring, int code,
            const char *message)
{
    int s;
    char *path, *token, *err;
    struct webauth_token *result;

    if (asprintf(&path, "data/tokens/%s", name) < 0)
        sysbail("cannot allocate memory");
    token = read_token(path);
    free(path);
    s = webauth_token_decode(ctx, type, token, ring, &result);
    is_int(code, s, "Fail to decode %s", name);
    if (asprintf(&err, "%s (%s)", webauth_error_message(NULL, code),
                 message) < 0)
        sysbail("cannot allocate memory");
    is_string(err, webauth_error_message(ctx, s), "...with error");
    free(err);
    free(token);
}


int
main(void)
{
    struct webauth_keyring *ring, *bad_ring;
    struct webauth_key *key;
    char *keyring;
    int status;
    struct webauth_context *ctx;
    struct webauth_token *result;
    struct webauth_token_app *app;
    struct webauth_token_cred *cred;
    struct webauth_token_error *err;
    struct webauth_token_id *id;
    struct webauth_token_login *login;
    struct webauth_token_proxy *proxy;
    struct webauth_token_request *req;
    struct webauth_token_webkdc_proxy *wkproxy;
    struct webauth_token_webkdc_service *service;

    plan(295);

    if (webauth_context_init(&ctx, NULL) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    /*
     * We're going to test token decoding and encoding using a set of
     * pre-created tokens in the data directory encrypted with a keyring
     * that's stored in that directory.  So start by loading that keyring.
     */
    keyring = test_file_path("data/keyring");
    status = webauth_keyring_read(ctx, keyring, &ring);
    if (status != WA_ERR_NONE)
        bail("cannot read %s: %s", keyring,
             webauth_error_message(ctx, status));
    test_file_path_free(keyring);

    /*
     * Test decoding of an app token.  There are two basic formats: one that
     * has all the authentication information and one that only holds a
     * session key.
     */
    result = check_decode(ctx, WA_TOKEN_APP, "app-ok", ring, 9);
    if (result != NULL) {
        app = &result->token.app;
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
    result = check_decode(ctx, WA_TOKEN_APP, "app-minimal", ring, 9);
    if (result != NULL) {
        app = &result->token.app;
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
    result = check_decode(ctx, WA_TOKEN_APP, "app-session", ring, 9);
    if (result != NULL) {
        app = &result->token.app;
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

    /* Test decoding error cases for app tokens. */
    check_error(ctx, WA_TOKEN_APP, "app-bad-hmac", ring, WA_ERR_BAD_HMAC,
                "HMAC check failed while decrypting token");
    check_error(ctx, WA_TOKEN_APP, "app-empty", ring, WA_ERR_CORRUPT,
                "decoding attribute s failed");
    check_error(ctx, WA_TOKEN_APP, "app-expired", ring, WA_ERR_TOKEN_EXPIRED,
                "token expired at 1308871632");
    check_error(ctx, WA_TOKEN_APP, "cred-ok", ring, WA_ERR_CORRUPT,
                "wrong token type cred while decoding app token");

    /*
     * Create a different keyring and test decoding a token using a keyring
     * that does not contain a usable key.
     */
    status = webauth_key_create(ctx, WA_AES_KEY, WA_AES_128, NULL, &key);
    if (key == NULL)
        bail("cannot create key: %s", webauth_error_message(ctx, status));
    bad_ring = webauth_keyring_from_key(ctx, key);
    check_error(ctx, WA_TOKEN_APP, "app-ok", bad_ring, WA_ERR_BAD_HMAC,
                "HMAC check failed while decrypting token");

    /* Test decoding of a credential token. */
    result = check_decode(ctx, WA_TOKEN_CRED, "cred-ok", ring, 7);
    if (result != NULL) {
        cred = &result->token.cred;
        is_string("testuser", cred->subject, "...subject");
        is_string("krb5", cred->type, "...type");
        is_string("webauth/example.com@EXAMPLE.COM", cred->service,
                  "...service");
        ok(memcmp("some\0cred;da;;ta", cred->data, 16) == 0, "...data");
        is_int(16, cred->data_len, "...data length");
        is_int(1308777900, cred->creation, "...creation");
        is_int(2147483600, cred->expiration, "...expiration");
    }

    /* Test decoding error cases for cred tokens. */
    check_error(ctx, WA_TOKEN_CRED, "cred-empty", ring, WA_ERR_CORRUPT,
                "decoding attribute s failed");
    check_error(ctx, WA_TOKEN_CRED, "cred-exp", ring, WA_ERR_TOKEN_EXPIRED,
                "token expired at 1308871632");
    check_error(ctx, WA_TOKEN_CRED, "error-ok", ring, WA_ERR_CORRUPT,
                "wrong token type error while decoding cred token");

    /* Test decoding of an error token. */
    result = check_decode(ctx, WA_TOKEN_ERROR, "error-ok", ring, 3);
    if (result != NULL) {
        err = &result->token.error;
        is_int(16, err->code, "...code");
        is_string("user canceled login", err->message, "...message");
        is_int(1308777900, err->creation, "...creation");
    }

    /* Test decoding error cases for error tokens. */
    check_error(ctx, WA_TOKEN_ERROR, "error-code", ring, WA_ERR_CORRUPT,
                "error code foo is not a number");
    check_error(ctx, WA_TOKEN_ERROR, "id-krb5", ring, WA_ERR_CORRUPT,
                "wrong token type id while decoding error token");

    /* Test decoding of a id tokens.  There are several variants. */
    result = check_decode(ctx, WA_TOKEN_ID, "id-webkdc", ring, 9);
    if (result != NULL) {
        id = &result->token.id;
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
    result = check_decode(ctx, WA_TOKEN_ID, "id-krb5", ring, 9);
    if (result != NULL) {
        id = &result->token.id;
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
    result = check_decode(ctx, WA_TOKEN_ID, "id-minimal", ring, 9);
    if (result != NULL) {
        id = &result->token.id;
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

    /* Test decoding error cases for id tokens. */
    check_error(ctx, WA_TOKEN_ID, "id-expired", ring, WA_ERR_TOKEN_EXPIRED,
                "token expired at 1308871632");
    check_error(ctx, WA_TOKEN_ID, "login-pass", ring, WA_ERR_CORRUPT,
                "wrong token type login while decoding id token");

    /* Test decoding of login tokens. */
    result = check_decode(ctx, WA_TOKEN_LOGIN, "login-pass", ring, 4);
    if (result != NULL) {
        login = &result->token.login;
        is_string("testuser", login->username, "...username");
        is_string("some;s=password", login->password, "...password");
        is_string(NULL, login->otp, "...otp");
        is_int(1308777900, login->creation, "...creation");
    }
    result = check_decode(ctx, WA_TOKEN_LOGIN, "login-otp", ring, 4);
    if (result != NULL) {
        login = &result->token.login;
        is_string("testuser", login->username, "...username");
        is_string(NULL, login->password, "...password");
        is_string("489147", login->otp, "...otp");
        is_int(1308777900, login->creation, "...creation");
    }

    /* Test decoding error cases for login tokens. */
    check_error(ctx, WA_TOKEN_LOGIN, "login-empty", ring, WA_ERR_CORRUPT,
                "decoding attribute ct failed");
    check_error(ctx, WA_TOKEN_LOGIN, "proxy-ok", ring, WA_ERR_CORRUPT,
                "wrong token type proxy while decoding login token");

    /* Test decoding of a proxy token. */
    result = check_decode(ctx, WA_TOKEN_PROXY, "proxy-ok", ring, 9);
    if (result != NULL) {
        proxy = &result->token.proxy;
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

    /* Test decoding error cases for proxy tokens. */
    check_error(ctx, WA_TOKEN_PROXY, "proxy-empty", ring, WA_ERR_CORRUPT,
                "decoding attribute s failed");
    check_error(ctx, WA_TOKEN_PROXY, "proxy-exp", ring, WA_ERR_TOKEN_EXPIRED,
                "token expired at 1308871632");
    check_error(ctx, WA_TOKEN_PROXY, "req-id", ring, WA_ERR_CORRUPT,
                "wrong token type req while decoding proxy token");

    /* Test decoding of several types of request tokens. */
    result = check_decode(ctx, WA_TOKEN_REQUEST, "req-id", ring, 12);
    if (result != NULL) {
        req = &result->token.request;
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
    result = check_decode(ctx, WA_TOKEN_REQUEST, "req-id-krb5", ring, 12);
    if (result != NULL) {
        req = &result->token.request;
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
    result = check_decode(ctx, WA_TOKEN_REQUEST, "req-minimal", ring, 12);
    if (result != NULL) {
        req = &result->token.request;
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
    result = check_decode(ctx, WA_TOKEN_REQUEST, "req-proxy", ring, 12);
    if (result != NULL) {
        req = &result->token.request;
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
    result = check_decode(ctx, WA_TOKEN_REQUEST, "req-command", ring, 12);
    if (result != NULL) {
        req = &result->token.request;
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

    /* Test decoding error cases for request tokens. */
    check_error(ctx, WA_TOKEN_REQUEST, "wkproxy-ok", ring, WA_ERR_CORRUPT,
                "wrong token type webkdc-proxy while decoding req token");

    /* Test decoding of several webkdc-proxy tokens. */
    result = check_decode(ctx, WA_TOKEN_WEBKDC_PROXY, "wkproxy-ok", ring, 9);
    if (result != NULL) {
        wkproxy = &result->token.webkdc_proxy;
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
    result = check_decode(ctx, WA_TOKEN_WEBKDC_PROXY, "wkproxy-min", ring, 9);
    if (result != NULL) {
        wkproxy = &result->token.webkdc_proxy;
        is_string("testuser", wkproxy->subject, "...subject");
        is_string("remuser", wkproxy->proxy_type, "...proxy type");
        is_string("WEBKDC:remuser", wkproxy->proxy_subject,
                  "...proxy subject");
        ok(wkproxy->data == NULL, "...proxy data");
        is_int(0, wkproxy->data_len, "...proxy data length");
        is_string(NULL, wkproxy->initial_factors, "...initial factors");
        is_int(0, wkproxy->loa, "...level of assurance");
        is_int(1308777900, wkproxy->creation, "...creation");
        is_int(2147483600, wkproxy->expiration, "...expiration");
    }

    /* Test decoding error cases for webkdc-proxy tokens. */
    check_error(ctx, WA_TOKEN_WEBKDC_PROXY, "wkproxy-exp", ring,
                WA_ERR_TOKEN_EXPIRED, "token expired at 1308871632");
    check_error(ctx, WA_TOKEN_WEBKDC_PROXY, "app-ok", ring, WA_ERR_CORRUPT,
                "wrong token type app while decoding webkdc-proxy token");

    /* Test decoding of a webkdc-service token. */
    result = check_decode(ctx, WA_TOKEN_WEBKDC_SERVICE, "service-ok", ring, 5);
    if (result != NULL) {
        service = &result->token.webkdc_service;
        is_string("krb5:service/foo@EXAMPLE.COM", service->subject,
                  "...subject");
        ok(memcmp("s=foo\0s=bar;;da", service->session_key, 15) == 0,
           "...session key");
        is_int(15, service->session_key_len, "...session key length");
        is_int(1308777900, service->creation, "...creation");
        is_int(2147483600, service->expiration, "...expiration");
    }

    /* Test decoding error cases for webkdc-service tokens. */
    check_error(ctx, WA_TOKEN_WEBKDC_SERVICE, "service-exp", ring,
                WA_ERR_TOKEN_EXPIRED, "token expired at 1308871632");
    check_error(ctx, WA_TOKEN_WEBKDC_SERVICE, "app-ok", ring, WA_ERR_CORRUPT,
                "wrong token type app while decoding webkdc-service token");

    /*
     * Now test for the generic decoding function.  We'll run each of the
     * token types we support through it and make sure that it works
     * properly.  We won't bother checking every data element of the tokens,
     * just something relatively unique to that token.
     */
    result = check_decode(ctx, WA_TOKEN_ANY, "app-ok", ring, 2);
    if (result != NULL) {
        is_int(WA_TOKEN_APP, result->type, "...with correct type");
        app = &result->token.app;
        is_int(1308777930, app->last_used, "...last used");
    }
    result = check_decode(ctx, WA_TOKEN_ANY, "cred-ok", ring, 2);
    if (result != NULL) {
        is_int(WA_TOKEN_CRED, result->type, "...with correct type");
        cred = &result->token.cred;
        is_string("webauth/example.com@EXAMPLE.COM", cred->service,
                  "...service");
    }
    result = check_decode(ctx, WA_TOKEN_ANY, "error-ok", ring, 2);
    if (result != NULL) {
        is_int(WA_TOKEN_ERROR, result->type, "...with correct type");
        err = &result->token.error;
        is_string("user canceled login", err->message, "...message");
    }
    result = check_decode(ctx, WA_TOKEN_ANY, "id-webkdc", ring, 2);
    if (result != NULL) {
        is_int(WA_TOKEN_ID, result->type, "...with correct type");
        id = &result->token.id;
        is_string("webkdc", id->auth, "...subject auth");
    }
    result = check_decode(ctx, WA_TOKEN_LOGIN, "login-pass", ring, 2);
    if (result != NULL) {
        is_int(WA_TOKEN_LOGIN, result->type, "...with correct type");
        login = &result->token.login;
        is_string("some;s=password", login->password, "...password");
    }
    result = check_decode(ctx, WA_TOKEN_ANY, "proxy-ok", ring, 2);
    if (result != NULL) {
        is_int(WA_TOKEN_PROXY, result->type, "..with correct type");
        proxy = &result->token.proxy;
        ok(memcmp("s=foo\0s=bar;;da", proxy->webkdc_proxy, 15) == 0,
           "...WebKDC proxy token");
    }
    result = check_decode(ctx, WA_TOKEN_ANY, "req-id", ring, 2);
    if (result != NULL) {
        is_int(WA_TOKEN_REQUEST, result->type, "..with correct type");
        req = &result->token.request;
        is_string("https://example.com/", req->return_url, "...return URL");
    }
    result = check_decode(ctx, WA_TOKEN_ANY, "wkproxy-ok", ring, 2);
    if (result != NULL) {
        is_int(WA_TOKEN_WEBKDC_PROXY, result->type, "...with correct type");
        wkproxy = &result->token.webkdc_proxy;
        is_string("krb5:service/foo@EXAMPLE.COM", wkproxy->proxy_subject,
                  "...proxy subject");
    }
    result = check_decode(ctx, WA_TOKEN_ANY, "service-ok", ring, 2);
    if (result != NULL) {
        is_int(WA_TOKEN_WEBKDC_SERVICE, result->type, "...with correct type");
        service = &result->token.webkdc_service;
        is_string("krb5:service/foo@EXAMPLE.COM", service->subject,
                  "...subject");
    }

    /* And test basic error handling with generic decoding. */
    check_error(ctx, WA_TOKEN_ANY, "app-bad-hmac", ring, WA_ERR_BAD_HMAC,
                "HMAC check failed while decrypting token");

    /* Test decoding of a raw app token. */
    result = check_decode_raw(ctx, WA_TOKEN_APP, "app-raw", ring, 9);
    if (result != NULL) {
        app = &result->token.app;
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

    /* Clean up. */
    webauth_context_free(ctx);
    return 0;
}
