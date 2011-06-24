/*
 * Test token encoding and decoding.
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


int
main(void)
{
    WEBAUTH_KEYRING *ring;
    char *keyring, *token;
    int status;
    struct webauth_context *ctx;
    struct webauth_token_app *app;
    struct webauth_token_cred *cred;
    struct webauth_token_proxy *proxy;

    plan(55);

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
        ok_block(6, 0, "Decoding failed");
    } else {
        is_string("testuser", app->subject, "...subject");
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
        ok_block(6, 0, "Decoding failed");
    } else {
        is_string("testuser", app->subject, "...subject");
        is_int(0, app->last_used, "...last used");
        is_string(NULL, app->initial_factors, "...initial factors");
        is_string(NULL, app->session_factors, "...session factors");
        is_int(0, app->loa, "...level of assurance");
        is_int(0, app->creation, "...creation");
        is_int(2147483600, app->expiration, "...expiration");
    }
    free(token);

    /* Test decoding error cases for app tokens. */
    token = read_token("data/tokens/app-bad-hmac");
    status = webauth_token_decode_app(ctx, token, ring, &app);
    is_int(WA_ERR_BAD_HMAC, status, "Fail to decode app-bad-hmac");
    is_string("bad app token: HMAC check failed",
              webauth_error_message(ctx, status), "...with correct error");
    free(token);
    token = read_token("data/tokens/app-empty");
    status = webauth_token_decode_app(ctx, token, ring, &app);
    is_int(WA_ERR_CORRUPT, status, "Fail to decode app-empty");
    is_string("decoding attribute s failed: data is incorrectly formatted",
              webauth_error_message(ctx, status), "...with correct error");
    free(token);
    token = read_token("data/tokens/app-expired");
    status = webauth_token_decode_app(ctx, token, ring, &app);
    is_int(WA_ERR_TOKEN_EXPIRED, status, "Fail to decode app-expired");
    is_string("bad app token: token has expired",
              webauth_error_message(ctx, status), "...with correct error");
    free(token);
    token = read_token("data/tokens/cred-ok");
    status = webauth_token_decode_app(ctx, token, ring, &app);
    is_int(WA_ERR_CORRUPT, status, "Fail to decode cred-ok as app token");
    is_string("wrong token type cred while decoding app token: data is"
              " incorrectly formatted", webauth_error_message(ctx, status),
              "...with correct error");
    free(token);

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
    token = read_token("data/tokens/app-bad-hmac");
    status = webauth_token_decode_cred(ctx, token, ring, &cred);
    is_int(WA_ERR_BAD_HMAC, status, "Fail to decode app-bad-hmac");
    is_string("bad cred token: HMAC check failed",
              webauth_error_message(ctx, status), "...with correct error");
    free(token);
    token = read_token("data/tokens/cred-empty");
    status = webauth_token_decode_cred(ctx, token, ring, &cred);
    is_int(WA_ERR_CORRUPT, status, "Fail to decode cred-empty");
    is_string("decoding attribute s failed: data is incorrectly formatted",
              webauth_error_message(ctx, status), "...with correct error");
    free(token);
    token = read_token("data/tokens/cred-exp");
    status = webauth_token_decode_cred(ctx, token, ring, &cred);
    is_int(WA_ERR_TOKEN_EXPIRED, status, "Fail to decode cred-exp");
    is_string("bad cred token: token has expired",
              webauth_error_message(ctx, status), "...with correct error");
    free(token);
    token = read_token("data/tokens/app-ok");
    status = webauth_token_decode_cred(ctx, token, ring, &cred);
    is_int(WA_ERR_CORRUPT, status, "Fail to decode app-ok as cred token");
    is_string("wrong token type app while decoding cred token: data is"
              " incorrectly formatted", webauth_error_message(ctx, status),
              "...with correct error");
    free(token);

    /* Test decoding of a proxy token. */
    token = read_token("data/tokens/proxy-ok");
    status = webauth_token_decode_proxy(ctx, token, ring, &proxy);
    is_int(WA_ERR_NONE, status, "Decode proxy-ok");
    if (proxy == NULL) {
        is_string("", webauth_error_message(ctx, status), "Decoding failed");
        ok_block(5, 0, "Decoding failed");
    } else {
        is_string("testuser", proxy->subject, "...subject");
        is_string("krb5", proxy->type, "...type");
        ok(memcmp("s=foo\0s=bar;;da", proxy->webkdc_proxy, 15) == 0,
           "...WebKDC proxy token");
        is_int(15, proxy->webkdc_proxy_len, "...WebKDC proxy token length");
        is_int(1308777900, proxy->creation, "...creation");
        is_int(2147483600, proxy->expiration, "...expiration");
    }
    free(token);

    /* Test decoding error cases for proxy tokens. */
    token = read_token("data/tokens/app-bad-hmac");
    status = webauth_token_decode_proxy(ctx, token, ring, &proxy);
    is_int(WA_ERR_BAD_HMAC, status, "Fail to decode app-bad-hmac");
    is_string("bad proxy token: HMAC check failed",
              webauth_error_message(ctx, status), "...with correct error");
    free(token);
    token = read_token("data/tokens/proxy-empty");
    status = webauth_token_decode_proxy(ctx, token, ring, &proxy);
    is_int(WA_ERR_CORRUPT, status, "Fail to decode proxy-empty");
    is_string("decoding attribute s failed: data is incorrectly formatted",
              webauth_error_message(ctx, status), "...with correct error");
    free(token);
    token = read_token("data/tokens/proxy-exp");
    status = webauth_token_decode_proxy(ctx, token, ring, &proxy);
    is_int(WA_ERR_TOKEN_EXPIRED, status, "Fail to decode proxy-exp");
    is_string("bad proxy token: token has expired",
              webauth_error_message(ctx, status), "...with correct error");
    free(token);
    token = read_token("data/tokens/app-ok");
    status = webauth_token_decode_proxy(ctx, token, ring, &proxy);
    is_int(WA_ERR_CORRUPT, status, "Fail to decode app-ok as proxy token");
    is_string("wrong token type app while decoding proxy token: data is"
              " incorrectly formatted", webauth_error_message(ctx, status),
              "...with correct error");
    free(token);

    /* Clean up. */
    webauth_context_free(ctx);
    return 0;
}
