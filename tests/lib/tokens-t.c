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

    plan(10);

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

    /* Test encoding and decoding of an app token. */
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

    /* Test error cases for app tokens. */
    token = read_token("data/tokens/app-bad-hmac");
    status = webauth_token_decode_app(ctx, token, ring, &app);
    is_int(WA_ERR_BAD_HMAC, status, "Fail to decode app-bad-hmac");
    is_string("bad application token: HMAC check failed",
              webauth_error_message(ctx, status), "...with correct error");
    free(token);

    /* Clean up. */
    webauth_context_free(ctx);
    return 0;
}
