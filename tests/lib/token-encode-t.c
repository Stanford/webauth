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

    plan(28);

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

    /* Clean up. */
    webauth_keyring_free(ring);
    webauth_context_free(ctx);
    return 0;
}
