/*
 * Test low-level token crypto routines.
 *
 * Test encrypting and decrypting data using the token algorithm.  We can test
 * this with arbitrary data, since these routines don't care about the
 * attribute formatting or content.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2012
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <tests/tap/basic.h>
#include <webauth/basic.h>
#include <webauth/keys.h>
#include <webauth/tokens.h>


/*
 * Read a token from a file name and store the resulting data and length in
 * the provided arguments.
 */
static void
read_token(const char *filename, void **data, size_t *length)
{
    char buffer[4096];
    char *path;
    FILE *token;

    path = test_file_path(filename);
    if (path == NULL)
        bail("cannot find test file %s", filename);
    token = fopen(path, "rb");
    if (token == NULL)
        sysbail("cannot open %s", path);
    test_file_path_free(path);
    *length = fread(buffer, 1, sizeof(buffer), token);
    if (*length == 0)
        sysbail("cannot read %s", path);
    fclose(token);
    *data = bmalloc(*length);
    memcpy(*data, buffer, *length);
}


int
main(void)
{
    struct webauth_context *ctx;
    struct webauth_keyring *ring;
    char *keyring;
    int status;
    void *data, *out, *token;
    size_t length, outlen;
    const char raw_data[] = { ';', ';', 0, ';', 't', '4', 1, 255 };
    const char app_raw[] =
        "t=app;s=testuser;lt=N\2]\312;ia=p;san=c;loa=\0\0\0\1;ct=N\2]\254;"
        "et=\177\377\377\320;";

    plan(10);

    if (webauth_context_init(&ctx, NULL) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    /* Load the precreated keyring that we'll use for token encryption. */
    keyring = test_file_path("data/keyring");
    status = webauth_keyring_read(ctx, keyring, &ring);
    if (status != WA_ERR_NONE)
        bail("cannot read %s: %s", keyring,
             webauth_error_message(ctx, status));
    test_file_path_free(keyring);

    /*
     * Test encrypting and then decrypting data and make sure that the
     * functions are symmetric.
     */
    status = webauth_token_encrypt(ctx, raw_data, sizeof(raw_data), &data,
                                   &length, ring);
    if (status != WA_ERR_NONE)
        diag("error: %s", webauth_error_message(ctx, status));
    is_int(0, status, "Token encryption works");
    status = webauth_token_decrypt(ctx, data, length, &out, &outlen, ring);
    if (status != WA_ERR_NONE)
        diag("error: %s", webauth_error_message(ctx, status));
    is_int(0, status, "Token decryption works");
    is_int(sizeof(raw_data), outlen, "...and output length is correct");
    if (out == NULL)
        ok(false, "...and output data is correct");
    else
        ok(memcmp(raw_data, out, sizeof(raw_data) - 1) == 0,
           "...and output data is correct");

    /* Test encrypting and decrypting the empty token. */
    status = webauth_token_encrypt(ctx, "", 0, &data, &length, ring);
    if (status != WA_ERR_NONE)
        diag("error: %s", webauth_error_message(ctx, status));
    is_int(0, status, "Encryption of empty token works");
    status = webauth_token_decrypt(ctx, data, length, &out, &outlen, ring);
    if (status != WA_ERR_NONE)
        diag("error: %s", webauth_error_message(ctx, status));
    is_int(0, status, "Decryption of empty token works");
    is_int(0, outlen, "...and output length is correct");

    /* Load some known data and decrypt it to verify the results. */
    read_token("data/tokens/app-raw", &token, &length);
    status = webauth_token_decrypt(ctx, token, length, &out, &outlen, ring);
    if (status != WA_ERR_NONE)
        diag("error: %s", webauth_error_message(ctx, status));
    is_int(0, status, "Decryption of app-raw works");
    is_int(sizeof(app_raw) - 1, outlen, "...and output length is correct");
    ok(memcmp(app_raw, out, sizeof(app_raw) - 1) == 0,
       "...and output data is correct");

    /* Clean up. */
    free(token);
    webauth_context_free(ctx);
    return 0;
}
