/*
 * Test WebAuth Application Server token cache support.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2012
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <time.h>

#include <tests/tap/basic.h>
#include <tests/tap/string.h>
#include <webauth/basic.h>
#include <webauth/keys.h>
#include <webauth/was.h>


int
main(void)
{
    struct webauth_context *ctx;
    struct webauth_was_token_cache cache, cache2;
    struct webauth_key *key;
    time_t now;
    char *tmpdir, *path;
    int s;

    plan(20);

    if (webauth_context_init(&ctx, NULL) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    /* Create some random data to store in a token cache. */
    now = time(NULL);
    s = webauth_key_create(ctx, WA_KEY_AES, WA_AES_128, NULL, &key);
    if (s != WA_ERR_NONE)
        bail("cannot create key: %s", webauth_error_message(ctx, s));
    cache.token = (char *) "asdfghjkl;v=1";
    cache.key_type = key->type;
    cache.key_data = key->data;
    cache.key_data_len = key->length;
    cache.created = now;
    cache.expires = now + 10;
    cache.last_renewal = now;
    cache.next_renewal = now + 5;

    /* Test storing that data in a cache file. */
    tmpdir = test_tmpdir();
    basprintf(&path, "%s/token-cache", tmpdir);
    s = webauth_was_token_cache_write(ctx, &cache, path);
    is_int(WA_ERR_NONE, s, "Writing token cache succeeds");
    is_int(0, access(path, R_OK), "...and file now exists");

    /* Read the data back in. */
    memset(&cache2, 0, sizeof(cache2));
    s = webauth_was_token_cache_read(ctx, path, &cache2);
    is_int(WA_ERR_NONE, s, "Reading token cache succeeds");
    is_string(cache.token, cache2.token, "...and token is correct");
    is_int(cache.key_type, cache2.key_type, "...and key type is correct");
    is_int(cache.key_data_len, cache2.key_data_len,
           "...and key length is correct");
    ok(memcmp(cache.key_data, cache2.key_data, cache.key_data_len) == 0,
       "...and key data is correct");
    is_int(cache.created, cache2.created, "...and created is correct");
    is_int(cache.expires, cache2.expires, "...and expires is correct");
    is_int(cache.last_renewal, cache2.last_renewal,
           "...and last renewal is correct");
    is_int(cache.next_renewal, cache2.next_renewal,
           "...and next renewal is correct");
    unlink(path);
    free(path);

    /* Read in a known service token and ensure that we can decode it. */
    path = test_file_path("data/service-token");
    memset(&cache, 0, sizeof(cache));
    s = webauth_was_token_cache_read(ctx, path, &cache);
    if (s != WA_ERR_NONE)
        diag("failed: %s", webauth_error_message(ctx, s));
    is_int(WA_ERR_NONE, s, "Reading known token succeeds");
    ok(cache.token != NULL, "...and token is non-NULL");
    is_int(WA_KEY_AES, cache.key_type, "...and key type is correct");
    is_int(WA_AES_128, cache.key_data_len, "...and key length is correct");
    ok(cache.key_data != NULL, "...and key data is non-NULL");
    is_int(1346791413, cache.created, "...and created is correct");
    is_int(1349383413, cache.expires, "...and expires is correct");
    is_int(0, cache.last_renewal, "...and last renewal is correct");
    is_int(1349124213, cache.next_renewal, "...and next renewal is correct");

    /* Clean up. */
    test_file_path_free(path);
    test_tmpdir_free(tmpdir);
    webauth_context_free(ctx);
    return 0;
}
