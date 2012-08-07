/*
 * Test suite for libwebauth Kerberos TGT manipulation.
 *
 * Written by Roland Schemers
 * Updated for current TAP library support by Russ Allbery
 * Copyright 2003, 2006, 2009, 2010, 2012
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <tests/tap/basic.h>
#include <tests/tap/kerberos.h>
#include <tests/tap/string.h>
#include <webauth.h>
#include <webauth/basic.h>
#include <webauth/krb5.h>

#define CHECK(ctx, s, m) check_status((ctx), (s), (m), __FILE__, __LINE__)


static void
check_status(struct webauth_context *ctx, int s, const char *message,
             const char *file, unsigned long line)
{
    if (s != WA_ERR_NONE)
        diag("webauth call failed %s line %lu: %s (%d)\n", file, line,
             webauth_error_message(ctx, s), s);
    is_int(s, WA_ERR_NONE, "%s", message);
}

   
static void
do_export(struct webauth_context *ctx, const char *principal,
          const char *cache, const char *path)
{
    int s;
    struct webauth_krb5 *kc;
    void *tgt, *req, *etgt;
    size_t tgt_len, req_len, etgt_len;
    time_t expiration;
    char b64[4192];
    size_t b64_len;
    FILE *export;

    export = fopen(path, "w");
    if (export == NULL)
        sysbail("cannot create %s", path);
    s = webauth_krb5_new(ctx, &kc);
    CHECK(ctx, s, "Create context");
    s = webauth_krb5_init_via_cache(ctx, kc, cache);
    CHECK(ctx, s, "Initialize from cache");
    s = webauth_krb5_export_cred(ctx, kc, NULL, &tgt, &tgt_len, &expiration);
    CHECK(ctx, s, "Export TGT");
    s = webauth_krb5_make_auth_data(ctx, kc, principal, &req, &req_len,
                                    tgt, tgt_len, &etgt, &etgt_len);
    CHECK(ctx, s, "Make AP-REQ with data");
    s = webauth_base64_encode(req, req_len, b64, &b64_len, sizeof(b64) - 1);
    CHECK(ctx, s, "base64-encode AP-REQ");
    b64[b64_len] = '\0';
    fprintf(export, "%s\n", b64);
    s = webauth_base64_encode(etgt, etgt_len, b64, &b64_len, sizeof(b64) - 1);
    CHECK(ctx, s, "base64-encode supporting data");
    b64[b64_len] = '\0';
    fprintf(export, "%s\n", b64);
    fclose(export);
    webauth_krb5_free(ctx, kc);
}


static void
do_import(struct webauth_context *ctx, struct kerberos_config *config,
          const char *path)
{
    int s;
    struct webauth_krb5 *kc;
    char req[4192], tgt[4192];
    size_t req_len, tgt_len, dec_tgt_len;
    void *dec_tgt;
    char *cprinc, *sprinc;
    FILE *data;

    data = fopen(path, "r");
    if (data == NULL)
        sysbail("cannot open %s", path);
    if (fgets(req, sizeof(req), data) == NULL)
        sysbail("error reading from %s", path);
    if (req[strlen(req) - 1] != '\n')
        bail("newline not found in %s", path);
    req[strlen(req) - 1] = '\0';
    if (fgets(tgt, sizeof(tgt), data) == NULL)
        sysbail("error reading from %s", path);
    if (tgt[strlen(tgt) - 1] != '\n')
        bail("newline not found in %s", path);
    tgt[strlen(tgt) - 1] = '\0';
    fclose(data);

    s = webauth_base64_decode(req, strlen(req), req, &req_len, strlen(req));
    CHECK(ctx, s, "base64-decode AP-REQ");
    s = webauth_base64_decode(tgt, strlen(tgt), tgt, &tgt_len, strlen(tgt));
    CHECK(ctx, s, "base64-decode additional data");
    s = webauth_krb5_new(ctx, &kc);
    CHECK(ctx, s, "Create new context");
    s = webauth_krb5_read_auth_data(ctx, kc, req, req_len, config->keytab,
                                    NULL, &sprinc, &cprinc,
                                    WA_KRB5_CANON_NONE, tgt, tgt_len,
                                    &dec_tgt, &dec_tgt_len);
    CHECK(ctx, s, "Read request and data");
    is_string(config->principal, cprinc, "Client principal matches keytab");
    is_string(config->principal, sprinc, "Server principal matches keytab");
    s = webauth_krb5_import_cred(ctx, kc, dec_tgt, dec_tgt_len, NULL);
    CHECK(ctx, s, "Initialize from credentials");
    webauth_krb5_free(ctx, kc);
}


int 
main(void)
{
    struct webauth_context *ctx;
    struct kerberos_config *config;
    char *tmpdir, *path;

    /* Read the configuration information. */
    config = kerberos_setup(TAP_KRB_NEEDS_KEYTAB);
    tmpdir = test_tmpdir();
    basprintf(&path, "%s/test-cred", tmpdir);

    /* Do the tests. */
    plan(13);
    if (webauth_context_init(&ctx, NULL) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");
    do_export(ctx, config->principal, getenv("KRB5CCNAME"), path);
    do_import(ctx, config, path);

    /* Clean up. */
    unlink(path);
    free(path);
    test_tmpdir_free(tmpdir);
    webauth_context_free(ctx);
    return 0;
}
