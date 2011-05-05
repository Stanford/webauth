/*
 * Test suite for libwebauth Kerberos TGT manipulation.
 *
 * Written by Roland Schemers
 * Updated for current TAP library support by Russ Allbery
 * Copyright 2003, 2006, 2009, 2010
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <lib/webauth.h>
#include <tests/tap/basic.h>
#include <tests/tap/kerberos.h>

#define CHECK(s, c, m) check_status(s, c, m, __FILE__, __LINE__)


static void
check_status(int s, WEBAUTH_KRB5_CTXT *c, const char *message,
             const char *file, unsigned long line)
{
    if (s == WA_ERR_KRB5 && c != NULL)
        diag("webauth call failed %s line %lu: %s (%d): %s %d\n", file, line,
             webauth_error_message(s), s, webauth_krb5_error_message(c),
             webauth_krb5_error_code(c));
    else if (s != WA_ERR_NONE)
        diag("webauth call failed %s line %lu: %s (%d)\n", file, line,
             webauth_error_message(s), s);
    is_int(s, WA_ERR_NONE, "%s", message);
}

   
static void
do_export(const char *principal, const char *cache)
{
    int s;
    WEBAUTH_KRB5_CTXT *c;
    char *tgt, *req, *etgt;
    size_t tgt_len, req_len, etgt_len;
    time_t expiration;
    char b64[4192];
    size_t b64_len;
    FILE *export;

    export = fopen("test-cred", "w");
    if (export == NULL)
        sysbail("cannot create test-cred");
    s = webauth_krb5_new(&c);
    CHECK(s, c, "Create context");
    s = webauth_krb5_init_via_cache(c, cache);
    CHECK(s, c, "Initialize from cache");
    s = webauth_krb5_keep_cred_cache(c);
    CHECK(s, c, "Mark cache as kept");
    s = webauth_krb5_export_tgt(c, &tgt, &tgt_len, &expiration);
    CHECK(s, c, "Export TGT");
    s = webauth_krb5_mk_req_with_data(c, principal, &req, &req_len,
                                      tgt, tgt_len, &etgt, &etgt_len);
    CHECK(s, c, "Make AP-REQ with data");
    s = webauth_base64_encode(req, req_len, b64, &b64_len, sizeof(b64) - 1);
    CHECK(s, c, "base64-encode AP-REQ");
    b64[b64_len] = '\0';
    fprintf(export, "%s\n", b64);
    s = webauth_base64_encode(etgt, etgt_len, b64, &b64_len, sizeof(b64) - 1);
    CHECK(s, c, "base64-encode supporting data");
    b64[b64_len] = '\0';
    fprintf(export, "%s\n", b64);
    fclose(export);

    free(tgt);
    free(req);
    free(etgt);
    s = webauth_krb5_free(c);
    CHECK(s, c, "Free context");
}


static void
do_import(const char *keytab)
{
    int s;
    WEBAUTH_KRB5_CTXT *c;
    char req[4192], tgt[4192];
    size_t req_len, tgt_len, dec_tgt_len;
    char *dec_tgt;
    char *cprinc;
    char *sprinc;
    FILE *data;

    data = fopen("test-cred", "r");
    if (data == NULL)
        sysbail("cannot open test-cred");
    if (fgets(req, sizeof(req), data) == NULL)
        sysbail("error reading from test-cred");
    if (req[strlen(req) - 1] != '\n')
        bail("newline not found in test-cred");
    req[strlen(req) - 1] = '\0';
    if (fgets(tgt, sizeof(tgt), data) == NULL)
        sysbail("error reading from test-cred");
    if (tgt[strlen(tgt) - 1] != '\n')
        bail("newline not found in test-cred");
    tgt[strlen(tgt) - 1] = '\0';
    fclose(data);
    unlink("test-cred");

    s = webauth_base64_decode(req, strlen(req), req, &req_len, strlen(req));
    CHECK(s, NULL, "base64-decode AP-REQ");
    s = webauth_base64_decode(tgt, strlen(tgt), tgt, &tgt_len, strlen(tgt));
    CHECK(s, NULL, "base64-decode additional data");
    s = webauth_krb5_new(&c);
    CHECK(s, c, "Create new context");
    s = webauth_krb5_rd_req_with_data(c, req, req_len, keytab, NULL, &sprinc,
                                      &cprinc, 1, tgt, tgt_len, &dec_tgt,
                                      &dec_tgt_len);
    CHECK(s, c, "Read request and data");
    ok(cprinc != NULL, "Client principal is not NULL");
    ok(sprinc != NULL, "Server principal is not NULL");
    free(cprinc);
    free(sprinc);
    s = webauth_krb5_init_via_cred(c, dec_tgt, dec_tgt_len, NULL);
    CHECK(s, c, "Initialize from credentials");
    s = webauth_krb5_keep_cred_cache(c);
    CHECK(s, c, "Save credential cache");
    s = webauth_krb5_free(c);
    CHECK(s, NULL, "Free context");
}


int 
main(void)
{
    char *principal, *keytab;

    /* Read the configuration information. */
    principal = kerberos_setup();
    if (principal == NULL)
        skip_all("No valid Kerberos ticket cache");
    keytab = test_file_path("data/test.keytab");

    /* Do the tests. */
    plan(17);
    do_export(principal, getenv("KRB5CCNAME"));
    do_import(keytab);

    kerberos_cleanup();
    return 0;
}
