/*
 * Test suite for libwebauth Kerberos TGT manipulation.
 *
 * Written by Roland Schemers
 * Copyright 2003, 2006, 2009
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include "config.h"

#include <stdio.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <lib/webauth.h>
#include "webauthtest.h"

#define BUFSIZE 4096
#define MAX_ATTRS 128

void
usage(char *prog)
{
  printf("usage: %s {command}\n", prog);
  printf("  export {principal} [cache]    export tgt to specified princpal\n");
  printf("  import {keytab} {cache} {req} {tgt}   import an exported tgt\n");
  exit(1);
}

void check_status(int s, WEBAUTH_KRB5_CTXT *c, char *file, int line)
{
    if (s == WA_ERR_NONE)
        return;


    if (s == WA_ERR_KRB5 && c != NULL) {
        fprintf(stderr, 
                "webauth call failed %s line %d: %s (%d): %s %d\n",
                file, line,
                webauth_error_message(s), s,
                webauth_krb5_error_message(c),
                webauth_krb5_error_code(c));
    } else {
        fprintf(stderr, 
                "webauth call failed %s line %d: %s (%d)\n",
                file, line,
                webauth_error_message(s), s);
    }
    exit(1);
}

#define CHECK(s, c) check_status(s, c, __FILE__, __LINE__)
   
void do_export(char *principal, char *cache)
{
    int s;
    WEBAUTH_KRB5_CTXT *c;
    char *tgt, *req, *etgt;
    int tgt_len, req_len, etgt_len;
    time_t expiration;
    char b64[4192];
    int b64_len;

    s = webauth_krb5_new(&c);
    CHECK(s,c);
    s = webauth_krb5_init_via_cache(c, cache);
    CHECK(s,c);
    s = webauth_krb5_keep_cred_cache(c);
    CHECK(s,c);
    s = webauth_krb5_export_tgt(c, &tgt, &tgt_len, &expiration);
    CHECK(s,c);
    s = webauth_krb5_mk_req_with_data(c, principal,
                                      &req, &req_len,
                                      tgt, tgt_len,
                                      &etgt, &etgt_len);
    CHECK(s,c);

    s = webauth_base64_encode(req, req_len, b64, &b64_len, sizeof(b64)-1);
    CHECK(s,c);
    b64[b64_len] = '\0';
    printf("REQ(%d) = %s\n", b64_len, b64);

    s = webauth_base64_encode(etgt, etgt_len, b64, &b64_len, sizeof(b64)-1);
    CHECK(s,c);
    b64[b64_len] = '\0';
    printf("ETGT(%d) = %s\n", b64_len, b64);

    free(tgt);
    free(req);
    free(etgt);
    s = webauth_krb5_free(c);
    CHECK(s,c);
}

void do_import(char *keytab, char *cache, char *req, char *tgt)
{
    int s;
    WEBAUTH_KRB5_CTXT *c;
    int req_len, tgt_len, dec_tgt_len;
    char *dec_tgt;
    char *cprinc;
    char *sprinc;

    s = webauth_base64_decode(req, strlen(req), req, &req_len, strlen(req));
    CHECK(s, NULL);

    s = webauth_base64_decode(tgt, strlen(tgt), tgt, &tgt_len, strlen(tgt));
    CHECK(s, NULL);

    s = webauth_krb5_new(&c);
    CHECK(s,c);
    s = webauth_krb5_rd_req_with_data(c, req, req_len, keytab, NULL, &sprinc,
                                      &cprinc, 1, tgt, tgt_len, &dec_tgt,
                                      &dec_tgt_len);
    CHECK(s,c);
    printf("cprinc = %s\n", cprinc);
    printf("cprinc = %s\n", sprinc);
    free(cprinc);
    free(sprinc);

    s = webauth_krb5_init_via_cred(c, 
                                   dec_tgt, 
                                   dec_tgt_len,
                                   (cache != NULL && *cache) ? cache : NULL);
    CHECK(s,c);
    s = webauth_krb5_keep_cred_cache(c);
    CHECK(s,c);
    s = webauth_krb5_free(c);
    CHECK(s,NULL);
}


int 
main(int argc, char *argv[])
{
    if (argc < 3 || argc > 6)
        usage(argv[0]);

    if ((strcmp(argv[1], "export") == 0) && (argc == 3 || argc == 4))
        do_export(argv[2], argv[3]);
    else if ((strcmp(argv[1], "import") == 0) && argc == 6)
        do_import(argv[2], argv[3], argv[4], argv[5]);
    else 
        usage(argv[0]);
    exit(0);
}
