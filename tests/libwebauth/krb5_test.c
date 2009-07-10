/*
 * Test suite for libwebauth Kerberos functions.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2003, 2006, 2008, 2009
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lib/webauth.h>
#include "webauthtest.h"

#define BUFSIZE 4096
#define MAX_ATTRS 128

void
usage()
{
  printf("usage: krb5_test {username} {password} {keytab} {service} {host}\n");
  printf("  keytab         name of keytab file used to verify tgt\n");
  printf("  service/host   name of service/host to test export_ticket with\n");
  exit(1);
}

int main(int argc, char *argv[])
{
    int s;
    WEBAUTH_KRB5_CTXT *c;
    TEST_VARS;
    char *username, *password, *keytab_path, *server, *server_principal;
    char *service, *host;
    char *cp;
    char *sa;
    int salen;
    char *tgt, *ticket;
    int tgtlen, ticketlen;
    time_t expiration;
    char *cprinc, *crealm;

    if (argc != 6) {
        usage();
    }

    username = argv[1];
    password = argv[2];
    keytab_path = argv[3];
    service = argv[4];
    host = argv[5];

    cprinc = NULL;
    crealm = NULL;

    START_TESTS(32);

    s = webauth_krb5_new(&c);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK(c != NULL);

    /* test failure case */
    s = webauth_krb5_get_principal(c, &cprinc, 1);
    TEST_OK2(WA_ERR_INVALID_CONTEXT, s);
    s = webauth_krb5_get_realm(c, &crealm);
    TEST_OK2(WA_ERR_INVALID_CONTEXT, s);

    s = webauth_krb5_init_via_password(c, username, password, 
                                       keytab_path, NULL,
                                       NULL, &server_principal);

    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK(server_principal != NULL);

    s = webauth_krb5_get_principal(c, &cprinc, WA_KRB5_CANON_LOCAL);
    /*printf("cprinc = %s\n", cprinc);*/
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK(strchr(cprinc, '@') == NULL);
    free(cprinc);
    s = webauth_krb5_get_principal(c, &cprinc, WA_KRB5_CANON_NONE);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK(strchr(cprinc, '@') != NULL);
    free(cprinc);
    s = webauth_krb5_get_principal(c, &cprinc, WA_KRB5_CANON_STRIP);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK(strchr(cprinc, '@') == NULL);

    s = webauth_krb5_get_realm(c, &crealm);
    /*printf("crealm = %s\n", crealm);*/
    TEST_OK2(WA_ERR_NONE, s);

    /*
    printf("code(%d) mess(%s)\n", 
           webauth_krb5_error_code(c),
           webauth_krb5_error_message(c));
    */

    sa = NULL;

    s = webauth_krb5_mk_req(c, server_principal, &sa, &salen);
    free(server_principal);

    TEST_OK2(WA_ERR_NONE, s);

    s = webauth_krb5_rd_req(c, sa, salen, keytab_path, NULL, &cp, 1);
    /*printf("cp = %s\n", cp);*/
    TEST_OK2(WA_ERR_NONE, s);
    if (cp) {
        free(cp);
    }

    if (sa != NULL) {
        free(sa);
    }

    tgt = NULL;
    s = webauth_krb5_export_tgt(c, &tgt, &tgtlen, &expiration);
    TEST_OK2(WA_ERR_NONE, s);

    s = webauth_krb5_service_principal(c, service, host, &server);
    TEST_OK2(WA_ERR_NONE, s);

    s = webauth_krb5_export_ticket(c, server,
                                   &ticket, &ticketlen, &expiration);
    free(server);

    TEST_OK2(WA_ERR_NONE, s);

    s = webauth_krb5_free(c);
    TEST_OK2(WA_ERR_NONE, s);

    if (tgt != NULL) {
        s = webauth_krb5_new(&c);
        TEST_OK2(WA_ERR_NONE, s);
        TEST_OK(c != NULL);
            
        s = webauth_krb5_init_via_cred(c, tgt, tgtlen, NULL);
        free(tgt);
        TEST_OK2(WA_ERR_NONE, s);

        if (ticket != NULL) {
            s = webauth_krb5_import_cred(c, ticket, ticketlen);
            /*free(ticket);*/
            TEST_OK2(WA_ERR_NONE, s);
        }

        s = webauth_krb5_free(c);
        TEST_OK2(WA_ERR_NONE, s);
    }

    if (tgt != NULL) {
        s = webauth_krb5_new(&c);
        TEST_OK2(WA_ERR_NONE, s);
        TEST_OK(c != NULL);

        s = webauth_krb5_init_via_cred(c, ticket, ticketlen, NULL);
        free(ticket);
        TEST_OK2(WA_ERR_NONE, s);

        /*s = webauth_krb5_keep_cred_cache(c);*/

        s = webauth_krb5_free(c);
        TEST_OK2(WA_ERR_NONE, s);
    }

    s = webauth_krb5_new(&c);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK(c != NULL);
            
    s = webauth_krb5_init_via_keytab(c, keytab_path, NULL, NULL);
    TEST_OK2(WA_ERR_NONE, s);

    s = webauth_krb5_free(c);
    TEST_OK2(WA_ERR_NONE, s);

    if (cprinc != NULL)
        free(cprinc);

    END_TESTS;
    exit(NUM_FAILED_TESTS ? 1 : 0);
}
