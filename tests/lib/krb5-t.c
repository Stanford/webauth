/*
 * Test suite for libwebauth Kerberos functions.
 *
 * Written by Roland Schemers
 * Updated for current TAP library support by Russ Allbery
 * Copyright 2002, 2003, 2006, 2008, 2009, 2010
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <tests/tap/basic.h>
#include <webauth.h>
#include <webauth/basic.h>

#define BUFSIZE 4096
#define MAX_ATTRS 128


int
main(void)
{
    int s;
    WEBAUTH_KRB5_CTXT *c;
    char username[BUFSIZ], password[BUFSIZ], principal[BUFSIZ];
    char *server_principal, *keytab, *path;
    char *cp;
    char *sa;
    size_t salen;
    char *tgt, *ticket, *prealm;
    size_t tgtlen, ticketlen;
    time_t expiration;
    char *cprinc = NULL;
    char *crealm = NULL;
    FILE *file;

    /* Read the configuration information. */
    path = test_file_path("data/test.principal");
    if (path == NULL)
        skip_all("Kerberos tests not configured");
    keytab = test_file_path("data/test.keytab");
    if (keytab == NULL)
        skip_all("Kerberos tests not configured");
    file = fopen(path, "r");
    if (file == NULL)
        sysbail("cannot open %s", path);
    if (fgets(principal, sizeof(principal), file) == NULL) {
        fclose(file);
        bail("cannot read %s", path);
    }
    fclose(file);
    if (principal[strlen(principal) - 1] != '\n')
        bail("no newline in %s", path);
    test_file_path_free(path);
    principal[strlen(principal) - 1] = '\0';
    path = test_file_path("data/test.password");
    if (path == NULL)
        skip_all("Kerberos tests not configured");
    file = fopen(path, "r");
    if (file == NULL)
        sysbail("cannot open %s", path);
    if (fgets(username, sizeof(username), file) == NULL)
        bail("cannot read %s", path);
    if (fgets(password, sizeof(password), file) == NULL)
        bail("cannot read password from %s", path);
    fclose(file);
    if (username[strlen(username) - 1] != '\n')
        bail("no newline in %s", path);
    username[strlen(username) - 1] = '\0';
    if (password[strlen(password) - 1] != '\n')
        bail("username or password too long in %s", path);
    password[strlen(password) - 1] = '\0';
    test_file_path_free(path);
    
    plan(31);

    s = webauth_krb5_new(&c);
    is_int(WA_ERR_NONE, s, "Creating a context succeeds");
    ok(c != NULL, "...and the context is not NULL");

    /* We can't get information before we initialize. */
    s = webauth_krb5_get_principal(c, &cprinc, 1);
    is_int(WA_ERR_INVALID_CONTEXT, s,
           "Getting the principal fails with the right error");
    s = webauth_krb5_get_realm(c, &crealm);
    is_int(WA_ERR_INVALID_CONTEXT, s,
           "Getting the realm fails with the right error");

    /* Do the authentication with the username and password. */
    s = webauth_krb5_init_via_password(c, username, password, NULL, keytab,
                                       NULL, NULL, &server_principal);
    is_int(WA_ERR_NONE, s, "Kerberos initialization succeeds");
    ok(server_principal != NULL, "...and returns the server principal");

    /* Test principal canonicalization. */
    s = webauth_krb5_get_principal(c, &cprinc, WA_KRB5_CANON_LOCAL);
    is_int(WA_ERR_NONE, s, "Local canonicalization");
    free(cprinc);
    s = webauth_krb5_get_principal(c, &cprinc, WA_KRB5_CANON_NONE);
    is_int(WA_ERR_NONE, s, "No canonicalization");
    ok(strchr(cprinc, '@') != NULL, "...and resulting principal has a realm");
    s = webauth_krb5_get_realm(c, &crealm);
    is_int(WA_ERR_NONE, s, "Getting the realm");
    prealm = strchr(cprinc, '@');
    if (prealm == NULL)
        skip("canonicalized principal has no realm");
    else
        is_string(prealm + 1, crealm, "...and it matches principal");
    free(cprinc);
    free(crealm);
    s = webauth_krb5_get_principal(c, &cprinc, WA_KRB5_CANON_STRIP);
    is_int(WA_ERR_NONE, s, "Strip canonicalization");
    ok(strchr(cprinc, '@') == NULL, "...and resulting principal has no realm");

    sa = NULL;
    s = webauth_krb5_mk_req(c, server_principal, &sa, &salen);
    is_int(WA_ERR_NONE, s, "Building an AP-REQ");
    free(server_principal);
    s = webauth_krb5_rd_req(c, sa, salen, keytab, NULL, &cp, 1);
    is_int(WA_ERR_NONE, s, "...and it then validates");
    if (cp != NULL)
        free(cp);
    if (sa != NULL)
        free(sa);

    tgt = NULL;
    s = webauth_krb5_export_tgt(c, &tgt, &tgtlen, &expiration);
    is_int(WA_ERR_NONE, s, "Exporting a TGT");
    s = webauth_krb5_export_ticket(c, principal, &ticket, &ticketlen,
                                   &expiration);
    is_int(WA_ERR_NONE, s, "Exporting the service ticket");

    s = webauth_krb5_free(c);
    is_int(WA_ERR_NONE, s, "Freeing the context");

    if (tgt == NULL)
        skip_block(4, "TGT creation failed");
    else {
        s = webauth_krb5_new(&c);
        is_int(WA_ERR_NONE, s, "Creating a new context");
        ok(c != NULL, "...and the context is not NULL");
        s = webauth_krb5_init_via_cred(c, tgt, tgtlen, NULL);
        is_int(WA_ERR_NONE, s, "Initializing with a credential");
        free(tgt);
        if (ticket == NULL)
            skip("Service ticket exporting failed");
        else {
            s = webauth_krb5_import_cred(c, ticket, ticketlen);
            is_int(WA_ERR_NONE, s, "Importing a ticket");
        }
        s = webauth_krb5_free(c);
        is_int(WA_ERR_NONE, s, "Freeing the context");
    }

    if (ticket == NULL)
        skip_block(4, "Ticket exporting failed");
    else {
        s = webauth_krb5_new(&c);
        is_int(WA_ERR_NONE, s, "Creating a new context");
        ok(c != NULL, "...and the context is not NULL");
        s = webauth_krb5_init_via_cred(c, ticket, ticketlen, NULL);
        is_int(WA_ERR_NONE, s, "Initializing with a ticket");
        free(ticket);
        s = webauth_krb5_free(c);
        is_int(WA_ERR_NONE, s, "Freeing the context");
    }

    s = webauth_krb5_new(&c);
    is_int(WA_ERR_NONE, s, "Creating a new context");
    ok(c != NULL, "...and the context is not NULL");
    s = webauth_krb5_init_via_keytab(c, keytab, NULL, NULL);
    is_int(WA_ERR_NONE, s, "Initializing with a keytab");
    s = webauth_krb5_free(c);
    is_int(WA_ERR_NONE, s, "Freeing the context");

    if (cprinc != NULL)
        free(cprinc);

    return 0;
}
