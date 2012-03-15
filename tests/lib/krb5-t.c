/*
 * Test suite for libwebauth Kerberos functions.
 *
 * Written by Roland Schemers
 * Updated for current TAP library support by Russ Allbery
 * Copyright 2002, 2003, 2006, 2008, 2009, 2010, 2012
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


int
main(void)
{
    int s;
    WEBAUTH_KRB5_CTXT *c;
    struct kerberos_config *config;
    char *server_principal, *cp, *sa, *tgt, *ticket, *prealm, *cache, *tmpdir;
    size_t salen, tgtlen, ticketlen;
    time_t expiration;
    char *cprinc = NULL;
    char *crealm = NULL;
    char *ccache = NULL;

    /* Read the configuration information. */
    config = kerberos_setup(TAP_KRB_NEEDS_BOTH);
    
    plan(39);

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
    s = webauth_krb5_get_cache(c, &ccache);
    is_int(WA_ERR_INVALID_CONTEXT, s,
           "Getting the cache fails with the right error");

    /* Do the authentication with the username and password. */
    s = webauth_krb5_init_via_password(c, config->userprinc, config->password,
                                       NULL, config->keytab, NULL, NULL,
                                       &server_principal);
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
        skip_block(2, "canonicalized principal has no realm");
    else {
        is_string(prealm + 1, crealm, "...and it matches principal");
        is_string(config->realm, crealm, "...and the configuration");
    }
    free(cprinc);
    free(crealm);
    s = webauth_krb5_get_principal(c, &cprinc, WA_KRB5_CANON_STRIP);
    is_int(WA_ERR_NONE, s, "Strip canonicalization");
    ok(strchr(cprinc, '@') == NULL, "...and resulting principal has no realm");

    sa = NULL;
    s = webauth_krb5_mk_req(c, server_principal, &sa, &salen);
    is_int(WA_ERR_NONE, s, "Building an AP-REQ");
    free(server_principal);
    s = webauth_krb5_rd_req(c, sa, salen, config->keytab, NULL, &cp, 1);
    is_int(WA_ERR_NONE, s, "...and it then validates");
    if (cp != NULL)
        free(cp);
    if (sa != NULL)
        free(sa);

    tgt = NULL;
    s = webauth_krb5_export_tgt(c, &tgt, &tgtlen, &expiration);
    is_int(WA_ERR_NONE, s, "Exporting a TGT");
    s = webauth_krb5_export_ticket(c, config->principal, &ticket, &ticketlen,
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
    s = webauth_krb5_init_via_keytab(c, config->keytab, NULL, NULL);
    is_int(WA_ERR_NONE, s, "Initializing with a keytab");
    s = webauth_krb5_free(c);
    is_int(WA_ERR_NONE, s, "Freeing the context");

    /* Test specifying an explicit cache file and getting it back. */
    s = webauth_krb5_new(&c);
    is_int(WA_ERR_NONE, s, "Creating a new context");
    ok(c != NULL, "...and the context is not NULL");
    tmpdir = test_tmpdir();
    basprintf(&cache, "FILE:%s/tmp_krb5cc", tmpdir);
    s = webauth_krb5_init_via_keytab(c, config->keytab, NULL, cache);
    is_int(WA_ERR_NONE, s, "Initializing with a keytab");
    s = webauth_krb5_get_cache(c, &ccache);
    is_int(WA_ERR_NONE, s, "Retrieving the cache name");
    is_string(cache, ccache, "...and the name is correct");
    free(ccache);
    s = webauth_krb5_free(c);
    is_int(WA_ERR_NONE, s, "Freeing the context");
    unlink(cache);
    free(cache);
    test_tmpdir_free(tmpdir);

    if (cprinc != NULL)
        free(cprinc);

    return 0;
}
