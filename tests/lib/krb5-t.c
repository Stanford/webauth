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

   
int
main(void)
{
    int s;
    struct webauth_context *ctx;
    struct webauth_krb5 *kc;
    struct kerberos_config *config;
    char *server, *cp, *prealm, *cache, *tmpdir;
    void *sa, *tgt, *ticket, *tmp;
    size_t salen, tgtlen, ticketlen;
    time_t expiration;
    char *cprinc = NULL;
    char *crealm = NULL;
    char *ccache = NULL;

    /* Read the configuration information. */
    config = kerberos_setup(TAP_KRB_NEEDS_BOTH);
    
    plan(44);

    if (webauth_context_init(&ctx, NULL) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    s = webauth_krb5_new(ctx ,&kc);
    CHECK(ctx, s, "Creating a Kerberos context");
    ok(kc != NULL, "...and the context is not NULL");

    /* We can't get information before we initialize. */
    s = webauth_krb5_get_principal(ctx, kc, &cprinc, WA_KRB5_CANON_LOCAL);
    is_int(WA_ERR_INVALID_CONTEXT, s,
           "Getting the principal fails with the right error");
    s = webauth_krb5_get_realm(ctx, kc, &crealm);
    is_int(WA_ERR_INVALID_CONTEXT, s,
           "Getting the realm fails with the right error");
    s = webauth_krb5_get_cache(ctx, kc, &ccache);
    is_int(WA_ERR_INVALID_CONTEXT, s,
           "Getting the cache fails with the right error");

    /* Do the authentication with the username and password. */
    s = webauth_krb5_init_via_password(ctx, kc, config->userprinc,
                                       config->password, NULL,
                                       config->keytab, NULL, NULL, &server);
    CHECK(ctx, s, "Kerberos initialization from password");
    is_string(config->principal, server,
              "...and returns the correct server principal");

    /* Test principal canonicalization. */
    s = webauth_krb5_get_principal(ctx, kc, &cprinc, WA_KRB5_CANON_LOCAL);
    CHECK(ctx, s, "Local canonicalization");
    diag("Local canonicalized principal: %s", cprinc);
    s = webauth_krb5_get_principal(ctx, kc, &cprinc, WA_KRB5_CANON_NONE);
    CHECK(ctx, s, "No canonicalization");
    ok(strchr(cprinc, '@') != NULL, "...and resulting principal has a realm");
    s = webauth_krb5_get_realm(ctx, kc, &crealm);
    CHECK(ctx, s, "Getting the realm");
    prealm = strchr(cprinc, '@');
    if (prealm == NULL)
        ok_block(2, false, "canonicalized principal has no realm");
    else {
        is_string(prealm + 1, crealm, "...and it matches principal");
        is_string(config->realm, crealm, "...and the configuration");
    }
    s = webauth_krb5_get_principal(ctx, kc, &cprinc, WA_KRB5_CANON_STRIP);
    CHECK(ctx, s, "Strip canonicalization");
    ok(strchr(cprinc, '@') == NULL, "...and resulting principal has no realm");

    /* Test simple authenticators. */
    sa = NULL;
    s = webauth_krb5_make_auth(ctx, kc, server, &sa, &salen);
    CHECK(ctx, s, "Building an AP-REQ");
    s = webauth_krb5_read_auth(ctx, kc, sa, salen, config->keytab, NULL, &cp,
                               WA_KRB5_CANON_NONE);
    CHECK(ctx, s, "...and it then validates");
    is_string(config->userprinc, cp, "...and returns the correct identity");

    /* Test credential export. */
    tgt = NULL;
    expiration = 0;
    s = webauth_krb5_export_cred(ctx, kc, NULL, &tgt, &tgtlen, &expiration);
    CHECK(ctx, s, "Exporting a TGT");
    ok(expiration != 0, "...and expiration is set");
    expiration = 0;
    s = webauth_krb5_export_cred(ctx, kc, config->principal, &ticket,
                                 &ticketlen, &expiration);
    CHECK(ctx, s, "Exporting the service ticket");
    ok(expiration != 0, "...and expiration is set");

    /* Copy the exported tickets and free the Kerberos context. */
    if (tgt != NULL) {
        tmp = bmalloc(tgtlen);
        memcpy(tmp, tgt, tgtlen);
        tgt = tmp;
    }
    if (ticket != NULL) {
        tmp = bmalloc(ticketlen);
        memcpy(tmp, ticket, ticketlen);
        ticket = tmp;
    }
    webauth_krb5_free(ctx, kc);

    /* Test reimporting the exported credentials. */
    if (tgt == NULL)
        skip_block(5, "TGT creation failed");
    else {
        s = webauth_krb5_new(ctx, &kc);
        CHECK(ctx, s, "Creating a new context");
        s = webauth_krb5_import_cred(ctx, kc, tgt, tgtlen, NULL);
        CHECK(ctx, s, "Initializing with a credential");
        s = webauth_krb5_get_principal(ctx, kc, &cp, WA_KRB5_CANON_NONE);
        CHECK(ctx, s, "...and we can get the principal name");
        is_string(config->userprinc, cp, "...and it matches expectations");
        free(tgt);
        if (ticket == NULL)
            skip("Service ticket exporting failed");
        else {
            s = webauth_krb5_import_cred(ctx, kc, ticket, ticketlen, NULL);
            CHECK(ctx, s, "Importing a ticket");
        }
        webauth_krb5_free(ctx, kc);
    }

    /* Test importing just a regular ticket without a TGT. */
    if (ticket == NULL)
        skip_block(4, "Ticket exporting failed");
    else {
        s = webauth_krb5_new(ctx, &kc);
        CHECK(ctx, s, "Creating a new context");
        s = webauth_krb5_import_cred(ctx, kc, ticket, ticketlen, NULL);
        CHECK(ctx, s, "Initializing with a ticket");
        s = webauth_krb5_get_principal(ctx, kc, &cp, WA_KRB5_CANON_NONE);
        CHECK(ctx, s, "...and we can get the principal name");
        is_string(config->userprinc, cp, "...and it matches expectations");
        free(ticket);
        webauth_krb5_free(ctx, kc);
    }

    /* Test initialization from a keytab. */
    s = webauth_krb5_new(ctx, &kc);
    CHECK(ctx, s, "Creating a new context");
    s = webauth_krb5_init_via_keytab(ctx, kc, config->keytab, NULL, NULL);
    CHECK(ctx, s, "Initializing with a keytab");
    s = webauth_krb5_get_principal(ctx, kc, &cp, WA_KRB5_CANON_NONE);
    CHECK(ctx, s, "...and we can get the principal name");
    is_string(config->principal, cp, "...and it matches expectations");
    webauth_krb5_free(ctx, kc);
    s = webauth_krb5_new(ctx, &kc);
    CHECK(ctx, s, "Creating a new context");
    s = webauth_krb5_init_via_keytab(ctx, kc, config->keytab,
                                     config->principal, NULL);
    CHECK(ctx, s, "Initializing with a keytab and specific principal");
    s = webauth_krb5_get_principal(ctx, kc, &cp, WA_KRB5_CANON_NONE);
    CHECK(ctx, s, "...and we can get the principal name");
    is_string(config->principal, cp, "...and it matches expectations");
    webauth_krb5_free(ctx, kc);

    /* Test specifying an explicit cache file and getting it back. */
    s = webauth_krb5_new(ctx, &kc);
    CHECK(ctx, s, "Creating a new context");
    tmpdir = test_tmpdir();
    basprintf(&cache, "FILE:%s/tmp_krb5cc", tmpdir);
    s = webauth_krb5_init_via_keytab(ctx, kc, config->keytab, NULL, cache);
    CHECK(ctx, s, "Initializing with a keytab");
    s = webauth_krb5_get_cache(ctx, kc, &ccache);
    CHECK(ctx, s, "Retrieving the cache name");
    is_string(cache, ccache, "...and the name is correct");
    webauth_krb5_free(ctx, kc);
    ok(access(cache, F_OK) < 0, "...and the cache is destroyed on free");

    /* Clean up. */
    unlink(cache);
    free(cache);
    test_tmpdir_free(tmpdir);
    webauth_context_free(ctx);
    return 0;
}
