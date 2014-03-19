/*
 * Test suite for libwebauth Kerberos functions.
 *
 * Written by Roland Schemers
 * Updated for current TAP library support by Russ Allbery
 * Copyright 2002, 2003, 2006, 2008, 2009, 2010, 2012, 2013, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <time.h>

#include <tests/tap/basic.h>
#include <tests/tap/kerberos.h>
#include <tests/tap/string.h>
#include <webauth/basic.h>
#include <webauth/krb5.h>

/*
 * An address list for testing.  The data structure is completely different
 * between MIT and Heimdal.
 */
static const unsigned char test_addr_data[4] = { 192, 0, 2, 10 };
#ifdef HAVE_KRB5_MIT
static const krb5_address test_addr = {
    KV5M_ADDRESS, ADDRTYPE_INET, 4, (unsigned char *) test_addr_data
};
static const krb5_address *const test_addrlist[2] = { &test_addr, NULL };
static krb5_address **const test_addrlist_ptr
    = (krb5_address **) test_addrlist;
#else
static const krb5_address test_addr = {
    KRB5_ADDRESS_INET, { 4, (void *) test_addr_data }
};
static const krb5_addresses test_addrlist = { 1, (krb5_address *) &test_addr };
static krb5_addresses *const test_addrlist_ptr
    = (krb5_addresses *) &test_addrlist;
#endif

#define CHECK(ctx, s, m) check_status((ctx), (s), (m), __FILE__, __LINE__)
#define CHECK_CHANGE(ctx, s, m) \
    check_change((ctx), (s), (m), __FILE__, __LINE__)


/*
 * Check that a WebAuth call succeeded.  If it didn't, display the error
 * message with diag in addition to reporting a failure.  Normally called via
 * the CHECK() macro.
 */
static void
check_status(struct webauth_context *ctx, int s, const char *message,
             const char *file, unsigned long line)
{
    if (s != WA_ERR_NONE)
        diag("webauth call failed %s line %lu: %s (%d)\n", file, line,
             webauth_error_message(ctx, s), s);
    is_int(s, WA_ERR_NONE, "%s", message);
}


/*
 * Check the result of a password change.
 *
 * Unfortunately, the result reporting from the Kerberos password change
 * protocol does not work properly through NAT (although the password is
 * changed), so these password changes may fail with "Incorrect net address"
 * errors.  Detect that case and report it as a skip.
 */
static void
check_change(struct webauth_context *ctx, int s, const char *message,
             const char *file, unsigned long line)
{
    const char *error;

    if (s != WA_ERR_KRB5) {
        check_status(ctx, s, message, file, line);
        return;
    }
    error = webauth_error_message(ctx, s);
    if (strstr(error, "Incorrect net address") != NULL)
        skip("password change status bogus behind NAT");
    else
        check_status(ctx, s, message, file, line);
}


/*
 * Obtain Kerberos credentials from the configured keytab, but set addresses
 * on the ticket.  This tests encoding of tickets with addresses (which has
 * had bugs in the past).  Returns the path to a new Kerberos cache or NULL if
 * we can't get tickets because the KDC won't let us.
 */
static char *
kinit_with_addresses(struct kerberos_config *config)
{
    char *tmpdir, *krbtgt, *cache;
    krb5_error_code code;
    krb5_context ctx;
    krb5_ccache ccache;
    krb5_principal kprinc;
    krb5_keytab keytab;
    krb5_get_init_creds_opt *opts;
    krb5_creds creds;
    const char *realm;

    /* Determine the path to the temporary cache we'll use. */
    tmpdir = test_tmpdir();
    basprintf(&cache, "%s/krb5cc_addresses", tmpdir);

    /* Create a Kerberos context. */
    code = krb5_init_context(&ctx);
    if (code != 0)
        bail_krb5(ctx, code, "error initializing Kerberos");

    /* Determine the principal names we'll use. */
    code = krb5_parse_name(ctx, config->principal, &kprinc);
    if (code != 0)
        bail_krb5(ctx, code, "error parsing principal %s", config->principal);
    realm = krb5_principal_get_realm(ctx, kprinc);
    basprintf(&krbtgt, "krbtgt/%s@%s", realm, realm);

    /* Configure the credential options, enabling addresses. */
    code = krb5_get_init_creds_opt_alloc(ctx, &opts);
    if (code != 0)
        bail_krb5(ctx, code, "cannot allocate credential options");
    krb5_get_init_creds_opt_set_default_flags(ctx, NULL, realm, opts);
    krb5_get_init_creds_opt_set_address_list(opts, test_addrlist_ptr);
    krb5_get_init_creds_opt_set_forwardable(opts, 0);
    krb5_get_init_creds_opt_set_proxiable(opts, 0);

    /* Obtain the credentials. */
    code = krb5_kt_resolve(ctx, config->keytab, &keytab);
    if (code != 0)
        bail_krb5(ctx, code, "cannot open keytab %s", config->keytab);
    code = krb5_get_init_creds_keytab(ctx, &creds, kprinc, keytab, 0, krbtgt,
                                      opts);

    /*
     * If the return status is KRB5KRB_AP_ERR_BADADDR, the KDC is enforcing a
     * requirement that we only get our own ticket addresses, so we can't run
     * this check.
     */
    if (code == KRB5KRB_AP_ERR_BADADDR)
        return NULL;
    else if (code != 0)
        bail_krb5(ctx, code, "cannot get Kerberos tickets");

    /* Store them in the ticket cache. */
    code = krb5_cc_resolve(ctx, cache, &ccache);
    if (code != 0)
        bail_krb5(ctx, code, "error setting ticket cache");
    code = krb5_cc_initialize(ctx, ccache, kprinc);
    if (code != 0)
        bail_krb5(ctx, code, "error initializing ticket cache");
    code = krb5_cc_store_cred(ctx, ccache, &creds);
    if (code != 0)
        bail_krb5(ctx, code, "error storing credentials");
    krb5_cc_close(ctx, ccache);
    krb5_free_cred_contents(ctx, &creds);
    krb5_kt_close(ctx, keytab);
    krb5_get_init_creds_opt_free(ctx, opts);
    krb5_free_principal(ctx, kprinc);
    krb5_free_context(ctx);
    free(krbtgt);
    test_tmpdir_free(tmpdir);
    return cache;
}

   
int
main(void)
{
    int s;
    struct webauth_context *ctx;
    struct webauth_krb5 *kc;
    struct kerberos_config *config;
    char *server, *cp, *prealm, *cache, *tmpdir, *password;
    void *sa, *tgt, *ticket, *tmp;
    size_t salen, tgtlen, ticketlen;
    time_t expiration;
    char *cprinc = NULL;
    char *crealm = NULL;
    char *ccache = NULL;

    /* Read the configuration information. */
    config = kerberos_setup(TAP_KRB_NEEDS_BOTH);
    
    plan(53);

    if (webauth_context_init(&ctx, NULL) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    s = webauth_krb5_new(ctx ,&kc);
    CHECK(ctx, s, "Creating a Kerberos context");
    ok(kc != NULL, "...and the context is not NULL");
    if (kc == NULL)
        bail("Cannot continue without a Kerberos context");

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

    /* Test getting a ticket with addresses and then exporting it. */
    cache = kinit_with_addresses(config);
    if (cache == NULL)
        skip_block(4, "Cannot get tickets with a specific address");
    else {
        s = webauth_krb5_new(ctx, &kc);
        CHECK(ctx, s, "Creating a new context");
        s = webauth_krb5_init_via_cache(ctx, kc, cache);
        CHECK(ctx, s, "Initializing from a cache of address-locked tickets");
        tgt = NULL;
        s = webauth_krb5_export_cred(ctx, kc, NULL, &tgt, &tgtlen, NULL);
        CHECK(ctx, s, "Exporting a TGT");
        ok(tgt != NULL, "...and the TGT is not NULL");
        free(cache);
        webauth_krb5_free(ctx, kc);
    }

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

    /*
     * Test password change.
     *
     * Unfortunately, the Kerberos password change protocol does not work
     * properly through NAT, so these password changes may fail with
     * "Incorrect net address" errors.  Detect that case and skip the tests.
     */
    s = webauth_krb5_new(ctx, &kc);
    CHECK(ctx, s, "Creating a new context");
    s = webauth_krb5_init_via_password(ctx, kc, config->userprinc,
                                       config->password, "kadmin/changepw",
                                       NULL, NULL, NULL, NULL);
    CHECK(ctx, s, "kadmin/changepw initialization from password");
    basprintf(&password, "%s_tmp%lu", config->password,
              (unsigned long) time(NULL));
    s = webauth_krb5_change_password(ctx, kc, password);
    CHECK_CHANGE(ctx, s, "Password change");
    s = webauth_krb5_init_via_password(ctx, kc, config->userprinc,
                                       password, "kadmin/changepw",
                                       NULL, NULL, NULL, NULL);
    CHECK(ctx, s, "kadmin/changepw initialization from new password");
    s = webauth_krb5_change_password(ctx, kc, config->password);
    CHECK_CHANGE(ctx, s, "Change password back");

    /* Clean up. */
    unlink(cache);
    free(cache);
    test_tmpdir_free(tmpdir);
    webauth_context_free(ctx);
    return 0;
}
