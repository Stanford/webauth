/*
 * Test Kerberos password change over remctl.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <tests/tap/basic.h>
#include <tests/tap/kerberos.h>
#include <tests/tap/remctl.h>
#include <tests/tap/string.h>
#include <webauth/basic.h>
#include <webauth/krb5.h>

#define CHECK(ctx, s, m) check_status((ctx), (s), (m), __FILE__, __LINE__)


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


int
main(void)
{
    struct kerberos_config *krbconf;
    struct webauth_context *ctx;
    struct webauth_krb5 *kc;
    struct webauth_krb5_change_config config;
    char buffer[BUFSIZ];
    char *tmpdir, *path;
    FILE *output = NULL;
    int s;

    /* Skip this test if built without remctl support. */
#ifndef HAVE_REMCTL
    skip_all("built without remctl support");
#endif

    /* Load test configuration and start remctl. */
    krbconf = kerberos_setup(TAP_KRB_NEEDS_KEYTAB);
    remctld_start(krbconf, "data/conf-webkdc", (char *) 0);
    if (webauth_context_init(&ctx, NULL) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    /* Output our plan. */
    plan(11);

    /* Create a Kerberos context and get credentials for our principal. */
    s = webauth_krb5_new(ctx ,&kc);
    CHECK(ctx, s, "Creating a Kerberos context");
    if (kc == NULL)
        bail("Kerberos context creation failed");
    s = webauth_krb5_init_via_keytab(ctx, kc, krbconf->keytab, NULL, NULL);
    CHECK(ctx, s, "Initializing with a keytab");

    /* Configure the password change parameters.  First check kpasswd. */
    memset(&config, 0, sizeof(config));
    config.protocol   = WA_CHANGE_KPASSWD;
    s = webauth_krb5_change_config(ctx, kc, &config);
    CHECK(ctx, s, "Password change configuration for kpasswd");

    /* Check missing or invalid parameter errors. */
    config.protocol = 42;
    s = webauth_krb5_change_config(ctx, kc, &config);
    is_int(WA_ERR_UNIMPLEMENTED, s, "Unknown password change protocol");
    config.protocol = WA_CHANGE_REMCTL;
    s = webauth_krb5_change_config(ctx, kc, &config);
    is_int(WA_ERR_INVALID, s, "No host in change configuration");
    config.host = "127.0.0.1";
    s = webauth_krb5_change_config(ctx, kc, &config);
    is_int(WA_ERR_INVALID, s, "No command in change configuration");
    config.command = "kadmin";
    s = webauth_krb5_change_config(ctx, kc, &config);
    is_int(WA_ERR_INVALID, s, "No subcommand in change configuration");

    /* Set the real parameters for testing. */
    config.host       = "127.0.0.1";
    config.port       = 14373;
    config.identity   = krbconf->principal;
    config.command    = "kadmin";
    config.subcommand = "password";
    s = webauth_krb5_change_config(ctx, kc, &config);
    CHECK(ctx, s, "Correct password change configuration");

    /* Send the new password. */
    s = webauth_krb5_change_password(ctx, kc, "new password");
    CHECK(ctx, s, "Password change");

    /* Read the results in and verify them. */
    tmpdir = test_tmpdir();
    basprintf(&path, "%s/password-input", tmpdir);
    output = fopen(path, "r");
    if (output == NULL)
        ok_block(2, false, "No output from remctl command");
    else {
        if (fgets(buffer, sizeof(buffer), output) == NULL)
            ok(false, "Correct user identity");
        else {
            buffer[strlen(buffer) - 1] = '\0';
            is_string(krbconf->principal, buffer, "Correct user identity");
        }
        if (fgets(buffer, sizeof(buffer), output) == NULL)
            ok(false, "Correct password");
        else
            is_string("new password", buffer, "Correct password");
        fclose(output);
        unlink(path);
    }
    free(path);
    test_tmpdir_free(tmpdir);

    /* Clean up. */
    webauth_context_free(ctx);
    return 0;
}
