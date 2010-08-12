/*
 * Utility functions for tests that use Kerberos.
 *
 * Currently only provides kerberos_setup(), which assumes a particular set of
 * data files in either the SOURCE or BUILD directories and, using those,
 * obtains Kerberos credentials, sets up a ticket cache, and sets the
 * environment variable pointing to the Kerberos keytab to use for testing.
 *
 * Copyright 2006, 2007, 2009, 2010
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <tests/tap/basic.h>
#include <tests/tap/kerberos.h>
#include <util/concat.h>
#include <util/xmalloc.h>


/*
 * Obtain Kerberos tickets for the principal specified in test.principal using
 * the keytab specified in test.keytab, both of which are presumed to be in
 * tests/data in either the build or the source tree.
 *
 * Returns the contents of test.principal in newly allocated memory or NULL if
 * Kerberos tests are apparently not configured.  If Kerberos tests are
 * configured but something else fails, calls bail().
 *
 * The error handling here is not great.  We should have a bail_krb5 that uses
 * the same logic as messages-krb5.c, which hasn't yet been imported into
 * rra-c-util.
 */
char *
kerberos_setup(void)
{
    char *path, *krbtgt;
    const char *build, *realm;
    FILE *file;
    char principal[BUFSIZ];
    krb5_error_code code;
    krb5_context ctx;
    krb5_ccache ccache;
    krb5_principal kprinc;
    krb5_keytab keytab;
    krb5_get_init_creds_opt *opts;
    krb5_creds creds;

    /* Read the principal name and find the keytab file. */
    path = test_file_path("data/test.principal");
    if (path == NULL)
        return NULL;
    file = fopen(path, "r");
    if (file == NULL) {
        free(path);
        return NULL;
    }
    if (fgets(principal, sizeof(principal), file) == NULL) {
        fclose(file);
        bail("cannot read %s", path);
    }
    fclose(file);
    if (principal[strlen(principal) - 1] != '\n')
        bail("no newline in %s", path);
    free(path);
    principal[strlen(principal) - 1] = '\0';
    path = test_file_path("data/test.keytab");
    if (path == NULL)
        return NULL;

    /* Set the KRB5CCNAME and KRB5_KTNAME environment variables. */
    build = getenv("BUILD");
    if (build == NULL)
        build = ".";
    putenv(concat("KRB5CCNAME=", build, "/data/test.cache", (char *) 0));
    putenv(concat("KRB5_KTNAME=", path, (char *) 0));

    /* Now do the Kerberos initialization. */
    code = krb5_init_context(&ctx);
    if (code != 0)
        bail("error initializing Kerberos");
    code = krb5_cc_default(ctx, &ccache);
    if (code != 0)
        bail("error setting ticket cache");
    code = krb5_parse_name(ctx, principal, &kprinc);
    if (code != 0)
        bail("error parsing principal %s", principal);
    realm = krb5_principal_get_realm(ctx, kprinc);
    krbtgt = concat("krbtgt/", realm, "@", realm, (char *) 0);
    code = krb5_kt_resolve(ctx, path, &keytab);
    if (code != 0)
        bail("cannot open keytab %s", path);
    code = krb5_get_init_creds_opt_alloc(ctx, &opts);
    if (code != 0)
        bail("cannot allocate credential options");
    krb5_get_init_creds_opt_set_default_flags(ctx, NULL, realm, opts);
    krb5_get_init_creds_opt_set_forwardable(opts, 0);
    krb5_get_init_creds_opt_set_proxiable(opts, 0);
    code = krb5_get_init_creds_keytab(ctx, &creds, kprinc, keytab, 0, krbtgt,
                                      opts);
    if (code != 0)
        bail("cannot get Kerberos tickets");
    code = krb5_cc_initialize(ctx, ccache, kprinc);
    if (code != 0)
        bail("error initializing ticket cache");
    code = krb5_cc_store_cred(ctx, ccache, &creds);
    if (code != 0)
        bail("error storing credentials");
    krb5_cc_close(ctx, ccache);
    krb5_free_cred_contents(ctx, &creds);
    krb5_kt_close(ctx, keytab);
    krb5_free_principal(ctx, kprinc);
    krb5_free_context(ctx);
    free(krbtgt);
    free(path);

    return xstrdup(principal);
}


/*
 * Clean up at the end of a test.  Currently, all this does is remove the
 * ticket cache.
 */
void
kerberos_cleanup(void)
{
    char *path;

    path = concatpath(getenv("BUILD"), "data/test.cache");
    unlink(path);
    free(path);
}
