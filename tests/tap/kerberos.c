/*
 * Utility functions for tests that use Kerberos.
 *
 * Currently only provides kerberos_setup(), which assumes a particular set of
 * data files in either the SOURCE or BUILD directories and, using those,
 * obtains Kerberos credentials, sets up a ticket cache, and sets the
 * environment variable pointing to the Kerberos keytab to use for testing.
 *
 * The canonical version of this file is maintained in the rra-c-util package,
 * which can be found at <http://www.eyrie.org/~eagle/software/rra-c-util/>.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2006, 2007, 2009, 2010, 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <tests/tap/basic.h>
#include <tests/tap/kerberos.h>
#include <util/concat.h>
#include <util/xmalloc.h>


/*
 * These variables hold the allocated strings for the principal and the
 * environment to point to a different Kerberos ticket cache and keytab.  We
 * store them so that we can free them on exit for cleaner valgrind output,
 * making it easier to find real memory leaks in the tested programs.
 */
static char *principal = NULL;
static char *krb5ccname = NULL;
static char *krb5_ktname = NULL;


/*
 * Clean up at the end of a test.  This removes the ticket cache and resets
 * and frees the memory allocated for the environment variables so that
 * valgrind output on test suites is cleaner.
 */
void
kerberos_cleanup(void)
{
    char *path;

    path = concatpath(getenv("BUILD"), "data/test.cache");
    unlink(path);
    free(path);
    if (principal != NULL) {
        free(principal);
        principal = NULL;
    }
    putenv((char *) "KRB5CCNAME=");
    putenv((char *) "KRB5_KTNAME=");
    if (krb5ccname != NULL) {
        free(krb5ccname);
        krb5ccname = NULL;
    }
    if (krb5_ktname != NULL) {
        free(krb5_ktname);
        krb5_ktname = NULL;
    }
}


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
const char *
kerberos_setup(void)
{
    char *path, *krbtgt;
    const char *build, *realm;
    FILE *file;
    char buffer[BUFSIZ];
    krb5_error_code code;
    krb5_context ctx;
    krb5_ccache ccache;
    krb5_principal kprinc;
    krb5_keytab keytab;
    krb5_get_init_creds_opt *opts;
    krb5_creds creds;

    /* If we were called before, clean up after the previous run. */
    if (principal != NULL)
        kerberos_cleanup();

    /* Read the principal name and find the keytab file. */
    path = test_file_path("data/test.principal");
    if (path == NULL)
        return NULL;
    file = fopen(path, "r");
    if (file == NULL) {
        free(path);
        return NULL;
    }
    if (fgets(buffer, sizeof(buffer), file) == NULL) {
        fclose(file);
        bail("cannot read %s", path);
    }
    fclose(file);
    if (buffer[strlen(buffer) - 1] != '\n')
        bail("no newline in %s", path);
    free(path);
    buffer[strlen(buffer) - 1] = '\0';
    path = test_file_path("data/test.keytab");
    if (path == NULL)
        return NULL;

    /* Set the KRB5CCNAME and KRB5_KTNAME environment variables. */
    build = getenv("BUILD");
    if (build == NULL)
        build = ".";
    krb5ccname = concat("KRB5CCNAME=", build, "/data/test.cache", (char *) 0);
    krb5_ktname = concat("KRB5_KTNAME=", path, (char *) 0);
    putenv(krb5ccname);
    putenv(krb5_ktname);

    /* Now do the Kerberos initialization. */
    code = krb5_init_context(&ctx);
    if (code != 0)
        bail("error initializing Kerberos");
    code = krb5_cc_default(ctx, &ccache);
    if (code != 0)
        bail("error setting ticket cache");
    code = krb5_parse_name(ctx, buffer, &kprinc);
    if (code != 0)
        bail("error parsing principal %s", buffer);
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
    krb5_get_init_creds_opt_free(ctx, opts);
    free(krbtgt);
    test_file_path_free(path);

    /*
     * Register the cleanup function as an atexit handler so that the caller
     * doesn't have to worry about cleanup.
     */
    if (atexit(kerberos_cleanup) != 0)
        sysdiag("cannot register cleanup function");

    /* Store the principal and return it. */
    principal = bstrdup(buffer);
    return principal;
}
