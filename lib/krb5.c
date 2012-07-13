/*
 * Kerberos interface for WebAuth.
 *
 * All WebAuth functions that use Kerberos use the routines in this file.
 * This is the only code in WebAuth with direct Kerberos dependencies, so
 * ports to different versions of Kerberos should only require changing this
 * one file and its associated components.
 *
 * There are currently only five functions whose implementation varies between
 * MIT and Heimdal, namely cred_to_attr_encoding, cred_from_attr_encoding,
 * webauth_krb5_mk_req_with_data, webauth_krb5_rd_req_with_data, and
 * webauth_krb5_export_tgt.  Since those functions need (in most cases)
 * intimate knowledge of the layout of data structures, it's easiest to just
 * maintain two implementations.  Accordingly, we *include* either krb5-mit.c
 * or krb5-heimdal.c into this file based on configure results.  We do this
 * with the preprocessor to preserve static linkage of functions.
 *
 * Accordingly, if you don't see some functino here, look in krb5-mit.c and
 * krb5-heimdal.c.  If you have to modify either of those files, you'll
 * probably need to modify both.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2003, 2006, 2007, 2009, 2010, 2011, 2012
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <assert.h>
#include <errno.h>
#ifdef HAVE_ET_COM_ERR_H
# include <et/com_err.h>
#else
# include <com_err.h>
#endif

#include <util/macros.h>
#include <webauth.h>
#include <webauth/basic.h>

typedef struct {
    krb5_context ctx;
    krb5_ccache cc;
    krb5_principal princ;
    krb5_error_code code;
    char *pwchange_err;
    int keep_cache;
} WEBAUTH_KRB5_CTXTP;

/*
 * Attribute names for the token serialization of Kerberos credentials.  These
 * names are kept to a minimum since encoded creds end up in cookies, etc.
 */
#define CR_ADDRTYPE             "A%d"
#define CR_ADDRCONT             "a%d"
#define CR_CLIENT               "c"
#define CR_AUTHDATATYPE         "D%d"
#define CR_AUTHDATACONT         "d%d"
#define CR_TICKETFLAGS          "f"
#define CR_ISSKEY               "i"
#define CR_SERVER               "s"
#define CR_KEYBLOCK_CONTENTS    "k"
#define CR_KEYBLOCK_ENCTYPE     "K"
#define CR_NUMADDRS             "na"
#define CR_NUMAUTHDATA          "nd"
#define CR_TICKET               "t"
#define CR_TICKET2              "t2"
#define CR_AUTHTIME             "ta"
#define CR_STARTTIME            "ts"
#define CR_ENDTIME              "te"
#define CR_RENEWTILL            "tr"

/*
 * Forward declarations for the functions that have to be used by the MIT- and
 * Heimdal-specific code.
 */
static int
    open_keytab(WEBAUTH_KRB5_CTXTP *, const char *, const char *,
                krb5_principal *, krb5_keytab *);
static krb5_error_code
    mk_req_with_principal(krb5_context, krb5_auth_context *, krb5_flags,
                          krb5_principal, krb5_data *, krb5_ccache,
                          krb5_data *);

/* Include the appropriate implementation-specific Kerberos bits. */
#if HAVE_KRB5_MIT
# include "krb5-mit.c"
#elif HAVE_KRB5_HEIMDAL
# include "krb5-heimdal.c"
#else
# error "Unknown Kerberos implementation"
#endif


/*
 * Replacement for krb5_unparse_name_flags for implementations that don't have
 * it (MIT and older Heimdal).  Only supports the
 * KRB5_PRINCIPAL_UNPARSE_NO_REALM flag and always assumes that flag is set.
 */
#ifndef HAVE_KRB5_UNPARSE_NAME_FLAGS
#define KRB5_PRINCIPAL_UNPARSE_NO_REALM 1
static krb5_error_code
krb5_unparse_name_flags(krb5_context ctx, krb5_principal princ,
                        int flags UNUSED, char **name)
{
    krb5_error_code code;
    char *realm;

    code = krb5_unparse_name(ctx, princ, name);
    if (code != 0)
        return code;
    realm = strchr(*name, '@');
    if (realm != NULL)
        *realm = '\0';
    return 0;
}
#endif


/*
 * Open up a keytab and return a krb5_principal to use with that keytab.  If
 * in_principal is NULL, returned out_principal is first principal found in
 * keytab.
 */
static int
open_keytab(WEBAUTH_KRB5_CTXTP *c, const char *keytab_path,
            const char *in_principal, krb5_principal *out_principal,
            krb5_keytab *id_out)
{
    krb5_keytab id;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;

    assert(c != NULL);
    assert(keytab_path != NULL);
    assert(out_principal != NULL);
    assert(id_out != NULL);

    c->code = krb5_kt_resolve(c->ctx, keytab_path, &id);
    if (c->code != 0)
        return WA_ERR_KRB5;

    if (in_principal != NULL)
        c->code = krb5_parse_name(c->ctx, (char *)in_principal,
                                  out_principal);
    else {
        c->code = krb5_kt_start_seq_get(c->ctx, id, &cursor);
        if (c->code != 0) {
            /* FIXME: needs better logging. */
            krb5_kt_close(c->ctx, id);
            return WA_ERR_KRB5;
        }

        c->code = krb5_kt_next_entry(c->ctx, id, &entry, &cursor);
        if (c->code == 0) {
            c->code = krb5_copy_principal(c->ctx, entry.principal,
                                          out_principal);
            /* FIXME: needs better logging. */
            krb5_kt_free_entry(c->ctx, &entry);
        }
        /* FIXME: needs better logging. */
        krb5_kt_end_seq_get(c->ctx, id, &cursor);
    }

    if (c->code == 0) {
        *id_out = id;
        return WA_ERR_NONE;
    } else {
        *id_out = NULL;
        krb5_kt_close(c->ctx, id);
        return WA_ERR_KRB5;
    }
}


/*
 *  Like krb5_mk_req, but takes a principal instead of a service/host.
 */
static krb5_error_code
mk_req_with_principal(krb5_context context, krb5_auth_context *auth_context,
                      krb5_flags ap_req_options, krb5_principal server,
                      krb5_data *in_data, krb5_ccache ccache,
                      krb5_data *outbuf)
{
    krb5_error_code retval;
    krb5_creds *credsp;
    krb5_creds creds;

    memset(&creds, 0, sizeof(creds));
    retval = krb5_copy_principal(context, server, &creds.server);
    if (retval)
        return retval;
    retval = krb5_cc_get_principal(context, ccache, &creds.client);
    if (retval)
        goto cleanup_creds;
    retval = krb5_get_credentials(context, 0, ccache, &creds, &credsp);
    if (retval)
        goto cleanup_creds;
    retval = krb5_mk_req_extended(context, auth_context, ap_req_options,
                                  in_data, credsp, outbuf);
    krb5_free_creds(context, credsp);

cleanup_creds:
    krb5_free_cred_contents(context, &creds);
    return retval;
}


/*
 * Verify a Kerberos TGT (stored in the context) by obtaining a service ticket
 * for the principal stored in our local keytab and then verifying that
 * service ticket is correct.  This should probably be replaced with
 * krb5_verify_init_creds.
 */
static int
verify_tgt(WEBAUTH_KRB5_CTXTP *c, const char *keytab_path,
           const char *server_principal, char **server_principal_out)
{
    krb5_principal server;
    krb5_keytab keytab;
    krb5_auth_context auth;
    krb5_data outbuf;
    int s;

    assert(c != NULL);
    assert(keytab_path != NULL);
    assert(server_principal_out != NULL);

    *server_principal_out = NULL;

    s = open_keytab(c, keytab_path, server_principal, &server, &keytab);
    if (s != WA_ERR_NONE)
        return s;

    auth = NULL;
    c->code = mk_req_with_principal(c->ctx, &auth, 0, server, NULL, c->cc,
                                    &outbuf);
    if (c->code != 0) {
        krb5_free_principal(c->ctx, server);
        return WA_ERR_KRB5;
    }

    if (auth != NULL)
        krb5_auth_con_free(c->ctx, auth);

    auth = NULL;
    c->code = krb5_rd_req(c->ctx, &auth, &outbuf, server, keytab, NULL, NULL);
    if (auth != NULL)
        krb5_auth_con_free(c->ctx, auth);

    krb5_free_data_contents(c->ctx, &outbuf);
    krb5_kt_close(c->ctx, keytab);

    if (c->code == 0)
        c->code = krb5_unparse_name(c->ctx, server, server_principal_out);

    krb5_free_principal(c->ctx, server);

    return (c->code == 0) ? WA_ERR_NONE : WA_ERR_KRB5;
}


/*
 * Given a portion of a Kerberos principal and its length, allocate a new
 * string and write the escaped form of that portion of a principal to the
 * newly allocated string.  Returns the newly allocated string, which the
 * caller is responsible for freeing, or NULL on failure.
 */
static char *
escape_principal(const char *in, size_t length)
{
    const char *src;
    char *out, *dest;
    size_t needed = 0;

    /*
     * We take two passes through the data, one to count the size of the newly
     * allocated string and one to copy it over.
     */
    for (src = in; (size_t) (src - in) < length; src++) {
        switch (*src) {
        case '/':  case '@':  case '\\': case '\t':
        case '\n': case '\b': case '\0':
            needed++;
            break;
        default:
            break;
        }
        needed++;
    }
    out = malloc(needed + 1);
    if (out == NULL)
        return NULL;
    for (src = in, dest = out; (size_t) (src - in) < length; src++) {
        switch (*src) {
        case '/':
        case '@':
        case '\\':
            *dest++ = '\\';
            *dest++ = *src;
            break;
        case '\t':
            *dest++ = '\\';
            *dest++ = 't';
            break;
        case '\n':
            *dest++ = '\\';
            *dest++ = 'n';
            break;
        case '\b':
            *dest++ = '\\';
            *dest++ = 'b';
            break;
        case '\0':
            *dest++ = '\\';
            *dest++ = '0';
            break;
        default:
            *dest++ = *src;
            break;
        }
    }
    *dest = '\0';
    return out;
}


/*
 * Create a new WEBAUTH_KRB5_CTXT.  Returns a WA_ERR code and stores the newly
 * created context in the ctxt argument.
 */
int
webauth_krb5_new(WEBAUTH_KRB5_CTXT **ctxt)
{
    WEBAUTH_KRB5_CTXTP *c;
    assert(ctxt);

    *ctxt = NULL;

    c = malloc(sizeof(WEBAUTH_KRB5_CTXTP));
    if (c == NULL)
        return WA_ERR_NO_MEM;

    c->cc = NULL;
    c->princ = NULL;
    c->keep_cache = 0;
    c->ctx = NULL;
    c->pwchange_err = NULL;
    c->code = krb5_init_context(&c->ctx);
    *ctxt = (WEBAUTH_KRB5_CTXT *) c;
    return (c->code == 0) ? WA_ERR_NONE : WA_ERR_KRB5;
}


/*
 * Return the Kerberos error code from the last operation.
 */
int
webauth_krb5_error_code(WEBAUTH_KRB5_CTXT *context)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP *) context;
    assert(c);
    return c->code;
}


/*
 * Return the Kerberos error message from the last operation, using com_err
 * to map the code to a message.
 */
const char *
webauth_krb5_error_message(WEBAUTH_KRB5_CTXT *context)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP *) context;
    assert(c);
    if (c->code == 0)
        return "success";
    else {
        if (c->pwchange_err != NULL)
            return c->pwchange_err;
        else
            return error_message(c->code);
    }
}


/*
 * Change a user's password, given context and the new password.  The user to
 * change should be already in the context, which should also have credentials
 * for kadmin/changepw in order to perform the change.
 */
int
webauth_krb5_change_password(WEBAUTH_KRB5_CTXT *context,
                             const char *password)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP *) context;
    int result_code;
    int retval;
    krb5_data result_code_string, result_string;
    char *username = NULL;
#if HAVE_KRB5_MIT
    krb5_creds in, *out = NULL;
#endif

    assert(c != NULL);
    assert(password != NULL);

    memset(&result_code_string, 0, sizeof(krb5_data));
    memset(&result_string, 0, sizeof(krb5_data));
    if (c->pwchange_err != NULL) {
        free(c->pwchange_err);
        c->pwchange_err = NULL;
    }

    krb5_unparse_name(c->ctx, c->princ, &username);

    /*
     * The actual change.  MIT Kerberos up to at least 1.9 has a bug in the
     * set_password implementation that causes it to misparse replies that are
     * larger than 256 bytes and return an incorrect error code, so for MIT
     * Kerberos we use the old change_password API instead.
     */
#if HAVE_KRB5_MIT
    memset(&in, 0, sizeof(in));
    c->code = krb5_copy_principal(c->ctx, c->princ, &in.client);
    if (c->code != 0)
        goto done;
    c->code = krb5_build_principal(c->ctx, &in.server,
                                   krb5_princ_realm(c->ctx, c->princ)->length,
                                   krb5_princ_realm(c->ctx, c->princ)->data,
                                   "kadmin", "changepw", NULL);
    if (c->code != 0)
        goto done;
    c->code = krb5_get_credentials(c->ctx, 0, c->cc, &in, &out);
    if (c->code != 0)
        goto done;
    c->code = krb5_change_password(c->ctx, out, (char *) password,
                                   &result_code, &result_code_string,
                                   &result_string);
#else
    c->code = krb5_set_password_using_ccache(c->ctx, c->cc, (char *) password,
                                             c->princ, &result_code,
                                             &result_code_string,
                                             &result_string);
#endif /* !HAVE_KRB5_MIT */

    /* Everything from here on is just handling diagnostics and output. */
    if (c->code != 0)
        goto done;
    if (result_code != 0) {
        c->code = result_code;
        retval = asprintf(&c->pwchange_err, "password change failed for %s:"
                          " (%d) %.*s%s%.*s", username, result_code,
                          (int) result_code_string.length,
                          (char *) result_code_string.data,
                          result_string.length == 0 ? "" : ": ",
                          (int) result_string.length,
                          (char *) result_string.data);
        if (retval == -1) {
            c->pwchange_err = NULL;
            c->code = ENOMEM;
        }
    }

done:
    krb5_free_data_contents(c->ctx, &result_string);
    krb5_free_data_contents(c->ctx, &result_code_string);
    if (username != NULL)
        krb5_free_unparsed_name(c->ctx, username);
#if HAVE_KRB5_MIT
    krb5_free_cred_contents(c->ctx, &in);
    if (out != NULL)
        krb5_free_creds(c->ctx, out);
#endif
    return (c->code == 0) ? WA_ERR_NONE : WA_ERR_KRB5;
}


/*
 * Obtain a TGT from a user's password, verifying it with the provided keytab
 * and server principal if given.  If no keytab is given, we do not verify the
 * TGT, and server_principal_out is not set.  If get_principal is set, then we
 * get credentials for that principal rather than the given user.
 */
int
webauth_krb5_init_via_password(WEBAUTH_KRB5_CTXT *context,
                               const char *username, const char *password,
                               const char *get_principal,
                               const char *keytab,
                               const char *server_principal,
                               const char *cache_name,
                               char **server_principal_out)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP *) context;
    char ccname[128];
    char *tpassword;
    krb5_creds creds;
    krb5_get_init_creds_opt *opts;

    assert(c != NULL);
    assert(username != NULL);
    assert(password != NULL);
    assert(server_principal_out != NULL);
    *server_principal_out = NULL;

    c->code = krb5_parse_name(c->ctx, username, &c->princ);

    if (c->code != 0)
        return WA_ERR_KRB5;

    if (cache_name == NULL) {
        snprintf(ccname, sizeof(ccname), "MEMORY:%p", c);
        cache_name = ccname;
    }

    c->code = krb5_cc_resolve(c->ctx, cache_name, &c->cc);
    if (c->code != 0)
        return WA_ERR_KRB5;

    c->code = krb5_cc_initialize(c->ctx, c->cc, c->princ);
    if (c->code != 0)
        return WA_ERR_KRB5;

    c->code = krb5_get_init_creds_opt_alloc(c->ctx, &opts);
    if (c->code != 0)
        return WA_ERR_KRB5;
    krb5_get_init_creds_opt_set_default_flags(c->ctx, "webauth", NULL, opts);

    if (get_principal == NULL)
        krb5_get_init_creds_opt_set_forwardable(opts, 1);
    else {
        krb5_get_init_creds_opt_set_forwardable(opts, 0);
        krb5_get_init_creds_opt_set_proxiable(opts, 0);
        krb5_get_init_creds_opt_set_renew_life(opts, 0);
    }

    tpassword = strdup(password);
    if (tpassword == NULL)
        return WA_ERR_NO_MEM;

    c->code = krb5_get_init_creds_password(c->ctx, &creds, c->princ,
                                           tpassword, NULL, NULL, 0,
                                           (char *) get_principal, opts);
    krb5_get_init_creds_opt_free(c->ctx, opts);
    memset(tpassword, 0, strlen(tpassword));
    free(tpassword);

    if (c->code != 0) {
        switch (c->code) {
        case KRB5KRB_AP_ERR_BAD_INTEGRITY:
        case KRB5KDC_ERR_PREAUTH_FAILED:
        case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
            return WA_ERR_LOGIN_FAILED;
        case KRB5KDC_ERR_KEY_EXP:
            return WA_ERR_CREDS_EXPIRED;
        case KRB5KDC_ERR_POLICY:
        case KRB5KDC_ERR_NAME_EXP:
            return WA_ERR_USER_REJECTED;
        default:
            /* FIXME: needs better logging. */
            return WA_ERR_KRB5;
        }

    }

    /* Add the creds to the cache. */
    c->code = krb5_cc_store_cred(c->ctx, c->cc, &creds);
    krb5_free_cred_contents(c->ctx, &creds);
    if (c->code != 0)
        return WA_ERR_KRB5;
    else {
        if (keytab != NULL)
            return verify_tgt(c, keytab, server_principal,
                              server_principal_out);
        else
            return WA_ERR_NONE;
    }
}


/*
 * Initialize a context from an existing ticket cache.
 */
int
webauth_krb5_init_via_cache(WEBAUTH_KRB5_CTXT *context,
                            const char *cache_name)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP *) context;

    assert(c != NULL);

    if (cache_name != NULL)
        c->code = krb5_cc_resolve(c->ctx, cache_name, &c->cc);
    else
        c->code = krb5_cc_default(c->ctx, &c->cc);
    if (c->code != 0)
        return WA_ERR_KRB5;
    c->code = krb5_cc_get_principal(c->ctx, c->cc, &c->princ);
    return (c->code == 0) ? WA_ERR_NONE : WA_ERR_KRB5;
}


/*
 * Set the keep_cache flag on a context.  When this flag is set, the ticket
 * cache will just be closed, not destroyed, when the context is freed.
 * Returns a WA_ERR code.
 */
int
webauth_krb5_keep_cred_cache(WEBAUTH_KRB5_CTXT *context)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP *) context;

    assert(c != NULL);

    c->keep_cache = 1;
    return WA_ERR_NONE;
}


/*
 * Free a Kerberos context and the associated data.  Returns a WA_ERR code.
 */
int
webauth_krb5_free(WEBAUTH_KRB5_CTXT *context)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP *) context;

    assert(c != NULL);

    if (c->cc) {
        if (c->keep_cache)
            krb5_cc_close(c->ctx, c->cc);
        else
            krb5_cc_destroy(c->ctx, c->cc);
    }
    if (c->princ)
        krb5_free_principal(c->ctx, c->princ);
    if (c->ctx != NULL)
        krb5_free_context(c->ctx);
    if (c->pwchange_err != NULL)
        free(c->pwchange_err);
    free(context);
    return WA_ERR_NONE;
}


/*
 * Generate a mk_req Kerberos request with no associated data.  This just
 * calls webauth_krb5_mk_req_with_data, which is separately implemented for
 * both MIT and Heimdal in krb5-mit.c and krb5-heimdal.c.
 */
int
webauth_krb5_mk_req(WEBAUTH_KRB5_CTXT *context, const char *server_principal,
                    char **output, size_t *length)
{
    return webauth_krb5_mk_req_with_data(context, server_principal, output,
                                         length, NULL, 0, NULL, NULL);
}


/*
 * Read an encrypted Kerberos request generated by webauth_krb5_mk_req that
 * has no associated data.  This just calls webauth_krb5_rd_req_with_data,
 * which is separately implemented for both MIT and Heimdal in krb5-mit.c and
 * krb5-heimdal.c.
 */
int
webauth_krb5_rd_req(WEBAUTH_KRB5_CTXT *context, const char *req,
                    size_t length, const char *keytab_path,
                    const char *server_principal, char **client_principal,
                    int local)
{
    return webauth_krb5_rd_req_with_data(context, req, length, keytab_path,
                                         server_principal, NULL,
                                         client_principal, local, NULL, 0,
                                         NULL, NULL);
}


/*
 * Initialize a context from a keytab and obtain a TGT.  Optionally takes a
 * cache name, which if NULL indicates to use a memory cache.
 */
int
webauth_krb5_init_via_keytab(WEBAUTH_KRB5_CTXT *context,
                             const char *keytab_path,
                             const char *server_principal,
                             const char *cache_name)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP *) context;
    char ccname[128];
    krb5_creds creds;
    krb5_get_init_creds_opt *opts;
    krb5_keytab keytab;
    int s;

    assert(c != NULL);
    assert(keytab_path != NULL);

    if (c->princ != NULL)
        krb5_free_principal(c->ctx, c->princ);

    s = open_keytab(c, keytab_path, server_principal, &c->princ, &keytab);
    if (s != WA_ERR_NONE)
        return WA_ERR_KRB5;

    if (cache_name == NULL) {
        snprintf(ccname, sizeof(ccname), "MEMORY:%p", c);
        cache_name = ccname;
    }

    c->code = krb5_cc_resolve(c->ctx, cache_name, &c->cc);
    if (c->code != 0) {
        krb5_kt_close(c->ctx, keytab);
        return WA_ERR_KRB5;
    }

    c->code = krb5_cc_initialize(c->ctx, c->cc, c->princ);
    if (c->code != 0) {
        krb5_kt_close(c->ctx, keytab);
        return WA_ERR_KRB5;
    }

    c->code = krb5_get_init_creds_opt_alloc(c->ctx, &opts);
    if (c->code != 0) {
        krb5_kt_close(c->ctx, keytab);
        return WA_ERR_KRB5;
    }
    krb5_get_init_creds_opt_set_default_flags(c->ctx, "webauth", NULL, opts);

    c->code = krb5_get_init_creds_keytab(c->ctx, &creds, c->princ, keytab,
                                         0, NULL, opts);
    krb5_get_init_creds_opt_free(c->ctx, opts);

    /* FIXME: needs better logging. */
    krb5_kt_close(c->ctx, keytab);

    if (c->code != 0) {
        switch (c->code) {
            case KRB5KRB_AP_ERR_BAD_INTEGRITY:
            case KRB5KDC_ERR_PREAUTH_FAILED:
            case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
                return WA_ERR_LOGIN_FAILED;
            default:
                /* FIXME: log once logging is in */
                return WA_ERR_KRB5;
        }
    }

    /* Add the creds to the cache. */
    c->code = krb5_cc_store_cred(c->ctx, c->cc, &creds);
    krb5_free_cred_contents(c->ctx, &creds);
    if (c->code != 0)
        return WA_ERR_KRB5;
    else
        return WA_ERR_NONE;
}


/*
 * Initialize a context via a passed, delegated credential.
 */
int
webauth_krb5_init_via_cred(WEBAUTH_KRB5_CTXT *context, const void *cred,
                           size_t cred_len, const char *cache_name)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP *) context;
    krb5_creds creds;
    char ccname[128];
    int s;

    assert(c != NULL);
    assert(cred != NULL);

    s = cred_from_attr_encoding(c, cred, cred_len, &creds);

    if (s != WA_ERR_NONE)
        return s;

    if (cache_name == NULL) {
        snprintf(ccname, sizeof(ccname), "MEMORY:%p", c);
        cache_name = ccname;
    }

    c->code = krb5_cc_resolve(c->ctx, cache_name, &c->cc);
    if (c->code != 0)
        return WA_ERR_KRB5;

    c->code = krb5_copy_principal(c->ctx, creds.client, &c->princ);
    if (c->code != 0)
        return WA_ERR_KRB5;

    c->code = krb5_cc_initialize(c->ctx, c->cc, c->princ);
    if (c->code != 0)
        return WA_ERR_KRB5;

    /* Add the creds to the cache. */
    c->code = krb5_cc_store_cred(c->ctx, c->cc, &creds);
    krb5_free_cred_contents(c->ctx, &creds);
    if (c->code != 0)
        return WA_ERR_KRB5;
    else
        return WA_ERR_NONE;
}


/*
 * Initialize a context from a passed, delegated credential, but do
 * not import the credential.
 */
int
webauth_krb5_prepare_via_cred(WEBAUTH_KRB5_CTXT *context, const void *cred,
                              size_t cred_len, const char *cache_name)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP *) context;
    krb5_creds creds;
    char ccname[128];
    int s;

    assert(c != NULL);
    assert(cred != NULL);

    if (cache_name == NULL) {
        snprintf(ccname, sizeof(ccname), "MEMORY:%p", c);
        cache_name = ccname;
    }
    s = cred_from_attr_encoding(c, cred, cred_len, &creds);
    if (s != WA_ERR_NONE)
        return s;
    c->code = krb5_cc_resolve(c->ctx, cache_name, &c->cc);
    if (c->code != 0)
        return WA_ERR_KRB5;
    c->code = krb5_copy_principal(c->ctx, creds.client, &c->princ);
    if (c->code != 0)
        return WA_ERR_KRB5;
    c->code = krb5_cc_initialize(c->ctx, c->cc, c->princ);
    if (c->code != 0)
        return WA_ERR_KRB5;
    return WA_ERR_NONE;
}


/*
 * Import a credential into an existing ticket cache.
 */
int
webauth_krb5_import_cred(WEBAUTH_KRB5_CTXT *context, const char *cred,
                         size_t cred_len)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP *) context;
    krb5_creds creds;
    int s;

    assert(c != NULL);
    assert(cred != NULL);

    s = cred_from_attr_encoding(c, cred, cred_len, &creds);
    if (s!= WA_ERR_NONE)
        return s;

    /* Add the creds to the cache. */
    c->code = krb5_cc_store_cred(c->ctx, c->cc, &creds);
    krb5_free_cred_contents(c->ctx, &creds);
    if (c->code != 0)
        return WA_ERR_KRB5;
    else
        return WA_ERR_NONE;
}


/*
 * Export a ticket into the encoded form that we put into tokens, used for
 * delegating credentials or storing credentials in cookies.
 */
int
webauth_krb5_export_ticket(WEBAUTH_KRB5_CTXT *context,
                           const char *server_principal, char **ticket,
                           size_t *ticket_len, time_t *expiration)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP *) context;
    krb5_creds *credsp, creds;
    int s;

    s = WA_ERR_KRB5;
    memset(&creds, 0, sizeof(creds));

    c->code = krb5_parse_name(c->ctx, server_principal, &creds.server);
    if (c->code != 0)
        goto cleanup_creds;

    c->code = krb5_cc_get_principal(c->ctx, c->cc, &creds.client);
    if (c->code != 0)
        goto cleanup_creds;

    c->code = krb5_get_credentials(c->ctx, 0, c->cc, &creds, &credsp);
    if (c->code != 0)
        goto cleanup_creds;

    s = cred_to_attr_encoding(c, credsp, ticket, ticket_len, expiration);
    krb5_free_creds(c->ctx, credsp);

 cleanup_creds:
    krb5_free_cred_contents(c->ctx, &creds);
    return s;
}


/*
 * Get the principal from a context.
 *
 * Principal canonicalization is controlled by the third argument.  If it's
 * WA_KRB5_CANON_NONE, do no canonicalization.  If it's WA_KRB5_CANON_LOCAL,
 * run the principal through krb5_aname_to_localname first to try to generate
 * a local username and fall through a fully-qualified name.  If it's
 * WA_KRB5_CANON_STRIP, strip the realm from the principal, whatever it may
 * be.
 */
int
webauth_krb5_get_principal(WEBAUTH_KRB5_CTXT *context, char **principal,
                           enum webauth_krb5_canon canonicalize)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP *) context;
    krb5_error_code tcode;
    char lname[256];

    if (c->princ == NULL)
        return WA_ERR_INVALID_CONTEXT;

    switch (canonicalize) {
    case WA_KRB5_CANON_LOCAL:
        tcode = krb5_aname_to_localname(c->ctx, c->princ, sizeof(lname) - 1,
                                        lname);
        if (tcode == 0) {
            *principal = strdup(lname);
            if (*principal == NULL)
                return WA_ERR_NO_MEM;
            return WA_ERR_NONE;
        }
        /* Fall through. */
    case WA_KRB5_CANON_NONE:
        c->code = krb5_unparse_name(c->ctx, c->princ, principal);
        break;
    case WA_KRB5_CANON_STRIP:
        c->code = krb5_unparse_name_flags(c->ctx, c->princ,
                                          KRB5_PRINCIPAL_UNPARSE_NO_REALM,
                                          principal);
        break;
    }
    return c->code == 0 ? WA_ERR_NONE : WA_ERR_KRB5;
}


/*
 * Get the authentication realm from the context.  Stores the newly allocated
 * string in realm and returns WA_ERR_NONE on success, or another error code
 * on failure.
 */
int
webauth_krb5_get_realm(WEBAUTH_KRB5_CTXT *context, char **realm)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP *) context;
    const char *raw;
    size_t length;

    if (c->princ == NULL)
        return WA_ERR_INVALID_CONTEXT;
    raw = krb5_principal_get_realm(c->ctx, c->princ);
    if (raw == NULL)
        return WA_ERR_INVALID_CONTEXT;
    length = strlen(raw);
    *realm = escape_principal(raw, length);
    return (*realm == NULL) ? WA_ERR_NO_MEM : WA_ERR_NONE;
}


/*
 * Get the ticket cache from the context.  Stores the newly allocated string
 * in cache and returns WA_ERR_NONE on success, or another error code on
 * failure.
 */
int
webauth_krb5_get_cache(WEBAUTH_KRB5_CTXT *context, char **cache)
{
    WEBAUTH_KRB5_CTXTP *c = (WEBAUTH_KRB5_CTXTP *) context;
    const char *type, *name;
    size_t length;

    if (c->cc == NULL)
        return WA_ERR_INVALID_CONTEXT;
    type = krb5_cc_get_type(c->ctx, c->cc);
    if (type == NULL)
        return WA_ERR_KRB5;
    name = krb5_cc_get_name(c->ctx, c->cc);
    if (name == NULL)
        return WA_ERR_KRB5;
    length = strlen(type) + 1 + strlen(name) + 1;
    *cache = malloc(length);
    if (*cache == NULL)
        return WA_ERR_NO_MEM;
    strlcpy(*cache, type, length);
    strlcat(*cache, ":", length);
    strlcat(*cache, name, length);
    return WA_ERR_NONE;
}
