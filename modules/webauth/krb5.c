/*
 * Kerberos-related functions for the WebAuth Apache module.
 *
 * Written by Roland Schemers
 * Copyright 2003, 2006, 2009, 2010, 2011, 2012, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config-mod.h>
#include <portable/apache.h>
#include <portable/apr.h>
#include <portable/stdbool.h>

#include <apr_base64.h>
#ifdef HAVE_LIBKEYUTILS
# include <keyutils.h>
#endif
#include <unistd.h>

#include <modules/webauth/mod_webauth.h>
#include <webauth/basic.h>
#include <webauth/krb5.h>
#include <webauth/tokens.h>

APLOG_USE_MODULE(webauth);


static void
log_webauth_error(struct webauth_context *ctx, server_rec *s, int status,
                  const char *mwa_func, const char *func, const char *extra)
{
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                 "mod_webauth: %s: %s%s%s failed: %s (%d)",
                 mwa_func,
                 func,
                 extra == NULL ? "" : " ",
                 extra == NULL ? "" : extra,
                 webauth_error_message(ctx, status), status);
}


/*
 * get a WEBAUTH_KRB5_CTXT
 */
static struct webauth_krb5 *
get_webauth_krb5_ctxt(struct webauth_context *ctx, server_rec *server,
                      const char *mwa_func)
{
    struct webauth_krb5 *kc = NULL;
    int status;

    status = webauth_krb5_new(ctx, &kc);
    if (status != WA_ERR_NONE) {
        log_webauth_error(ctx, server, status, mwa_func,
                          "webauth_krb5_new", NULL);
        return NULL;
    }
    return kc;
}


static const char *
krb5_validate_sad(MWA_REQ_CTXT *rc, const void *sad, size_t sad_len)
{
    struct webauth_krb5 *kc;
    int status;
    char *subject;
    const char *mwa_func = "krb5_validate_sad";
    char *kt;

    if (rc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                     "mod_webauth: %s: called", mwa_func);

    kc = get_webauth_krb5_ctxt(rc->ctx, rc->r->server, mwa_func);
    if (kc == NULL)
        return NULL;

    kt = apr_pstrcat(rc->r->pool, "FILE:", rc->sconf->keytab_path, NULL);

    status = webauth_krb5_read_auth(rc->ctx, kc, sad, sad_len, kt,
                                    rc->sconf->keytab_principal,
                                    &subject, WA_KRB5_CANON_LOCAL);
    if (status != WA_ERR_NONE) {
        log_webauth_error(rc->ctx, rc->r->server, status, mwa_func,
                          "webauth_krb5_read_auth", NULL);
        return NULL;
    }
    return subject;
}


static int
krb5_prepare_file_creds(MWA_REQ_CTXT *rc, apr_array_header_t *creds)
{
    const char *mwa_func="krb5_prepare_file_creds";
    struct webauth_krb5 *kc;
    size_t i;
    int status;
    char *temp_cred_file;
    apr_file_t *fp;
    apr_int32_t flags;
    apr_status_t astatus;

    astatus = apr_filepath_merge(&temp_cred_file,
                                 rc->sconf->cred_cache_dir,
                                 "temp.krb5.XXXXXX",
                                 0,
                                 rc->r->pool);
    if (astatus != APR_SUCCESS) {
        mwa_log_apr_error(rc->r->server, astatus, mwa_func,
                          "apr_filepath_merge", rc->sconf->cred_cache_dir,
                          "temp.krb5.XXXXX");
        return 0;
    }

    flags = (APR_FOPEN_CREATE | APR_FOPEN_READ | APR_FOPEN_WRITE
             | APR_FOPEN_EXCL);
    astatus = apr_file_mktemp(&fp, temp_cred_file, flags, rc->r->pool);
    if (astatus != APR_SUCCESS) {
        mwa_log_apr_error(rc->r->server, astatus, mwa_func,
                          "apr_file_mktemp", temp_cred_file, NULL);
        return 0;
    }

    /* we close it here, and register a pool cleanup handler */
    astatus = apr_file_close(fp);
    if (astatus != APR_SUCCESS) {
        mwa_log_apr_error(rc->r->server, astatus, mwa_func,
                          "apr_file_close", temp_cred_file, NULL);
        return 0;
    }

    if (rc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                     "mod_webauth: %s: temp_cred_file mktemp(%s)",
                     mwa_func, temp_cred_file);

    kc = get_webauth_krb5_ctxt(rc->ctx, rc->r->server, mwa_func);
    if (kc == NULL)
        return 0;

    for (i = 0; i < (size_t) creds->nelts; i++) {
        struct webauth_token_cred *cred;

        cred = APR_ARRAY_IDX(creds, i, struct webauth_token_cred *);
        if (strcmp(cred->type, "krb5") == 0) {
            if (rc->sconf->debug)
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                             "mod_webauth: %s: prepare (%s) for (%s)",
                             mwa_func, cred->service, cred->subject);
            status = webauth_krb5_import_cred(rc->ctx, kc, cred->data,
                                              cred->data_len, temp_cred_file);
            if (status != WA_ERR_NONE)
                log_webauth_error(rc->ctx, rc->r->server,
                                  status, mwa_func,
                                  "webauth_krb5_import_cred", NULL);
        }
    }

    /* set environment variable */
    apr_table_setn(rc->r->subprocess_env, ENV_KRB5CCNAME, temp_cred_file);
    return 1;
}


#ifdef HAVE_LIBKEYUTILS
static int
krb5_prepare_keyring_creds(MWA_REQ_CTXT *rc, apr_array_header_t *creds)
{
    const char *mwa_func="krb5_prepare_keyring_creds";
    struct webauth_krb5 *kc;
    size_t i;
    int status;
    const char *kr_ccache_name;
    key_serial_t kr_ccache = 0;
    key_serial_t key;

    kr_ccache_name = rc->sconf->cred_cache_dir;
    if (rc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                     "mod_webauth: %s: krb5 keyring cache %s)",
                     mwa_func, kr_ccache_name);

    kc = get_webauth_krb5_ctxt(rc->ctx, rc->r->server, mwa_func);
    if (kc == NULL)
        return 0;

    for (i = 0; i < (size_t) creds->nelts; i++) {
        struct webauth_token_cred *cred;

        cred = APR_ARRAY_IDX(creds, i, struct webauth_token_cred *);

        /* FIXME: Do something here other than just ignoring them. */
        if (strcmp(cred->type, "krb5") != 0)
            continue;

        /*
         * In order to enforce possessor-only permissions on our keyring
         * ccache, create the keys and set permissions before krb5 fills the
         * keys.  There is still a window between add_key and setperm where
         * other procs can link the key to become a "possessor"..
         */
        if (kr_ccache == 0) {
            if (rc->sconf->debug)
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                             "mod_webauth: %s: prepare (%s) for (%s)",
                             mwa_func, cred->service, cred->subject);
            kr_ccache = add_key("keyring", kr_ccache_name + 8, NULL, 0,
                                KEY_SPEC_SESSION_KEYRING);
            if (kr_ccache < 0) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                      "mod_webauth: %s: failed to create ccache keyring %s: %s",
                       mwa_func, kr_ccache_name, strerror(errno));
                return 0;
            }
            keyctl_setperm(kr_ccache, KEY_POS_ALL);
            status = webauth_krb5_prepare_via_cred(rc->ctx, kc, cred->data,
                                                   cred->data_len,
                                                   kr_ccache_name);
            if (status != WA_ERR_NONE) {
                log_webauth_error(rc->ctx, rc->r->server, status, mwa_func,
                                  "webauth_krb5_prepare_via_cred", NULL);
                return 0;
            }
            key = keyctl_search(kr_ccache, "user", "__krb5_princ__", 0);
            if (key < 0) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                      "mod_webauth: %s: failed to find princ in keyring %d: %s",
                       mwa_func, kr_ccache, strerror(errno));
                return 0;
            }
            keyctl_setperm(key, KEY_POS_ALL);
        }
        key = add_key("user", cred->service, "null", 4, kr_ccache);
        if (key < 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                  "mod_webauth: %s: add_key failed for %s, keyring %d: %s",
                   mwa_func, cred->service, kr_ccache, strerror(errno));
            continue;
        }
        keyctl_setperm(key, KEY_POS_ALL);

        status = webauth_krb5_import_cred(rc->ctx, kc, cred->data,
                                          cred->data_len, NULL);
        if (status != WA_ERR_NONE)
            log_webauth_error(rc->ctx, rc->r->server, status, mwa_func,
                              "webauth_krb5_import_cred", NULL);
    }

    /* set environment variable */
    apr_table_setn(rc->r->subprocess_env, ENV_KRB5CCNAME, kr_ccache_name);
    return 1;
}
#endif


/*
 * prepare any krb5 creds
 */
static int
krb5_prepare_creds(MWA_REQ_CTXT *rc, apr_array_header_t *creds)
{
    if (rc->sconf->cred_cache_dir == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                     "mod_webauth: WebAuthCredCacheDir is not set");
        return 0;
    }
#ifdef HAVE_LIBKEYUTILS
    if (strncmp(rc->sconf->cred_cache_dir, "KEYRING:", 8) == 0)
        return krb5_prepare_keyring_creds(rc, creds);
#endif
    return krb5_prepare_file_creds(rc, creds);
}


static const char *
krb5_webkdc_credential(struct webauth_context *ctx, server_rec *server,
                       struct server_config *sconf, apr_pool_t *pool)
{
    struct webauth_krb5 *kc;
    void *k5_req;
    char *bk5_req;
    int status;
    size_t k5_req_len, bk5_req_len;
    static const char *mwa_func = "krb5_webkdc_credential";
    char *kt;

    kc = get_webauth_krb5_ctxt(ctx, server, mwa_func);
    if (kc == NULL)
        return NULL;

    kt = apr_pstrcat(pool, "FILE:", sconf->keytab_path, NULL);

    status = webauth_krb5_init_via_keytab(ctx, kc, kt,
                                          sconf->keytab_principal, NULL);
    if (status != WA_ERR_NONE) {
        log_webauth_error(ctx, server, status, mwa_func,
                          "webauth_krb5_init_via_keytab", kt);
        webauth_krb5_free(ctx, kc);
        return NULL;
    }

    status = webauth_krb5_make_auth(ctx, kc, sconf->webkdc_principal,
                                    &k5_req, &k5_req_len);

    if (status != WA_ERR_NONE) {
        log_webauth_error(ctx, server, status, mwa_func,
                          "webauth_krb5_mk_req", sconf->webkdc_principal);
        webauth_krb5_free(ctx, kc);
        return 0;
    }

    bk5_req_len = apr_base64_encode_len(k5_req_len);
    bk5_req = apr_palloc(pool, bk5_req_len);
    apr_base64_encode(bk5_req, k5_req, k5_req_len);
    webauth_krb5_free(ctx, kc);
    return bk5_req;
}

static MWA_CRED_INTERFACE krb5_cred_interface = {
    "krb5",
    krb5_validate_sad,
    krb5_prepare_creds,
    krb5_webkdc_credential
};

MWA_CRED_INTERFACE *mwa_krb5_cred_interface = &krb5_cred_interface;
