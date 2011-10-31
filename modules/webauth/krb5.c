/*
 * Kerberos-related functions for the WebAuth Apache module.
 *
 * Written by Roland Schemers
 * Copyright 2003, 2006, 2009, 2010, 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <modules/mod-config.h>

#include <apr_base64.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <httpd.h>
#include <http_log.h>
#include <unistd.h>

#include <modules/webauth/mod_webauth.h>
#include <webauth/basic.h>
#include <webauth/tokens.h>


static void
log_webauth_error(server_rec *s, int status, WEBAUTH_KRB5_CTXT *ctxt,
                  const char *mwa_func, const char *func, const char *extra)
{
    if (status == WA_ERR_KRB5 && ctxt != NULL)
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "mod_webauth: %s: %s%s%s failed: %s (%d): %s %d",
                     mwa_func, func,
                     extra == NULL ? "" : " ",
                     extra == NULL ? "" : extra,
                     webauth_error_message(NULL, status), status,
                     webauth_krb5_error_message(ctxt),
                     webauth_krb5_error_code(ctxt));
    else
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "mod_webauth: %s: %s%s%s failed: %s (%d)",
                     mwa_func,
                     func,
                     extra == NULL ? "" : " ",
                     extra == NULL ? "" : extra,
                     webauth_error_message(NULL, status), status);
}


/*
 * get a WEBAUTH_KRB5_CTXT
 */
static WEBAUTH_KRB5_CTXT *
get_webauth_krb5_ctxt(server_rec *server, const char *mwa_func)
{
    WEBAUTH_KRB5_CTXT *ctxt;
    int status;

    status = webauth_krb5_new(&ctxt);
    if (status != WA_ERR_NONE) {
        log_webauth_error(server, status, ctxt, mwa_func, "webauth_krb5_new",
                          NULL);
        if (status == WA_ERR_KRB5)
            webauth_krb5_free(ctxt);
        return NULL;
    }
    return ctxt;
}


static const char *
krb5_validate_sad(MWA_REQ_CTXT *rc, const void *sad, size_t sad_len)
{
    WEBAUTH_KRB5_CTXT *ctxt;
    int status;
    char *principal, *subject;
    const char *mwa_func = "krb5_validate_sad";
    char *kt;

    if (rc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                     "mod_webauth: %s: called", mwa_func);

    ctxt = get_webauth_krb5_ctxt(rc->r->server, mwa_func);
    if (ctxt == NULL)
        return NULL;

    kt = apr_pstrcat(rc->r->pool, "FILE:", rc->sconf->keytab_path, NULL);

    status = webauth_krb5_rd_req(ctxt, sad, sad_len, kt,
                                 rc->sconf->keytab_principal,
                                 &principal, 1);
    webauth_krb5_free(ctxt);

    if (status != WA_ERR_NONE) {
        log_webauth_error(rc->r->server, status, ctxt, mwa_func,
                              "webauth_krb5_rd_req", NULL);
        return NULL;
    }

    subject = apr_pstrdup(rc->r->pool, principal);
    free(principal);
    return subject;
}


/*
 * called when the request pool gets cleaned up
 */
static apr_status_t
cred_cache_destroy(void *data)
{
    char *path = (char*)data;
    /*
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                 "mod_webauth: cleanup cred: %s", path);
    */
    if (unlink(path) == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "mod_webauth: cleanup cred: unlink(%s) errno(%d)",
                     path, errno);
    }
    return APR_SUCCESS;
}


/*
 * prepare any krb5 creds
 */
static int
krb5_prepare_creds(MWA_REQ_CTXT *rc, apr_array_header_t *creds)
{
    const char *mwa_func="krb5_prepare_creds";
    WEBAUTH_KRB5_CTXT *ctxt;
    size_t i;
    int status;
    char *temp_cred_file;
    apr_file_t *fp;
    apr_status_t astatus;

    if (rc->sconf->cred_cache_dir == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                     "mod_webauth: %s: cred_cache_dir is not set (%s)",
                     mwa_func, CM_CredCacheDir);
        return 0;
    }

    astatus = apr_filepath_merge(&temp_cred_file,
                                 rc->sconf->cred_cache_dir,
                                 "temp.krb5.XXXXXX",
                                 0,
                                 rc->r->pool);

    astatus = apr_file_mktemp(&fp, temp_cred_file,
                              APR_CREATE|APR_READ|APR_WRITE|APR_EXCL,
                              rc->r->pool);
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

    apr_pool_cleanup_register(rc->r->pool, temp_cred_file,
                              cred_cache_destroy,
                              apr_pool_cleanup_null);

    if (rc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                     "mod_webauth: %s: temp_cred_file mktemp(%s)",
                     mwa_func, temp_cred_file);

    ctxt = get_webauth_krb5_ctxt(rc->r->server, mwa_func);
    if (ctxt == NULL)
        return 0;

    webauth_krb5_keep_cred_cache(ctxt);

    for (i = 0; i < (size_t) creds->nelts; i++) {
        struct webauth_token_cred *cred;

        cred = APR_ARRAY_IDX(creds, i, struct webauth_token_cred *);
        if (strcmp(cred->type, "krb5") == 0) {
            if (rc->sconf->debug)
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                             "mod_webauth: %s: prepare (%s) for (%s)",
                             mwa_func, cred->service, cred->subject);
            if (i == 0) {
                status = webauth_krb5_init_via_cred(ctxt,
                                                    (void *) cred->data,
                                                    cred->data_len,
                                                    temp_cred_file);
            } else {
                status = webauth_krb5_import_cred(ctxt,
                                                  (void *) cred->data,
                                                  cred->data_len);
            }
            if (status != WA_ERR_NONE)
                log_webauth_error(rc->r->server,
                                  status, ctxt, mwa_func,
                                  i == 0 ? "webauth_krb5_init_via_cred" :
                                  "webauth_krb5_import_cred", NULL);
        }
    }
    webauth_krb5_free(ctxt);

    /* set environment variable */
    apr_table_setn(rc->r->subprocess_env, ENV_KRB5CCNAME, temp_cred_file);
    return 1;
}


static const char *
krb5_webkdc_credential(server_rec *server,
                       MWA_SCONF *sconf,
                       apr_pool_t *pool)
{
    WEBAUTH_KRB5_CTXT *ctxt;
    char *k5_req, *bk5_req;
    int status;
    size_t k5_req_len, bk5_req_len;
    static const char *mwa_func = "krb5_webkdc_credential";
    char *kt;

    ctxt = get_webauth_krb5_ctxt(server, mwa_func);
    if (ctxt == NULL)
        return 0;

    kt = apr_pstrcat(pool, "FILE:", sconf->keytab_path, NULL);

    status = webauth_krb5_init_via_keytab(ctxt, kt,
                                          sconf->keytab_principal, NULL);
    if (status != WA_ERR_NONE) {
        log_webauth_error(server, status, ctxt, mwa_func,
                          "webauth_krb5_init_via_keytab", kt);
        webauth_krb5_free(ctxt);
        return 0;
    }

    status = webauth_krb5_mk_req(ctxt, sconf->webkdc_principal,
                                 &k5_req, &k5_req_len);

    if (status != WA_ERR_NONE) {
        log_webauth_error(server, status, ctxt, mwa_func,
                          "webauth_krb5_mk_req",
                          sconf->webkdc_principal);
        webauth_krb5_free(ctxt);
        return 0;
    }
    webauth_krb5_free(ctxt);

    bk5_req_len = apr_base64_encode_len(k5_req_len);
    bk5_req = apr_palloc(pool, bk5_req_len);
    apr_base64_encode(bk5_req, k5_req, k5_req_len);
    free(k5_req);
    return bk5_req;
}

static MWA_CRED_INTERFACE krb5_cred_interface = {
    "krb5",
    krb5_validate_sad,
    krb5_prepare_creds,
    krb5_webkdc_credential
};

MWA_CRED_INTERFACE *mwa_krb5_cred_interface = &krb5_cred_interface;
