/*
 * utility stuff
 */

#include "mod_webauth.h"

/*
 * get a required char* attr from a token, with logging if not present.
 * returns value or NULL on error,
 */
char *
mwa_get_str_attr(WEBAUTH_ATTR_LIST *alist, 
                 const char *name, 
                 request_rec *r, 
                 const char *func,
                 int *vlen)
{
    int status, i;

    status = webauth_attr_list_find(alist, name, &i);
    if (i == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "mod_webauth: %s: can't find attr(%s) in attr list",
                     func, name);
        return NULL;
    }
    if (vlen) 
        *vlen = alist->attrs[i].length;

    return (char*)alist->attrs[i].value;
}

/*
 * get note from main request 
 */
const char *
mwa_get_note(request_rec *r, const char *note)
{
    if (r->main) {
        return apr_table_get(r->main->notes, note);
    } else {
        return apr_table_get(r->notes, note);
    }
}

/*
 * remove note from main request, and return it if it was set, or NULL
 * if unset
 */
char *
mwa_remove_note(request_rec *r, const char *note)
{
    const char *val;
    if (r->main)
        r = r->main;

    val = apr_table_get(r->notes, note);

    if (val != NULL)
        apr_table_unset(r->notes, note);

    return (char*)val;
}

/*
 * set note in main request. does not make copy of data
 */
void
mwa_setn_note(request_rec *r, const char *note, const char *val)
{
    if (r->main) {
        apr_table_setn(r->main->notes, note, val);
    } else {
        apr_table_setn(r->notes, note, val);
    }
}

void
mwa_log_apr_error(server_rec *server,
                  apr_status_t astatus,
                  const char *mwa_func,
                  const char *ap_func,
                  const char *path1,
                  const char *path2)
{
    char errbuff[512];
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, 
                 "mod_webauth: %s: %s (%s%s%s): %s (%d)",
                 mwa_func,
                 ap_func,
                 path1,
                 path2 != NULL ? " -> " : "",
                 path2 != NULL ? path2  : "",
                 apr_strerror(astatus, errbuff, sizeof(errbuff)-1),
                 astatus);
}


/*
 * log interesting stuff from the request
 */
void 
mwa_log_request(request_rec *r, const char *msg)
{
#define LOG_S(a,b) ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, \
              "mod_webauth: %s(%s)", a, (b != NULL)? b:"(null)");
#define LOG_D(a,b) ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, \
              "mod_webauth: %s(%d)", a, b);

    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                 "mod_webauth: -------------- %s ------------------", msg);

    LOG_S("ap_auth_type", ap_auth_type(r));
    LOG_S("the_request", r->the_request);
    LOG_S("unparsed_uri", r->unparsed_uri);
    LOG_S("uri", r->uri);
    LOG_S("filename", r->filename);
    LOG_S("canonical_filename", r->canonical_filename);
    LOG_S("path_info", r->path_info);
    LOG_S("args", r->args);
    LOG_D("rpu->is_initialized", r->parsed_uri.is_initialized);
    LOG_S("rpu->query", r->parsed_uri.query);

    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                 "mod_webauth: -------------- %s ------------------", msg);

#undef LOG_S
#undef LOG_D
}

/*
 * get a WEBAUTH_KRB5_CTXT
 */
WEBAUTH_KRB5_CTXT *
mwa_get_webauth_krb5_ctxt(server_rec *server, const char *mwa_func)
{
    WEBAUTH_KRB5_CTXT *ctxt;
    int status;

    status = webauth_krb5_new(&ctxt);
    if (status != WA_ERR_NONE) {
        mwa_log_webauth_error(server, 
                              status, ctxt, mwa_func, "webauth_krb5_new",
                              NULL);
        if (status == WA_ERR_KRB5)
            webauth_krb5_free(ctxt);
        return NULL;
    }
    return ctxt;
}


void
mwa_log_webauth_error(server_rec *s, 
                       int status, 
                      WEBAUTH_KRB5_CTXT *ctxt,
                      const char *mwa_func,
                      const char *func,
                      const char *extra)
{
    if (status == WA_ERR_KRB5 && ctxt != NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "mod_webauth: %s: %s%s%s failed: %s (%d): %s %d",
                     mwa_func, func,
                     extra == NULL ? "" : " ",
                     extra == NULL ? "" : extra,
                     webauth_error_message(status), status,
                     webauth_krb5_error_message(ctxt), 
                     webauth_krb5_error_code(ctxt));
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "mod_webauth: %s: %s%s%s failed: %s (%d)",
                     mwa_func,
                     func,
                     extra == NULL ? "" : " ",
                     extra == NULL ? "" : extra,
                     webauth_error_message(status), status);
    }
}

int
mwa_cache_keyring(server_rec *serv, MWA_SCONF *sconf)
{
    int status;
    WEBAUTH_KAU_STATUS kau_status;
    WEBAUTH_ERR update_status;

    static const char *mwa_func = "mwa_cache_keyring";

    status = webauth_keyring_auto_update(sconf->keyring_path, 
                                         sconf->keyring_auto_update,
                                         sconf->keyring_key_lifetime,
                                         &sconf->ring,
                                         &kau_status,
                                         &update_status);

    if (status != WA_ERR_NONE) {
            mwa_log_webauth_error(serv, status, NULL,
                                  mwa_func, 
                                  "webauth_keyring_auto_update",
                                  sconf->keyring_path);
    }

    if (kau_status == WA_KAU_UPDATE && update_status != WA_ERR_NONE) {
            mwa_log_webauth_error(serv, status, NULL,
                                  mwa_func, 
                                  "webauth_keyring_auto_update",
                                  sconf->keyring_path);
            /* complain even more */
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, serv,
                         "mod_webauth: %s: couldn't update ring: %s",
                         mwa_func, sconf->keyring_path);
    }

    if (sconf->debug) {
        char *msg;
        if (kau_status == WA_KAU_NONE) 
            msg = "opened";
        else if (kau_status == WA_KAU_CREATE)
            msg = "create";
        else if (kau_status == WA_KAU_UPDATE)
            msg = "updated";
        else
            msg = "<unknown>";
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, serv,
                     "mod_webauth: %s key ring: %s", msg, sconf->keyring_path);
    }

    return status;
}

apr_array_header_t *
mwa_get_webauth_cookies(request_rec *r)
{
    char *c;
    char *last, *val;
    apr_array_header_t *a;
    char **p;

    c = (char*) apr_table_get(r->headers_in, "Cookie");

    if (c == NULL || (ap_strstr(c, "webauth_") == NULL))
        return NULL;

    c = apr_pstrdup(r->pool, c);

    last = NULL;
    a = NULL;
    val = apr_strtok(c, ";\0", &last);

    while(val) {
        while (*val && *val==' ') {
            val++;
        }
        if (strncmp(val, "webauth_", 8) == 0) {
            if (a == NULL) {
                a = apr_array_make(r->pool, 5, sizeof(char*));
            }
            p = apr_array_push(a);
            *p = val;
        }
        val = apr_strtok(NULL, ";\0", &last);
    }
    return a;
}



/*
 * parse a cred-token. return pointer to it on success, NULL on failure.
 */

MWA_CRED_TOKEN *
mwa_parse_cred_token(char *token, 
                     WEBAUTH_KEYRING *ring,
                     WEBAUTH_KEY *key, 
                     MWA_REQ_CTXT *rc)
{
    WEBAUTH_ATTR_LIST *alist;
    int blen, status;
    const char *tt;
    MWA_CRED_TOKEN ct, *nct;
    const char *mwa_func="mwa_parse_cred_token";

    ap_unescape_url(token);
    blen = apr_base64_decode(token, token);
    status = WA_ERR_NONE;
    nct = NULL;

    /* parse the token, TTL is zero because cred-tokens don't have ttl,
     * just expiration
     */


    if (key != NULL) {
        status = webauth_token_parse_with_key(token, blen, 0, key, &alist);
    } else if (ring != NULL){
        status = webauth_token_parse(token, blen, 0, ring, &alist);
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                     "mod_webauth: %s: callled with NULL key and ring!",
                     mwa_func);
        return NULL;
    } 
        

    if (status != WA_ERR_NONE) {
        mwa_log_webauth_error(rc->r->server, status, NULL,
                              mwa_func, "webauth_token_parse", NULL);
        return NULL;
    }

    /* make sure its a cred-token */
    tt = mwa_get_str_attr(alist, WA_TK_TOKEN_TYPE, rc->r, mwa_func, NULL);
    if (tt == NULL || strcmp(tt, WA_TT_CRED) != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                     "mod_webauth: %s: token type(%s) not (%s)",
                     mwa_func, tt ? tt : "(null)", WA_TT_CRED);
        goto cleanup;
    }

    /* pull out subject */
    ct.subject = mwa_get_str_attr(alist, WA_TK_SUBJECT, rc->r, mwa_func, NULL);
    
    if (ct.subject == NULL) {
        goto cleanup;
    }

    /* pull out type */
    ct.cred_type = mwa_get_str_attr(alist, WA_TK_CRED_TYPE,
                                    rc->r, mwa_func, NULL);
    if (ct.cred_type == NULL) {
        goto cleanup;
    }

    /* pull out type */
    ct.cred_server = mwa_get_str_attr(alist, WA_TK_CRED_SERVER,
                                      rc->r, mwa_func, NULL);
    if (ct.cred_server == NULL) {
        goto cleanup;
    }

    webauth_attr_list_get_time(alist, WA_TK_CREATION_TIME,
                               &ct.creation_time, WA_F_NONE);

    webauth_attr_list_get_time(alist, WA_TK_EXPIRATION_TIME,
                               &ct.expiration_time, WA_F_NONE);

    status = webauth_attr_list_get(alist, WA_TK_CRED_DATA,
                                   &ct.cred_data, 
                                   &ct.cred_data_len, WA_F_NONE);

    if (status != WA_ERR_NONE) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                     "mod_webauth: %s: "
                     "can't get cred data from proxy-token",
                     mwa_func);
        goto cleanup;
    }

    nct = (MWA_CRED_TOKEN*)apr_pcalloc(rc->r->pool, sizeof(MWA_CRED_TOKEN));

    /* need to strdup/copy stuff into the request pool */
    nct->cred_type = apr_pstrdup(rc->r->pool, ct.cred_type);
    nct->cred_server = apr_pstrdup(rc->r->pool, ct.cred_server);
    nct->subject = apr_pstrdup(rc->r->pool, ct.subject);
    nct->creation_time = ct.creation_time;
    nct->expiration_time = ct.expiration_time;
    nct->cred_data = 
        apr_pstrmemdup(rc->r->pool, ct.cred_data, ct.cred_data_len);
    nct->cred_data_len = ct.cred_data_len;

 cleanup:
    webauth_attr_list_free(alist);
    return nct;
}
