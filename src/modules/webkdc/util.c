
/*
 * utility stuff
 */

#include "mod_webkdc.h"

/* initiaized in child */
static apr_thread_mutex_t *mwk_mutex[MWK_MUTEX_MAX];

void
mwk_init_mutexes(server_rec *s)
{
#if APR_HAS_THREADS
    int i;
    apr_status_t astatus;
    char errbuff[512];

    for (i=0; i < MWK_MUTEX_MAX; i++) {
        astatus = apr_thread_mutex_create(&mwk_mutex[i],
                                          APR_THREAD_MUTEX_DEFAULT,
                                          s->process->pool);
        if (astatus != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "mod_webkdc: mwk_init_mutex: "
                         "apr_thread_mutex_create(%d): %s (%d)",
                         i,
                         apr_strerror(astatus, errbuff, sizeof(errbuff)),
                         astatus);
            mwk_mutex[i] = NULL;
        }
    }
#endif
}

static void
lock_or_unlock_mutex(MWK_REQ_CTXT *rc, enum mwk_mutex_type type, int lock)
{
#if APR_HAS_THREADS

    apr_status_t astatus;

    if (type < 0 || type >= MWK_MUTEX_MAX) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                     "mod_webkdc: lock_mutex: invalid type (%d) ignored", 
                     type);
        return;
    }
        
    if (mwk_mutex[type] != NULL) {
        if (lock)
            astatus = apr_thread_mutex_lock(mwk_mutex[type]);
        else 
            astatus = apr_thread_mutex_unlock(mwk_mutex[type]);

        if (astatus != APR_SUCCESS) {
            char errbuff[512];
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                         "mod_webkdc: lock_mutex(%d,%d): %s (%d)",
                         type, lock, 
                         apr_strerror(astatus, errbuff, sizeof(errbuff)-1),
                         astatus);
            /* FIXME: now what? */
        }
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                     "mod_webkdc: lock_mutex: mutex(%d) is NULL", type);
        /* FIXME: now what? */
        }
#endif
}

void
mwk_lock_mutex(MWK_REQ_CTXT *rc, enum mwk_mutex_type type)
{
    lock_or_unlock_mutex(rc, type, 1);
}

void
mwk_unlock_mutex(MWK_REQ_CTXT *rc, enum mwk_mutex_type type)
{
    lock_or_unlock_mutex(rc, type, 0);
}

/*
 *
 */
void 
mwk_init_string(MWK_STRING *string, apr_pool_t *pool)
{
    memset(string, 0, sizeof(MWK_STRING));
    string->pool = pool;
}

#define CHUNK_SIZE 4096

/*
 * given an MWA_STRING, append some new data to it.
 */
void 
mwk_append_string(MWK_STRING *string, const char *in_data, int in_size)
{
    int needed_size;

    if (in_size == 0)
        in_size = strlen(in_data);

    needed_size = string->size+in_size;

    if (string->data == NULL || needed_size > string->capacity) {
        char *new_data;
        while (string->capacity < needed_size+1)
            string->capacity += CHUNK_SIZE;

        new_data = apr_palloc(string->pool, string->capacity);

        if (string->data != NULL) {
            memcpy(new_data, string->data, string->size);
        } 
        /* don't have to free existing data since it from a pool */
        string->data = new_data;
    }
    memcpy(string->data+string->size, in_data, in_size);
    string->size = needed_size;
    /* always null-terminate, we have space becase of the +1 above */
    string->data[string->size] = '\0';
}

/*
 * get a required char* attr from a token, with logging if not present.
 * returns value or NULL on error,
 */
char *
mwk_get_str_attr(WEBAUTH_ATTR_LIST *alist, 
                 const char *name, 
                 request_rec *r, 
                 const char *func,
                 int *vlen)
{
    int status, i;

    status = webauth_attr_list_find(alist, name, &i);
    if (i == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "mod_webkdc: %s: can't find attr(%s) in attr list",
                     func, name);
        return NULL;
    }
    if (vlen) 
        *vlen = alist->attrs[i].length;

    return (char*)alist->attrs[i].value;
}

/*
 * get a WEBAUTH_KRB5_CTXT
 */
WEBAUTH_KRB5_CTXT *
mwk_get_webauth_krb5_ctxt(request_rec *r, const char *mwk_func)
{
    WEBAUTH_KRB5_CTXT *ctxt;
    int status;

    status = webauth_krb5_new(&ctxt);
    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(r->server, status, ctxt, mwk_func,
                              "webauth_krb5_new", NULL);
        if (status == WA_ERR_KRB5)
            webauth_krb5_free(ctxt);
        return NULL;
    }
    return ctxt;
}


char *
mwk_webauth_error_message(request_rec *r, 
                          int status, 
                          WEBAUTH_KRB5_CTXT *ctxt,
                          const char *webauth_func,
                          const char *extra)
{
    if (status == WA_ERR_KRB5 && ctxt != NULL) {
        return apr_psprintf(r->pool,
                            "%s%s%s failed: %s (%d): %s %d",
                            webauth_func,
                            extra == NULL ? "" : " ",
                            extra == NULL ? "" : extra,
                            webauth_error_message(status), status,
                            webauth_krb5_error_message(ctxt), 
                            webauth_krb5_error_code(ctxt));
    } else {
        return apr_psprintf(r->pool,
                            "%s%s%s failed: %s (%d)",
                            webauth_func,
                            extra == NULL ? "" : " ",
                            extra == NULL ? "" : extra,
                            webauth_error_message(status), status);
    }
}

void
mwk_log_webauth_error(server_rec *serv,
                      int status, 
                      WEBAUTH_KRB5_CTXT *ctxt,
                      const char *mwk_func,
                      const char *func,
                      const char *extra)
{

    if (status == WA_ERR_KRB5 && ctxt != NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, serv,
                 "mod_webkdc: %s:%s%s%s failed: %s (%d): %s %d",
                     mwk_func,
                     func,
                     extra == NULL ? "" : " ",
                     extra == NULL ? "" : extra,
                     webauth_error_message(status), status,
                     webauth_krb5_error_message(ctxt), 
                     webauth_krb5_error_code(ctxt));
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, serv,
                     "mod_webkdc: %s:%s%s%s failed: %s (%d)",
                     mwk_func,
                     func,
                     extra == NULL ? "" : " ",
                     extra == NULL ? "" : extra,
                     webauth_error_message(status), status);
    }
}


int
mwk_cache_keyring(server_rec *serv, MWK_SCONF *sconf)
{
    int status;
    WEBAUTH_KAU_STATUS kau_status;
    WEBAUTH_ERR update_status;

    static const char *mwk_func = "mwk_init_keyring";

    status = webauth_keyring_auto_update(sconf->keyring_path, 
                                         sconf->keyring_auto_update,
                                         sconf->keyring_key_lifetime,
                                         &sconf->ring,
                                         &kau_status,
                                         &update_status);

    if (status != WA_ERR_NONE) {
            mwk_log_webauth_error(serv, status, NULL,
                                  mwk_func, 
                                  "webauth_keyring_auto_update",
                                  sconf->keyring_path);
    } else {
        /* #if taken from ssl_scache_dbm.c */
#if !defined(OS2) && !defined(WIN32) && !defined(BEOS) && !defined(NETWARE)
    /*
     * We have to make sure the Apache child processes have access to
     * the keyring file.
     */
    if (geteuid() == 0 /* is superuser */) {
        chown(sconf->keyring_path, unixd_config.user_id, -1);
    }
#endif
    }

    if (kau_status == WA_KAU_UPDATE && update_status != WA_ERR_NONE) {
            mwk_log_webauth_error(serv, status, NULL,
                                  mwk_func, 
                                  "webauth_keyring_auto_update",
                                  sconf->keyring_path);
            /* complain even more */
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, serv,
                         "mod_webkdc: %s: couldn't update ring: %s",
                         mwk_func, sconf->keyring_path);
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
                     "mod_webkdc: %s key ring: %s", msg, sconf->keyring_path);
    }

    return status;
}
