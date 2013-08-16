/*
 * Utility functions for Apache WebKDC module.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2003, 2009, 2011, 2012, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config-mod.h>
#include <portable/apache.h>
#include <portable/apr.h>

#include <apr_errno.h>
#include <apr_thread_mutex.h>
#include <stdlib.h>
#include <unistd.h>

#include <modules/webkdc/mod_webkdc.h>
#include <webauth/basic.h>
#include <webauth/keys.h>
#include <webauth/krb5.h>

APLOG_USE_MODULE(webkdc);

/* Initiaized in child. */
static apr_thread_mutex_t *mwk_mutex[MWK_MUTEX_MAX];

/* The increment used for resizing an MWK_STRING. */
#define CHUNK_SIZE 4096


/*
 * Initialize our mutexes.  This is stubbed out if we don't have threads.
 */
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
                         "apr_thread_mutex_create(%d): %s (%d)", i,
                         apr_strerror(astatus, errbuff, sizeof(errbuff)),
                         astatus);
            mwk_mutex[i] = NULL;
        }
    }
#endif
}


/*
 * Lock or unlock a mutex.  The type is the mutex to lock or unlock, and the
 * last parameter says whether to lock it (if true) or unlock it (if false).
 * This is stubbed out if there are no threads.  This is the underlying
 * routine beneath the public functions to lock and unlock mutexes.
 *
 * FIXME: Currently, if this fails, we log an error but then continue on and
 * hope there is no problem.  We should probably fail harder.
 */
static void
lock_or_unlock_mutex(MWK_REQ_CTXT *rc, enum mwk_mutex_type type, int lock)
{
#if APR_HAS_THREADS
    apr_status_t astatus;

    if (type >= MWK_MUTEX_MAX) {
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


/*
 * Lock a mutex.  Takes the type of the mutex.
 */
void
mwk_lock_mutex(MWK_REQ_CTXT *rc, enum mwk_mutex_type type)
{
    lock_or_unlock_mutex(rc, type, 1);
}


/*
 * Unlock a mutex.  Takes the type of the mutex.
 */
void
mwk_unlock_mutex(MWK_REQ_CTXT *rc, enum mwk_mutex_type type)
{
    lock_or_unlock_mutex(rc, type, 0);
}


/*
 * Given an APR pool, initialize an MWK_STRING structure and set its pool to
 * use that pool.
 */
void
mwk_init_string(MWK_STRING *string, apr_pool_t *pool)
{
    memset(string, 0, sizeof(MWK_STRING));
    string->pool = pool;
}


/*
 * Given an MWA_STRING, append some new data to it.  The size of the data is
 * optional; if not given, it will be determined via strlen on in_data.  If
 * in_size is given, in_data may contain embedded nuls.  However, the string
 * is always nul-terminated.
 */
void
mwk_append_string(MWK_STRING *string, const char *in_data, size_t in_size)
{
    size_t needed_size;

    if (in_size == 0)
        in_size = strlen(in_data);
    needed_size = string->size + in_size;

    if (string->data == NULL || needed_size > string->capacity) {
        char *new_data;

        while (string->capacity < needed_size + 1)
            string->capacity += CHUNK_SIZE;
        new_data = apr_palloc(string->pool, string->capacity);
        if (string->data != NULL)
            memcpy(new_data, string->data, string->size);

        /* We don't have to free existing data since it from a pool. */
        string->data = new_data;
    }
    memcpy(string->data+string->size, in_data, in_size);
    string->size = needed_size;

    /* Always nul-terminate.  We have space becase of the +1 above. */
    string->data[string->size] = '\0';
}


/*
 * Get a Kerberos context, with logging if it fails.  Return NULL if the call
 * fails for some reason.
 */
struct webauth_krb5 *
mwk_get_webauth_krb5_ctxt(struct webauth_context *ctx, request_rec *r,
                          const char *mwk_func)
{
    struct webauth_krb5 *kc;
    int status;

    status = webauth_krb5_new(ctx, &kc);
    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(ctx, r->server, status, mwk_func,
                              "webauth_krb5_new", NULL);
        return NULL;
    }
    return kc;
}


/*
 * Return the error message from an error return from libwebauth.  Either
 * returns the Kerberos error or the general WebAuth error.  Takes the request
 * struct, the status return from libwebauth, the Kerberos context, the name
 * of the function in which the error occurred, and any extra data that should
 * be added to the message.
 */
char *
mwk_webauth_error_message(struct webauth_context *ctx, request_rec *r,
                          int status, const char *webauth_func,
                          const char *extra)
{
    return apr_psprintf(r->pool, "%s%s%s error: %s (%d)", webauth_func,
                        extra == NULL ? "" : " ",
                        extra == NULL ? "" : extra,
                        webauth_error_message(ctx, status), status);
}


/*
 * The same as mwk_webauth_error_message, except that it just logs the message
 * rather than returning it.
 */
void
mwk_log_webauth_error(struct webauth_context *ctx, server_rec *serv,
                      int status, const char *mwk_func, const char *func,
                      const char *extra)
{

    ap_log_error(APLOG_MARK, APLOG_ERR, 0, serv,
                 "mod_webkdc: %s: %s%s%s failed: %s (%d)", mwk_func, func,
                 extra == NULL ? "" : " ",
                 extra == NULL ? "" : extra,
                 webauth_error_message(ctx, status), status);
}


/*
 * Update the keyring for the WebKDC server, returning a WebAuth keyring
 * status code and logging the results.  This also takes care of setting
 * ownership permissions for the keyring.
 */
int
mwk_cache_keyring(server_rec *serv, struct config *sconf)
{
    int status;
    enum webauth_kau_status kau_status;
    int update_status;
    static const char *mwk_func = "mwk_init_keyring";

    status = webauth_keyring_auto_update(sconf->ctx, sconf->keyring_path,
                 sconf->keyring_auto_update,
                 sconf->keyring_auto_update ? sconf->key_lifetime : 0,
                 &sconf->ring, &kau_status, &update_status);
    if (status != WA_ERR_NONE) {
        mwk_log_webauth_error(sconf->ctx, serv, status, mwk_func,
                              "webauth_keyring_auto_update",
                              sconf->keyring_path);
    } else {
        /*
         * We have to make sure the Apache child processes have access to the
         * keyring file.
         */
        if (geteuid() == 0)
            if (chown(sconf->keyring_path, ap_unixd_config.user_id, -1) < 0)
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, serv,
                             "mod_webkdc: %s: cannot chown keyring: %s",
                             mwk_func, sconf->keyring_path);
    }
    if (kau_status == WA_KAU_UPDATE && update_status != WA_ERR_NONE) {
        mwk_log_webauth_error(sconf->ctx, serv, status, mwk_func,
                                  "webauth_keyring_auto_update",
                                  sconf->keyring_path);
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, serv,
                         "mod_webkdc: %s: couldn't update ring: %s",
                         mwk_func, sconf->keyring_path);
    }

    /*
     * If debugging is enabled, log a message every time we update the
     * keyring.
     */
    if (sconf->debug) {
        const char *msg;

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
