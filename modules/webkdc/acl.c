/*
 * Token ACL file handling for the Apache WebKDC module.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2003, 2006, 2009, 2012, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config-mod.h>
#include <portable/apache.h>
#include <portable/apr.h>

#include <apr_hash.h>

#include <modules/webkdc/mod_webkdc.h>

APLOG_USE_MODULE(webkdc);


/*
 * used to hold the result of reading the acl file
 *
 * keys/values are of the form:
 *  id;{subject} => int*, int set to 1
 *  cred;{proxy-type};{subject} => apr_array_header_t*, array of creds
 *
 */
typedef struct {
    apr_pool_t *pool;         /* pool to allocate new keys/values from */
    apr_hash_t *wild_entries; /* entries with a wildcard */
    apr_hash_t *entries;      /* entries without a wildcard */
} MWK_ACL;

static int
add_entry(MWK_REQ_CTXT *rc,
          MWK_ACL *acl,
          const char *subject,
          const char *entry_type,
          const char *proxy_type,
          const char *cred)
{
    apr_hash_t *hash;

    hash = ap_is_matchexp(subject) ? acl->wild_entries : acl->entries;

    if (strcmp(entry_type, "id") == 0) {
        char *key = apr_pstrcat(rc->r->pool, "id;", subject, NULL);
        void *p = apr_hash_get(hash, key, APR_HASH_KEY_STRING);
        if (p == NULL) {
            apr_hash_set(hash,
                         apr_pstrdup(acl->pool, key),
                         APR_HASH_KEY_STRING,
                         apr_pstrdup(acl->pool, "1"));
        }
        return 1;
    } else if (strcmp(entry_type, "cred") == 0) {
        char *key = apr_pstrcat(rc->r->pool,
                                "cred;",
                                proxy_type,
                                ";",
                                subject, NULL);
        apr_array_header_t *a =
            apr_hash_get(hash, key, APR_HASH_KEY_STRING);
        if (a == NULL) {
            char **c;
            a = apr_array_make(acl->pool, 5, sizeof(char*));
            c = apr_array_push(a);
            *c = (char*)apr_pstrdup(acl->pool, cred);
            apr_hash_set(hash, apr_pstrdup(acl->pool, key),
                         APR_HASH_KEY_STRING, a);
        } else {
            char **c = apr_array_push(a);
            *c = (char*)apr_pstrdup(acl->pool, cred);
        }
        return 1;
    } else {
        return 0;
    }
}


static void
log_apr_error(MWK_REQ_CTXT *rc,
             apr_status_t astatus,
             const char *mwk_func,
             const char *ap_func,
             const char *path)
{
    char errbuff[512];
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                 "mod_webkdc: %s: %s (%s): %s (%d)",
                 mwk_func,
                 ap_func,
                 path,
                 apr_strerror(astatus, errbuff, sizeof(errbuff)-1),
                 astatus);
}

/*
 * returns the cached ACL after checking to make its up to date.
 * returns NULL on error.
 *
 * Should only be called while holding the MWK_MUTEX_ACL mutex.
 *
 */
static MWK_ACL *
get_acl(MWK_REQ_CTXT *rc)
{
    static MWK_ACL *acl = NULL;
    static apr_time_t acl_mtime = 0;
    MWK_ACL *new_acl;
    const char *mwk_func="get_acl";
    apr_status_t astatus;
    apr_file_t *acl_file;
    apr_pool_t *acl_pool;
    int lineno, error;
    char line[1024];
    struct apr_finfo_t finfo;
    apr_int32_t flags;

    if (acl != NULL) {
        /* FIXME: stat and free current acl if out-of-date */
        astatus = apr_stat(&finfo, rc->sconf->token_acl_path,
                           APR_FINFO_MTIME, rc->r->pool);

        if (astatus != APR_SUCCESS) {
            log_apr_error(rc, astatus, mwk_func, "apr_file_open",
                          rc->sconf->token_acl_path);
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                         "mod_webkdc: %s: couldn't stat acl file(%s), "
                         "using previously cached acl",
                         mwk_func, rc->sconf->token_acl_path);
            return acl;
        }
        /* no change, return current acl */
        if (finfo.mtime == acl_mtime)
            return acl;
    }

    if (rc->sconf->debug) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                     "mod_webkdc: %s: %sloading acl file: %s",
                     mwk_func,
                     acl == NULL ? "" : "re",
                     rc->sconf->token_acl_path);
    }

    /* open ACL file */
    flags = APR_FOPEN_READ | APR_FOPEN_BUFFERED | APR_FOPEN_NOCLEANUP;
    astatus = apr_file_open(&acl_file, rc->sconf->token_acl_path, flags,
                            APR_FPROT_OS_DEFAULT, rc->r->pool);

    if (astatus != APR_SUCCESS) {
        log_apr_error(rc, astatus, mwk_func, "apr_file_open",
                      rc->sconf->token_acl_path);
        if (acl != NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                         "mod_webkdc: %s: couldn't open new acl file, "
                         "using previously cached acl",
                         mwk_func);
        } else {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, rc->r->server,
                         "mod_webkdc: %s: couldn't open acl file: %s",
                         mwk_func, rc->sconf->token_acl_path);
        }
        return acl;
    }

    apr_pool_create(&acl_pool, NULL);
    new_acl = (MWK_ACL*) apr_pcalloc(acl_pool, sizeof(MWK_ACL));
    new_acl->pool = acl_pool;
    new_acl->wild_entries = apr_hash_make(new_acl->pool);
    new_acl->entries = apr_hash_make(new_acl->pool);

    error = 1;

    lineno = -1;

    while ((astatus = apr_file_gets(line, sizeof(line)-1, acl_file)) ==
           APR_SUCCESS) {
        char *subject, *type;
        char *last;

        lineno++;

#if 0
        if (rc->sconf->debug) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                         "mod_webkdc: %s: read line: [%s] "
                         "file %s, line %d", mwk_func,
                         line,
                         rc->sconf->token_acl_path, lineno);
        }
#endif

        /* make sure line ends with a \n, if not it was truncated  */
        if (line[strlen(line)-1] != '\n') {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                         "mod_webkdc: %s: line too long, file %s, line %d",
                         mwk_func,
                         rc->sconf->token_acl_path, lineno);
            goto done;
        }

        if (line[0] == '#' || line[0] == '\n')
            continue;

        subject = apr_strtok(line, " \t\n", &last);

        if (subject == NULL) {
            /* blank line */
            continue;
        }

        type = apr_strtok(NULL, " \t\n", &last);

        if (type == NULL) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                             "mod_webkdc: %s: missing acl type "
                             "in file %s, line %d", mwk_func,
                             rc->sconf->token_acl_path, lineno);
                goto done;
        }

        if (strcmp(type, "cred") == 0) {
            char *proxy_type, *cred;
            proxy_type = apr_strtok(NULL, " \t\n", &last);

            if (proxy_type == NULL ||
                strcmp(proxy_type, "krb5") != 0) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                             "mod_webkdc: %s: invalid proxy type(%s) "
                             "in file %s, line %d", mwk_func,
                             proxy_type ? proxy_type : "null",
                             rc->sconf->token_acl_path, lineno);
                goto done;
            }

            cred = apr_strtok(NULL, " \t\n", &last);

            if (cred == NULL) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                             "mod_webkdc: %s: missing cred "
                             "in file %s, line %d", mwk_func,
                             rc->sconf->token_acl_path, lineno);
                goto done;
            }

            if (rc->sconf->debug) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                             "mod_webkdc: %s: adding cred access: %s %s %s",
                             mwk_func, subject, proxy_type, cred);
            }

            add_entry(rc, new_acl, subject, type, proxy_type, cred);

        } else if (strcmp(type, "id") == 0) {
            if (rc->sconf->debug) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                             "mod_webkdc: %s: adding id access: %s",
                             mwk_func, subject);
            }

            add_entry(rc, new_acl, subject, type, NULL, NULL);

        } else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                         "mod_webkdc: %s: unknown acl type(%s) "
                         "in file %s, line %d", mwk_func,
                         type, rc->sconf->token_acl_path, lineno);
            goto done;
        }
    }

    if (astatus == APR_EOF) {
        error = 0;
    } else {
        log_apr_error(rc, astatus, mwk_func, "apr_file_gets",
                      rc->sconf->token_acl_path);
        goto done;
    }

 done:

    apr_file_close(acl_file);

    /* if we had any errors, destroy new_acl, re-use old one if
       it was set */
    if (error) {
        apr_pool_destroy(new_acl->pool);
        new_acl = NULL;
        if (acl != NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                         "mod_webkdc: %s: couldn't load new acl file, "
                         "using previously cached acl",
                         mwk_func);
        }
    } else {
        /* free existing acl, set new one */
        if (acl != NULL)
            apr_pool_destroy(acl->pool);
        acl = new_acl;

        if (rc->sconf->debug) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                         "mod_webkdc: %s: acl file loaded ok: %s",
                         mwk_func,
                         rc->sconf->token_acl_path);
        }
    }

    return acl;
}

int
mwk_has_service_access(MWK_REQ_CTXT *rc,
                      const char *subject)
{
    /* for now this is defined as having access to an id token */
    return mwk_has_id_access(rc, subject);
}

int
mwk_has_id_access(MWK_REQ_CTXT *rc,
                  const char *subject)
{
    char *key = apr_pstrcat(rc->r->pool, "id;", subject, NULL);
    apr_hash_index_t *hi;
    void *p;
    int allowed;
    MWK_ACL *acl;

    allowed = 0;

    mwk_lock_mutex(rc, MWK_MUTEX_TOKENACL); /****** LOCKING! ************/

    acl = get_acl(rc);
    if (acl == NULL)
        goto done;

    /* check non-wild first */
    p = apr_hash_get(acl->entries, key, APR_HASH_KEY_STRING);
    if (p != NULL) {
        allowed = 1;
        goto done;
    }

    /* enumerate through all the wild entries */
    for (hi = apr_hash_first(rc->r->pool, acl->wild_entries); hi;
         hi = apr_hash_next(hi)) {
        const void *vhkey;
        const char *hkey;

        apr_hash_this(hi, &vhkey, NULL, &p);
        hkey = vhkey;
        if (strncmp(hkey, "id;", 3) == 0) {
            if (ap_strcmp_match(subject, hkey+3) == 0) {
                allowed = 1;
                goto done;
            }
        }
    }

 done:
    mwk_unlock_mutex(rc, MWK_MUTEX_TOKENACL); /****** UNLOCKING! ************/

    if (rc->sconf->debug) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                     "mod_webkdc: mwk_has_id_access: %s => %d",
                     subject, allowed);
    }

    return allowed;
}

int
mwk_has_proxy_access(MWK_REQ_CTXT *rc,
                     const char *subject,
                     const char *proxy_type)
{
    apr_hash_index_t *hi;
    void *p;
    char *prefix, *key;
    int plen, allowed;
    MWK_ACL *acl;

    allowed = 0;

    mwk_lock_mutex(rc, MWK_MUTEX_TOKENACL); /****** LOCKING! ************/

    acl = get_acl(rc);
    if (acl == NULL)
        goto done;

    prefix = apr_pstrcat(rc->r->pool, "cred;", proxy_type, ";", NULL);
    key = apr_pstrcat(rc->r->pool, prefix, subject, NULL);

    /* check non-wild first */
    p = apr_hash_get(acl->entries, key, APR_HASH_KEY_STRING);
    if (p != NULL) {
        allowed = 1;
        goto done;
    }

    plen = strlen(prefix);

    /* enumerate through all the wild entries */
    for (hi = apr_hash_first(rc->r->pool, acl->wild_entries); hi;
         hi = apr_hash_next(hi)) {
        const void *vhkey;
        const char *hkey;

        apr_hash_this(hi, &vhkey, NULL, &p);
        hkey = vhkey;
        if (strncmp(hkey, prefix, plen) == 0) {
            if (ap_strcmp_match(subject, hkey+plen) == 0) {
                allowed = 1;
                goto done;
            }
        }
    }

 done:
    mwk_unlock_mutex(rc, MWK_MUTEX_TOKENACL); /****** UNLOCKING! ************/

    if (rc->sconf->debug) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                     "mod_webkdc: mwk_has_proxy_access: %s, %s => %d",
                     subject, proxy_type, allowed);
    }

    return allowed;
}

int
mwk_has_cred_access(MWK_REQ_CTXT *rc,
                    const char *subject,
                    const char *cred_type,
                    const char *cred)
{
    apr_hash_index_t *hi;
    void *va;
    apr_array_header_t *a;
    char *prefix, *key;
    int plen, i, allowed;
    MWK_ACL *acl;

    allowed = 0;

    mwk_lock_mutex(rc, MWK_MUTEX_TOKENACL); /****** LOCKING! ************/

    acl = get_acl(rc);
    if (acl == NULL)
        goto done;

    prefix = apr_pstrcat(rc->r->pool, "cred;", cred_type, ";", NULL);
    key = apr_pstrcat(rc->r->pool, prefix, subject, NULL);

    /* check non-wild first */
    a = apr_hash_get(acl->entries, key, APR_HASH_KEY_STRING);
    if (a != NULL) {
        char **p = (char**)a->elts;
        for (i=0; i < a->nelts; i++) {
            if (strcmp(p[i], cred) == 0) {
                allowed = 1;
                goto done;
            }
        }
    }

    plen = strlen(prefix);

    /* enumerate through all the wild entries */
    for (hi = apr_hash_first(rc->r->pool, acl->wild_entries); hi;
         hi = apr_hash_next(hi)) {
        const void *vhkey;
        const char *hkey;

        apr_hash_this(hi, &vhkey, NULL, &va);
        hkey = vhkey;
        a = va;
        if (strncmp(hkey, prefix, plen) == 0) {
            if (ap_strcmp_match(subject, hkey + plen) == 0) {
                char **p = (char **) a->elts;
                for (i = 0; i < a->nelts; i++) {
                    if (strcmp(p[i], cred) == 0) {
                        allowed = 1;
                        goto done;
                    }
                }
            }
        }
    }

 done:
    mwk_unlock_mutex(rc, MWK_MUTEX_TOKENACL); /****** UNLOCKING! ************/

    if (rc->sconf->debug) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                     "mod_webkdc: mwk_has_cred_access: %s, %s, %s => %d",
                     subject, cred_type, cred, allowed);
    }

    return allowed;
}


int
mwk_can_use_proxy_token(MWK_REQ_CTXT *rc,
                        const char *subject,
                        const char *proxy_subject)
{
    int allowed;

    allowed = (strcmp(subject, proxy_subject) == 0) ||
        (strncmp(proxy_subject, "WEBKDC:", 7) == 0);

   if (rc->sconf->debug) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                     "mod_webkdc: mwk_can_use_proxy_token: %s, %s, => %d",
                     subject, proxy_subject, allowed);
    }

    return allowed;
}
