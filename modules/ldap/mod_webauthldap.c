/*
 * Core WebAuth LDAP Apache module code.
 *
 * Written by Anton Ushakov
 * Copyright 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config-mod.h>
#include <portable/apache.h>
#include <portable/apr.h>
#include <portable/krb5.h>

#include <apr.h>
#include <apr_base64.h>
#include <apr_errno.h>
#include <apr_file_info.h>
#include <apr_file_io.h>
#include <apr_lib.h>
#include <apr_signal.h>
#include <apr_thread_mutex.h>
#include <apr_xml.h>
#include <errno.h>
#include <ldap.h>
#ifdef HAVE_MOD_AUTH_H
# include <mod_auth.h>
#endif
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <modules/ldap/mod_webauthldap.h>
#include <util/macros.h>

APLOG_USE_MODULE(webauthldap);


/**
 * This gets called by SASL to handle the user "auth interaction", like
 * reading the password, etc. In our case it's a no-op. The function signature
 * must comply exactly, but the arguments are discarded in this case.
 */
static int
sasl_interact_stub(LDAP *ld UNUSED, unsigned flags UNUSED,
                   void *defaults UNUSED, void *in UNUSED)
{
    return LDAP_SUCCESS;
}


/**
 * Called during server startup to initialize this module.
 */
static int
post_config_hook(apr_pool_t *pconf, apr_pool_t *plog UNUSED,
                 apr_pool_t *ptemp UNUSED, server_rec *s)
{
    server_rec *scheck;
    struct server_config *sconf;
    char *tktenv;
    const char *tktcache = NULL;
    size_t size;

    sconf = ap_get_module_config(s->module_config, &webauthldap_module);
    for (scheck = s; scheck != NULL; scheck = scheck->next) {
        mwl_config_init(scheck, sconf, pconf);

        /*
         * This has to be the same for all server configuration.  For the sake
         * of convenience, grab the last one.
         */
        tktcache = sconf->tktcache;
    }

    /* Don't use pool memory for this so that the environment variable
       pointers don't become invalid when the pool is cleared. */
    if (tktcache != NULL) {
        size = strlen("KRB5CCNAME=FILE:") + strlen(tktcache) + 1;
        tktenv = malloc(size);
        if (tktenv == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "webauthldap: cannot allocate memory for ticket cache"
                         " environment variable");
            return -1;
        }
        apr_snprintf(tktenv, size, "KRB5CCNAME=FILE:%s", tktcache);
        if (putenv(tktenv) != 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "webauthldap: cannot set ticket cache environment"
                         " variable");
            return -1;
        }
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                 "mod_webauthldap: initialized");

    return OK;
}


/**
 * This inserts the userid in every marked spot in the filter string. So
 * e.g. if the marker is the string "USER", a filter like
 * ((uid=USER)|(sunetid=USER))
 * will be converted to ((uid=antonu)|(sunetid=antonu))
 * @param lc main context struct for this module, for passing things around
 * @return new filter string with userid substituted
 */
static char *
webauthldap_make_filter(MWAL_LDAP_CTXT *lc)
{
    apr_pool_t * p = lc->r->pool;
    char *userid = lc->r->user;
    char *filter_template = apr_pstrdup(lc->r->pool, lc->sconf->filter);
    char *beg = filter_template;
    char *end = filter_template;
    char *filter = NULL;
    int match_length = strlen(FILTER_MATCH);

    if (lc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                     "webauthldap(%s): filter template is %s", lc->r->user, filter_template);

    do {
        /* Everytime we find a marker */
        if (strncmp(end, FILTER_MATCH, match_length) == 0) {

            /* Can't apr_pstrcat nulls strings - that's how it tells where the
               last passed parameter is. */
            if (filter == NULL)
                filter = apr_pstrcat(p, apr_pstrndup(p, beg, end - beg),
                                     userid, NULL);
            else
                filter = apr_pstrcat(p,filter, apr_pstrndup(p, beg, end - beg),
                                     userid, NULL);

            beg = end + match_length;
        }
    } while(*(++end) != '\0');

    /* Append the last chunk. If no substitutions were done, this is the
       entire template string. */
    if (end > beg)
        filter = apr_pstrcat(p,filter, apr_pstrndup(p, beg, end - beg), NULL);

    return filter;
}

/**
 * This obtains the K5 ticket from the given keytab and places it into the
 * given credentials cache file
 * @param lc main context struct for this module, for passing things around
 * @return zero if OK, kerberos error code if not
 */
static int
webauthldap_get_ticket(MWAL_LDAP_CTXT* lc)
{
    krb5_context ctx;
    krb5_creds creds;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    krb5_get_init_creds_opt *opts;
    krb5_keytab keytab;
    krb5_ccache cc;
    krb5_principal princ = NULL;
    krb5_error_code code;
    char *kt, *cc_path;

    kt = apr_pstrcat(lc->r->pool, "FILE:", lc->sconf->keytab_path, NULL);

    /* initialize the main struct that holds kerberos context */
    if ((code = krb5_init_context(&ctx)) != 0)
        return code;

    /* locate, open, and read the keytab */
    if ((code = krb5_kt_resolve(ctx, kt, &keytab)) != 0)
        return code;

    /* if the principal has been specified via directives, use it,
       otherwise just read the first entry out of the keytab. */
    if (lc->sconf->keytab_principal) {
        code = krb5_parse_name(ctx, lc->sconf->keytab_principal, &princ);
    } else {
        if ((code = krb5_kt_start_seq_get(ctx, keytab, &cursor)) != 0) {
            krb5_kt_close(ctx, keytab);
            return code;
        }

        if ((code = krb5_kt_next_entry(ctx, keytab, &entry, &cursor)) == 0) {
            code = krb5_copy_principal(ctx, entry.principal, &princ);
            krb5_kt_free_entry(ctx, &entry);
        }
        krb5_kt_end_seq_get(ctx, keytab, &cursor);
    }

    if (code != 0) {
        krb5_kt_close(ctx, keytab);
        if (princ != NULL)
            krb5_free_principal(ctx, princ);
        return code;
    }

    /* locate and open the creadentials cache file */
    cc_path = apr_pstrcat(lc->r->pool, "FILE:", lc->sconf->tktcache, NULL);
    if ((code = krb5_cc_resolve(ctx, cc_path, &cc)) != 0) {
        krb5_kt_close(ctx, keytab);
        krb5_free_principal(ctx, princ);
        return code;
    }

    /* initialize it if necessary */
    if ((code = krb5_cc_initialize(ctx, cc, princ)) != 0) {
        krb5_kt_close(ctx, keytab);
        krb5_free_principal(ctx, princ);
        return code;
    }

    if ((code = krb5_get_init_creds_opt_alloc(ctx, &opts)) != 0) {
        krb5_kt_close(ctx, keytab);
        krb5_free_principal(ctx, princ);
        return code;
    }
    krb5_get_init_creds_opt_set_default_flags(ctx, "webauth", NULL, opts);

    /* get the tgt for this principal */
    code = krb5_get_init_creds_keytab(ctx,
                                      &creds,
                                      princ,
                                      keytab,
                                      0, /* start_time */
                                      NULL, /* in_tkt_service */
                                      opts);
    krb5_get_init_creds_opt_free(ctx, opts);
    krb5_kt_close(ctx, keytab);
    krb5_free_principal(ctx, princ);

    if (code == 0) {
        /* add the creds to the cache */
        code = krb5_cc_store_cred(ctx, cc, &creds);
        krb5_free_cred_contents(ctx, &creds);
        krb5_cc_close(ctx, cc);
    }

    krb5_free_context(ctx);

    return code;
}


/**
 * This will initialize the main context struct and set up the tables of
 * attributes and privgroups to later put into environment variables.
 * @param lc main context struct for this module, for passing things around
 * @return zero if OK, HTTP_INTERNAL_SERVER_ERROR if not
 */
static void
webauthldap_init(MWAL_LDAP_CTXT* lc)
{
    int i;
    char** attrib;
    char *p, *privgroup;
    apr_array_header_t* attribs, *oper_attribs;

    if (lc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server, "%s %s",
                     "webauthldap: invoked for user", lc->r->user);

    /* These come with defaults: */
    lc->filter = webauthldap_make_filter(lc);
    lc->port = lc->sconf->port;

    if (lc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                     "webauthldap(%s): filter is %s", lc->r->user, lc->filter);

    /* Allocate the table of attributes to later put into env vars */
    lc->envvars = apr_table_make(lc->r->pool, 5);

    /* Whatever else env vars the conf file added. This will override the
       defaults since apr_table_set is used here, and all names are
       uppercased. */
    if (lc->dconf->attribs) {
        attribs = apr_array_copy(lc->r->pool, lc->dconf->attribs);

        for(i=0; ((attrib = apr_array_pop(attribs)) != NULL); i++) {
            for (p = *attrib; *p != '\0'; p++)
                *p = toupper(*p);
            apr_table_set(lc->envvars, *attrib, *attrib);

        if (lc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                         "webauthldap(%s): conf attribute to put into env: %s",
                         lc->r->user, *attrib);
        }
    }

    if (lc->dconf->oper_attribs) {
        oper_attribs = apr_array_copy(lc->r->pool, lc->dconf->oper_attribs);

        for (i = 0; ((attrib = apr_array_pop(oper_attribs)) != NULL); i++) {
            for (p = *attrib; *p != '\0'; p++)
                *p = toupper(*p);
            apr_table_set(lc->envvars, *attrib, *attrib);

            if (lc->sconf->debug)
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                             "webauthldap(%s): oper attribute to put into env: %s",
                             lc->r->user, *attrib);
        }
    }

    /* Allocate the privgroups table, and populate its keys with the
       privgroups we've been asked to check and export. We do not care about
       the values in this table; we're only using it to generate a set of
       unique privgroup names. */
    lc->privgroups = apr_table_make(lc->r->pool, 5);
    if (lc->dconf->privgroups) {
        for(i=0; i<lc->dconf->privgroups->nelts; i++) {
            privgroup = ((char **)(lc->dconf->privgroups)->elts)[i];
            apr_table_set(lc->privgroups, privgroup, "");
            if (lc->sconf->debug)
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                             "webauthldap(%s): conf privgroup to check: %s",
                             lc->r->user, privgroup);
        }
    }

    /* Allocate table for cached privgroup results */
    lc->privgroup_cache = apr_table_make(lc->r->pool, 5);

    if (lc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                     "webauthldap(%s): initialized successfully", lc->r->user);
}



/**
 * This will set some LDAP options, initialize the ldap connection and
 * bind to the ldap server.
 * @param lc main context struct for this module, for passing things around
 * @return zero if OK, HTTP_INTERNAL_SERVER_ERROR if not
 */
static int
webauthldap_bind(MWAL_LDAP_CTXT* lc, int print_local_error)
{
    int rc;
    MWAL_SASL_DEFAULTS *defaults;
    LDAPURLDesc url;
    char *ldapuri;

    /* Initialize the connection */
    memset(&url, 0, sizeof(url));
    url.lud_scheme = (char *) "ldap";
    url.lud_host = (char *) lc->sconf->host;
    url.lud_port = lc->port;
    url.lud_scope = LDAP_SCOPE_DEFAULT;
    ldapuri = ldap_url_desc2str(&url);
    rc = ldap_initialize(&lc->ld, ldapuri);
    if (rc != LDAP_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, lc->r->server,
                     "webauthldap(%s): ldap_initialize failed with URL %s",
                     lc->r->user, ldapuri);
        free(ldapuri);
        return -1;
    }
    free(ldapuri);

    /* Set to no referrals */
    if (ldap_set_option(lc->ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF)
        != LDAP_OPT_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, lc->r->server,
                     "webauthldap(%s): Could not set LDAP_OPT_REFERRALS",
                     lc->r->user);
        return -1;
    }

    /* Only works with version 3 */
    if (ldap_set_option(lc->ld, LDAP_OPT_PROTOCOL_VERSION,
                        &lc->sconf->ldapversion)
        != LDAP_OPT_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, lc->r->server,
                     "webauthldap(%s): Could not set LDAP_OPT_PROTOCOL_VERSION %d",
                     lc->r->user, lc->sconf->ldapversion);
        return -1;
    }

    /* Turn on SSL if configured */
    if (lc->sconf->ssl) {
        rc = ldap_start_tls_s(lc->ld, NULL, NULL);

        if (rc != LDAP_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, lc->r->server,
                         "webauthldap(%s): Could not start tls: %s (%d)",
                         lc->r->user, ldap_err2string(rc), rc);
            return -1;
        }
    }

    /* Set up SASL defaults. */
    defaults = (MWAL_SASL_DEFAULTS*) apr_pcalloc(lc->r->pool,
                                                 sizeof(MWAL_SASL_DEFAULTS));
    ldap_get_option(lc->ld, LDAP_OPT_X_SASL_MECH, &defaults->mech);
    ldap_get_option(lc->ld, LDAP_OPT_X_SASL_REALM, &defaults->realm);
    ldap_get_option(lc->ld, LDAP_OPT_X_SASL_AUTHCID, &defaults->authcid);
    ldap_get_option(lc->ld, LDAP_OPT_X_SASL_AUTHZID, &defaults->authzid);

    if (!defaults->mech)
        defaults->mech = "GSSAPI";

    /* the bind itself */
    rc = ldap_sasl_interactive_bind_s(lc->ld, lc->sconf->binddn,
                                      defaults->mech, NULL, NULL,
                                      LDAP_SASL_QUIET, sasl_interact_stub,
                                      defaults);

    /* a bit of cleanup */
    if (defaults->authcid != NULL) {
        ldap_memfree (defaults->authcid);
        defaults->authcid = NULL;
    }

    /* this likely means the ticket is missing or expired,
       so we signal to try again with a fresh ticket */
    if (rc == LDAP_LOCAL_ERROR) {
        if (print_local_error)
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, lc->r->server,
                         "webauthldap(%s): ldap_sasl_interactive_bind_s: %s (%d)",
                         lc->r->user, ldap_err2string(rc), rc);
        return -2;
    } else if (rc != LDAP_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, lc->r->server,
                     "webauthldap(%s): ldap_sasl_interactive_bind_s: %s (%d)",
                     lc->r->user, ldap_err2string(rc), rc);
        return -1;
    }

    return 0;
}


/**
 * This function does bind management. It sets the ticket variable and it will
 * get a new ticket if the firt attempt to bind fails. On "local error" it will
 * retry the bind.
 * @param lc main context struct for this module, for passing things around
 * @return zero if OK, HTTP_INTERNAL_SERVER_ERROR if not
 */
static int
webauthldap_managedbind(MWAL_LDAP_CTXT* lc)
{
    int rc;
    struct stat keytab_stat;
    int fd;
    int princ_specified;

    if (lc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                     "webauthldap(%s): begins ldap bind", lc->r->user);

    rc = webauthldap_bind(lc, 0);

    if (rc == 0) { /* all good */
        if (lc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                         "webauthldap(%s): using existing ticket",
                         lc->r->user);
    } else if (rc == -1) { /* some other problem */
        return -1;
    } else if (rc == -2) { /* ticket expired */
        if (lc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                         "webauthldap(%s): getting new ticket", lc->r->user);

        /* so let's get a new ticket */
        if (stat(lc->sconf->keytab_path, &keytab_stat) < 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, lc->r->server,
                         "webauthldap(%s): cannot stat the keytab: %s %s (%d)",
                         lc->r->user,
                         lc->sconf->keytab_path, strerror(errno), errno);
            return -1;
        }

        if ((fd = open(lc->sconf->keytab_path, O_RDONLY, 0)) < 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, lc->r->server,
                         "webauthldap(%s): cannot read the keytab %s: %s (%d)",
                         lc->r->user, lc->sconf->keytab_path,
                         strerror(errno), errno);
            close(fd);
            return -1;
        }
        close(fd);

        princ_specified = lc->sconf->keytab_principal? 1:0;

        rc = webauthldap_get_ticket(lc);

        if (rc == KRB5_REALM_CANT_RESOLVE) {
            if (princ_specified)
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, lc->r->server,
                             "webauthldap(%s): cannot get ticket: %s %s %s",
                             lc->r->user, "check if the keytab",
                             lc->sconf->keytab_path,
                             "is valid for the specified principal");
            else
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, lc->r->server,
                             "webauthldap(%s): cannot get ticket: %s %s %s",
                             lc->r->user, "check if the keytab",
                             lc->sconf->keytab_path,
                             "is valid and only contains the right principal");

            return -1;
        } if (rc != 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, lc->r->server,
                         "webauthldap(%s): cannot get ticket (%d)",
                         lc->r->user, rc);
            return -1;
        }

        /* Trying the bind the second time. */

        /* TODO should clear the previous ld using unbind(lc->ld);
           but current ld->ld_error bug prevents it.
           so for now it leaks memory: */
        lc->ld = NULL;
        rc = webauthldap_bind(lc, 1);
        if (rc != 0) {
            /* now we fail totally. error messages are inside
               the webauthldap_bind function */
            return -1;
        }

    }

    if (lc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                     "webauthldap(%s): bound successfully to %s", lc->r->user,
                     lc->sconf->host);

    return 0;
}


/**
 * This function gets a cached ldap connection from the array that stores them
 * @param lc main context struct for this module, for passing things around
 * @return zero if OK, managedbind's result if not
 */
static int
webauthldap_getcachedconn(MWAL_LDAP_CTXT* lc)
{

    LDAP** newld;

    lc->ld = NULL;
    apr_thread_mutex_lock(lc->sconf->ldmutex); /****** LOCKING! ************/

    if (!apr_is_empty_array(lc->sconf->ldarray)) {
        newld = (LDAP**) apr_array_pop(lc->sconf->ldarray);
        lc->ld = *newld;
        lc->sconf->ldcount--;
        if (lc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                     "webauthldap(%s): got cached conn - cache size %d",
                     lc->r->user, lc->sconf->ldcount);
    }

    apr_thread_mutex_unlock(lc->sconf->ldmutex); /****** UNLOCKING! ********/

    return (lc->ld != NULL) ? 0 : webauthldap_managedbind(lc);

}

/**
 * This puts the connection back into the array. If no more spaces on the
 * storage array, it unbinds it.
 * @param lc main context struct for this module, for passing things around
 */
static void
webauthldap_returnconn(MWAL_LDAP_CTXT* lc)
{

    LDAP** newld = NULL;

    apr_thread_mutex_lock(lc->sconf->ldmutex); /****** LOCKING! ************/

    if (lc->sconf->ldarray->nelts < MAX_LDAP_CONN) {
        newld = apr_array_push(lc->sconf->ldarray);
        *newld = lc->ld;
        lc->sconf->ldcount++;
        if (lc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                     "webauthldap(%s): cached this conn - cache size %d",
                     lc->r->user, lc->sconf->ldcount);
    }

    apr_thread_mutex_unlock(lc->sconf->ldmutex); /****** UNLOCKING! ********/

    if (newld == NULL) {
        ldap_unbind_ext(lc->ld, NULL, NULL);
    }

}

/**
 * This will parse a given ldap entry, placing all attributes and values into
 * the given apr table. Duplicates are preserved. It also saves all privilege
 * groups (discovered as values for the authorization attribute) in our
 * context struct's privgroup_cache, in order to prevent unnecessary
 * comparisons on these values later.
 * @param lc main context struct for this module, for passing things around
 * @param entry the given LDAP entry to parse
 * @param attr_table is the table to place the attributes into
 * @return nothing
 */
static void
webauthldap_parse_entry(MWAL_LDAP_CTXT* lc, LDAPMessage * entry, apr_table_t * attr_table)
{
    char *a, *val, *dn;
    int i, is_privgroupattr;
    BerElement *ber = NULL;
    struct berval **bvals;

    /* the DN's are collected to be used in the ldap_compares of the
       privgroups */
    dn = ldap_get_dn(lc->ld, entry);
    apr_table_add(attr_table, DN_ATTRIBUTE, dn);

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                 "webauthldap(%s): retrieved entry DN = %s",
                 lc->r->user, dn);
    ldap_memfree( dn );

    /* attributes and values are stored in a table */
    for (a = ldap_first_attribute(lc->ld, entry, &ber); a != NULL;
         a = ldap_next_attribute(lc->ld, entry, ber)) {

        if (lc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                         "webauthldap(%s): got attrib: %s", lc->r->user, a);

        is_privgroupattr = !strcasecmp(a, lc->sconf->auth_attr);

        if ((bvals = ldap_get_values_len(lc->ld, entry, a)) != NULL) {
            for (i = 0; bvals[i] != NULL; i++) {
                val = apr_pstrndup(lc->r->pool, (char *)bvals[i]->bv_val,
                                   (apr_size_t) bvals[i]->bv_len);
                apr_table_add(attr_table, a, val);
                if (is_privgroupattr)
                    apr_table_set(lc->privgroup_cache, val, "TRUE");
            }
            ber_bvecfree(bvals);
        }
        ldap_memfree(a);
    }

    if (ber != NULL) {
        ber_free(ber, 0);
    }
}


/**
 * This will conduct the ldap search and parse the returned messages. It
 * all messages except entries, on which it calls ebauthldap_parse_entry
 * @param lc main context struct for this module, for passing things around
 * @return zero if OK, HTTP_INTERNAL_SERVER_ERROR if not
 */
static int
webauthldap_dosearch(MWAL_LDAP_CTXT* lc)
{
    LDAPMessage *res = NULL;
    LDAPMessage *msg = NULL;
    ber_int_t msgid;
    int rc, numMessages;
    int attrsonly = 0;

    rc = ldap_search_ext(lc->ld, lc->sconf->base, lc->sconf->scope, lc->filter,
                         lc->attrs, attrsonly, NULL, NULL, NULL,
                         LDAP_SIZELIMIT, &msgid);

    if (rc != LDAP_SUCCESS) {
        if (rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR) {
            if (lc->sconf->debug)
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, lc->r->server,
                            "webauthldap(%s): timeout during ldap_search_ext: %s (%d)",
                             lc->r->user, ldap_err2string(rc), rc);
            return HTTP_SERVICE_UNAVAILABLE;
        } else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, lc->r->server,
                         "webauthldap(%s): ldap_search_ext: %s (%d)",
                         lc->r->user, ldap_err2string(rc), rc);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if ((rc =
         ldap_result(lc->ld, LDAP_RES_ANY, LDAP_MSG_ALL, NULL, &res)) > 0) {

        numMessages = ldap_count_messages(lc->ld, res);

        if (lc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                         "webauthldap(%s): search returned %d messages",
                         lc->r->user, numMessages);

        if (numMessages > 0) {
            lc->entries = (apr_table_t **)
                apr_pcalloc(lc->r->pool,
                            (numMessages+1)*sizeof(apr_table_t *));
            lc->numEntries = 0;
            for (msg = ldap_first_message(lc->ld, res);
                 msg != NULL; msg = ldap_next_message(lc->ld, msg)) {

                if (ldap_msgtype(msg) == LDAP_RES_SEARCH_ENTRY) {
                    lc->entries[lc->numEntries] = apr_table_make(lc->r->pool,
                                                                 50);
                    webauthldap_parse_entry(lc, msg,
                                            lc->entries[lc->numEntries]);
                    lc->numEntries++;
                }
            }
            if (lc->sconf->debug)
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                             "webauthldap(%s): search returned %lu entries",
                             lc->r->user, (unsigned long) lc->numEntries);
        }
        ldap_msgfree(res);
    }

    if ((rc == -1) || (rc == 0)) {
        return HTTP_SERVICE_UNAVAILABLE;
    }


    if (lc->numEntries == 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, lc->r->server,
                     "webauthldap: user %s not found in ldap",
                     lc->r->user);

    return 0;
}


static int
webauthldap_docompare(MWAL_LDAP_CTXT* lc, const char* value)
{
    int rc;
    size_t i;
    char *dn;
    const char *attr, *cached;
    struct berval bvalue = { 0, NULL };

    attr = lc->sconf->auth_attr;

    /* Return cached result if we've performed this comparison already */
    if ((cached = apr_table_get(lc->privgroup_cache, value)) != NULL) {
        if (lc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                         "webauthldap(%s): cached %s comparing %s=%s",
                         lc->r->user, cached, attr, value);
        return strcmp(cached, "TRUE") ? LDAP_COMPARE_FALSE : LDAP_COMPARE_TRUE;
    }

    bvalue.bv_val = (char *) value;
    bvalue.bv_len = strlen(bvalue.bv_val);

    for (i=0; i<lc->numEntries; i++) {
        dn = (char*)apr_table_get(lc->entries[i], DN_ATTRIBUTE);

        rc = ldap_compare_ext_s(lc->ld, dn, attr, &bvalue, NULL, NULL);

        if (rc == LDAP_COMPARE_TRUE) {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                         "webauthldap(%s): SUCCEEDED comparing %s=%s in %s",
                         lc->r->user, attr, value, dn);
            apr_table_set(lc->privgroup_cache, value, "TRUE");
            return rc;
        } else if (rc == LDAP_COMPARE_FALSE) {
            if (lc->sconf->debug) {
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                             "webauthldap(%s): FALSE comparing %s=%s in %s",
                             lc->r->user, attr, value, dn);
            }
            apr_table_set(lc->privgroup_cache, value, "FALSE");
        } else {
            if (lc->sconf->debug) {
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                             "webauthldap(%s): %s(%d) comparing %s=%s in %s",
                             lc->r->user, ldap_err2string(rc), rc,
                             attr, value, dn);
            }
        }
    }

    return LDAP_COMPARE_FALSE;
}

/**
 * This function stores a key-value pair in a request's subprocess_env
 * table. If the key already exists (as in the case of multi-valued LDAP
 * attributes), we ensure that a new environment variable is added for the new
 * value, with the name of the var containing a sequence number at the end. No
 * particular order of values is guaranteed. If a separator is specified in
 * the server configuration, we also append that separator, then the new value
 * to the primary environment variable.
 */
static void
webauthldap_setenv(MWAL_LDAP_CTXT* lc, const char *key, const char *val)
{
    int i;
    const char *numbered_key, *existing_val, *newval;

    existing_val = (char*) apr_table_get(lc->r->subprocess_env, key);

    /* Normal case of single-valued attribute. */
    if (existing_val == NULL) {
        if (lc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                         "webauthldap(%s): setting %s as single valued",
                         lc->r->user, key);
        apr_table_set(lc->r->subprocess_env, key, val);
    } else {
        /* Set WEBAUTH_LDAP_BLAH1 to be the same as WEBAUTH_LDAP_BLAH. */
        numbered_key = apr_psprintf(lc->r->pool, "%s%d", key, 1);
        if (apr_table_get(lc->r->subprocess_env, numbered_key) == NULL) {
            if (lc->sconf->debug)
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                             "webauthldap(%s): setting %s", lc->r->user,
                             numbered_key);
            apr_table_set(lc->r->subprocess_env, numbered_key,
                          existing_val);
        }

        /* Update WEBAUTH_LDAP_BLAH if separator isn't NULL. */
        if (lc->sconf->separator != NULL) {
            newval = apr_psprintf(lc->r->pool, "%s%s%s", existing_val,
                                  lc->sconf->separator, val);
            apr_table_set(lc->r->subprocess_env, key, newval);
        }

        /* now set WEBAUTH_LDAP_BLAH2 WEBAUTH_LDAP_BLAH3 and so on */
        i = 2;
        while (1) {
            numbered_key = apr_psprintf(lc->r->pool, "%s%d", key, i);
            if (apr_table_get(lc->r->subprocess_env, numbered_key) == NULL) {
                if (lc->sconf->debug)
                    ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                                 "webauthldap(%s): setting %s", lc->r->user,
                                 numbered_key);
                apr_table_set(lc->r->subprocess_env, numbered_key, val);
                break;
            }
            i++;
        }
    }
}

/**
 * This will be called with every attribute value pair that was received
 * from the LDAP search. Only attributes that were requested through the conf
 * directives as well as a few default attributes will be placed in
 * environment variables starting with "WEBAUTH_LDAP_".
 *
 * Multi-valued attributes are stored in numbered variables (and optionally
 * as a concatenated string in the normal variable, if a separator is set)
 * by webauthldap_setenv, above.
 *
 * @param lcp main context struct for this module, for passing things around
 * @param key the attribute name, as supplied by LDAP api
 * @param val the value of the attribute
 * @return always 1, which means keep going through the table
 */
static int
webauthldap_exportattrib(void* lcp, const char *key, const char *val)
{
    char *newkey, *p;
    MWAL_LDAP_CTXT* lc = (MWAL_LDAP_CTXT*) lcp;

    if ((key == NULL) || (val == NULL))
        return 1;

    /* conf directive could have been in different capitalization,
       simpler to just uppercase for the comparison */
    newkey = apr_pstrdup(lc->r->pool, key);
    for (p = newkey; *p != '\0'; p++)
        *p = toupper(*p);

    /* set into the environment only those attributes, which were specified */
    if (!apr_table_get(lc->envvars, newkey))
        return 1;

    /* to keep track which ones we have already seen */
    apr_table_set(lc->envvars, newkey, "placed in env vars");

#ifndef NO_STANFORD_SUPPORT
    if (strcasecmp(newkey, "MAIL") == 0 && lc->legacymode) {
        apr_table_set(lc->r->subprocess_env, "SU_AUTH_DIRMAIL", val);
    } else if (strcasecmp(newkey, "DISPLAYNAME") == 0 && lc->legacymode) {
        apr_table_set(lc->r->subprocess_env, "SU_AUTH_DIRNAME", val);
    } else if (strcasecmp(newkey, "SUUNIVID") == 0 && lc->legacymode) {
        apr_table_set(lc->r->subprocess_env, "SU_AUTH_UNIVID", val);
    }
#endif

    /* newkey is already uppercased, as environment var names should be */
    newkey = apr_psprintf(lc->r->pool, "WEBAUTH_LDAP_%s", newkey);

    /* Store the value in the environment with an appropriate name */
    webauthldap_setenv(lc, newkey, val);

    return 1; /* means keep going thru all available entries */
}

/**
 * This will be called with every attribute value pair that was requested
 * to be placed in environment variables, but was not found in ldap.
 *
 * @param lcp main context struct for this module, for passing things around
 * @param key the attribute name, as supplied by LDAP api
 * @param val the value of the attribute
 * @return always 1, which means keep going through the table
 */
static int
webauthldap_attribnotfound(void* lcp, const char *key, const char *val)
{
    MWAL_LDAP_CTXT* lc = (MWAL_LDAP_CTXT*) lcp;


    if (strcmp(val, "placed in env vars"))
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, lc->r->server,
                     "webauthldap(%s): requested attribute not found: %s",
                     lc->r->user, key);

    return 1; /* means keep going thru all available entries */
}

/**
 * This function is called with every privgroup in which we were asked to
 * check membership. Since we're just using an apr_table_t to ensure
 * uniqueness of privgroup names, we ignore the value argument.
 *
 * Privgroups which compare true are stored in numbered variables (and
 * optionally as a concatenated string in the normal variable, if a separator
 * is set) by webauthldap_setenv, above.
 *
 * @param lcp main context struct for this module, for passing things around
 * @param key the privgroup name
 * @param val the dummy value stored in our privgroups-to-check table
 * @return always 1, which means keep going through the table
 */
static int
webauthldap_exportprivgroup(void* lcp, const char *key,
                            const char *val UNUSED)
{
    char *privgroup;
    MWAL_LDAP_CTXT* lc = (MWAL_LDAP_CTXT*) lcp;

    privgroup = apr_pstrdup(lc->r->pool, key);
    if (webauthldap_docompare(lc, privgroup) == LDAP_COMPARE_TRUE)
        webauthldap_setenv(lc, "WEBAUTH_LDAPPRIVGROUP", privgroup);

    return 1; /* means keep going thru all available entries */
}


/*
 * Check whether a user is authorized by a list of privgroups.  Currently,
 * this takes the rest of the require line as a string and has to do parsing
 * itself.  Returns an authz_status.
 *
 * FIXME: Should pre-parse the require privgroup lines and pass in the
 * privgroups already parsed out.
 */
#if HAVE_DECL_AP_REGISTER_AUTH_PROVIDER
static authz_status
webauthldap_check_privgroups(MWAL_LDAP_CTXT *lc, const char *line)
{
    const char *group;
    request_rec *r = lc->r;
    int rc;

    while ((group = ap_getword_conf(r->pool, &line)) && group[0] != '\0') {
        if (lc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "webauthldap(%s): found require privgroup %s",
                         r->user, group);
        rc = webauthldap_docompare(lc, group);
        if (rc == LDAP_COMPARE_TRUE) {
            lc->authrule = apr_psprintf(lc->r->pool, "privgroup %s", group);
            if (lc->sconf->debug)
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                             "webauthldap(%s): authorizing via privgroup %s",
                             r->user, group);
            return AUTHZ_GRANTED;
        }
    }
    if (lc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "webauthldap: user %s AUTHZ_DENIED", r->user);
    return AUTHZ_DENIED;
}
#endif /* HAVE_DECL_AP_REGISTER_AUTH_PROVIDER */


#if !HAVE_DECL_AP_REGISTER_AUTH_PROVIDER
static int UNUSED
webauthldap_validate_privgroups(MWAL_LDAP_CTXT* lc,
                                const apr_array_header_t *reqs_arr,
                                int* needs_further_handling)
{
    int authorized, i, m, rc;
    require_line *reqs;
    const char *t;
    char *w;
    request_rec * r = lc->r;

    m = r->method_number;
    authorized = 1;
    lc->authrule = NULL;

    if (reqs_arr) {
        reqs = (require_line *)reqs_arr->elts;

        authorized = 0;
        for (i = 0; i < reqs_arr->nelts; i++) {
            if (!(reqs[i].method_mask & (AP_METHOD_BIT << m))) {
                continue;
            }

            /* short circuit on the first directive to positively validate */
            if (authorized)
                break;

            t = reqs[i].requirement;
            w = ap_getword_white(r->pool, &t);

            if (!strcmp(w, "valid-user")) {
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                             "webauthldap(%s): SUCCEEDED on require valid-user", r->user);
                authorized = 1;
                lc->authrule = "valid-user";
                break;
            } else if (!strcmp(w, "user")) {
                while (t[0]) {
                    w = ap_getword_conf(r->pool, &t);
                    if (lc->sconf->debug)
                        ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                                     "webauthldap: found require user %s", w);
                    if (!strcmp(r->user, w)) {
                        authorized = 1;
                        lc->authrule = apr_psprintf(lc->r->pool, "user %s", w);
                        ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                                     "webauthldap: SUCCEEDED on require user %s", w);
                        break;
                    }
                }
            }
            else if (!strcmp(w, PRIVGROUP_DIRECTIVE)) {
                while (t[0]) {
                    w = ap_getword_conf(r->pool, &t);
                    if (lc->sconf->debug)
                        ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                                     "webauthldap(%s): found: require %s %s",
                                     r->user, PRIVGROUP_DIRECTIVE, w);

                    rc = webauthldap_docompare(lc, w);
                    if (rc == LDAP_COMPARE_TRUE) {
                        authorized = 1;
                        lc->authrule = apr_psprintf(lc->r->pool, "%s %s",
                                                    PRIVGROUP_DIRECTIVE, w);
                        break;
                    }
                }
#ifndef NO_STANFORD_SUPPORT
            } else if ((!strcmp(w, "group")) && lc->legacymode) {

                while (t[0]) {
                    w = ap_getword_conf(r->pool, &t);
                    if (lc->sconf->debug)
                        ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                                     "webauthldap(%s): StanfordAuth: found: require group %s",
                                     r->user, w);

                    if (ap_strstr(w, ":") != NULL) {
                        rc = webauthldap_docompare(lc, w);
                        if (rc == LDAP_COMPARE_TRUE) {
                            authorized = 1;
                            lc->authrule = apr_psprintf(lc->r->pool, "%s %s",
                                                        PRIVGROUP_DIRECTIVE, w);
                            *needs_further_handling = 0;
                            break;
                        }
                    } else {
                        *needs_further_handling = 1;
                    }
                }
#endif
            } else {
                while (t[0]) {
                    w = ap_getword_conf(r->pool, &t);

                    if (lc->sconf->debug)
                        ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                             "webauthldap(%s): found: require %s",  r->user, w);

                    /* This means some other require directive like "group" is
                       encountered. Notice that we continue looking for the
                       ones that matter to us anyway. */
                    *needs_further_handling = 1;
                }
            }
        }
    }

    if (!authorized && !(*needs_further_handling)) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server,
                     "webauthldap: user %s UNAUTHORIZED", r->user);
        return HTTP_UNAUTHORIZED;
    }

    return 0;
}
#endif /* !HAVE_DECL_AP_REGISTER_AUTH_PROVIDER */


/**
 * This is the API hook for this module, it gets called first in the
 * auth_check stage, and is only invoked if some require directive was
 * present at the requested location. This initializes the module, binds to
 * the ldap server and conducts the search for the user's record. Then it
 * checks the access validity against the user's privilege group attributes
 * and sets specified attributes into environment variables.
 * @param r is the apache request record pointer
 * @return the HTTP code in case of an error, HTTP_UNAUTHORIZED is access is
 * not allowed, or OK if access is confirmed.
 */
#if !HAVE_DECL_AP_REGISTER_AUTH_PROVIDER
static int UNUSED
auth_checker_hook(request_rec * r)
{
    MWAL_LDAP_CTXT* lc;
    int rc;
    size_t i;
    const apr_array_header_t *reqs_arr = ap_requires(r);
    require_line *reqs;
    const char *t;
    char *w;
    int m = r->method_number;
    int needs_further_handling;
#ifdef SIGPIPE
#if APR_HAVE_SIGACTION
    apr_sigfunc_t *old_signal;
#else
    void *old_signal;
#endif
#endif

#ifndef NO_STANFORD_SUPPORT
    if (!apr_table_get(r->subprocess_env, "SU_AUTH_USER") &&
        !apr_table_get(r->subprocess_env, "WEBAUTH_USER")) {
        return DECLINED;
    }
#else
    if (apr_table_get(r->subprocess_env, "WEBAUTH_USER") == NULL) {
        return DECLINED;
    }
#endif

    if (r->user == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "webauthldap: user is not set");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    lc = (MWAL_LDAP_CTXT*) apr_pcalloc(r->pool, sizeof(MWAL_LDAP_CTXT));
    lc->r = r;
    lc->dconf = ap_get_module_config(lc->r->per_dir_config,
                                     &webauthldap_module);
    lc->sconf = ap_get_module_config(lc->r->server->module_config,
                                     &webauthldap_module);

    lc->legacymode = apr_table_get(r->subprocess_env, "SU_AUTH_USER") ? 1 : 0;

    /* See if there is anything for us to do */

    needs_further_handling = 0;
    /* if we have attributes to set or privgroups to check, we need to keep
       going */
    if (!apr_is_empty_array((const apr_array_header_t *)lc->dconf->attribs) ||
        !apr_is_empty_array((const apr_array_header_t *)lc->dconf->oper_attribs) ||
        !apr_is_empty_array((const apr_array_header_t *)lc->dconf->privgroups))
        needs_further_handling = 1;
    else if (reqs_arr) {
        reqs = (require_line *)reqs_arr->elts;

        for (i = 0; (ssize_t) i < reqs_arr->nelts; i++) {
            if (!(reqs[i].method_mask & (AP_METHOD_BIT << m))) {
                continue;
            }

            t = reqs[i].requirement;
            w = ap_getword_white(r->pool, &t);

            /* if we see PRIVGROUP_DIRECTIVEs we will need to process them */
            if (!strcmp(w, PRIVGROUP_DIRECTIVE)) {
                needs_further_handling = 1;
                break;
            }
#ifndef NO_STANFORD_SUPPORT
            /* if we see oldschool stanford:groupname, process them as well */
            if ((!strcmp(w, "group")) && lc->legacymode) {
                needs_further_handling = 1;
                break;
            }
#endif
        }
    }

    if (!needs_further_handling) {
        if (lc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                         "webauthldap(%s): nothing to check, finishing",
                         r->user);
        return DECLINED;
    }

    /* So there is something for us to do. Let's init, get a connection,
       and search. */

    apr_thread_mutex_lock(lc->sconf->totalmutex); /****** LOCKING! ************/

    webauthldap_init(lc);

    /* This will get an available connection from the pool, or bind a new one
       if needed. */
    if (webauthldap_getcachedconn(lc) != 0) {
        apr_thread_mutex_unlock(lc->sconf->totalmutex); /*** ERR UNLOCKING! ***/
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = webauthldap_dosearch(lc);

    if (rc == HTTP_SERVICE_UNAVAILABLE) {

        if (lc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                  "webauthldap(%s): this connection expired",
                     lc->r->user);

        /* Set this to ignore Broken Pipes that always happen when unbinding
           expired ldap connections. */
#ifdef SIGPIPE
        old_signal = apr_signal(SIGPIPE, SIG_IGN);
        if (old_signal == SIG_ERR) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, lc->r->server,
                         "webauthldap(%s): %s %s (%d)",
                         "can't set SIGPIPE signals to SIG_IGN: ",
                         lc->r->user, strerror(errno), errno);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
#endif
        if (lc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server,
                         "webauthldap(%s): unbinding the expired connection",
                             lc->r->user);
        ldap_unbind_ext(lc->ld, NULL, NULL);
        lc->ld = NULL;
#ifdef SIGPIPE
        apr_signal(SIGPIPE, old_signal);
#endif

        if (webauthldap_managedbind(lc) != 0) {
            apr_thread_mutex_unlock(lc->sconf->totalmutex); /* ERR UNLOCKING! */
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        if (webauthldap_dosearch(lc) != 0) {
            apr_thread_mutex_unlock(lc->sconf->totalmutex); /* ERR UNLOCKING! */
            return HTTP_INTERNAL_SERVER_ERROR;
        }

    } else if (rc != 0) {
        apr_thread_mutex_unlock(lc->sconf->totalmutex); /** ERR UNLOCKING! ****/
        return HTTP_INTERNAL_SERVER_ERROR;
    }


    /* Validate privgroups. */

    needs_further_handling = 0;
    if ((rc = webauthldap_validate_privgroups(lc, reqs_arr,
                                              &needs_further_handling)) != 0){
        webauthldap_returnconn(lc);
        apr_thread_mutex_unlock(lc->sconf->totalmutex); /***ERR UNLOCKING! ****/
        return rc; /* means not authorized, or error */
    }


    /* This sets a envvar for the rule on which authorization succeeded. */
    if (lc->sconf->authrule && lc->authrule)
        apr_table_set(lc->r->subprocess_env, "WEBAUTH_LDAPAUTHRULE",
                       lc->authrule);

    /* Now set the env vars */

    for (i=0; i<lc->numEntries; i++) {
        apr_table_do(webauthldap_exportattrib, lc, lc->entries[i], NULL);
    }
    apr_table_do(webauthldap_attribnotfound, lc, lc->envvars, NULL);

    /* Perform any additional privgroup checks and set those env vars, too */

    apr_table_do(webauthldap_exportprivgroup, lc, lc->privgroups, NULL);

    /*
     * If configured to look for operational attributes, query LDAP again for
     * all operational attributes and export them into the environment.
     */
     if (lc->dconf->oper_attribs != NULL) {
        if (lc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                "webauthldap: looking up operational attributes");

        lc->attrs = apr_pcalloc(lc->r->pool, (sizeof(char*) * 2));
        lc->attrs[0] = LDAP_ALL_OPERATIONAL_ATTRIBUTES;
        lc->attrs[1] = NULL;

        if (webauthldap_dosearch(lc) != 0) {
            apr_thread_mutex_unlock(lc->sconf->totalmutex); /* error: unlock */
            return DECLINED;
        }

        /* Cool, we got the oper attrs, now set the envvars */
        for (i = 0; i<  lc->numEntries; i++)
            apr_table_do(webauthldap_exportattrib, lc, lc->entries[i], NULL);
        apr_table_do(webauthldap_attribnotfound, lc, lc->envvars, NULL);

        if (lc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                "webauthldap: finished looking up params");
     }

    webauthldap_returnconn(lc);
    apr_thread_mutex_unlock(lc->sconf->totalmutex); /**** FINAL UNLOCKING! ****/

    if (lc->sconf->debug) {
        if (needs_further_handling)
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                         "webauthldap(%s): returning DECLINED", r->user);
        else
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                         "webauthldap(%s): returning OK", r->user);

        ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server, "%s %s",
                     "webauthldap: finished for user", lc->r->user);
    }

    return (needs_further_handling ? DECLINED : OK);
}
#endif /* !HAVE_DECL_AP_REGISTER_AUTH_PROVIDER */


/*
 * The authorization provider for this module, and therefore the heart of the
 * module.  This callback function is called for each require privgroup
 * directive found in the Apache configuration.
 *
 * We initialize the module, bind to the LDAP server, and search for the
 * user's record, and then check whether the user has a privilege group
 * attribute whose value matches one of the groups we're looking for.  If
 * access is granted, it also sets specified attributes in environment
 * variables.
 *
 * We don't specify a require line parser, so the parsed_require_line argument
 * is always NULL.  We expect the arguments in the require line to be a list
 * of privgroups granting access.
 */
#if HAVE_DECL_AP_REGISTER_AUTH_PROVIDER
static authz_status
privgroup_check_authorization(request_rec *r, const char *line,
                              const void *parsed_require_line UNUSED)
{
    MWAL_LDAP_CTXT *lc;
    int rc;
#ifdef SIGPIPE
# if APR_HAVE_SIGACTION
    apr_sigfunc_t *old_signal;
# else
    void *old_signal;
# endif
#endif

    /* Decline to authorize anyone who didn't use WebAuth. */
    if (r->user == NULL)
        return AUTHZ_DENIED_NO_USER;
    if (apr_table_get(r->subprocess_env, "WEBAUTH_USER") == NULL)
        return AUTHZ_DENIED;

    /* Get our module configuration. */
    lc = ap_get_module_config(r->request_config, &webauthldap_module);
    if (lc == NULL) {
        lc = apr_pcalloc(r->pool, sizeof(MWAL_LDAP_CTXT));
        lc->r = r;
        lc->dconf = ap_get_module_config(r->per_dir_config,
                                         &webauthldap_module);
        lc->sconf = ap_get_module_config(r->server->module_config,
                                         &webauthldap_module);
        ap_set_module_config(r->request_config, &webauthldap_module, lc);
    }

    /* Initialize, get a connection, and search. */
    apr_thread_mutex_lock(lc->sconf->totalmutex); /****** LOCKING! ***********/
    webauthldap_init(lc);

    /* Get an available connection from the pool or bind a new one. */
    if (webauthldap_getcachedconn(lc) != 0) {
        apr_thread_mutex_unlock(lc->sconf->totalmutex); /*** ERR UNLOCKING! **/
        return AUTHZ_GENERAL_ERROR;
    }
    rc = webauthldap_dosearch(lc);

    /* Handle errors on our search.  We may have to rebind and try again. */
    if (rc == HTTP_SERVICE_UNAVAILABLE) {
        if (lc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                         "webauthldap(%s): this connection expired",
                         lc->r->user);

        /*
         * Set this to ignore broken pipes that always happen when unbinding
         * expired ldap connections.
         */
#ifdef SIGPIPE
        old_signal = apr_signal(SIGPIPE, SIG_IGN);
        if (old_signal == SIG_ERR) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                         "webauthldap(%s): can't set SIGPIPE signals to"
                         " SIG_IGN: %s (%d)", r->user, strerror(errno), errno);
            return AUTHZ_GENERAL_ERROR;
        }
#endif
        if (lc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                         "webauthldap(%s): unbinding the expired connection",
                         r->user);
        ldap_unbind_ext(lc->ld, NULL, NULL);
        lc->ld = NULL;
#ifdef SIGPIPE
        apr_signal(SIGPIPE, old_signal);
#endif
        if (webauthldap_managedbind(lc) != 0) {
            apr_thread_mutex_unlock(lc->sconf->totalmutex); /* ERR UNLOCKING */
            return AUTHZ_GENERAL_ERROR;
        }
        if (webauthldap_dosearch(lc) != 0) {
            apr_thread_mutex_unlock(lc->sconf->totalmutex); /* ERR UNLOCKING */
            return AUTHZ_GENERAL_ERROR;
        }
    } else if (rc != 0) {
        apr_thread_mutex_unlock(lc->sconf->totalmutex); /** ERR UNLOCKING! ***/
        return AUTHZ_GENERAL_ERROR;
    }

    /* Validate privgroups. */
    rc = webauthldap_check_privgroups(lc, line);
    webauthldap_returnconn(lc);
    apr_thread_mutex_unlock(lc->sconf->totalmutex); /**** FINAL UNLOCKING! ****/
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                 "webauthldap(%s): returning %d", r->user, rc);
    return rc;
}
#endif /* HAVE_DECL_AP_REGISTER_AUTH_PROVIDER */


/*
 * The LDAP module fixups hook.
 *
 * This is where we set our environment variables and do lookups for any
 * supplemental privgroups.
 *
 * Returns OK or DECLINED.
 */
#if HAVE_DECL_AP_REGISTER_AUTH_PROVIDER
static int
fixups_hook(request_rec *r)
{
    MWAL_LDAP_CTXT *lc;
    size_t i;

    /* We can only do lookups if the user authenticated with WebAuth. */
    if (r->user == NULL)
        return OK;
    if (apr_table_get(r->subprocess_env, "WEBAUTH_USER") == NULL)
        return OK;

    /*
     * Obtain our cached configuration if we have one.  Otherwise, open a new
     * one, since we may be looking up attributes without having checked a
     * privgroup and therefore never done setup.
     */
    lc = ap_get_module_config(r->request_config, &webauthldap_module);
    if (lc == NULL) {
        lc = apr_pcalloc(r->pool, sizeof(MWAL_LDAP_CTXT));
        lc->r = r;
        lc->dconf = ap_get_module_config(r->per_dir_config,
                                         &webauthldap_module);
        lc->sconf = ap_get_module_config(r->server->module_config,
                                         &webauthldap_module);
        webauthldap_init(lc);
        apr_thread_mutex_lock(lc->sconf->totalmutex); /****** LOCKING! *******/
        if (webauthldap_getcachedconn(lc) != 0) {
            apr_thread_mutex_unlock(lc->sconf->totalmutex); /* ERR UNLOCKING */
            return DECLINED;
        }
        if (webauthldap_dosearch(lc) != 0) {
            apr_thread_mutex_unlock(lc->sconf->totalmutex); /* ERR UNLOCKING */
            return DECLINED;
        }
        webauthldap_returnconn(lc);
        apr_thread_mutex_unlock(lc->sconf->totalmutex); /** FINAL UNLOCKING! */
        ap_set_module_config(r->request_config, &webauthldap_module, lc);
    }

    /* Set the rule that caused authorization to succeed, if desired. */
    if (lc->sconf->authrule && lc->authrule != NULL)
        apr_table_set(lc->r->subprocess_env, "WEBAUTH_LDAPAUTHRULE",
                      lc->authrule);

    /* Set the environment variables for our query results. */
    for (i = 0; i < lc->numEntries; i++)
        apr_table_do(webauthldap_exportattrib, lc, lc->entries[i], NULL);
    apr_table_do(webauthldap_attribnotfound, lc, lc->envvars, NULL);

    /*
     * If configured to perform additional privgroup checks, get our
     * connection again and do those queries.  We ideally should retry our
     * connection here if we get a failure, but we just did that validation
     * while processing the main require directive.
     *
     * FIXME: Retry handling should be in webauthldap_getcachedconn.
     */
    apr_thread_mutex_lock(lc->sconf->totalmutex); /****** LOCKING! ***********/
    if (webauthldap_getcachedconn(lc) != 0) {
        apr_thread_mutex_unlock(lc->sconf->totalmutex); /*** ERR UNLOCKING! **/
        return DECLINED;
    }
    apr_table_do(webauthldap_exportprivgroup, lc, lc->privgroups, NULL);

    /*
     * If configured to look for operational attributes, query LDAP again for
     * all operational attributes and export them into the environment.
     */
     if (lc->dconf->oper_attribs != NULL) {
        if (lc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                "webauthldap: looking up operational attributes");

        lc->attrs = apr_pcalloc(lc->r->pool, (sizeof(char*) * 2));
        lc->attrs[0] = (char *) LDAP_ALL_OPERATIONAL_ATTRIBUTES;
        lc->attrs[1] = NULL;

        if (webauthldap_dosearch(lc) != 0) {
            apr_thread_mutex_unlock(lc->sconf->totalmutex); /* error: unlock */
            return DECLINED;
        }

        /* Cool, we got the oper attrs, now set the envvars */
        for (i = 0; i<  lc->numEntries; i++)
            apr_table_do(webauthldap_exportattrib, lc, lc->entries[i], NULL);
        apr_table_do(webauthldap_attribnotfound, lc, lc->envvars, NULL);
     }

    webauthldap_returnconn(lc);
    apr_thread_mutex_unlock(lc->sconf->totalmutex); /**** FINAL UNLOCKING! ****/

    /* All done. */
    if (lc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%s %s",
                     "webauthldap: finished for user", lc->r->user);
    return OK;
}
#endif /* HAVE_DECL_AP_REGISTER_AUTH_PROVIDER */


/* Authorization group provider struct. */
#if HAVE_DECL_AP_REGISTER_AUTH_PROVIDER
static const authz_provider authz_privgroup_provider = {
    &privgroup_check_authorization,
    NULL,
};
#endif /* HAVE_DECL_AP_REGISTER_AUTH_PROVIDER */


/**
 * Standard hook registration function
 */
static void
webauthldap_register_hooks(apr_pool_t *p UNUSED)
{
#if !HAVE_DECL_AP_REGISTER_AUTH_PROVIDER
    /* get this module called after webauth */
    static const char * const mods[]={ "mod_access.c", "mod_auth.c", NULL };

    ap_hook_auth_checker(auth_checker_hook, NULL, mods, APR_HOOK_FIRST);
#else
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "privgroup",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_privgroup_provider,
                              AP_AUTH_INTERNAL_PER_CONF);
    ap_hook_fixups(fixups_hook, NULL, NULL, APR_HOOK_MIDDLE);
#endif
    ap_hook_post_config(post_config_hook, NULL, NULL, APR_HOOK_MIDDLE);
}


/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA webauthldap_module = {
    STANDARD20_MODULE_STUFF,
    mwl_dir_config_create,      /* create per-dir    config structures */
    mwl_dir_config_merge,       /* merge  per-dir    config structures */
    mwl_server_config_create,   /* create per-server config structures */
    mwl_server_config_merge,    /* merge  per-server config structures */
    webauthldap_cmds,           /* table of config file commands       */
    webauthldap_register_hooks  /* register hooks                      */
};
