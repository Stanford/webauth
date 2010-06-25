/*
 * Core WebAuth LDAP Apache module code.
 *
 * Written by Anton Ushakov
 * Copyright 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "apr_signal.h"

#include "mod-config.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <krb5.h>
#ifdef HAVE_ET_COM_ERR_H
# include <et/com_err.h>
#else
# include <com_err.h>
#endif
#include <ldap.h>

#include <modules/webauthldap/mod_webauthldap.h>
#include <util/macros.h>

module AP_MODULE_DECLARE_DATA webauthldap_module;

/** 
 *  Stolen from mod_webauth
 */
static int 
die(const char *message, server_rec *s)
{
    if (s) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "webauthldap: fatal error: %s", message);
    }
    printf("webauthldap: fatal error: %s\n", message);
    exit(1);
}

/** 
 *  Stolen from mod_webauth
 */
static void 
die_directive(server_rec *s, const char *dir, apr_pool_t *ptemp)
{
    char *msg;

    if (s->is_virtual) {
        msg = apr_psprintf(ptemp, 
                          "directive %s must be set for virtual host %s:%d", 
                          dir, s->defn_name, s->defn_line_number);
    } else {
        msg = apr_psprintf(ptemp, 
                          "directive %s must be set in main config", 
                          dir);
    }
    die(msg, s);
}

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
 * Standard conf directive parser for strings
 */
static const char *
cfg_str(cmd_parms * cmd, void *mconf UNUSED, const char *arg)
{
    intptr_t e = (intptr_t) cmd->info;
    char *error_str = NULL;
    /* MWAL_DCONF *dconf = (MWAL_DCONF *) mconf; */

    MWAL_SCONF *sconf = (MWAL_SCONF *)
        ap_get_module_config(cmd->server->module_config, &webauthldap_module);

    switch (e) {
        /* server configs */
    case E_Host:
        sconf->host = apr_pstrdup(cmd->pool, arg);
        break;
    case E_Base:
        sconf->base = apr_pstrdup(cmd->pool, arg);
        break;
    case E_Binddn:
        sconf->binddn = apr_pstrdup(cmd->pool, arg);
        break;
    case E_Filter_templ:
        sconf->filter_templ = apr_pstrdup(cmd->pool, arg);
        sconf->filter_templ_ex = 1;
        break;
    case E_Port:
        sconf->port = apr_pstrdup(cmd->pool, arg);
        sconf->port_ex = 1;
        break;
    case E_Privgroupattr:
        sconf->privgroupattr = apr_pstrdup(cmd->pool, arg);
        break;
    case E_Separator:
        sconf->separator = apr_pstrdup(cmd->pool, arg);
        break;
    case E_Tktcache:
        sconf->tktcache = ap_server_root_relative(cmd->pool, arg);
        break;

    default:
        error_str =
            apr_psprintf(cmd->pool,
                         "Invalid value cmd->info(%d) for directive %s",
                         (int) e, cmd->directive->directive);
        break;

    }
    return error_str;
}

/**
 * Standard conf directive parser for flags
 */
static const char *
cfg_flag(cmd_parms * cmd, void *mconfig UNUSED, int flag)
{
    intptr_t e = (intptr_t) cmd->info;
    char *error_str = NULL;
    /* MWAL_DCONF *dconf = (MWAL_DCONF *) mconfig; */

    MWAL_SCONF *sconf = (MWAL_SCONF *)
        ap_get_module_config(cmd->server->module_config, &webauthldap_module);

    switch (e) {
        /* server configs */
    case E_SSL:
        sconf->ssl = flag;
        break;
    case E_Debug:
        sconf->debug = flag;
        break;
    case E_Authrule:
        sconf->set_authrule = flag;
        sconf->set_authrule_ex = 1;
        break;
    default:
        error_str =
            apr_psprintf(cmd->pool,
                         "Invalid value cmd->info(%d) for directive %s",
                         (int) e, cmd->directive->directive);
        break;

    }
    return error_str;
}

/**
 * Standard conf directive parser for multiple string values
 */
static const char *
cfg_multistr(cmd_parms * cmd, void *mconf, const char *arg)
{
    intptr_t e = (intptr_t) cmd->info;
    char *error_str = NULL;
    MWAL_DCONF *dconf = (MWAL_DCONF *) mconf;
    char** attrib;

    switch (e) {
        /* server configs */
    case E_Attribs:
        if (dconf->attribs == NULL) {
            dconf->attribs = apr_array_make(cmd->pool, 5, sizeof(char*));
        }

        attrib = apr_array_push(dconf->attribs);
        *attrib = apr_pstrdup(cmd->pool, arg);
        break;
    default:
        error_str =
            apr_psprintf(cmd->pool,
                         "Invalid value cmd->info(%d) for directive %s",
                         (int) e, cmd->directive->directive);
        break;

    }
    return error_str;
}

static const char *
cfg_take12(cmd_parms *cmd, void *mconfig UNUSED, const char *w1,
           const char *w2)
{
    intptr_t e = (intptr_t) cmd->info;
    char *error_str = NULL;

    MWAL_SCONF *sconf = (MWAL_SCONF *)
        ap_get_module_config(cmd->server->module_config, &webauthldap_module);
    
    switch (e) {
        /* server configs */
        case E_Keytab:
            sconf->keytab = ap_server_root_relative(cmd->pool, w1);
            sconf->principal= (w2 != NULL) ? apr_pstrdup(cmd->pool, w2) : NULL;
            break;
        default:
            error_str = 
                apr_psprintf(cmd->pool,
                             "Invalid value cmd->info(%d) for directive %s",
                             (int) e, cmd->directive->directive);
            break;
    }
    return error_str;
}


#define SSTR(dir,mconfig,help) \
  {dir, (cmd_func)cfg_str,(void*)mconfig, RSRC_CONF, TAKE1, help}

#define SSTR12(dir,mconfig,help) \
  {dir, (cmd_func)cfg_take12,(void*)mconfig, RSRC_CONF, TAKE12, help}

#define SFLAG(dir,mconfig,help) \
  {dir, (cmd_func)cfg_flag,(void*)mconfig, RSRC_CONF, FLAG, help}

#define ADSTR(dir,mconfig,help) \
  {dir, (cmd_func)cfg_str,(void*)mconfig, ACCESS_CONF, TAKE1, help}

#define ADFLAG(dir,mconfig,help) \
  {dir, (cmd_func)cfg_flag,(void*)mconfig, ACCESS_CONF, FLAG, help}

#define DITSTR(dir,mconfig,help) \
  {dir, (cmd_func)cfg_multistr,(void*)mconfig, OR_AUTHCFG, TAKE1, help}

#define SITSTR(dir,mconfig,help) \
  {dir, (cmd_func)cfg_multistr,(void*)mconfig, RSRC_CONF, TAKE1, help}

static const command_rec cmds[] = {
    /* server/vhost */
    SSTR(CD_Host, E_Host, CM_Host),
    SSTR(CD_Base, E_Base, CM_Base),
    SSTR(CD_Binddn, E_Binddn, CM_Binddn),
    SSTR(CD_Filter_templ, E_Filter_templ, CM_Filter_templ),
    SSTR12(CD_Keytab, E_Keytab, CM_Keytab),
    SSTR(CD_Tktcache, E_Tktcache, CM_Tktcache),
    SSTR(CD_Port, E_Port, CM_Port),
    SSTR(CD_Privgroupattr, E_Privgroupattr, CM_Privgroupattr),
    SSTR(CD_Separator, E_Separator, CM_Separator),

    SFLAG(CD_SSL, E_SSL, CM_SSL),
    SFLAG(CD_Debug, E_Debug, CM_Debug),
    SFLAG(CD_Authrule, E_Authrule, CM_Authrule),

    DITSTR(CD_Attribs, E_Attribs, CM_Attribs),
    { NULL, { NULL }, NULL, 0, 0, NULL }
};

#undef SSTR
#undef SFLAG
#undef ADSTR
#undef ADFLAG
#undef DITSTR
#undef SITSTR


/**
 * Handler for creating a server conf structure
 */
static void *
config_server_create(apr_pool_t * p, server_rec * s UNUSED)
{
    MWAL_SCONF *sconf;

    sconf = (MWAL_SCONF *) apr_pcalloc(p, sizeof(MWAL_SCONF));

    /* init defaults */

    sconf->debug = DF_Debug;
    sconf->filter_templ = DF_Filter_templ;
    sconf->port = DF_Port;
    sconf->ssl = DF_SSL;
    sconf->set_authrule = DF_Authrule;

    return (void *)sconf;
}

/**
 * Handler for creating a per-directory conf structure
 */
static void *
config_dir_create(apr_pool_t * p, char *path UNUSED)
{
    MWAL_DCONF *dconf;
    dconf = (MWAL_DCONF *) apr_pcalloc(p, sizeof(MWAL_DCONF));
    /* init defaults */

    return (void *)dconf;
}


#define MERGE(field) \
    conf->field = oconf->field ? oconf->field : bconf->field

/**
 * Handler for merging server conf structures
 */
static void *
config_server_merge(apr_pool_t *p, void *basev, void *overv)
{
    MWAL_SCONF *conf, *bconf, *oconf;

    conf = (MWAL_SCONF*) apr_pcalloc(p, sizeof(MWAL_SCONF));
    bconf = (MWAL_SCONF*) basev;
    oconf = (MWAL_SCONF*) overv;

    MERGE(base);
    MERGE(binddn);
    MERGE(debug);
    conf->filter_templ = oconf->filter_templ_ex ?
        oconf->filter_templ : bconf->filter_templ;
    conf->filter_templ_ex = oconf->filter_templ_ex || bconf->filter_templ_ex;
    MERGE(host);
    MERGE(keytab);
    conf->port = oconf->port_ex ? oconf->port : bconf->port;
    conf->port_ex = oconf->port_ex || bconf->port_ex;
    MERGE(principal);
    MERGE(privgroupattr);
    MERGE(tktcache);
    MERGE(ssl);
    MERGE(separator);
    conf->set_authrule = oconf->set_authrule_ex ?
        oconf->set_authrule : bconf->set_authrule;
    conf->set_authrule_ex = oconf->set_authrule_ex || bconf->set_authrule_ex;

    return (void *)conf;
}

/**
 * Handler for merging per-directory conf structures
 */
static void *
config_dir_merge(apr_pool_t *p, void *basev, void *overv) 
{
    MWAL_DCONF *conf, *bconf, *oconf;

    conf = (MWAL_DCONF*) apr_pcalloc(p, sizeof(MWAL_DCONF));
    bconf = (MWAL_DCONF*) basev;
    oconf = (MWAL_DCONF*) overv;

    if (bconf->attribs == NULL) {
        conf->attribs = oconf->attribs;
    } else if (oconf->attribs == NULL) {
        conf->attribs = bconf->attribs;
    } else {
        /* dups here are OK */
        conf->attribs = apr_array_append(p, bconf->attribs, oconf->attribs);
    }

    return (void *)conf;
}

#undef MERGE


/**
 * Called during server startup to initialize this module.
 */
static int
post_config_hook(apr_pool_t *pconf, apr_pool_t *plog UNUSED,
                 apr_pool_t *ptemp, server_rec *s) 
{
    server_rec *scheck;
    MWAL_SCONF *sconf;
    char *tktenv;
    char *tktcache = NULL;
    size_t size;

    for (scheck=s; scheck; scheck=scheck->next) {
        sconf = (MWAL_SCONF*)ap_get_module_config(scheck->module_config,
                                                  &webauthldap_module);
        /* These all must be non-null: */
#define NULCHECK(val, label) \
    if (val == NULL) die_directive(scheck, label, ptemp);

        NULCHECK(sconf->keytab, CD_Keytab);
        NULCHECK(sconf->tktcache, CD_Tktcache);
        NULCHECK(sconf->host, CD_Host);
        NULCHECK(sconf->base, CD_Base);
        NULCHECK(sconf->privgroupattr, CD_Privgroupattr);
#undef NULCHECK

        /* Global settings */
        sconf->ldapversion = LDAP_VERSION3;
        sconf->scope = LDAP_SCOPE_SUBTREE;

        /* Mutex for storing ldap connections */
        if (sconf->ldmutex == NULL) {
            apr_thread_mutex_create(&sconf->ldmutex,
                                    APR_THREAD_MUTEX_DEFAULT,
                                    pconf);
        }

        if (sconf->totalmutex == NULL) {
            apr_thread_mutex_create(&sconf->totalmutex,
                                    APR_THREAD_MUTEX_DEFAULT,
                                    pconf);
        }
  
        if (sconf->ldarray == NULL) {
            sconf->ldcount = 0;
            sconf->ldarray = apr_array_make(pconf, 10, sizeof(LDAP *));
        }

        /* This has to be the same for all server configuration.  For the sake
           of convenience, grab the last one. */
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
webauthldap_make_filter(MWAL_LDAP_CTXT* lc) 
{
    apr_pool_t * p = lc->r->pool;
    char* userid = lc->r->user;
    char* filter_template = apr_pstrdup(lc->r->pool, lc->sconf->filter_templ);
    char* beg = filter_template;
    char* end = filter_template;
    char* filter = NULL;

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
    krb5_get_init_creds_opt opts;
    krb5_keytab keytab;
    krb5_ccache cc;
    krb5_principal princ;
    krb5_error_code code;
    krb5_error_code tcode;
    char *kt, *cc_path;

    kt = apr_pstrcat(lc->r->pool, "FILE:", lc->sconf->keytab, NULL);

    /* initialize the main struct that holds kerberos context */
    if ((code = krb5_init_context(&ctx)) != 0)
        return code;

    /* locate, open, and read the keytab */
    if ((code = krb5_kt_resolve(ctx, kt, &keytab)) != 0)
        return code;

    /* if the principal has been specified via directives, use it, 
       otherwise just read the first entry out of the keytab. */
    if (lc->sconf->principal) {
        code = krb5_parse_name(ctx, lc->sconf->principal, &princ);
    } else {
        if ((code = krb5_kt_start_seq_get(ctx, keytab, &cursor)) != 0) {
            tcode = krb5_kt_close(ctx, keytab);
            return code;
        }

        if ((code = krb5_kt_next_entry(ctx, keytab, &entry, &cursor)) == 0) {
            code = krb5_copy_principal(ctx, entry.principal, &princ);
#ifdef HAVE_KRB5_FREE_KEYTAB_ENTRY_CONTENTS
            tcode = krb5_free_keytab_entry_contents(ctx, &entry);
#else
            tcode = krb5_kt_free_entry(ctx, &entry);
#endif
        }
        tcode = krb5_kt_end_seq_get(ctx, keytab, &cursor);
    }

    if (code != 0) {
        tcode = krb5_kt_close(ctx, keytab);
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
    if ((code != krb5_cc_initialize(ctx, cc, princ)) != 0) {
        krb5_kt_close(ctx, keytab);
        krb5_free_principal(ctx, princ);
        return code;
    }
    
    krb5_get_init_creds_opt_init(&opts);

    /* get the tgt for this principal */
    code = krb5_get_init_creds_keytab(ctx,
                                      &creds,
                                      princ,
                                      keytab,
                                      0, /* start_time */
                                      NULL, /* in_tkt_service */
                                      &opts);

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
 * This will initialize the main context struct and set up the table of
 * attributes to later put into environment variables.
 * @param lc main context struct for this module, for passing things around
 * @return zero if OK, HTTP_INTERNAL_SERVER_ERROR if not
 */
static void
webauthldap_init(MWAL_LDAP_CTXT* lc)
{
    int i;
    char** attrib;
    char *p;
    apr_array_header_t* attribs;

    if (lc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server, "%s %s",
                     "webauthldap: invoked for user", lc->r->user);

    /* These come with defaults: */
    lc->filter = webauthldap_make_filter(lc);
    lc->port = atoi(lc->sconf->port);

    if (lc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server, 
                     "webauthldap(%s): filter is %s", lc->r->user, lc->filter);

    /* Allocate the table of attributes to later put into env vars */
    lc->envvars = apr_table_make(lc->r->pool, 5);

    /* Whatever else env vars the conf file added. This will override the 
       defaults since apr_table_set is used here, and all names are
       lowercased. */
    if (lc->dconf->attribs) {
        attribs = apr_array_copy(lc->r->pool, lc->dconf->attribs);

        for(i=0; ((attrib = apr_array_pop(attribs)) != NULL); i++) {
            for (p = *attrib; *p != '\0'; p++)
                *p = tolower(*p);
            apr_table_set(lc->envvars, *attrib, *attrib);

        if (lc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server, 
                         "webauthldap(%s): conf attribute to put into env: %s",
                         lc->r->user, *attrib);
        }
    }
    
    if (lc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server, 
                     "webauthldap(%s): initialized sucessfully", lc->r->user);
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
    url.lud_host = lc->sconf->host;
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
        if (stat(lc->sconf->keytab, &keytab_stat) < 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, lc->r->server,
                         "webauthldap(%s): cannot stat the keytab: %s %s (%d)",
                         lc->r->user, 
                         lc->sconf->keytab, strerror(errno), errno);
            return -1;
        }

        if ((fd = open(lc->sconf->keytab, O_RDONLY, 0)) < 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, lc->r->server,
                         "webauthldap(%s): cannot read the keytab %s: %s (%d)", 
                         lc->r->user, lc->sconf->keytab, 
                         strerror(errno), errno);
            close(fd);
            return -1;
        }
        close(fd);

        princ_specified = lc->sconf->principal? 1:0;

        rc = webauthldap_get_ticket(lc);

        if (rc == KRB5_REALM_CANT_RESOLVE) {
            if (princ_specified)
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, lc->r->server,
                             "webauthldap(%s): cannot get ticket: %s %s %s",
                             lc->r->user, "check if the keytab", 
                             lc->sconf->keytab,
                             "is valid for the specified principal");
            else
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, lc->r->server,
                             "webauthldap(%s): cannot get ticket: %s %s %s",
                             lc->r->user, "check if the keytab", 
                             lc->sconf->keytab,
                             "is valid and only contains the right principal");

            return -1;
        } if (rc != 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, lc->r->server,
                         "webauthldap(%s): cannot get ticket: %s (%d)", 
                         lc->r->user, error_message(rc), rc);
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
                     "webauthldap(%s): bound sucessfully to %s", lc->r->user, 
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
 * the given apr table. It will also copy out the privgroup attributes into a
 * separate table. Duplicates are preserved in both cases.
 * @param lc main context struct for this module, for passing things around
 * @param entry the given LDAP entry to parse
 * @param attr_table is the table to place the attributes into
 * @return nothing
 */
static void
webauthldap_parse_entry(MWAL_LDAP_CTXT* lc, LDAPMessage * entry, apr_table_t * attr_table)
{
    char *a, *val, *dn;
    int i;
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

        if ((bvals = ldap_get_values_len(lc->ld, entry, a)) != NULL) {
            for (i = 0; bvals[i] != NULL; i++) {
                val = apr_pstrndup(lc->r->pool, (char *)bvals[i]->bv_val,
                                   (apr_size_t) bvals[i]->bv_len);
                apr_table_add(attr_table, a, val);
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
                             "webauthldap(%s): search returned %d entries", 
                             lc->r->user, lc->numEntries);
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
webauthldap_docompare(MWAL_LDAP_CTXT* lc, char* value)
{
    int i, rc;
    char* dn, *attr;
    struct berval bvalue = { 0, NULL };

    attr = lc->sconf->privgroupattr;
    bvalue.bv_val = value;
    bvalue.bv_len = strlen(bvalue.bv_val);

    for (i=0; i<lc->numEntries; i++) {
        dn = (char*)apr_table_get(lc->entries[i], DN_ATTRIBUTE);

        rc = ldap_compare_ext_s(lc->ld, dn, attr, &bvalue, NULL, NULL);

        if (rc == LDAP_COMPARE_TRUE) {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server, 
                         "webauthldap(%s): SUCCEEDED comparing %s=%s in %s", 
                         lc->r->user, attr, value, dn);
	    lc->authrule = value;
            return rc;
        } else if (rc == LDAP_COMPARE_FALSE) {
            if (lc->sconf->debug) {
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server, 
                             "webauthldap(%s): FALSE comparing %s=%s in %s", 
                             lc->r->user, attr, value, dn);
            }
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
 * This will be called with every attribute value pair that was received
 * from the LDAP search. Only attributes that were requested through the conf 
 * directives as well as a few default attributes will be placed in 
 * environment variables starting with "WEBAUTH_LDAP_".
 *
 * The single valued attributes go into appropriately named env vars, while
 * multivalued attributes have a env var for each value, with the name of the 
 * var containing a sequence number at the end. No particular order is 
 * guaranteed. In the multivalued case, the env var with the canonical 
 * (unnumbered) name will contain the value we encounter, essentially random.
 * @param lcp main context struct for this module, for passing things around
 * @param key the attribute name, as supplied by LDAP api
 * @param val the value of the attribute
 * @return always 1, which means keep going through the table
 */
static int
webauthldap_setenv(void* lcp, const char *key, const char *val)
{
    int i;
    char *newkey, *numbered_key, *p, *existing_val, *newval;
    MWAL_LDAP_CTXT* lc = (MWAL_LDAP_CTXT*) lcp;

    if ((key == NULL) || (val == NULL))
        return 1;

    /* conf directive could have been in different capitalization, 
       simpler to just lowercase for the comparison */
    newkey = apr_psprintf(lc->r->pool, key);
    for (p = newkey; *p != '\0'; p++)
        *p = tolower(*p);

    /* set into the environment only those attributes, which were specified */
    if (!apr_table_get(lc->envvars, newkey))
        return 1;

    /* to keep track which ones we have already seen */
    apr_table_set(lc->envvars, newkey, "placed in env vars");

#ifndef NO_STANFORD_SUPPORT
    if (!strcmp(newkey, "mail") && lc->legacymode) {
        apr_table_set(lc->r->subprocess_env, "SU_AUTH_DIRMAIL", val);
    } else if (!strcmp(newkey, "displayname") && lc->legacymode) {
        apr_table_set(lc->r->subprocess_env, "SU_AUTH_DIRNAME", val);
    } else if (!strcmp(newkey, "suunivid") && lc->legacymode) {
        apr_table_set(lc->r->subprocess_env, "SU_AUTH_UNIVID", val);
    }
#endif

    newkey = apr_psprintf(lc->r->pool, "WEBAUTH_LDAP_%s", key);

    /* environment var names should be uppercased */
    for (p = newkey; *p != '\0'; p++)
        *p = toupper(*p);

    existing_val = (char*) apr_table_get(lc->r->subprocess_env, newkey);

    /* Normal case of single-valued attribute. */
    if (existing_val == NULL) {
        if (lc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server, 
                         "webauthldap(%s): setting %s as single valued", 
                         lc->r->user, newkey);
        apr_table_set(lc->r->subprocess_env, newkey, val);
    } else {
        /* Set WEBAUTH_LDAP_BLAH1 to be the same as WEBAUTH_LDAP_BLAH. */
        numbered_key = apr_psprintf(lc->r->pool, "%s%d", newkey, 1);
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
            apr_table_set(lc->r->subprocess_env, newkey, newval);
        }
            
        /* now set WEBAUTH_LDAP_BLAH2 WEBAUTH_LDAP_BLAH3 and so on */
        for (i=2; i<MAX_ENV_VALUES; i++) {
            numbered_key = apr_psprintf(lc->r->pool, "%s%d", newkey, i);
            if (apr_table_get(lc->r->subprocess_env, numbered_key) == NULL) {
                if (lc->sconf->debug)
                    ap_log_error(APLOG_MARK, APLOG_INFO, 0, lc->r->server, 
                                 "webauthldap(%s): setting %s", lc->r->user,
                                 numbered_key);
                apr_table_set(lc->r->subprocess_env, numbered_key, val);
                break;
            }
        }
    }

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
webauthldap_envnotfound(void* lcp, const char *key, const char *val)
{
    MWAL_LDAP_CTXT* lc = (MWAL_LDAP_CTXT*) lcp;


    if (strcmp(val, "placed in env vars"))
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, lc->r->server, 
                     "webauthldap(%s): requested attribute not found: %s", 
                     lc->r->user, key);

    return 1; /* means keep going thru all available entries */
}



static int
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
static int
auth_checker_hook(request_rec * r)
{
    MWAL_LDAP_CTXT* lc;
    int rc, i;

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
    lc->dconf = (MWAL_DCONF*)
        ap_get_module_config(lc->r->per_dir_config, &webauthldap_module);

    lc->sconf = (MWAL_SCONF*) 
        ap_get_module_config(lc->r->server->module_config,&webauthldap_module);

    lc->legacymode = apr_table_get(r->subprocess_env, "SU_AUTH_USER") ? 1 : 0;

    /* See if there is anything for us to do */

    needs_further_handling = 0;
    /* if we have attributes to set, we need to keep going */
    if (!apr_is_empty_table((const apr_table_t *)lc->dconf->attribs))
        needs_further_handling = 1;
    else if (reqs_arr) {
        reqs = (require_line *)reqs_arr->elts;

        for (i = 0; i < reqs_arr->nelts; i++) {
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
    if (lc->sconf->set_authrule && lc->authrule)
        apr_table_set(lc->r->subprocess_env, "WEBAUTH_LDAPAUTHRULE", 
                       lc->authrule);

    /* Now set the env vars */

    for (i=0; i<lc->numEntries; i++) {
        apr_table_do(webauthldap_setenv, lc, lc->entries[i], NULL);
    }
    apr_table_do(webauthldap_envnotfound, lc, lc->envvars, NULL);

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

/**
 * Standard hook registration function 
 */
static void
webauthldap_register_hooks(apr_pool_t *p UNUSED)
{
    /* get this module called after webauth */
    static const char * const mods[]={ "mod_access.c", "mod_auth.c", NULL };

    ap_hook_post_config(post_config_hook, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_auth_checker(auth_checker_hook, NULL, mods, APR_HOOK_FIRST);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA webauthldap_module = {
    STANDARD20_MODULE_STUFF,
    config_dir_create,               /* create per-dir config structures */
    config_dir_merge,                /* merge  per-dir    config structures */
    config_server_create,            /* create per-server config structures */
    config_server_merge,             /* merge  per-server config structures */
    cmds,                            /* table of config file commands */
    webauthldap_register_hooks       /* register hooks */
};


/* 
** Local variables: 
** mode: c 
** c-basic-offset: 4 
** indent-tabs-mode: nil 
** end: 
*/
