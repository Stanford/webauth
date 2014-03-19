/*
 * Configuration for the mod_webauthldap module.
 *
 * Handle configuration parsing for the module configuration, storing the
 * results in appropriate data structures for use by the rest of the module.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Based on original code by Anton Ushakov
 * Copyright 2003, 2004, 2006, 2008, 2009, 2010, 2011, 2012, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config-mod.h>
#include <portable/apache.h>
#include <portable/apr.h>
#include <portable/stdbool.h>

#include <ldap.h>
#include <stdio.h>

#include <modules/ldap/mod_webauthldap.h>
#include <util/macros.h>

APLOG_USE_MODULE(webauthldap);

/*
 * For each directive, we have the directive name (CD_), a usage string (CU_),
 * and an enum constant (E_) used to identify the directive in the parsing
 * routines.  We may also have a default value (DF_).  The usage string is
 * displayed during a syntax error and should state what the parameter of the
 * directive is supposed to be.
 *
 * For each of these, the remaining name of the variable is the directive name
 * with the leading WebAuthLdap removed.
 *
 * Use a bit of preprocessor trickery to make this easier to read.
 */
#define DIRN(name, desc)                                                  \
    static const char CD_ ## name [] = "WebAuthLdap" APR_STRINGIFY(name); \
    static const char CU_ ## name [] = desc;
#define DIRD(name, desc, type, def)             \
    DIRN(name, desc)                            \
    static const type DF_ ## name = def;

DIRN(Attribute,              "additional LDAP attributes to retrieve")
DIRN(OperationalAttribute,   "operational LDAP attributes to retrieve")
DIRN(AuthorizationAttribute, "LDAP attribute for privilege groups")
DIRD(Authrule,               "whether to display the authorization rule",
     bool, true)
DIRN(Base,                   "search base for LDAP lookups")
DIRN(BindDN,                 "bind DN for the LDAP connection")
DIRN(Debug,                  "whether to log debug messages")
DIRD(Filter,                 "LDAP search filer to use",
     const char * const, "uid=USER")
DIRN(Host,                   "LDAP host for LDAP lookups")
DIRN(Keytab,                 "keytab and the principal to bind as")
DIRN(Port,                   "LDAP port to connect to")
DIRN(Privgroup,              "additional privgroups to check membership in")
DIRN(Separator,              "separator for multi-valued attributes")
DIRN(SSL,                    "whether to use SSL for LDAP binds")
DIRN(TktCache,               "Kerberos ticket cache for LDAP")

enum {
    E_Attribute,
    E_OperationalAttribute,
    E_AuthorizationAttribute,
    E_Authrule,
    E_Base,
    E_BindDN,
    E_Debug,
    E_Filter,
    E_Host,
    E_Keytab,
    E_Port,
    E_Privgroup,
    E_Separator,
    E_SSL,
    E_TktCache,
};

/*
 * Macros used for merging.  There are a few cases here: pointers that are
 * merged based on whether they're not NULL, pointers that merge based on
 * another pointer, arrays that merge, integers that are merged based on
 * whether they're non-zero, and directives that are merged based on whether
 * they've been set.
 *
 * Assumes the merged configuration is conf, the overriding configuration is
 * oconf, and the base configuration is bconf.
 */
#define MERGE_ARRAY(field)                                              \
    if (bconf->field == NULL)                                           \
        conf->field = oconf->field;                                     \
    else if (oconf->field == NULL)                                      \
        conf->field = bconf->field;                                     \
    else                                                                \
        conf->field = apr_array_append(pool, bconf->field, oconf->field);
#define MERGE_INT(field)                                                \
    conf->field = (oconf->field != 0)    ? oconf->field : bconf->field
#define MERGE_PTR(field)                                                \
    conf->field = (oconf->field != NULL) ? oconf->field : bconf->field
#define MERGE_PTR_OTHER(field, other)                                   \
    conf->field = (oconf->other != NULL) ? oconf->field : bconf->field
#define MERGE_SET(field)                                                \
    conf->field = (oconf->field ## _set) ? oconf->field : bconf->field; \
    conf->field ## _set = oconf->field ## _set || bconf->field ## _set

/*
 * Macro used for checking if a directive is set.  Takes the struct attribute,
 * the name of the directive, and the value to check against and calls
 * fatal_config if the directive value is set to the given value.  Expects the
 * configuration to be in a variable named sconf, the server record to be
 * server, and the temporary APR pool to be p.
 */
#define CHECK_DIRECTIVE(field, dir, value)      \
    if (sconf->field == value)                  \
        fatal_config(server, CD_ ## dir, p)


/*
 * Create the initial struct for the server configuration.  This is called as
 * the server config creation hook for the module.
 */
void *
mwl_server_config_create(apr_pool_t *pool, server_rec *s UNUSED)
{
    struct server_config *sconf;

    sconf = apr_pcalloc(pool, sizeof(struct server_config));
    sconf->authrule = DF_Authrule;
    sconf->filter   = DF_Filter;
    return sconf;
}


/*
 * Create the initial struct for the directory configuration.  This is called
 * as the directory config creation hook for the module.
 */
void *
mwl_dir_config_create(apr_pool_t *pool, char *path UNUSED)
{
    struct dir_config *dconf;

    dconf = apr_pcalloc(pool, sizeof(struct dir_config));
    return dconf;
}


/*
 * Merge together two server configurations (if, for instance, there's a
 * virtual host with some settings overriding global settings).  Takes the
 * base configuration and the overriding configuration and generates a new
 * configuration based on them.
 *
 * The variable names must not change so that the macros work.
 */
void *
mwl_server_config_merge(apr_pool_t *pool, void *basev, void *overv)
{
    struct server_config *conf, *bconf, *oconf;

    conf  = apr_pcalloc(pool, sizeof(struct server_config));
    bconf = basev;
    oconf = overv;

    MERGE_PTR(auth_attr);
    MERGE_SET(authrule);
    MERGE_PTR(base);
    MERGE_PTR(binddn);
    MERGE_SET(debug);
    MERGE_SET(filter);
    MERGE_PTR(host);
    MERGE_PTR(keytab_path);
    MERGE_PTR_OTHER(keytab_principal, keytab_path);
    MERGE_INT(port);
    MERGE_PTR(separator);
    MERGE_SET(ssl);
    MERGE_PTR(tktcache);
    return conf;
}


/*
 * Merge together two directory configurations.  Takes the base configuration
 * and the overriding configuration and generates a new configuration based on
 * them.
 *
 * The variable names must not change so that the macros work.
 */
void *
mwl_dir_config_merge(apr_pool_t *pool, void *basev, void *overv)
{
    struct dir_config *conf, *bconf, *oconf;

    conf  = apr_pcalloc(pool, sizeof(struct dir_config));
    bconf = basev;
    oconf = overv;

    /* FIXME: Should probably remove duplicates. */
    MERGE_ARRAY(attribs);
    MERGE_ARRAY(oper_attribs);
    MERGE_ARRAY(privgroups);
    return conf;
}


/*
 * Report a fatal error during configuration checking.  This actually forcibly
 * terminates Apache, which is apparently common practice for Apache modules
 * with fatal configuration or setup errors.  Takes the server record, the
 * directive we were checking when we encountered a problem, and a temporary
 * APR pool.
 */
static void
fatal_config(server_rec *s, const char *dir, apr_pool_t *ptemp)
{
    const char *msg;

    if (s->is_virtual)
        msg = apr_psprintf(ptemp, "directive %s must be set for virtual host"
                           " %s (at %d)", dir, s->defn_name,
                           s->defn_line_number);
    else
        msg = apr_psprintf(ptemp, "directive %s must be set", dir);
    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                 "mod_webauthldap: fatal error: %s", msg);
    fprintf(stderr, "mod_webauthldap: fatal error: %s\n", msg);
    exit(1);
}


/*
 * Initialize the server configuration.  This performs final checks to ensure
 * that the configuration is complete and loads any additional information
 * that we store in the configuration even though it doesn't come directly
 * from an Apache configuration directive.
 */
void
mwl_config_init(server_rec *server, struct server_config *bconf UNUSED,
                apr_pool_t *p)
{
    struct server_config *sconf;

    sconf = ap_get_module_config(server->module_config, &webauthldap_module);
    CHECK_DIRECTIVE(auth_attr,    AuthorizationAttribute, NULL);
    CHECK_DIRECTIVE(base,         Base,                   NULL);
    CHECK_DIRECTIVE(keytab_path,  Keytab,                 NULL);
    CHECK_DIRECTIVE(host,         Host,                   NULL);
    CHECK_DIRECTIVE(tktcache,     TktCache,               NULL);

    /* Global defaults. */
    sconf->ldapversion = LDAP_VERSION3;
    sconf->scope = LDAP_SCOPE_SUBTREE;

    /* Mutexes for protecting our array of LDAP connections. */
    if (sconf->ldmutex == NULL)
        apr_thread_mutex_create(&sconf->ldmutex, APR_THREAD_MUTEX_DEFAULT, p);
    if (sconf->totalmutex == NULL)
        apr_thread_mutex_create(&sconf->totalmutex, APR_THREAD_MUTEX_DEFAULT,
                                p);

    /* Initialize our array of LDAP connections. */
    if (sconf->ldarray == NULL) {
        sconf->ldcount = 0;
        sconf->ldarray = apr_array_make(p, 10, sizeof(LDAP *));
    }
}


/*
 * Utility function for parsing a number.  Returns an error string or NULL
 * on success.
 */
static const char *
parse_number(cmd_parms *cmd, const char *arg, unsigned long *value)
{
    long result;
    char *end;

    errno = 0;
    result = strtol(arg, &end, 10);
    if (result < 0 || *end != '\0' || errno != 0)
        return apr_psprintf(cmd->pool, "Invalid number \"%s\" for %s", arg,
                            cmd->directive->directive);
    *value = result;
    return NULL;
}


/*
 * Return the error message for an internal error parsing a configuration
 * directive.  This happens when the wrong configuration handling routine is
 * called for a directive and indicates a coding error in the configuration
 * parsing logic.
 */
static const char *
unknown_error(cmd_parms *cmd, intptr_t value, const char *function)
{
    return apr_psprintf(cmd->pool, "Invalid value %d for directive %s in %s",
                        (int) value, cmd->directive->directive, function);
}


/*
 * Handle all configuration directives that take a single string argument.
 * Returns an error string or NULL on success.
 *
 * The info paramter of the cmd_parms struct contains data that we set in the
 * struct defined below, which in our case will be the numeric value of the
 * directive enum stored as a void *.  This is a bit of a hack on the C type
 * system, but since we never dereference the pointer, it should be okay.
 */
static const char *
cfg_str(cmd_parms *cmd, void *mconf, const char *arg)
{
    intptr_t directive = (intptr_t) cmd->info;
    struct server_config *sconf;
    struct dir_config *dconf = mconf;
    const char *err = NULL;
    const char **attrib, **privgroup, **oper_attrib;

    sconf = ap_get_module_config(cmd->server->module_config,
                                 &webauthldap_module);

    switch (directive) {
    /* Server scope only. */
    case E_AuthorizationAttribute:
        sconf->auth_attr = apr_pstrdup(cmd->pool, arg);
        break;
    case E_Base:
        sconf->base = apr_pstrdup(cmd->pool, arg);
        break;
    case E_BindDN:
        sconf->binddn = apr_pstrdup(cmd->pool, arg);
        break;
    case E_Filter:
        sconf->filter = apr_pstrdup(cmd->pool, arg);
        sconf->filter_set = true;
        break;
    case E_Host:
        sconf->host = apr_pstrdup(cmd->pool, arg);
        break;
    case E_Port:
        err = parse_number(cmd, arg, &sconf->port);
        break;
    case E_Separator:
        sconf->separator = apr_pstrdup(cmd->pool, arg);
        break;
    case E_TktCache:
        sconf->tktcache = ap_server_root_relative(cmd->pool, arg);
        break;

    /* Directory scope only. */
    case E_Attribute:
        if (dconf->attribs == NULL)
            dconf->attribs
                = apr_array_make(cmd->pool, 5, sizeof(const char *));
        attrib = apr_array_push(dconf->attribs);
        *attrib = apr_pstrdup(cmd->pool, arg);
        break;
    case E_OperationalAttribute:
        if (dconf->oper_attribs == NULL)
            dconf->oper_attribs
                = apr_array_make(cmd->pool, 5, sizeof(const char *));
        oper_attrib = apr_array_push(dconf->oper_attribs);
        *oper_attrib = apr_pstrdup(cmd->pool, arg);
        break;
    case E_Privgroup:
        if (dconf->privgroups == NULL)
            dconf->privgroups
                = apr_array_make(cmd->pool, 5, sizeof(const char *));
        privgroup = apr_array_push(dconf->privgroups);
        *privgroup = apr_pstrdup(cmd->pool, arg);
        break;

    default:
        err = unknown_error(cmd, directive, "cfg_str");
        break;
    }
    return err;
}


/*
 * Same as cfg_str, but handle all configuration directives that take one or
 * two string arguments.  Returns an error string or NULL on success.
 */
static const char *
cfg_str12(cmd_parms *cmd, void *mconf UNUSED, const char *arg,
          const char *arg2)
{
    intptr_t directive = (intptr_t) cmd->info;
    struct server_config *sconf;
    const char *err = NULL;

    sconf = ap_get_module_config(cmd->server->module_config,
                                 &webauthldap_module);

    switch (directive) {
    /* Server scope only. */
    case E_Keytab:
        sconf->keytab_path = ap_server_root_relative(cmd->pool, arg);
        if (arg2 == NULL)
            sconf->keytab_principal = NULL;
        else
            sconf->keytab_principal = apr_pstrdup(cmd->pool, arg2);
        break;

    default:
        err = unknown_error(cmd, directive, "cfg_str12");
        break;
    }
    return err;
}


/*
 * Same as cfg_str, but handle all configuration directives that take a flag
 * as an argument.  Returns an error string or NULL on success.
 */
static const char *
cfg_flag(cmd_parms *cmd, void *mconf UNUSED, int flag)
{
    intptr_t directive = (intptr_t) cmd->info;
    struct server_config *sconf;
    const char *err = NULL;

    sconf = ap_get_module_config(cmd->server->module_config,
                                 &webauthldap_module);

    switch (directive) {
    /* Server scope only. */
    case E_Authrule:
        sconf->authrule = flag;
        sconf->authrule_set = true;
        break;
    case E_Debug:
        sconf->debug = flag;
        sconf->debug_set = true;
        break;
    case E_SSL:
        sconf->ssl = flag;
        sconf->ssl_set = true;
        break;

    default:
        err = unknown_error(cmd, directive, "cfg_flag");
        break;
    }
    return err;
}


/*
 * The configuration command table.  We use some preprocessor magic to try to
 * make this more readable, using the variables that we defined at the start
 * of this file.
 */
#define DIRECTIVE(init, func, scope, dir)                               \
    init(CD_ ## dir, func, (void *) E_ ## dir, scope, CU_ ## dir)

const command_rec webauthldap_cmds[] = {
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   RSRC_CONF,  AuthorizationAttribute),
    DIRECTIVE(AP_INIT_FLAG,    cfg_flag,  RSRC_CONF,  Authrule),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   RSRC_CONF,  Base),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   RSRC_CONF,  BindDN),
    DIRECTIVE(AP_INIT_FLAG,    cfg_flag,  RSRC_CONF,  Debug),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   RSRC_CONF,  Filter),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   RSRC_CONF,  Host),
    DIRECTIVE(AP_INIT_TAKE12,  cfg_str12, RSRC_CONF,  Keytab),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   RSRC_CONF,  Port),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   RSRC_CONF,  Separator),
    DIRECTIVE(AP_INIT_FLAG,    cfg_flag,  RSRC_CONF,  SSL),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   RSRC_CONF,  TktCache),

    DIRECTIVE(AP_INIT_ITERATE, cfg_str,   OR_AUTHCFG, Attribute),
    DIRECTIVE(AP_INIT_ITERATE, cfg_str,   OR_AUTHCFG, OperationalAttribute),
    DIRECTIVE(AP_INIT_ITERATE, cfg_str,   OR_AUTHCFG, Privgroup),

    { NULL, { NULL }, NULL, OR_NONE, RAW_ARGS, NULL }
};
