/*
 * Configuration for the mod_webkdc module.
 *
 * Handle configuration parsing for the module configuration, storing the
 * results in appropriate data structures for use by the rest of the module.
 * This module only has one instance inside a particular Apache server and
 * therefore takes no per-directory configuration.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Based on original code by Roland Schemers
 * Copyright 2002, 2003, 2005, 2006, 2008, 2009, 2011, 2012, 2013, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config-mod.h>
#include <portable/apache.h>
#include <portable/apr.h>

#include <modules/webkdc/mod_webkdc.h>
#include <util/macros.h>
#include <webauth/basic.h>
#include <webauth/util.h>
#include <webauth/webkdc.h>

APLOG_USE_MODULE(webkdc);

/*
 * For each directive, we have the directive name (CD_), a usage string (CU_),
 * and an enum constant (E_) used to identify the directive in the parsing
 * routines.  We may also have a default value (DF_).  The usage string is
 * displayed during a syntax error and should state what the parameter of the
 * directive is supposed to be.
 *
 * For each of these, the remaining name of the variable is the directive name
 * with the leading WebKdc removed.
 *
 * Use a bit of preprocessor trickery to make this easier to read.
 */
#define DIRN(name, desc)                                                \
    static const char CD_ ## name [] = "WebKdc" APR_STRINGIFY(name);    \
    static const char CU_ ## name [] = desc;
#define DIRD(name, desc, type, def)             \
    DIRN(name, desc)                            \
    static const type DF_ ## name = def;

DIRN(Debug,               "whether to log debug messages")
DIRN(FastArmorCache,      "path to credential cache for FAST armor tickets")
DIRN(IdentityAcl,         "path to the identity ACL file")
DIRN(KerberosFactors,     "list of factors used as initial factors")
DIRN(Keyring,             "path to the keyring file")
DIRD(KeyringAutoUpdate,   "whether to automatically update keyring", bool, true)
DIRD(KeyringKeyLifetime,  "lifetime of keys we create", int, 60 * 60 * 24 * 30)
DIRN(Keytab,              "path to the Kerberos keytab file")
DIRN(LocalRealms,         "realms to strip, \"none\", or \"local\"")
DIRD(LoginTimeLimit,      "time limit for completing login", int, 60 * 5)
DIRN(PermittedRealms,     "list of realms permitted for authentication")
DIRN(ProxyTokenLifetime,  "lifetime of webkdc-proxy tokens")
DIRN(ServiceTokenLifetime,"lifetime of webkdc-service tokens")
DIRN(TokenAcl,            "path to the token ACL file")
DIRD(TokenMaxTTL,         "max lifetime of recent tokens", int, 60 * 5)
DIRN(UserInfoIgnoreFail,  "ignore failure to get user information")
DIRN(UserInfoJSON,        "whether to use JSON protocol for user information")
DIRN(UserInfoPrincipal,   "authentication identity of the information service")
DIRD(UserInfoTimeout,     "timeout for user information queries", int, 30)
DIRN(UserInfoURL,         "URL to user information service")

enum {
    E_Debug,
    E_FastArmorCache,
    E_IdentityAcl,
    E_KerberosFactors,
    E_Keyring,
    E_KeyringAutoUpdate,
    E_KeyringKeyLifetime,
    E_Keytab,
    E_LocalRealms,
    E_LoginTimeLimit,
    E_PermittedRealms,
    E_ProxyTokenLifetime,
    E_ServiceTokenLifetime,
    E_TokenAcl,
    E_TokenMaxTTL,
    E_UserInfoIgnoreFail,
    E_UserInfoJSON,
    E_UserInfoPrincipal,
    E_UserInfoTimeout,
    E_UserInfoURL
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
 * fatal_config if the directive value is set to NULL.  Expects the
 * configuration to be in a variable named sconf, the server record to be
 * server, and the temporary APR pool to be ptemp.
 */
#define CHECK_DIRECTIVE(field, dir, value)      \
    if (sconf->field == value)                  \
        fatal_config(server, CD_ ## dir, p)


/*
 * Create the initial struct for configuration.  This is called as the server
 * creation hook for the module.
 */
void *
webkdc_config_create(apr_pool_t *pool, server_rec *s UNUSED)
{
    struct config *sconf;

    sconf = apr_pcalloc(pool, sizeof(struct config));
    sconf->keyring_auto_update = DF_KeyringAutoUpdate;
    sconf->key_lifetime        = DF_KeyringKeyLifetime;
    sconf->login_time_limit    = DF_LoginTimeLimit;
    sconf->token_max_ttl       = DF_TokenMaxTTL;
    sconf->userinfo_timeout    = DF_UserInfoTimeout;
    sconf->local_realms        = apr_array_make(pool, 0, sizeof(const char *));
    sconf->permitted_realms    = apr_array_make(pool, 0, sizeof(const char *));
    sconf->kerberos_factors    = apr_array_make(pool, 0, sizeof(const char *));
    return sconf;
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
webkdc_config_merge(apr_pool_t *pool, void *basev, void *overv)
{
    struct config *conf, *bconf, *oconf;

    conf  = apr_pcalloc(pool, sizeof(struct config));
    bconf = basev;
    oconf = overv;

    MERGE_PTR(fast_armor_path);
    MERGE_PTR(identity_acl_path);
    MERGE_PTR(keyring_path);
    MERGE_PTR(keytab_path);
    MERGE_PTR_OTHER(keytab_principal, keytab_path);
    MERGE_PTR(token_acl_path);
    MERGE_PTR(userinfo_config);
    MERGE_PTR(userinfo_principal);
    MERGE_SET(userinfo_timeout);
    MERGE_SET(userinfo_json);
    MERGE_SET(userinfo_ignore_fail);
    MERGE_SET(debug);
    MERGE_SET(keyring_auto_update);
    MERGE_SET(key_lifetime);
    MERGE_SET(login_time_limit);
    MERGE_SET(proxy_lifetime);
    MERGE_INT(service_lifetime);
    MERGE_SET(token_max_ttl);
    MERGE_ARRAY(permitted_realms);
    MERGE_ARRAY(kerberos_factors);

    /* FIXME: Handle merging of local realm settings properly. */
    MERGE_ARRAY(local_realms);
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
    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "mod_webkdc: fatal error: %s",
                 msg);
    fprintf(stderr, "mod_webkdc: fatal error: %s\n", msg);
    exit(1);
}


/*
 * Initialize the server configuration.  This performs final checks to ensure
 * that the configuration is complete and loads any additional information
 * that we store in the configuration even though it doesn't come directly
 * from an Apache configuration directive.
 */
void
webkdc_config_init(server_rec *server, struct config *bconf UNUSED,
                   apr_pool_t *p)
{
    struct config *sconf;
    int status;

    sconf = ap_get_module_config(server->module_config, &webkdc_module);
    CHECK_DIRECTIVE(keyring_path,     Keyring,              NULL);
    CHECK_DIRECTIVE(keytab_path,      Keytab,               NULL);
    CHECK_DIRECTIVE(service_lifetime, ServiceTokenLifetime, 0);
    CHECK_DIRECTIVE(token_acl_path,   TokenAcl,             NULL);

    /*
     * Create a WebAuth context that will last for the life of the server
     * configuration.  We need this because there is some data, such as the
     * main server keyring, that needs to live as long as the server, although
     * most operations will be done on the per-request context.
     */
    status = webauth_context_init_apr(&sconf->ctx, p);
    if (status != WA_ERR_NONE) {
        const char *msg = webauth_error_message(NULL, status);

        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, server,
                     "mod_webauth: fatal error: %s", msg);
        fprintf(stderr, "mod_webauth: fatal error: %s\n", msg);
        exit(1);
    }
}


/*
 * Utility function for parsing an interval.  Returns an error string or NULL
 * on success.
 */
static const char *
parse_interval(cmd_parms *cmd, const char *arg, unsigned long *value)
{
    int status;

    status = webauth_parse_interval(arg, value);
    if (status != WA_ERR_NONE)
        return apr_psprintf(cmd->pool, "Invalid interval \"%s\" for %s", arg,
                            cmd->directive->directive);
    return NULL;
}


/*
 * Utility function for parsing a user information service URL.  This also
 * does validation of the URL and the protocol to ensure that it represents a
 * supported user information service.  Returns an error string or NULL on
 * success.  The URL will be of the form:
 *
 *     remctl://hostname.example.com:4373/oath
 *
 * where the path portion is the remctl command name.
 */
static const char *
parse_userinfo_url(cmd_parms *cmd, const char *arg,
                   struct webauth_user_config *config)
{
    apr_uri_t uri;
    int status;

    status = apr_uri_parse(cmd->pool, arg, &uri);
    if (status != APR_SUCCESS)
        return apr_psprintf(cmd->pool, "Invalid user information service URL"
                            " \"%s\" for %s", arg, cmd->directive->directive);
    if (strcmp(uri.scheme, "remctl") != 0)
        return apr_psprintf(cmd->pool, "Unknown user information protocol"
                            " \"%s\" for %s", uri.scheme,
                            cmd->directive->directive);
    config->protocol = WA_PROTOCOL_REMCTL;
    config->host = uri.hostname;
    config->port = uri.port;
    config->command = uri.path + 1;
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
cfg_str(cmd_parms *cmd, void *mconf UNUSED, const char *arg)
{
    intptr_t directive = (intptr_t) cmd->info;
    const char *err = NULL;
    const char **realm, **factor;
    struct config *sconf;

    sconf = ap_get_module_config(cmd->server->module_config, &webkdc_module);

    switch (directive) {
    case E_FastArmorCache:
        sconf->fast_armor_path = apr_pstrdup(cmd->pool, arg);
        break;
    case E_IdentityAcl:
        sconf->identity_acl_path = ap_server_root_relative(cmd->pool, arg);
        break;
    case E_Keyring:
        sconf->keyring_path = ap_server_root_relative(cmd->pool, arg);
        break;
    case E_KeyringKeyLifetime:
        err = parse_interval(cmd, arg, &sconf->key_lifetime);
        if (err == NULL)
            sconf->key_lifetime_set = true;
        break;
    case E_LocalRealms:
        realm = apr_array_push(sconf->local_realms);
        *realm = apr_pstrdup(cmd->pool, arg);
        break;
    case E_LoginTimeLimit:
        err = parse_interval(cmd, arg, &sconf->login_time_limit);
        if (err == NULL)
            sconf->login_time_limit_set = true;
        break;
    case E_PermittedRealms:
        realm = apr_array_push(sconf->permitted_realms);
        *realm = apr_pstrdup(cmd->pool, arg);
        break;
    case E_ProxyTokenLifetime:
        err = parse_interval(cmd, arg, &sconf->proxy_lifetime);
        if (err == NULL)
            sconf->proxy_lifetime_set = true;
        break;
    case E_ServiceTokenLifetime:
        err = parse_interval(cmd, arg, &sconf->service_lifetime);
        break;
    case E_TokenAcl:
        sconf->token_acl_path = ap_server_root_relative(cmd->pool, arg);
        break;
    case E_TokenMaxTTL:
        err = parse_interval(cmd, arg, &sconf->token_max_ttl);
        if (err == NULL)
            sconf->token_max_ttl_set = true;
        break;
    case E_UserInfoURL:
        sconf->userinfo_config
            = apr_palloc(cmd->pool, sizeof(struct webauth_user_config));
        err = parse_userinfo_url(cmd, arg, sconf->userinfo_config);
        break;
    case E_UserInfoPrincipal:
        sconf->userinfo_principal = arg;
        break;
    case E_UserInfoTimeout:
        err = parse_interval(cmd, arg, &sconf->userinfo_timeout);
        if (err == NULL)
            sconf->userinfo_timeout_set = true;
        break;
    case E_KerberosFactors:
        factor = apr_array_push(sconf->kerberos_factors);
        *factor = apr_pstrdup(cmd->pool, arg);
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
    const char *err = NULL;
    struct config *sconf;

    sconf = ap_get_module_config(cmd->server->module_config, &webkdc_module);

    switch (directive) {
    case E_Keytab:
        sconf->keytab_path = ap_server_root_relative(cmd->pool, arg);
        if (arg2 != NULL)
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
cfg_flag(cmd_parms *cmd, void *mconfig UNUSED, int flag)
{
    intptr_t directive = (intptr_t) cmd->info;
    const char *err = NULL;
    struct config *sconf;

    sconf = ap_get_module_config(cmd->server->module_config, &webkdc_module);

    switch (directive) {
    case E_UserInfoIgnoreFail:
        sconf->userinfo_ignore_fail = flag;
        sconf->userinfo_ignore_fail_set = true;
        break;
    case E_UserInfoJSON:
        sconf->userinfo_json = flag;
        sconf->userinfo_json_set = true;
        break;
    case E_Debug:
        sconf->debug = flag;
        sconf->debug_set = 1;
        break;
    case E_KeyringAutoUpdate:
        sconf->keyring_auto_update = flag;
        sconf->keyring_auto_update_set = true;
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
#define DIRECTIVE(init, func, dir) \
    init(CD_ ## dir, func, (void *) E_ ## dir, RSRC_CONF, CU_ ## dir)

const command_rec webkdc_cmds[] = {
    DIRECTIVE(AP_INIT_FLAG,    cfg_flag,  Debug),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   FastArmorCache),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   IdentityAcl),
    DIRECTIVE(AP_INIT_ITERATE, cfg_str,   KerberosFactors),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   Keyring),
    DIRECTIVE(AP_INIT_TAKE12,  cfg_str12, Keytab),
    DIRECTIVE(AP_INIT_FLAG,    cfg_flag,  KeyringAutoUpdate),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   KeyringKeyLifetime),
    DIRECTIVE(AP_INIT_ITERATE, cfg_str,   LocalRealms),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   LoginTimeLimit),
    DIRECTIVE(AP_INIT_ITERATE, cfg_str,   PermittedRealms),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   ProxyTokenLifetime),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   ServiceTokenLifetime),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   TokenAcl),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   TokenMaxTTL),
    DIRECTIVE(AP_INIT_FLAG,    cfg_flag,  UserInfoIgnoreFail),
    DIRECTIVE(AP_INIT_FLAG,    cfg_flag,  UserInfoJSON),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   UserInfoPrincipal),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   UserInfoTimeout),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   UserInfoURL),
    { NULL, { NULL }, NULL, OR_NONE, RAW_ARGS, NULL }
};
