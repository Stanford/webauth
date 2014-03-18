/*
 * Configuration for the mod_webauth module.
 *
 * Handle configuration parsing for the module configuration, storing the
 * results in appropriate data structures for use by the rest of the module.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Based on original code by Roland Schemers
 * Copyright 2002, 2003, 2004, 2006, 2008, 2009, 2010, 2011, 2012, 2013, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config-mod.h>
#include <portable/apache.h>
#include <portable/apr.h>
#include <portable/stdbool.h>

#include <stdlib.h>
#include <unistd.h>

#include <modules/webauth/mod_webauth.h>
#include <util/macros.h>
#include <webauth/basic.h>
#include <webauth/util.h>

APLOG_USE_MODULE(webauth);

/*
 * For each directive, we have the directive name (CD_), a usage string (CU_),
 * and an enum constant (E_) used to identify the directive in the parsing
 * routines.  We may also have a default value (DF_).  The usage string is
 * displayed during a syntax error and should state what the parameter of the
 * directive is supposed to be.
 *
 * For each of these, the remaining name of the variable is the directive name
 * with the leading WebAuth removed.
 *
 * Use a bit of preprocessor trickery to make this easier to read.
 */
#define DIRN(name, desc)                                                \
    static const char CD_ ## name [] = "WebAuth" APR_STRINGIFY(name);   \
    static const char CU_ ## name [] = desc;
#define DIRD(name, desc, type, def)             \
    DIRN(name, desc)                            \
    static const type DF_ ## name = def;

DIRN(AppTokenLifetime,   "lifetime of app tokens")
DIRN(AuthType,           "additional AuthType alias")
DIRN(CookiePath,         "path scope for WebAuth cookies")
DIRN(Cred,               "credential to obtain")
DIRN(CredCacheDir,       "path to the credential cache directory")
DIRN(Debug,              "whether to log debug messages")
DIRN(DoLogout,           "whether to destroy all WebAuth cookies")
DIRN(DontCache,          "whether to set Expires to the current date")
DIRD(ExtraRedirect,      "redirect to strip tokens from the URL", bool, true)
DIRN(FailureURL,         "URL to redirect to after serious WebAuth failure")
DIRN(ForceLogin,         "whether to force initial authentication")
DIRD(HttpOnly,           "whether to set HttpOnly for cookies", bool, true)
DIRN(InactiveExpire,     "duration of inactivity before an app token expires")
DIRN(Keyring,            "path to the keyring file")
DIRD(KeyringAutoUpdate,  "whether to automatically update keyring", bool, true)
DIRD(KeyringKeyLifetime, "lifetime of keys we create", int, 60 * 60 * 24 * 30)
DIRN(Keytab,             "path to the Kerberos keytab file")
DIRN(LastUseUpdateInterval, "how often to update last-used time in app token")
DIRN(LoginCanceledURL,   "URL to return to if the user cancels login")
DIRN(LoginURL,           "URL for the WebLogin page")
DIRN(Optional,           "whether to let unauthenticated users through")
DIRN(PostReturnURL,      "URL to return to after a WebAuth redirect on a POST")
DIRN(RequireInitialFactor,  "required factors for initial authentication")
DIRN(RequireLOA,         "required level of assurance for authentication")
DIRD(RequireSSL,         "whether SSL is required", bool, true)
DIRN(RequireSessionFactor,  "required factors for session authentication")
DIRN(ReturnURL,          "URL to return to after logging in")
DIRN(ServiceTokenCache,  "path to the service token cache file")
DIRN(SSLRedirect,        "whether to redirect to SSL for protected pages")
DIRD(SSLRedirectPort,    "SSL port for SSL redirects", int, 443)
DIRN(SSLReturn,          "whether to force the return URL to be https")
DIRD(StripURL,           "whether to strip tokens in internal URL", bool, true)
DIRD(SubjectAuthType,    "requested subject authenticator", char *, "webkdc")
DIRD(TokenMaxTTL,        "maximum lifetime of recent tokens", int, 300)
DIRN(TrustAuthzIdentity, "whether to trust asserted authorization identities")
DIRN(WebKdcPrincipal,    "WebKDC Kerberos principal name")
DIRD(WebKdcSSLCertCheck, "whether to check the WebKDC certificate", bool, true)
DIRN(WebKdcSSLCertFile,  "file containing the WebKDC's certificate")
DIRN(WebKdcURL,          "URL for the WebKDC XML service")
DIRN(UseCreds,           "whether to create a credential cache file")
DIRN(VarPrefix,          "prefix to prepend to environment variables")

/* Similar macro for the Stanford WebAuth 2.5 compatibility directives. */
#ifndef NO_STANFORD_SUPPORT
# define SADIRN(name, desc)                                                 \
    static const char SCD_ ## name [] = "StanfordAuth" APR_STRINGIFY(name); \
    static const char SCU_ ## name [] = desc;

SADIRN(ConfirmMsg,  "unsupported WebAuth 2.5 option")
SADIRN(DoConfirm,   "unsupported WebAuth 2.5 option")
SADIRN(DontCache,   "ignored")
SADIRN(ForceReload, "mapped to WebAuthExtraRedirect")
SADIRN(Groups,      "unsupported WebAuth 2.5 option")
SADIRN(Life,        "mapped to WebAuthAppTokenLifetime, enables force login")
SADIRN(ReturnURL,   "mapped to WebAuthReturnURL")
#endif /* !NO_STANFORD_SUPPORT */

enum {
#ifndef NO_STANFORD_SUPPORT
    SE_ConfirmMsg,
    SE_DoConfirm,
    SE_DontCache,
    SE_ForceReload,
    SE_Groups,
    SE_Life,
    SE_ReturnURL,
#endif
    E_AppTokenLifetime,
    E_AuthType,
    E_CookiePath,
    E_Cred,
    E_CredCacheDir,
    E_Debug,
    E_DoLogout,
    E_DontCache,
    E_ExtraRedirect,
    E_FailureURL,
    E_ForceLogin,
    E_HttpOnly,
    E_InactiveExpire,
    E_Keyring,
    E_KeyringAutoUpdate,
    E_KeyringKeyLifetime,
    E_Keytab,
    E_LastUseUpdateInterval,
    E_LoginCanceledURL,
    E_LoginURL,
    E_Optional,
    E_PostReturnURL,
    E_RequireInitialFactor,
    E_RequireLOA,
    E_RequireSSL,
    E_RequireSessionFactor,
    E_ReturnURL,
    E_SSLRedirect,
    E_SSLRedirectPort,
    E_SSLReturn,
    E_ServiceTokenCache,
    E_StripURL,
    E_SubjectAuthType,
    E_TokenMaxTTL,
    E_TrustAuthzIdentity,
    E_UseCreds,
    E_VarPrefix,
    E_WebKdcPrincipal,
    E_WebKdcSSLCertCheck,
    E_WebKdcSSLCertFile,
    E_WebKdcURL
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
mwa_server_config_create(apr_pool_t *pool, server_rec *s UNUSED)
{
    struct server_config *sconf;

    sconf = apr_pcalloc(pool, sizeof(struct server_config));
    sconf->extra_redirect       = DF_ExtraRedirect;
    sconf->httponly             = DF_HttpOnly;
    sconf->keyring_auto_update  = DF_KeyringAutoUpdate;
    sconf->keyring_key_lifetime = DF_KeyringKeyLifetime;
    sconf->require_ssl          = DF_RequireSSL;
    sconf->subject_auth_type    = DF_SubjectAuthType;
    sconf->strip_url            = DF_StripURL;
    sconf->token_max_ttl        = DF_TokenMaxTTL;
    sconf->webkdc_cert_check    = DF_WebKdcSSLCertCheck;
    return sconf;
}


/*
 * Create the initial struct for the directory configuration.  This is called
 * as the directory config creation hook for the module.
 */
void *
mwa_dir_config_create(apr_pool_t *pool, char *path UNUSED)
{
    struct dir_config *dconf;

    dconf = apr_pcalloc(pool, sizeof(struct dir_config));
    dconf->extra_redirect = DF_ExtraRedirect;
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
mwa_server_config_merge(apr_pool_t *pool, void *basev, void *overv)
{
    struct server_config *conf, *bconf, *oconf;

    conf  = apr_pcalloc(pool, sizeof(struct server_config));
    bconf = basev;
    oconf = overv;

    MERGE_PTR(auth_type);
    MERGE_PTR(cred_cache_dir);
    MERGE_SET(debug);
    MERGE_SET(extra_redirect);
    MERGE_SET(httponly);
    MERGE_SET(keyring_auto_update);
    MERGE_SET(keyring_key_lifetime);
    MERGE_PTR(keyring_path);
    MERGE_PTR(keytab_path);
    MERGE_PTR_OTHER(keytab_principal, keytab_path);
    MERGE_PTR(login_url);
    MERGE_SET(require_ssl);
    MERGE_SET(ssl_redirect);
    MERGE_SET(ssl_redirect_port);
    MERGE_PTR(st_cache_path);
    MERGE_SET(strip_url);
    MERGE_SET(subject_auth_type);
    MERGE_SET(trust_authz_identity);
    MERGE_SET(webkdc_cert_check);
    MERGE_PTR(webkdc_cert_file);
    MERGE_PTR(webkdc_principal);
    MERGE_PTR(webkdc_url);
    MERGE_SET(token_max_ttl);
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
mwa_dir_config_merge(apr_pool_t *pool, void *basev, void *overv)
{
    struct dir_config *conf, *bconf, *oconf;

    conf  = apr_pcalloc(pool, sizeof(struct dir_config));
    bconf = basev;
    oconf = overv;

    MERGE_INT(app_token_lifetime);
    MERGE_PTR(cookie_path);
    MERGE_SET(do_logout);
    MERGE_SET(dont_cache);
    MERGE_SET(extra_redirect);
    MERGE_PTR(failure_url);
    MERGE_SET(force_login);
    MERGE_INT(inactive_expire);
    MERGE_PTR(initial_factors);
    MERGE_INT(last_use_update_interval);
    MERGE_SET(loa);
    MERGE_PTR(login_canceled_url);
    MERGE_SET(optional);
    MERGE_PTR(post_return_url);
    MERGE_PTR(return_url);
    MERGE_PTR(session_factors);
    MERGE_SET(ssl_return);
    MERGE_SET(trust_authz_identity);
    MERGE_SET(use_creds);
    MERGE_PTR(var_prefix);
#ifndef NO_STANFORD_SUPPORT
    MERGE_PTR(su_authgroups);
#endif

    /* FIXME: Should probably remove duplicates. */
    MERGE_ARRAY(creds);

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
    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "mod_webauth: fatal error: %s",
                 msg);
    fprintf(stderr, "mod_webauth: fatal error: %s\n", msg);
    exit(1);
}


/*
 * Initialize the server configuration.  This performs final checks to ensure
 * that the configuration is complete and loads any additional information
 * that we store in the configuration even though it doesn't come directly
 * from an Apache configuration directive.
 */
void
mwa_config_init(server_rec *server, struct server_config *bconf UNUSED,
                apr_pool_t *p)
{
    struct server_config *sconf;
    int status;

    sconf = ap_get_module_config(server->module_config, &webauth_module);
    CHECK_DIRECTIVE(keyring_path,     Keyring,           NULL);
    CHECK_DIRECTIVE(keytab_path,      Keytab,            NULL);
    CHECK_DIRECTIVE(login_url,        LoginURL,          NULL);
    CHECK_DIRECTIVE(st_cache_path,    ServiceTokenCache, NULL);
    CHECK_DIRECTIVE(webkdc_principal, WebKdcPrincipal,   NULL);
    CHECK_DIRECTIVE(webkdc_url,       WebKdcURL,         NULL);

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

    /* Initialize the mutex. */
    if (sconf->mutex == NULL)
        apr_thread_mutex_create(&sconf->mutex, APR_THREAD_MUTEX_DEFAULT, p);

    /* Unlink any existing service token cache so that we'll get a new one. */
    if (unlink(sconf->st_cache_path) < 0 && errno != ENOENT)
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "mod_webauth: cannot remove service token cache %s: %s",
                     sconf->st_cache_path, strerror(errno));
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
    const char **factor;

    sconf = ap_get_module_config(cmd->server->module_config, &webauth_module);

    switch (directive) {
    /* Server scope only. */
    case E_AuthType:
        sconf->auth_type = apr_pstrdup(cmd->pool, arg);
        break;
    case E_CredCacheDir:
        if (strncmp(arg, "KEYRING:", 8) == 0)
            sconf->cred_cache_dir = apr_pstrdup(cmd->pool, arg);
        else
            sconf->cred_cache_dir = ap_server_root_relative(cmd->pool, arg);
        break;
    case E_Keyring:
        sconf->keyring_path = ap_server_root_relative(cmd->pool, arg);
        break;
    case E_KeyringKeyLifetime:
        err = parse_interval(cmd, arg, &sconf->keyring_key_lifetime);
        if (err == NULL)
            sconf->keyring_key_lifetime_set = true;
        break;
    case E_LoginURL:
        sconf->login_url = apr_pstrdup(cmd->pool, arg);
        break;
    case E_ServiceTokenCache:
        sconf->st_cache_path = ap_server_root_relative(cmd->pool, arg);
        break;
    case E_SSLRedirectPort:
        err = parse_number(cmd, arg, &sconf->ssl_redirect_port);
        if (err == NULL)
            sconf->ssl_redirect_port_set = true;
        break;
    case E_SubjectAuthType:
        sconf->subject_auth_type = apr_pstrdup(cmd->pool, arg);
        sconf->subject_auth_type_set = true;

        /* FIXME: this check needs to be more dynamic, or done later. */
        if (strcmp(arg, "krb5") != 0 && strcmp(arg,"webkdc") != 0)
            err = apr_psprintf(cmd->pool, "Invalid value %s for directive %s",
                               arg, cmd->directive->directive);
        break;
    case E_TokenMaxTTL:
        err = parse_interval(cmd, arg, &sconf->token_max_ttl);
        if (err == NULL)
            sconf->token_max_ttl_set = true;
        break;
    case E_WebKdcPrincipal:
        sconf->webkdc_principal = apr_pstrdup(cmd->pool, arg);
        break;
    case E_WebKdcSSLCertFile:
        sconf->webkdc_cert_file = ap_server_root_relative(cmd->pool, arg);
        break;
    case E_WebKdcURL:
        sconf->webkdc_url = apr_pstrdup(cmd->pool, arg);
        break;

    /* Directory scope only. */
    case E_AppTokenLifetime:
        err = parse_interval(cmd, arg, &dconf->app_token_lifetime);
        break;
    case E_CookiePath:
        dconf->cookie_path = apr_pstrdup(cmd->pool, arg);
        break;
    case E_FailureURL:
        dconf->failure_url = apr_pstrdup(cmd->pool, arg);
        break;
    case E_InactiveExpire:
        err = parse_interval(cmd, arg, &dconf->inactive_expire);
        break;
    case E_LastUseUpdateInterval:
        err = parse_interval(cmd, arg, &dconf->last_use_update_interval);
        break;
    case E_LoginCanceledURL:
        dconf->login_canceled_url = apr_pstrdup(cmd->pool, arg);
        break;
    case E_PostReturnURL:
        dconf->post_return_url = apr_pstrdup(cmd->pool, arg);
        break;
    case E_RequireInitialFactor:
        if (dconf->initial_factors == NULL)
            dconf->initial_factors
                = apr_array_make(cmd->pool, 1, sizeof(const char *));
        factor = apr_array_push(dconf->initial_factors);
        *factor = apr_pstrdup(cmd->pool, arg);
        break;
    case E_RequireLOA:
        err = parse_number(cmd, arg, &dconf->loa);
        if (err == NULL)
            dconf->loa_set = true;
        break;
    case E_RequireSessionFactor:
        if (dconf->session_factors == NULL)
            dconf->session_factors
                = apr_array_make(cmd->pool, 1, sizeof(const char *));
        factor = apr_array_push(dconf->session_factors);
        *factor = apr_pstrdup(cmd->pool, arg);
        break;
    case E_ReturnURL:
        dconf->return_url = apr_pstrdup(cmd->pool, arg);
        break;
    case E_VarPrefix:
        dconf->var_prefix = apr_pstrdup(cmd->pool, arg);
        break;

    /* Directory scope only, legacy. */
#ifndef NO_STANFORD_SUPPORT
    case SE_ConfirmMsg:
        break;
    case SE_Groups:
        dconf->su_authgroups = apr_pstrdup(cmd->pool, arg);
        break;
    case SE_Life:
        err = parse_number(cmd, arg, &dconf->app_token_lifetime);
        if (err != NULL) {
            dconf->app_token_lifetime *= 60;
            dconf->force_login = true;
            dconf->force_login_set = true;
        }
        break;
    case SE_ReturnURL:
        dconf->return_url = apr_pstrdup(cmd->pool, arg);
        break;
#endif

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
cfg_str12(cmd_parms *cmd, void *mconf, const char *arg, const char *arg2)
{
    intptr_t directive = (intptr_t) cmd->info;
    struct server_config *sconf;
    struct dir_config *dconf = mconf;
    const char *err = NULL;
    MWA_WACRED *cred;

    sconf = ap_get_module_config(cmd->server->module_config, &webauth_module);

    switch (directive) {
    /* Server scope only. */
    case E_Keytab:
        sconf->keytab_path = ap_server_root_relative(cmd->pool, arg);
        if (arg2 == NULL)
            sconf->keytab_principal = NULL;
        else
            sconf->keytab_principal = apr_pstrdup(cmd->pool, arg2);
        break;

    /* Directory scope only. */
    case E_Cred:
        if (dconf->creds == NULL)
            dconf->creds = apr_array_make(cmd->pool, 1, sizeof(MWA_WACRED));
        cred = apr_array_push(dconf->creds);
        cred->type = apr_pstrdup(cmd->pool, arg);
        cred->service = (arg2 == NULL) ? NULL : apr_pstrdup(cmd->pool, arg2);
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
cfg_flag(cmd_parms *cmd, void *mconf, int flag)
{
    intptr_t directive = (intptr_t) cmd->info;
    const char *err = NULL;
    struct server_config *sconf;
    struct dir_config *dconf = mconf;

    sconf = ap_get_module_config(cmd->server->module_config, &webauth_module);

    switch (directive) {
    /* Server scope only. */
    case E_Debug:
        sconf->debug = flag;
        sconf->debug_set = true;
        break;
    case E_HttpOnly:
        sconf->httponly = flag;
        sconf->httponly_set = true;
        break;
    case E_KeyringAutoUpdate:
        sconf->keyring_auto_update = flag;
        sconf->keyring_auto_update_set = true;
        break;
    case E_RequireSSL:
        sconf->require_ssl = flag;
        sconf->require_ssl_set = true;
        break;
    case E_SSLRedirect:
        sconf->ssl_redirect = flag;
        sconf->ssl_redirect_set = true;
        break;
    case E_WebKdcSSLCertCheck:
        sconf->webkdc_cert_check = flag;
        sconf->webkdc_cert_check_set = true;
        break;

    /* Server or directory scope. */
    case E_ExtraRedirect:
        if (cmd->path == NULL) {
            sconf->extra_redirect = flag;
            sconf->extra_redirect_set = true;
        } else {
            dconf->extra_redirect = flag;
            dconf->extra_redirect_set = true;
        }
        break;
    case E_TrustAuthzIdentity:
        if (cmd->path == NULL) {
            sconf->trust_authz_identity = flag;
            sconf->trust_authz_identity_set = true;
        } else {
            dconf->trust_authz_identity = flag;
            dconf->trust_authz_identity_set = true;
        }
        break;

    /* Directory scope only. */
    case E_DoLogout:
        dconf->do_logout = flag;
        dconf->do_logout_set = true;
        break;
    case E_DontCache:
        dconf->dont_cache = flag;
        dconf->dont_cache_set = true;
        break;
    case E_ForceLogin:
        dconf->force_login = flag;
        dconf->force_login_set = true;
        break;
    case E_Optional:
        dconf->optional = flag;
        dconf->optional_set = true;
        break;
    case E_SSLReturn:
        dconf->ssl_return = flag;
        dconf->ssl_return_set = true;
        break;
    case E_StripURL:
        sconf->strip_url = flag;
        sconf->strip_url_set = true;
        break;
    case E_UseCreds:
        dconf->use_creds = flag;
        dconf->use_creds_set = true;
        break;

    /* Directory scope only, legacy. */
#ifndef NO_STANFORD_SUPPORT
    case SE_DoConfirm:
        if (flag)
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL,
                         "mod_webauth: ignoring WebAuth 2.5 directive: %s",
                         cmd->directive->directive);
        break;
    case SE_DontCache:
        dconf->dont_cache = flag;
        dconf->dont_cache_set = true;
        break;
    case SE_ForceReload:
        dconf->extra_redirect = flag;
        dconf->extra_redirect_set = true;
        break;
#endif

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
#define SDIRECTIVE(init, func, scope, dir)                              \
    init(SCD_ ## dir, func, (void *) SE_ ## dir, scope, SCU_ ## dir)
#define RSRC_ORAUTH (OR_AUTHCFG | RSRC_CONF)

const command_rec webauth_cmds[] = {
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   RSRC_CONF,   AuthType),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   RSRC_CONF,   CredCacheDir),
    DIRECTIVE(AP_INIT_FLAG,    cfg_flag,  RSRC_CONF,   Debug),
    DIRECTIVE(AP_INIT_FLAG,    cfg_flag,  RSRC_CONF,   HttpOnly),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   RSRC_CONF,   Keyring),
    DIRECTIVE(AP_INIT_FLAG,    cfg_flag,  RSRC_CONF,   KeyringAutoUpdate),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   RSRC_CONF,   KeyringKeyLifetime),
    DIRECTIVE(AP_INIT_TAKE12,  cfg_str12, RSRC_CONF,   Keytab),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   RSRC_CONF,   LoginURL),
    DIRECTIVE(AP_INIT_FLAG,    cfg_flag,  RSRC_CONF,   RequireSSL),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   RSRC_CONF,   ServiceTokenCache),
    DIRECTIVE(AP_INIT_FLAG,    cfg_flag,  RSRC_CONF,   SSLRedirect),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   RSRC_CONF,   SSLRedirectPort),
    DIRECTIVE(AP_INIT_FLAG,    cfg_flag,  RSRC_CONF,   StripURL),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   RSRC_CONF,   SubjectAuthType),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   RSRC_CONF,   TokenMaxTTL),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   RSRC_CONF,   WebKdcPrincipal),
    DIRECTIVE(AP_INIT_FLAG,    cfg_flag,  RSRC_CONF,   WebKdcSSLCertCheck),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   RSRC_CONF,   WebKdcSSLCertFile),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   RSRC_CONF,   WebKdcURL),

    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   ACCESS_CONF, AppTokenLifetime),
    DIRECTIVE(AP_INIT_TAKE12,  cfg_str12, ACCESS_CONF, Cred),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   ACCESS_CONF, FailureURL),
    DIRECTIVE(AP_INIT_FLAG,    cfg_flag,  ACCESS_CONF, ForceLogin),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   ACCESS_CONF, InactiveExpire),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   ACCESS_CONF, LastUseUpdateInterval),
    DIRECTIVE(AP_INIT_FLAG,    cfg_flag,  ACCESS_CONF, UseCreds),

    DIRECTIVE(AP_INIT_FLAG,    cfg_flag,  RSRC_ORAUTH, ExtraRedirect),
    DIRECTIVE(AP_INIT_FLAG,    cfg_flag,  RSRC_ORAUTH, TrustAuthzIdentity),

    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   OR_AUTHCFG,  CookiePath),
    DIRECTIVE(AP_INIT_FLAG,    cfg_flag,  OR_AUTHCFG,  DoLogout),
    DIRECTIVE(AP_INIT_FLAG,    cfg_flag,  OR_AUTHCFG,  DontCache),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   OR_AUTHCFG,  LoginCanceledURL),
    DIRECTIVE(AP_INIT_FLAG,    cfg_flag,  OR_AUTHCFG,  Optional),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   OR_AUTHCFG,  PostReturnURL),
    DIRECTIVE(AP_INIT_ITERATE, cfg_str,   OR_AUTHCFG,  RequireInitialFactor),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   OR_AUTHCFG,  RequireLOA),
    DIRECTIVE(AP_INIT_ITERATE, cfg_str,   OR_AUTHCFG,  RequireSessionFactor),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   OR_AUTHCFG,  ReturnURL),
    DIRECTIVE(AP_INIT_FLAG,    cfg_flag,  OR_AUTHCFG,  SSLReturn),
    DIRECTIVE(AP_INIT_TAKE1,   cfg_str,   OR_AUTHCFG,  VarPrefix),

#ifndef NO_STANFORD_SUPPORT
    SDIRECTIVE(AP_INIT_TAKE1,  cfg_str,   OR_AUTHCFG,  ConfirmMsg),
    SDIRECTIVE(AP_INIT_FLAG,   cfg_flag,  OR_AUTHCFG,  DoConfirm),
    SDIRECTIVE(AP_INIT_FLAG,   cfg_flag,  OR_AUTHCFG,  DontCache),
    SDIRECTIVE(AP_INIT_FLAG,   cfg_flag,  OR_AUTHCFG,  ForceReload),
    SDIRECTIVE(AP_INIT_TAKE1,  cfg_str,   OR_AUTHCFG,  Groups),
    SDIRECTIVE(AP_INIT_TAKE1,  cfg_str,   OR_AUTHCFG,  Life),
    SDIRECTIVE(AP_INIT_TAKE1,  cfg_str,   OR_AUTHCFG,  ReturnURL),
#endif

    { NULL, { NULL }, NULL, OR_NONE, RAW_ARGS, NULL }
};
