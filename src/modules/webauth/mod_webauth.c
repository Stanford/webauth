/* 
**  mod_webauth.c -- Apache sample webauth module
**  [Autogenerated via ``apxs -n webauth -g'']
**
**  To play with this sample module first compile it into a
**  DSO file and install it into Apache's modules directory 
**  by running:
**
**    $ apxs -c -i mod_webauth.c
**
**  Then activate it in Apache's httpd.conf file for instance
**  for the URL /webauth in as follows:
**
**    #   httpd.conf
**    LoadModule webauth_module modules/mod_webauth.so
**    <Location /webauth>
**    SetHandler webauth
**    </Location>
**
**  Then after restarting Apache via
**
**    $ apachectl restart
**
**  you immediately can request the URL /webauth and watch for the
**  output of this module. This can be achieved for instance via:
**
**    $ lynx -mime_header http://localhost/webauth 
**
**  The output should be similar to the following one:
**
**    HTTP/1.1 200 OK
**    Date: Tue, 31 Mar 1998 14:42:22 GMT
**    Server: Apache/1.3.4 (Unix)
**    Connection: close
**    Content-Type: text/html
**  
**    The sample page from mod_webauth.c
*/ 

#include "mod_webauth.h"

/*
 *
 */
static void log_request(request_rec *r, const char *msg)
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

static int 
die(const char *message, server_rec *s)
{
    if (s) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "mod_webauth: fatal error: %s", message);
    }
    printf("mod_webauth: fatal error: %s\n", message);
    exit(1);
}




/*
 * called after config has been loaded in parent process
 */
static int
post_config_hook(apr_pool_t *pconf, apr_pool_t *plog,
                 apr_pool_t *ptemp, server_rec *s)
{
    WEBAUTH_SCONF *sconf;

    sconf = (WEBAUTH_SCONF*)ap_get_module_config(s->module_config,
                                                 &webauth_module);

    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_webauth: post_config_hook");

#define CHECK_DIR(field,dir) if (sconf->field == NULL) \
             die(apr_psprintf(ptemp, "directive %s must be set", dir), s)

    CHECK_DIR(login_url, CD_LoginURL);

#undef CHECK_DIR

    return OK;
}

/*
 * called once per-child
 */
static void
child_init_hook(apr_pool_t *p, server_rec *s)
{
    WEBAUTH_SCONF *sconf;

    sconf = (WEBAUTH_SCONF*)ap_get_module_config(s->module_config,
                                                 &webauth_module);

    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_webauth: child_init_hook");
}

/*
**
**  per-server configuration structure handling
**
*/

static void *
config_server_create(apr_pool_t *p, server_rec *s)
{
    WEBAUTH_SCONF *sconf;

    sconf = (WEBAUTH_SCONF*)apr_pcalloc(p, sizeof(WEBAUTH_SCONF));
    /* no defaults */
    return (void *)sconf;
}

static void *
config_dir_create(apr_pool_t *p, char *path)
{
    WEBAUTH_DCONF *dconf;
    dconf = (WEBAUTH_DCONF*)apr_pcalloc(p, sizeof(WEBAUTH_DCONF));
    /* no defaults */
    return (void *)dconf;
}


#define SET_STR(field) \
    conf->field = (oconf->field != NULL) ? oconf->field : bconf->field

#define SET_INT(field) \
    conf->field = oconf->field ? oconf->field : bconf->field

static void *
config_server_merge(apr_pool_t *p, void *basev, void *overv)
{
    WEBAUTH_SCONF *conf, *bconf, *oconf;

    conf = (WEBAUTH_SCONF*) apr_pcalloc(p, sizeof(WEBAUTH_SCONF));
    bconf = (WEBAUTH_SCONF*) basev;
    oconf = (WEBAUTH_SCONF*) overv;

    SET_STR(webkdc_url);
    SET_STR(login_url);
    SET_STR(failure_url);
    SET_STR(keyring_path);
    SET_STR(keytab_path);
    SET_STR(st_cache_path);
    SET_STR(var_prefix);
    SET_INT(debug);
    return (void *)conf;
}

static void *
config_dir_merge(apr_pool_t *p, void *basev, void *overv)
{
    WEBAUTH_DCONF *conf, *bconf, *oconf;

    conf = (WEBAUTH_DCONF*) apr_pcalloc(p, sizeof(WEBAUTH_DCONF));
    bconf = (WEBAUTH_DCONF*) basev;
    oconf = (WEBAUTH_DCONF*) overv;

    SET_INT(app_token_lifetime);
    SET_INT(token_max_ttl);
    SET_STR(subject_auth_type);
    SET_INT(inactive_expire);
    SET_INT(hard_expire);
    SET_INT(force_login);
    SET_STR(return_url);
    return (void *)conf;
}

#undef SET_STR
#undef SET_INT

/* The sample content handler */
static int 
handler_hook(request_rec *r)
{
    if (strcmp(r->handler, "webauth")) {
        return DECLINED;
    }
    r->content_type = "text/html";      

    if (!r->header_only)
        ap_rputs("The sample page from mod_webauth.c\n", r);
    return OK;
}

static int 
check_user_id_hook(request_rec *r)
{
    const char *at = ap_auth_type(r);
    WEBAUTH_SCONF *sconf;

    sconf = (WEBAUTH_SCONF*)ap_get_module_config(r->server->module_config,
                                                 &webauth_module);

    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                 "mod_webauth: in check_user_id hook");


    if ((at == NULL) || (strcmp(at, "WebAuth") != 0)) {
        return DECLINED;
    }

    if ((r->args != NULL) && (*(r->args) == 'Z')) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                 "mod_webauth: set Location, returning redirect...");
    apr_table_setn(r->headers_out, "Location", sconf->login_url);
        return HTTP_MOVED_TEMPORARILY;
    } else {
        return OK;
    }
}

static int 
auth_checker_hook(request_rec *r)
{
    return DECLINED;
}

static void
strip_end(char *c)
{
    char *p;
    char *t = ";;GOO=";
    if (c != NULL) {
        p = ap_strstr(c, t);
        if (p != NULL)
            *p = '\0';
    }
}

/*
 *  need to check the following to see if we got passed back any tokens
 *    r->the_request
 *    r->unparsed_uri
 *    r->uri
 *    r->filename
 *    r->canonical_filename
 *    r->path_info
 *    r->args
 *    r->parsed_uri.path
 *    r->parsed_uri.query
 *
 *  we'll stick the token in the notes table for the initial
 *  request
 *  
 */
static int 
translate_name_hook(request_rec *r)
{
    char *p;
    char *t = ";;GOO=";

    /* only need to check for tokens on the initial requeste */
    if (!ap_is_initial_req(r)) {
        return DECLINED;
    }

    log_request(r, "before xlate");

    if (r->the_request != NULL) {
        p = ap_strstr(r->the_request, t);
        if (p != NULL) {
            char *d = p;
            int past_goo=0;
            p += 6;
            while (*p) {
                if (!past_goo && (*p == ';' && *(p+1) == ';')) {
                    p+=2;
                    past_goo = 1;
                }
                if (past_goo) {
                    *d++ = *p;
                }
                p++;
            }
            *d = '\0';
        }
    }

    strip_end(r->unparsed_uri);
    strip_end(r->uri);
    strip_end(r->filename);
    strip_end(r->canonical_filename);
    strip_end(r->path_info);
    strip_end(r->args);
    strip_end(r->parsed_uri.path);
    strip_end(r->parsed_uri.query);

    log_request(r, "after xlate");

    return DECLINED;
}

static int 
fixups_hook(request_rec *r)
{
    WEBAUTH_DCONF *dconf;
    WEBAUTH_SCONF *sconf;

    dconf = (WEBAUTH_DCONF*)ap_get_module_config(r->per_dir_config,
                                                 &webauth_module);

    sconf = (WEBAUTH_SCONF*)ap_get_module_config(r->server->module_config,
                                                 &webauth_module);


    if (ap_is_initial_req(r)) {
        char *new_cookie;
        const char *at;
        /*new_cookie = apr_psprintf(r->pool, "MOD_WEBAUTH=%d; path=/",
                                  apr_time_now());
        apr_table_setn(r->headers_out, "Set-Cookie", new_cookie);
        */

        at = ap_auth_type(r);
        if (at == NULL) at = "(null)";
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, 
                     "mod_webauth: fixups auth_type(%s)", at);
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, 
                     "mod_webauth: main fixups url(%s)", r->unparsed_uri);

    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, 
                     "mod_webauth: subreq fixups url(%s)", r->unparsed_uri);
    }
    return DECLINED;
}


static const char *
cfg_str(cmd_parms *cmd, void *mconf, const char *arg)
{
    int e = (int)cmd->info;
    char *error_str = NULL;
    WEBAUTH_DCONF *dconf = (WEBAUTH_DCONF *)mconf;

    WEBAUTH_SCONF *sconf = (WEBAUTH_SCONF *)
        ap_get_module_config(cmd->server->module_config, &webauth_module);
    
    char *value = apr_pstrdup(cmd->pool, arg);

    switch (e) {
        /* server configs */
        case E_WebKDCURL:
            sconf->webkdc_url = value;
            break;
        case E_LoginURL:
            sconf->login_url = value;
            break;
        case E_FailureURL:
            sconf->failure_url = value;
            break;
        case E_Keyring:
            sconf->keyring_path = value;
            break;
        case E_Keytab:
            sconf->keytab_path = value;
            break;
        case E_ServiceTokenCache:
            sconf->st_cache_path = value;
            break;
        case E_VarPrefix:
            sconf->var_prefix = value;
            break;
            /* start of dconfigs */
        case E_SubjectAuthType:
            dconf->subject_auth_type = value;
            break;
        case E_ReturnURL:
            dconf->return_url = value;
            break;
        default:
            error_str = 
                apr_psprintf(cmd->pool,
                             "Invalid value cmd->info(%d) for directive %s",
                             e,
                             cmd->directive->directive);
            break;

    }
    return error_str;
}


static const char *
cfg_flag(cmd_parms *cmd, void *mconfig, int flag)
{
    int e = (int)cmd->info;
    char *error_str = NULL;
    WEBAUTH_DCONF *dconf = (WEBAUTH_DCONF*) mconfig;

    WEBAUTH_SCONF *sconf = (WEBAUTH_SCONF *)
        ap_get_module_config(cmd->server->module_config, &webauth_module);
    
    switch (e) {
        /* server configs */
        case E_Debug:
            sconf->debug = flag;
            break;
            /* start of dconfigs */
        case E_ForceLogin:
            dconf->force_login = flag;
            break;
        default:
            error_str = 
                apr_psprintf(cmd->pool,
                             "Invalid value cmd->info(%d) for directive %s",
                             e,
                             cmd->directive->directive);
            break;

    }
    return error_str;
}

static const char *
cfg_int(cmd_parms *cmd, void *mconf, const char *arg)
{
    int e = (int)cmd->info;
    char *endptr;
    char *error_str = NULL;
    WEBAUTH_DCONF *dconf = (WEBAUTH_DCONF*) mconf;

    int val = (int) strtol(arg, &endptr, 10);

    if ((*arg == '\0') || (*endptr != '\0')) {
        error_str = apr_psprintf(cmd->pool,
                     "Invalid value for directive %s, expected integer",
                     cmd->directive->directive);
    } else {
        switch (e) {
            /* start of dconfigs */
            case E_AppTokenLifetime:
                dconf->app_token_lifetime = val;
                break;
            case E_TokenMaxTTL:
                dconf->token_max_ttl = val;
                break;
            case E_InactiveExpire:
                dconf->inactive_expire = val;
                break;
            case E_HardExpire:
                dconf->hard_expire = val;
                break;
            default:
                error_str = 
                    apr_psprintf(cmd->pool,
                                "Invalid value cmd->info(%d) for directive %s",
                                 e,
                                 cmd->directive->directive);
                break;
        }
    }
    return error_str;
}


#define SSTR(dir,mconfig,help) \
  {dir, (cmd_func)cfg_str,(void*)mconfig, RSRC_CONF, TAKE1, help}

#define SFLAG(dir,mconfig,help) \
  {dir, (cmd_func)cfg_flag,(void*)mconfig, RSRC_CONF, FLAG, help}

#define SINT(dir,mconfig,help) \
  {dir, (cmd_func)cfg_int, (void*)mconfig, RSRC_CONF, TAKE1, help}

#define DSTR(dir,mconfig,help) \
  {dir, (cmd_func)cfg_str,(void*)mconfig, OR_AUTHCFG, TAKE1, help}

#define DFLAG(dir,mconfig,help) \
  {dir, (cmd_func)cfg_flag,(void*)mconfig, OR_AUTHCFG, FLAG, help}

#define DINT(dir,mconfig,help) \
  {dir, (cmd_func)cfg_int, (void*)mconfig, OR_AUTHCFG, TAKE1, help}

static const command_rec cmds[] = {
    /* server/vhost */
    SSTR(CD_WebKDCURL, E_WebKDCURL, CM_WebKDCURL),
    SSTR(CD_LoginURL, E_LoginURL, CM_LoginURL),
    SSTR(CD_FailureURL, E_FailureURL, CM_FailureURL),
    SSTR(CD_Keyring, E_Keyring, CM_Keyring),
    SSTR(CD_Keytab, E_Keytab,  CM_Keytab),
    SSTR(CD_ServiceTokenCache, E_ServiceTokenCache, CM_ServiceTokenCache),
    SSTR(CD_VarPrefix, E_VarPrefix, CM_VarPrefix),
    SFLAG(CD_Debug, E_Debug, CM_Debug),

    /* directory */
    DINT(CD_AppTokenLifetime, E_AppTokenLifetime, CM_AppTokenLifetime),
    DINT(CD_TokenMaxTTL, E_TokenMaxTTL, CM_TokenMaxTTL),
    DSTR(CD_SubjectAuthType, E_SubjectAuthType, CM_SubjectAuthType),
    DINT(CD_InactiveExpire, E_InactiveExpire, CM_InactiveExpire),
    DINT(CD_HardExpire, E_HardExpire, CM_HardExpire),
    DFLAG(CD_ForceLogin, E_ForceLogin, CM_ForceLogin),
    DSTR(CD_ReturnURL, E_ReturnURL, CM_ReturnURL)
};

#undef SSTR
#undef SFLAG
#undef SINT
#undef DSTR
#undef DFLAG
#undef DINT

static void 
register_hooks(apr_pool_t *p)
{
    /* get our module called before the basic authentication stuff */
    static const char * const mods[]={ "mod_access.c", "mod_auth.c", NULL };

    ap_hook_post_config(post_config_hook, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(child_init_hook, NULL, NULL, APR_HOOK_MIDDLE);

    /* unclear if we have to use APR_HOOK_FIRST or not for translate_name */
    ap_hook_translate_name(translate_name_hook, NULL, NULL, APR_HOOK_FIRST);

    ap_hook_check_user_id(check_user_id_hook, NULL, mods, APR_HOOK_MIDDLE);
    //ap_hook_auth_checker(webauth_auth_checker, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(handler_hook, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_fixups(fixups_hook, NULL,NULL,APR_HOOK_MIDDLE);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA webauth_module = {
    STANDARD20_MODULE_STUFF, 
    config_dir_create,     /* create per-dir    config structures */
    config_dir_merge,      /* merge  per-dir    config structures */
    config_server_create,  /* create per-server config structures */
    config_server_merge,   /* merge  per-server config structures */
    cmds,                  /* table of config file commands       */
    register_hooks         /* register hooks                      */
};

