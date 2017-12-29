/*
 * Core WebAuth Apache module code.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2003, 2004, 2006, 2008, 2009, 2010, 2011, 2012, 2013, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config-mod.h>
#include <portable/apache.h>
#include <portable/apr.h>
#include <portable/stdbool.h>

#include <unistd.h>

#include <modules/webauth/mod_webauth.h>
#include <util/macros.h>
#include <webauth/basic.h>
#include <webauth/factors.h>
#include <webauth/keys.h>
#include <webauth/tokens.h>

APLOG_USE_MODULE(webauth);

#if MODULE_MAGIC_NUMBER_MAJOR >= 20111201
# define HTTPD24 1
#endif


/*
 * Called at any entry point where we may be doing WebAuth operations that
 * need a keyring.  Do lazy initialization of the in-memory keyring from the
 * disk file and store it in the virtual host context.  Returns true if the
 * keyring could be loaded correctly and false otherwise.
 */
static bool
ensure_keyring_loaded(MWA_REQ_CTXT *rc)
{
    int s;

    apr_thread_mutex_lock(rc->sconf->mutex);
    if (rc->sconf->ring != NULL) {
        apr_thread_mutex_unlock(rc->sconf->mutex);
        return true;
    }
    s = mwa_cache_keyring(rc->r->server, rc->sconf);
    apr_thread_mutex_unlock(rc->sconf->mutex);
    return (s == WA_ERR_NONE && rc->sconf->ring != NULL);
}


/*
 * Check whether the AuthType of the current request is set to one of the
 * AuthType values that we handle.  Returns true if so and false if not.
 */
static bool
is_supported_authtype(request_rec *r, MWA_REQ_CTXT *rc)
{
    const char *auth_type = ap_auth_type(r);

    if (auth_type == NULL)
        return false;
    if (strcmp(auth_type, "WebAuth") == 0)
        return true;
    if (rc->sconf->auth_type != NULL)
        if (strcmp(auth_type, rc->sconf->auth_type) == 0)
            return true;
    return false;
}


static void
dont_cache(MWA_REQ_CTXT *rc)
{
    rc->r->no_cache = 1;
    rc->r->mtime = apr_time_now();
    apr_table_addn(rc->r->err_headers_out, "Pragma", "no-cache");
    apr_table_setn(rc->r->err_headers_out, "Cache-Control",
                   "private, no-cache, no-store, max-age=0");
    apr_table_addn(rc->r->err_headers_out, "Vary", "*");
}


static int
do_redirect(MWA_REQ_CTXT *rc)
{
    dont_cache(rc);
    return HTTP_MOVED_TEMPORARILY;
}


/*
 * remove a string from the end of another string
 */
static void
strip_end(char *c, const char *t)
{
    char *p;
    if (c != NULL) {
        p = ap_strstr(c, t);
        if (p != NULL)
            *p = '\0';
    }
}


/*
 * return 1 if current request is "https"
 */
static int
is_https(request_rec *r)
{
    const char *scheme;

    scheme = ap_http_scheme(r);
    return (scheme != NULL) && strcmp(scheme, "https") == 0;
}


/*
 * Remove any webauth_* cookies and tokens from Referer before proxying the
 * request.
 *
 * FIXME: We do in-place edits on the headers, which APR says you're not
 * supposed to do (the return type is declared const).  We should figure out
 * if there's a better way to do this.
 */
static void
strip_webauth_info(MWA_REQ_CTXT *rc)
{
    char *c;
    size_t cookie_start, copy;
    char *d, *s;
    const char *mwa_func = "strip_webauth_cookies";

    c = (char*) apr_table_get(rc->r->headers_in, "Referer");
    if (c != NULL)
        strip_end(c, WEBAUTHR_MAGIC);

    c = (char*) apr_table_get(rc->r->headers_in, "Cookie");

    if (c == NULL || (ap_strstr(c, "webauth_") == NULL))
        return;

    if (rc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                     "mod_webauth: %s: need to strip: %s", mwa_func, c);
    s = d = c;
    cookie_start = copy = 1;
    while (*s) {
        if (cookie_start && *s != ' ') {
            copy = strncmp(s, "webauth_", 8) != 0;
            cookie_start = 0;
        } else if (*s == ';') {
            cookie_start = 1;
        }
        if (copy) {
            if (d != s)
                *d = *s;
            d++;
        }
        s++;
    }

    /* strip of trailing space */
    while (d > c && *(d-1) == ' ')
        d--;

    /* null-terminate */
    *d = '\0';

    if (*c == '\0') {
        apr_table_unset(rc->r->headers_in, "Cookie");
        if (rc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                         "mod_webauth: %s: no cookies after strip", mwa_func);
    } else {
        /* we modified the Cookie header in place */
        if (rc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                         "mod_webauth: %s: after strip: %s", mwa_func, c);
    }
}


/*
 * find a cookie in the Cookie header and return its value, otherwise
 * return NULL.
 */
static char *
find_cookie(MWA_REQ_CTXT *rc, const char *name)
{
    const char *c;
    char *cs, *ce, *cval;
    int len;

    c = apr_table_get(rc->r->headers_in, "Cookie");
    if (c == NULL)
        return NULL;

    len = strlen(name);

    while ((cs = ap_strstr(c, name))) {
        if (cs[len] == '=') {
            cs += len+1;
            break;
        }
        c += len;
    }

    if (cs == NULL)
        return NULL;

    ce = ap_strchr(cs, ';');

    if (ce == NULL) {
        cval = apr_pstrdup(rc->r->pool, cs);
    } else {
        cval = apr_pstrmemdup(rc->r->pool, cs, ce-cs);
    }

    return cval;
}


/*
 * nuke a cooke by directly updating r->err_headers_out. If
 * if_set is true, then only nuke the cookie if its set.
 */
static void
nuke_cookie(MWA_REQ_CTXT *rc, const char *name, int if_set)
{
    char *cookie;
    const char *path = "/";
    bool is_secure = is_https(rc->r) || rc->dconf->ssl_return;

    if (if_set && find_cookie(rc, name) == NULL)
        return;

    if (rc->dconf->cookie_path != NULL)
        path = rc->dconf->cookie_path;
    cookie = apr_psprintf(rc->r->pool,
                          "%s=; path=%s; expires=%s;%s",
                          name, path,
                          "Thu, 26-Mar-1998 00:00:01 GMT",
                          is_secure ? "secure" : "");
    if (rc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                     "mod_webauth: nuking cookie(%s): (%s)",
                     name, cookie);
    apr_table_addn(rc->r->err_headers_out, "Set-Cookie", cookie);
}


/*
 * add set cookie header
 */
static int
set_pending_cookie_cb(void *rec, const char *key, const char *value)
{
    MWA_REQ_CTXT *rc = rec;

    if (strncmp(key, "mod_webauth_COOKIE_", 19) == 0) {
        apr_table_addn(rc->r->err_headers_out, "Set-Cookie", value);
        if (rc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                         "mod_webauth: set_pending_cookie_cb: %s", value);
    }
    return 1;
}


/*
 * Pending cookies that we're going to send are stored as notes inside the
 * main request and then converted into outgoing headers during fixups.  This
 * function converts the notes to headers and is called during fixups.
 */
static void
set_pending_cookies(MWA_REQ_CTXT *rc)
{
    apr_table_t *t;

    if (rc->r->main != NULL)
        t = rc->r->main->notes;
    else
        t = rc->r->notes;

    /*
     * If there is no notes table, assume we have no cookies to set.  This
     * reportedly can happen with Solaris 10 x86's included Apache (2.0.63).
     */
    if (t != NULL)
        apr_table_do(set_pending_cookie_cb, rc, t, NULL);
}


/*
 * Stores a cookie that will get set later by the fixup handler.  Takes the
 * name of the cookie, the value, and optionally the path, which may be NULL
 * to use a path of /.  The secure flag is always set if the request came in
 * via SSL, and the HttpOnly flag is set based on the server configuration.
 */
static void
fixup_setcookie(MWA_REQ_CTXT *rc, const char *name, const char *value,
                const char *path)
{
    bool is_secure = is_https(rc->r) || rc->dconf->ssl_return;

    if (path == NULL)
        path = "/";
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                 "mod_webauth: setting pending %s cookie (path %s)", name,
                 path);
    mwa_setn_note(rc->r,
                  "mod_webauth_COOKIE_",
                  name,
                  "%s=%s; path=%s%s%s",
                  name,
                  value,
                  path,
                  is_secure ? "; secure" : "",
                  rc->sconf->httponly ? "; HttpOnly" : "");
}


/*
 * set environment variables in the subprocess_env table.
 * also handles WebAuthVarPrefix
 */
static void
mwa_setenv(MWA_REQ_CTXT *rc, const char *name, const char *value)
{
    if (rc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, rc->r->server,
                     "mod_webauth: mwa_setenv: (%s) (%s)",
                     name, value);
    apr_table_setn(rc->r->subprocess_env, name, value);
    if (rc->dconf->var_prefix != NULL) {
        name = apr_pstrcat(rc->r->pool,
                          rc->dconf->var_prefix, name, NULL);
        apr_table_setn(rc->r->subprocess_env, name, value);
    }
}


/*
 * enumerate through all webauth_ cookies and nuke them.
 */
static void
nuke_all_webauth_cookies(MWA_REQ_CTXT *rc)
{
    int i;
    apr_array_header_t *cookies;

    cookies = mwa_get_webauth_cookies(rc->r);
    if (cookies == NULL)
        return;
    for (i = 0; i < cookies->nelts; i++) {
        char *cookie, *val;

        /*
         * Nuke all WebAuth cookies except for the ones used by WebLogin.  The
         * latter may appear if the same virtual host is used as both a
         * WebAuth Application Server and a WebLogin server.
         */
        cookie = APR_ARRAY_IDX(cookies, i, char *);
        val = ap_strchr(cookie, '=');
        if (val != NULL) {
            *val++ = '\0';
            if (strncmp(cookie, "webauth_wpt", 11) != 0
                && strncmp(cookie, "webauth_wft", 11) != 0) {
                nuke_cookie(rc, cookie, 1);
            }
        }
    }
}


/* FIXME: should we pass some query paramters along with
 *        failure_redirect to indicate what failure occured?
 *
 */
static int
failure_redirect(MWA_REQ_CTXT *rc)
{
    const char *redirect_url, *uri;
    const char *mwa_func="failure_redirect";

    ap_discard_request_body(rc->r);

    uri = rc->dconf->failure_url;

    if (uri == NULL) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, rc->r->server,
                     "mod_webauth: %s: no URL configured", mwa_func);
        set_pending_cookies(rc);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (uri[0] != '/') {
        redirect_url = uri;
    } else {
        redirect_url = ap_construct_url(rc->r->pool, uri, rc->r);
    }

    apr_table_setn(rc->r->err_headers_out, "Location", redirect_url);

    if (rc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                     "mod_webauth: %s: redirect(%s)", mwa_func, redirect_url);

    set_pending_cookies(rc);
    return do_redirect(rc);
}


static int
login_canceled_redirect(MWA_REQ_CTXT *rc)
{
    const char *redirect_url, *uri;
    const char *mwa_func = "login_canceled_redirect";
    ap_discard_request_body(rc->r);

    uri = rc->dconf->login_canceled_url;

    if (uri == NULL) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, rc->r->server,
                   "mod_webauth: %s: no URL configured!", mwa_func);
        return failure_redirect(rc);
    }

    if (uri[0] != '/') {
        redirect_url = uri;
    } else {
        redirect_url = ap_construct_url(rc->r->pool, uri, rc->r);
    }

    apr_table_setn(rc->r->err_headers_out, "Location", redirect_url);

    if (rc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                     "mod_webauth: %s: redirect(%s)", mwa_func, redirect_url);

    set_pending_cookies(rc);
    return do_redirect(rc);
}


/*
 * called on restarts
 */
static apr_status_t
mod_webauth_cleanup(void *data)
{
    server_rec *s = (server_rec*) data;
    server_rec *t;
    struct server_config *sconf;

    sconf = ap_get_module_config(s->module_config, &webauth_module);
    if (sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_webauth: cleanup");

    /* walk through list of servers and clean up */
    for (t=s; t; t=t->next) {
        struct server_config *tconf;

        tconf = ap_get_module_config(t->module_config, &webauth_module);

        /* service_token is currently never set in the parent,
         * add it here in case we change caching strategy.
         */
        if (tconf->service_token) {
            apr_pool_destroy(tconf->service_token->pool);
            tconf->service_token = NULL;
            if (sconf->debug) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                             "mod_webauth: cleanup service_token: %s",
                             tconf->st_cache_path);
            }
        }
    }
    return APR_SUCCESS;
}


/*
 * called after config has been loaded in parent process
 */
static int
mod_webauth_init(apr_pool_t *pconf, apr_pool_t *plog UNUSED,
                 apr_pool_t *ptemp UNUSED, server_rec *s)
{
    struct server_config *sconf;
    server_rec *scheck;

    sconf = ap_get_module_config(s->module_config, &webauth_module);

    /* FIXME: this needs to be configurable at some point */
    mwa_register_cred_interface(s, sconf, pconf, mwa_krb5_cred_interface);

    if (sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "mod_webauth: initializing");

    apr_pool_cleanup_register(pconf, s,
                              mod_webauth_cleanup,
                              apr_pool_cleanup_null);

    for (scheck=s; scheck; scheck=scheck->next) {
        mwa_config_init(scheck, sconf, pconf);
    }

    ap_add_version_component(pconf, "WebAuth/" VERSION);

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                 "mod_webauth: initialized (%s)%s", VERSION,
                 sconf->debug ? " (" PACKAGE_BUILD_INFO ")" : "");

    return OK;
}


/*
 * Called when a new request is created.  Initialize our per-request data
 * structure and store it in the request.
 */
static int
mod_webauth_create_request(request_rec *r)
{
    MWA_REQ_CTXT *rc;

    rc = apr_pcalloc(r->pool, sizeof(MWA_REQ_CTXT));
    rc->r = r;
    ap_set_module_config(r->request_config, &webauth_module, rc);
    return OK;
}


/*
 * Finish setting up the WebAuth request context by retrieving the module
 * configuration information.
 *
 * In the 2.2 httpd, called from access_checker.
 * in the 2.4 httpd, called from post_perdir_config.
 */
static int
mod_webauth_post_config(request_rec *r) {
    MWA_REQ_CTXT *rc;

    rc = ap_get_module_config(r->request_config, &webauth_module);
    rc->dconf = ap_get_module_config(r->per_dir_config, &webauth_module);
    rc->sconf = ap_get_module_config(r->server->module_config, &webauth_module);

#ifdef HTTPD24
    /* post_perdir_config says: */
    return OK;
#else
    /* access_checker says: */
    return DECLINED;
#endif
}


static const char *
status_check_access(const char *path, apr_int32_t flag, request_rec *r)
{
    apr_status_t st;
    apr_file_t *f;
    char errbuff[512];

    st = apr_file_open(&f, path, flag, APR_FPROT_UREAD | APR_FPROT_UWRITE,
                       r->pool);
    if (st != APR_SUCCESS) {
        errbuff[0] = 0;
        apr_strerror(st, errbuff, sizeof(errbuff)-1);
        return apr_pstrdup(r->pool, errbuff);
    } else {
        apr_file_close(f);
        return "ok";
    }
}


static void
dt_str(const char *n, const char *v, request_rec *r)
{
    ap_rprintf(r, "<dt><strong>%s:</strong> "
               /*"<tt>%s</tt></dt>\n", n, v);*/
               "<font size=\"+1\"><tt>%s</tt></font></dt>\n", n, v);
}


static void
dd_dir_str(const char *n, const char *v, request_rec *r)
{
    if (v == NULL) {
        return;
        /*v = "(value not set)";*/
    }

    ap_rprintf(r, "<dd><tt>%s %s</tt></dd>",
               ap_escape_html(r->pool, n),
               ap_escape_html(r->pool, v));
}


static void
dd_dir_int(const char *n, int v, request_rec *r)
{
    ap_rprintf(r, "<dd><tt>%s %d</tt></dd>",
               ap_escape_html(r->pool, n),
               v);
}


static void
dd_dir_time(const char *n, time_t t, request_rec *r)
{
    char buffer[APR_CTIME_LEN+1];

    apr_ctime(buffer, (apr_time_from_sec(t)));
    dd_dir_str(n, buffer, r);
}


/* The content handler */
static int
handler_hook(request_rec *r)
{
    struct server_config *sconf;
    MWA_REQ_CTXT *rc;
    MWA_SERVICE_TOKEN *st;
    apr_int32_t flags;

    if (strcmp(r->handler, "webauth")) {
        return DECLINED;
    }

    r->allowed |= (AP_METHOD_BIT << M_GET);
    if (r->method_number != M_GET)
        return DECLINED;

    sconf = ap_get_module_config(r->server->module_config, &webauth_module);

    /*
     * Create a module context and try to load the keyring.  If this fails,
     * we'll notice and print out diagnostic information later.
     */
    rc = apr_pcalloc(r->pool, sizeof(MWA_REQ_CTXT));
    rc->r = r;
    rc->dconf = ap_get_module_config(r->per_dir_config, &webauth_module);
    rc->sconf = sconf;
    ensure_keyring_loaded(rc);

    r->content_type = "text/html";

    if (!sconf->debug) {
        ap_rputs(DOCTYPE_HTML_3_2
                 "<html><head><title>mod_webauth status</title></head>\n", r);
        ap_rputs("<body><h1 align=\"center\">mod_webauth status</h1>\n", r);
        ap_rputs("<b>You must have \"WebAuthDebug on\" in your config file "
                 "to enable this information.</b>", r);
        ap_rputs("</body></html>\n", r);
        return OK;
    }

    ap_rputs(DOCTYPE_HTML_3_2
             "<html><head><title>mod_webauth status</title></head>\n", r);
    ap_rputs("<body><h1 align=\"center\">mod_webauth status</h1>\n", r);
    ap_rputs("<hr/>", r);

    ap_rputs("<dl>", r);
    dt_str("Server Version", ap_get_server_description(), r);
    dt_str("Server Built",   ap_get_server_built(), r);
    dt_str("Hostname/port",
           apr_psprintf(r->pool, "%s:%u",
                        ap_get_server_name(r), ap_get_server_port(r)), r);
    ap_rputs("</dl>", r);
    ap_rputs("<hr/>", r);

    ap_rputs("<dl>", r);

    dt_str("WebAuth Info Version", VERSION, r);
    dt_str("WebAuth Info Build", PACKAGE_BUILD_INFO, r);

    ap_rputs("<dt><strong>Current Configuration (server directives only):</strong></dt>\n", r);


    dd_dir_str("WebAuthAuthType", sconf->auth_type, r);
    dd_dir_str("WebAuthCredCacheDir", sconf->cred_cache_dir, r);
    dd_dir_str("WebAuthDebug", sconf->debug ? "on" : "off", r);
    dd_dir_str("WebAuthKeyRing", sconf->keyring_path, r);
    dd_dir_str("WebAuthKeyRingAutoUpdate", sconf->keyring_auto_update ? "on" : "off", r);
    dd_dir_str("WebAuthKeyRingKeyLifetime",
               apr_psprintf(r->pool, "%lus", sconf->keyring_key_lifetime), r);
    if (sconf->keytab_principal == NULL) {
        dd_dir_str("WebAuthKeytab", sconf->keytab_path, r);
    } else {
        dd_dir_str("WebAuthKeytab",
                   apr_psprintf(r->pool, "%s %s",
                                sconf->keytab_path,
                                sconf->keytab_principal), r);
    }
    dd_dir_str("WebAuthLoginUrl", sconf->login_url, r);
    dd_dir_str("WebAuthServiceTokenCache", sconf->st_cache_path, r);
    dd_dir_str("WebAuthSubjectAuthType", sconf->subject_auth_type, r);
    dd_dir_str("WebAuthSSLRedirect", sconf->ssl_redirect ? "on" : "off", r);
    if (sconf->ssl_redirect_port != 0) {
        dd_dir_str("WebAuthSSLRedirectPort",
                   apr_psprintf(r->pool, "%lu", sconf->ssl_redirect_port), r);
    }
    dd_dir_str("WebAuthTokenMaxTTL",
               apr_psprintf(r->pool, "%lus", sconf->token_max_ttl), r);
    dd_dir_str("WebAuthWebKdcPrincipal", sconf->webkdc_principal, r);
    dd_dir_str("WebAuthWebKdcSSLCertFile", sconf->webkdc_cert_file, r);
    dd_dir_str("WebAuthWebKdcSSLCertCheck",
               sconf->webkdc_cert_check ? "on" : "off", r);
    dd_dir_str("WebAuthWebKdcURL", sconf->webkdc_url, r);

    ap_rputs("</dl>", r);
    ap_rputs("<hr/>", r);

    ap_rputs("<dl>", r);
    dt_str("Keyring read check",
           status_check_access(sconf->keyring_path, APR_FOPEN_READ, r), r);
    ap_rputs("<dt><strong>Keyring info:</strong></dt>\n", r);

    if (sconf->ring == NULL) {
        ap_rputs("<dd>"
                 "keyring is NULL. This usually indicates a permissions "
                 "problem with the keyring file."
                 "</dd>", r);
    } else {
        int i;
        struct webauth_keyring_entry *entry;

        dd_dir_int("num_entries", sconf->ring->entries->nelts, r);
        for (i = 0; i < sconf->ring->entries->nelts; i++) {
            entry = &APR_ARRAY_IDX(sconf->ring->entries, i,
                                   struct webauth_keyring_entry);
            dd_dir_time(apr_psprintf(r->pool, "entry %d creation time", i),
                        entry->creation, r);
            dd_dir_time(apr_psprintf(r->pool, "entry %d valid after", i),
                        entry->valid_after, r);
        }
    }

    ap_rputs("</dl>", r);
    ap_rputs("<hr/>", r);

    ap_rputs("<dl>", r);

    dt_str("Keytab read check",
           status_check_access(sconf->keytab_path, APR_FOPEN_READ, r), r);
    ap_rputs("</dl>", r);
    ap_rputs("<hr/>", r);

    ap_rputs("<dl>", r);

    st = mwa_get_service_token(r->server, sconf, r->pool, 0);

    flags = APR_FOPEN_READ | APR_FOPEN_WRITE | APR_FOPEN_CREATE;
    dt_str("Service Token Cache read/write check",
           status_check_access(sconf->st_cache_path, flags, r), r);
    ap_rputs("<dt><strong>Service Token info:</strong></dt>\n", r);

    if (st == NULL) {
        ap_rputs("<dd>"
                 "service_token is NULL. This usually indicates a permissions "
                 "problem with the service token cache and/or keytab file."
                 "</dd>", r);
    } else {
        dd_dir_time("created", st->created, r);
        dd_dir_time("expires", st->expires, r);
        dd_dir_time("next_renewal_attempt", st->next_renewal_attempt, r);
        if (st->last_renewal_attempt != 0)
            dd_dir_time("last_renewal_attempt", st->last_renewal_attempt, r);
    }

    ap_rputs("</dl>", r);
    ap_rputs("<hr/>", r);
    ap_rputs(ap_psignature("",r), r);
    ap_rputs("</body></html>\n", r);
    return OK;
}


/*
 * return the name of the app cookie
 */
static const char *
app_cookie_name(void)
{
    return "webauth_at";
}


/*
 * given the proxy_type return the cookie name to use
 */
static char *
proxy_cookie_name(const char *proxy_type, MWA_REQ_CTXT *rc)
{
    return apr_pstrcat(rc->r->pool, "webauth_pt_", proxy_type, NULL);
}


/*
 * given the proxy_type return the cookie name to use
 */
static char *
cred_cookie_name(const char *cred_type,
                 const char *cred_server,
                 MWA_REQ_CTXT *rc)
{
    char *p;
    /* if cred_server has an '=' in it we need to change it to '-'
       instead, since cookie names can't have an '=' in it. The
       risk of a potential collision with another valid cred name
       that has a '-' in it already is small enough not to worry.
       It might turn out we need to do more extensive encoding/decoding
       later anyways... */
    if ((p=ap_strchr(cred_server, '='))) {
        cred_server = apr_pstrdup(rc->r->pool, cred_server);
        while(p) {
            *p = '-';
            p=ap_strchr(cred_server, '=');
        }
    }
    return apr_pstrcat(rc->r->pool, "webauth_ct_", cred_type, "_",
                       cred_server, NULL);
}


/*
 * create a proxy-token cookie.
 */
static int
make_proxy_cookie(const char *proxy_type,
                  const char *subject,
                  const void *wpt,
                  size_t wpt_len,
                  const char *initial_factors,
                  const char *session_factors,
                  uint32_t loa,
                  time_t expiration_time,
                  MWA_REQ_CTXT *rc)
{
    const char *mwa_func = "make_proxy_cookie";
    struct webauth_token *data;
    struct webauth_token_proxy *pt;
    void *webkdc_proxy;
    const char *token;
    int status;

    if (!ensure_keyring_loaded(rc))
        return 0;
    data = apr_pcalloc(rc->r->pool, sizeof(struct webauth_token));
    data->type = WA_TOKEN_PROXY;
    pt = &data->token.proxy;
    pt->subject = apr_pstrdup(rc->r->pool, subject);
    pt->type = apr_pstrdup(rc->r->pool, proxy_type);
    webkdc_proxy = apr_palloc(rc->r->pool, wpt_len);
    memcpy(webkdc_proxy, wpt, wpt_len);
    pt->webkdc_proxy = webkdc_proxy;
    pt->webkdc_proxy_len = wpt_len;
    pt->initial_factors = apr_pstrdup(rc->r->pool, initial_factors);
    pt->session_factors = apr_pstrdup(rc->r->pool, session_factors);
    pt->loa = loa;
    pt->expiration = expiration_time;
    status = webauth_token_encode(rc->ctx, data, rc->sconf->ring, &token);
    if (status != WA_ERR_NONE) {
        mwa_log_webauth_error(rc, status, mwa_func,
                              "webauth_token_encode_proxy", subject);
        return 0;
    }
    rc->pt = pt;
    fixup_setcookie(rc, proxy_cookie_name(proxy_type, rc), token,
                    rc->dconf->cookie_path);
    return 1;
}


/*
 * create a cred-token cookie.
 */
static int
make_cred_cookie(struct webauth_token_cred *ct, MWA_REQ_CTXT *rc)
{
    const char *mwa_func = "make_cred_cookie";
    const char *token;
    struct webauth_token data;
    int status;

    if (!ensure_keyring_loaded(rc))
        return 0;
    data.type = WA_TOKEN_CRED;
    data.token.cred = *ct;
    status = webauth_token_encode(rc->ctx, &data, rc->sconf->ring, &token);
    if (status != WA_ERR_NONE) {
        mwa_log_webauth_error(rc, status, mwa_func,
                              "webauth_token_encode_cred", ct->subject);
        return 0;
    }
    fixup_setcookie(rc, cred_cookie_name(ct->type, ct->service, rc), token,
                    rc->dconf->cookie_path);
    return 1;
}


/*
 * create/update an app-token cookie. If creation_time is 0 it means
 * we are creating an app-token, otherwise we are updating an
 * existing one.
 */
static int
make_app_cookie(const char *subject,
                const char *authz_subject,
                time_t creation_time,
                time_t expiration_time,
                time_t last_used_time,
                const char *initial_factors,
                const char *session_factors,
                uint32_t loa,
                MWA_REQ_CTXT *rc)
{
    const char *mwa_func = "make_app_cookie";
    struct webauth_token *data;
    struct webauth_token_app *app;
    const char *token;
    int status;

    if (!ensure_keyring_loaded(rc))
        return 0;
    if (creation_time == 0) {
        creation_time = time(NULL);
        if (rc->dconf->app_token_lifetime)
            expiration_time = creation_time + rc->dconf->app_token_lifetime;
        last_used_time =
            rc->dconf->last_use_update_interval ? creation_time : 0;
    }
    data = apr_pcalloc(rc->r->pool, sizeof(struct webauth_token));
    data->type = WA_TOKEN_APP;
    app = &data->token.app;
    app->subject = apr_pstrdup(rc->r->pool, subject);
    if (authz_subject != NULL)
        app->authz_subject = apr_pstrdup(rc->r->pool, authz_subject);
    app->last_used = last_used_time;
    if (initial_factors != NULL)
        app->initial_factors = apr_pstrdup(rc->r->pool, initial_factors);
    if (session_factors != NULL)
        app->session_factors = apr_pstrdup(rc->r->pool, session_factors);
    app->loa = loa;
    app->creation = creation_time;
    app->expiration = expiration_time;
    status = webauth_token_encode(rc->ctx, data, rc->sconf->ring, &token);
    if (status != WA_ERR_NONE) {
        mwa_log_webauth_error(rc, status, mwa_func,
                              "webauth_token_encode_app", subject);
        return 0;
    }
    rc->at = app;
    fixup_setcookie(rc, app_cookie_name(), token, rc->dconf->cookie_path);
    return 1;
}


/*
 * checks last-use-time in token, returns 0 if expired, 1 if ok.
 * potentially updates app-token and cookie
 */
static int
app_token_maint(MWA_REQ_CTXT *rc)
{
    unsigned long curr;

    if (!rc->dconf->inactive_expire && !rc->dconf->last_use_update_interval)
        return 1;
    if (rc->at == NULL)
        return 0;
    if (rc->at->last_used == 0)
        return 0;

    curr = time(NULL);

    /* see if its inactive */
    if (rc->dconf->inactive_expire
        && (rc->at->last_used + rc->dconf->inactive_expire < curr)) {
        if (rc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                         "mod_webauth: manage_inactivity: inactive(%s)",
                         rc->at->subject);
        return 0;
    }

    /*
     * See if last_used is older then the interval we update tokens.  If it
     * is, we have to update the token.
     *
     * FIXME: If this fails, should we expire the cookie?
     */
    if ((rc->dconf->last_use_update_interval == 0)
        || (rc->at->last_used + rc->dconf->last_use_update_interval > curr))
        return 1;
    rc->at->last_used = curr;
    make_app_cookie(rc->at->subject,
                    rc->at->authz_subject,
                    rc->at->creation,
                    rc->at->expiration,
                    rc->at->last_used,
                    rc->at->initial_factors,
                    rc->at->session_factors,
                    rc->at->loa,
                    rc);
    return 1;
}


/*
 * parse an app-token, store in rc->at.
 * return 0 on failure, 1 on success
 */
static int
parse_app_token(char *token, MWA_REQ_CTXT *rc)
{
    const char *mwa_func = "parse_app_token";
    int status;
    struct webauth_token *app;

    if (!ensure_keyring_loaded(rc))
        return 0;
    ap_unescape_url(token);
    status = webauth_token_decode(rc->ctx, WA_TOKEN_APP, token,
                                  rc->sconf->ring, &app);
    if (status == WA_ERR_TOKEN_EXPIRED) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, rc->r->server,
                     "mod_webauth: user credentials (from %s cookie) have"
                     " expired", app_cookie_name());
        return 0;
    } else if (status != WA_ERR_NONE) {
        mwa_log_webauth_error(rc, status, mwa_func, "webauth_token_decode",
                              NULL);
        return 0;
    }
    rc->at = &app->token.app;

    /*
     * Update last-use-time and check inactivity.  If we can't use the app
     * token due to inactivity, clear it out.
     */
    status = app_token_maint(rc);
    if (status == 0)
        rc->at = NULL;
    return status;
}


/*
 * check cookie for valid app-token. If an epxired one is found,
 * do a Set-Cookie to blank it out.
 */
static int
parse_app_token_cookie(MWA_REQ_CTXT *rc)
{
    char *cval;
    const char *mwa_func = "parse_app_token_cookie";
    const char *cname = app_cookie_name();

    cval = find_cookie(rc, cname);
    if (cval == NULL || cval[0] == '\0')
        return 0;

    if (!parse_app_token(cval, rc)) {
        /* we coudn't use the cookie, lets set it up to be nuked */
        fixup_setcookie(rc, cname, "", rc->dconf->cookie_path);
        return 0;
    }  else {
        if (rc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                         "mod_webauth: %s: found valid %s cookie for (%s)",
                         mwa_func, cname, rc->at->subject);
        return 1;
    }
}


/*
 * parse a proxy-token from a cookie.
 * return pointer to it on success, NULL on failure.
 */
static struct webauth_token_proxy *
parse_proxy_token(char *token, MWA_REQ_CTXT *rc)
{
    const char *mwa_func = "parse_proxy_token";
    struct webauth_token *pt;
    int status;

    if (!ensure_keyring_loaded(rc))
        return 0;
    ap_unescape_url(token);
    status = webauth_token_decode(rc->ctx, WA_TOKEN_PROXY, token,
                                  rc->sconf->ring, &pt);
    if (status != WA_ERR_NONE) {
        mwa_log_webauth_error(rc, status, mwa_func, "webauth_token_decode",
                              NULL);
        return NULL;
    }
    return &pt->token.proxy;
}


/*
 * check cookie for valid proxy-token. If an expired one is found,
 * do a Set-Cookie to blank it out.
 */
static struct webauth_token_proxy *
parse_proxy_token_cookie(MWA_REQ_CTXT *rc, char *proxy_type)
{
    char *cval;
    char *cname = proxy_cookie_name(proxy_type, rc);
    struct webauth_token_proxy *pt;
    const char *mwa_func = "parse_proxy_token_cookie";

    cval = find_cookie(rc, cname);
    if (cval == NULL)
        return 0;

    pt =  parse_proxy_token(cval, rc);

    if (pt == NULL) {
        /* we coudn't use the cookie, lets set it up to be nuked */
        fixup_setcookie(rc, cname, "", rc->dconf->cookie_path);
    }  else {
        if (rc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                         "mod_webauth: %s: found valid %s cookie for (%s)",
                         mwa_func, cname,
                         (rc->at != NULL) ? rc->at->subject : "NULL");
    }
    return pt;
}


static struct webauth_key *
get_session_key(char *token, MWA_REQ_CTXT *rc)
{
    struct webauth_token *data;
    struct webauth_token_app *app;
    struct webauth_key *key;
    size_t klen;
    int status;
    const char *mwa_func = "get_session_key";

    ap_unescape_url(token);
    if (!ensure_keyring_loaded(rc))
        return NULL;
    status = webauth_token_decode(rc->ctx, WA_TOKEN_APP, token,
                                  rc->sconf->ring, &data);
    if (status != WA_ERR_NONE) {
        mwa_log_webauth_error(rc, status, mwa_func, "webauth_token_decode",
                              NULL);
        return NULL;
    }
    app = &data->token.app;

    /* Pull out the session key and make it a WEBAUTH_KEY. */
    klen = app->session_key_len;
    if (klen != WA_AES_128 && klen != WA_AES_192 && klen != WA_AES_256) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                     "mod_webauth: get_session_key: invalid key length: %lu",
                     (unsigned long) klen);
        return NULL;
    }
    status = webauth_key_create(rc->ctx, WA_KEY_AES, klen, app->session_key,
                                &key);
    if (status != WA_ERR_NONE) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                     "mod_webauth: get_session_key: %s",
                     webauth_error_message(rc->ctx, status));
        return NULL;
    }
    return key;
}


static int
handle_id_token(const struct webauth_token_id *id, MWA_REQ_CTXT *rc)
{
    const char *mwa_func = "handle_id_token";
    const char *subject, *authz_subject;
    unsigned long now;

    now = time(NULL);
    if (id->creation + rc->sconf->token_max_ttl < now) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                     "mod_webauth: %s: id token too old", mwa_func);
        return 0;
    }

    /*
     * The authz_subject value from the id token is only honored if the token
     * type is webkdc.  A krb5 subject auth type means we're supposed to
     * independently verify their identity, but there's no way to
     * independently verify the authorization identity.
     */
    authz_subject = id->authz_subject;
    if (id->auth_data != NULL) {
        MWA_CRED_INTERFACE *mci;

        mci = mwa_find_cred_interface(rc->r->server, id->auth);
        if (mci == NULL)
            return 0;
        subject = mci->validate_sad(rc, id->auth_data, id->auth_data_len);
        authz_subject = NULL;
    } else if (strcmp(id->auth, "webkdc") == 0) {
        subject = id->subject;
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                     "mod_webauth: %s: unknown subject auth type: %s",
                     mwa_func, id->auth);
        subject = NULL;
    }

    /* wheeee! create an app-token! */
    if (subject != NULL) {
        if (rc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                         "mod_webauth: %s: got subject(%s) from id token",
                         mwa_func, subject);
        make_app_cookie(subject, authz_subject, 0, id->expiration, 0,
                        id->initial_factors, id->session_factors, id->loa, rc);
    } else {
        /* everyone else should have logged something, right? */
    }
    return subject != NULL;
}


static int
handle_proxy_token(const struct webauth_token_proxy *proxy, MWA_REQ_CTXT *rc)
{
    const char *mwa_func = "handle_proxy_token";
    int status;
    unsigned long now;

    now = time(NULL);
    if (proxy->creation + rc->sconf->token_max_ttl < now) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                     "mod_webauth: %s: proxy token too old", mwa_func);
        return 0;
    }
    if (rc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                     "mod_webauth: %s: got subject(%s) from proxy token",
                     mwa_func, proxy->subject);

    /*
     * FIXME: app-tokens where subject-auth-type is krb5 to need to request an
     * id-token from the WebKDC, assuming the proxy-type is also krb5.
     */
    status = make_proxy_cookie(proxy->type, proxy->subject,
                               proxy->webkdc_proxy, proxy->webkdc_proxy_len,
                               proxy->initial_factors, proxy->session_factors,
                               proxy->loa, proxy->expiration, rc);
    if (status)
        status = make_app_cookie(proxy->subject, proxy->authz_subject, 0,
                                 proxy->expiration, 0, proxy->initial_factors,
                                 proxy->session_factors, proxy->loa, rc);
    return status;
}


static int
handle_error_token(const struct webauth_token_error *err, MWA_REQ_CTXT *rc)
{
    static const char *mwa_func = "handle_error_token";
    const char *log_message;
    unsigned long now;

    now = time(NULL);
    if (err->creation + rc->sconf->token_max_ttl < now) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                     "mod_webauth: %s: error token too old", mwa_func);
        return failure_redirect(rc);
    }
    if (rc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                     "mod_webauth: %s: parsed an error token(%lu, %s)",
                     mwa_func, err->code, err->message);

    switch (err->code) {
    case WA_PEC_LOGIN_CANCELED:
        /* user canceled out of login page */
        return login_canceled_redirect(rc);
        break;
    default:
        /*
         * Catch other all other errors that we aren't expecting, which is
         * pretty much all of them, since if the server can't even parse our
         * request-token, it can't figure out the return URL.
         */
        log_message = "unhandled error";
        break;
    }
    ap_log_error(APLOG_MARK, APLOG_ALERT, 0, rc->r->server,
                 "mod_webauth: %s: %s: %s (%lu)", mwa_func, log_message,
                 err->message, err->code);
    return failure_redirect(rc);
}


/*
 * return OK or an HTTP_* code.
 */
static int
parse_returned_token(char *token, struct webauth_key *key, MWA_REQ_CTXT *rc)
{
    static const char *mwa_func = "parse_returned_token";
    struct webauth_keyring *ring;
    enum webauth_token_type type = WA_TOKEN_ANY;
    struct webauth_token *data;
    int status, code;

    /* FIXME: We return OK on errors? */
    code = OK;

    /* if we successfully parse an id-token, write out new webauth_at cookie */
    ap_unescape_url(token);
    ring = webauth_keyring_from_key(rc->ctx, key);
    status = webauth_token_decode(rc->ctx, type, token, ring, &data);
    if (status != WA_ERR_NONE) {
        mwa_log_webauth_error(rc, status, mwa_func, "webauth_token_decode",
                              NULL);
        return code;
    }

    /* get the token-type to see what we should do with it */
    switch (data->type) {
    case WA_TOKEN_ID:
        if (!handle_id_token(&data->token.id, rc)) {
            /* FIXME: WHAT DO WE DO? failure redirect or ...?
               doing nothing will cause another redirect for auth...
             */
        }
        break;
    case WA_TOKEN_PROXY:
        if (!handle_proxy_token(&data->token.proxy, rc)) {
            /* FIXME: WHAT DO WE DO? failure redirect or ...?
               doing nothing will cause another redirect for auth...
             */
        }
        break;
    case WA_TOKEN_ERROR:
        code = handle_error_token(&data->token.error, rc);
        break;
    case WA_TOKEN_UNKNOWN:
    case WA_TOKEN_APP:
    case WA_TOKEN_CRED:
    case WA_TOKEN_LOGIN:
    case WA_TOKEN_REQUEST:
    case WA_TOKEN_WEBKDC_FACTOR:
    case WA_TOKEN_WEBKDC_PROXY:
    case WA_TOKEN_WEBKDC_SERVICE:
    case WA_TOKEN_ANY:
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                     "mod_webauth: %s: unhandled token type(%d)",
                     mwa_func, type);
        break;
    }
    return code;
}


/*
 * check to see if we got passed WEBAUTHR and WEBAUTHS, and if so
 * attempt to parse and fill in rc->at. If we return OK,
 * caller will check to see if rc->at got set, otherwise
 * it will return the HTTP_* code to the Apache framework.
 */
static int
check_url(MWA_REQ_CTXT *rc, int *in_url)
{
    const char *note;
    char *wr, *ws;
    struct webauth_key *key = NULL;

    note = mwa_get_note(rc->r, N_WEBAUTHR);
    if (note == NULL) {
        *in_url = 0;
        return OK;
    } else {
        *in_url = 1;
    }
    wr = apr_pstrdup(rc->r->pool, note);

    if (rc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                     "mod_webauth: check_url: found  WEBAUTHR");

    /* see if we have WEBAUTHS, which has the session key to use */
    note = mwa_get_note(rc->r, N_WEBAUTHS);
    if (note != NULL) {
        ws = apr_pstrdup(rc->r->pool, note);

        /* don't have to free key, its allocated from a pool */
        key = get_session_key(ws, rc);
        if (key == NULL)
            return OK;
        return parse_returned_token(wr, key, rc);
    } else {
        MWA_SERVICE_TOKEN *st;

        st = mwa_get_service_token(rc->r->server, rc->sconf, rc->r->pool, 0);
        if (st != NULL)
            return parse_returned_token(wr, &st->key, rc);
    }
    return OK;
}


static char *
make_return_url(MWA_REQ_CTXT *rc,
                int check_dconf_return_url)
{
    char *uri = rc->r->unparsed_uri;

    /* use explicit return_url if there is one */
    if (check_dconf_return_url) {
        if (rc->r->method_number == M_GET && rc->dconf->return_url) {
            if (rc->dconf->return_url[0] != '/')
                return apr_pstrdup(rc->r->pool, rc->dconf->return_url);
            else
                return ap_construct_url(rc->r->pool,
                                        rc->dconf->return_url, rc->r);
        } else if (rc->r->method_number == M_POST &&
                   rc->dconf->post_return_url) {
            if (rc->dconf->post_return_url[0] != '/')
                return apr_pstrdup(rc->r->pool, rc->dconf->post_return_url);
            else
                return ap_construct_url(rc->r->pool,
                                        rc->dconf->post_return_url, rc->r);
        }
    }

    /* if we are proxying or if the uri is parsed and scheme is non-null
       just use unparsed_uri */
    if ((rc->r->proxyreq == PROXYREQ_PROXY) ||
        (rc->r->parsed_uri.is_initialized && rc->r->parsed_uri.scheme != NULL)
        ) {
        /* do nothing, use uri */
    } else {
        uri = ap_construct_url(rc->r->pool, uri, rc->r);
    }

    if (rc->dconf->ssl_return && strncmp(uri, "http:", 5) == 0) {
        uri = apr_pstrcat(rc->r->pool, "https:", uri + 5, NULL);
    }

    return uri;
}


static int
redirect_request_token(MWA_REQ_CTXT *rc)
{
    const char *mwa_func = "redirect_request_token";
    MWA_SERVICE_TOKEN *st;
    struct webauth_keyring *ring;
    struct webauth_token data;
    struct webauth_token_request *req;
    char *redirect_url, *return_url;
    const char *token;
    int status;

    if (rc->r->method_number != M_GET &&
        (rc->r->method_number != M_POST ||
         (rc->r->method_number == M_POST &&
          rc->dconf->post_return_url == NULL))) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, rc->r->server,
                     "mod_webauth: redirect_request_token: no auth during %s, "
                     "denying request",  rc->r->method);
        if (rc->r->method_number == M_POST) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, rc->r->server,
                         "mod_webauth: use WebAuthPostReturnURL to specify a"
                         " return URL");
        }
        return HTTP_UNAUTHORIZED;
    }

    ap_discard_request_body(rc->r);

    st = mwa_get_service_token(rc->r->server, rc->sconf, rc->r->pool, 0);
    if (st == NULL) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, rc->r->server,
                     "mod_webauth: %s: no service token, denying request",
                     mwa_func);
        return failure_redirect(rc);
    }

    memset(&data, 0, sizeof(data));
    data.type = WA_TOKEN_REQUEST;
    req = &data.token.request;
    if (rc->dconf->force_login || rc->dconf->login_canceled_url != NULL) {
        int fl = rc->dconf->force_login;
        int lc = rc->dconf->login_canceled_url != NULL;

        req->options = apr_pstrcat(rc->r->pool,
                                   fl         ? "fa" : "",
                                   (fl && lc) ? ","  : "",
                                   lc         ? "lc" : "",
                                   NULL);
    }
    if (rc->dconf->creds) {
        req->type = "proxy";
        if (rc->needed_proxy_type) {
            req->proxy_type = rc->needed_proxy_type;
        } else {
            MWA_WACRED *cred;

            /*
             * If we don't know which one we need, lets request a proxy token
             * for the first one in the list.
             */
            cred = &APR_ARRAY_IDX(rc->dconf->creds, 0, MWA_WACRED);
            req->proxy_type = cred->type;
        }
        if (rc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                         "mod_webauth: %s: redirecting for proxy token (%s)",
                         mwa_func, req->proxy_type);
    } else {
        req->type = "id";
        req->auth = rc->sconf->subject_auth_type;
        if (rc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                         "mod_webauth: %s: redirecting for id token",
                         mwa_func);
    }

    if (st->app_state != NULL) {
        req->state = st->app_state;
        req->state_len = st->app_state_len;
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                     "mod_webauth: %s: app state is NULL",
                     mwa_func);
    }

    return_url = make_return_url(rc, 1);

    /* never let return URL have  ?WEBAUTHR=...;;WEBUTHS=...; on the
       end of it, that could get ugly... */
    strip_end(return_url, WEBAUTHR_MAGIC);

    req->return_url = return_url;

    /* Add factor and level of assurance requirements. */
    if (rc->dconf->loa > 0)
        req->loa = rc->dconf->loa;
    if (rc->dconf->initial_factors != NULL)
        req->initial_factors
            = apr_array_pstrcat(rc->r->pool, rc->dconf->initial_factors, ',');
    if (rc->dconf->session_factors != NULL)
        req->session_factors
            = apr_array_pstrcat(rc->r->pool, rc->dconf->session_factors, ',');

    if (rc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                     "mod_webauth: %s: return_url(%s)", mwa_func, return_url);

    ring = webauth_keyring_from_key(rc->ctx, &st->key);
    status = webauth_token_encode(rc->ctx, &data, ring, &token);
    if (status != WA_ERR_NONE) {
        mwa_log_webauth_error(rc, status, mwa_func, "webauth_token_encode",
                              NULL);
        return failure_redirect(rc);
    }

    redirect_url = apr_pstrcat(rc->r->pool,
                               rc->sconf->login_url,
                               "?RT=", token,
                               ";ST=", st->token,
                               NULL);

    apr_table_setn(rc->r->err_headers_out, "Location", redirect_url);

    if (rc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                     "mod_webauth: redirect_requst_token: redirect(%s)",
                     redirect_url);

    set_pending_cookies(rc);
    return do_redirect(rc);
}


static int
extra_redirect(MWA_REQ_CTXT *rc)
{
    char *redirect_url;

    redirect_url = make_return_url(rc, 0);
    /* always strip extra-redirect URL */
    strip_end(redirect_url, WEBAUTHR_MAGIC);

    apr_table_setn(rc->r->err_headers_out, "Location", redirect_url);

    if (rc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                     "mod_webauth: extra_redirect: redirect(%s)",
                     redirect_url);

    set_pending_cookies(rc);
    return do_redirect(rc);
}


static int
ssl_redirect(MWA_REQ_CTXT *rc)
{
    char *redirect_url;
    apr_uri_t uri;

    redirect_url = make_return_url(rc, 0);

    apr_uri_parse(rc->r->pool, redirect_url, &uri);

    if (rc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                     "mod_webauth: ssl_redirect: redirect(%s)",
                     redirect_url);

    if (strcmp(uri.scheme, "http") == 0) {
        uri.scheme = (char *) "https";
        if (rc->sconf->ssl_redirect_port) {
            uri.port_str = apr_psprintf(rc->r->pool,
                                        "%lu", rc->sconf->ssl_redirect_port);
            uri.port = rc->sconf->ssl_redirect_port;
        } else {
            uri.port_str = apr_psprintf(rc->r->pool,
                                        "%d", APR_URI_HTTPS_DEFAULT_PORT);
            uri.port = APR_URI_HTTPS_DEFAULT_PORT;
        }
        redirect_url = apr_uri_unparse(rc->r->pool, &uri, 0);
    } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, rc->r->server,
                         "mod_webauth: ssl_redirect: error with "
                         "redirect url(%s) denying request", redirect_url);
            return HTTP_UNAUTHORIZED;
    }

    apr_table_setn(rc->r->err_headers_out, "Location", redirect_url);

    if (rc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                     "mod_webauth: ssl_redirect: redirect(%s)",
                     redirect_url);

    set_pending_cookies(rc);
    return do_redirect(rc);
}


/*
 * check cookie for valid cred-token. If an epxired one is found,
 * do a Set-Cookie to blank it out. returns NULL on error/expired
 * cookie.
 */
static struct webauth_token_cred *
parse_cred_token_cookie(MWA_REQ_CTXT *rc, MWA_WACRED *cred)
{
    char *cval;
    char *cname = cred_cookie_name(cred->type, cred->service, rc);
    struct webauth_token_cred *ct;
    const char *mwa_func = "parse_cred_token_cookie";

    if (!ensure_keyring_loaded(rc))
        return NULL;

    cval = find_cookie(rc, cname);
    if (cval == NULL)
        return 0;

    ct =  mwa_parse_cred_token(cval, rc->sconf->ring, NULL, rc);

    if (ct == NULL) {
        /* we coudn't use the cookie, lets set it up to be nuked */
        fixup_setcookie(rc, cname, "", rc->dconf->cookie_path);
    }  else {
        if (rc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                         "mod_webauth: %s: found valid %s cookie for (%s)",
                         mwa_func, cname,
                         (rc->at != NULL) ? rc->at->subject : "NULL");
    }
    return ct;
}


/*
 * add a proxy type to the array if it isn't present.
 */
static void
add_proxy_type(apr_array_header_t *a, char *type)
{
   int i;
   char **ntype;

   for (i = 0; i < a->nelts; i++)
       if (strcmp(APR_ARRAY_IDX(a, i, char *), type) == 0)
           return;
   ntype = apr_array_push(a);
   *ntype = type;
}


/*
 * take all the creds for the given proxy_type and
 * prepare them. i.e., for krb5 this means creating
 * a credential cache file and setting KRB5CCNAME.
 */
static int
prepare_creds(MWA_REQ_CTXT *rc, char *proxy_type, apr_array_header_t *creds)
{
    const char *mwa_func="prepare_creds";

    MWA_CRED_INTERFACE *mci =
        mwa_find_cred_interface(rc->r->server, proxy_type);

    if (mci != NULL) {
        return mci->prepare_creds(rc, creds);
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, rc->r->server,
                     "mod_webauth: %s: unhandled proxy type: (%s)",
                     mwa_func, proxy_type);
        return 0;
    }
}


/*
 * acquire all the creds of the specified proxy_type. this
 * means making requests to the webkdc. If we don't have
 * the specified proxy_type, we'll need to do a redirect to
 * get it.
 */
static int
acquire_creds(MWA_REQ_CTXT *rc, char *proxy_type,
              apr_array_header_t *needed_creds,
              apr_array_header_t **acquired_creds)
{
    const char *mwa_func = "acquire_creds";
    struct webauth_token_proxy *pt = NULL;

    if (rc->sconf->debug) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                     "mod_webauth: %s: need this proxy type: (%s)",
                     mwa_func, proxy_type);
    }

    if (rc->pt && strcmp(rc->pt->type, proxy_type) == 0) {
        pt = rc->pt;
    } else {
        pt = parse_proxy_token_cookie(rc, proxy_type);
    }

    /* if we don't have the proxy type then redirect! */
    if (pt == NULL) {
        rc->needed_proxy_type = proxy_type;
        return redirect_request_token(rc);
    }

    if (!mwa_get_creds_from_webkdc(rc, pt, needed_creds, acquired_creds)) {

        /* FIXME: what do we want to do here? mwa_get_creds_from_webkdc
           will log any errors. We could either cause a failure_redirect
           or let the request continue without all the desired credentials
           and let the app cope. This might need to be a directive.
           for now, lets just continue, since that seems like the most
           reasonable choice... */

        if (rc->sconf->debug) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, rc->r->server,
                         "mod_webauth: %s: mwa_get_creds_from_webkdc failed!",
                         mwa_func);
        }
    } else {
        /* need to construct new cookies for newly gathered creds */
        if (*acquired_creds != NULL) {
            struct webauth_token_cred *cred;
            size_t i;

            for (i = 0; i < (size_t) (*acquired_creds)->nelts; i++) {
                cred = APR_ARRAY_IDX(*acquired_creds, i,
                                     struct webauth_token_cred *);
                make_cred_cookie(cred, rc);
            }
        }
    }

    return OK;
}


/*
 * use_creds is on, so we need to gather creds (from cookies and/or
 * webkdc, redirecting if we don't have a proxy-token)
 */
static int
gather_creds(MWA_REQ_CTXT *rc)
{
    int i, code;
    apr_array_header_t *needed_creds = NULL; /* (MWA_WACRED) */
    apr_array_header_t *needed_proxy_types = NULL; /* (char *) */
    apr_array_header_t *all_proxy_types = NULL; /* (char *) */
    apr_array_header_t *gathered_creds = NULL; /* (webauth_token_cred *) */
    apr_array_header_t *acquired_creds = NULL; /* (webauth_token_cred *) */
    MWA_WACRED *ncred, *cred;
    struct webauth_token_cred *ct, **nct;

    for (i = 0; i < rc->dconf->creds->nelts; i++) {
        cred = &APR_ARRAY_IDX(rc->dconf->creds, i, MWA_WACRED);
        if (cred->service) {

            if (all_proxy_types == NULL)
                all_proxy_types
                    = apr_array_make(rc->r->pool, 2, sizeof(char *));
            add_proxy_type(all_proxy_types, cred->type);

            /* check the cookie first */
            ct = parse_cred_token_cookie(rc, cred);

            if (ct != NULL) {
                /* save in gathered creds */
                if (gathered_creds == NULL)
                    gathered_creds
                        = apr_array_make(rc->r->pool, rc->dconf->creds->nelts,
                                         sizeof(struct webauth_token_cred *));
                nct = apr_array_push(gathered_creds);
                *nct = ct;
            } else {
                /* keep track of the ones we need */
                if (needed_creds == NULL) {
                    needed_creds
                        = apr_array_make(rc->r->pool, 5, sizeof(MWA_WACRED));
                    needed_proxy_types
                        = apr_array_make(rc->r->pool, 2, sizeof(char *));
                }
                ncred = apr_array_push(needed_creds);
                ncred->type = cred->type;
                ncred->service = cred->service;
                add_proxy_type(needed_proxy_types, cred->type);
            }
        }
    }

    /* now, for each proxy type that has needed credentials,
       try and acquire them from the webkdc. */
    if (needed_proxy_types != NULL) {
        char *proxy;

        /* foreach proxy type, attempt to acquire the needed creds */
        for (i = 0; i < needed_proxy_types->nelts; i++) {
            proxy = APR_ARRAY_IDX(needed_proxy_types, i, char *);
            code = acquire_creds(rc, proxy, needed_creds, &acquired_creds);
            if (code != OK)
                return code;
        }
    }

    if (gathered_creds != NULL || acquired_creds != NULL) {
        if (gathered_creds == NULL)
            gathered_creds = acquired_creds;
        else if (acquired_creds != NULL)
            apr_array_cat(gathered_creds, acquired_creds);
    }

    /* now go through all_proxy_types, and for do any special
       handling for the proxy type and all its credentials.
       for example, for krb5, we'll want to create the cred file,
       dump in all the creds, and point KRB%CCNAME at it for
       cgi programs.
    */

    if (all_proxy_types != NULL && gathered_creds != NULL) {
        char *proxy;

        /* foreach proxy type, process the creds */
        for (i = 0; i < all_proxy_types->nelts; i++) {
            proxy = APR_ARRAY_IDX(all_proxy_types, i, char *);
            if (!prepare_creds(rc, proxy, gathered_creds)) {
                /* FIXME: similar as case where we can't get
                   creds from the webkdc. prepare_creds will log
                   any errors. For now, we continue and let the
                   app cope.
                */
            }
        }
    }

    return OK;
}


/*
 * go through cookies first. If we don't have a valid
 * app-token and/or proxy-token cookie, check URL and
 * process the token if present.
 */
static int
gather_tokens(MWA_REQ_CTXT *rc)
{
    int code, in_url;
    struct webauth_factors *have, *want;

    /* check the URL. this will parse the token in WEBAUTHR if there
       was one, and create the appropriate cookies, as well as fill in
       rc->{at, proxy_tokens}. */
    code = check_url(rc, &in_url);
    if (code != OK)
        return code;

    if (rc->at == NULL) {
        /* not in URL, check cookie. If we have a bad/expired token in the
         cookie, parse_app_token_cookie will set it up to be expired. */
        parse_app_token_cookie(rc);

        /*
         * If its still NULL, we normally redirect to the WebLogin server.
         * However, if WebAuthOptional is set in the Apache configuration, we
         * instead return OK without setting REMOTE_USER.
         */
        if (rc->at == NULL) {
            if (rc->dconf->optional)
                return OK;
            else
                return redirect_request_token(rc);
        }
    }

    /*
     * We have an app token.  Now check whether our factor and LoA
     * requirements are met.  If they're not, return a redirect.
     *
     * FIXME: Need better error reporting if there are no initial or session
     * factors in the app token.  We may be dealing with a WebKDC that cannot
     * satisfy our request.  Consider making that a fatal error leading to a
     * permission denied screen instead of a redirect once the WebKDC always
     * includes initial and session factor information.  Likewise for level of
     * assurance.
     */
    if (rc->dconf->loa > rc->at->loa) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, rc->r,
                      "mod_webauth: insufficient level of assurance (have"
                      " %lu, want %lu)", rc->at->loa, rc->dconf->loa);
        return redirect_request_token(rc);
    }
    if (rc->dconf->initial_factors != NULL) {
        want = webauth_factors_new(rc->ctx, rc->dconf->initial_factors);
        if (rc->at->initial_factors == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, rc->r,
                          "mod_webauth: initial authentication factors"
                          " required (want %s)",
                          webauth_factors_string(rc->ctx, want));
            return redirect_request_token(rc);
        }
        have = webauth_factors_parse(rc->ctx, rc->at->initial_factors);
        if (!webauth_factors_satisfies(rc->ctx, have, want)) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, rc->r,
                          "mod_webauth: insufficient initial"
                          " authentication factors (have %s, want %s)",
                          rc->at->initial_factors,
                          webauth_factors_string(rc->ctx, want));
            return redirect_request_token(rc);
        }
    }
    if (rc->dconf->session_factors != NULL) {
        want = webauth_factors_new(rc->ctx, rc->dconf->session_factors);
        if (rc->at->session_factors == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, rc->r,
                          "mod_webauth: session authentication factors"
                          " required (want %s)",
                          webauth_factors_string(rc->ctx, want));
            return redirect_request_token(rc);
        }
        have = webauth_factors_parse(rc->ctx, rc->at->session_factors);
        if (!webauth_factors_satisfies(rc->ctx, have, want)) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, rc->r,
                          "mod_webauth: insufficient session"
                          " authentication factors (have %s, want %s)",
                          rc->at->session_factors,
                          webauth_factors_string(rc->ctx, want));
            return redirect_request_token(rc);
        }
    }

    /* check if the WEBAUTHR crap was in the URL and we are configured
       to do a redirect. redirect now so we don't waste time doing saving
       creds if we are configured to saved creds for this request */
    if (in_url
        && ((rc->dconf->extra_redirect_set && rc->dconf->extra_redirect)
            || (!rc->dconf->extra_redirect_set && rc->sconf->extra_redirect)))
        return extra_redirect(rc);

    /* if use_creds is on, look for creds. If creds aren't found,
       see if we have a proxy-token for the creds. The proxy-token
       might already be set from check_url, if not, we need to call
       parse_proxy_token_cookie to see if we have one in a cookie.
       If we don't, time for a redirect! */
    if (rc->dconf->use_creds && rc->dconf->creds) {
        code = gather_creds(rc);
        if (code != OK)
            return code;
    }

    return OK;
}


/*
 * This hook gathers authentication information if the user is already
 * authenticated and stashes it in a note.  If the user is not already
 * authenticated, this is where we force the redirect to WebLogin.  This hook
 * also handles checking for SSL if SSL is required and redirecting if
 * configured to do so.
 *
 * If the user is not authenticated but WebAuthOptional is enabled, return OK
 * here to bypass the check_id hook and not attempt to authenticate the user.
 *
 * Run via ap_hook_check_access_ex for Apache 2.4 and called directly from the
 * check_user_id hook for Apache 2.2.
 */
static int
mod_webauth_check_access(request_rec *r)
{
    MWA_REQ_CTXT *rc;
    const char *subject = NULL, *authz;
    int status;

    /* Get the module configuration. */
    rc = ap_get_module_config(r->request_config, &webauth_module);

    /* Decline if the request is for an AuthType we don't handle. */
    if (!is_supported_authtype(r, rc))
        return DECLINED;

    status = webauth_context_init_apr(&rc->ctx, rc->r->pool);
    if (status != WA_ERR_NONE) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server,
                     "mod_webauth: webauth_context_init failed: %s",
                     webauth_error_message(NULL, status));
        return DECLINED;
    }

    /* If we can't load the keyring, return a fatal error. */
    if (!ensure_keyring_loaded(rc))
        return HTTP_INTERNAL_SERVER_ERROR;

    /* check to see if SSL is required */
    if (rc->sconf->require_ssl && !is_https(r)) {
        if (rc->sconf->ssl_redirect) {
            return ssl_redirect(rc);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
                         "mod_webauth: connection is not https, "
                         "denying request");
            return HTTP_UNAUTHORIZED;
        }
    }

    /* Get user authentication or redirect the user. */
    status = gather_tokens(rc);
    if (status != OK)
        return status;

    if (rc->at != NULL) {
        /* stick it in note for future reference */
        subject = rc->at->subject;
        authz = rc->at->authz_subject;
        if (rc->sconf->debug)
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "mod_webauth: stash note, user(%s), authz(%s)",
                         subject, authz == NULL ? "" : authz);
        mwa_setn_note(r, N_SUBJECT, NULL, "%s", subject);
        if (authz != NULL)
            mwa_setn_note(r, N_AUTHZ_SUBJECT, NULL, "%s", authz);
    }

    /*
     * If WebAuth is optional and the user isn't authenticated, skip
     * check_user_id by returning OK, which bypasses any subsequent need for
     * authentication.
     */
    if (subject == NULL && rc->at == NULL && rc->dconf->optional)
        return OK;

    return DECLINED;
}


/*
 * Normally, the hook that authenticates the user.  However, most of the work
 * is currently done in mod_webauth_check_access, which runs before this hook
 * in Apache 2.4 and is called explicitly below in Apache 2.2.
 *
 * This hook does the work of setting the environment variables and request
 * state to reflect the successful authentication.
 */
static int
check_user_id_hook(request_rec *r)
{
    const char *at = ap_auth_type(r);
    char *wte, *wtc, *wtlu, *wif, *wsf, *wloa;
    const char *subject, *authz;
    bool trust_authz;
    MWA_REQ_CTXT *rc;
#ifndef HTTPD24
    int status;
#endif

    /* Get the module configuration. */
    rc = ap_get_module_config(r->request_config, &webauth_module);

    if (rc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "mod_webauth: in check_user_id hook(%s)",
                     rc->r->unparsed_uri != NULL ?
                     rc->r->unparsed_uri : "null-uri");

    /* Decline if the request is for an AuthType we don't handle. */
    if (!is_supported_authtype(r, rc))
        return DECLINED;

    /* If we can't load the keyring, return a fatal error. */
    if (!ensure_keyring_loaded(rc))
        return HTTP_INTERNAL_SERVER_ERROR;

#ifndef HTTPD24
    status = mod_webauth_check_access(r);
    if (status != DECLINED)
        return status;
#endif

    /* first check if we've already validated the user */
    subject = mwa_get_note(r, N_SUBJECT);
    authz = mwa_get_note(r, N_AUTHZ_SUBJECT);
    if (rc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "mod_webauth: found note, user(%s), authz(%s)",
                     subject, authz == NULL ? "" : authz);

    /*
     * This should never get called, since if WebAuth is not optional,
     * gather_tokens should set us up for a redirect and not return OK.  We
     * put this here as a safety net.
     */
    if (subject == NULL && rc->at == NULL) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
                     "mod_webauth: check_user_id_hook subject still NULL!");
        return HTTP_UNAUTHORIZED;
    }

    /*
     * If we're trusting authorization identities, set r->user to the
     * authorization identity if there is one.  Otherwise, set it to the
     * authentication identity.
     */
    trust_authz = rc->dconf->trust_authz_identity_set
        ? rc->dconf->trust_authz_identity
        : rc->sconf->trust_authz_identity;
    if (trust_authz && authz != NULL) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                     "mod_webauth: user %s authorized as %s", subject, authz);
        r->user = (char *) authz;
    } else {
        r->user = (char *) subject;
    }
    r->ap_auth_type = (char *) at;
    if (rc->sconf->debug)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "mod_webauth: check_user_id_hook setting user(%s)",
                     r->user);

    /*
     * Set environment variables.  WEBAUTH_USER is always the authentication
     * identity.  WEBAUTH_AUTHZ_USER is the authorization identity if one is
     * set, even if we're not trusting them.
     *
     * FIXME: This is only run when we have an app token, which means that if
     * we get the identity from a note, we skip all of that.  Is that correct?
     */
    mwa_setenv(rc, ENV_WEBAUTH_USER, subject);
    if (authz != NULL)
        mwa_setenv(rc, ENV_WEBAUTH_AUTHZ_USER, authz);
    if (rc->at != NULL) {
        wte = rc->at->expiration ?
            apr_psprintf(rc->r->pool, "%d", (int) rc->at->expiration) : NULL;
        wtc = rc->at->creation ?
            apr_psprintf(rc->r->pool, "%d", (int) rc->at->creation) : NULL;
        wtlu = rc->at->last_used ?
            apr_psprintf(rc->r->pool, "%d", (int) rc->at->last_used) : NULL;
        wif = rc->at->initial_factors != NULL ?
            apr_pstrdup(rc->r->pool, rc->at->initial_factors) : NULL;
        wsf = rc->at->session_factors != NULL ?
            apr_pstrdup(rc->r->pool, rc->at->session_factors) : NULL;
        wloa = rc->at->loa > 0 ?
            apr_psprintf(rc->r->pool, "%lu", (unsigned long) rc->at->loa) : NULL;

        if (wte != NULL)
            mwa_setenv(rc, ENV_WEBAUTH_TOKEN_EXPIRATION, wte);
        if (wtc != NULL)
            mwa_setenv(rc, ENV_WEBAUTH_TOKEN_CREATION, wtc);
        if (wtlu != NULL)
            mwa_setenv(rc, ENV_WEBAUTH_TOKEN_LASTUSED, wtlu);
        if (wif != NULL)
            mwa_setenv(rc, ENV_WEBAUTH_FACTORS_INITIAL, wif);
        if (wsf != NULL)
            mwa_setenv(rc, ENV_WEBAUTH_FACTORS_SESSION, wsf);
        if (wloa != NULL)
            mwa_setenv(rc, ENV_WEBAUTH_LOA, wloa);
    }

    if (rc->dconf->dont_cache_set && rc->dconf->dont_cache)
        dont_cache(rc);

#ifndef NO_STANFORD_SUPPORT

    if (rc->dconf->su_authgroups != NULL) {
        /* always deny access in this case */
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
                     "mod_webauth: denying access due to use of unsupported "
                     "StanfordAuthGroups directive: %s",
                     rc->dconf->su_authgroups);
        return HTTP_UNAUTHORIZED;
    }

    if (strcmp(at, "StanfordAuth") == 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
                     "AuthType StanfordAuth (URL: %s) is deprecated and"
                     " will be removed in a subsequent release",
                     r->uri == NULL ? "UNKNOWN" : r->uri);
        mwa_setenv(rc, "SU_AUTH_USER", r->user);
        if (rc->at != NULL && rc->at->creation > 0) {
            time_t age = time(NULL) - rc->at->creation;
            if (age < 0)
                age = 0;
            mwa_setenv(rc, "SU_AUTH_AGE",
                       apr_psprintf(rc->r->pool, "%d", (int) age));
        }
    }
#endif

    if (rc->sconf->debug) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "mod_webauth: check_user_id_hook: no_cache(%d) dont_cache(%d) dont_cache_ex(%d)", r->no_cache,
                     rc->dconf->dont_cache, rc->dconf->dont_cache_set);
    }

    if (r->proxyreq != PROXYREQ_NONE) {
        /* make sure any webauth_* cookies don't end up proxied */
        /* also strip out stuff from Referer */
        strip_webauth_info(rc);
    }

    return OK;
}


/*
 * this hook will attempt to find the returned-token and the
 * state-token in the URL (r->the_request). If we find them and stash them in
 * the notes for the master request, and then remove them from
 * everywhere we find them, so they
 * don't show up in access_logs.
 *
 *  we strip them in the following places:
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
 *  we'll stick the tokens in the notes table for the initial
 *  request
 *
 */
static int
translate_name_hook(request_rec *r)
{
    char *p, *s, *rp;
    char *wr, *ws;
    struct server_config *sconf;
    static const char *rmagic = WEBAUTHR_MAGIC;
    static const char *smagic = WEBAUTHS_MAGIC;

    sconf = ap_get_module_config(r->server->module_config, &webauth_module);
    if (!ap_is_initial_req(r)) {
        return DECLINED;
    }

    /* mwa_log_request(r, "before xlate"); */

    rp = ap_strstr(r->the_request, rmagic);
    if (rp == NULL) {
        /* no tokens in the request, return */
        return DECLINED;
    }

    /* we need to save the tokens for check_user_id_hook. */

    s = rp+WEBAUTHR_MAGIC_LEN;
    p = ap_strchr(s, ';');
    if (p == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "mod_webauth: didn't find end of %s", rmagic);
        return DECLINED;
    }
    wr = apr_pstrmemdup(r->pool, s, p-s);
    /*
     * if (sconf->debug)
     * ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
     * "mod_webauth: stash wr(%s)", wr);
     */
    mwa_setn_note(r, N_WEBAUTHR, NULL, "%s", wr);

    s = p + 1;
    p = ap_strstr(s, smagic);
    if (p != NULL) {
        s = p + WEBAUTHS_MAGIC_LEN;
        p = ap_strchr(s, ';');
        if (p == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                         "mod_webauth: didn't find end of %s", smagic);
            return DECLINED;
        }
        ws = apr_pstrmemdup(r->pool, s, p-s);
        /*if (sconf->debug)
         * ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
         * "mod_webauth: stash ws(%s)", ws);
         */
        mwa_setn_note(r, N_WEBAUTHS, NULL, "%s", ws);
        s = p + 1;
    }

    /* Strip the WebAuth information from the internal URL unless asked. */
    if (sconf->strip_url) {
        /* move over remaining */
        strcpy(rp, s);

        /* these are easier, we strip rmagic and everything after it,
           which might include smagic */

        strip_end(r->unparsed_uri, rmagic);
        strip_end(r->uri, rmagic);
        strip_end(r->filename, rmagic);
        strip_end(r->canonical_filename, rmagic);
        strip_end(r->path_info, rmagic);
        /* make sure to try rmagic and rmagic+1, since if there were
           no query args, rmagic ends up looking like query args and
           the ? gets stripped */
        strip_end(r->args, rmagic);
        strip_end(r->args, rmagic+1);
        if (r->args != NULL && *r->args == 0)
            r->args = NULL;
        strip_end(r->parsed_uri.path, rmagic);
        /* make sure to try rmagic and rmagic+1, since if there were
           no query args, rmagic ends up looking like query args and
           the ? gets stripped */
        strip_end(r->parsed_uri.query, rmagic);
        strip_end(r->parsed_uri.query, rmagic+1);
        if (r->parsed_uri.query != NULL && *r->parsed_uri.query == 0)
            r->parsed_uri.query = NULL;
    }

    /* mwa_log_request(r, "after xlate"); */

    /* still need to return DECLINED, so other modules (like mod_rerewrite)
       get a crack at things */
    return DECLINED;
}


/*
 * Hook into fixups to ensure that all WebAuth cookies are set properly.  If
 * we're doing logout, we'll also ensure that the headers saying not to cache
 * the response are set properly.
 */
static int
fixups_hook(request_rec *r)
{
    MWA_REQ_CTXT *rc;

    rc = ap_get_module_config(r->request_config, &webauth_module);

    /*
     * Reportedly with Solaris 10 x86's included Apache (2.0.63),
     * r->per_dir_config may not always be set.  If it isn't set, assume
     * that we're not doing logout.
     * UVMXXX - do we still need to worry about this case?
     */
    if (r->per_dir_config != NULL)
        rc->dconf = ap_get_module_config(r->per_dir_config, &webauth_module);
    if (rc->dconf != NULL && rc->dconf->do_logout) {
        nuke_all_webauth_cookies(rc);
        dont_cache(rc);
    } else {
        set_pending_cookies(rc);
    }
    return DECLINED;
}


static void
register_hooks(apr_pool_t *p UNUSED)
{
    /* get our module called before the basic authentication stuff */
    static const char * const mods[]={ "mod_access.c", "mod_auth.c", NULL };

    ap_hook_post_config(mod_webauth_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_create_request(mod_webauth_create_request, NULL, NULL,
                           APR_HOOK_MIDDLE);

    /* we need to get run before anyone else, so we can clean up the URL
       if need be */
    ap_hook_translate_name(translate_name_hook, NULL, NULL,
                           APR_HOOK_REALLY_FIRST);
#ifdef HTTPD24
    ap_hook_check_access_ex(mod_webauth_check_access, NULL, NULL,
                            APR_HOOK_LAST, AP_AUTH_INTERNAL_PER_CONF);
    ap_hook_post_perdir_config(mod_webauth_post_config, NULL, NULL,
                               APR_HOOK_MIDDLE);
#else
    ap_hook_access_checker(mod_webauth_post_config, NULL, NULL,
                           APR_HOOK_MIDDLE);
#endif

    /* The core authentication hook. */
    ap_hook_check_authn(check_user_id_hook, NULL, mods, APR_HOOK_MIDDLE,
                        AP_AUTH_INTERNAL_PER_CONF);
    ap_hook_handler(handler_hook, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_fixups(fixups_hook, NULL,NULL,APR_HOOK_MIDDLE);
}


/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA webauth_module = {
    STANDARD20_MODULE_STUFF,
    mwa_dir_config_create,      /* create per-dir    config structures */
    mwa_dir_config_merge,       /* merge  per-dir    config structures */
    mwa_server_config_create,   /* create per-server config structures */
    mwa_server_config_merge,    /* merge  per-server config structures */
    webauth_cmds,               /* table of config file commands       */
    register_hooks              /* register hooks                      */
};
