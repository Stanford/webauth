#ifndef MOD_WEBAUTH_H
#define MOD_WEBAUTH_H

#include <unistd.h>

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_config.h"
#include "apr.h"
#include "apr_lib.h"
#include "apr_file_io.h"
#include "apr_file_info.h"
#include "apr_errno.h"
#include "apr_strings.h"
#include "apr_pools.h"
#include "apr_tables.h"
#include "apr_time.h"
#include "apr_xml.h"
#include "apr_base64.h"

#include <curl/curl.h>

#include "webauth.h"

/* how long to wait between trying for a new token when 
 * a renewal attempt fails
 */
#define TOKEN_RETRY_INTERVAL  600

/* 
 * how long into the tokens lifetime do we attempt our first revnewal 
 */
#define START_RENEWAL_ATTEMPT_PERCENT (0.90)

/* where to look in URL for returned tokens */
#define WEBAUTHR_MAGIC "?WEBAUTHR="
#define WEBAUTHR_MAGIC_LEN (sizeof(WEBAUTHR_MAGIC)-1)

#define WEBAUTHS_MAGIC ";WEBAUTHS="
#define WEBAUTHS_MAGIC_LEN (sizeof(WEBAUTHS_MAGIC)-1)

/* environment variables to set */
#define ENV_WEBAUTH_USER "WEBAUTH_USER"
#define ENV_WEBAUTH_TOKEN_CREATION "WEBAUTH_TOKEN_CREATION"
#define ENV_WEBAUTH_TOKEN_EXPIRATION "WEBAUTH_TOKEN_EXPIRATION"
#define ENV_WEBAUTH_TOKEN_LASTUSED "WEBAUTH_TOKEN_LASTUSED"
#define ENV_KRB5CCNAME "KRB5CCNAME"

/* defines for config directives */
#define CD_WebKdcURL "WebAuthWebKdcURL"
#define CM_WebKdcURL "URL for the WebKdc XML service"

#define CD_WebKdcPrincipal "WebAuthWebKdcPrincipal"
#define CM_WebKdcPrincipal "K5 WebKDC principal name"

#define CD_WebKdcURL "WebAuthWebKdcURL"
#define CM_WebKdcURL "URL for the WebKdc XML service"

#define CD_WebKdcSSLCertFile "WebAuthWebKdcSSLCertFile"
#define CM_WebKdcSSLCertFile "cert file containing the WebKDC's certificate"

#define CD_WebKdcSSLCertCheck "WebAuthWebKdcSSLCertCheck"
#define CM_WebKdcSSLCertCheck "whether or not to perform security checks on the SSL cert used by the WebKDC"
#define DF_WebKdcSSLCertCheck 1

#define CD_LoginURL "WebAuthLoginURL"
#define CM_LoginURL "URL for the login page"

#define CD_AuthType "WebAuthAuthType"
#define CM_AuthType "additional AuthType alias"

#define CD_FailureURL "WebAuthFailureURL"
#define CM_FailureURL "URL for serious webauth failures"

#define CD_Keyring "WebAuthKeyring"
#define CM_Keyring "path to the keyring file"

#define CD_KeyringKeyLifetime "WebAuthKeyringKeyLifetime"
#define CM_KeyringKeyLifetime "lifetime of keys we create"
#define DF_KeyringKeyLifetime (60*60*24*30) /* 30 days */

#define CD_KeyringAutoUpdate "WebAuthKeyringAutoUpdate"
#define CM_KeyringAutoUpdate "whether or not to automatically update keyring"
#define DF_KeyringAutoUpdate 1

#define CD_Keytab "WebAuthKeytab"
#define CM_Keytab "path to the K5 keytab file"

#define CD_CredCacheDir "WebAuthCredCacheDir"
#define CM_CredCacheDir "path to the credential cache directory"

#define CD_ServiceTokenCache "WebAuthServiceTokenCache"
#define CM_ServiceTokenCache "path to the service token cache file"

#define CD_VarPrefix "WebAuthVarPrefix"
#define CM_VarPrefix "prefix to prepend to env variables"

#define CD_Debug "WebAuthDebug"
#define CM_Debug "turn debugging on or off"


#define CD_ProxyHeaders "WebAuthProxyHeaders"
#define CM_ProxyHeaders "turn proxy WebAuth headers on or off"

#define CD_DoLogout "WebAuthDoLogout"
#define CM_DoLogout "nuke all WebAuth cookies"

#define CD_RequireSSL "WebAuthRequireSSL"
#define CM_RequireSSL "whether or not SSL is required"
#define DF_RequireSSL 1

#define CD_AppTokenLifetime "WebAuthAppTokenLifetime"
#define CM_AppTokenLifetime "lifetime of app-tokens"

#define CD_Cred "WebAuthCred"
#define CM_Cred "credential to obtain"

#define CD_TokenMaxTTL "WebAuthTokenMaxTTL"
#define CM_TokenMaxTTL "max ttl of tokens that are supposed to be \"recent\""
#define DF_TokenMaxTTL 300

#define CD_SubjectAuthType "WebAuthSubjectAuthType"
#define CM_SubjectAuthType "type of subject authenticator returned in id-token"
#define DF_SubjectAuthType "webkdc"

#define CD_StripURL "WebAuthStripURL"
#define CM_StripURL "strip returned webkdc tokens from URL"
#define DF_StripURL 1

#define CD_ExtraRedirect "WebAuthExtraRedirect"
#define CM_ExtraRedirect "do extra redirect after getting returned from WebKDC"

#define CD_InactiveExpire "WebAuthInactiveExpire"
#define CM_InactiveExpire "duration of inactivity before an app-token expires"

#define CD_LastUseUpdateInterval "WebAuthLastUseUpdateInterval"
#define CM_LastUseUpdateInterval "how often to update last-used-time in cookie"

#define CD_ForceLogin "WebAuthForceLogin"
#define CM_ForceLogin "having no valid app-token forces a "\
                      "username/password prompt"

#define CD_UseCreds "WebAuthUseCreds"
#define CM_UseCreds "whether or not to create a cred cache file"

#define CD_ReturnURL "WebAuthReturnURL"
#define CM_ReturnURL "url to return to after logging in"

#define CD_LoginCanceledURL "WebAuthLoginCanceledURL"
#define CM_LoginCanceledURL "url to return if user cancel's out of login"

#define CD_DontCache "WebAuthDontCache"
#define CM_DontCache "sets Expires header to current date"

#ifndef NO_STANFORD_SUPPORT

/* Stanford WebAuth 2.5 compat */
#define SCD_ConfirmMsg "StanfordAuthConfirmMsg"
#define SCM_ConfirmMsg "unsupported WebAuth 2.5 option"

#define SCD_DoConfirm "StanfordAuthDoConfirm"
#define SCM_DoConfirm "unsupported WebAuth 2.5 option"

#define SCD_DontCache "StanfordAuthDontCache"
#define SCM_DontCache "ignored"

#define SCD_ForceReload "StanfordAuthForceReload"
#define SCM_ForceReload "maps to WebAuthExtraRedirect"

#define SCD_Groups "StanfordAuthGroups"
#define SCM_Groups "unsupported WebAuth 2.5 option"

#define SCD_Life "StanfordAuthLife"
#define SCM_Life "maps to WebAuthAppTokenLifetime and enables WebAuthForceLogin"
#define SCD_ReturnURL "StanfordAuthReturnURL"
#define SCM_ReturnURL "maps to WebAuthReturnURL"

#endif

/* r->notes keys */
#define N_WEBAUTHR "mod_webauth_WEBAUTHR"
#define N_WEBAUTHS "mod_webauth_WEBAUTHS"
#define N_SUBJECT  "mod_webauth_SUBJECT"

/* attr list macros to make code easier to read and audit 
 * we don't need to check error codes since we are using
 * WA_F_NONE, which doesn't allocate any memory.
 */

#define ADD_STR(name,value) \
       webauth_attr_list_add_str(alist, name, value, 0, WA_F_NONE)

#define ADD_PTR(name,value, len) \
       webauth_attr_list_add(alist, name, value, len, WA_F_NONE)

#define ADD_TIME(name,value) \
       webauth_attr_list_add_time(alist, name, value, WA_F_NONE)

#define SET_APP_STATE(state,len)     ADD_PTR(WA_TK_APP_STATE, state, len)
#define SET_COMMAND(cmd)             ADD_STR(WA_TK_COMMAND, cmd)
#define SET_CRED_DATA(data, len)     ADD_PTR(WA_TK_CRED_DATA, data, len)
#define SET_CRED_TYPE(type)          ADD_STR(WA_TK_CRED_TYPE, type)
#define SET_CRED_SERVER(server)      ADD_STR(WA_TK_CRED_SERVER, server)
#define SET_CREATION_TIME(time)      ADD_TIME(WA_TK_CREATION_TIME, time)
#define SET_ERROR_CODE(code)         ADD_STR(WA_TK_ERROR_CODE, code)
#define SET_ERROR_MESSAGE(msg)       ADD_STR(WA_TK_ERROR_MESSAGE, msg)
#define SET_EXPIRATION_TIME(time)    ADD_TIME(WA_TK_EXPIRATION_TIME, time)
#define SET_INACTIVITY_TIMEOUT(to)   ADD_STR(WA_TK_INACTIVITY_TIMEOUT, to)
#define SET_SESSION_KEY(key,len)     ADD_PTR(WA_TK_SESSION_KEY, key, len)
#define SET_LASTUSED_TIME(time)      ADD_TIME(WA_TK_LASTUSED_TIME, time)
#define SET_PROXY_TYPE(type)         ADD_STR(WA_TK_PROXY_TYPE, type)
#define SET_PROXY_DATA(data,len)     ADD_PTR(WA_TK_PROXY_DATA, data, len)
#define SET_PROXY_SUBJECT(sub)       ADD_STR(WA_TK_PROXY_SUBJECT, sub)
#define SET_REQUEST_OPTIONS(ro)      ADD_STR(WA_TK_REQUEST_OPTIONS, ro)
#define SET_REQUESTED_TOKEN_TYPE(t)  ADD_STR(WA_TK_REQUESTED_TOKEN_TYPE, t)
#define SET_RETURN_URL(url)          ADD_STR(WA_TK_RETURN_URL, url)
#define SET_SUBJECT(s)               ADD_STR(WA_TK_SUBJECT, s)
#define SET_SUBJECT_AUTH(sa)         ADD_STR(WA_TK_SUBJECT_AUTH, sa)
#define SET_SUBJECT_AUTH_DATA(d,l)   ADD_PTR(WA_TK_SUBJECT_AUTH_DATA, d, l)
#define SET_TOKEN_TYPE(type)         ADD_STR(WA_TK_TOKEN_TYPE, type)
#define SET_WEBKDC_TOKEN(d,l)        ADD_PTR(WA_TK_WEBKDC_TOKEN, d, l)

/* enums for config directives */

enum {
    E_AuthType,
    E_AppTokenLifetime,
    E_Cred,
    E_CredCacheDir,
    E_Debug,
    E_DontCache,
    E_DoLogout,
    E_ExtraRedirect,
    E_FailureURL,
    E_ForceLogin,
    E_InactiveExpire,
    E_Keyring,
    E_KeyringAutoUpdate,
    E_KeyringKeyLifetime,
    E_Keytab,
    E_LastUseUpdateInterval,
    E_LoginURL,
    E_LoginCanceledURL,
    E_ProxyHeaders,
    E_ReturnURL,
    E_RequireSSL,
    E_UseCreds,
    E_ServiceTokenCache,
    E_StripURL,
    E_SubjectAuthType,
    E_TokenMaxTTL,
    E_VarPrefix,
    E_WebKdcPrincipal,
    E_WebKdcSSLCertFile,
    E_WebKdcSSLCertCheck,
    E_WebKdcURL,
#ifndef NO_STANFORD_SUPPORT
    SE_ConfirmMsg,
    SE_DoConfirm,
    SE_DontCache,
    SE_ForceReload,
    SE_Life,
    SE_ReturnURL,
    SE_Groups,
#endif
};

extern module webauth_module;

/* a service token and associated data, all memory (including key)
 * is allocated from a pool
 */
typedef struct {
    apr_pool_t *pool; /* pool this token belongs to */
    WEBAUTH_KEY key;
    time_t expires;
    unsigned char *token;
    time_t created; /* when we first obtained this token */
    time_t next_renewal_attempt; /* next time we try to renew */
    time_t last_renewal_attempt; /* time we last tried to renew */
    void *app_state; /* used as "as" attribute in request tokens */
    int app_state_len;
} MWA_SERVICE_TOKEN;

/* server conf stuff */
typedef struct {
    char *auth_type;
    char *webkdc_url;
    char *webkdc_principal;
    char *webkdc_cert_file;
    int webkdc_cert_check;
    int webkdc_cert_check_ex;
    char *login_url;
    char *keyring_path;
    char *keytab_path;
    char *keytab_principal;
    char *cred_cache_dir;
    char *st_cache_path;
    int  debug;
    int debug_ex;
    int proxy_headers;
    int proxy_headers_ex;
    int  require_ssl;
    int require_ssl_ex;
    char *subject_auth_type;
    int strip_url;
    int strip_url_ex; 
    int keyring_auto_update;
    int keyring_auto_update_ex;
    int keyring_key_lifetime;
    int keyring_key_lifetime_ex;
    int subject_auth_type_ex;
    int token_max_ttl; 
    int token_max_ttl_ex;
    /* stuff we need to clean up on restarts and what not */
    WEBAUTH_KEYRING *ring; /* our keyring */
    int free_ring;         /* set if we should free ring */
    MWA_SERVICE_TOKEN *service_token; /*cached service_token, always free */
    apr_thread_mutex_t *mutex; /* mutex to use when modfiying sconf stuff */
} MWA_SCONF;

/* directory conf stuff */
typedef struct {
    int app_token_lifetime;
    int inactive_expire;
    int last_use_update_interval;
    int force_login;
    int force_login_ex;
    int use_creds;
    int use_creds_ex;
    int do_logout;
    int do_logout_ex;
    char *return_url;
    char *failure_url;
    char *login_canceled_url;
    int extra_redirect;
    int extra_redirect_ex; /* if it was explicitly specified in conf file */
    char *var_prefix;
    apr_array_header_t *creds; /* array of MWA_WACRED's */
    int dont_cache;
    int dont_cache_ex;
#ifndef NO_STANFORD_SUPPORT
    char *su_authgroups;
#endif
} MWA_DCONF;

/* a cred, used to keep track of WebAuthCred directives. */
typedef struct {
    char *type;
    char *service;
} MWA_WACRED;

/* enums for MWA_TOKEN_DATA->type */
enum {
    MWA_T_APP,
    MWA_T_PROXY,
    MWA_T_CRED,
};

/* enums for MWA_TOKEN_DATA->source */
enum {
    MWA_TDS_COOKIE, /* data was in a cookie */
    MWA_TDS_NOTE,   /* data was in a note, from a cookie */
    MWA_TDS_URL,    /* data was from WEBAUTHR in URL */
    MWA_TDS_TOKEN,  /* data was from newly-created token */
};

typedef struct {
    const char *subject;
    time_t creation_time;
    time_t expiration_time;
    time_t last_used_time;
} MWA_APP_TOKEN;

typedef struct {
    const char *proxy_type;
    const char *subject;
    time_t creation_time;
    time_t expiration_time;
    void *wpt; /* webkdc-proxy-token */
    int wpt_len;
} MWA_PROXY_TOKEN;

typedef struct {
    const char *cred_type;
    const char *cred_server;
    const char *subject;
    void *cred_data; /* this is ready to be blasted to a file */
    int cred_data_len;
    time_t creation_time;
    time_t expiration_time;
} MWA_CRED_TOKEN;

/* handy bunch of bits to pass around during a request */
typedef struct {
    request_rec *r;
    MWA_SCONF *sconf;
    MWA_DCONF *dconf;
    MWA_APP_TOKEN at;
    char *needed_proxy_type; /* set if we are redirecting for a proxy-token */
    MWA_PROXY_TOKEN *pt; /* proxy-token that came from URL */
    apr_array_header_t *cred_tokens; /* cred token(s) */
} MWA_REQ_CTXT;

/* used to append a bunch of data together */
typedef struct {
    char *data;
    int size;
    int capacity;
    apr_pool_t *pool;
} MWA_STRING;

/* structure that defines the proxy/credential interface */
typedef struct {
    /* proxy/cred type (i.e., "krb5") */
    const char *type;

    /* function to validate subject-authenticator-data */
    const char *(*validate_sad) (MWA_REQ_CTXT *rc, 
                                 void *sad, 
                                 int sad_len);

    /* function to run through all the cred tokens and prepare any
       cred tokens that are the same as our type for use by CGI */
    int (*prepare_creds)(MWA_REQ_CTXT *rc,
                         MWA_CRED_TOKEN **creds, 
                         int num_creds);

    /* get the base64'd blob that we would send to the WebKDC
       in the <requesterCredential> element. */
    const char *(*webkdc_credential)(server_rec *server, 
                                     MWA_SCONF *sconf,
                                     apr_pool_t *pool);

} MWA_CRED_INTERFACE;


/* webkdc.c */

MWA_SERVICE_TOKEN *
mwa_get_service_token(server_rec *server, 
                      MWA_SCONF *sconf, apr_pool_t *pool,
                      int local_cache_only);


int
mwa_get_creds_from_webkdc(MWA_REQ_CTXT *rc,
                          MWA_PROXY_TOKEN *pt,
                          MWA_WACRED *creds,
                          int num_creds,
                          apr_array_header_t **acquired_creds);

/* util.c */

/*
 * get a string from an attr list, log an error if not present.
 * vlen is optional and can be set to NULL.
 */

char *
mwa_get_str_attr(WEBAUTH_ATTR_LIST *alist, const char *name, 
                 request_rec *r, const char *func, int *vlen);

/*
 * get note from main request 
 */
const char *
mwa_get_note(request_rec *r, const char *note);

/*
 * remove note from main request, and return it if it was set, or NULL
 * if unset
 */
char *
mwa_remove_note(request_rec *r, const char *note);

/*
 * set note to main request. does not make copy of data
 */
void
mwa_setn_note(request_rec *r, const char *note, const char *val);

/*
 * log interesting stuff from the request
 */
void 
mwa_log_request(request_rec *r, const char *msg);

/*
 * log a webauth-related error
 */
void
mwa_log_webauth_error(server_rec *r, 
                      int status, 
                      const char *mwa_func,
                      const char *func,
                      const char *extra);

/*
 * this should only be called in the module init routine
 */
int
mwa_cache_keyring(server_rec *serv, MWA_SCONF *sconf);

/* 
 * get all cookies that start with webauth_
 */
apr_array_header_t *
mwa_get_webauth_cookies(request_rec *r);

/*
 * parse a cred token. If key is non-null use it, otherwise
 * if ring is non-null use it, otherwise log an error and return NULL.
 */
MWA_CRED_TOKEN *
mwa_parse_cred_token(char *token, 
                     WEBAUTH_KEYRING *ring,
                     WEBAUTH_KEY *key, 
                     MWA_REQ_CTXT *rc);

void 
mwa_log_apr_error(server_rec *server,
                  apr_status_t astatus,
                  const char *mwa_func,
                  const char *ap_func,
                  const char *path1,
                  const char *path2);


void
mwa_register_cred_interface(server_rec *server,
                            MWA_SCONF *sconf,
                            apr_pool_t *pool,
                            MWA_CRED_INTERFACE *interface);

MWA_CRED_INTERFACE *
mwa_find_cred_interface(server_rec *server,
                        const char *type);

/* krb5.c */
extern MWA_CRED_INTERFACE *mwa_krb5_cred_interface;

#endif
