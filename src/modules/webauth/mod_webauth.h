#ifndef MOD_WEBAUTH_H
#define MOD_WEBAUTH_H

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
#include "apr_xml.h"
#include "apr_base64.h"

#include <curl/curl.h>

#include "webauth.h"

/* probably need a better place for this constant */
#define WEBAUTH_VERSION "WebAuth/3"

/* how long to wait between trying for a new token when 
 * a renewal attempt fails
 */
#define TOKEN_RETRY_INTERVAL  600

/* 
 * how long into the tokens lifetime do we attempt our first revnewal 
 */
#define START_RENEWAL_ATTEMPT_PERCENT (0.90)

/* where to look in URL for returned tokens */
#define WEBAUTHR_MAGIC ";WEBAUTHR="
#define WEBAUTHR_MAGIC_LEN (sizeof(WEBAUTHR_MAGIC)-1)

#define WEBAUTHS_MAGIC ";WEBAUTHS="
#define WEBAUTHS_MAGIC_LEN (sizeof(WEBAUTHS_MAGIC)-1)

/* name of our main app-token cookie */
#define AT_COOKIE_NAME "webauth_at"

/* environment variables to set */
#define ENV_WEBAUTH_USER "WEBAUTH_USER"
#define ENV_WEBAUTH_TOKEN_CREATION "WEBAUTH_TOKEN_CREATION"
#define ENV_WEBAUTH_TOKEN_EXPIRATION "WEBAUTH_TOKEN_EXPIRATION"
#define ENV_WEBAUTH_TOKEN_LASTUSED "WEBAUTH_TOKEN_LASTUSED"

/* defines for config directives */
#define CD_WebKdcURL "WebAuthWebKdcURL"
#define CM_WebKdcURL "URL for the WebKdc XML service"

#define CD_WebKdcPrincipal "WebAuthWebKdcPrincipal"
#define CM_WebKdcPrincipal "K5 WebKDC principal name"

#define CD_LoginURL "WebAuthLoginURL"
#define CM_LoginURL "URL for the login page"

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

#define CD_ServiceTokenCache "WebAuthServiceTokenCache"
#define CM_ServiceTokenCache "path to the service token cache file"

#define CD_VarPrefix "WebAuthVarPrefix"
#define CM_VarPrefix "prefix to prepend to env variables"

#define CD_Debug "WebAuthDebug"
#define CM_Debug "turn debugging on or off"

#define CD_DoLogout "WebAuthDoLogout"
#define CM_DoLogout "nuke all WebAuth cookies"

#define CD_RequireSSL "WebAuthRequireSSL"
#define CM_RequireSSL "whether or not SSL is required"
#define DF_RequireSSL 1

#define CD_AppTokenLifetime "WebAuthAppTokenLifetime"
#define CM_AppTokenLifetime "lifetime of app-tokens"

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

#define CD_ReturnURL "WebAuthReturnURL"
#define CM_ReturnURL "url to return to after logging in"

#define CD_LoginCanceledURL "WebAuthLoginCanceledURL"
#define CM_LoginCanceledURL "url to return if user cancel's out of login"

/* r->notes keys */
#define N_WEBAUTHR "mod_webauth_WEBAUTHR"
#define N_WEBAUTHS "mod_webauth_WEBAUTHS"
#define N_SUBJECT  "mod_webauth_SUBJECT"
#define N_EXPIRATION "mod_webauth_EXPIRAION"
#define N_CREATION   "mod_webauth_CREATION"
#define N_LASTUSED   "mod_webauth_LASTUSED"
#define N_APP_COOKIE  "mod_webauth_APP_COOKIE"


/* enum for mutexes */
enum mwa_mutex_type {
    MWA_MUTEX_KEYRING = 0,
    MWA_MUTEX_SERVICE_TOKEN,
    MWA_MUTEX_MAX /* MUST BE LAST! */
};

/* enums for config directives */

enum {
    E_AppTokenLifetime,
    E_Debug,
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
    E_ReturnURL,
    E_RequireSSL,
    E_ServiceTokenCache,
    E_StripURL,
    E_SubjectAuthType,
    E_TokenMaxTTL,
    E_VarPrefix,
    E_WebKdcPrincipal,
    E_WebKdcURL,
};

module webauth_module;

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
    char *webkdc_url;
    char *webkdc_principal;
    char *login_url;
    char *keyring_path;
    char *keytab_path;
    char *st_cache_path;
    char *var_prefix;
    int  debug;
    int debug_ex;
    int  require_ssl;
    int require_ssl_ex;
    char *subject_auth_type;
    int extra_redirect;
    int extra_redirect_ex; /* if it was explicitly specified in conf file */
    int strip_url;
    int strip_url_ex; 
    int keyring_auto_update;
    int keyring_auto_update_ex;
    int keyring_key_lifetime;
    int keyring_key_lifetime_ex;
    int subject_auth_type_ex;
    int token_max_ttl; 
    int token_max_ttl_ex;
} MWA_SCONF;

/* directory conf stuff */
typedef struct {
    int app_token_lifetime;
    int inactive_expire;
    int last_use_update_interval;
    int force_login;
    int force_login_ex;
    int do_logout;
    int do_logout_ex;
    char *return_url;
    char *failure_url;
    char *login_canceled_url;
} MWA_DCONF;

/* handy bunch of bits to pass around during a request */
typedef struct {
    request_rec *r;
    MWA_SCONF *sconf;
    MWA_DCONF *dconf;
    /* subject from token, url, etc */
    char *subject;
    /* times from parsed/newly created app token */
    time_t creation_time;
    time_t expiration_time;
    time_t last_used_time;
} MWA_REQ_CTXT;

/* used to append a bunch of data together */
typedef struct {
    char *data;
    int size;
    int capacity;
    apr_pool_t *pool;
} MWA_STRING;

/* webkdc.c */

MWA_SERVICE_TOKEN *
mwa_get_service_token(MWA_REQ_CTXT *rc);

/* util.c */

/*
 * initialize all our mutexes
 */
void
mwa_init_mutexes(server_rec *s);

/*
 * lock a mutex
 */
void
mwa_lock_mutex(MWA_REQ_CTXT *rc, enum mwa_mutex_type type);

/*
 * unlock a mutex 
 */
void
mwa_unlock_mutex(MWA_REQ_CTXT *rc, enum mwa_mutex_type type);

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
 * get a WEBAUTH_KRB5_CTXT, log errors
 */
WEBAUTH_KRB5_CTXT *
mwa_get_webauth_krb5_ctxt(request_rec *r, const char *mwa_func);


/*
 * log a webauth-related error. ctxt can be NULL.
 */
void
mwa_log_webauth_error(request_rec *r, 
                      int status, 
                      WEBAUTH_KRB5_CTXT *ctxt,
                      const char *mwa_func,
                      const char *func);

/* 
 * should only be called (and result used) while you have
 * the MWA_MUTEX_KEYRING mutex.
 */

WEBAUTH_KEYRING *
mwa_get_keyring(MWA_REQ_CTXT *rc);

#endif
