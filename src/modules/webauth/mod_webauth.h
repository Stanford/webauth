#ifndef MOD_WEBAUTH_H
#define MOD_WEBAUTH_H

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_core.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "apr.h"
#include "apr_lib.h"
#include "apr_file_io.h"
#include "apr_file_info.h"
#include "apr_errno.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_xml.h"

#include <curl/curl.h>

#include "webauth.h"

/* probably need a better place for this constant */
#define WEBAUTH_VERSION "WebAuth/3"

/* where to look in URL for returned tokens */
#define WEBAUTHR_MAGIC ";WEBAUTHR="
#define WEBAUTHR_MAGIC_LEN (sizeof(WEBAUTHR_MAGIC)-1)

#define WEBAUTHS_MAGIC ";WEBAUTHS="
#define WEBAUTHS_MAGIC_LEN (sizeof(WEBAUTHS_MAGIC)-1)

/* name of our main app-token cookie */
#define AT_COOKIE_NAME "webauth_at"

/* environment variable to set */
#define ENV_WEBAUTH_USER "WEBAUTH_USER"

/* for searching Cookie: header */
#define AT_COOKIE_NAME_EQ "webauth_at="

/* defines for config directives */
#define CD_SecureCookie "WebAuthSecureCookie"
#define CM_SecureCookie "make cookies with the 'secure' attribute"
#define DF_SecureCookie 1

#define CD_WebKDCURL "WebAuthWebKDCURL"
#define CM_WebKDCURL "URL for the WebKDC XML service"

#define CD_WebKDCPrincipal "WebAuthWebKDCPrincipal"
#define CM_WebKDCPrincipal "K5 WebKDC principal name"

#define CD_LoginURL "WebAuthLoginURL"
#define CM_LoginURL "URL for the login page"

#define CD_FailureURL "WebAuthFailureURL"
#define CM_FailureURL "URL for serious webauth failures"

#define CD_Keyring "WebAuthKeyring"
#define CM_Keyring "path to the keyring file"

#define CD_Keytab "WebAuthKeytab"
#define CM_Keytab "path to the K5 keytab file"

#define CD_ServiceTokenCache "WebAuthServiceTokenCache"
#define CM_ServiceTokenCache "path to the service token cache file"

#define CD_VarPrefix "WebAuthVarPrefix"
#define CM_VarPrefix "prefix to prepend to env variables"

#define CD_Debug "WebAuthDebug"
#define CM_Debug "turn debugging on or off"

#define CD_AppTokenLifetime "WebAuthAppTokenLifetime"
#define CM_AppTokenLifetime "lifetime of app-tokens"

#define CD_TokenMaxTTL "WebAuthTokenMaxTTL"
#define CM_TokenMaxTTL "max ttl of tokens that are supposed to be \"recent\""
#define DF_TokenMaxTTL 300

#define CD_SubjectAuthType "WebAuthSubectAuthType"
#define CM_SubjectAuthType "type of subject authenticator returned in id-token"

#define CD_InactiveExpire "WebAuthInactiveExpire"
#define CM_InactiveExpire "duration of inactivity before an app-token expires"

#define CD_ForceLogin "WebAuthForceLogin"
#define CM_ForceLogin "having no valid app-token forces a "\
                      "username/password prompt"

#define CD_ReturnURL "WebAuthReturnURL"
#define CM_ReturnURL "url to return to after logging in"

/* r->notes keys */
#define N_WEBAUTHR "mod_webauth_WEBAUTHR"
#define N_WEBAUTHS "mod_webauth_WEBAUTHS"
#define N_SUBJECT  "mod_webauth_SUBJECT"
#define N_APP_COOKIE  "mod_webauth_APP_COOKIE"

/* enums for config directives */

enum {
    E_SecureCookie,
    E_WebKDCURL,
    E_WebKDCPrincipal,
    E_LoginURL,
    E_FailureURL,
    E_Keyring,
    E_Keytab,
    E_ServiceTokenCache,
    E_VarPrefix,
    E_Debug,
    E_AppTokenLifetime,
    E_TokenMaxTTL,
    E_SubjectAuthType,
    E_InactiveExpire,
    E_ForceLogin,
    E_ReturnURL
};

module webauth_module;


/* a service token and associated data, all memory (including key)
 * is allocated from a pool
 */
typedef struct {
    WEBAUTH_KEY key;
    time_t expires;
    unsigned char *token;
    time_t last_renewal_attempt; /* timed we last tried to renew */
} MWA_SERVICE_TOKEN;


/* server conf stuff */
typedef struct {
    char *webkdc_url;
    char *webkdc_principal;
    char *login_url;
    char *failure_url;
    char *keyring_path;
    char *keytab_path;
    char *st_cache_path;
    char *var_prefix;
    int  debug;
    int secure_cookie;
    int secure_cookie_ex; /* if it was explicitly specified in conf file */
    int token_max_ttl; 
    int token_max_ttl_ex; /* if it was explicitly specified in conf file */
} MWA_SCONF;

/* directory conf stuff */
typedef struct {
    int app_token_lifetime;
    char *subject_auth_type;
    int inactive_expire;
    int force_login;
    char *return_url;
} MWA_DCONF;

/* handy bunch of bits to pass around during a request */
typedef struct {
    request_rec *r;
    MWA_SCONF *sconf;
    MWA_DCONF *dconf;
} MWA_REQ_CTXT;

/* used to suck back XML data from the webkdc */
typedef struct {
    char *data;
    int size;
    int capacity;
    request_rec *r;
} MWA_CURL_POST_GATHER_CTXT;


/* globals */
WEBAUTH_KEYRING *mwa_g_ring;
MWA_SERVICE_TOKEN *mwa_g_service_token;

/* service_token.c */

MWA_SERVICE_TOKEN *
mwa_get_service_token(MWA_REQ_CTXT *rc);

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

#endif
