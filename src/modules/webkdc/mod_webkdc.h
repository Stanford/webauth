#ifndef MOD_WEBKDC_H
#define MOD_WEBKDC_H

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
#include "apr_thread_mutex.h"
#include "apr_base64.h"

#include <curl/curl.h>

#include "webauth.h"

/* probably need a better place for this constant, and a real version# */
#define WEBKDC_VERSION "WebKDC/3"

/* defines for config directives */

#define CD_Keyring "WebKDCKeyring"
#define CM_Keyring "path to the keyring file"

#define CD_Keytab "WebKDCKeytab"
#define CM_Keytab "path to the K5 keytab file"

#define CD_Debug "WebKDCDebug"
#define CM_Debug "turn debugging on or off"

#define CD_ProxyTokenMaxLifetime "WebKDCProxyTokenMaxLifetime"
#define CM_ProxyTokenMaxLifetime "lifetime of app-tokens"

#define CD_ServiceTokenLifetime "WebKDCServiceTokenLifetime"
#define CM_ServiceTokenLifetime "lifetime of app-tokens"

#define CD_TokenMaxTTL "WebKDCTokenMaxTTL"
#define CM_TokenMaxTTL "max ttl of tokens that are supposed to be \"recent\""
#define DF_TokenMaxTTL 300

/* max number of <token>'s we will return. 64 is overkill */
#define MAX_TOKENS_RETURNED 64

/* max number of <proxyToken>'s we will accept/return in the
   processRequestTokens command. 64 is  overkill */
#define MAX_PROXY_TOKENS_ACCEPTED 64
#define MAX_PROXY_TOKENS_RETURNED 64

/* enum for mutexes */
enum mwk_mutex_type {
    MWK_MUTEX_KEYRING,
    MWK_MUTEX_MAX /* MUST BE LAST! */
};

/* enum for return code */
enum mwk_status {
    MWK_ERROR = 0,
    MWK_OK = 1
};

/* enums for config directives */

enum {
    E_Debug,
    E_Keyring,
    E_Keytab,
    E_ProxyTokenMaxLifetime,
    E_ServiceTokenLifetime,
    E_TokenMaxTTL,
};

module webkdc_module;

/* server conf stuff */
typedef struct {
    char *keyring_path;
    char *keytab_path;
    int  debug;
    int debug_ex;
    int proxy_token_max_lifetime;
    int service_token_lifetime;
    int token_max_ttl; 
    int token_max_ttl_ex;
} MWK_SCONF;

/* handy bunch of bits to pass around during a request */
typedef struct {
    request_rec *r;
    MWK_SCONF *sconf;
    int error_code; /* set if an error happened */
    const char *error_message;
    const char *mwk_func; /* function error occured in */
    int need_to_log; /* set if we need to log error  */
} MWK_REQ_CTXT;

/* interesting stuff from a parsed webkdc-service-token */
typedef struct {
    WEBAUTH_KEY key;
    char *subject;
} MWK_SERVICE_TOKEN;

/* interesting stuff from a parsed webkdc-service-token */
typedef struct {
    char *proxy_type;
    char *proxy_subject;
    char *subject;
    void *proxy_data;
    int proxy_data_len;
    time_t expiration;
} MWK_PROXY_TOKEN;

/* interesting stuff from a parsed login-token */
typedef struct {
    char *username;
    char *password;
} MWK_LOGIN_TOKEN;

/* interesting stuff from a parsed request-token */
typedef struct {
    char *cmd;
    void *app_state;
    int app_state_len;
    char *return_url;
    char *request_reason;
    char *requested_token_type;
    union {
        /* when requested_token_type is 'id' */
        char *subject_auth_type;
        /* when requested_token_type is 'proxy' */
        char *proxy_type;
    } u;
} MWK_REQUEST_TOKEN;

/* used to represent processed <requesterCredential> */
typedef struct {
    char *type; /* krb5|service */
    char *subject; /* always set */
    union {
        /* when type is service */
        MWK_SERVICE_TOKEN st;
    } u;
} MWK_REQUESTER_CREDENTIAL;

/* used to represent <subjectCredential> */
typedef struct {
    char *type; /* proxy|login */
    union {
        struct {
            int num_proxy_tokens;
            MWK_PROXY_TOKEN pt[MAX_PROXY_TOKENS_ACCEPTED];
        } proxy;
        MWK_LOGIN_TOKEN lt;
    } u;
} MWK_SUBJECT_CREDENTIAL;

/* used to represent returned tokens */
typedef struct {
    const char *id;
    const char *token_data;
    const char *session_key; /* might be NULL */
    const char *expires; /* might be NULL */
} MWK_RETURNED_TOKEN;

/* used to represent returned proxy-tokens for 
 * the processRequestTokenResponse.
 */
typedef struct {
    const char *type;
    const char *token_data;
} MWK_RETURNED_PROXY_TOKEN;

/* used to append a bunch of data together */
typedef struct {
    char *data;
    int size;
    int capacity;
    apr_pool_t *pool;
} MWK_STRING;


/* util.c */

/*
 * initialize all our mutexes
 */
void
mwk_init_mutexes(server_rec *s);

/*
 * lock a mutex
 */
void
mwk_lock_mutex(MWK_REQ_CTXT *rc, enum mwk_mutex_type type);

/*
 * unlock a mutex 
 */
void
mwk_unlock_mutex(MWK_REQ_CTXT *rc, enum mwk_mutex_type type);

/*
 * get a string from an attr list, log an error if not present.
 * vlen is optional and can be set to NULL.
 */

char *
mwk_get_str_attr(WEBAUTH_ATTR_LIST *alist, const char *name, 
                 request_rec *r, const char *func, int *vlen);

/*
 * get a WEBAUTH_KRB5_CTXT, log errors
 */
WEBAUTH_KRB5_CTXT *
mwk_get_webauth_krb5_ctxt(request_rec *r, const char *mwk_func);

/*
 * construct a detailed error message
 */

char *
mwk_webauth_error_message(request_rec *r, 
                          int status, 
                          WEBAUTH_KRB5_CTXT *ctxt,
                          const char *webauth_func);

/*
 * log a webauth-related error. ctxt can be NULL.
 */
void
mwk_log_webauth_error(request_rec *r, 
                      int status, 
                      WEBAUTH_KRB5_CTXT *ctxt,
                      const char *mwk_func,
                      const char *func);

/*
 * initialize a string for use with mwk_append_string
 */
void 
mwk_init_string(MWK_STRING *string, apr_pool_t *pool);

/*
 * given an MWK_STRING, append some new data to it.
 */
void 
mwk_append_string(MWK_STRING *string, const char *in_data, int in_size);


#endif
