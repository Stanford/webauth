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

/* max number of <token>'s we will return. 128 is probably overkill */
#define MAX_TOKENS_RETURNED 128

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

/* used to represent <requesterCredential> */
typedef struct {
    char *type; /* krb5|service */
    char *subject; /* always set */
    union {
        /* when type is service */
        struct {
            MWK_SERVICE_TOKEN st;
            char *cmd; /* cmd from request-token */
        } service;
    } u;
} MWK_REQUESTER_CREDENTIAL;

/* used to represent <subjectCredential> */
typedef struct {
    char *type; /* proxy */
    union {
        MWK_PROXY_TOKEN pt; /* when type is proxy */
    } u;
} MWK_SUBJECT_CREDENTIAL;

/* used to represent returned tokens */
typedef struct {
    const char *id;
    const char *token_data;
    const char *session_key; /* might be NULL */
    const char *expires; /* might be NULL */
} MWK_RETURNED_TOKEN;

/* used to append a bunch of data together */
typedef struct {
    char *data;
    int size;
    int capacity;
    apr_pool_t *pool;
} MWK_STRING;

/* util.c */

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

/*
 * concat all the text pieces together and return data
 */
const char *
mwk_get_elem_text(MWK_REQ_CTXT *rc, apr_xml_elem *e, const char *def);

#endif
