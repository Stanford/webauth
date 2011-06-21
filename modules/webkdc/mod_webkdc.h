/*
 * Internal definitions and prototypes for Apache WebKDC module.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2003, 2005, 2006, 2008, 2009, 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#ifndef MOD_WEBKDC_H
#define MOD_WEBKDC_H

#include <modules/mod-config.h>

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
#include "unixd.h"
#include "ap_config_auto.h"

#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if HAVE_INTTYPES_H
# include <inttypes.h>
#elif HAVE_STDINT_H
# include <stdint.h>
#endif
#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <webauth.h>

/* defines for config directives */

#define CD_Keyring "WebKdcKeyring"
#define CM_Keyring "path to the keyring file"

#define CD_KeyringKeyLifetime "WebKdcKeyringKeyLifetime"
#define CM_KeyringKeyLifetime "lifetime of keys we create"
#define DF_KeyringKeyLifetime (60*60*24*30) /* 30 days */

#define CD_KeyringAutoUpdate "WebKdcKeyringAutoUpdate"
#define CM_KeyringAutoUpdate "whether or not to automatically update keyring"
#define DF_KeyringAutoUpdate 1

#define CD_TokenAcl "WebKdcTokenAcl"
#define CM_TokenAcl "path to the token acl file"

#define CD_Keytab "WebKdcKeytab"
#define CM_Keytab "path to the K5 keytab file"

#define CD_Debug "WebKdcDebug"
#define CM_Debug "turn debugging on or off"

#define CD_ProxyTokenLifetime "WebKdcProxyTokenLifetime"
#define CM_ProxyTokenLifetime "lifetime of webdc-proxy-tokens"
#define DF_ProxyTokenLifetime 0

#define CD_ServiceTokenLifetime "WebKdcServiceTokenLifetime"
#define CM_ServiceTokenLifetime "lifetime of webkdc-service-tokens"

#define CD_TokenMaxTTL "WebKdcTokenMaxTTL"
#define CM_TokenMaxTTL "max ttl of tokens that are supposed to be \"recent\""
#define DF_TokenMaxTTL (60*5)

#define CD_PermittedRealms "WebKdcPermittedRealms"
#define CM_PermittedRealms "list of realms permited for authentication"

#define CD_LocalRealms "WebKdcLocalRealms"
#define CM_LocalRealms "realms stripped from identities, \"none\" or \"local\""

/* max number of <token>'s we will return. 64 is overkill */
#define MAX_TOKENS_RETURNED 64

/* max number of <proxyToken>'s we will accept/return in the
   processRequestTokens command. 64 is  overkill */
#define MAX_PROXY_TOKENS_ACCEPTED 64
#define MAX_PROXY_TOKENS_RETURNED 64

/* enum for mutexes */
enum mwk_mutex_type {
    MWK_MUTEX_TOKENACL,
    MWK_MUTEX_MAX /* MUST BE LAST! */
};

/* enum for return code */
enum mwk_status {
    MWK_ERROR = 0,
    MWK_OK = 1
};

/* enums for config directives */

enum {
    E_TokenAcl,
    E_Debug,
    E_Keyring,
    E_KeyringAutoUpdate,
    E_KeyringKeyLifetime,
    E_Keytab,
    E_ProxyTokenLifetime,
    E_ServiceTokenLifetime,
    E_TokenMaxTTL,
    E_PermittedRealms,
    E_LocalRealms,
};

extern module webkdc_module;

/* server conf stuff */
typedef struct {
    char *keyring_path;
    char *keytab_path;
    char *keytab_principal;
    char *token_acl_path;
    int debug;
    int debug_ex;
    int proxy_token_lifetime;
    int proxy_token_lifetime_ex;
    int service_token_lifetime;
    int token_max_ttl;
    int token_max_ttl_ex;
    int keyring_auto_update;
    int keyring_auto_update_ex;
    int keyring_key_lifetime;
    int keyring_key_lifetime_ex;
    apr_array_header_t *permitted_realms;
    apr_array_header_t *local_realms;
    /* stuff we need to clean up on restarts and what not */
    WEBAUTH_KEYRING *ring; /* our keyring */
    int free_ring;         /* set if we should free ring */
} MWK_SCONF;

/* requestInfo */
typedef struct {
    char *local_addr;
    char *local_port;
    char *remote_addr;
    char *remote_port;
    char *remote_user;
} MWK_REQUEST_INFO;

/* interesting stuff from a parsed webkdc-service-token */
typedef struct {
    WEBAUTH_KEY key;
    char *subject;
} MWK_SERVICE_TOKEN;

/* interesting stuff from a parsed webkdc-proxy-token */
typedef struct {
    const char *proxy_type;
    char *proxy_subject;
    const char *subject;
    void *proxy_data;
    size_t proxy_data_len;
    time_t expiration;
    time_t creation;
    const char *factors;
    uint32_t loa;
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
    size_t app_state_len;
    char *return_url;
    const char *request_options;
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
    const char *type; /* proxy|login */
    union {
        struct {
            size_t num_proxy_tokens;
            MWK_PROXY_TOKEN pt[MAX_PROXY_TOKENS_ACCEPTED];
        } proxy;
        MWK_LOGIN_TOKEN lt;
    } u;
} MWK_SUBJECT_CREDENTIAL;

/* used to represent returned tokens */
typedef struct {
    const char *id;
    char *token_data;
    char *session_key; /* might be NULL */
    const char *expires; /* might be NULL */
    const char *subject; /* used only for logging */
    const char *info; /* used only for logging */
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
    size_t size;
    size_t capacity;
    apr_pool_t *pool;
} MWK_STRING;

/* handy bunch of bits to pass around during a request */
typedef struct {
    request_rec *r;
    MWK_SCONF *sconf;
    int error_code; /* set if an error happened */
    const char *error_message;
    const char *mwk_func; /* function error occured in */
    int need_to_log; /* set if we need to log error  */
} MWK_REQ_CTXT;

/* acl.c */

int
mwk_can_use_proxy_token(MWK_REQ_CTXT *rc,
                        const char *subject,
                        const char *proxy_subject);


int
mwk_has_service_access(MWK_REQ_CTXT *rc,
                       const char *subject);

int
mwk_has_id_access(MWK_REQ_CTXT *rc,
                  const char *subject);

int
mwk_has_proxy_access(MWK_REQ_CTXT *rc,
                     const char *subject,
                     const char *proxy_type);

int
mwk_has_cred_access(MWK_REQ_CTXT *rc,
                    const char *subject,
                    const char *cred_type,
                    const char *cred);

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
                 request_rec *r, const char *func, size_t *vlen);

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
                          const char *webauth_func,
                          const char *extra);

/*
 * log a webauth-related error. ctxt can be NULL.
 */
void
mwk_log_webauth_error(server_rec *serv,
                      int status,
                      WEBAUTH_KRB5_CTXT *ctxt,
                      const char *mwk_func,
                      const char *func,
                      const char *extra);

/*
 * initialize a string for use with mwk_append_string
 */
void
mwk_init_string(MWK_STRING *string, apr_pool_t *pool);

/*
 * given an MWK_STRING, append some new data to it.
 */
void
mwk_append_string(MWK_STRING *string, const char *in_data, size_t in_size);

int
mwk_cache_keyring(server_rec *serv, MWK_SCONF *sconf);

#endif
