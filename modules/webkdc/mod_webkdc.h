/*
 * Internal definitions and prototypes for Apache WebKDC module.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2003, 2005, 2006, 2008, 2009, 2011, 2012, 2013, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#ifndef MOD_WEBKDC_H
#define MOD_WEBKDC_H

#include <config-mod.h>
#include <portable/stdbool.h>

#include <httpd.h>
#include <apr_pools.h>
#include <apr_tables.h>
#include <sys/types.h>

#include <webauth/tokens.h>

struct webauth_context;
struct webauth_keyring;

/* defines for config directives */

/* max number of <token>'s we will return. 64 is overkill */
#define MAX_TOKENS_RETURNED 64

/* max number of <proxyToken>'s we will accept/return in the
   processRequestTokens command. 64 is  overkill */
#define MAX_PROXY_TOKENS_ACCEPTED 64
#define MAX_PROXY_TOKENS_RETURNED 64

/* enum for mutexes */
enum mwk_mutex_type {
    MWK_MUTEX_TOKENACL,
    MWK_MUTEX_KEYRING,
    MWK_MUTEX_MAX /* MUST BE LAST! */
};

/* enum for return code */
enum mwk_status {
    MWK_ERROR = 0,
    MWK_OK = 1
};

/* Command table provided by the configuration handling code. */
extern const command_rec webkdc_cmds[];

/*
 * Server configuration.  For parameters where there's no obvious designated
 * value for when the directive hasn't been set, there's a corresponding _set
 * variable that holds whether that directive is set in a particular scope.
 */
struct config {
    const char *fast_armor_path;
    const char *identity_acl_path;
    const char *keyring_path;
    const char *keytab_path;
    const char *keytab_principal;
    const char *token_acl_path;
    struct webauth_user_config *userinfo_config;
    const char *userinfo_principal;
    unsigned long userinfo_timeout;
    bool userinfo_ignore_fail;
    bool userinfo_json;
    bool debug;
    bool keyring_auto_update;
    unsigned long key_lifetime;
    unsigned long login_time_limit;
    unsigned long proxy_lifetime;
    unsigned long service_lifetime;
    unsigned long token_max_ttl;
    apr_array_header_t *local_realms;           /* Array of const char * */
    apr_array_header_t *permitted_realms;       /* Array of const char * */
    apr_array_header_t *kerberos_factors;       /* Array of const char * */

    /* Only used during configuration merging. */
    bool userinfo_timeout_set;
    bool userinfo_ignore_fail_set;
    bool userinfo_json_set;
    bool debug_set;
    bool keyring_auto_update_set;
    bool key_lifetime_set;
    bool login_time_limit_set;
    bool proxy_lifetime_set;
    bool token_max_ttl_set;

    /*
     * These aren't part of the Apache configuration, but they are loaded as
     * part of reading the configuration, are global to the module, and need
     * to be reset when the module is reloaded, so we store them here.
     */
    struct webauth_context *ctx;
    struct webauth_keyring *ring;
};

/* requestInfo */
typedef struct {
    char *local_addr;
    char *local_port;
    char *remote_addr;
    char *remote_port;
    char *remote_user;
} MWK_REQUEST_INFO;

/* interesting stuff from a parsed login-token */
typedef struct {
    const char *username;
    const char *password;
} MWK_LOGIN_TOKEN;

/* used to represent processed <requesterCredential> */
typedef struct {
    const char *type; /* krb5|service */
    const char *subject; /* always set */
    union {
        /* when type is service */
        struct webauth_token_webkdc_service st;
    } u;
} MWK_REQUESTER_CREDENTIAL;

/* used to represent <subjectCredential> */
typedef struct {
    const char *type; /* proxy|login */
    union {
        struct {
            size_t num_proxy_tokens;
            struct webauth_token_webkdc_proxy pt[MAX_PROXY_TOKENS_ACCEPTED];
        } proxy;
        struct webauth_token_login lt;
    } u;
} MWK_SUBJECT_CREDENTIAL;

/* used to represent returned tokens */
typedef struct {
    const char *id;
    const char *token_data;
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
    struct config *sconf;
    struct webauth_context *ctx;
    int error_code; /* set if an error happened */
    const char *error_message;
    const char *mwk_func; /* function error occured in */
    bool need_to_log; /* set if we need to log error  */
} MWK_REQ_CTXT;

BEGIN_DECLS

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


/* config.c */

/* Create a new server configuration, used in the module hooks. */
void *webkdc_config_create(apr_pool_t *, server_rec *s);

/* Merge two server configurations, used in the module hooks. */
void *webkdc_config_merge(apr_pool_t *, void *, void *);

/* Perform final checks on the configuration (called from post_config hook). */
void webkdc_config_init(server_rec *, struct config *, apr_pool_t *);


/* logging.c */

/* Logging functions used as context callbacks for library messages. */
void mwk_log_trace(struct webauth_context *ctx, void *, const char *);
void mwk_log_info(struct webauth_context *ctx, void *, const char *);
void mwk_log_notice(struct webauth_context *ctx, void *, const char *);
void mwk_log_warning(struct webauth_context *ctx, void *, const char *);


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
 * get a WEBAUTH_KRB5_CTXT, log errors
 */
struct webauth_krb5 *
mwk_get_webauth_krb5_ctxt(struct webauth_context *, request_rec *r,
                          const char *mwk_func);

/*
 * construct a detailed error message
 */

char *
mwk_webauth_error_message(struct webauth_context *,
                          request_rec *r,
                          int status,
                          const char *webauth_func,
                          const char *extra);

/*
 * log a webauth-related error.  The Kerberos context can be NULL.
 */
void
mwk_log_webauth_error(struct webauth_context *,
                      server_rec *serv,
                      int status,
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
mwk_cache_keyring(server_rec *serv, struct config *sconf);

#endif
