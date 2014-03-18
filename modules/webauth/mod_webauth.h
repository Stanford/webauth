/*
 * Internal definitions and prototypes for Apache WebAuth module.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2003, 2006, 2008, 2009, 2010, 2011, 2012, 2013, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#ifndef MOD_WEBAUTH_H
#define MOD_WEBAUTH_H

#include <config-mod.h>
#include <portable/stdbool.h>

#include <apr_pools.h>          /* apr_pool_t */
#include <apr_tables.h>         /* apr_array_header_t */
#include <httpd.h>              /* server_rec and request_rec */
#include <sys/types.h>          /* size_t, etc. */

#include <webauth/keys.h>
#include <webauth/tokens.h>

/* Command table provided by the configuration handling code. */
extern const command_rec webauth_cmds[];

/* how long to wait between trying for a new token when
 * a renewal attempt fails
 */
#define TOKEN_RETRY_INTERVAL 600

/*
 * how long into the tokens lifetime do we attempt our first revnewal
 */
#define START_RENEWAL_ATTEMPT_PERCENT (0.90)

/* where to look in URL for returned tokens */
#define WEBAUTHR_MAGIC "?WEBAUTHR="
#define WEBAUTHR_MAGIC_LEN (sizeof(WEBAUTHR_MAGIC) - 1)

#define WEBAUTHS_MAGIC ";WEBAUTHS="
#define WEBAUTHS_MAGIC_LEN (sizeof(WEBAUTHS_MAGIC) - 1)

/* environment variables to set */
#define ENV_WEBAUTH_USER "WEBAUTH_USER"
#define ENV_WEBAUTH_AUTHZ_USER "WEBAUTH_AUTHZ_USER"
#define ENV_WEBAUTH_TOKEN_CREATION "WEBAUTH_TOKEN_CREATION"
#define ENV_WEBAUTH_TOKEN_EXPIRATION "WEBAUTH_TOKEN_EXPIRATION"
#define ENV_WEBAUTH_TOKEN_LASTUSED "WEBAUTH_TOKEN_LASTUSED"
#define ENV_WEBAUTH_FACTORS_INITIAL "WEBAUTH_FACTORS_INITIAL"
#define ENV_WEBAUTH_FACTORS_SESSION "WEBAUTH_FACTORS_SESSION"
#define ENV_WEBAUTH_LOA "WEBAUTH_LOA"
#define ENV_KRB5CCNAME "KRB5CCNAME"

/* r->notes keys */
#define N_WEBAUTHR      "mod_webauth_WEBAUTHR"
#define N_WEBAUTHS      "mod_webauth_WEBAUTHS"
#define N_SUBJECT       "mod_webauth_SUBJECT"
#define N_AUTHZ_SUBJECT "mod_webauth_AUTHZ"


/* a service token and associated data, all memory (including key)
 * is allocated from a pool
 */
typedef struct {
    apr_pool_t *pool; /* pool this token belongs to */
    struct webauth_key key;
    time_t expires;
    char *token;
    time_t created; /* when we first obtained this token */
    time_t next_renewal_attempt; /* next time we try to renew */
    time_t last_renewal_attempt; /* time we last tried to renew */
    const void *app_state; /* used as "as" attribute in request tokens */
    size_t app_state_len;
} MWA_SERVICE_TOKEN;

/*
 * Server configuration.  For parameters where there's no obvious designated
 * value for when the directive hasn't been set, there's a corresponding _set
 * variable that holds whether that directive is set in a particular scope.
 */
struct server_config {
    const char *auth_type;
    const char *cred_cache_dir;
    bool debug;
    bool extra_redirect;
    bool httponly;
    bool keyring_auto_update;
    unsigned long keyring_key_lifetime;
    const char *keyring_path;
    const char *keytab_path;
    const char *keytab_principal;
    const char *login_url;
    bool require_ssl;
    const char *st_cache_path;
    bool ssl_redirect;
    unsigned long ssl_redirect_port;
    bool strip_url;
    const char *subject_auth_type;
    unsigned long token_max_ttl;
    bool trust_authz_identity;
    bool webkdc_cert_check;
    const char *webkdc_cert_file;
    const char *webkdc_principal;
    const char *webkdc_url;

    /* Only used during configuration merging. */
    bool debug_set;
    bool extra_redirect_set;
    bool httponly_set;
    bool keyring_auto_update_set;
    bool keyring_key_lifetime_set;
    bool require_ssl_set;
    bool ssl_redirect_set;
    bool ssl_redirect_port_set;
    bool strip_url_set;
    bool subject_auth_type_set;
    bool token_max_ttl_set;
    bool trust_authz_identity_set;
    bool webkdc_cert_check_set;

    /*
     * These aren't part of the Apache configuration, but they are loaded as
     * part of reading the configuration, are global to the module, and need
     * to be reset when the module is reloaded, so we store them here.
     */
    struct webauth_context *ctx;
    struct webauth_keyring *ring;
    MWA_SERVICE_TOKEN *service_token;

    /* Mutex to hold when modifying the server configuration. */
    apr_thread_mutex_t *mutex;
};

/* The same, but for the directory configuration. */
struct dir_config {
    unsigned long app_token_lifetime;
    const char *cookie_path;
    bool do_logout;
    bool dont_cache;
    bool extra_redirect;
    const char *failure_url;
    bool force_login;
    unsigned long inactive_expire;
    unsigned long last_use_update_interval;
    unsigned long loa;
    const char *login_canceled_url;
    bool optional;
    const char *post_return_url;
    const char *return_url;
    bool ssl_return;
    bool trust_authz_identity;
    bool use_creds;
    const char *var_prefix;
    apr_array_header_t *creds;           /* Array of MWA_WACRED */
    apr_array_header_t *initial_factors; /* Array of const char * */
    apr_array_header_t *session_factors; /* Array of const char * */

#ifndef NO_STANFORD_SUPPORT
    char *su_authgroups;
#endif

    /* Only used during configuration merging. */
    bool do_logout_set;
    bool dont_cache_set;
    bool extra_redirect_set;
    bool force_login_set;
    bool loa_set;
    bool optional_set;
    bool ssl_return_set;
    bool trust_authz_identity_set;
    bool use_creds_set;
};

/* a cred, used to keep track of WebAuthCred directives. */
typedef struct {
    char *type;
    char *service;
} MWA_WACRED;

/* handy bunch of bits to pass around during a request */
typedef struct {
    request_rec *r;
    struct server_config *sconf;
    struct dir_config *dconf;
    struct webauth_context *ctx;
    struct webauth_token_app *at;
    char *needed_proxy_type; /* set if we are redirecting for a proxy-token */
    struct webauth_token_proxy *pt; /* proxy-token that came from URL */
    apr_array_header_t *cred_tokens; /* cred token(s) */
} MWA_REQ_CTXT;

/* used to append a bunch of data together */
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
    apr_pool_t *pool;
} MWA_STRING;

/* structure that defines the proxy/credential interface */
typedef struct {
    /* proxy/cred type (i.e., "krb5") */
    const char *type;

    /* function to validate subject-authenticator-data */
    const char *(*validate_sad) (MWA_REQ_CTXT *rc,
                                 const void *sad,
                                 size_t sad_len);

    /* function to run through all the cred tokens and prepare any
       cred tokens that are the same as our type for use by CGI */
    int (*prepare_creds)(MWA_REQ_CTXT *rc, apr_array_header_t *creds);

    /* get the base64'd blob that we would send to the WebKDC
       in the <requesterCredential> element. */
    const char *(*webkdc_credential)(struct webauth_context *ctx,
                                     server_rec *server,
                                     struct server_config *sconf,
                                     apr_pool_t *pool);

} MWA_CRED_INTERFACE;


/* config.c */

/* Create a new server or directory configuration, used in the module hooks. */
void *mwa_dir_config_create(apr_pool_t *, char *path);
void *mwa_server_config_create(apr_pool_t *, server_rec *s);

/* Merge two server or directory configurations, used in the module hooks. */
void *mwa_dir_config_merge(apr_pool_t *, void *, void *);
void *mwa_server_config_merge(apr_pool_t *, void *, void *);

/* Perform final checks on the configuration (called from post_config hook). */
void mwa_config_init(server_rec *, struct server_config *, apr_pool_t *);


/* webkdc.c */

MWA_SERVICE_TOKEN *
mwa_get_service_token(server_rec *server,
                      struct server_config *sconf, apr_pool_t *pool,
                      int local_cache_only);


int
mwa_get_creds_from_webkdc(MWA_REQ_CTXT *rc,
                          struct webauth_token_proxy *pt,
                          apr_array_header_t *needed_creds,
                          apr_array_header_t **acquired_creds);

/* util.c */

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
 * set note in main request. the prefix should be a string constant. the
 * full key for the note is constructed by concatenating the prefix with
 * the name, if the latter is not null. the value of the note is specified
 * by a format string and subsequent argument list. key (if necessary)
 * and value strings are created in the topmost request's pool.
 */
void
mwa_setn_note(request_rec *r,
              const char *prefix,
              const char *name,
              const char *valfmt,
              ...);

/*
 * log interesting stuff from the request
 */
void
mwa_log_request(request_rec *r, const char *msg);

/*
 * log a webauth-related error
 */
void
mwa_log_webauth_error(MWA_REQ_CTXT *rc, int status, const char *mwa_func,
                      const char *func, const char *extra);

/*
 * this should only be called in the ensure_keyring_loaded routine
 */
int
mwa_cache_keyring(server_rec *serv, struct server_config *sconf);

/*
 * get all cookies that start with webauth_
 */
apr_array_header_t *
mwa_get_webauth_cookies(request_rec *r);

/*
 * parse a cred token. If key is non-null use it, otherwise
 * if ring is non-null use it, otherwise log an error and return NULL.
 */
struct webauth_token_cred *
mwa_parse_cred_token(char *token,
                     struct webauth_keyring *ring,
                     struct webauth_key *key,
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
                            struct server_config *sconf,
                            apr_pool_t *pool,
                            MWA_CRED_INTERFACE *interface);

MWA_CRED_INTERFACE *
mwa_find_cred_interface(server_rec *server,
                        const char *type);

/* krb5.c */
extern MWA_CRED_INTERFACE *mwa_krb5_cred_interface;

#endif
