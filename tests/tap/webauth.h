/*
 * Helper functions for testing WebAuth code.
 *
 * Additional functions that are helpful for testing WebAuth code and have
 * knowledge of WebAuth functions and data structures.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2013, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#ifndef TAP_WEBAUTH_H
#define TAP_WEBAUTH_H 1

#include <config.h>
#include <tests/tap/macros.h>

#include <webauth/tokens.h>     /* struct webauth_token_* */
#include <webauth/webkdc.h>     /* struct webauth_login */

struct kerberos_config;
struct webauth_context;
struct webauth_keyring;

/* Empty tokens, used in building test data. */
#define EMPTY_TOKEN_ID       { NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, 0, 0 }
#define EMPTY_TOKEN_LOGIN    { NULL, NULL, NULL, NULL, NULL, 0 }
#define EMPTY_TOKEN_PROXY    { NULL, NULL, NULL, NULL, NULL, 0, 0, 0 }
#define EMPTY_TOKEN_WKFACTOR { NULL, NULL, 0, 0 }
#define EMPTY_TOKEN_WKPROXY  { NULL, NULL, NULL, NULL, 0, NULL, 0, 0, 0, NULL }

/* Empty webauth_login struct, used in building test data. */
#define EMPTY_LOGIN { NULL, NULL, 0 }

/* Helper macro for a successful login with no message in WebKDC login data. */
#define LOGIN_SUCCESS 0, NULL

/* Helper macro for no factor information in WebKDC login data. */
#define NO_FACTOR_DATA NULL, NULL

/* Helper macro for no authorization identities in WebKDC login data. */
#define NO_AUTHZ_IDS { NULL, NULL, NULL }

/* Helper macros for empty token sets in WebKDC login data. */
#define NO_TOKENS_LOGIN \
    { EMPTY_TOKEN_LOGIN, EMPTY_TOKEN_LOGIN, EMPTY_TOKEN_LOGIN }
#define NO_TOKENS_WKFACTOR \
    { EMPTY_TOKEN_WKFACTOR, EMPTY_TOKEN_WKFACTOR, EMPTY_TOKEN_WKFACTOR }
#define NO_TOKENS_WKPROXY \
    { EMPTY_TOKEN_WKPROXY, EMPTY_TOKEN_WKPROXY, EMPTY_TOKEN_WKPROXY }

/* Helper macro for an empty login history in WebKDC login data. */
#define NO_LOGINS { EMPTY_LOGIN, EMPTY_LOGIN, EMPTY_LOGIN }

/*
 * All of the following structs for test token data are paralle to the regular
 * webauth_token_* definitions except that they may omit some data that must
 * be constructed at runtime and have special handling for some fields.
 *
 * All identity strings plus the login password field support the following
 * special tokens, which are replaced with information from the Kerberos
 * configuration:
 *
 *     <principal>              Keytab principal
 *     <krb5-principal>         Keytab principal prefixed with "krb5:"
 *     <webkdc-principal>       Keytab principal prefixed with "WEBKDC:krb5:"
 *     <userprinc>              User principal
 *     <username>               User principal without the realm
 *     <password>               User password
 *
 * For creation and expiration if the value is < 10000 and > 0, it is taken as
 * a *negative* offset from now for creation and a *positive* offset from now
 * for expiration.  If creation is 0, check that the creation is somewhere
 * around the current time.  If expiration is 0, check to ensure that it's in
 * the future but otherwise don't be picky.
 */

/*
 * Data for an id token.  Authentication data may be generated or checked on
 * the fly if the auth type is krb5.
 */
struct wat_token_id {
    const char *subject;
    const char *authz_subject;
    const char *auth;
    const void *auth_data;
    size_t auth_data_len;
    const char *initial_factors;
    const char *session_factors;
    unsigned long loa;
    time_t creation;
    time_t expiration;
};

/* Data for a login token. */
struct wat_token_login {
    const char *username;
    const char *password;
    const char *otp;
    const char *otp_type;
    const char *device_id;
    time_t creation;
};

/*
 * Data for proxy token.  The webkdc_proxy field of a regular proxy token
 * struct is handled specially.
 */
struct wat_token_proxy {
    const char *subject;
    const char *authz_subject;
    const char *type;
    const char *initial_factors;
    const char *session_factors;
    unsigned long loa;
    time_t creation;
    time_t expiration;
};

/*
 * Data for a webkdc-proxy token.  Proxy data may be generated or checked on
 * the fly if the proxy_type is krb5.
 */
struct wat_token_webkdc_proxy {
    const char *subject;
    const char *proxy_type;
    const char *proxy_subject;
    const void *data;
    size_t data_len;
    const char *initial_factors;
    unsigned long loa;
    time_t creation;
    time_t expiration;

    /* Not included in the wire representation. */
    const char *session_factors;
};

/*
 * Data for a test service token.  Omit the session key, which we generate on
 * the fly while constructing the test.
 */
struct wat_token_webkdc_service {
    const char *subject;
    time_t creation;
    time_t expiration;
};

/*
 * Test data for a WebKDC login request (<requestTokensRequest>).  This is in
 * a different form than the internal struct so that it can be statically
 * initialized when building test cases and so that it doesn't contain
 * encrypted tokens that will vary with each run.
 */
struct wat_login_request {
    struct wat_token_webkdc_service service;

    /* Authentication tokens. */
    struct wat_token_login logins[3];
    struct wat_token_webkdc_proxy wkproxies[3];
    struct webauth_token_webkdc_factor wkfactors[3];

    /* Requested authorization subject. */
    const char *authz_subject;

    /* Authentication request from the WAS. */
    struct webauth_token_request request;
};

/*
 * Expected data for a WebKDC login response (<requestTokensResponse>).  This
 * includes only the data that can't be trivially derived from the request or
 * from other parts of the response, and is structured differently from the
 * normal internal data structure so that it can be statically initialized and
 * doesn't contain encrypted tokens that will vary with each run.
 */
struct wat_login_response {
    const char *user_message;
    const char *login_state;

    /* Represented as strings of comma-separated factors. */
    const char *factors_wanted;
    const char *factors_configured;

    /* Single sign-on tokens and user identity. */
    struct wat_token_webkdc_proxy proxies[3];
    struct webauth_token_webkdc_factor factor_token;

    /* Only one of result_id or result_proxy will be set. */
    struct wat_token_id result_id;
    struct wat_token_proxy result_proxy;

    /* User information service information from logins. */
    struct webauth_login logins[3];
    time_t password_expires;

    /* Permitted authorization identities. */
    const char *permitted_authz[3];
};

/* Data for a single WebKDC login test case. */
struct wat_login_test {
    const char *name;
    int status;
    const char *error;
    struct wat_login_request request;
    struct wat_login_response response;
};

BEGIN_DECLS

/* Compare two tokens of various types. */
void is_token_error(const struct webauth_token_error *wanted,
                    const struct webauth_token_error *seen,
                    const char *format, ...)
    __attribute__((__format__(printf, 3, 4)));
void is_token_id(const struct webauth_token_id *wanted,
                 const struct webauth_token_id *seen,
                 const char *format, ...)
    __attribute__((__format__(printf, 3, 4)));
void is_token_proxy(const struct webauth_token_proxy *wanted,
                    const struct webauth_token_proxy *seen,
                    const char *format, ...)
    __attribute__((__format__(printf, 3, 4)));
void is_token_webkdc_factor(const struct webauth_token_webkdc_factor *wanted,
                            const struct webauth_token_webkdc_factor *seen,
                            const char *format, ...)
    __attribute__((__format__(printf, 3, 4)));
void is_token_webkdc_proxy(const struct webauth_token_webkdc_proxy *wanted,
                           const struct webauth_token_webkdc_proxy *seen,
                           const char *format, ...)
    __attribute__((__format__(printf, 3, 4)));

/*
 * Run a test of the WebKDC login handling.  Takes the WebAuth context in
 * which to run the tests, the test case description, and the keyring to use
 * for the WebKDC.
 */
void run_login_test(struct webauth_context *, const struct wat_login_test *,
                    const struct webauth_keyring *,
                    const struct kerberos_config *)
    __attribute__((__nonnull__(1, 2, 3)));

END_DECLS

#endif /* !TAP_WEBAUTH_H */
