/*
 * Helper functions for testing WebAuth code.
 *
 * Additional functions that are helpful for testing WebAuth code and have
 * knowledge of WebAuth functions and data structures.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2013
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

struct webauth_context;
struct webauth_keyring;

/* Empty tokens, used in building test data. */
#define EMPTY_TOKEN_ID       { NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, 0, 0 }
#define EMPTY_TOKEN_LOGIN    { NULL, NULL, NULL, NULL, 0 }
#define EMPTY_TOKEN_PROXY    { NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, 0, 0 }
#define EMPTY_TOKEN_WKFACTOR { NULL, NULL, 0, 0 }
#define EMPTY_TOKEN_WKPROXY  { NULL, NULL, NULL, NULL, 0, NULL, 0, 0, 0, NULL }

/* Empty webauth_login struct, used in building test data. */
#define EMPTY_LOGIN { NULL, NULL, 0 }

/*
 * Data for a test service token.  We want to generate the key on the fly, so
 * to build a test case we use the following data instead of the full
 * webkdc-service token data and then build the rest when running the test.
 *
 * If expiration < 1000, it is taken as a positive offset from the current
 * time.
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
    struct webauth_token_login logins[3];
    struct webauth_token_webkdc_proxy wkproxies[3];
    struct webauth_token_webkdc_factor wkfactors[3];

    /* Requested authorization subject. */
    const char *authz_subject;

    /* Authentication request from the WAS. */
    struct webauth_token_request request;

    /* Login client information. */
    const char *remote_user;
    const char *local_ip;
    const char *local_port;
    const char *remote_ip;
    const char *remote_port;
};

/*
 * Expected data for a WebKDC login response (<requestTokensResponse>).  This
 * includes only the data that can't be trivially derived from the request or
 * from other parts of the response, and is structured differently from the
 * normal internal data structure so that it can be statically initialized and
 * doesn't contain encrypted tokens that will vary with each run.
 */
struct wat_login_response {
    int login_error;
    const char *login_message;
    const char *user_message;

    /* Represented as strings of comma-separated factors. */
    const char *factors_wanted;
    const char *factors_configured;

    /* Single sign-on tokens and user identity. */
    struct webauth_token_webkdc_proxy proxies[3];
    struct webauth_token_webkdc_factor factor_token;

    /* Only one of result_id or result_proxy will be set. */
    struct webauth_token_id result_id;
    struct webauth_token_proxy result_proxy;

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
                    const struct webauth_keyring *)
    __attribute__((__nonnull__));

END_DECLS

#endif /* !TAP_WEBAUTH_H */
