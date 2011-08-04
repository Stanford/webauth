/*
 * WebAuth functions specific to WebKDC services.
 *
 * These interfaces provide the building blocks of the WebKDC functionality.
 * They're normally only used inside the mod_webkdc module, but are provided
 * in the shared library for ease of testing and custom development.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef WEBAUTH_WEBKDC_H
#define WEBAUTH_WEBKDC_H 1

#include <webauth/defines.h>

#include <sys/types.h>

#include <webauth.h>

struct webauth_context;

/*
 * General configuration information for the WebKDC functions.  The WebKDC
 * Apache module gets this information from the Apache configuration and then
 * passes it into the library via webauth_webkdc_config.
 */
struct webauth_webkdc_config {
    const char *keytab_path;    /* Path to WebKDC's Kerberos keytab. */
    const char *principal;      /* WebKDC's Kerberos principal. */
    time_t proxy_lifetime;      /* Maximum webkdc-proxy token lifetime (s). */
    WA_APR_ARRAY_HEADER_T *permitted_realms; /* Array of char * realms. */
    WA_APR_ARRAY_HEADER_T *local_realms;     /* Array of char * realms. */
};

/*
 * Holds an encoded webkdc-proxy token along with some additional metadata
 * about it that may be needed by consumers who can't decode the token (or
 * don't want to).
 */
struct webauth_webkdc_proxy_data {
    const char *type;
    const char *token;
};

/*
 * Input for a <requestTokenRequest>, which is sent from the WebLogin server
 * to the WebKDC and represents a request by a user to authenticate to a WAS.
 * This request may contain webkdc-proxy tokens, representing existing single
 * sign-on credentials, and a login token, representing a username and
 * authentication credential provided by the user in this session.
 */
struct webauth_webkdc_login_request {
    struct webauth_token_webkdc_service *service;
    WA_APR_ARRAY_HEADER_T *creds;       /* Array of webauth_token pointers. */
    struct webauth_token_request *request;
    const char *remote_user;
    const char *local_ip;
    const char *local_port;
    const char *remote_ip;
    const char *remote_port;
};

/*
 * Result from a <requestTokenResponse>, which is sent by the WebKDC back to
 * the WebLogin server containing the results of an authentication request.
 * It was successful if the login_error is 0.
 */
struct webauth_webkdc_login_response {
    int login_error;
    const char *login_message;
    WA_APR_ARRAY_HEADER_T *factors_wanted;     /* Array of char * factors. */
    WA_APR_ARRAY_HEADER_T *factors_configured; /* Array of char * factors. */
    WA_APR_ARRAY_HEADER_T *proxies; /* Array of webkdc_proxy_data structs. */
    const char *return_url;
    const char *requester;
    const char *subject;
    const char *result;         /* Encrypted id or cred token. */
    const char *result_type;    /* Type of result token as a string. */
    const char *login_cancel;   /* Encrypted error token. */
    const void *app_state;
    size_t app_state_len;
    WA_APR_ARRAY_HEADER_T *logins;      /* Array of struct webauth_login. */
};    

/*
 * Supported protocols for contacting the user metadata and multifactor
 * authentication services.  Currently, only remctl is supported.
 */
enum webauth_user_protocol {
    WA_PROTOCOL_NONE   = 0,
    WA_PROTOCOL_REMCTL = 1
};

/*
 * Configuration information for the user metadata service.  This is used to
 * bundle together the configuration parameters and pass them into
 * webauth_user_config.  The port may be 0, which indicates the standard port
 * should be used.  identity is the identity of the metadata service for
 * authentication purposes and may be NULL to use the default.  command is
 * protocol-specific command information, such as a partial URL or a remctl
 * command.
 */
struct webauth_user_config {
    enum webauth_user_protocol protocol;
    const char *host;
    unsigned short port;        /* May be 0 to use the standard port. */
    const char *identity;       /* Metadata service identity (may be NULL). */
    const char *command;        /* Protocol-specific command. */
};

/*
 * Stores a single suspicious or questionable login, or a login that for some
 * other reason the user should be notified about.  Returned in an APR array
 * in the webauth_userinfo struct.
 */
struct webauth_login {
    const char *ip;
    const char *hostname;
    time_t timestamp;
};

/*
 * The webauth_user_info struct and its supporting data structures stores
 * metadata about a user, returned from the site-local user management
 * middleware.
 */
struct webauth_user_info {
    WA_APR_ARRAY_HEADER_T *factors;     /* Array of char * factor codes. */
    int multifactor_required;           /* Whether multifactor is forced. */
    unsigned long max_loa;              /* Maximum level of assurance. */
    time_t password_expires;            /* Password expiration time or 0. */
    WA_APR_ARRAY_HEADER_T *logins;      /* Array of struct webauth_login. */
};

/*
 * The webauth_user_validate struct is very similar to webauth_user_info, but
 * is returned after an attempted OTP validation.  It contains the result of
 * that validation, the factors configured, login history if any, and the LoA
 * of the authentication were it successful.
 */
struct webauth_user_validate {
    int success;                        /* Whether the validation succeeded. */
    WA_APR_ARRAY_HEADER_T *factors;     /* Array of char * factor codes. */
    unsigned long loa;                  /* Level of assurance. */
};

BEGIN_DECLS

/*
 * Configure how to access the user metadata service.  Takes the context and
 * the configuration information.  The configuration information is stored in
 * the WebAuth context and used for all subsequent webauth_userinfo queries.
 * Returns a status code, which will be WA_ERR_NONE unless invalid parameters
 * were passed.
 */
int webauth_user_config(struct webauth_context *, struct webauth_user_config *)
    __attribute__((__nonnull__));

/*
 * Obtain user information for a given user.  The IP address of the user (as a
 * string) is also provided.  The timestamp of the query is assumed to be the
 * current time.  The final flag indicates whether a site requested random
 * multifactor and asks the user metadata service to calculate whether
 * multifactor is forced based on that random multifactor chance.
 *
 * webauth_user_config generally must be called before this function.
 * Depending on the method used, authentication credentials may also need to
 * be set up before calling this function.
 *
 * On success, sets the info parameter to a new webauth_user_info struct
 * allocated from pool memory and returns WA_ERR_NONE.  On failure, returns an
 * error code and sets the info parameter to NULL.
 */
int webauth_user_info(struct webauth_context *, const char *user,
                      const char *ip, int, struct webauth_user_info **)
    __attribute__((__nonnull__));

/*
 * Validate an authentication code for a given user (generally an OTP code).
 * The IP address (as a string) is also provided.  The timestamp of the query
 * is sent to the remote server and assumed to be the current time.
 *
 * webauth_user_config must be called before this function.  Depending on the
 * method used, authentication credentials may also need to be set up before
 * calling this function.
 *
 * On success, sets the info parameter to a new webauth_user_info struct
 * allocated from pool memory and returns WA_ERR_NONE.  On failure, returns an
 * error code and sets the info parameter to NULL.  Note that success only
 * means that the call completed, not that the validation was successful.
 */
int webauth_user_validate(struct webauth_context *, const char *user,
                          const char *code, struct webauth_user_validate **)
    __attribute__((__nonnull__));

/*
 * Configure the WebKDC services.  Takes the context and the configuration
 * information.  The configuration information is stored in the WebAuth
 * context and is used for all subsequent webauth_webkdc functions.  Returns a
 * status code, which will be WA_ERR_NONE unless invalid parameters were
 * passed.
 */
int webauth_webkdc_config(struct webauth_context *,
                          struct webauth_webkdc_config *)
    __attribute__((__nonnull__));

/*
 * Given the data from a <requestTokenRequest> login attempt, process that
 * attempted login and return the information for a <requestTokenResponse> in
 * a newly-allocated struct from pool memory.  All of the tokens included in
 * the input and output are the unencrypted struct representations; the caller
 * does the encryption or decryption and base64 conversion.
 *
 * Returns WA_ERR_NONE if the request was successfully processed, which
 * doesn't mean it succeeded; see the login_code attribute of the struct for
 * that.  Returns an error code if we were unable to process the struct even
 * to generate an error response.
 */
int webauth_webkdc_login(struct webauth_context *,
                         struct webauth_webkdc_login_request *,
                         struct webauth_webkdc_login_response **,
                         WEBAUTH_KEYRING *keyring)
    __attribute__((__nonnull__));

END_DECLS

#endif /* !WEBAUTH_WEBKDC_H */
