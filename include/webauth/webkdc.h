/*
 * WebAuth functions specific to WebKDC services.
 *
 * These interfaces provide the building blocks of the WebKDC functionality.
 * They're normally only used inside the mod_webkdc module, but are provided
 * in the shared library for ease of testing and custom development.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2011, 2012, 2013, 2014
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

struct webauth_context;
struct webauth_factors;
struct webauth_keyring;

/*
 * General configuration information for the WebKDC functions.  The WebKDC
 * Apache module gets this information from the Apache configuration and then
 * passes it into the library via webauth_webkdc_config.
 */
struct webauth_webkdc_config {
    const char *keytab_path;    /* Path to WebKDC's Kerberos keytab. */
    const char *id_acl_path;    /* Path to WebKDC's identity ACL file. */
    const char *principal;      /* WebKDC's Kerberos principal. */
    time_t proxy_lifetime;      /* Maximum webkdc-proxy token lifetime (s). */
    time_t login_time_limit;    /* Time limit for completing login process. */
    const char *fast_armor_path;        /* Path to cache for FAST armor. */
    const WA_APR_ARRAY_HEADER_T *permitted_realms; /* Array of char * realms */
    const WA_APR_ARRAY_HEADER_T *local_realms;     /* Array of char * realms */
};

/*
 * Holds an encoded webkdc-factor token along with some additional metadata
 * about it that may be needed by consumers who can't decode the token (or
 * don't want to).
 */
struct webauth_webkdc_factor_data {
    time_t expiration;
    const char *token;
};

/*
 * Holds an encoded webkdc-proxy token along with some additional metadata
 * about it that may be needed by consumers who can't decode the token (or
 * don't want to), or that allows the WebLogin server to tell the WebKDC the
 * source of the token (for session factors).
 */
struct webauth_webkdc_proxy_data {
    const char *type;
    const char *token;
    const char *source;
};

/*
 * Input for a <requestTokenRequest>, which is sent from the WebLogin server
 * to the WebKDC and represents a request by a user to authenticate to a WAS.
 * All of the tokens are still encrypted strings.
 *
 * This request may contain webkdc-proxy tokens, representing existing single
 * sign-on credentials, webkdc-factor tokens, representing persistent factors,
 * and login tokens, representing a username and authentication credential
 * provided by the user in this session.
 */
struct webauth_webkdc_login_request {
    const char *service;        /* webkdc-service token for requester. */
    const char *authz_subject;  /* Requested authorization identity. */
    const char *login_state;    /* Opaque object for multifactor. */

    /* User credentials. */
    const WA_APR_ARRAY_HEADER_T *wkproxies; /* webauth_webkdc_proxy_data */
    const WA_APR_ARRAY_HEADER_T *wkfactors; /* const char * */
    const WA_APR_ARRAY_HEADER_T *logins;    /* const char * */

    /* request token from WAS. */
    const char *request;

    /* IP address of host sending the command, usually WebLogin. */
    const char *client_ip;

    /* Information about the connection to the WebLogin server. */
    const char *remote_user;
    const char *local_ip;
    const char *local_port;
    const char *remote_ip;
    const char *remote_port;
};

/*
 * Result from a <requestTokenResponse>, which is sent by the WebKDC back to
 * the WebLogin server containing the results of an authentication request.
 *
 * The initial factors, session factors, and LoA information is not returned
 * to WebLogin, but is included for better logging in the WebKDC.
 */
struct webauth_webkdc_login_response {
    const char *user_message;
    const char *login_state;
    const struct webauth_factors *factors_wanted;
    const struct webauth_factors *factors_configured;
    const char *default_device; /* Default second factor device. */
    const char *default_factor; /* Default second factor. */
    const WA_APR_ARRAY_HEADER_T *proxies;         /* webkdc_proxy_data. */
    const WA_APR_ARRAY_HEADER_T *factor_tokens;   /* webkdc_factor_data. */
    const char *return_url;
    const char *requester;
    const char *subject;
    const char *authz_subject;  /* Authorization identity, if different. */
    const char *result;         /* Encrypted id or cred token. */
    const char *result_type;    /* Type of result token as a string. */
    const char *login_cancel;   /* Encrypted error token. */
    const void *app_state;
    size_t app_state_len;
    const WA_APR_ARRAY_HEADER_T *logins;        /* Array of webauth_login. */
    time_t password_expires;            /* Time of password expiration or 0. */
    const WA_APR_ARRAY_HEADER_T *permitted_authz;  /* Allowable authz ids. */
    const WA_APR_ARRAY_HEADER_T *devices; /* Array of struct webauth_device. */
};    

/*
 * Supported protocols for contacting the user information and multifactor
 * authentication services.  Currently, only remctl is supported.
 */
enum webauth_user_protocol {
    WA_PROTOCOL_NONE   = 0,
    WA_PROTOCOL_REMCTL = 1
};

/*
 * Configuration information for the user information service.  This is used
 * to bundle together the configuration parameters and pass them into
 * webauth_user_config.  The port may be 0, which indicates the standard port
 * should be used.  identity is the identity of the information service for
 * authentication purposes and may be NULL to use the default.  command is
 * protocol-specific command information, such as a partial URL or a remctl
 * command.
 *
 * The timeout will only be enforced if the library is built with remctl 3.1
 * or later (which have remctl_set_timeout).
 *
 * The ignore_failure flag only applies to user information queries.  If set
 * and the remote call fails, webauth_user_info will return a minimal result
 * saying that the user can only do password authentication.  The
 * webauth_user_validate call ignores ignore_failure and always must succeed.
 */
struct webauth_user_config {
    enum webauth_user_protocol protocol;
    const char *host;
    unsigned short port;        /* May be 0 to use the standard port. */
    const char *identity;       /* Metadata service identity (may be NULL). */
    const char *command;        /* Protocol-specific command. */
    const char *keytab;         /* Kerberos keytab for authentication. */
    const char *principal;      /* Principal from keytab for authentication. */
    time_t timeout;             /* Network timeout, or 0 for no timeout. */
    int ignore_failure;         /* Whether to continue despite remote fail. */
    int json;                   /* Whether to use JSON for communication. */
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

/* Stores a single device the user can use as an additional authentication
 * factor.  Returned in an APR array in the webauth_userinfo struct.
 */
struct webauth_device {
    const char *name;           /* Human-meaningful device name. */
    const char *id;             /* System device ID. */
    const struct webauth_factors *factors;
};

/*
 * The webauth_user_info struct and its supporting data structures stores data
 * about a user, returned from the site-local user information middleware.
 *
 * default_device, default_factor, and devices are only available when the
 * JSON protocol is used.
 */
struct webauth_user_info {
    const struct webauth_factors *factors;
    const struct webauth_factors *additional;
    const struct webauth_factors *required;
    const char *default_device;         /* Default second factor device. */
    const char *default_factor;         /* Default second factor. */
    time_t valid_threshold;             /* Cutoff for persistent validity. */
    int random_multifactor;             /* If random multifactor was done. */
    unsigned long max_loa;              /* Maximum level of assurance. */
    time_t password_expires;            /* Password expiration time or 0. */
    const WA_APR_ARRAY_HEADER_T *logins;  /* Array of struct webauth_login. */
    const WA_APR_ARRAY_HEADER_T *devices; /* Array of struct webauth_device. */
    const char *error;                  /* Error returned from userinfo. */
    const char *user_message;           /* Message to pass along to a user. */
    const char *login_state;            /* Opaque state object for WebLogin. */
};

/*
 * The webauth_user_validate struct is very similar to webauth_user_info, but
 * is returned after an attempted OTP validation.  It contains the result of
 * that validation, the factors configured, login history if any, and the LoA
 * of the authentication were it successful.
 */
struct webauth_user_validate {
    int success;                        /* Whether the validation succeeded. */
    const struct webauth_factors *factors;
    time_t factors_expiration;          /* Expiration time of factors. */
    const struct webauth_factors *persistent;
    time_t persistent_expiration;       /* Expiration time of persistent. */
    time_t valid_threshold;             /* Cutoff for persistent validity. */
    unsigned long loa;                  /* Level of assurance. */
    const char *user_message;           /* Message to pass along to a user. */
    const char *login_state;            /* Opaque state object for WebLogin. */
};

BEGIN_DECLS

/*
 * Configure how to access the user information service.  Takes the context
 * and the configuration information.  The configuration information is stored
 * in the WebAuth context and used for all subsequent webauth_userinfo
 * queries.  Returns a status code, which will be WA_ERR_NONE unless invalid
 * parameters were passed.
 */
int webauth_user_config(struct webauth_context *,
                        const struct webauth_user_config *)
    __attribute__((__nonnull__));

/*
 * Obtain user information for a given user.  The IP address of the user (as a
 * string) is also provided.  If NULL, it defaults to 127.0.0.1 for the XML
 * protocol, where IP is required.  The timestamp of the query is assumed to
 * be the current time.  The random_mf flag indicates whether a site requested
 * random multifactor and asks the user information service to calculate
 * whether multifactor is forced based on that random multifactor chance.  The
 * return URL should be provided, which may be used to make decisions in the
 * user information service.  Finally, the factors is a comma-separated list
 * of authentication factors that the user has already established in some
 * way, which may be NULL if no factors have yet been established.
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
                      const char *ip, int random_mf, const char *url,
                      const char *factors, struct webauth_user_info **)
    __attribute__((__nonnull__(1, 2, 5)));

/*
 * Validate an authentication code for a given user (generally an OTP code),
 * or attempt a second factor authentication.  The IP address (as a string) is
 * also provided.  Either the device and type or the code must be provided.
 * If NULL and the XML protocol is used (which requires an IP), it defaults to
 * 127.0.0.1.
 *
 * The device information is not passed to the user information service in the
 * XML protocol, so, to make full use of that information, the JSON protocol
 * must be used.
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
                          const char *ip, const char *code, const char *type,
                          const char *device, const char *state,
                          struct webauth_user_validate **)
    __attribute__((__nonnull__(1, 2, 4, 7)));

/*
 * Configure the WebKDC services.  Takes the context and the configuration
 * information.  The configuration information is stored in the WebAuth
 * context and is used for all subsequent webauth_webkdc functions.  Returns a
 * status code, which will be WA_ERR_NONE unless invalid parameters were
 * passed.
 */
int webauth_webkdc_config(struct webauth_context *,
                          const struct webauth_webkdc_config *)
    __attribute__((__nonnull__));

/*
 * Given the data from a <requestTokenRequest> login attempt, process that
 * attempted login and return the information for a <requestTokenResponse> in
 * a newly-allocated struct from pool memory.  All of the tokens included in
 * the input and output are the unencrypted struct representations; the caller
 * does the encryption or decryption and base64 conversion.
 *
 * Returns WA_ERR_NONE if the authentication was successful.  Otherwise,
 * returns a protocol status code.  The return status and WebAuth error
 * message will be appropriate for a <requestTokenResponse> or <errorResponse>
 * XML message.
 */
int webauth_webkdc_login(struct webauth_context *,
                         const struct webauth_webkdc_login_request *,
                         struct webauth_webkdc_login_response **,
                         const struct webauth_keyring *)
    __attribute__((__nonnull__));

END_DECLS

#endif /* !WEBAUTH_WEBKDC_H */
