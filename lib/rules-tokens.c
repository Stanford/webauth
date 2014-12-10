/*
 * Automatically generated -- do not edit!
 *
 * This file was automatically generated from the encode comments on the
 * members of structs in the WebAuth source using the encoding-rules
 * script.  To make changes, modify either the encode comments or (more
 * rarely) the encoding-rules script and run it again.
 *
 * Copyright 2012, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <portable/system.h>

#include <lib/internal.h>
#include <include/webauth/tokens.h>

const struct wai_encoding wai_token_app_encoding[] = {
    {
        "s",
        "subject",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_app, subject),
        0,
        0,
        NULL
    },
    {
        "sz",
        "authz subject",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_app, authz_subject),
        0,
        0,
        NULL
    },
    {
        "lt",
        "last used",
        WA_TYPE_TIME,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_app, last_used),
        0,
        0,
        NULL
    },
    {
        "k",
        "session key",
        WA_TYPE_DATA,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_app, session_key),
        offsetof(struct webauth_token_app, session_key_len),
        0,
        NULL
    },
    {
        "ia",
        "initial factors",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_app, initial_factors),
        0,
        0,
        NULL
    },
    {
        "san",
        "session factors",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_app, session_factors),
        0,
        0,
        NULL
    },
    {
        "loa",
        "loa",
        WA_TYPE_ULONG,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_app, loa),
        0,
        0,
        NULL
    },
    {
        "ct",
        "creation",
        WA_TYPE_TIME,
        true,  /* optional */
        false, /* ascii    */
        true,  /* creation */
        offsetof(struct webauth_token_app, creation),
        0,
        0,
        NULL
    },
    {
        "et",
        "expiration",
        WA_TYPE_TIME,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_app, expiration),
        0,
        0,
        NULL
    },
    WA_ENCODING_END
};
const struct wai_encoding wai_token_cred_encoding[] = {
    {
        "s",
        "subject",
        WA_TYPE_STRING,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_cred, subject),
        0,
        0,
        NULL
    },
    {
        "crt",
        "type",
        WA_TYPE_STRING,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_cred, type),
        0,
        0,
        NULL
    },
    {
        "crs",
        "service",
        WA_TYPE_STRING,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_cred, service),
        0,
        0,
        NULL
    },
    {
        "crd",
        "data",
        WA_TYPE_DATA,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_cred, data),
        offsetof(struct webauth_token_cred, data_len),
        0,
        NULL
    },
    {
        "ct",
        "creation",
        WA_TYPE_TIME,
        false, /* optional */
        false, /* ascii    */
        true,  /* creation */
        offsetof(struct webauth_token_cred, creation),
        0,
        0,
        NULL
    },
    {
        "et",
        "expiration",
        WA_TYPE_TIME,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_cred, expiration),
        0,
        0,
        NULL
    },
    WA_ENCODING_END
};
const struct wai_encoding wai_token_error_encoding[] = {
    {
        "ec",
        "code",
        WA_TYPE_ULONG,
        false, /* optional */
        true,  /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_error, code),
        0,
        0,
        NULL
    },
    {
        "em",
        "message",
        WA_TYPE_STRING,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_error, message),
        0,
        0,
        NULL
    },
    {
        "ct",
        "creation",
        WA_TYPE_TIME,
        false, /* optional */
        false, /* ascii    */
        true,  /* creation */
        offsetof(struct webauth_token_error, creation),
        0,
        0,
        NULL
    },
    WA_ENCODING_END
};
const struct wai_encoding wai_token_id_encoding[] = {
    {
        "s",
        "subject",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_id, subject),
        0,
        0,
        NULL
    },
    {
        "sz",
        "authz subject",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_id, authz_subject),
        0,
        0,
        NULL
    },
    {
        "sa",
        "auth",
        WA_TYPE_STRING,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_id, auth),
        0,
        0,
        NULL
    },
    {
        "sad",
        "auth data",
        WA_TYPE_DATA,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_id, auth_data),
        offsetof(struct webauth_token_id, auth_data_len),
        0,
        NULL
    },
    {
        "ia",
        "initial factors",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_id, initial_factors),
        0,
        0,
        NULL
    },
    {
        "san",
        "session factors",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_id, session_factors),
        0,
        0,
        NULL
    },
    {
        "loa",
        "loa",
        WA_TYPE_ULONG,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_id, loa),
        0,
        0,
        NULL
    },
    {
        "ct",
        "creation",
        WA_TYPE_TIME,
        false, /* optional */
        false, /* ascii    */
        true,  /* creation */
        offsetof(struct webauth_token_id, creation),
        0,
        0,
        NULL
    },
    {
        "et",
        "expiration",
        WA_TYPE_TIME,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_id, expiration),
        0,
        0,
        NULL
    },
    WA_ENCODING_END
};
const struct wai_encoding wai_token_login_encoding[] = {
    {
        "u",
        "username",
        WA_TYPE_STRING,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_login, username),
        0,
        0,
        NULL
    },
    {
        "p",
        "password",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_login, password),
        0,
        0,
        NULL
    },
    {
        "otp",
        "otp",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_login, otp),
        0,
        0,
        NULL
    },
    {
        "ott",
        "otp type",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_login, otp_type),
        0,
        0,
        NULL
    },
    {
        "did",
        "device id",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_login, device_id),
        0,
        0,
        NULL
    },
    {
        "ct",
        "creation",
        WA_TYPE_TIME,
        false, /* optional */
        false, /* ascii    */
        true,  /* creation */
        offsetof(struct webauth_token_login, creation),
        0,
        0,
        NULL
    },
    WA_ENCODING_END
};
const struct wai_encoding wai_token_proxy_encoding[] = {
    {
        "s",
        "subject",
        WA_TYPE_STRING,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_proxy, subject),
        0,
        0,
        NULL
    },
    {
        "sz",
        "authz subject",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_proxy, authz_subject),
        0,
        0,
        NULL
    },
    {
        "pt",
        "type",
        WA_TYPE_STRING,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_proxy, type),
        0,
        0,
        NULL
    },
    {
        "wt",
        "webkdc proxy",
        WA_TYPE_DATA,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_proxy, webkdc_proxy),
        offsetof(struct webauth_token_proxy, webkdc_proxy_len),
        0,
        NULL
    },
    {
        "ia",
        "initial factors",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_proxy, initial_factors),
        0,
        0,
        NULL
    },
    {
        "san",
        "session factors",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_proxy, session_factors),
        0,
        0,
        NULL
    },
    {
        "loa",
        "loa",
        WA_TYPE_ULONG,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_proxy, loa),
        0,
        0,
        NULL
    },
    {
        "ct",
        "creation",
        WA_TYPE_TIME,
        false, /* optional */
        false, /* ascii    */
        true,  /* creation */
        offsetof(struct webauth_token_proxy, creation),
        0,
        0,
        NULL
    },
    {
        "et",
        "expiration",
        WA_TYPE_TIME,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_proxy, expiration),
        0,
        0,
        NULL
    },
    WA_ENCODING_END
};
const struct wai_encoding wai_token_request_encoding[] = {
    {
        "rtt",
        "type",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_request, type),
        0,
        0,
        NULL
    },
    {
        "sa",
        "auth",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_request, auth),
        0,
        0,
        NULL
    },
    {
        "pt",
        "proxy type",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_request, proxy_type),
        0,
        0,
        NULL
    },
    {
        "as",
        "state",
        WA_TYPE_DATA,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_request, state),
        offsetof(struct webauth_token_request, state_len),
        0,
        NULL
    },
    {
        "ru",
        "return url",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_request, return_url),
        0,
        0,
        NULL
    },
    {
        "ro",
        "options",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_request, options),
        0,
        0,
        NULL
    },
    {
        "ia",
        "initial factors",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_request, initial_factors),
        0,
        0,
        NULL
    },
    {
        "san",
        "session factors",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_request, session_factors),
        0,
        0,
        NULL
    },
    {
        "loa",
        "loa",
        WA_TYPE_ULONG,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_request, loa),
        0,
        0,
        NULL
    },
    {
        "cmd",
        "command",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_request, command),
        0,
        0,
        NULL
    },
    {
        "ct",
        "creation",
        WA_TYPE_TIME,
        false, /* optional */
        false, /* ascii    */
        true,  /* creation */
        offsetof(struct webauth_token_request, creation),
        0,
        0,
        NULL
    },
    WA_ENCODING_END
};
const struct wai_encoding wai_token_webkdc_factor_encoding[] = {
    {
        "s",
        "subject",
        WA_TYPE_STRING,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_webkdc_factor, subject),
        0,
        0,
        NULL
    },
    {
        "ia",
        "factors",
        WA_TYPE_STRING,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_webkdc_factor, factors),
        0,
        0,
        NULL
    },
    {
        "ct",
        "creation",
        WA_TYPE_TIME,
        false, /* optional */
        false, /* ascii    */
        true,  /* creation */
        offsetof(struct webauth_token_webkdc_factor, creation),
        0,
        0,
        NULL
    },
    {
        "et",
        "expiration",
        WA_TYPE_TIME,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_webkdc_factor, expiration),
        0,
        0,
        NULL
    },
    WA_ENCODING_END
};
const struct wai_encoding wai_token_webkdc_proxy_encoding[] = {
    {
        "s",
        "subject",
        WA_TYPE_STRING,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_webkdc_proxy, subject),
        0,
        0,
        NULL
    },
    {
        "pt",
        "proxy type",
        WA_TYPE_STRING,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_webkdc_proxy, proxy_type),
        0,
        0,
        NULL
    },
    {
        "ps",
        "proxy subject",
        WA_TYPE_STRING,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_webkdc_proxy, proxy_subject),
        0,
        0,
        NULL
    },
    {
        "pd",
        "data",
        WA_TYPE_DATA,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_webkdc_proxy, data),
        offsetof(struct webauth_token_webkdc_proxy, data_len),
        0,
        NULL
    },
    {
        "ia",
        "initial factors",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_webkdc_proxy, initial_factors),
        0,
        0,
        NULL
    },
    {
        "loa",
        "loa",
        WA_TYPE_ULONG,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_webkdc_proxy, loa),
        0,
        0,
        NULL
    },
    {
        "ct",
        "creation",
        WA_TYPE_TIME,
        false, /* optional */
        false, /* ascii    */
        true,  /* creation */
        offsetof(struct webauth_token_webkdc_proxy, creation),
        0,
        0,
        NULL
    },
    {
        "et",
        "expiration",
        WA_TYPE_TIME,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_webkdc_proxy, expiration),
        0,
        0,
        NULL
    },
    WA_ENCODING_END
};
const struct wai_encoding wai_token_webkdc_service_encoding[] = {
    {
        "s",
        "subject",
        WA_TYPE_STRING,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_webkdc_service, subject),
        0,
        0,
        NULL
    },
    {
        "k",
        "session key",
        WA_TYPE_DATA,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_webkdc_service, session_key),
        offsetof(struct webauth_token_webkdc_service, session_key_len),
        0,
        NULL
    },
    {
        "ct",
        "creation",
        WA_TYPE_TIME,
        false, /* optional */
        false, /* ascii    */
        true,  /* creation */
        offsetof(struct webauth_token_webkdc_service, creation),
        0,
        0,
        NULL
    },
    {
        "et",
        "expiration",
        WA_TYPE_TIME,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_token_webkdc_service, expiration),
        0,
        0,
        NULL
    },
    WA_ENCODING_END
};
