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
#include <include/webauth/was.h>

const struct wai_encoding wai_was_token_cache_encoding[] = {
    {
        "token",
        "token",
        WA_TYPE_STRING,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct webauth_was_token_cache, token),
        0,
        0,
        NULL
    },
    {
        "key_type",
        "key type",
        WA_TYPE_UINT32,
        false, /* optional */
        true,  /* ascii    */
        false, /* creation */
        offsetof(struct webauth_was_token_cache, key_type),
        0,
        0,
        NULL
    },
    {
        "key",
        "key data",
        WA_TYPE_DATA,
        false, /* optional */
        true,  /* ascii    */
        false, /* creation */
        offsetof(struct webauth_was_token_cache, key_data),
        offsetof(struct webauth_was_token_cache, key_data_len),
        0,
        NULL
    },
    {
        "created",
        "created",
        WA_TYPE_TIME,
        false, /* optional */
        true,  /* ascii    */
        false, /* creation */
        offsetof(struct webauth_was_token_cache, created),
        0,
        0,
        NULL
    },
    {
        "expires",
        "expires",
        WA_TYPE_TIME,
        false, /* optional */
        true,  /* ascii    */
        false, /* creation */
        offsetof(struct webauth_was_token_cache, expires),
        0,
        0,
        NULL
    },
    {
        "last_renewal_attempt",
        "last renewal",
        WA_TYPE_TIME,
        false, /* optional */
        true,  /* ascii    */
        false, /* creation */
        offsetof(struct webauth_was_token_cache, last_renewal),
        0,
        0,
        NULL
    },
    {
        "next_renewal_attempt",
        "next renewal",
        WA_TYPE_TIME,
        false, /* optional */
        true,  /* ascii    */
        false, /* creation */
        offsetof(struct webauth_was_token_cache, next_renewal),
        0,
        0,
        NULL
    },
    WA_ENCODING_END
};
