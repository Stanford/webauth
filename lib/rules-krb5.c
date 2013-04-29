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

const struct wai_encoding wai_krb5_cred_encoding[] = {
    {
        "c",
        "client principal",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct wai_krb5_cred, client_principal),
        0,
        0,
        NULL
    },
    {
        "s",
        "server principal",
        WA_TYPE_STRING,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct wai_krb5_cred, server_principal),
        0,
        0,
        NULL
    },
    {
        "K",
        "keyblock enctype",
        WA_TYPE_INT32,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct wai_krb5_cred, keyblock_enctype),
        0,
        0,
        NULL
    },
    {
        "k",
        "keyblock data",
        WA_TYPE_DATA,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct wai_krb5_cred, keyblock_data),
        offsetof(struct wai_krb5_cred, keyblock_data_len),
        0,
        NULL
    },
    {
        "ta",
        "auth time",
        WA_TYPE_INT32,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct wai_krb5_cred, auth_time),
        0,
        0,
        NULL
    },
    {
        "ts",
        "start time",
        WA_TYPE_INT32,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct wai_krb5_cred, start_time),
        0,
        0,
        NULL
    },
    {
        "te",
        "end time",
        WA_TYPE_INT32,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct wai_krb5_cred, end_time),
        0,
        0,
        NULL
    },
    {
        "tr",
        "renew until",
        WA_TYPE_INT32,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct wai_krb5_cred, renew_until),
        0,
        0,
        NULL
    },
    {
        "i",
        "is skey",
        WA_TYPE_INT32,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct wai_krb5_cred, is_skey),
        0,
        0,
        NULL
    },
    {
        "f",
        "flags",
        WA_TYPE_INT32,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct wai_krb5_cred, flags),
        0,
        0,
        NULL
    },
    {
        "na",
        "address",
        WA_TYPE_REPEAT,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct wai_krb5_cred, address),
        offsetof(struct wai_krb5_cred, address_count),
        sizeof(struct wai_krb5_cred_address),
        wai_krb5_cred_address_encoding
    },
    {
        "t",
        "ticket",
        WA_TYPE_DATA,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct wai_krb5_cred, ticket),
        offsetof(struct wai_krb5_cred, ticket_len),
        0,
        NULL
    },
    {
        "t2",
        "second ticket",
        WA_TYPE_DATA,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct wai_krb5_cred, second_ticket),
        offsetof(struct wai_krb5_cred, second_ticket_len),
        0,
        NULL
    },
    {
        "nd",
        "authdata",
        WA_TYPE_REPEAT,
        true,  /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct wai_krb5_cred, authdata),
        offsetof(struct wai_krb5_cred, authdata_count),
        sizeof(struct wai_krb5_cred_authdata),
        wai_krb5_cred_authdata_encoding
    },
    WA_ENCODING_END
};
const struct wai_encoding wai_krb5_cred_address_encoding[] = {
    {
        "A",
        "type",
        WA_TYPE_INT32,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct wai_krb5_cred_address, type),
        0,
        0,
        NULL
    },
    {
        "a",
        "data",
        WA_TYPE_DATA,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct wai_krb5_cred_address, data),
        offsetof(struct wai_krb5_cred_address, data_len),
        0,
        NULL
    },
    WA_ENCODING_END
};
const struct wai_encoding wai_krb5_cred_authdata_encoding[] = {
    {
        "D",
        "type",
        WA_TYPE_INT32,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct wai_krb5_cred_authdata, type),
        0,
        0,
        NULL
    },
    {
        "d",
        "data",
        WA_TYPE_DATA,
        false, /* optional */
        false, /* ascii    */
        false, /* creation */
        offsetof(struct wai_krb5_cred_authdata, data),
        offsetof(struct wai_krb5_cred_authdata, data_len),
        0,
        NULL
    },
    WA_ENCODING_END
};
