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

const struct wai_encoding wai_keyring_encoding[] = {
    {
        "v",
        "version",
        WA_TYPE_UINT32,
        false, /* optional */
        true,  /* ascii    */
        false, /* creation */
        offsetof(struct wai_keyring, version),
        0,
        0,
        NULL
    },
    {
        "n",
        "entry",
        WA_TYPE_REPEAT,
        false, /* optional */
        true,  /* ascii    */
        false, /* creation */
        offsetof(struct wai_keyring, entry),
        offsetof(struct wai_keyring, entry_count),
        sizeof(struct wai_keyring_entry),
        wai_keyring_entry_encoding
    },
    WA_ENCODING_END
};
const struct wai_encoding wai_keyring_entry_encoding[] = {
    {
        "ct",
        "creation",
        WA_TYPE_TIME,
        false, /* optional */
        true,  /* ascii    */
        false, /* creation */
        offsetof(struct wai_keyring_entry, creation),
        0,
        0,
        NULL
    },
    {
        "va",
        "valid after",
        WA_TYPE_TIME,
        false, /* optional */
        true,  /* ascii    */
        false, /* creation */
        offsetof(struct wai_keyring_entry, valid_after),
        0,
        0,
        NULL
    },
    {
        "kt",
        "key type",
        WA_TYPE_UINT32,
        false, /* optional */
        true,  /* ascii    */
        false, /* creation */
        offsetof(struct wai_keyring_entry, key_type),
        0,
        0,
        NULL
    },
    {
        "kd",
        "key",
        WA_TYPE_DATA,
        false, /* optional */
        true,  /* ascii    */
        false, /* creation */
        offsetof(struct wai_keyring_entry, key),
        offsetof(struct wai_keyring_entry, key_len),
        0,
        NULL
    },
    WA_ENCODING_END
};
