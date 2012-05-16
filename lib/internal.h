/*
 * Internal data types, definitions, and prototypes for the WebAuth library.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011, 2012
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#ifndef LIB_INTERNAL_H
#define LIB_INTERNAL_H 1

#include <portable/macros.h>
#include <portable/stdbool.h>

#include <apr_xml.h>

#include <webauth.h>            /* WEBAUTH_KEYRING */

/*
 * The internal context struct, which holds any state information required for
 * general WebAuth library interfaces.
 */
struct webauth_context {
    apr_pool_t *pool;           /* Pool used for all memory allocations. */
    const char *error;          /* Error message from last failure. */
    int code;                   /* Error code from last failure. */

    /* The below are used only for the WebKDC functions. */

    /* General WebKDC configuration. */
    struct webauth_webkdc_config *webkdc;

    /* Configuration for contacting the user metadata service. */
    struct webauth_user_config *user;
};

/*
 * An APR-managed buffer, used to accumulate data that comes in chunks.  This
 * is managed by the webauth_buffer_* functions.
 */
struct buffer {
    apr_pool_t *pool;
    size_t size;
    size_t used;
    char *data;
};

BEGIN_DECLS

/* Default to a hidden visibility for all internal functions. */
#pragma GCC visibility push(hidden)

/* Allocate a new buffer and initialize its contents. */
struct buffer *webauth_buffer_new(apr_pool_t *)
    __attribute__((__nonnull__));

/* Set the buffer contents, ignoring anything currently there. */
void webauth_buffer_set(struct buffer *, const char *data, size_t length)
    __attribute__((__nonnull__));

/* Append data to the buffer. */
void webauth_buffer_append(struct buffer *, const char *data, size_t length)
    __attribute__((__nonnull__));

/*
 * Find a given string in the buffer.  Returns the offset of the string (with
 * the same meaning as start) in offset if found, and returns true if the
 * terminator is found and false otherwise.
 */
bool webauth_buffer_find_string(struct buffer *, const char *, size_t start,
                                size_t *offset)
    __attribute__((__nonnull__));

/* Set the internal WebAuth error message and error code. */
void webauth_error_set(struct webauth_context *, int err, const char *, ...)
    __attribute__((__nonnull__, __format__(printf, 3, 4)));

/*
 * Encrypts an input buffer (normally encoded attributes) into a token, using
 * the key from the keyring that has the most recent valid valid_from time.
 * The encoded token will be stored in newly pool-allocated memory in the
 * provided output argument, with its length stored in output_len.
 *
 * Returns a WebAuth status code, which may be WA_ERR_BAD_KEY if no suitable
 * and valid encryption key could be found in the keyring.
 */
int webauth_token_encrypt(struct webauth_context *, const char *input,
                          size_t len, char **output, size_t *output_len,
                          const WEBAUTH_KEYRING *)
    __attribute__((__nonnull__));

/*
 * Decrypts a token.  The best decryption key on the ring will be tried first,
 * and if that fails all the remaining keys will be tried.  Returns the
 * decrypted data in output and its length in output_len.
 *
 * Returns WA_ERR_NONE, WA_ERR_NO_MEM, WA_ERR_CORRUPT, WA_ERR_BAD_HMAC, or
 * WA_ERR_BAD_KEY.
 */
int webauth_token_decrypt(struct webauth_context *, const char *input,
                          size_t input_len, char **output, size_t *output_len,
                          const WEBAUTH_KEYRING *)
    __attribute__((__nonnull__));

/* Retrieve all of the text inside an XML element and return it. */
int webauth_xml_content(struct webauth_context *, apr_xml_elem *,
                        const char **)
    __attribute__((__nonnull__));

/* Undo default visibility change. */
#pragma GCC visibility pop

END_DECLS

#endif /* !LIB_INTERNAL_H */
