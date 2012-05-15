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

#include <webauth.h>            /* WEBAUTH_ATTR_LIST, WEBAUTH_KEY* */

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
 * Encodes and encrypts attributes into a token, using the key from the
 * keyring that has the most recent valid valid_from time.  If hint is 0 then
 * the current time will be used.  The encoded token will be stored in newly
 * pool-allocated memory in the provided output argument, with its length
 * stored in output_len.
 *
 * Returns a WebAuth status code, which may be WA_ERR_BAD_KEY if no suitable
 * and valid encryption key could be found in the keyring.
 */
int webauth_token_create(struct webauth_context *, const WEBAUTH_ATTR_LIST *,
                         time_t hint, char **output, size_t *output_len,
                         const WEBAUTH_KEYRING *)
    __attribute__((__nonnull__));

/*
 * Decrypts and decodes attributes from a token.  The best decryption key on
 * the ring will be tried first, and if that fails all the remaining keys will
 * be tried.  input is modified and the returned attrs in list point into
 * input.
 *
 * The following checks are made:
 *
 * * If the token has a WA_TK_EXPIRATION_TIME attribute, it must be 4 bytes
 *   long and is assumed to be the expiration time of the token in network
 *   byte order.  It is compared against the current time, and
 *   WA_ERR_TOKEN_EXPIRED is returned if the token has expired.
 *
 * * WA_TK_CREATION_TIME is checked if and only if the token doesn't have an
 *   explicit expiration time and ttl is non-zero.  In that case, if the token
 *   has a WA_TK_CREATION_TIME attribute, it must be 4 bytes long and is
 *   assumed to be the creation time of the token in network byte order.  The
 *   creation time is compared against the current time + ttl and
 *   WA_ERR_TOKEN_STALE is returned if the token is stale.
 *
 * The list will point to the dynamically-allocated list of attributes and
 * must be freed when no longer needed.  If WA_ERR_TOKEN_EXPIRED or
 * WA_ERR_TOKEN_STALE are returned, an attribute list is still allocated and
 * needs to be freed.
 *
 * Returns WA_ERR_NONE, WA_ERR_NO_MEM, WA_ERR_CORRUPT, WA_ERR_BAD_HMAC,
 * WA_ERR_BAD_KEY, WA_ERR_TOKEN_EXPIRED, or WA_ERR_TOKEN_STALE.
 */
int webauth_token_parse(struct webauth_context *, const char *input,
                        size_t input_len, unsigned long ttl,
                        const WEBAUTH_KEYRING *, WEBAUTH_ATTR_LIST **)
    __attribute__((__nonnull__));

/* Retrieve all of the text inside an XML element and return it. */
int webauth_xml_content(struct webauth_context *, apr_xml_elem *,
                        const char **)
    __attribute__((__nonnull__));

/* Undo default visibility change. */
#pragma GCC visibility pop

END_DECLS

#endif /* !LIB_INTERNAL_H */
