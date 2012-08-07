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

#include <apr_pools.h>          /* apr_pool_t */
#include <apr_xml.h>            /* apr_xml_elem */

struct webauth_keyring;

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

/*
 * The types of data that can be encoded.  WA_TYPE_REPEAT is special and
 * indicates a part of the encoding that is repeated some number of times.
 * This is represented as a count followed by that many repetitions of some
 * structure.
 */
enum webauth_encoding_type {
    WA_TYPE_DATA,
    WA_TYPE_STRING,
    WA_TYPE_INT32,
    WA_TYPE_UINT32,
    WA_TYPE_TIME,
    WA_TYPE_REPEAT
};

/*
 * An encoding specification.  This is used to turn data elements into an
 * encoded attribute string, or to translate an encoded attribute string back
 * into a data structure.
 *
 * All types use offset as the offset to the basic value (obtained via
 * offsetof).  WA_TYPE_DATA also uses lenoff as the offset to the length.  For
 * WA_TYPE_REPEAT, the named attribute will be the count of elements and will
 * be stored as WA_TYPE_UINT32, and then size specifies the size of the
 * structure to store each element and repeat is a set of rules for each
 * element.  In this case, a number will be appended to the name in each rule
 * inside the repeated structure.
 *
 * Only one level of nesting of WA_TYPE_REPEAT is supported.
 */
struct webauth_encoding {
    const char *attr;                   /* Attribute name in encoding */
    const char *desc;                   /* Description for error reporting */
    enum webauth_encoding_type type;    /* Data type */
    bool optional;                      /* Whether attribute is optional */
    size_t offset;                      /* Offset of data value */
    size_t len_offset;                  /* Offset of data value length */
    size_t size;                        /* Size of nested structure */
    const struct webauth_encoding *repeat; /* Rules for nested structure */
};

/* Used as the terminator for an encoding specification. */
#define WA_ENCODING_END { NULL, NULL, 0, false, 0, 0, 0, NULL }

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

/*
 * Decode the binary attribute representation into the struct pointed to by
 * data following the provided rules.  Takes a separate pool to use for memory
 * allocation.
 */
int webauth_decode(struct webauth_context *, apr_pool_t *,
                   const struct webauth_encoding *, const void *input, size_t,
                   void *data)
    __attribute__((__nonnull__));

/*
 * Encode the struct pointed to by data according to given the rules into the
 * output parameter, storing the encoded data length.  The result will be in
 * WebAuth attribute encoding format.  Takes a separate pool to use for memory
 * allocation.
 */
int webauth_encode(struct webauth_context *, apr_pool_t *,
                   const struct webauth_encoding *, void *data, void **,
                   size_t *)
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
int webauth_token_encrypt(struct webauth_context *, const void *input,
                          size_t len, void **output, size_t *output_len,
                          const struct webauth_keyring *)
    __attribute__((__nonnull__));

/*
 * Decrypts a token.  The best decryption key on the ring will be tried first,
 * and if that fails all the remaining keys will be tried.  Returns the
 * decrypted data in output and its length in output_len.
 *
 * Returns WA_ERR_NONE, WA_ERR_NO_MEM, WA_ERR_CORRUPT, WA_ERR_BAD_HMAC, or
 * WA_ERR_BAD_KEY.
 */
int webauth_token_decrypt(struct webauth_context *, const void *input,
                          size_t input_len, void **output, size_t *output_len,
                          const struct webauth_keyring *)
    __attribute__((__nonnull__));

/* Retrieve all of the text inside an XML element and return it. */
int webauth_xml_content(struct webauth_context *, apr_xml_elem *,
                        const char **)
    __attribute__((__nonnull__));

/* Undo default visibility change. */
#pragma GCC visibility pop

END_DECLS

#endif /* !LIB_INTERNAL_H */
