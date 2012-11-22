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

#include <apr_errno.h>          /* apr_status_t */
#include <apr_pools.h>          /* apr_pool_t */
#include <apr_xml.h>            /* apr_xml_elem */

/* Flags to webauth_attr_list_add functions. */
#define WA_F_NONE       0x00
#define WA_F_COPY_VALUE 0x01
#define WA_F_COPY_NAME  0x02
#define WA_F_FMT_STR    0x04
#define WA_F_FMT_HEX    0x08
#define WA_F_COPY_BOTH  (WA_F_COPY_NAME | WA_F_COPY_VALUE)

/* Factor constants. */
#define WA_FA_COOKIE               "c"
#define WA_FA_PASSWORD             "p"
#define WA_FA_KERBEROS             "k"
#define WA_FA_MULTIFACTOR          "m"
#define WA_FA_OTP                  "o"
#define WA_FA_OTP_TYPE             "o%d"
#define WA_FA_RANDOM_MULTIFACTOR   "rm"
#define WA_FA_UNKNOWN              "u"
#define WA_FA_X509                 "x"
#define WA_FA_X509_TYPE            "x%d"

struct webauth_keyring;
struct webauth_token;

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
 * is managed by the wai_buffer_* functions.
 */
struct buffer {
    apr_pool_t *pool;
    size_t size;
    size_t used;
    char *data;
};

/*
 * Holds a generic name/value attribute for constructing and parsing tokens.
 * Names must not contain "=", and values may contain binary data, since the
 * length must be specified.
 */
typedef struct {
    const char *name;           /* Name of attribute. */
    unsigned int flags;         /* Flags passed in during add */
    void *value;                /* Value of attribute (binary data). */
    size_t length;              /* Length of attribute value in bytes. */
    char val_buff[32];          /* Temp buffer to avoid malloc on encoding. */
} WEBAUTH_ATTR;

/*
 * Holds a list of attributes.  You must always use use webauth_attr_list_new
 * to construct a new attr list so that webauth_attr_list_{add,free} work
 * correctly.
 */
typedef struct {
    size_t num_attrs;
    size_t capacity;
    WEBAUTH_ATTR *attrs;
} WEBAUTH_ATTR_LIST;

/*
 * The types of data that can be encoded.  WA_TYPE_REPEAT is special and
 * indicates a part of the encoding that is repeated some number of times.
 * This is represented as a count followed by that many repetitions of some
 * structure.
 */
enum wai_encoding_type {
    WA_TYPE_DATA,
    WA_TYPE_STRING,
    WA_TYPE_INT32,
    WA_TYPE_UINT32,
    WA_TYPE_ULONG,
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
struct wai_encoding {
    const char *attr;                   /* Attribute name in encoding */
    const char *desc;                   /* Description for error reporting */
    enum wai_encoding_type type;        /* Data type */
    bool optional;                      /* Whether attribute is optional */
    bool ascii;                         /* Whether to use ASCII-safe format */
    bool creation;                      /* Whether this is a creation time */
    size_t offset;                      /* Offset of data value */
    size_t len_offset;                  /* Offset of data value length */
    size_t size;                        /* Size of nested structure */
    const struct wai_encoding *repeat;  /* Rules for nested structure */
};

/* Used as the terminator for an encoding specification. */
#define WA_ENCODING_END { NULL, NULL, 0, false, false, false, 0, 0, 0, NULL }

/*
 * Encoding rules.  These are defined in the lib/rules-*.c files, which in
 * turn are automatically generated by the lib/encoding-rules script from the
 * comments in specific structs.
 */
extern const struct wai_encoding wai_keyring_encoding[];
extern const struct wai_encoding wai_keyring_entry_encoding[];
extern const struct wai_encoding wai_krb5_cred_encoding[];
extern const struct wai_encoding wai_krb5_cred_address_encoding[];
extern const struct wai_encoding wai_krb5_cred_authdata_encoding[];
extern const struct wai_encoding wai_token_app_encoding[];
extern const struct wai_encoding wai_token_cred_encoding[];
extern const struct wai_encoding wai_token_error_encoding[];
extern const struct wai_encoding wai_token_id_encoding[];
extern const struct wai_encoding wai_token_login_encoding[];
extern const struct wai_encoding wai_token_proxy_encoding[];
extern const struct wai_encoding wai_token_request_encoding[];
extern const struct wai_encoding wai_token_webkdc_proxy_encoding[];
extern const struct wai_encoding wai_token_webkdc_service_encoding[];
extern const struct wai_encoding wai_was_token_cache_encoding[];

/*
 * The internal representation of a Kerberos credential.  This representation
 * avoids any nested data structures and uses informative member names (so
 * that their stringification can be used in diagnostic output).  It is also
 * standard across all Kerberos implementations.  We later translate from this
 * structure into the krb5_creds structure in implementation-specific code.
 *
 * These structs are only used in the Kerberos code, but are present here to
 * make it easier to generate encoding rules for them.
 */
struct wai_krb5_cred_address {
    int32_t type;                       /* encode: A */
    void *data;                         /* encode: a */
    size_t data_len;
};
struct wai_krb5_cred_authdata {
    int32_t type;                       /* encode: D */
    void *data;                         /* encode: d */
    size_t data_len;
};
struct wai_krb5_cred {
    char *client_principal;             /* encode: c, optional */
    char *server_principal;             /* encode: s, optional */
    int32_t keyblock_enctype;           /* encode: K */
    void *keyblock_data;                /* encode: k */
    size_t keyblock_data_len;
    int32_t auth_time;                  /* encode: ta */
    int32_t start_time;                 /* encode: ts */
    int32_t end_time;                   /* encode: te */
    int32_t renew_until;                /* encode: tr */
    int32_t is_skey;                    /* encode: i */
    int32_t flags;                      /* encode: f */
    uint32_t address_count;             /* encode: na, optional, repeat */
    struct wai_krb5_cred_address *address;
    void *ticket;                       /* encode: t, optional */
    size_t ticket_len;
    void *second_ticket;                /* encode: t, optional */
    size_t second_ticket_len;
    uint32_t authdata_count;            /* encode: nd, optional, repeat */
    struct wai_krb5_cred_authdata *authdata;
};

/*
 * The internal representation of a WebAuth keyring, used for encoding and
 * decoding.  This is converted to and from the public webauth_keyring struct
 * after decoding and encoding.
 *
 * These structs are only used in the internal keyring code, but are present
 * here to make it easier to generate encoding rules for them.
 */
struct wai_keyring_entry {
    time_t creation;                    /* encode: ct, ascii */
    time_t valid_after;                 /* encode: va, ascii */
    uint32_t key_type;                  /* encode: kt, ascii */
    void *key;                          /* encode: kd, ascii */
    size_t key_len;
};
struct wai_keyring {
    uint32_t version;                   /* encode: v, ascii */
    uint32_t entry_count;               /* encode: n, ascii, repeat */
    struct wai_keyring_entry *entry;
};

BEGIN_DECLS

/* Default to a hidden visibility for all internal functions. */
#pragma GCC visibility push(hidden)

/* Creates a new attribute list, returning it or NULL if no memory. */
WEBAUTH_ATTR_LIST *webauth_attr_list_new(size_t initial_capacity);

/*
 * Adds an attribute to the attribute list, growing the list if need be.  Both
 * the name and value are copied, and value always has a null added to the end
 * of it.  Returns WA_ERR_NONE or WA_ERR_NO_MEM.
 */
int webauth_attr_list_add(WEBAUTH_ATTR_LIST *, const char *name, void *value,
                          size_t vlen, unsigned int flags)
    __attribute__((__nonnull__));

/*
 * Adds an attribute string to the attribute list, growing the list if need
 * be.  Name and value are not copied by default; the pointers are added
 * directly unless WA_F_COPY_* are used in flags.  If vlen is 0, then
 * strlen(value) is used.  Returns WA_ERR_NONE or WA_ERR_NO_MEM.
 */
int webauth_attr_list_add_str(WEBAUTH_ATTR_LIST *, const char *name,
                              const char *value, size_t vlen,
                              unsigned int flags)
    __attribute__((__nonnull__));

/*
 * Adds a number to an attribute list, growing the list if need be.  All of
 * these interfaces imply WA_COPY_VALUE.  Returns WA_ERR_NONE or
 * WA_ERR_NO_MEM.
 */
int webauth_attr_list_add_uint32(WEBAUTH_ATTR_LIST *, const char *name,
                                 uint32_t value, unsigned int flags)
    __attribute__((__nonnull__));
int webauth_attr_list_add_int32(WEBAUTH_ATTR_LIST *, const char *name,
                                int32_t value, unsigned int flags)
    __attribute__((__nonnull__));
int webauth_attr_list_add_time(WEBAUTH_ATTR_LIST *, const char *name,
                               time_t value, unsigned int flags)
    __attribute__((__nonnull__));

/*
 * Retrieve a specific attribute by name.  Stores its value in the value
 * parameter and its length in the value_len parameter.
 *
 * If flags contains WA_F_FMT_HEX, hex-decode the value.  If flags contains
 * WA_F_COPY_VALUE or WA_F_FMT_HEX, return a copy of the value rather than a
 * pointer into the attribute.
 *
 * Returns WA_ERR_NONE, WA_ERR_NOT_FOUND, WA_ERR_CORRUPT, or WA_ERR_NO_MEM.
 */
int webauth_attr_list_get(WEBAUTH_ATTR_LIST *, const char *name, void **value,
                          size_t *value_len, unsigned int flags)
    __attribute__((__nonnull__));

/*
 * Retrieve a string attribute by name.  Stores the string in value and the
 * length of the string in value_len.  Takes the same flags as
 * webauth_attr_list_get.  Returns WA_ERR_NONE, WA_ERR_NOT_FOUND,
 * WA_ERR_CORRUPT, or WA_ERR_NO_MEM.
 */
int webauth_attr_list_get_str(WEBAUTH_ATTR_LIST *, const char *name,
                              char **value, size_t *value_len,
                              unsigned int flags)
    __attribute__((__nonnull__));

/*
 * Retrieve a numeric attribute by name, storing it in value.  Takes the same
 * flags as webauth_attr_list_get, but WA_F_COPY_VALUE is meaningless.
 * Returns WA_ERR_NONE, WA_ERR_NOT_FOUND, WA_ERR_CORRUPT, or WA_ERR_NO_MEM.
 */
int webauth_attr_list_get_uint32(WEBAUTH_ATTR_LIST *, const char *name,
                                 uint32_t *value, unsigned int flags)
    __attribute__((__nonnull__));
int webauth_attr_list_get_int32(WEBAUTH_ATTR_LIST *, const char *name,
                                int32_t *value, unsigned int flags)
    __attribute__((__nonnull__));
int webauth_attr_list_get_time(WEBAUTH_ATTR_LIST *, const char *name,
                               time_t *value, unsigned int flags)
    __attribute__((__nonnull__));

/*
 * Searches for the named attribute in the list and returns the index in i and
 * WA_ERR_NONE or sets i to -1 and returns WA_ERR_NOT_FOUND.
 */
int webauth_attr_list_find(WEBAUTH_ATTR_LIST *, const char *name, ssize_t *i)
    __attribute__((__nonnull__));

/*
 * Frees the memory associated with an attribute list, including all the
 * attributes in the list.
 */
void webauth_attr_list_free(WEBAUTH_ATTR_LIST *)
    __attribute__((__nonnull__));

/*
 * Given an array of attributes, returns the amount of space required to
 * encode them.
 */
size_t webauth_attrs_encoded_length(const WEBAUTH_ATTR_LIST *)
    __attribute__((__nonnull__));

/*
 * Given an array of attributes, encode them into the buffer.  max_buffer_len
 * must be set to the maxium size of the output buffer.  output is NOT
 * null-terminated Returns WA_ERR_NONE or WA_ERR_NO_ROOM.
 */
int webauth_attrs_encode(const WEBAUTH_ATTR_LIST *, char *output,
                         size_t *output_len, size_t max_output_len)
    __attribute__((__nonnull__));

/*
 * Decodes the given buffer into an array of attributes.  The buffer is
 * modifed as part of the decoding.  Returns WA_ERR_NONE, WA_ERR_CORRUPT, or
 * WA_ERR_NO_MEM.
 */
int webauth_attrs_decode(char *, size_t, WEBAUTH_ATTR_LIST **)
    __attribute__((__nonnull__));

/* Allocate a new buffer and initialize its contents. */
struct buffer *wai_buffer_new(apr_pool_t *)
    __attribute__((__nonnull__));

/*
 * Resize a buffer to be at least as large as the provided size.  Invalidates
 * pointers into the buffer.
 */
void wai_buffer_resize(struct buffer *, size_t);

/* Set the buffer contents, ignoring anything currently there. */
void wai_buffer_set(struct buffer *, const char *data, size_t length)
    __attribute__((__nonnull__));

/* Append data to the buffer. */
void wai_buffer_append(struct buffer *, const char *data, size_t length)
    __attribute__((__nonnull__));

/* Append printf-style data to the buffer. */
void wai_buffer_append_sprintf(struct buffer *, const char *, ...)
    __attribute__((__nonnull__, __format__(printf, 2, 3)));
void wai_buffer_append_vsprintf(struct buffer *, const char *, va_list)
    __attribute__((__nonnull__));

/*
 * Find a given string in the buffer.  Returns the offset of the string (with
 * the same meaning as start) in offset if found, and returns true if the
 * terminator is found and false otherwise.
 */
bool wai_buffer_find_string(struct buffer *, const char *, size_t start,
                            size_t *offset)
    __attribute__((__nonnull__));

/*
 * Decode the binary attribute representation into the struct pointed to by
 * data following the provided rules.  Takes a separate pool to use for memory
 * allocation.
 */
int wai_decode(struct webauth_context *, apr_pool_t *,
               const struct wai_encoding *, const void *input, size_t,
               void *data)
    __attribute__((__nonnull__));

/*
 * Similar to wai_decode, but decodes a WebAuth token, including handling the
 * determination of the type of the token from the attributes.  Uses the
 * memory pool from the WebAuth context.  This does not perform any sanity
 * checking on the token data; that must be done by higher-level code.
 */
int wai_decode_token(struct webauth_context *, const void *input, size_t,
                     struct webauth_token *)
    __attribute__((__nonnull__));

/*
 * Encode the struct pointed to by data according to given the rules into the
 * output parameter, storing the encoded data length.  The result will be in
 * WebAuth attribute encoding format.  Takes a separate pool to use for memory
 * allocation.
 */
int wai_encode(struct webauth_context *, apr_pool_t *,
               const struct wai_encoding *, const void *data, void **,
               size_t *)
    __attribute__((__nonnull__));

/*
 * Similar to wai_encode, but encodes a WebAuth token, including adding the
 * appropriate encoding of the token type.  This does not perform any sanity
 * checking on the token data; that must be done by higher-level code.
 */
int wai_encode_token(struct webauth_context *,
                     const struct webauth_token *, void **, size_t *)
    __attribute__((__nonnull__));

/* Set the internal WebAuth error message and error code. */
void wai_error_set(struct webauth_context *, int err, const char *, ...)
    __attribute__((__nonnull__, __format__(printf, 3, 4)));

/* The same, but include the string expansion of an APR error. */
void wai_error_set_apr(struct webauth_context *, int err, apr_status_t,
                       const char *, ...)
    __attribute__((__nonnull__, __format__(printf, 4, 5)));

/* The same, but include the string expansion of an errno. */
void wai_error_set_system(struct webauth_context *, int err, int syserr,
                          const char *, ...)
    __attribute__((__nonnull__, __format__(printf, 4, 5)));

/* Read the contents of a file into memory. */
int wai_file_read(struct webauth_context *, const char *, void **, size_t *)
    __attribute__((__nonnull__));

/* Replace the contents of a file with the provided data. */
int wai_file_write(struct webauth_context *, const void *, size_t,
                   const char *path)
    __attribute__((__nonnull__));

/*
 * Returns the amount of space required to hex encode data of the given
 * length.  Returned length does NOT include room for a null-termination.
 */
size_t webauth_hex_encoded_length(size_t length)
    __attribute__((__const__));

/*
 * Returns the amount of space required to decode the hex encoded data of the
 * given length.  Returned length does NOT include room for a
 * null-termination.
 *
 * Returns WA_ERR_NONE on succes, or WA_ERR_CORRUPT if length is not greater
 * then 0 and a multiple of 2.
 */
int webauth_hex_decoded_length(size_t length, size_t *out_length)
    __attribute__((__nonnull__));

/*
 * Hex-encodes the given data.  Does NOT null-terminate.  output can point to
 * input as long as max_output_len is long enough.
 *
 * Returns WA_ERR_NONE or WA_ERR_NO_ROOM.
 */
int webauth_hex_encode(char *input, size_t input_len,
                       char *output, size_t *output_len,
                       size_t max_output_len)
    __attribute__((__nonnull__));

/*
 * Hex-decodes the given data.  Does NOT null-terminate.  output can point to
 * input.
 *
 * Returns WA_ERR_NONE, WA_ERR_NO_ROOM, or WA_ERR_CORRUPT.
 */
int webauth_hex_decode(char *input, size_t input_len,
                       char *output, size_t *output_length,
                       size_t max_output_len)
    __attribute__((__nonnull__));

/*
 * Map a token type code to the corresponding encoding rule set and data
 * pointer.  Takes the token struct (which must have the type filled out), and
 * stores a pointer to the encoding rules and a pointer to the correct data
 * portion of the token struct in the provided output arguments.  Returns an
 * error code, which will be set to an error if the token type is not
 * recognized.
 */
int wai_token_encoding(struct webauth_context *, const struct webauth_token *,
                       const struct wai_encoding **, const void **)
    __attribute__((__nonnull__));

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
int wai_xml_content(struct webauth_context *, apr_xml_elem *, const char **)
    __attribute__((__nonnull__));

/* Undo default visibility change. */
#pragma GCC visibility pop

END_DECLS

#endif /* !LIB_INTERNAL_H */
