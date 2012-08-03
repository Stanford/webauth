/*
 * Interface to the libwebauth utility library.
 *
 * The libwebauth utility library contains the basic token handling functions
 * used by all other parts of the webauth code.  It contains functions to
 * encode and decode lists of attributes, generate tokens from them, encode
 * and decode tokens in base64 or hex encoding, and other functions.
 *
 * This file will be going away, replaced by separate include files under
 * the webauth directory.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2003, 2008, 2009, 2010, 2011, 2012
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

#ifndef WEBAUTH_H
#define WEBAUTH_H 1

#include <webauth/defines.h>

#include <sys/types.h>
#include <time.h>

BEGIN_DECLS

/*
 * ERROR AND STATUS CODES
 */

/*
 * Protocol error codes (PEC) for error-token and XML messages.  These numbers
 * must not change, as they are part of the protocol
 */
typedef enum {
    WA_PEC_SERVICE_TOKEN_EXPIRED       =  1,
    WA_PEC_SERVICE_TOKEN_INVALID       =  2, /* Can't decrypt / bad format */
    WA_PEC_PROXY_TOKEN_EXPIRED         =  3,
    WA_PEC_PROXY_TOKEN_INVALID         =  4, /* Can't decrypt / bad format */
    WA_PEC_INVALID_REQUEST             =  5, /* Missing/incorrect data, etc */
    WA_PEC_UNAUTHORIZED                =  6, /* Access denied */
    WA_PEC_SERVER_FAILURE              =  7, /* Server failure, try again */
    WA_PEC_REQUEST_TOKEN_STALE         =  8,
    WA_PEC_REQUEST_TOKEN_INVALID       =  9, /* Can't decrypt / bad format */
    WA_PEC_GET_CRED_FAILURE            = 10, /* Can't get credential */
    WA_PEC_REQUESTER_KRB5_CRED_INVALID = 11, /* <requesterCredential> was bad */
    WA_PEC_LOGIN_TOKEN_STALE           = 12,
    WA_PEC_LOGIN_TOKEN_INVALID         = 13, /* Can't decrypt / bad format */
    WA_PEC_LOGIN_FAILED                = 14, /* Username/passwword failed */
    WA_PEC_PROXY_TOKEN_REQUIRED        = 15, /* Missing required proxy-token */
    WA_PEC_LOGIN_CANCELED              = 16, /* User cancelled login */
    WA_PEC_LOGIN_FORCED                = 17, /* User must re-login */
    WA_PEC_USER_REJECTED               = 18, /* Principal not permitted */
    WA_PEC_CREDS_EXPIRED               = 19, /* User password expired */
    WA_PEC_MULTIFACTOR_REQUIRED        = 20, /* Multifactor login required */
    WA_PEC_MULTIFACTOR_UNAVAILABLE     = 21, /* MF required, not available */
    WA_PEC_LOGIN_REJECTED              = 22, /* User may not log on now */
    WA_PEC_LOA_UNAVAILABLE             = 23, /* Requested LoA not available */
    WA_PEC_AUTH_REJECTED               = 24, /* Auth to this site rejected */
} WEBAUTH_ET_ERR;


/*
 * PROTOCOL CONSTANTS
 */

/* Token constants. */
#define WA_TK_APP_STATE            "as"
#define WA_TK_COMMAND              "cmd"
#define WA_TK_CRED_DATA            "crd"
#define WA_TK_CRED_SERVICE         "crs"
#define WA_TK_CRED_TYPE            "crt"
#define WA_TK_CREATION_TIME        "ct"
#define WA_TK_ERROR_CODE           "ec"
#define WA_TK_ERROR_MESSAGE        "em"
#define WA_TK_EXPIRATION_TIME      "et"
#define WA_TK_INITIAL_FACTORS      "ia"
#define WA_TK_SESSION_KEY          "k"
#define WA_TK_LOA                  "loa"
#define WA_TK_LASTUSED_TIME        "lt"
#define WA_TK_OTP                  "otp"
#define WA_TK_PASSWORD             "p"
#define WA_TK_PROXY_DATA           "pd"
#define WA_TK_PROXY_SUBJECT        "ps"
#define WA_TK_PROXY_TYPE           "pt"
#define WA_TK_REQUEST_OPTIONS      "ro"
#define WA_TK_REQUESTED_TOKEN_TYPE "rtt"
#define WA_TK_RETURN_URL           "ru"
#define WA_TK_SUBJECT              "s"
#define WA_TK_SUBJECT_AUTH         "sa"
#define WA_TK_SUBJECT_AUTH_DATA    "sad"
#define WA_TK_SESSION_FACTORS      "san"
#define WA_TK_TOKEN_TYPE           "t"
#define WA_TK_USERNAME             "u"
#define WA_TK_WEBKDC_TOKEN         "wt"

/* Token type constants. */
#define WA_TT_WEBKDC_SERVICE       "webkdc-service"
#define WA_TT_WEBKDC_PROXY         "webkdc-proxy"
#define WA_TT_REQUEST              "req"
#define WA_TT_ERROR                "error"
#define WA_TT_ID                   "id"
#define WA_TT_PROXY                "proxy"
#define WA_TT_CRED                 "cred"
#define WA_TT_APP                  "app"
#define WA_TT_LOGIN                "login"

/* Subject auth type constants. */
#define WA_SA_KRB5                 "krb5"
#define WA_SA_WEBKDC               "webkdc"

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


/*
 * API CONSTANTS
 */

/* Flags to webauth_attr_list_add functions. */
#define WA_F_NONE       0x00
#define WA_F_COPY_VALUE 0x01
#define WA_F_COPY_NAME  0x02
#define WA_F_FMT_STR    0x04
#define WA_F_FMT_HEX    0x08
#define WA_F_COPY_BOTH  (WA_F_COPY_NAME | WA_F_COPY_VALUE)


/*
 * TYPES
 */

/*
 * Holds a generic name/value attribute for constructing and parsing tokens.
 * Names must not contain "=", and values may contain binary data, since the
 * length must be specified.
 */
typedef struct {
    const char *name;           /* Name of attribute. */
    unsigned int flags;         /* flags passed in during add */
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
 * BASE64 ENCODING AND DECODING
 */

/*
 * Returns the amount of space required to base64-encode data.  Returned
 * length does NOT include room for nul-termination.
 */
size_t webauth_base64_encoded_length(size_t length);

/*
 * Amount of space required to base64-decode data.
 *
 * Returns the amount of space required to base64-decode data of the given
 * length.  Does not actually attempt to ensure that the input contains a
 * valid base64-encoded string, other than checking the last two characters
 * for padding ("=").  Returned length does NOT include room for
 * nul-termination.
 *
 * Returns WA_ERR_NONE on success, or WA_ERR_CORRUPT if length is not greater
 * than 0 and a multiple of 4, since the input data cannot be valid
 * base64-encoded data.
 */
int webauth_base64_decoded_length(const char *, size_t length,
                                  size_t *decoded_length);

/*
 * Base64-encode the given data.
 *
 * Does NOT nul-terminate.  Output cannot point to the same memory space as
 * input.
 *
 * Returns WA_ERR_NONE on success, or WA_ERR_NO_ROOM if encoding the provided
 * data would require more space than max_output_len.
 */
int webauth_base64_encode(const char *input, size_t input_len,
                          char *output, size_t *output_len,
                          size_t max_output_len);

/*
 * Base64-decode the given data.
 *
 * Does NOT nul-terminate.  Output may point to input.
 *
 * Returns WA_ERR_NONE on success, WA_ERR_NO_ROOM if decoding the provided
 * data would require more space than max_output_len, or WA_ERR_CORRUPT if
 * input is not valid base64-encoded data.
 */
int webauth_base64_decode(char *input, size_t input_len,
                          char *output, size_t *output_len,
                          size_t max_output_len);


/*
 * HEX ENCODING AND DECODING
 */

/*
 * Returns the amount of space required to hex encode data of the given
 * length.  Returned length does NOT include room for a null-termination.
 */
size_t webauth_hex_encoded_length(size_t length);

/*
 * Returns the amount of space required to decode the hex encoded data of the
 * given length.  Returned length does NOT include room for a
 * null-termination.
 *
 * Returns WA_ERR_NONE on succes, or WA_ERR_CORRUPT if length is not greater
 * then 0 and a multiple of 2.
 */
int webauth_hex_decoded_length(size_t length, size_t *out_length);

/*
 * Hex-encodes the given data.  Does NOT null-terminate.  output can point to
 * input as long as max_output_len is long enough.
 *
 * Returns WA_ERR_NONE or WA_ERR_NO_ROOM.
 */
int webauth_hex_encode(char *input, size_t input_len,
                       char *output, size_t *output_len,
                       size_t max_output_len);

/*
 * Hex-decodes the given data.  Does NOT null-terminate.  output can point to
 * input.
 *
 * Returns WA_ERR_NONE, WA_ERR_NO_ROOM, or WA_ERR_CORRUPT.
 */
int webauth_hex_decode(char *input, size_t input_len,
                       char *output, size_t *output_length,
                       size_t max_output_len);


/*
 * ATTRIBUTE MANIPULATION
 */

/* Creates a new attribute list, returning it or NULL if no memory. */
WEBAUTH_ATTR_LIST *webauth_attr_list_new(size_t initial_capacity);

/*
 * Adds an attribute to the attribute list, growing the list if need be.  Both
 * the name and value are copied, and value always has a null added to the end
 * of it.
 *
 * Returns WA_ERR_NONE or WA_ERR_NO_MEM.
 */
int webauth_attr_list_add(WEBAUTH_ATTR_LIST *, const char *name, void *value,
                          size_t vlen, unsigned int flags);

/*
 * Adds an attribute string to the attribute list, growing the list if need
 * be.  Name and value are not copied; the pointers are added directly.  If
 * vlen is 0, then strlen(value) is used.
 *
 * Returns WA_ERR_NONE or WA_ERR_NO_MEM.
 */
int webauth_attr_list_add_str(WEBAUTH_ATTR_LIST *, const char *name,
                              const char *value, size_t vlen,
                              unsigned int flags);


/*
 * Adds a number to an attribute list, growing the list if need be.  All of
 * these interfaces imply WA_COPY_VALUE.
 *
 * Returns WA_ERR_NONE or WA_ERR_NO_MEM.
 */
int webauth_attr_list_add_uint32(WEBAUTH_ATTR_LIST *, const char *name,
                                 uint32_t value, unsigned int flags);
int webauth_attr_list_add_int32(WEBAUTH_ATTR_LIST *, const char *name,
                                int32_t value, unsigned int flags);
int webauth_attr_list_add_time(WEBAUTH_ATTR_LIST *, const char *name,
                               time_t value, unsigned int flags);

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
                          size_t *value_len, unsigned int flags);

/*
 * Retrieve a string attribute by name.  Stores the string in value and the
 * length of the string in value_len.  Takes the same flags as
 * webauth_attr_list_get.
 *
 * Returns WA_ERR_NONE, WA_ERR_NOT_FOUND, WA_ERR_CORRUPT, or WA_ERR_NO_MEM.
 */
int webauth_attr_list_get_str(WEBAUTH_ATTR_LIST *, const char *name,
                              char **value, size_t *value_len,
                              unsigned int flags);

/*
 * Retrieve a numeric attribute by name, storing it in value.  Takes the same
 * flags as webauth_attr_list_get, but WA_F_COPY_VALUE is meaningless.
 *
 * Returns WA_ERR_NONE, WA_ERR_NOT_FOUND, WA_ERR_CORRUPT, or WA_ERR_NO_MEM.
 */
int webauth_attr_list_get_uint32(WEBAUTH_ATTR_LIST *, const char *name,
                                 uint32_t *value, unsigned int flags);
int webauth_attr_list_get_int32(WEBAUTH_ATTR_LIST *, const char *name,
                                int32_t *value, unsigned int flags);
int webauth_attr_list_get_time(WEBAUTH_ATTR_LIST *, const char *name,
                               time_t *value, unsigned int flags);

/*
 * Searches for the named attribute in the list and returns the index in i and
 * WA_ERR_NONE or sets i to -1 and returns WA_ERR_NOT_FOUND.
 */
int webauth_attr_list_find(WEBAUTH_ATTR_LIST *, const char *name, ssize_t *i);

/*
 * Frees the memory associated with an attribute list, including all the
 * attributes in the list.
 */
void webauth_attr_list_free(WEBAUTH_ATTR_LIST *);

/*
 * Given an array of attributes, returns the amount of space required to
 * encode them.
 */
size_t webauth_attrs_encoded_length(const WEBAUTH_ATTR_LIST *);

/*
 * Given an array of attributes, encode them into the buffer.  max_buffer_len
 * must be set to the maxium size of the output buffer.  output is NOT
 * null-terminated
 *
 * Returns WA_ERR_NONE or WA_ERR_NO_ROOM.
 */
int webauth_attrs_encode(const WEBAUTH_ATTR_LIST *, char *output,
                         size_t *output_len, size_t max_output_len);

/*
 * Decodes the given buffer into an array of attributes.  The buffer is
 * modifed as part of the decoding.
 *
 * Returns WA_ERR_NONE, WA_ERR_CORRUPT, or WA_ERR_NO_MEM.
 */
int webauth_attrs_decode(char *, size_t, WEBAUTH_ATTR_LIST **);

END_DECLS

#endif /* !WEBAUTH_H */
