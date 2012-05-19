/*
 * Interface to the libwebauth utility library.
 *
 * The libwebauth utility library contains the basic token handling functions
 * used by all other parts of the webauth code.  It contains functions to
 * encode and decode lists of attributes, generate tokens from them, encode
 * and decode tokens in base64 or hex encoding, and some additional utility
 * functions to generate random numbers or new AES keys.
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

/* Flags for webauth_krb5_get_principal. */
enum webauth_krb5_canon {
    WA_KRB5_CANON_NONE  = 0,    /* Do not canonicalize principals. */
    WA_KRB5_CANON_LOCAL = 1,    /* Strip the local realm. */
    WA_KRB5_CANON_STRIP         /* Strip any realm. */
};


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

/* A WebAuth Kerberos context for Kerberos support functions. */
typedef struct webauth_krb5_ctxt WEBAUTH_KRB5_CTXT;


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


/*
 * RANDOM DATA
 */

/*
 * Returns pseudo random bytes, suitable for use a nonce or random data, but
 * not necessarily suitable for use as an encryption key.  Use
 * webauth_random_key for that.  The number of bytes specified is placed in
 * the output buffer, which must contain enough room to contain the requested
 * number of bytes.
 *
 * Returns WA_ERR_NONE on success, or WA_ERR_RAND_FAILURE on error.
 */
int webauth_random_bytes(unsigned char *, size_t);

/*
 * Used to create random bytes suitable for use as a key.  The number of bytes
 * specified is placed in the output buffer, which must contain enough room to
 * hold that many bytes.
 *
 * Returns WA_ERR_NONE on success, or WA_ERR_RAND_FAILURE on error.
 */
int webauth_random_key(unsigned char *, size_t);


/*
 * KERBEROS
 */

/*
 * Create new webauth krb5 context for use with all the webauth_krb5_* calls.
 * The context must be freed with webauth_krb5_free when finished.  One of the
 * various webauth_krb5_init_via* calls should be made before the context is
 * fully usable, except when using webauth_krb5_rd_req.
 *
 * If this call returns WA_ERR_KRB5, the only calls that can be made using the
 * context are webauth_krb5_error_code and webauth_krb5_error_message.  The
 * context still needs to be freed.
 *
 * Returns WA_ERR_NONE, WA_ERR_NO_MEM, or WA_ERR_KRB5.
 */
int webauth_krb5_new(WEBAUTH_KRB5_CTXT **);

/*
 * Sets an internal flag in the context that causes webauth_krb5_free to close
 * the credential cache instead of destroying it.  This call is only useful
 * when you need a file-based cache to remain intact after a call to
 * webauth_krb5_free.
 *
 * Currently always returns WA_ERR_NONE.
 */
int webauth_krb5_keep_cred_cache(WEBAUTH_KRB5_CTXT *);

/*
 * Frees a context.  If the credential cache hasn't been closed, it will be
 * destroyed unless webauth_krb5_keep_cred_cache was previously called with
 * this context.
 *
 * Currently always returns WA_ERR_NONE.
 */
int webauth_krb5_free(WEBAUTH_KRB5_CTXT *);

/*
 * Returns the internal Kerberos error code from the last Kerberos call or 0
 * if there wasn't any error.  This code is internal to the Kerberos
 * libraries; one can't do much useful with it except report it.
 */
int webauth_krb5_error_code(WEBAUTH_KRB5_CTXT *);

/*
 * Returns the error message from the last Kerberos call or the string
 * "success" if the error code was 0.  The returned string points to internal
 * storage and does not need to be freed.
 */
const char *webauth_krb5_error_message(WEBAUTH_KRB5_CTXT *);

/*
 * Change the password for a principal.  The credential cache to use for the
 * password change is already set up in a given context, as is the principal
 * to change.
 *
 * Returns WA_ERR_NONE or WA_ERR_KRB5.
 */
int webauth_krb5_change_password(WEBAUTH_KRB5_CTXT *, const char *password);

/*
 * Initialize a context with username/password to obtain a ticket-granting
 * ticket (TGT).  The TGT is verified using the specified keytab, unless
 * the keytab is NULL.  The TGT will be placed in the specified cache, or a
 * memory cache if cache_name is NULL.
 *
 * If server_principal is NULL, the first principal in the keytab will be
 # used.  Otherwise, the specifed server principal will be used.
 *
 * If get_principal is not NULL, then we acquire credentials for that
 * principal instead.  The purpose of this is to get credentials for
 * kadmin/changepw with a user's username and password.
 *
 * server_principal_out will be set to the fully qualified server principal
 * used, unless the keytab is NULL.  If WA_ERR_NONE is returned, then it
 * should instead be freed.
 *
 * Returns WA_ERR_NONE, WA_ERR_LOGIN_FAILED, WA_ERR_NO_MEM, or WA_ERR_KRB5.
 */
int webauth_krb5_init_via_password(WEBAUTH_KRB5_CTXT *, const char *username,
                                   const char *password,
                                   const char *get_principal,
                                   const char *keytab,
                                   const char *server_principal,
                                   const char *cache_name,
                                   char **server_principal_out);

/*
 * Initialize a context with a keytab.  Credentials will be placed in the
 * specified cache, or a memory cache if cache_name is NULL.
 *
 * If server_princpal is NULL, the first principal in the keytab will be used;
 * otherwise, the specifed server principal will be used.
 *
 * Returns WA_ERR_NONE, WA_ERR_LOGIN_FAILED, or WA_ERR_KRB5.
 */
int webauth_krb5_init_via_keytab(WEBAUTH_KRB5_CTXT *, const char *path,
                                 const char *server_principal,
                                 const char *cache_name);

/*
 * Initialize a context with an existing credential cache.  If cache_name is
 * NULL, krb5_cc_default is used.
 *
 * Returns WA_ERR_NONE or WA_ERR_KRB5.
 */
int webauth_krb5_init_via_cache(WEBAUTH_KRB5_CTXT *, const char *cache_name);

/*
 * Initialize a context with a credential that was created via
 * webauth_krb5_export_tgt or webauth_krb5_export_ticket.  If cache_name is
 * NULL, a memory cache is used.
 *
 * Returns WA_ERR_NONE or WA_ERR_KRB5.
 */
int webauth_krb5_init_via_cred(WEBAUTH_KRB5_CTXT *, const void *cred,
                               size_t cred_len, const char *cache_name);

/*
 * Export the TGT from the context and also store the expiration time.  This
 * is used to construct a proxy-token after a call to
 * webauth_krb5_init_via_password or webauth_krb5_init_via_tgt.  Memory
 * returned in TGT should be freed when it is no longer needed.
 *
 * Returns WA_ERR_NONE, WA_ERR_NO_MEM, or WA_ERR_KRB5.
 */
int webauth_krb5_export_tgt(WEBAUTH_KRB5_CTXT *, char **, size_t *, time_t *);

/*
 * Import a credential (TGT or ticket) that was exported via
 * webauth_krb5_export_{ticket,tgt}.  The context should have been initialized
 * by calling webauth_krb5_init_via_import first.
 *
 * Returns WA_ERR_NONE, WA_ERR_CORRUPT, WA_ERR_NO_MEM, or WA_ERR_KRB5.
 */
int webauth_krb5_import_cred(WEBAUTH_KRB5_CTXT *, const char *, size_t);

/*
 * Get the string form of the principal from the context.  This should only be
 * called after a successful call to webauth_krb5_init_via_*.
 *
 * If the canon argument is WA_KRB5_CANON_LOCAL, krb5_aname_to_localname is
 * called on the principal.  If krb5_aname_to_localname returns an error, the
 * fully-qualified principal name is returned.
 *
 * If the canon argument is WA_KRB5_CANON_STRIP, the realm is stripped,
 * regardless of what it is.
 *
 * If the canon argument is WA_KRB5_CANON_NONE, the fully-qualified Kerberos
 * principal is always returned.
 *
 * principal should be freed when it is no longer needed.
 *
 * Returns WA_ERR_NONE, WA_ERR_INVALID_CONTEXT, or WA_ERR_KRB5.
 */
int webauth_krb5_get_principal(WEBAUTH_KRB5_CTXT *, char **principal,
                               enum webauth_krb5_canon canon);

/*
 * Get the ticket cache from the context.  This is the string suitable for
 * storing in KRB5CCNAME.  It should only be called after a successful call to
 * webauth_krb5_init_via_*.  It should be freed when it is no longer needed.
 *
 * Returns WA_ERR_NONE, WA_ERR_INVALID_CONTEXT, WA_ERR_NO_MEM, or WA_ERR_KRB5.
 */
int webauth_krb5_get_cache(WEBAUTH_KRB5_CTXT *, char **);

/*
 * Get the realm from the context.  This should only be called after a
 * successful call to webauth_krb5_init_via_*.  realm should be freed when it
 * is no longer needed.
 *
 * Returns WA_ERR_NONE, WA_ERR_INVALID_CONTEXT, or WA_ERR_NO_MEM.
 */
int webauth_krb5_get_realm(WEBAUTH_KRB5_CTXT *, char **);

/*
 * Export a ticket for the given server_principal.  ticket should be freed
 * when no longer needed.  This should only be called after one of the
 * webauth_krb5_init_via_* methods has been successfully called.
 *
 * Returns WA_ERR_NONE, WA_ERR_NO_MEM, or WA_ERR_KRB5.
 */
int webauth_krb5_export_ticket(WEBAUTH_KRB5_CTXT *,
                               const char *server_principal,
                               char **ticket, size_t *ticket_len,
                               time_t *expiration);

/*
 * Calls krb5_mk_req using the specified service and stores the resulting
 * request in req, which should be freed when it is no longer needed.  This
 * should only be called after one of the webauth_krb5_init_via_* methods has
 * been successfully called.
 *
 * Returns WA_ERR_NONE, WA_ERR_KRB5, or WA_ERR_NO_MEM.
 */
int webauth_krb5_mk_req(WEBAUTH_KRB5_CTXT *, const char *server_principal,
                        char **req, size_t *length);

/*
 * Calls krb5_rd_req on the specified request and returns the client principal
 * in client_principal on success.  client_principal should be freed when it
 * is no longer needed.
 *
 * If server_princpal is NULL, the first principal in the keytab will be used;
 * otherwise, the specifed server principal will be used.
 *
 * If local is 1, then krb5_aname_to_localname is called on the principal.  If
 * krb5_aname_to_localname returns an error, the fully-qualified principal
 * name is returned.
 *
 * This function can be called any time after calling webauth_krb5_new.
 *
 * Returns WA_ERR_NONE, WA_ERR_KRB5, or WA_ERR_NO_MEM.
 */
int webauth_krb5_rd_req(WEBAUTH_KRB5_CTXT *, const char *req, size_t length,
                        const char *keytab, const char *server_principal,
                        char **client_principal, int local);

/*
 * Similar to webauth_krb5_mk_req, but additionally calls krb5_mk_priv
 * on in_data and places the encrypted data in the out_data buffer.
 *
 * Returns WA_ERR_NONE, WA_ERR_KRB5, or WA_ERR_NO_MEM.
 */
int webauth_krb5_mk_req_with_data(WEBAUTH_KRB5_CTXT *,
                                  const char *server_principal,
                                  char **req, size_t *length,
                                  char *in_data, size_t in_length,
                                  char **out_data, size_t *out_length);

/*
 * Similar to webauth_krb5_rd_req, but additionally calls krb5_rd_priv
 * on in_data and places the decrypted data in the out_data buffer.
 *
 * Returns WA_ERR_NONE, WA_ERR_KRB5, or WA_ERR_NO_MEM.
 */
int webauth_krb5_rd_req_with_data(WEBAUTH_KRB5_CTXT *,
                                  const char *req, size_t length,
                                  const char *keytab,
                                  const char *server_principal,
                                  char **out_server_princ,
                                  char **client_principal, int local,
                                  char *in_data, size_t in_length,
                                  char **out_data, size_t *out_length);

END_DECLS

#endif /* !WEBAUTH_H */
