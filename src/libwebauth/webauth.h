/** \file
 * Interface to the libwebauth utility library.
 *
 * The libwebauth utility library contains the basic token handling functions
 * used by all other parts of the webauth code.  It contains functions to
 * encode and decode lists of attributes, generate tokens from them, encode
 * and decode tokens in base64 or hex encoding, and some additional utility
 * functions to generate random numbers or new AES keys.
 *
 * $Id$
 */

#ifndef _WEBAUTH_H
#define _WEBAUTH_H

#ifdef  __cplusplus
//extern "C" {
#endif

/******************** error codes ********************/

/** libwebauth error codes.
 *
 * Many libwebauth functions return an error status, or 0 on success.  For
 * those functions, the error codes are chosen from the following enum.
 */
typedef enum {
    WA_ERR_NO_ROOM = -2000,  /**< Supplied buffer too small. */
    WA_ERR_CORRUPT,          /**< Data is incorrectly formatted. */
    WA_ERR_NO_MEM,           /**< No memory. */
    WA_ERR_BAD_HMAC,         /**< HMAC check failed. */
    WA_ERR_RAND_FAILURE,     /**< Unable to get random data. */

    /* must be last */
    WA_ERR_NONE = 0          /**< No error occured. */
    /* must be last */
}  WEBAUTH_ERR;    

/******************** constants for token attributes **********/

#define WA_TK_APP_NAME "an"
#define WA_TK_CRED_DATA "crd"
#define WA_TK_CRED_TYPE "crt"
#define WA_TK_CREATION_TIME "ct"
#define WA_TK_ERROR_CODE "ec"
#define WA_TK_ERROR_MESSAGE "em"
#define WA_TK_EXPIRATION_TIME "et"
#define WA_TK_INACTIVITY_TIMEOUT "it"
#define WA_TK_SESSION_KEY "k"
#define WA_TK_LASTUSED_TIME "lt"
#define WA_TK_PROXY_TYPE "prt"
#define WA_TK_PROXY_DATA "prd"
#define WA_TK_PROXY_OWNER "pro"
#define WA_TK_POST_URL "pu"
#define WA_TK_REQUEST_REASON "rr"
#define WA_TK_REQUESTED_TOKEN_TYPE "rt"
#define WA_TK_REQUESTED_TOKEN_HASH "rth"
#define WA_TK_RETURN_URL "ru"
#define WA_TK_SUBJECT "s"
#define WA_TK_SUBJECT_AUTHENTICATOR "sa"
#define WA_TK_SERVICE_AUTHENTICATOR_NAME "san"
#define WA_TK_TOKEN_TYPE "t"
#define WA_TK_TOKEN_VERSION "ver"

/******************** other constants *****************/

/* supported AES key sizes */
#define WA_AES_128 16
#define WA_AES_192 24
#define WA_AES_256 32

/********************* convenience macros to set attrs **********/
#define WA_ATTR_STR(a, n, v) \
  { WEBAUTH_ATTR *t = &a; t->name=n; t->value=v; t->length=strlen(t->value);}

#define WA_ATTR_BIN(a, n, v, l) \
  { WEBAUTH_ATTR *t= &a; t->name=n; t->value=v; t->length=l;}

/******************** types ********************/

/** A generic attribute.
 *
 * Holds a generic name/value attribute for constructing and parsing tokens.
 * Names <b>must not</b> contain "=", and values \b may contain binary data,
 * since the length \b must be specified.
 */
typedef struct {
    char *name;                 /**< Name of attribute. */
    void *value;                /**< Value of attribute (binary data). */
    int length;                 /**< Length of attribute value in bytes. */
} WEBAUTH_ATTR;

/* an AES key */
typedef struct webauth_aes_key WEBAUTH_AES_KEY;

/******************** base64 ********************/

/** Amount of space required to base64-encode data.
 *
 * Returns the amount of space required to base64-encode data.  Returned
 * length does \b NOT include room for nul-termination.
 *
 * \param length Length of data to be encoded.
 * \return Space base64-encoded data will require.
 */
int webauth_base64_encoded_length(int length);

/** Amount of space required to base64-decode data.
 *
 * Returns the amount of space required to base64-decode data of the given
 * length.  Does not actually attempt to ensure that the input contains a
 * valid base64-encoded string, other than checking the last two characters
 * for padding ("=").  Returned length does \b NOT include room for
 * nul-termination.
 *
 * \param input Base64-encoded data.
 * \param length Length of base64-encoded data.
 *
 * \return Returns the required space in bytes provided that length is
 *   greater than 0 and a multiple of 4.  Otherwise, returns #WA_ERR_CORRUPT
 *   since the input data cannot be valid base64-encoded data.
 */
int webauth_base64_decoded_length(const unsigned char *input, int length);

/** Base64-encode the given data.
 *
 * Does \b NOT nul-terminate.  Output cannot point to the same memory space as
 * input.
 *
 * \param input Data to encode.
 * \param input_len Length of data to encode.
 * \param output Buffer into which to write base64-encoded data.
 * \param max_output_len Maximum number of bytes to write to \a output.
 *
 * \return Returns the number of bytes written to \a output, or
 *   #WA_ERR_NO_ROOM if encoding the provided data would require more space
 *   than \a max_output_len.
 */
int webauth_base64_encode(const unsigned char *input,
                          int input_len, 
                          unsigned char *output,
                          int max_output_len);

/** Base64-decode the given data.
 *
 * Does \b NOT nul-terminate.  Output may point to input.
 *
 * \param input Data to decode.
 * \param input_len Length of data to decode.
 * \param output Buffer into which to write base64-decoded data.
 * \param max_output_len Maximum number of bytes to write to \a output.
 *
 * \return Returns the number of bytes written to \a output, #WA_ERR_NO_ROOM
 *   if decoding the provided data would require more space than \a
 *   max_output_len, or #WA_ERR_CORRUPT if \a input is not valid
 *   base64-encoded data.
 */
int webauth_base64_decode(unsigned char *input,
                          int input_len,
                          unsigned char *output,
                          int max_output_len);

/******************** hex routines ********************/

/*
 * returns the amount of space required to hex encode data
 * of the given length. Returned length does *NOT* include room for a
 * null-termination.
 */
int webauth_hex_encoded_length(int length);


/*
 * returns the amount of space required to decode the hex encoded data
 * of the given length. Returned length does *NOT* include room for a
 * null-termination. 
 *
 * errors:
 *   WA_ERR_CORRUPT (if length is not greater then 0 and a multiple of 2)
 */
int webauth_hex_decoded_length(int length);

/*
 * hex encodes the given data, does *NOT* null-terminate.
 * output can point to input, as long as max_output_len is
 * long enough.
 *
 * returns output length or an error.
 *
 * errors:
 *   WA_ERR_NO_ROOM
 *   
 */
int webauth_hex_encode(unsigned char *input, 
                       int input_len,
                       unsigned char *output,
                       int max_output_len);


/*
 * hex decodes the given data, does *NOT* null-terminate.
 * output can point to input.
 *
 * returns output length or an error.
 *
 * errors:
 *   WA_ERR_NO_ROOM
 *   WA_ERR_CORRUPT
 */
int webauth_hex_decode(unsigned char *input,
                       int input_len,
                       unsigned char *output, 
                       int max_output_len);

/******************** attrs ********************/

/*
 * given an array of attributes, returns the amount
 * of space required to encode them.
 */

int webauth_attrs_encoded_length(const WEBAUTH_ATTR *attrs, 
                                 int num_attrs);

/*
 * given an array of attributes, encode them into the buffer.
 * max_buffer_len must be set to the maxium size of the output buffer.
 *
 * output is *NOT* null-terminated
 *
 * returns length of encoded data or an error
 *
 * errors:
 *   WA_ERR_NO_ROOM
 */

int webauth_attrs_encode(const WEBAUTH_ATTR *attrs, 
                         int num_attrs,
                         unsigned char *output,
                         int max_output_len);

/*
 * decodes the given buffer into an array of attributes.
 * The buffer is modifed, and the resulting names and
 * values in the attributes will point into the buffer.
 * All values will be null-terminated, for convenience
 * when dealing with values that are ASCII strings.
 *
 * if attrs is NULL, only returns the number of attributes
 * that would be decoded, or an error. In this case, buffer is
 * not modified, and max_num_attrs is ignored.
 *
 * returns the number of attributes decoded or an error
 *
 * errors:
 *   WA_ERR_NO_ROOM  (max attrs was too small)
 *   WA_ERR_CORRUPT
 */

int webauth_attrs_decode(unsigned char *buffer, 
                         int buffer_len,
                         WEBAUTH_ATTR *attrs,
                         int max_num_attrs);


/******************** random data ********************/

/*
 * returns pseudo random bytes, suitable for use a nonce
 * or random data, but not necessarily suitable for use
 * as an encryption key. Use webauth_random_key for that.
 * The number of bytes specified by output_len is placed in
 * output, which must contain enough room to contain the
 * requested number of bytes.
 */
int webauth_random_bytes(unsigned char *output, int num_bytes);

/*
 * used to create random bytes suitable for use as a key.
 * The number of bytes specified in key_len is placed in key, which
 * must contain enough room to hold key_len byte of data.
 */

int webauth_random_key(unsigned char *key, int key_len);

/******************** keys ********************/

/*
 * construct new AES key. 
 * key_len is the length of the key material and should
 * be WA_AES_128, WA_AES_192, or WA_AES_256.
 *
 * returns newly allocated key, or NULL on error
 *
 */

WEBAUTH_AES_KEY *webauth_key_create_aes(const unsigned char *key,
                                    int key_len);

/*
 * zeros out key memory and then frees it
 */

void webauth_key_destroy_aes(WEBAUTH_AES_KEY *key);

/******************** tokens ********************/
   
/*
 * returns length required to encrypt+base64 encode token,
 * not including null-termination.
 */
int webauth_token_encoded_length(const WEBAUTH_ATTR *attrs,
                                 int num_attrs);

/*
 * encrypts and base64 encodes attrs into a token
 *
 * returns length of base64-encoded token (not null-terminated) or an error
 *
 * errors:
 *  WA_ERR_NO_ROOM
 *  WA_ERR_NO_MEM
 *  
 */
int webauth_token_create(const WEBAUTH_ATTR *attrs,
                         int num_attrs,
                         unsigned char *output,
                         int max_output_len,
                         const WEBAUTH_AES_KEY *key);

/*
 * base64 decodes and decrypts attrs into a token
 * input buffer is modified, and the resulting
 * attrs point into it for their values.
 *
 * attrs will point to the dynamically-allocated array
 * of attrs and must be freed when no longer needed.
 *
 * returns number of attrs in the resulting token or an error
 *
 * errors:
 *  WA_ERR_NO_MEM
 *  WA_ERR_CORRUPT
 *  WA_ERR_BAD_HMAC
 */

int webauth_token_parse(unsigned char *input,
                        int input_len,
                        WEBAUTH_ATTR **attrs,
                        const WEBAUTH_AES_KEY *key);

#ifdef  __cplusplus
//}
#endif

/*
**  Local variables:
**  mode: c
**  c-basic-offset: 4
**  indent-tabs-mode: nil
**  end:
*/

#endif
