#ifndef _WEBAUTH_H
#define _WEoBAUTH_H

#ifdef  __cplusplus
//extern "C" {
#endif

/******************** error codes ********************/

typedef enum {
    WA_ERR_NO_ROOM = -2000,  /* supplied buffer too small */
    WA_ERR_CORRUPT,          /* data is incorrectly formatted */
    WA_ERR_NO_MEM,           /* no memory */
    WA_ERR_BAD_HMAC,         /* hmac check failed */
    WA_ERR_RAND_FAILURE,     /* unable to get random data */
    /* must be last */
    WA_ERR_NONE = 0          /* no error occured */
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

/*
 * generic name/value attributes for constructing tokens
 * names MUST not contain an "=", and values *MAY*
 * contain binary data, since the length *MUST* be specified.
 */

/* a generic attribute */
typedef struct {
    char *name;
    void *value;
    int length;
} WEBAUTH_ATTR;

/* an AES key */
typedef struct webauth_aes_key WEBAUTH_AES_KEY;

/******************** base64 ********************/

/*
 * returns the amount of space required to base64 encode data
 * of the given length. Returned length does *NOT* include room for a
 * null-termination.
 */
int webauth_base64_encoded_length(int length);


/*
 * returns the amount of space required to base64 decode data
 * of the given length. Does not actually attempt to ensure that
 * input contains a valid base64-encoded string, other the checking
 * the last two characters for padding ('='). Returned length does *NOT*
 * include room for a null-termination.
 *
 * errors:
 *   WA_ERR_CORRUPT (if length is not greater then 0 and a multiple of 4)
 *
 */
int webauth_base64_decoded_length(const unsigned char *input, int length);

/*
 * base64 encodes the given data, does *NOT* null-terminate.
 * output can *not* point to input.
 *
 * returns output length or an error.
 *
 * errors:
 *   WA_ERR_NO_ROOM
 *   
 */
int webauth_base64_encode(const unsigned char *input,
                          int input_len, 
                          unsigned char *output,
                          int max_output_len);

/*
 * base64 decodes the given data, does *NOT* null-terminate.
 * output can point to input.
 *
 * returns output length or an error.
 *
 * errors:
 *   WA_ERR_NO_ROOM
 *   WA_ERR_CORRUPT
 */
int 
webauth_base64_decode(unsigned char *input,
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

WEBAUTH_AES_KEY *webauth_key_create(const unsigned char *key,
                                    int key_len);

/*
 * zeros out key memory and then frees it
 */

void webauth_key_destroy(WEBAUTH_AES_KEY *key);

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
 * returns number of attrs in the resulting token or an error
 *
 * errors:
 *  WA_ERR_NO_ROOM
 *  WA_ERR_CORRUPT
 *  WA_ERR_BAD_HMAC
 */

int webauth_token_parse(unsigned char *input,
                        int input_len,
                        WEBAUTH_ATTR *attrs,
                        int max_num_attrs,
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
