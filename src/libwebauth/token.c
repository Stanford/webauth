#include "webauthp.h"

#include <sys/types.h>
#include <time.h>
#include <netinet/in.h>

#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

/* 
 *  define some macros for offsets (_O) and sizes (_S) in token
 *  {key-hint}{nonce}{hmac}{token-attributes}{padding} 
 */

#define T_HINT_S  4
#define T_NONCE_S 16
#define T_HMAC_S (SHA_DIGEST_LENGTH)

#define T_HINT_O 0
#define T_NONCE_O (T_HINT_O+T_HINT_S)
#define T_HMAC_O (T_NONCE_O+T_NONCE_S)
#define T_ATTR_O (T_HMAC_O+T_HMAC_S)


static int 
binary_encoded_length(const WEBAUTH_ATTR_LIST *list,
                      int *plen)
{
    int len, m;

    /* calculate encrypted data length first */

    /* get length of encoded attrs first */
    len = webauth_attrs_encoded_length(list);

    /* add in nonce and hmac */
    len += T_NONCE_S+T_HMAC_S;

    /* add in padding length */
    m = len % AES_BLOCK_SIZE;
    if (m) {
        *plen = AES_BLOCK_SIZE - m;
    } else {
        *plen = AES_BLOCK_SIZE;
    }

    len += *plen;

    /* add in 4 bytes for creation time */
    len += 4;

    /* now return length including base64 */
    return len;
}

int
webauth_token_encoded_length(const WEBAUTH_ATTR_LIST *list)
{
    int plen;
    int blen;

    assert(list != NULL);
    assert(list->num_attrs);
    blen = binary_encoded_length(list, &plen);
    return webauth_base64_encoded_length(blen);
}


/* ivec is always 0 since we use nonce as ivec */
static unsigned char aes_ivec[AES_BLOCK_SIZE] = 
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

/*
 * encrypts and base64 encodes attrs into a token
 */
int
webauth_token_create_with_key(const WEBAUTH_ATTR_LIST *list,
                              time_t hint,
                              unsigned char *output,
                              int *output_len,
                              int max_output_len,
                              const WEBAUTH_KEY *key)
{
    unsigned char *ebuff;
    int elen, blen, plen, alen, n, i, s;
    uint32_t currt; /* sizeof MUST equal T_HINT_S */

    AES_KEY aes_key;

    assert(list!= NULL);
    assert(list->num_attrs);
    assert(output != NULL);
    assert(max_output_len);
    assert(key != NULL);

    if (AES_set_encrypt_key(key->data, key->length*8, &aes_key)) {
        return WA_ERR_BAD_KEY;
    }

    /* {key-hint}{nonce}{hmac}{token-attributes}{padding} */

    elen = binary_encoded_length(list, &plen);
    blen = webauth_base64_encoded_length(elen);

    if (blen > max_output_len) {
        return WA_ERR_NO_ROOM;
    }

    ebuff = malloc(elen);
    if (ebuff == NULL) {
        return WA_ERR_NO_MEM;
    }

    n = 0;

    if (hint == 0) {
        time(&hint);
    }
    currt = htonl((uint32_t)hint);

    /* copy in hint */
    memcpy(ebuff, &currt, T_HINT_S);
    n += T_HINT_S;

    /* copy in nonce */
    s = webauth_random_bytes(ebuff+n, T_NONCE_S);
    if (s != WA_ERR_NONE) {
        free(ebuff);
        return s;
    }

    n += T_NONCE_S;

    /* leave room for hmac of data */
    n += T_HMAC_S;

    /* encode attributes */
    s = webauth_attrs_encode(list, ebuff+T_ATTR_O, &alen, elen-n-plen);
    if (s != WA_ERR_NONE) {
        free(ebuff);
        return s;
    }

    n += alen;

    /* add padding for AES */
    for (i=0; i < plen; i++) {
        *(ebuff+n+i) = plen;
    }
    n += plen;

    /* calculate hmac over data+padding 
       FIXME: change hmac key to something better.*/
    /* HMAC doesn't return an errors */
    HMAC(EVP_sha1(), 
         (void*)key->data, key->length, /* key, len */
         ebuff+T_ATTR_O, alen+plen,     /* data, len */
         ebuff+T_HMAC_O, NULL);         /* hmac, len (out) */

    /* now AES encrypt everything but the time at the front */
    /* AES_cbc_encrypt doesn't return anything */

    AES_cbc_encrypt(ebuff+T_NONCE_O,
                    ebuff+T_NONCE_O, /* encrypt in-place */
                    elen-T_HINT_S,
                    &aes_key,
                    aes_ivec, AES_ENCRYPT);

    /* now base64 token */
    s = webauth_base64_encode(ebuff, elen, output, &blen, max_output_len);

    /* free buffer */
    free(ebuff);

    if (s != WA_ERR_NONE)
        return s;

    *output_len = blen;

    return WA_ERR_NONE;
}


/*
 * encrypts and base64 encodes attrs into a token
 */
int
webauth_token_create(const WEBAUTH_ATTR_LIST *list,
                     time_t hint,
                     unsigned char *output,
                     int *output_len,
                     int max_output_len,
                     const WEBAUTH_KEYRING *ring)
{
    WEBAUTH_KEY *key;

    assert(list!= NULL);
    assert(list->num_attrs);
    assert(output != NULL);
    assert(max_output_len);
    assert(ring != NULL);

    /* find the best key */
    key = webauth_keyring_best_key(ring, 1, 0);
    if (key == NULL) {
        return WA_ERR_BAD_KEY;
    }

    return webauth_token_create_with_key(list, hint, output, output_len, 
                                         max_output_len, key);
}


/*
 * decrypt token, return status
 */

static int
decrypt_token(const WEBAUTH_KEY *key, 
              unsigned char *input, int elen, int *dlen)
{
    /* hmac we compute from data */
    unsigned char computed_hmac[T_HMAC_S];
    int plen, i;
    AES_KEY aes_key;

    if (AES_set_decrypt_key(key->data, key->length*8, &aes_key)) {
        return WA_ERR_BAD_KEY;
    }

    /* decrypt using our key */
    /* now AES decrypt everything but the time at the front */
    /* AES_cbc_encrypt doesn't return anything useful */
    AES_cbc_encrypt(input+T_NONCE_O,
                    input+T_NONCE_O,  /* decrypt in-place */
                    elen-T_HINT_S,
                    &aes_key,
                    aes_ivec, AES_DECRYPT);

    /* we now need to compute HMAC to see if decryption succeeded */

    /* calculate hmac over data+padding */
    /* FIXME: change hmac key to something better */
    /* hamc doesn't return anything */
    HMAC(EVP_sha1(),
         (void*)key->data, key->length,  /* key, len */
         input+T_ATTR_O, elen-T_ATTR_O, /* data, len */
         computed_hmac, NULL);          /* hmac, len (out) */

    /* compare computed against decrypted */
    if (memcmp(input+T_HMAC_O, computed_hmac, T_HMAC_S) != 0) {
        return WA_ERR_BAD_HMAC;
    }

    /* check padding length validity */
    plen = *(input+elen-1);
    if (plen >= AES_BLOCK_SIZE || plen > elen) {
        return WA_ERR_CORRUPT;
    }
    /* check padding data validity */
    for (i=0; i < plen; i++) {
        if (*(input+elen-1-i) != plen) {
            return WA_ERR_CORRUPT;
        }
    }

    *dlen = elen-T_ATTR_O-plen;
    return WA_ERR_NONE;
}

int static
check_token(WEBAUTH_ATTR_LIST *list, int ttl)
{
    int s;
    time_t curr = 0, t;

    /* see if token has explicit expiration */
    s = webauth_attr_list_get_time(list, WA_TK_EXPIRATION_TIME, &t);
    if (s == WA_ERR_NONE) {
        time(&curr);
        if (t < curr) {
            return WA_ERR_TOKEN_EXPIRED;
        }
    } else if (s != WA_ERR_NOT_FOUND) {
        return s;
    }

    /* a ttl of 0 means don't check */
    if (ttl == 0)
        return WA_ERR_NONE;

    /* see if token has creation time */
    s = webauth_attr_list_get_time(list, WA_TK_CREATION_TIME, &t);
    if (s == WA_ERR_NONE) {
        if (curr == 0)
            time(&curr);
        if (t+ttl < curr) {
            return WA_ERR_TOKEN_STALE;
        }
    } else if (s != WA_ERR_NOT_FOUND) {
        return s;
    }

    return WA_ERR_NONE;
}

/*
 * base64 decodes and decrypts attrs into a token
 * input buffer is modified.
 *
 * {key-hint}{nonce}{hmac}{token-attributes}{padding}
 */

int
webauth_token_parse(unsigned char *input,
                    int input_len,
                    int ttl,
                    const WEBAUTH_KEYRING *ring,
                    WEBAUTH_ATTR_LIST **list)
{
    int elen, dlen, s, i;
    uint32_t temp;
    time_t hint;
    unsigned char *buff;

    WEBAUTH_KEY *hkey;

    assert(input != NULL);
    assert(list != NULL);
    assert(ring != NULL);

    *list = NULL;

    if (ring->num_entries == 0) {
        return WA_ERR_BAD_KEY;
    }

    /** base64 decode (in place) first */
    s = webauth_base64_decode(input, input_len, input, &elen, input_len);
    if (s != WA_ERR_NONE) {
        return s;
    }

    /* quick sanity check */
    if (elen < T_HINT_S+T_NONCE_S+T_HMAC_S+AES_BLOCK_SIZE) {
        return WA_ERR_CORRUPT;
    }

    buff = malloc(elen);
    if (buff == NULL) {
        return WA_ERR_NO_MEM;
    }

    /* use hint first */
    memcpy(&temp, input, sizeof(temp));
    hint = (time_t)ntohl(temp);
    hkey = webauth_keyring_best_key(ring, 0, hint);

    if (hkey != NULL) {
        memcpy(buff, input, elen);
        s = decrypt_token(hkey, buff, elen, &dlen);
    } else {
        s = WA_ERR_BAD_HMAC;
    }

    if (s != WA_ERR_NONE) {
        /* hint failed, try all keys, skipping hint */
        for (i=0; i < ring->num_entries; i++) {
            if (ring->entries[i].key != hkey) {
                memcpy(buff, input, elen);
                s = decrypt_token(ring->entries[i].key, buff, elen, &dlen);
                if (s == WA_ERR_NONE)
                    break;
            }
        }
    }

    if (s == WA_ERR_NONE)
        s = webauth_attrs_decode(buff+T_ATTR_O, dlen, list);

    free(buff);

    if (s != WA_ERR_NONE)
        return s;

    s = check_token(*list, ttl);

    if (s == WA_ERR_NONE || s == WA_ERR_TOKEN_EXPIRED || 
        s == WA_ERR_TOKEN_STALE) {
            return s;
    } else {
        /* token had an expiration/creation time that wasn't
           in the right format */
        webauth_attr_list_free(*list);
        return s;
    }
}


/*
 * base64 decodes and decrypts attrs into a token
 * input buffer is modified.
 *
 * {key-hint}{nonce}{hmac}{token-attributes}{padding}
 */

int
webauth_token_parse_with_key(unsigned char *input,
                             int input_len,
                             int ttl,
                             const WEBAUTH_KEY *key,
                             WEBAUTH_ATTR_LIST **list)
{
    int elen, dlen, s;

    assert(input != NULL);
    assert(list != NULL);
    assert(key != NULL);

    *list = NULL;

    /** base64 decode (in place) first */
    s = webauth_base64_decode(input, input_len, input, &elen, input_len);
    if (s != WA_ERR_NONE) {
        return s;
    }

    /* quick sanity check */
    if (elen < T_HINT_S+T_NONCE_S+T_HMAC_S+AES_BLOCK_SIZE) {
        return WA_ERR_CORRUPT;
    }

    s = decrypt_token(key, input, elen, &dlen);
    if (s == WA_ERR_NONE)
        s = webauth_attrs_decode(input+T_ATTR_O, dlen, list);

    if (s != WA_ERR_NONE)
        return s;

    s = check_token(*list, ttl);

    if (s == WA_ERR_NONE || s == WA_ERR_TOKEN_EXPIRED || 
        s == WA_ERR_TOKEN_STALE) {
            return s;
    } else {
        /* token had an expiration/creation time that wasn't
           in the right format */
        webauth_attr_list_free(*list);
        return s;
    }
}

/*
**  Local variables:
**  mode: c
**  c-basic-offset: 4
**  indent-tabs-mode: nil
**  end:
*/
