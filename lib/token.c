/*
 * WebAuth token handling.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2003, 2006, 2009
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <lib/webauthp.h>

#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <sys/types.h>
#include <time.h>

/*
 * An ivec to pass to the AES encryption function.  This is always 0 since we
 * use nonce as ivec.
 */
static unsigned char aes_ivec[AES_BLOCK_SIZE] =
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

/*
 * Define some macros for offsets (_O) and sizes (_S) in tokens.  The token
 * form is:
 *
 *     {key-hint}{nonce}{hmac}{attr}{padding}
 *
 * The SHA digest length for the HMAC comes from OpenSSL.
 */
#define T_HINT_S   4
#define T_NONCE_S 16
#define T_HMAC_S  (SHA_DIGEST_LENGTH)

#define T_HINT_O  0
#define T_NONCE_O (T_HINT_O  + T_HINT_S)
#define T_HMAC_O  (T_NONCE_O + T_NONCE_S)
#define T_ATTR_O  (T_HMAC_O  + T_HMAC_S)


/*
 * Given an attribute list, calculate the encoded binary length.  The length
 * of the padding needed is stored in plen.
 */
static int
binary_encoded_length(const WEBAUTH_ATTR_LIST *list, int *plen)
{
    int len, m;

    len = webauth_attrs_encoded_length(list);
    len += T_NONCE_S + T_HMAC_S;

    /* Add in padding length.  Tokens are padded to the AES block size. */
    m = len % AES_BLOCK_SIZE;
    if (m != 0)
        *plen = AES_BLOCK_SIZE - m;
    else
        *plen = AES_BLOCK_SIZE;
    len += *plen;

    /* Add in 4 bytes for creation time. */
    len += 4;

    return len;
}


/*
 * Returns the encoded length of an attribute list.
 */
int
webauth_token_encoded_length(const WEBAUTH_ATTR_LIST *list)
{
    int plen;

    assert(list != NULL);
    assert(list->num_attrs);

    return binary_encoded_length(list, &plen);
}


/*
 * Encode and encrypt attributes into a token, storing the token in the buffer
 * pointed to by output and the length of the encoded token in output_len.
 * max_output_len is the length of the buffer to which output points.  key is
 * the key in which to encrypt the token, and hint is the hint to use for
 * decoders to find the key.  If hint is 0, use the current time.
 *
 * Returns a WA_ERR code.
 */
int
webauth_token_create_with_key(const WEBAUTH_ATTR_LIST *list, time_t hint,
                              char *output, int *output_len,
                              int max_output_len, const WEBAUTH_KEY *key)
{
    int elen, plen, alen, n, i, s;
    AES_KEY aes_key;

    /* sizeof(currt) MUST equal T_HINT_S. */
    uint32_t currt;

    assert(list!= NULL);
    assert(list->num_attrs);
    assert(output != NULL);
    assert(max_output_len);
    assert(key != NULL);

    if (AES_set_encrypt_key((unsigned char *) key->data, key->length * 8,
                            &aes_key))
        return WA_ERR_BAD_KEY;

    /* {key-hint}{nonce}{hmac}{token-attributes}{padding} */

    elen = binary_encoded_length(list, &plen);
    if (elen > max_output_len)
        return WA_ERR_NO_ROOM;
    n = 0;

    /* key-hint */
    if (hint == 0)
        time(&hint);
    currt = htonl((uint32_t) hint);
    memcpy(output, &currt, T_HINT_S);
    n += T_HINT_S;

    /* nonce */
    s = webauth_random_bytes(output + n, T_NONCE_S);
    if (s != WA_ERR_NONE)
        return s;
    n += T_NONCE_S;

    /* Leave room for HMAC, which we'll add later. */
    n += T_HMAC_S;

    /* token-attributes */
    s = webauth_attrs_encode(list, output + T_ATTR_O, &alen, elen - n - plen);
    if (s != WA_ERR_NONE)
        return s;
    n += alen;

    /* padding */
    for (i = 0; i < plen; i++)
        *(output + n + i) = plen;
    n += plen;

    /*
     * Calculate the HMAC over the data and padding.  We should use something
     * better than this for the HMAC key.  The HMAC function doesn't return an
     * error.
     */
    HMAC(EVP_sha1(),
         (void *) key->data, key->length,                    /* key, len */
         (unsigned char *) output + T_ATTR_O, alen + plen,   /* data, len */
         (unsigned char *) output + T_HMAC_O, NULL);         /* hmac, len */

    /*
     * Now AES-encrypt in place everything but the time at the front.
     * AES_cbc_encrypt doesn't return anything.
     */
    AES_cbc_encrypt((unsigned char *) output + T_NONCE_O,
                    (unsigned char *) output + T_NONCE_O,
                    elen - T_HINT_S, &aes_key, aes_ivec, AES_ENCRYPT);

    /* All done.  Return the result. */
    *output_len = elen;
    return WA_ERR_NONE;
}


/*
 * A wrapper around webauth_token_create_with_key that first finds the best
 * key from the given keyring and then encodes with that key, returning the
 * results in the same way that webauth_token_create_with_key does.
 */
int
webauth_token_create(const WEBAUTH_ATTR_LIST *list, time_t hint,
                     char *output, int *output_len,
                     int max_output_len, const WEBAUTH_KEYRING *ring)
{
    WEBAUTH_KEY *key;

    assert(list!= NULL);
    assert(list->num_attrs);
    assert(output != NULL);
    assert(max_output_len);
    assert(ring != NULL);

    key = webauth_keyring_best_key(ring, 1, 0);
    if (key == NULL)
        return WA_ERR_BAD_KEY;
    return webauth_token_create_with_key(list, hint, output, output_len,
                                         max_output_len, key);
}


/*
 * Given a key, a token, and its length, decrypt it in place with that key and
 * return the decrypted length in dlen.  Returns a WA_ERR code.
 */
static int
decrypt_token(const WEBAUTH_KEY *key, char *input, int elen, int *dlen)
{
    unsigned char computed_hmac[T_HMAC_S];
    int plen, i;
    AES_KEY aes_key;

    if (AES_set_decrypt_key((unsigned char *) key->data, key->length * 8,
                            &aes_key))
        return WA_ERR_BAD_KEY;

    /*
     * Decrypt everything except the time at the front.  AES_cbc_encrypt
     * doesn't return anything useful.
     */
    AES_cbc_encrypt((unsigned char *) input + T_NONCE_O,
                    (unsigned char *) input + T_NONCE_O,
                    elen-T_HINT_S, &aes_key, aes_ivec, AES_DECRYPT);

    /*
     * We now need to compute the HMAC over data and padding to see if
     * decryption succeeded.  HMAC doesn't return anything.
     */
    HMAC(EVP_sha1(),
         (void *)key->data, key->length,                      /* key, len */
         (unsigned char *) input + T_ATTR_O, elen - T_ATTR_O, /* data, len */
         computed_hmac, NULL);                          /* hmac, len (out) */
    if (memcmp(input + T_HMAC_O, computed_hmac, T_HMAC_S) != 0)
        return WA_ERR_BAD_HMAC;

    /* Check padding length and data validity. */
    plen = *(input + elen - 1);
    if (plen > AES_BLOCK_SIZE || plen > elen)
        return WA_ERR_CORRUPT;
    for (i = 0; i < plen; i++)
        if (*(input + elen - 1 - i) != plen)
            return WA_ERR_CORRUPT;

    *dlen = elen - T_ATTR_O - plen;
    return WA_ERR_NONE;
}


/*
 * Check a token for basic validity.  This only checks the expiration time
 * and, if ttl is not zero, whether the creation time is more than ttl ago.
 */
int static
check_token(WEBAUTH_ATTR_LIST *list, int ttl)
{
    int s;
    time_t curr = 0, t;

    /* See if the token has an explicit expiration. */
    s = webauth_attr_list_get_time(list, WA_TK_EXPIRATION_TIME, &t, WA_F_NONE);
    if (s == WA_ERR_NONE) {
        time(&curr);
        if (t < curr)
            return WA_ERR_TOKEN_EXPIRED;
    } else if (s != WA_ERR_NOT_FOUND)
        return s;

    /* A ttl of 0 means don't check the creation time. */
    if (ttl == 0)
        return WA_ERR_NONE;

    /* See if token has creation time.  If it doesn't, it's always valid. */
    s = webauth_attr_list_get_time(list, WA_TK_CREATION_TIME, &t, WA_F_NONE);
    if (s == WA_ERR_NONE) {
        if (curr == 0)
            time(&curr);
        if (t + ttl < curr)
            return WA_ERR_TOKEN_STALE;
    } else if (s != WA_ERR_NOT_FOUND)
        return s;

    return WA_ERR_NONE;
}


/*
 * Decrypts and decodes attributes from a token, given the token as input and
 * its length as input_len.  If ttl is not zero, the token is treated as
 * invalid if its creation time is more than ttl ago.  Takes a keyring to use
 * for decryption and list, into which the new attribute list is put.  Returns
 * a WA_ERR code.
 */
int
webauth_token_parse(char *input, int input_len, int ttl,
                    const WEBAUTH_KEYRING *ring, WEBAUTH_ATTR_LIST **list)
{
    int dlen, s, i;
    WEBAUTH_KEY *hkey;

    assert(input != NULL);
    assert(list != NULL);
    assert(ring != NULL);

    *list = NULL;

    if (ring->num_entries == 0)
        return WA_ERR_BAD_KEY;
    if (input_len < T_HINT_S + T_NONCE_S + T_HMAC_S + AES_BLOCK_SIZE)
        return WA_ERR_CORRUPT;

    if (ring->num_entries > 1) {
        unsigned char *buff;
        int input_dirty;
        uint32_t temp;
        time_t hint;

        buff = malloc(input_len);
        if (buff == NULL)
            return WA_ERR_NO_MEM;
        memcpy(buff, input, input_len);
        input_dirty =0;

        /* First, try the hint. */
        memcpy(&temp, input, sizeof(temp));
        hint = (time_t) ntohl(temp);
        hkey = webauth_keyring_best_key(ring, 0, hint);

        if (hkey != NULL) {
            if (input_dirty)
                memcpy(input, buff, input_len);
            s = decrypt_token(hkey, input, input_len, &dlen);
            input_dirty = 1;
        } else
            s = WA_ERR_BAD_HMAC;

        /* If the hint failed, try all keys. */
        if (s != WA_ERR_NONE) {
            for (i = 0; i < ring->num_entries; i++)
                if (ring->entries[i].key != hkey) {
                    if (input_dirty)
                        memcpy(input, buff, input_len);
                    s = decrypt_token(ring->entries[i].key, input, input_len,
                                      &dlen);
                    input_dirty = 1;
                    if (s == WA_ERR_NONE)
                        break;
                }
        }
        free(buff);
    } else
        s = decrypt_token(ring->entries[0].key, input, input_len, &dlen);

    if (s == WA_ERR_NONE)
        s = webauth_attrs_decode(input+T_ATTR_O, dlen, list);

    if (s != WA_ERR_NONE)
        return s;

    s = check_token(*list, ttl);

    /*
     * If the token had an expiration/creation time that wasn't in the right
     * format, treat the key as invalid and free the list.  If it's just
     * expired or stale, keep the list and just return the error code.
     */
    if (s == WA_ERR_NONE || s == WA_ERR_TOKEN_EXPIRED
        || s == WA_ERR_TOKEN_STALE)
        return s;
    else {
        webauth_attr_list_free(*list);
        return s;
    }
}


/*
 * The same as webauth_token_parse, but use a specific key rather than a
 * keyring.
 *
 * Decrypts and decodes attributes from a token, given the token as input and
 * its length as input_len.  If ttl is not zero, the token is treated as
 * invalid if its creation time is more than ttl ago.  Takes a keyr to use for
 * decryption and list, into which the new attribute list is put.  Returns a
 * WA_ERR code.
 */
int
webauth_token_parse_with_key(char *input, int input_len, int ttl,
                             const WEBAUTH_KEY *key, WEBAUTH_ATTR_LIST **list)
{
    int dlen, s;

    assert(input != NULL);
    assert(list != NULL);
    assert(key != NULL);

    *list = NULL;

    if (input_len < T_HINT_S+T_NONCE_S+T_HMAC_S+AES_BLOCK_SIZE)
        return WA_ERR_CORRUPT;

    s = decrypt_token(key, input, input_len, &dlen);
    if (s == WA_ERR_NONE)
        s = webauth_attrs_decode(input+T_ATTR_O, dlen, list);

    if (s != WA_ERR_NONE)
        return s;

    s = check_token(*list, ttl);

    /*
     * If the token had an expiration/creation time that wasn't in the right
     * format, treat the key as invalid and free the list.  If it's just
     * expired or stale, keep the list and just return the error code.
     */
    if (s == WA_ERR_NONE || s == WA_ERR_TOKEN_EXPIRED
        || s == WA_ERR_TOKEN_STALE)
        return s;
    else {
        webauth_attr_list_free(*list);
        return s;
    }
}
