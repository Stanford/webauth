/*
 * WebAuth token handling.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2003, 2006, 2009, 2010, 2011, 2012
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <apr_pools.h>
#include <netinet/in.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <time.h>

#include <lib/internal.h>
#include <util/macros.h>
#include <webauth/basic.h>
#include <webauth/tokens.h>

/*
 * An ivec to pass to the AES encryption function.  This is always 0 since we
 * use nonce as ivec.
 */
static unsigned char aes_ivec[AES_BLOCK_SIZE] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

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
static size_t
encoded_length(const WEBAUTH_ATTR_LIST *list, size_t *plen)
{
    size_t elen, modulo;

    /* The header and the attributes. */
    elen = T_NONCE_S + T_HMAC_S;
    elen += webauth_attrs_encoded_length(list);

    /*
     * Add in padding length.  Tokens are padded to the AES block size.
     * We always add padding, so if the token is exactly the block size, we
     * add padding equal to the block size.
     */
    modulo = elen % AES_BLOCK_SIZE;
    if (modulo != 0)
        *plen = AES_BLOCK_SIZE - modulo;
    else
        *plen = AES_BLOCK_SIZE;
    elen += *plen;

    /* Add in the hint length. */
    elen += T_HINT_S;

    return elen;
}


/*
 * Encode and encrypt attributes into a token, storing the encoded string in a
 * new pool-allocated output buffer and the length in output_len.  The token
 * is *not* base64-encoded.  key is the key in which to encrypt the token, and
 * hint is the hint to use for decoders to find the key.  If hint is 0, use
 * the current time.
 *
 * Returns a WA_ERR code.
 */
static int
create_with_key(struct webauth_context *ctx, const WEBAUTH_ATTR_LIST *list,
                time_t hint, char **output, size_t *output_len,
                const WEBAUTH_KEY *key)
{
    size_t elen, plen, alen, i;
    int status;
    char *result, *p;
    AES_KEY aes_key;
    uint32_t hint_buf;

    /* Clear our output paramters in case of error. */
    *output = NULL;
    *output_len = 0;

    /*
     * Create our encryption key.
     *
     * FIXME: Get the actual OpenSSL error.
     */
    status = AES_set_encrypt_key((unsigned char *) key->data, key->length * 8,
                                 &aes_key);
    if (status != 0) {
        webauth_error_set(ctx, WA_ERR_BAD_KEY, "error setting encryption key");
        return WA_ERR_BAD_KEY;
    }

    /* {key-hint}{nonce}{hmac}{attr}{padding} */
    elen = encoded_length(list, &plen);
    result = apr_palloc(ctx->pool, elen);
    p = result;

    /* {key-hint} */
    if (hint == 0)
        hint = time(NULL);
    hint_buf = htonl(hint);
    memcpy(p, &hint_buf, T_HINT_S);
    p += T_HINT_S;

    /* {nonce} */
    status = webauth_random_bytes(p, T_NONCE_S);
    if (status != WA_ERR_NONE)
        return status;
    p += T_NONCE_S;

    /* Leave room for HMAC, which we'll add later. */
    p += T_HMAC_S;

    /* {attr} */
    status = webauth_attrs_encode(list, p, &alen, elen - (p - result) - plen);
    if (status != WA_ERR_NONE) {
        webauth_error_set(ctx, status, "error encoding attributes");
        return status;
    }
    p += alen;

    /* {padding} */
    for (i = 0; i < plen; i++)
        p[i] = plen;

    /*
     * Calculate the HMAC over the data and padding.  We should use something
     * better than this for the HMAC key.  The HMAC function doesn't return an
     * error.
     */
    HMAC(EVP_sha1(), key->data, key->length,
         (unsigned char *) result + T_ATTR_O, alen + plen,   /* data, len */
         (unsigned char *) result + T_HMAC_O, NULL);         /* hmac, len */

    /*
     * Now AES-encrypt in place everything but the time at the front.
     * AES_cbc_encrypt doesn't return anything.
     */
    AES_cbc_encrypt((unsigned char *) result + T_NONCE_O,
                    (unsigned char *) result + T_NONCE_O,
                    elen - T_HINT_S, &aes_key, aes_ivec, AES_ENCRYPT);

    /* All done.  Return the result. */
    *output = result;
    *output_len = elen;
    return WA_ERR_NONE;
}


/*
 * A wrapper around webauth_token_create_with_key that first finds the best
 * key from the given keyring and then encodes with that key, returning the
 * results in the same way that webauth_token_create_with_key does.
 */
int
webauth_token_create(struct webauth_context *ctx,
                     const WEBAUTH_ATTR_LIST *list, time_t hint,
                     char **output, size_t *output_len,
                     const WEBAUTH_KEYRING *ring)
{
    WEBAUTH_KEY *key;

    key = webauth_keyring_best_key(ring, 1, 0);
    if (key == NULL) {
        webauth_error_set(ctx, WA_ERR_BAD_KEY,
                          "unable to find usable encryption key");
        return WA_ERR_BAD_KEY;
    }
    return create_with_key(ctx, list, hint, output, output_len, key);
}


/*
 * Given a key, a token, and its length, decrypt it in place with that key and
 * return the decrypted length in dlen.  Returns a WA_ERR code.  On error, the
 * input data may have been partially decrypted and should not be used.
 *
 * FIXME: No need to decrypt in place.  We can have it take separate input and
 * output buffers.
 */
static int
decrypt_token(struct webauth_context *ctx, const WEBAUTH_KEY *key,
              unsigned char *input, size_t elen, size_t *dlen)
{
    unsigned char computed_hmac[T_HMAC_S];
    size_t plen, i;
    int status;
    AES_KEY aes_key;

    /* Basic sanity check. */
    if (elen < T_HINT_S + T_NONCE_S + T_HMAC_S + AES_BLOCK_SIZE) {
        webauth_error_set(ctx, WA_ERR_CORRUPT,
                          "token too short while decoding");
        return WA_ERR_CORRUPT;
    }

    /*
     * Create our decryption key.
     *
     * FIXME: Get the actual OpenSSL error.
     */
    status = AES_set_decrypt_key((unsigned char *) key->data, key->length * 8,
                                 &aes_key);
    if (status != 0) {
        webauth_error_set(ctx, WA_ERR_BAD_KEY, "error setting decryption key");
        return WA_ERR_BAD_KEY;
    }

    /*
     * Decrypt everything except the time at the front.  AES_cbc_encrypt
     * doesn't return anything useful.
     */
    AES_cbc_encrypt(input + T_NONCE_O, input + T_NONCE_O,
                    elen - T_HINT_S, &aes_key, aes_ivec, AES_DECRYPT);

    /*
     * We now need to compute the HMAC over data and padding to see if
     * decryption succeeded.  HMAC doesn't return anything.
     */
    HMAC(EVP_sha1(), key->data, key->length, input + T_ATTR_O,
         elen - T_ATTR_O, computed_hmac, NULL);
    if (memcmp(input + T_HMAC_O, computed_hmac, T_HMAC_S) != 0) {
        webauth_error_set(ctx, WA_ERR_BAD_HMAC,
                          "HMAC check failed while decrypting token");
        return WA_ERR_BAD_HMAC;
    }

    /* Check padding length and data validity. */
    plen = input[elen - 1];
    if (plen > AES_BLOCK_SIZE || plen > elen)
        return WA_ERR_CORRUPT;
    for (i = elen - plen; i < elen - 1; i++)
        if (input[i] != plen) {
            webauth_error_set(ctx, WA_ERR_CORRUPT,
                              "token padding corrupt while decrypting token");
            return WA_ERR_CORRUPT;
        }

    /* Store the decoded length and return. */
    *dlen = elen - T_ATTR_O - plen;
    return WA_ERR_NONE;
}


/*
 * Check a token for basic validity.  This only checks the expiration time
 * and, if ttl is not zero, whether the creation time is more than ttl ago.
 */
static int
check_token(struct webauth_context *ctx, WEBAUTH_ATTR_LIST *list,
            unsigned long ttl)
{
    int status;
    time_t t;
    time_t now = 0;

    /* See if the token has an explicit expiration. */
    status = webauth_attr_list_get_time(list, WA_TK_EXPIRATION_TIME, &t,
                                        WA_F_NONE);
    if (status == WA_ERR_NONE) {
        now = time(NULL);
        if (t < now) {
            status = WA_ERR_TOKEN_EXPIRED;
            webauth_error_set(ctx, status, "token expired at %lu",
                              (unsigned long) t);
            return status;
        }
    } else if (status != WA_ERR_NOT_FOUND) {
        webauth_error_set(ctx, status, "error retrieving expiration time");
        return status;
    }

    /* A ttl of 0 means don't check the creation time. */
    if (ttl == 0)
        return WA_ERR_NONE;

    /* See if token has creation time.  If it doesn't, it's always valid. */
    status = webauth_attr_list_get_time(list, WA_TK_CREATION_TIME, &t,
                                        WA_F_NONE);
    if (status == WA_ERR_NONE) {
        if (now == 0)
            now = time(NULL);
        if ((time_t) (t + ttl) < now) {
            status = WA_ERR_TOKEN_STALE;
            webauth_error_set(ctx, status, "token became stale at %lu",
                              t + ttl);
            return status;
        }
    } else if (status != WA_ERR_NOT_FOUND) {
        webauth_error_set(ctx, status, "error retrieving creation time");
        return status;
    }
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
webauth_token_parse(struct webauth_context *ctx, const char *input,
                    size_t input_len, unsigned long ttl,
                    const WEBAUTH_KEYRING *ring, WEBAUTH_ATTR_LIST **list)
{
    size_t dlen, i;
    int status;
    WEBAUTH_KEY *key;
    unsigned char *buf;
    bool input_dirty;

    *list = NULL;
    if (ring->num_entries == 0) {
        webauth_error_set(ctx, WA_ERR_BAD_KEY,
                          "empty keyring when decoding token");
        return WA_ERR_BAD_KEY;
    }

    /*
     * Make a copy of the input so that decoding doesn't destroy the original
     * string.  This also lets us restore the decoder input to its original
     * state each time decrypting fails.
     */
    buf = apr_palloc(ctx->pool, input_len);
    memcpy(buf, input, input_len);
    input_dirty = false;

    /*
     * Find the decryption key.  If there's only one entry in the keyring,
     * this is easy: we use that key.  Otherwise, we try the hinted key.
     * Failing that, we try all keys.
     */
    if (ring->num_entries == 1)
        status = decrypt_token(ctx, ring->entries[0].key, buf, input_len,
                               &dlen);
    else {
        uint32_t hint_buf;
        time_t hint;

        /* First, try the hint. */
        memcpy(&hint_buf, buf, sizeof(hint_buf));
        hint = ntohl(hint_buf);
        key = webauth_keyring_best_key(ring, 0, hint);
        if (key == NULL)
            status = WA_ERR_BAD_HMAC;
        else {
            status = decrypt_token(ctx, key, buf, input_len, &dlen);
            input_dirty = true;
        }

        /*
         * Now, as long as we didn't decode successfully, try each key in the
         * keyring in turn.  If the input is dirty, we have to replace the
         * input with our temporary buffer and try again.
         */
        for (i = 0; status != WA_ERR_NONE && i < ring->num_entries; i++) {
            if (ring->entries[i].key != key) {
                if (input_dirty)
                    memcpy(buf, input, input_len);
                status = decrypt_token(ctx, ring->entries[i].key, buf,
                                       input_len, &dlen);
                input_dirty = true;
            }
        }
    }

    /*
     * status is WA_ERR_NONE if we found a working key.  Decode the attributes
     * and then check for errors.
     */
    if (status == WA_ERR_NONE) {
        status = webauth_attrs_decode((char *) buf + T_ATTR_O, dlen, list);
        if (status != WA_ERR_NONE)
            webauth_error_set(ctx, status, "error decoding token attributes");
    }
    if (status != WA_ERR_NONE)
        return status;

    /*
     * If the token had an expiration/creation time that wasn't in the right
     * format, treat the key as invalid and free the list.  If it's just
     * expired or stale, keep the list and just return the error code, since
     * we may want to use the token anyway.
     */
    status = check_token(ctx, *list, ttl);
    if (status == WA_ERR_NONE
        || status == WA_ERR_TOKEN_EXPIRED
        || status == WA_ERR_TOKEN_STALE)
        return status;
    else {
        webauth_attr_list_free(*list);
        return status;
    }
}
