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
 * Given the length of the encoded attributes, calculate the encoded binary
 * length.  The length of the padding needed is stored in plen.
 */
static size_t
encoded_length(size_t alen, size_t *plen)
{
    size_t elen, modulo;

    /* The header and the attributes. */
    elen = T_NONCE_S + T_HMAC_S + alen;

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
 * A wrapper around webauth_token_create_with_key that first finds the best
 * key from the given keyring and then encodes with that key, returning the
 * results in the same way that webauth_token_create_with_key does.
 */
int
webauth_token_encrypt(struct webauth_context *ctx, const char *input,
                      size_t len, char **output, size_t *output_len,
                      const WEBAUTH_KEYRING *ring)
{
    WEBAUTH_KEY *key;
    size_t elen, plen, i;
    int status;
    char *result, *p;
    AES_KEY aes_key;
    uint32_t hint;

    /* Clear our output paramters in case of error. */
    *output = NULL;
    *output_len = 0;

    /* Find the encryption key to use. */
    key = webauth_keyring_best_key(ring, 1, 0);
    if (key == NULL) {
        webauth_error_set(ctx, WA_ERR_BAD_KEY,
                          "unable to find usable encryption key");
        return WA_ERR_BAD_KEY;
    }

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
    elen = encoded_length(len, &plen);
    result = apr_palloc(ctx->pool, elen);
    p = result;

    /* {key-hint} */
    hint = htonl(time(NULL));
    memcpy(p, &hint, T_HINT_S);
    p += T_HINT_S;

    /* {nonce} */
    status = webauth_random_bytes(p, T_NONCE_S);
    if (status != WA_ERR_NONE)
        return status;
    p += T_NONCE_S;

    /* Leave room for HMAC, which we'll add later. */
    p += T_HMAC_S;

    /* {attr} */
    memcpy(p, input, len);
    p += len;

    /* {padding} */
    for (i = 0; i < plen; i++)
        p[i] = plen;

    /*
     * Calculate the HMAC over the data and padding.  We should use something
     * better than this for the HMAC key.  The HMAC function doesn't return an
     * error.
     */
    HMAC(EVP_sha1(), key->data, key->length,
         (unsigned char *) result + T_ATTR_O, len + plen,    /* data, len */
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
 * Given a token and its length, decrypt it into the provided output buffer
 * with the length stored in output_len.  The output buffer must be at least
 * as large as the input length.  Uses the provided decryption key.
 *
 * Returns a WA_ERR code.
 */
static int
decrypt_token(struct webauth_context *ctx, const unsigned char *input,
              size_t length, unsigned char *output, size_t *output_len,
              const WEBAUTH_KEY *key)
{
    unsigned char computed_hmac[T_HMAC_S];
    size_t plen, i;
    int status;
    AES_KEY aes_key;

    /* Basic sanity check. */
    if (length < T_HINT_S + T_NONCE_S + T_HMAC_S + AES_BLOCK_SIZE) {
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
     * Decrypt everything except the time at the front.  We intentionally skip
     * the same number of bytes at the start of the output buffer as we skip
     * at the start of the input buffer to make the offsets line up and be
     * less annoying.
     *
     * AES_cbc_encrypt doesn't return anything useful.
     */
    AES_cbc_encrypt(input + T_NONCE_O, output + T_NONCE_O, length - T_HINT_S,
                    &aes_key, aes_ivec, AES_DECRYPT);

    /*
     * We now need to compute the HMAC over data and padding to see if
     * decryption succeeded.  HMAC doesn't return anything.
     */
    HMAC(EVP_sha1(), key->data, key->length, output + T_ATTR_O,
         length - T_ATTR_O, computed_hmac, NULL);
    if (memcmp(output + T_HMAC_O, computed_hmac, T_HMAC_S) != 0) {
        webauth_error_set(ctx, WA_ERR_BAD_HMAC,
                          "HMAC check failed while decrypting token");
        return WA_ERR_BAD_HMAC;
    }

    /* Check padding length and data validity. */
    plen = output[length - 1];
    if (plen > AES_BLOCK_SIZE || plen > length)
        return WA_ERR_CORRUPT;
    for (i = length - plen; i < length - 1; i++)
        if (output[i] != plen) {
            webauth_error_set(ctx, WA_ERR_CORRUPT,
                              "token padding corrupt while decrypting token");
            return WA_ERR_CORRUPT;
        }

    /*
     * Shift the interersting data up to the start of the output buffer, store
     * the decoded length and return.
     */
    *output_len = length - T_ATTR_O - plen;
    memmove(output, output + T_ATTR_O, *output_len);
    return WA_ERR_NONE;
}


/*
 * Decrypts a token into new pool-allocated memory, given the token as input
 * and its length as input_len, and stores the results in output and
 * output_len.  Takes a keyring to use for decryption.  Returns a WA_ERR code.
 */
int
webauth_token_decrypt(struct webauth_context *ctx, const char *input,
                      size_t input_len, char **output, size_t *output_len,
                      const WEBAUTH_KEYRING *ring)
{
    size_t dlen, i;
    int status;
    WEBAUTH_KEY *key;
    const unsigned char *inbuf = (unsigned char *) input;
    unsigned char *outbuf;

    /* Clear our output parameters in case of an error. */
    *output = NULL;
    *output_len = 0;

    /* Sanity-check our keyring. */
    if (ring->num_entries == 0) {
        webauth_error_set(ctx, WA_ERR_BAD_KEY,
                          "empty keyring when decoding token");
        return WA_ERR_BAD_KEY;
    }

    /*
     * Create a buffer to hold the decrypted output.  We don't need to include
     * the hint in this buffer, but keeping the same offsets in the input and
     * output buffer during decryption makes the code much easier to read.
     */
    dlen = input_len;
    outbuf = apr_palloc(ctx->pool, dlen);

    /*
     * Find the decryption key.  If there's only one entry in the keyring,
     * this is easy: we use that key.  Otherwise, we try the hinted key.
     * Failing that, we try all keys.
     */
    if (ring->num_entries == 1) {
        key = ring->entries[0].key;
        status = decrypt_token(ctx, inbuf, input_len, outbuf, &dlen, key);
    } else {
        uint32_t hint_buf;
        time_t hint;

        /* First, try the hint. */
        memcpy(&hint_buf, inbuf, sizeof(hint_buf));
        hint = ntohl(hint_buf);
        key = webauth_keyring_best_key(ring, 0, hint);
        if (key == NULL)
            status = WA_ERR_BAD_HMAC;
        else
            status = decrypt_token(ctx, inbuf, input_len, outbuf, &dlen, key);

        /*
         * Now, as long as we didn't decode successfully, try each key in the
         * keyring in turn.  If the input is dirty, we have to replace the
         * input with our temporary buffer and try again.
         */
        for (i = 0; status == WA_ERR_BAD_HMAC && i < ring->num_entries; i++)
            if (ring->entries[i].key != key)
                status = decrypt_token(ctx, inbuf, input_len, outbuf, &dlen,
                                       ring->entries[i].key);
    }
    if (status == WA_ERR_NONE) {
        *output = (char *) outbuf;
        *output_len = dlen;
    }
    return status;
}
