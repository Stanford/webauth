/*
 * WebAuth encryption and decryption token handling.
 *
 * This file contains all the low-level crypto functions for encoding tokens
 * into their encrypted form or reversing that process.  Although these
 * functions are intended for use with WebAuth tokens, they actually encrypt
 * and decrypt opaque data into the encrypted format WebAuth uses, and don't
 * care what they're encrypting.
 *
 * Written by Roland Schemers
 * Copyright 2002, 2003, 2006, 2009, 2010, 2011, 2012, 2013, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/apr.h>
#include <portable/system.h>

#include <apr_pools.h>
#include <netinet/in.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <time.h>

#include <lib/internal.h>
#include <util/macros.h>
#include <webauth/basic.h>
#include <webauth/keys.h>
#include <webauth/tokens.h>

/*
 * An IV to pass to the AES encryption function.  Since the first block of any
 * token is a random nonce, this is uninteresting and therefore always set to
 * all zeroes.  The random nonce will randomize the rest of the CBC mode
 * encryption.
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
 * Set the internal error for an OpenSSL error.  Takes the WebAuth context to
 * use to store the error, the WebAuth return status to use, and a
 * printf-style format.  Obtains the first error in the OpenSSL error stack
 * and its corresponding message, sets the WebAuth error to the result of the
 * format with a colon, space, and the OpenSSL error appended, and then
 * returns the WebAuth error code (so that the calling function can just
 * return the result of this function).
 */
static int
openssl_error(struct webauth_context *ctx, int s, const char *format, ...)
{
    va_list args;
    char *buf;
    char errbuf[BUFSIZ];
    unsigned long err;

    va_start(args, format);
    buf = apr_pvsprintf(ctx->pool, format, args);
    va_end(args);
    err = ERR_get_error();
    if (err == 0)
        wai_error_set(ctx, s, "%s", buf);
    else {
        ERR_error_string_n(err, errbuf, sizeof(errbuf));
        wai_error_set(ctx, s, "%s: %s", buf, errbuf);
    }
    return s;
}


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
webauth_token_encrypt(struct webauth_context *ctx, const void *input,
                      size_t len, void **output, size_t *output_len,
                      const struct webauth_keyring *ring)
{
    const struct webauth_key *key;
    size_t elen, plen, i;
    int s;
    unsigned char *result, *p, *hmac;
    AES_KEY aes_key;
    uint32_t hint;

    /* Clear our output paramters in case of error. */
    *output = NULL;
    *output_len = 0;

    /* Find the encryption key to use. */
    s = webauth_keyring_best_key(ctx, ring, WA_KEY_ENCRYPT, 0, &key);
    if (s != WA_ERR_NONE)
        return s;

    /* Create our encryption key. */
    s = AES_set_encrypt_key(key->data, key->length * 8, &aes_key);
    if (s != 0) {
        s = WA_ERR_BAD_KEY;
        return openssl_error(ctx, s, "cannot set encryption key");
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
    s = RAND_pseudo_bytes(p, T_NONCE_S);
    if (s < 0) {
        s = WA_ERR_RAND_FAILURE;
        return openssl_error(ctx, s, "cannot generate random nonce");
    }
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
     * better than this for the HMAC key.
     */
    hmac = HMAC(EVP_sha1(), key->data, key->length,
                result + T_ATTR_O, len + plen,         /* data, len */
                result + T_HMAC_O, NULL);              /* hmac, len */
    if (hmac == NULL)
        return openssl_error(ctx, WA_ERR_CORRUPT, "cannot compute HMAC");

    /*
     * Now AES-encrypt in place everything but the time at the front.
     * AES_cbc_encrypt doesn't return anything.
     */
    AES_cbc_encrypt(result + T_NONCE_O, result + T_NONCE_O, elen - T_HINT_S,
                    &aes_key, aes_ivec, AES_ENCRYPT);

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
              const struct webauth_key *key)
{
    unsigned char computed_hmac[T_HMAC_S];
    size_t needed, plen, i;
    int s;
    unsigned char *hmac;
    AES_KEY aes_key;

    /* Basic sanity check. */
    needed = T_HINT_S + T_NONCE_S + T_HMAC_S;
    if (length < needed + needed % AES_BLOCK_SIZE)
        return wai_error_set(ctx, WA_ERR_CORRUPT, "token too short");

    /* Create our decryption key. */
    s = AES_set_decrypt_key(key->data, key->length * 8, &aes_key);
    if (s != 0)
        return openssl_error(ctx, WA_ERR_BAD_KEY, "cannot set encryption key");

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
     * decryption succeeded.
     */
    hmac = HMAC(EVP_sha1(), key->data, key->length, output + T_ATTR_O,
                length - T_ATTR_O, computed_hmac, NULL);
    if (hmac == NULL)
        return openssl_error(ctx, WA_ERR_CORRUPT, "cannot compute HMAC");
    if (memcmp(output + T_HMAC_O, computed_hmac, T_HMAC_S) != 0)
        return wai_error_set(ctx, WA_ERR_BAD_HMAC, NULL);

    /* Check padding length and data validity. */
    plen = output[length - 1];
    if (plen > AES_BLOCK_SIZE || plen > length)
        return wai_error_set(ctx, WA_ERR_CORRUPT, "token padding corrupt");
    for (i = length - plen; i < length - 1; i++)
        if (output[i] != plen)
            return wai_error_set(ctx, WA_ERR_CORRUPT, "token padding corrupt");

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
webauth_token_decrypt(struct webauth_context *ctx, const void *input,
                      size_t input_len, void **output, size_t *output_len,
                      const struct webauth_keyring *ring)
{
    size_t dlen, i;
    int s;
    const struct webauth_key *key;
    const unsigned char *inbuf = input;
    unsigned char *outbuf;
    const struct webauth_keyring_entry *entry;

    /* Clear our output parameters in case of an error. */
    *output = NULL;
    *output_len = 0;

    /* Sanity-check our keyring. */
    if (ring->entries->nelts == 0)
        return wai_error_set(ctx, WA_ERR_BAD_KEY, "empty keyring");

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
    if (ring->entries->nelts == 1) {
        entry = &APR_ARRAY_IDX(ring->entries, 0, struct webauth_keyring_entry);
        key = entry->key;
        s = decrypt_token(ctx, inbuf, input_len, outbuf, &dlen, key);
    } else {
        uint32_t hint_buf;
        time_t h;

        /* First, try the hint. */
        memcpy(&hint_buf, inbuf, sizeof(hint_buf));
        h = ntohl(hint_buf);
        s = webauth_keyring_best_key(ctx, ring, WA_KEY_DECRYPT, h, &key);
        if (s == WA_ERR_NONE)
            s = decrypt_token(ctx, inbuf, input_len, outbuf, &dlen, key);
        else
            s = WA_ERR_BAD_HMAC;

        /*
         * Now, as long as we didn't decode successfully, try each key in the
         * keyring in turn.  If the input is dirty, we have to replace the
         * input with our temporary buffer and try again.
         */
        if (s == WA_ERR_BAD_HMAC)
            for (i = 0; i < (size_t) ring->entries->nelts; i++) {
                entry = &APR_ARRAY_IDX(ring->entries, i,
                                       struct webauth_keyring_entry);
                if (entry->key == key)
                    continue;
                s = decrypt_token(ctx, inbuf, input_len, outbuf, &dlen,
                                  entry->key);
                if (s != WA_ERR_BAD_HMAC)
                    break;
            }
    }
    if (s == WA_ERR_NONE) {
        *output = outbuf;
        *output_len = dlen;
    }
    return s;
}
