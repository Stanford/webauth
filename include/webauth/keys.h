/*
 * WebAuth key and keyring manipulation functions.
 *
 * These interfaces handle WebAuth keys and keyrings.  A key is used for token
 * encryption and decryption.  A keyring is a collection of keys with various
 * use-by dates to allow key rollover while decrypting tokens encrypted with
 * older keys.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2011, 2012
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

#ifndef WEBAUTH_KEYS_H
#define WEBAUTH_KEYS_H 1

#include <webauth/defines.h>

struct webauth_context;

/* Supported key types. */
enum webauth_key_type {
    WA_KEY_AES = 1
};

/* Supported key sizes (in bytes, not bits). */
enum webauth_key_size {
    WA_AES_128 = 16,
    WA_AES_192 = 24,
    WA_AES_256 = 32
};

/*
 * Status for webauth_keyring_auto_update, indicating whether the keyring was
 * newly created, updated, or left alone.
 */
enum webauth_kau_status {
    WA_KAU_NONE = 0,
    WA_KAU_CREATE,
    WA_KAU_UPDATE
};

/* Intended usage for a key, used for webauth_keyring_best_key. */
enum webauth_key_usage {
    WA_KEY_DECRYPT = 0,
    WA_KEY_ENCRYPT = 1
};

/* A crypto key for encryption or decryption. */
struct webauth_key {
    enum webauth_key_type type;
    enum webauth_key_size length;
    unsigned char *data;
};

/* An entry in a keyring, holding a struct webauth_key with timestamps. */
struct webauth_keyring_entry {
    time_t creation;
    time_t valid_after;
    struct webauth_key *key;
};

/*
 * A keyring whose elements are of type struct webauth_keyring_entry.  Can be
 * serialized to disk.  We could just use the apr_array_header_t directly, but
 * it's not typed and we could end up with the wrong header.  Wrap it in a
 * struct so that we get the benefits of type checking.
 */
struct webauth_keyring {
    WA_APR_ARRAY_HEADER_T *entries;
};

BEGIN_DECLS

/*
 * Construct new key and stores it in the provided output argument.
 * key_material points to the key material and will be copied into the new
 * key.  If it's NULL, new random key material is generated.
 *
 * Returns a WebAuth status code, which may be WA_ERR_RAND_FAILURE if random
 * key material generation failed.
 */
int webauth_key_create(struct webauth_context *, enum webauth_key_type,
                       enum webauth_key_size,
                       const unsigned char *key_material,
                       struct webauth_key **)
    __attribute__((__nonnull__(1, 5)));

/* Make a copy of a key.  Returns the new key. */
struct webauth_key *webauth_key_copy(struct webauth_context *,
                                     const struct webauth_key *)
    __attribute__((__malloc__, __nonnull__));

/* Create a new keyring. */
struct webauth_keyring *webauth_keyring_new(struct webauth_context *,
                                            size_t initial_capacity)
    __attribute__((__malloc__, __nonnull__));

/*
 * Given a key, form a single-element keyring around it.  Used to convert keys
 * to keyrings for functions that want a keyring.  Stores the new keyring in
 * the ring argument and returns a WebAuth error code.  The key will currently
 * be copied into the ring.  The creation and valid after times for the key
 * will both be set to 0 so that it will be a valid key for any operation.
 */
struct webauth_keyring *webauth_keyring_from_key(struct webauth_context *,
                                                 const struct webauth_key *)
    __attribute__((__malloc__, __nonnull__));

/* Add a new entry to a keyring.  The key is copied into new pool memory. */
void webauth_keyring_add(struct webauth_context *, struct webauth_keyring *,
                         time_t creation, time_t valid_after,
                         const struct webauth_key *)
    __attribute__((__nonnull__));

/*
 * Remove the key at the specified index, shifting the remaining keys down.
 * Returns WA_ERR_NOT_FOUND if the index was not valid.
 */
int webauth_keyring_remove(struct webauth_context *,
                           struct webauth_keyring *, size_t index)
    __attribute__((__nonnull__));

/*
 * Given a keyring, return the best key on the ring for either encryption or
 * decryption.  The best key for encryption is the key with the most current
 * valid valid_after time.  The best key for decryption is the key with the
 * the valid_after time closest to but not more current then hint.
 *
 * A pointer to the key is stored in the key argument, and the function
 * returns a WebAuth status code.  This will be WA_ERR_NOT_FOUND if the
 * keyring is empty, has no valid keys, or (for decryption) has no keys with a
 * valid_after time prior to or equal to the hint.
 */
int webauth_keyring_best_key(struct webauth_context *,
                             const struct webauth_keyring *,
                             enum webauth_key_usage, time_t hint,
                             const struct webauth_key **)
    __attribute__((__nonnull__));

/*
 * Decode a keyring from the serialization format used for storing it in a
 * file or generated by webauth_keyring_encode, storing the result in the
 * webauth_keyring argument.  Returns a WebAuth status code.
 */
int webauth_keyring_decode(struct webauth_context *, const char *, size_t,
                           struct webauth_keyring **)
    __attribute__((__nonnull__));

/*
 * Encode a keyring in the serialization format used for storing it in a file
 * or decodable by webauth_keyring_decode, storing the result in the provided
 * char ** argument and the size of the resulting encoded keyring in the
 * size_t * argument.  Returns a WebAuth status code.
 */
int webauth_keyring_encode(struct webauth_context *,
                           const struct webauth_keyring *, char **, size_t *)
    __attribute__((__nonnull__));

/*
 * Reads a keyring from a file in encoded form and stores the newly-allocated
 * keyring in the provided argument.  Returns a WebAuth status code, which may
 * be WA_ERR_FILE_OPENREAD, WA_ERR_FILE_READ, WA_ERR_CORRUPT, or
 * WA_ERR_FILE_VERSION on failure.
 */
int webauth_keyring_read(struct webauth_context *, const char *,
                         struct webauth_keyring **)
    __attribute__((__nonnull__));

/*
 * Write a keyring to a file in encoded form.  Returns a WebAuth status code,
 * which may be WA_ERR_FILE_OPENWRITE or WA_ERR_FILE_WRITE on failure.
 */
int webauth_keyring_write(struct webauth_context *,
                          const struct webauth_keyring *, const char *)
    __attribute__((__nonnull__));

/*
 * Attempts to read a keyring file, storing the keyring read in the provided
 * argument.  If create is non-zero, it will create the file if it doesn't
 * exist.  If lifetime is non-zero, there must be at least one key in the ring
 * where valid_after + lifetime is greater then the current time; otherwise, a
 * new key will be created with valid_after set to the current time and the
 * key ring file will be updated.
 *
 * This function does no file locking.
 *
 * kau_status will be set to WA_KAU_NONE if we didn't create or update the
 * ring, WA_KAU_CREATE if we attempted to create it, and WA_KAU_UPDATE if we
 * attempted to update it.
 *
 * The return code applies to only the open and/or create.  If the open and/or
 * create succeed, then WA_ERR_NONE will always be returned, even if the
 * update fails.  If the update fails, then update_status will be set to
 * someting other then WA_ERR_NONE.
 *
 * Returns WA_ERR_NONE, WA_ERR_CORRUPT, WA_ERR_NO_MEM, WA_ERR_FILE_READ, or
 * WA_ERR_FILE_OPENREAD.
 */
int webauth_keyring_auto_update(struct webauth_context *, const char *path,
                                int create, unsigned long lifetime,
                                struct webauth_keyring **,
                                enum webauth_kau_status *, int *update_status)
    __attribute__((__nonnull__));

END_DECLS

#endif /* !WEBAUTH_KEYS_H */
