/*
 * Test suite for keyring handling.
 *
 * Written by Roland Schemers and Russ Allbery <eagle@eyrie.org>
 * Copyright 2002, 2003, 2005, 2006, 2009, 2010, 2012, 2013, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/apr.h>
#include <portable/system.h>

#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>

#include <tests/tap/basic.h>
#include <tests/tap/string.h>
#include <webauth/basic.h>
#include <webauth/keys.h>


int
main(void)
{
    struct webauth_context *ctx;
    struct webauth_key *key;
    const struct webauth_key *best;
    struct webauth_keyring *ring, *ring2;
    struct webauth_keyring_entry *entry, *entry2;
    char *tmpdir, *keyring, *lock, *buf2;
    char buf[4096];
    FILE *file;
    int s, ks, fd;
    size_t i, size;
    time_t now;
    enum webauth_kau_status kau;
    struct stat st;

    plan(98);

    if (webauth_context_init(&ctx, NULL) != WA_ERR_NONE)
        bail("cannot initialize WebAuth context");

    /* Create a random key and then create a keyring from that key. */
    s = webauth_key_create(ctx, WA_KEY_AES, WA_AES_128, NULL, &key);
    is_int(WA_ERR_NONE, s, "Key created successfully");
    ring = webauth_keyring_from_key(ctx, key);
    ok(ring->entries != NULL, "Keyring created successfully");
    if (ring->entries == NULL)
        bail("Cannot continue after keyring creation failure");
    is_int(1, ring->entries->nelts, "... with one entry");
    entry = &APR_ARRAY_IDX(ring->entries, 0, struct webauth_keyring_entry);
    is_int(0, entry->creation, "Key has 0 creation time");
    is_int(0, entry->valid_after, "... and 0 valid after");
    ok(entry->key != key, "Key in the ring is a copy");
    is_int(key->type, entry->key->type, "... with correct type");
    is_int(key->length, entry->key->length, "... and length");
    ok(memcmp(key->data, entry->key->data, key->length) == 0,
       "... and correct data");

    /* Create a ring with a specific capacity and add a couple of keys. */
    ring = webauth_keyring_new(ctx, 1);
    ok(ring != NULL, "Creating a keyring succeeds");
    s = webauth_key_create(ctx, WA_KEY_AES, WA_AES_256, NULL, &key);
    is_int(WA_ERR_NONE, s, "Creating a key succeeds");
    now = time(NULL);
    if (ring == NULL)
        bail("Cannot continue after keyring creation failure");
    webauth_keyring_add(ctx, ring, now, now, key);
    ok(ring->entries != NULL, "Key added successfully");
    if (ring->entries == NULL)
        bail("Cannot continue after keyring creation failure");
    is_int(1, ring->entries->nelts, "... with one entry");
    entry = &APR_ARRAY_IDX(ring->entries, 0, struct webauth_keyring_entry);
    is_int(now, entry->creation, "Key has correct creation time");
    is_int(now, entry->valid_after, "... and correct valid after");
    s = webauth_key_create(ctx, WA_KEY_AES, WA_AES_128, NULL, &key);
    is_int(WA_ERR_NONE, s, "Creating another new random key succeeds");
    webauth_keyring_add(ctx, ring, now, now + 3600, key);
    is_int(2, ring->entries->nelts, "Keyring now has two entries");
    entry = &APR_ARRAY_IDX(ring->entries, 1, struct webauth_keyring_entry);
    is_int(now, entry->creation, "Second key has correct creation time");
    is_int(now + 3600, entry->valid_after, "... and correct valid after");

    /* Write the keyring out and then read it back in. */
    tmpdir = test_tmpdir();
    basprintf(&keyring, "%s/webauth_keyring", tmpdir);
    basprintf(&lock, "%s.lock", keyring);
    s = webauth_keyring_write(ctx, ring, keyring);
    if (s != WA_ERR_NONE)
        diag("error message: %s", webauth_error_message(ctx, s));
    is_int(WA_ERR_NONE, s, "Writing the keyring to a file succeeds");
    s = webauth_keyring_read(ctx, keyring, &ring2);
    if (s != WA_ERR_NONE)
        diag("error message: %s", webauth_error_message(ctx, s));
    is_int(WA_ERR_NONE, s, "Reading the keyring back from a file succeeds");
    is_int(ring->entries->nelts, ring2->entries->nelts,
           "... and the key count matches");
    for (i = 0; i < (size_t) ring->entries->nelts; i++) {
        struct webauth_keyring_entry *e1, *e2;

        e1 = &APR_ARRAY_IDX(ring->entries, i, struct webauth_keyring_entry);
        e2 = &APR_ARRAY_IDX(ring2->entries, i, struct webauth_keyring_entry);
        is_int(e1->creation, e2->creation, "Creation of key %lu matches",
               (unsigned long) i);
        is_int(e1->valid_after, e2->valid_after,
               "Valid after of key %lu matches", (unsigned long) i);
        is_int(e1->key->type, e2->key->type, "Type of key %lu matches",
               (unsigned long) i);
        is_int(e1->key->length, e2->key->length, "Length of key %lu matches",
               (unsigned long) i);
        ok(memcmp(e1->key->data, e2->key->data, e1->key->length) == 0,
           "Data of key %lu matches", (unsigned long) i);
    }
    s = webauth_keyring_write(ctx, ring2, keyring);
    is_int(WA_ERR_NONE, s, "Writing the second keyring back out succeeds");

    /* Read the encoded keyring data back in. */
    file = fopen(keyring, "r");
    ok(file != NULL, "...and can open the file");
    if (file == NULL)
        ok_block(5, false, "Keyring file doesn't exist");
    else {
        size = fread(buf, 1, sizeof(buf), file);
        buf[size] = '\0';
        fclose(file);
        s = webauth_keyring_decode(ctx, buf, size, &ring2);
        is_int(WA_ERR_NONE, s, "...and decode the results");
        is_int(ring->entries->nelts, ring2->entries->nelts,
           "... and the key count matches");
        s = webauth_keyring_encode(ctx, ring, &buf2, &size);
        is_int(WA_ERR_NONE, s, "Encoding the first keyring works");
        is_int(strlen(buf), size,
               "...and the length matches the first encoding");
        ok(memcmp(buf, buf2, strlen(buf)) == 0,
           "...and the encoding matches what we read from the file");
    }

    /* Test removal of keys from a keyring. */
    s = webauth_keyring_remove(ctx, ring, 2);
    is_int(WA_ERR_NOT_FOUND, s,
           "Removal of nonexistent key returns correct error");
    s = webauth_keyring_remove(ctx, ring, 0);
    is_int(WA_ERR_NONE, s, "Removing the first key returns success");
    is_int(1, ring->entries->nelts, "Keyring now has one entry");
    entry = &APR_ARRAY_IDX(ring->entries, 1, struct webauth_keyring_entry);
    is_int(now, entry->creation, "First key has correct creation time");
    is_int(now + 3600, entry->valid_after, "... and correct valid after");

    /* Add keys back in. */
    s = webauth_key_create(ctx, WA_KEY_AES, WA_AES_256, NULL, &key);
    is_int(WA_ERR_NONE, s, "Creating a second key succeeds");
    webauth_keyring_add(ctx, ring, now, now, key);
    is_int(2, ring->entries->nelts, "Adding a key back in succeeds");
    s = webauth_key_create(ctx, WA_KEY_AES, WA_AES_192, NULL, &key);
    webauth_keyring_add(ctx, ring, now - 3600, now - 3600, key);
    is_int(WA_ERR_NONE, s, "Creating a third key succeeds");
    is_int(3, ring->entries->nelts,
           "Adding the same key with different times succeeds");

    /* Test finding the best decryption key. */
    s = webauth_keyring_best_key(ctx, ring, WA_KEY_DECRYPT, now - 3600, &best);
    is_int(WA_ERR_NONE, s, "Finding past decryption key works");
    entry = &APR_ARRAY_IDX(ring->entries, 2, struct webauth_keyring_entry);
    ok(entry->key == best, "... and matches the last key we added");
    s = webauth_keyring_best_key(ctx, ring, WA_KEY_DECRYPT, now - 3601, &best);
    is_int(WA_ERR_NOT_FOUND, s,
           "... but a hint older than all valid after returns error");
    s = webauth_keyring_best_key(ctx, ring, WA_KEY_DECRYPT, now - 1, &best);
    is_int(WA_ERR_NONE, s,
           "Finding a decryption key one second in the past works");
    ok(entry->key == best, "... and matches the last key we added");
    s = webauth_keyring_best_key(ctx, ring, WA_KEY_DECRYPT, now, &best);
    is_int(WA_ERR_NONE, s, "Finding the current key succeeds");
    is_int(WA_AES_256, best->length, "... and finds the 256-bit key");
    s = webauth_keyring_best_key(ctx, ring, WA_KEY_DECRYPT, now + 3600, &best);
    is_int(WA_ERR_NONE, s, "Finding a future key succeeds");
    is_int(WA_AES_256, best->length, "... and still finds the 256-bit key");

    /* Test finding the best encryption key. */
    s = webauth_keyring_best_key(ctx, ring, WA_KEY_ENCRYPT, now, &best);
    is_int(WA_ERR_NONE, s, "Finding an encryption key succeeds");
    is_int(WA_AES_256, best->length, "... and finds the 256-bit key");
    s = webauth_keyring_best_key(ctx, ring, WA_KEY_ENCRYPT, now - 3700, &best);
    is_int(WA_ERR_NONE, s, "Finding a past encryption key succeeds");
    is_int(WA_AES_256, best->length, "... and still finds the 256-bit key");

    /* Test finding keys in an empty keyring. */
    webauth_keyring_remove(ctx, ring, 2);
    webauth_keyring_remove(ctx, ring, 1);
    webauth_keyring_remove(ctx, ring, 0);
    s = webauth_keyring_best_key(ctx, ring, WA_KEY_DECRYPT, now, &best);
    is_int(WA_ERR_NOT_FOUND, s, "No decrypt key found in empty keyring");
    s = webauth_keyring_best_key(ctx, ring, WA_KEY_ENCRYPT, now, &best);
    is_int(WA_ERR_NOT_FOUND, s, "No encrypt key found in empty keyring");

    /* Truncate a keyring and test empty keyrings. */
    fd = open(keyring, O_WRONLY | O_TRUNC, 0644);
    if (fd < 0)
        sysbail("Cannot truncate %s", keyring);
    close(fd);
    s = webauth_keyring_read(ctx, keyring, &ring);
    is_int(WA_ERR_FILE_READ, s, "Correct error from reading empty keyring");

    /* Test creating a new keyring with keyring_auto_update. */
    unlink(keyring);
    s = webauth_keyring_auto_update(ctx, keyring, false, 0, &ring, &kau, &ks);
    is_int(WA_ERR_FILE_NOT_FOUND, s,
           "keyring_auto_update fails with no ring and no creation");
    is_int(WA_KAU_NONE, kau, "... with correct kau_status");
    s = webauth_keyring_auto_update(ctx, keyring, true, 0, &ring, &kau, &ks);
    is_int(WA_ERR_NONE, s, "keyring_auto_update creates a new ring");
    is_int(WA_KAU_CREATE, kau, "... with correct kau_status");
    is_int(WA_ERR_NONE, ks, "... and correct update status");
    is_int(1, ring->entries->nelts, "... and new ring has one entry");
    entry = &APR_ARRAY_IDX(ring->entries, 0, struct webauth_keyring_entry);
    ok(entry->creation - now < 2, "... with correct creation");
    ok(entry->valid_after - now < 2, "... and correct valid_after");
    is_int(WA_KEY_AES, entry->key->type, "... and correct key type");
    is_int(WA_AES_128, entry->key->length, "... and is 128-bit AES");
    s = webauth_keyring_read(ctx, keyring, &ring2);
    is_int(WA_ERR_NONE, s, "... and the new ring can be read from disk");
    is_int(1, ring2->entries->nelts, "... and has one entry");
    entry2 = &APR_ARRAY_IDX(ring2->entries, 0, struct webauth_keyring_entry);
    is_int(entry->creation, entry2->creation, "... and creation matches");
    is_int(entry->valid_after, entry2->valid_after, "... and valid matches");
    ok(memcmp(entry->key->data, entry2->key->data, entry->key->length) == 0,
       "... and key data matches");

    /*
     * Backdate the key in our ring and write it back out, then test the
     * automatic update part.
     */
    entry->creation = now - 3600;
    entry->valid_after = now - 3600;
    s = webauth_keyring_write(ctx, ring, keyring);
    is_int(WA_ERR_NONE, s, "Successfully overwrote keyring");
    s = webauth_keyring_auto_update(ctx, keyring, false, 0, &ring, &kau, &ks);
    is_int(WA_ERR_NONE, s, "Read updated keyring with keyring_auto_update");
    is_int(WA_KAU_NONE, kau, "... and keyring was not updated");
    is_int(1, ring->entries->nelts, "... and still has one entry");
    s = webauth_keyring_auto_update(ctx, keyring, false, 3600, &ring, &kau,
                                    &ks);
    is_int(WA_ERR_NONE, s,
           "Read keyring with keyring_auto_update with update");
    is_int(WA_KAU_UPDATE, kau, "... and keyring was updated");
    is_int(WA_ERR_NONE, ks, "... successfully");
    is_int(2, ring->entries->nelts, "... and the keyring now has two entries");
    entry = &APR_ARRAY_IDX(ring->entries, 1, struct webauth_keyring_entry);
    ok(entry->creation - now < 2, "... with correct new creation");
    ok(entry->valid_after - now < 2, "... and correct new valid_after");
    is_int(WA_KEY_AES, entry->key->type, "... and correct key type");
    is_int(WA_AES_128, entry->key->length, "... and is 128-bit AES");
    s = webauth_keyring_read(ctx, keyring, &ring2);
    is_int(WA_ERR_NONE, s, "... and the new ring can be read from disk");
    is_int(2, ring2->entries->nelts, "... and has two entries");
    entry2 = &APR_ARRAY_IDX(ring2->entries, 1, struct webauth_keyring_entry);
    is_int(entry->creation, entry2->creation, "... and creation matches");
    is_int(entry->valid_after, entry2->valid_after, "... and valid matches");
    ok(memcmp(entry->key->data, entry2->key->data, entry->key->length) == 0,
       "... and key data matches");

    /* Change the mode of the keyring and ensure it is preserved on write. */
    if (chmod(keyring, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) < 0)
        sysbail("cannot chmod %s", keyring);
    s = webauth_keyring_write(ctx, ring, keyring);
    is_int(WA_ERR_NONE, s, "Overwrote keyring with changed permissions");
    if (stat(keyring, &st) < 0)
        sysbail("cannot stat %s", keyring);
    is_int(S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP, st.st_mode,
           "...and writing the keyring preserves permissions");

    /* Clean up. */
    unlink(keyring);
    free(keyring);
    unlink(lock);
    free(lock);
    test_tmpdir_free(tmpdir);
    webauth_context_free(ctx);
    return 0;
}
