/*
 * Internal functions for file input/output.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2012, 2013, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/apr.h>
#include <portable/system.h>

#include <lib/internal.h>
#include <webauth/basic.h>


/*
 * Lock a file by name.  Returns a WebAuth error code, and stores the object
 * representing the file lock in the third argument.  That result should be
 * passed to wai_file_unlock to unlock the file.
 *
 * This function creates and locks a separate lock file formed by adding
 * ".lock" to the end of the provided file name.  This allows atomic replace
 * of the file being locked without releasing the lock, which eliminates some
 * race conditions.  It requires the locking process have write access to the
 * directory containing the file.
 */
int
wai_file_lock(struct webauth_context *ctx, const char *path,
              apr_file_t **lock)
{
    char *name;
    apr_file_t *file = NULL;
    apr_status_t code;
    apr_int32_t flags;
    apr_fileperms_t perms;

    /* Set the output parameter in case of error. */
    *lock = NULL;

    /*
     * Open the lock file.  First, try to open it assuming it exists.  If this
     * fails because the file doesn't exist, try again with exclusive create.
     */
    name = apr_psprintf(ctx->pool, "%s.lock", path);
    flags = APR_FOPEN_WRITE;
    perms = APR_FPROT_UREAD | APR_FPROT_UWRITE;
    code = apr_file_open(&file, name, flags, perms, ctx->pool);
    if (code != APR_SUCCESS && APR_STATUS_IS_ENOENT(code)) {
        flags |= APR_FOPEN_CREATE | APR_FOPEN_EXCL;
        code = apr_file_open(&file, name, flags, perms, ctx->pool);
    }
    if (code != APR_SUCCESS)
        return wai_error_set_apr(ctx, WA_ERR_FILE_OPENWRITE, code, "%s", name);

    /* Lock the file exclusively. */
    code = apr_file_lock(file, APR_FLOCK_EXCLUSIVE);
    if (code != APR_SUCCESS) {
        apr_file_close(file);
        return wai_error_set_apr(ctx, WA_ERR_FILE_LOCK, code, "%s", name);
    }

    /* Success.  Return the results. */
    *lock = file;
    return WA_ERR_NONE;
}


/*
 * Unlock a file.  Takes the path of the file to unlock for error reporting,
 * and the apr_file_t returned by wai_file_lock.
 */
int
wai_file_unlock(struct webauth_context *ctx, const char *path,
                apr_file_t *lock)
{
    int s;
    apr_status_t code;

    code = apr_file_unlock(lock);
    if (code != APR_SUCCESS) {
        s = WA_ERR_FILE_LOCK;
        return wai_error_set_apr(ctx, s, code, "unlock %s.lock", path);
    }
    apr_file_close(lock);
    return WA_ERR_NONE;
}


/*
 * Read in the entirety of a file, continuing after partial reads or signal
 * interruptions.  Takes the WebAuth context, the file name, and pointers into
 * which to store the newly allocated buffer and length.  Returns a WebAuth
 * error code.
 */
int
wai_file_read(struct webauth_context *ctx, const char *path,
              void **output, size_t *length)
{
    apr_file_t *file = NULL;
    apr_finfo_t finfo;
    apr_size_t size;
    void *buf;
    apr_status_t code;
    int s;

    /* Set output parameters in case of error. */
    *output = NULL;
    *length = 0;

    /* Open the file. */
    code = apr_file_open(&file, path, APR_FOPEN_READ | APR_FOPEN_NOCLEANUP,
                         APR_FPROT_UREAD | APR_FPROT_UWRITE, ctx->pool);
    if (code != APR_SUCCESS) {
        if (APR_STATUS_IS_ENOENT(code))
            s = WA_ERR_FILE_NOT_FOUND;
        else
            s = WA_ERR_FILE_OPENREAD;
        wai_error_set_apr(ctx, s, code, "%s", path);
        goto done;
    }

    /* Allocate enough room for the contents. */
    code = apr_file_info_get(&finfo, APR_FINFO_SIZE, file);
    if (code != APR_SUCCESS) {
        s = WA_ERR_FILE_READ;
        wai_error_set_apr(ctx, s, code, "stat of %s", path);
        goto done;
    }
    if (finfo.size == 0) {
        s = WA_ERR_FILE_READ;
        wai_error_set(ctx, s, "%s is empty", path);
        goto done;
    }
    buf = apr_palloc(ctx->pool, finfo.size);

    /* Read the contents. */
    code = apr_file_read_full(file, buf, finfo.size, &size);
    if (code != APR_SUCCESS) {
        s = WA_ERR_FILE_READ;
        wai_error_set_apr(ctx, s, code, "%s", path);
        goto done;
    }
    if ((apr_off_t) size != finfo.size) {
        s = WA_ERR_FILE_READ;
        wai_error_set(ctx, s, "%s modified during read", path);
        goto done;
    }
    *output = buf;
    *length = size;
    s = WA_ERR_NONE;

done:
    if (file != NULL)
        apr_file_close(file);
    return s;
}


/*
 * Write data to a file atomically, continuing after partial reads or signal
 * interruptions.  Takes the WebAuth context, the data, and the file name.
 * Returns a WebAuth error code.
 *
 * FIXME: Does not preserve permissions.
 */
int
wai_file_write(struct webauth_context *ctx, const void *data, size_t length,
               const char *path)
{
    apr_file_t *file = NULL;
    char *temp = NULL;
    apr_int32_t flags;
    apr_status_t code;
    int s;

    /* Create a temporary file for the new copy of the keyring. */
    temp = apr_psprintf(ctx->pool, "%s.XXXXXX", path);
    flags = (APR_FOPEN_CREATE | APR_FOPEN_WRITE | APR_FOPEN_EXCL
             | APR_FOPEN_NOCLEANUP);
    code = apr_file_mktemp(&file, temp, flags, ctx->pool);
    if (code != APR_SUCCESS) {
        s = WA_ERR_FILE_OPENWRITE;
        wai_error_set_apr(ctx, s, code, "temporary file %s", temp);
        goto done;
    }

    /* Write out the file contents. */
    code = apr_file_write_full(file, data, length, NULL);
    if (code == APR_SUCCESS) {
        code = apr_file_close(file);
        file = NULL;
    }
    if (code != APR_SUCCESS) {
        s = WA_ERR_FILE_WRITE;
        wai_error_set_apr(ctx, s, code, "temporary file %s", temp);
        goto done;
    }

    /* Set permissions. */
    code = apr_file_perms_set(temp, APR_FPROT_UREAD | APR_FPROT_UWRITE);
    if (code != APR_SUCCESS && code != APR_ENOTIMPL) {
        s = WA_ERR_FILE_WRITE;
        wai_error_set_apr(ctx, s, code, "setting permissions on %s", temp);
        goto done;
    }

    /* Rename the new file over the old path. */
    code = apr_file_rename(temp, path, ctx->pool);
    if (code != APR_SUCCESS) {
        s = WA_ERR_FILE_WRITE;
        wai_error_set_apr(ctx, s, code, "renaming %s to %s", temp, path);
        goto done;
    }
    temp = NULL;
    s = WA_ERR_NONE;

done:
    if (file != NULL)
        apr_file_close(file);
    if (temp != NULL)
        apr_file_remove(temp, ctx->pool);
    return s;
}
