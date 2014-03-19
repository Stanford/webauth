/*
 * Counted, reusable memory buffer.
 *
 * A buffer is an allocated bit of memory with a known size and a separate
 * data length.  It's intended to store strings that need to be appended to an
 * unbounded number of times, and tries to minimize the number of memory
 * allocations.  Buffers increase in increments of 64 bytes.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2011, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/apr.h>
#include <portable/system.h>

#include <lib/internal.h>


/*
 * Allocate a new struct wai_buffer and initialize it.
 */
struct wai_buffer *
wai_buffer_new(apr_pool_t *pool)
{
    struct wai_buffer *buffer;

    buffer = apr_palloc(pool, sizeof(struct wai_buffer));
    if (buffer == NULL)
        return buffer;
    buffer->pool = pool;
    buffer->size = 0;
    buffer->used = 0;
    buffer->data = NULL;
    return buffer;
}


/*
 * Resize a buffer to be at least as large as the provided second argument.
 * Resize buffers to multiples of 64 bytes to reduce the number of
 * reallocations.  Refuse to resize a buffer to make it smaller.
 */
void
wai_buffer_resize(struct wai_buffer *buffer, size_t size)
{
    char *data;

    if (size < buffer->size)
        return;
    buffer->size = (size + 63) & ~63UL;
    data = apr_palloc(buffer->pool, buffer->size);
    if (buffer->data != NULL)
        memcpy(data, buffer->data, buffer->used);
    buffer->data = data;
}


/*
 * Replace whatever data is currently in the buffer with the provided data.
 * Resize the buffer if needed.
 */
void
wai_buffer_set(struct wai_buffer *buffer, const char *data, size_t length)
{
    wai_buffer_resize(buffer, length + 1);
    if (length > 0)
        memmove(buffer->data, data, length + 1);
    buffer->data[length] = '\0';
    buffer->used = length;
}


/*
 * Append data to a buffer.  The new data shows up as additional unused data
 * at the end of the buffer.  Resize the buffer if needed.
 */
void
wai_buffer_append(struct wai_buffer *buffer, const char *data, size_t length)
{
    if (length == 0)
        return;
    wai_buffer_resize(buffer, buffer->used + length + 1);
    memcpy(buffer->data + buffer->used, data, length);
    buffer->used += length;
    buffer->data[buffer->used] = '\0';
}


/*
 * Print data into a buffer from the supplied va_list, appending to the end.
 * The trailing nul is not added to the buffer.
 */
void
wai_buffer_append_vsprintf(struct wai_buffer *buffer, const char *format,
                           va_list args)
{
    size_t avail;
    ssize_t status;
    va_list args_copy;

    avail = buffer->size - buffer->used;
    va_copy(args_copy, args);
    status = vsnprintf(buffer->data + buffer->used, avail, format, args_copy);
    va_end(args_copy);
    if (status < 0)
        return;
    if ((size_t) status + 1 > avail) {
        wai_buffer_resize(buffer, buffer->used + status + 1);
        avail = buffer->size - buffer->used;
        status = vsnprintf(buffer->data + buffer->used, avail, format, args);
        if (status < 0 || (size_t) status + 1 > avail)
            return;
    }
    buffer->used += status;
}


/*
 * Print data into a buffer, appending to the end.  Resize the buffer if
 * needed.  The trailing nul is not added to the buffer.
 */
void
wai_buffer_append_sprintf(struct wai_buffer *buffer, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    wai_buffer_append_vsprintf(buffer, format, args);
    va_end(args);
}


/*
 * Find a given string in the buffer.  Returns the offset of the string (with
 * the same meaning as start) in offset if found, and returns true if the
 * terminator is found and false otherwise.
 */
bool
wai_buffer_find_string(struct wai_buffer *buffer, const char *string,
                       size_t start, size_t *offset)
{
    char *terminator, *data;
    size_t length;

    /* If there isn't room for the search string, always return false. */
    length = strlen(string);
    if (buffer->size < length || start > buffer->size - length)
        return false;

    /* Check each possible match point by searching for the first octet. */
    do {
        data = buffer->data + start;
        terminator = memchr(data, string[0], buffer->used - start);
        if (terminator == NULL)
            return false;
        start = terminator - buffer->data;
        if (buffer->used - start < length)
            return false;
        start++;
    } while (memcmp(terminator, string, length) != 0);

    /* Success.  Return the offset. */
    *offset = start - 1;
    return true;
}
