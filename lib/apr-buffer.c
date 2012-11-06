/*
 * Counted, reusable memory buffer.
 *
 * A buffer is an allocated bit of memory with a known size and a separate
 * data length.  It's intended to store strings that need to be appended to an
 * unbounded number of times, and tries to minimize the number of memory
 * allocations.  Buffers increase in increments of 64 bytes.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/apr.h>
#include <portable/system.h>

#include <lib/internal.h>


/*
 * Allocate a new struct buffer and initialize it.
 */
struct buffer *
wai_buffer_new(apr_pool_t *pool)
{
    struct buffer *buffer;

    buffer = apr_palloc(pool, sizeof(struct buffer));
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
 * Resize buffers to multiples of 1KB to keep the number of reallocations to a
 * minimum.  Refuse to resize a buffer to make it smaller.
 */
static void
buffer_resize(struct buffer *buffer, size_t size)
{
    char *data;

    if (size < buffer->size)
        return;
    buffer->size = (size + 64) & ~64UL;
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
wai_buffer_set(struct buffer *buffer, const char *data, size_t length)
{
    buffer_resize(buffer, length + 1);
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
wai_buffer_append(struct buffer *buffer, const char *data, size_t length)
{
    if (length == 0)
        return;
    buffer_resize(buffer, buffer->used + length + 1);
    memcpy(buffer->data + buffer->used, data, length);
    buffer->used += length;
    buffer->data[buffer->used] = '\0';
}


/*
 * Find a given string in the buffer.  Returns the offset of the string (with
 * the same meaning as start) in offset if found, and returns true if the
 * terminator is found and false otherwise.
 */
bool
wai_buffer_find_string(struct buffer *buffer, const char *string,
                       size_t start, size_t *offset)
{
    char *terminator, *data;
    size_t length;

    length = strlen(string);
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
    *offset = start - 1;
    return true;
}
