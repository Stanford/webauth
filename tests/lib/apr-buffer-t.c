/*
 * APR buffer test suite.
 *
 * Test the APR-aware memory buffer code that's used internally by the
 * libwebauth library.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2012, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <lib/internal.h>
#include <tests/tap/basic.h>

static const char test_string1[] = "This is a test";
static const char test_string2[] = " of the buffer system";
static const char test_string3[] = "This is a test\0 of the buffer system";


/*
 * Test wai_buffer_append_vsprintf.  Wrapper needed to generate the va_list.
 */
static void
test_append_vsprintf(struct wai_buffer *buffer, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    wai_buffer_append_vsprintf(buffer, format, args);
    va_end(args);
}


int
main(void)
{
    apr_pool_t *pool;
    struct wai_buffer *buffer;
    size_t offset;
    char *data;

    if (apr_initialize() != APR_SUCCESS)
        bail("cannot initialize APR");
    if (apr_pool_create(&pool, NULL) != APR_SUCCESS)
        bail("cannot create memory pool");

    plan(41);

    /* buffer_new, buffer_set, buffer_append */
    buffer = wai_buffer_new(pool);
    ok(buffer != NULL, "buffer is not NULL");
    if (buffer == NULL)
        bail("Cannot continue after buffer creation failed");
    is_int(0, buffer->size, "buffer starts with no data");
    is_int(0, buffer->used, "...and no data used");
    ok(buffer->data == NULL, "...and no data pointer");
    wai_buffer_set(buffer, test_string1, sizeof(test_string1));
    is_int(64, buffer->size, "minimum size is 64");
    is_int(sizeof(test_string1), buffer->used, "used is correct after set");
    is_string(test_string1, buffer->data, "data is corect after set");
    wai_buffer_append(buffer, test_string2, sizeof(test_string2));
    is_int(64, buffer->size, "appended data doesn't change size");
    is_int(sizeof(test_string3), buffer->used, "but used is the right size");
    ok(memcmp(buffer->data, test_string3, sizeof(test_string3)) == 0,
       "and the resulting data is correct");

    /* buffer_resize */
    wai_buffer_resize(buffer, 32);
    is_int(64, buffer->size, "resizing to something smaller doesn't change");
    wai_buffer_resize(buffer, 65);
    is_int(128, buffer->size, "resizing to something larger goes to 128");

    /* buffer_find_string */
    offset = 42;
    ok(!wai_buffer_find_string(buffer, "foo", 0, &offset),
       "find string on a nonexistent string works");
    is_int(42, offset, "...and offset is unchanged");
    ok(wai_buffer_find_string(buffer, "st", 0, &offset),
       "find string for st succeeds");
    is_int(12, offset, "...with correct offset");
    ok(wai_buffer_find_string(buffer, "st", 13, &offset),
       "find string for second st succeeds");
    is_int(32, offset, "...with correct offset");
    offset = 42;
    ok(wai_buffer_find_string(buffer, "st", 32, &offset),
       "find string at the exact offset succeeds");
    is_int(32, offset, "...with correct offset");
    offset = 42;
    ok(!wai_buffer_find_string(buffer, "st", 33, &offset),
       "find string past the offset fails");
    is_int(42, offset, "...and offset is unchanged");
    ok(!wai_buffer_find_string(buffer, "st", 1024, &offset),
       "find string off the end of the string fails");
    ok(wai_buffer_find_string(buffer, "This", 0, &offset),
       "find string at the start of the string succeeds");
    is_int(0, offset, "...with correct offset");
    offset = 42;
    ok(wai_buffer_find_string(buffer, test_string3, 0, &offset),
       "finding the contents of the whole buffer works");
    is_int(0, offset, "...and returns the correct location");

    /* buffer_append_sprintf */
    buffer = wai_buffer_new(pool);
    wai_buffer_append_sprintf(buffer, "testing %d testing", 6);
    is_int(17, buffer->used, "append_sprintf sets used correctly");
    wai_buffer_append(buffer, "", 1);
    is_int(18, buffer->used, "appending a nul works");
    is_string("testing 6 testing", buffer->data, "the data is correct");
    buffer->used--;
    wai_buffer_append_sprintf(buffer, " %d", 7);
    is_int(19, buffer->used, "appending a digit works");
    wai_buffer_append(buffer, "", 1);
    is_string("testing 6 testing 7", buffer->data,
              "...and the data is correct");
    data = bmalloc(1050);
    memset(data, 'a', 1049);
    data[1049] = '\0';
    wai_buffer_set(buffer, "", 0);
    is_int(64, buffer->size, "size before large sprintf is 64");
    wai_buffer_append_sprintf(buffer, "%s", data);
    is_int(1088, buffer->size, "size after large sprintf is 1088");
    is_int(1049, buffer->used, "...and used is correct");
    wai_buffer_append(buffer, "", 1);
    is_string(data, buffer->data, "...and data is correct");
    free(data);

    /* buffer_vsprintf */
    buffer = wai_buffer_new(pool);
    test_append_vsprintf(buffer, "testing %d testing", 6);
    is_int(17, buffer->used, "buffer_append_vsprintf sets used correctly");
    wai_buffer_append(buffer, "", 1);
    is_int(18, buffer->used, "...and used is correct after appending a nul");
    is_string("testing 6 testing", buffer->data, "...and data is correct");
    buffer->used--;
    test_append_vsprintf(buffer, " %d", 7);
    is_int(19, buffer->used, "...and appending results in the correct used");
    wai_buffer_append(buffer, "", 1);
    is_string("testing 6 testing 7", buffer->data, "...and the right data");

    /* Clean up. */
    apr_terminate();
    return 0;
}
