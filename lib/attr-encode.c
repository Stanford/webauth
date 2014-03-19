/*
 * Low-level attribute encoding.
 *
 * Provided here is a table-driven encoder that transforms a struct into
 * WebAuth attribute encoding.  This is the encoding used inside tokens and
 * for some other WebAuth persistant data structures, such as service token
 * caches and keyrings.
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

#include <netinet/in.h>
#include <time.h>

#include <lib/internal.h>
#include <util/macros.h>
#include <webauth/basic.h>
#include <webauth/tokens.h>

/*
 * Macros used to resolve a void * pointer to a struct and an offset into a
 * pointer to the appropriate type.  Scary violations of the C type system
 * lurk here.
 */
#define LOC_DATA(d, o)   (void **)         (void *)((char *) (d) + (o))
#define LOC_INT32(d, o)  (int32_t *)       (void *)((char *) (d) + (o))
#define LOC_STRING(d, o) (char **)         (void *)((char *) (d) + (o))
#define LOC_SIZE(d, o)   (size_t *)        (void *)((char *) (d) + (o))
#define LOC_TIME(d, o)   (time_t *)        (void *)((char *) (d) + (o))
#define LOC_UINT32(d, o) (uint32_t *)      (void *)((char *) (d) + (o))
#define LOC_ULONG(d, o)  (unsigned long *) (void *)((char *) (d) + (o))


/*
 * Report an error while encoding an attribute.  Takes the WebAuth context,
 * status, description, context (for repeated elements), and element number
 * (for repeated elements).  This is an internal helper function for
 * encode_to_attrs.
 */
static void
encode_error_set(struct webauth_context *ctx, int s, const char *desc,
                 const char *context, size_t element)
{
    if (context != NULL && element != 0)
        wai_error_set(ctx, s, "encoding %s %s %lu", context, desc,
                      (unsigned long) element);
    else
        wai_error_set(ctx, s, "encoding %s", desc);
}


/*
 * Append an attribute and value to the output buffer.  Takes the output
 * buffer, the attribute key (as a string), the value and its length, and a
 * flag indicating whether to hex-encode the data.  Returns a WebAuth error
 * code.
 */
static int
encode_data(struct wai_buffer *output, const char *attr, const void *data,
            size_t length, bool ascii)
{
    size_t hexlen, i, enclen;
    const char *in = data;
    char *p;
    int s;

    wai_buffer_append_sprintf(output, "%s=", attr);
    if (ascii) {
        hexlen = wai_hex_encoded_length(length);
        wai_buffer_resize(output, output->used + hexlen + 1);
        s = wai_hex_encode(data, length, output->data + output->used,
                           &hexlen, hexlen);
        if (s != WA_ERR_NONE)
            return s;
        output->used += hexlen;
        output->data[output->used] = ';';
        output->used++;
    } else {
        for (i = 0, enclen = 0; i < length; i++, enclen++)
            if (in[i] == ';')
                enclen++;
        wai_buffer_resize(output, output->used + enclen + 1);
        for (i = 0, p = output->data + output->used; i < length; i++, p++) {
            *p = in[i];
            if (in[i] == ';') {
                p++;
                *p = ';';
            }
        }
        *p = ';';
        output->used += enclen + 1;
    }
    return WA_ERR_NONE;
}


/*
 * Encode an attribute and numeric value to the output buffer.  Takes the
 * output buffer, the attribute key (as a string), the value as an unsigned
 * integer, and a flag indicating whether to format the number as a string.
 */
static void
encode_number(struct wai_buffer *output, const char *attr, unsigned long value,
              bool ascii)
{
    if (ascii)
        wai_buffer_append_sprintf(output, "%s=%lu;", attr, value);
    else {
        uint32_t data = value;

        data = htonl(data);
        encode_data(output, attr, &data, sizeof(data), false);
    }
}


/*
 * Given an encoding specification, a data source, and a buffer, encode into
 * attribute form in the given buffer.  Context is a string to prepend to the
 * description for error reporting.  If context is non-NULL, we are handling a
 * repeated attribute encoding, and the element number is appended to the
 * attribute name when encoding it.
 *
 * This is an internal helper function used by wai_encode.
 */
static int
encode_to_attrs(struct webauth_context *ctx, const struct wai_encoding *rules,
                const void *input, struct wai_buffer *output,
                const char *context, unsigned long element)
{
    const struct wai_encoding *rule;
    const char *attr;
    unsigned long i;
    int s;
    void *data, *repeat;
    int32_t int32;
    char *string;
    size_t size;
    time_t timev;
    uint32_t uint32;
    unsigned long ulong;

    for (rule = rules; rule->attr != NULL; rule++) {
        if (context == NULL)
            attr = rule->attr;
        else
            attr = apr_psprintf(ctx->pool, "%s%lu", rule->attr, element);
        s = WA_ERR_NONE;
        switch (rule->type) {
        case WA_TYPE_DATA:
            data = *LOC_DATA(input, rule->offset);
            if (rule->optional && data == NULL)
                break;
            if (data == NULL) {
                s = WA_ERR_INVALID;
                break;
            }
            size = *LOC_SIZE(input, rule->len_offset);
            s = encode_data(output, attr, data, size, rule->ascii);
            break;
        case WA_TYPE_STRING:
            string = *LOC_STRING(input, rule->offset);
            if (rule->optional && string == NULL)
                break;
            if (string == NULL) {
                s = WA_ERR_INVALID;
                break;
            }
            s = encode_data(output, attr, string, strlen(string), false);
            break;
        case WA_TYPE_INT32:
            int32 = *LOC_INT32(input, rule->offset);
            if (rule->optional && int32 == 0)
                break;
            encode_number(output, attr, int32, rule->ascii);
            break;
        case WA_TYPE_UINT32:
            uint32 = *LOC_UINT32(input, rule->offset);
            if (rule->optional && uint32 == 0)
                break;
            encode_number(output, attr, uint32, rule->ascii);
            break;
        case WA_TYPE_ULONG:
            ulong = *LOC_ULONG(input, rule->offset);
            if (rule->optional && ulong == 0)
                break;
            encode_number(output, attr, ulong, rule->ascii);
            break;
        case WA_TYPE_TIME:
            timev = *LOC_TIME(input, rule->offset);
            if (rule->creation && timev == 0)
                timev = time(NULL);
            if (rule->optional && timev == 0)
                break;
            encode_number(output, attr, timev, rule->ascii);
            break;
        case WA_TYPE_REPEAT:
            uint32 = *LOC_UINT32(input, rule->len_offset);
            if (rule->optional && uint32 == 0)
                break;
            encode_number(output, attr, uint32, rules->ascii);
            for (i = 0; i < uint32; i++) {
                repeat = *LOC_STRING(input, rule->offset) + rule->size * i;
                s = encode_to_attrs(ctx, rule->repeat, repeat, output,
                                    attr, i);
                if (s != WA_ERR_NONE)
                    return s;
            }
            break;
        }
        if (s != WA_ERR_NONE) {
            encode_error_set(ctx, s, rule->desc, context, element);
            return s;
        }
    }
    return WA_ERR_NONE;
}


/*
 * Given an encoding specification and a pointer to the data to encode, encode
 * into attributes and return the encoded string in newly-allocated pool
 * memory.  Takes a separate pool to use rather than using the normal WebAuth
 * context pool, since attribute encoding can churn a lot of memory.
 */
int
wai_encode(struct webauth_context *ctx, const struct wai_encoding *rules,
           const void *data, void **output, size_t *length)
{
    struct wai_buffer *buffer;
    int s;

    buffer = wai_buffer_new(ctx->pool);
    s = encode_to_attrs(ctx, rules, data, buffer, NULL, 0);
    if (s != WA_ERR_NONE)
        return s;
    *output = buffer->data;
    *length = buffer->used;
    return WA_ERR_NONE;
}


/*
 * Similar to wai_encode, but encodes a WebAuth token, including adding the
 * appropriate encoding of the token type.  This does not perform any sanity
 * checking on the token data; that must be done by higher-level code.
 */
int
wai_encode_token(struct webauth_context *ctx,
                 const struct webauth_token *token, void **output,
                 size_t *length)
{
    struct wai_buffer *buffer;
    int s;
    const char *type;
    const struct wai_encoding *rules;
    const void *data;

    s = wai_token_encoding(ctx, token, &rules, &data);
    if (s != WA_ERR_NONE)
        return s;
    buffer = wai_buffer_new(ctx->pool);
    type = webauth_token_type_string(token->type);
    wai_buffer_append_sprintf(buffer, "t=%s;", type);
    s = encode_to_attrs(ctx, rules, data, buffer, NULL, 0);
    if (s != WA_ERR_NONE)
        return s;
    *output = buffer->data;
    *length = buffer->used;
    return WA_ERR_NONE;
}
