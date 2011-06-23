/*
 * Test suite for libwebauth attribute handling.
 *
 * Written by Roland Schemers
 * Updated for current TAP library support by Russ Allbery
 * Copyright 2002, 2003, 2006, 2009, 2010
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tests/tap/basic.h>
#include <webauth.h>
#include <webauth/basic.h>

#define BUFSIZE 2048
#define MAX_ATTRS 100


int
main(void)
{
    char *buff;
    WEBAUTH_ATTR_LIST *attrs_in, *attrs_out;
    size_t len, i, rlen;
    int s;
    ssize_t f;
    unsigned char binary_data[BUFSIZE];
    uint32_t temp_u32;
    int32_t temp_32;
    char *temp_str;
    size_t temp_len;

    plan(116);

    for (i = 0; i < sizeof(binary_data); i++)
        binary_data[i] = i % 256;
   
    attrs_in = webauth_attr_list_new(64);
    webauth_attr_list_add(attrs_in, "bin", 
                          binary_data, sizeof(binary_data), WA_F_NONE);
    webauth_attr_list_add_str(attrs_in, "0", "1", 0, WA_F_COPY_NAME);
    webauth_attr_list_add_str(attrs_in, "1", ";", 0, WA_F_COPY_VALUE);
    webauth_attr_list_add_str(attrs_in, "2", "", 0, WA_F_COPY_BOTH);
    webauth_attr_list_add_str(attrs_in, "3", ";a", 0, WA_F_NONE);
    webauth_attr_list_add_str(attrs_in, "4", ";aaa", 0, WA_F_NONE);
    webauth_attr_list_add_str(attrs_in, "5", "a;", 0, WA_F_NONE);
    webauth_attr_list_add_str(attrs_in, "6", "aaa;", 0, WA_F_NONE);
    webauth_attr_list_add_str(attrs_in, "7", ";aaa;", 0, WA_F_NONE);
    webauth_attr_list_add_str(attrs_in, "8", "a;a", 0, WA_F_NONE);
    webauth_attr_list_add_str(attrs_in, "9", "a;a;", 0, WA_F_NONE);
    webauth_attr_list_add_str(attrs_in, "10", "a;a;;", 0, WA_F_NONE);
    webauth_attr_list_add_str(attrs_in, "11", ";a;a;;", 0, WA_F_NONE);
    webauth_attr_list_add_str(attrs_in, "12", ";;", 0, WA_F_NONE);
    webauth_attr_list_add_str(attrs_in, "13", ";;;", 0, WA_F_NONE);
    webauth_attr_list_add_str(attrs_in, "14", ";;;;a", 0, WA_F_NONE);
    webauth_attr_list_add_uint32(attrs_in, "15", 123, WA_F_NONE);

    is_int(WA_ERR_NONE, webauth_attr_list_find(attrs_in, "4", &f),
           "Can find attribute 4");
    is_int(f, 5, "...and is attribute number 5");
    is_int(WA_ERR_NONE, webauth_attr_list_find(attrs_in, "bin", &f),
           "Can find attribute bin");
    is_int(f, 0, "...and is attribute number 0");
    is_int(WA_ERR_NOT_FOUND, webauth_attr_list_find(attrs_in, "foobar", &f),
           "Cannot find missing attribute");
    is_int(f, -1, "...and attribute number is set to -1");

    rlen = webauth_attrs_encoded_length(attrs_in);
    is_int(2192, rlen, "Encoded attribute length is correct");
    buff = malloc(rlen + 1);
    if (buff == NULL)
        sysbail("Cannot allocate memory");
    s = webauth_attrs_encode(attrs_in, buff, &len, rlen);
    is_int(WA_ERR_NONE, s, "Attribute encoding succeeds");
    is_int(rlen, len, "...and returns the correct length");
    buff[len] = '\0';

    s = webauth_attrs_decode(buff, len, &attrs_out);
    is_int(WA_ERR_NONE, s, "Attribute decoding succeeds");
    is_int(attrs_in->num_attrs, attrs_out->num_attrs,
           "...with the right count");
    for (i = 0; i < attrs_out->num_attrs; i++) {
        is_string(attrs_in->attrs[i].name, attrs_out->attrs[i].name,
                  "Attribute %d has the right value", i);
        is_int(attrs_in->attrs[i].length, attrs_out->attrs[i].length,
               "...and the right length");
        ok(memcmp(attrs_in->attrs[i].value, attrs_out->attrs[i].value, 
                  attrs_in->attrs[i].length) == 0, "...and the right value");
    }
    free(buff);
    webauth_attr_list_free(attrs_in);
    webauth_attr_list_free(attrs_out);

    attrs_in = webauth_attr_list_new(32);
    webauth_attr_list_add_str(attrs_in, "0", "hello", 0, WA_F_NONE);
    webauth_attr_list_add_str(attrs_in, "B0", "hello", 0, WA_F_FMT_B64);
    webauth_attr_list_add_str(attrs_in, "H0", "hello", 0, WA_F_FMT_HEX);
    webauth_attr_list_add_str(attrs_in, "1", "hello", 0, WA_F_NONE);
    webauth_attr_list_add_str(attrs_in, "B1", "hello", 0, WA_F_FMT_B64);
    webauth_attr_list_add_str(attrs_in, "H1", "hello", 0, WA_F_FMT_HEX);
    webauth_attr_list_add_uint32(attrs_in, "UI0", 12345, WA_F_FMT_STR);
    webauth_attr_list_add_uint32(attrs_in, "HUI0", 12345,
                                 WA_F_FMT_STR | WA_F_FMT_HEX);
    webauth_attr_list_add_uint32(attrs_in, "BUI0", 12345,
                                 WA_F_FMT_STR | WA_F_FMT_B64);
    webauth_attr_list_add_uint32(attrs_in, "UI1", 12345, WA_F_NONE);
    webauth_attr_list_add_uint32(attrs_in, "HUI1", 12345, WA_F_FMT_HEX);
    webauth_attr_list_add_uint32(attrs_in, "BUI1", 12345, WA_F_FMT_B64);
    webauth_attr_list_add_int32(attrs_in, "I0", -12345, WA_F_FMT_STR);
    webauth_attr_list_add_int32(attrs_in, "HI0", -12345,
                                 WA_F_FMT_STR | WA_F_FMT_HEX);
    webauth_attr_list_add_int32(attrs_in, "BI0", -12345,
                                 WA_F_FMT_STR | WA_F_FMT_B64);
    webauth_attr_list_add_int32(attrs_in, "I1", -12345, WA_F_NONE);
    webauth_attr_list_add_int32(attrs_in, "HI1", -12345, WA_F_FMT_HEX);
    webauth_attr_list_add_int32(attrs_in, "BI1", -12345, WA_F_FMT_B64);
    rlen = webauth_attrs_encoded_length(attrs_in);
    buff = malloc(rlen + 1);
    if (buff == NULL)
        sysbail("Cannot allocate memory");
    s = webauth_attrs_encode(attrs_in, buff, &len, rlen);
    is_int(WA_ERR_NONE, s, "Encoding a second attribute set works");
    is_int(rlen, len, "...with the expected length");
    s = webauth_attrs_decode(buff, len, &attrs_out);
    is_int(WA_ERR_NONE, s, "...and dcoding works");
    is_int(attrs_in->num_attrs, attrs_out->num_attrs,
           "...and returns the right number of attributes");

    /* Check retrieving string attributes. */
    s = webauth_attr_list_get_str(attrs_out, "0", &temp_str, &temp_len,
                                  WA_F_NONE);
    is_int(WA_ERR_NONE, s, "Retrieving attribute 0 works");
    is_string("hello", temp_str, "...with correct value");
    s = webauth_attr_list_get_str(attrs_out, "B0", &temp_str, &temp_len,
                                  WA_F_NONE);
    is_int(WA_ERR_NONE, s, "Retrieving attribute B0 works");
    is_string("aGVsbG8=", temp_str, "...and retrieves the base64 value");
    s = webauth_attr_list_get_str(attrs_out, "B0", &temp_str, &temp_len,
                                  WA_F_FMT_B64);
    is_int(WA_ERR_NONE, s, "Retrieving attribute B0 with base64 works");
    is_string("hello", temp_str, "...and retrieves the right value");
    s = webauth_attr_list_get_str(attrs_out, "H0", &temp_str, &temp_len,
                                  WA_F_NONE);
    is_int(WA_ERR_NONE, s, "Retriving attribute H0 works");
    is_string("68656c6c6f", temp_str,
              "...and retrieves the hex-encoded value");
    s = webauth_attr_list_get_str(attrs_out, "H0", &temp_str, &temp_len,
                                  WA_F_FMT_HEX);
    is_int(WA_ERR_NONE, s, "Retrieving attribute H0 with hex encoding works");
    is_string("hello", temp_str, "...and retrieves the right value");

    /* Check retrieving string attributes with memory allocation. */
    s = webauth_attr_list_get_str(attrs_out, "1", &temp_str, &temp_len,
                                  WA_F_NONE | WA_F_COPY_VALUE);
    is_int(WA_ERR_NONE, s, "Retriving attribute 1 with copy works");
    is_string("hello", temp_str, "...with correct value");
    free(temp_str);
    s = webauth_attr_list_get_str(attrs_out, "B1", &temp_str, &temp_len,
                                  WA_F_NONE | WA_F_COPY_VALUE);
    is_int(WA_ERR_NONE, s, "Retrieving attribute B1 with copy works");
    is_string("aGVsbG8=", temp_str, "...and retrieves base64 value");
    free(temp_str);
    s = webauth_attr_list_get_str(attrs_out, "B1", &temp_str, &temp_len,
                                  WA_F_FMT_B64 | WA_F_COPY_VALUE);
    is_int(WA_ERR_NONE, s,
           "Retrieving attribute B1 with base64 and copy works");
    is_string("hello", temp_str, "...with correct value");
    free(temp_str);
    s = webauth_attr_list_get_str(attrs_out, "H1", &temp_str, &temp_len,
                                  WA_F_NONE | WA_F_COPY_VALUE);
    is_int(WA_ERR_NONE, s, "Retrieiving attribute H1 with copy works");
    is_string("68656c6c6f", temp_str, "...and retrieves hex value");
    free(temp_str);
    s = webauth_attr_list_get_str(attrs_out, "H1", &temp_str, &temp_len,
                                  WA_F_FMT_HEX | WA_F_COPY_VALUE);
    is_int(WA_ERR_NONE, s, "Retrieving attribute H1 with copy and hex works");
    is_string("hello", temp_str, "...with correct value");
    free(temp_str);

    /* Get the hex value again.  Since we copied, it should still be there. */
    s = webauth_attr_list_get_str(attrs_out, "H1", &temp_str, &temp_len,
                                  WA_F_NONE);
    is_int(WA_ERR_NONE, s, "...and the hex value is still there");
    is_string("68656c6c6f", temp_str, "...and is correct");

    /* Now check unsigned numbers, getting the string value first. */
    s = webauth_attr_list_get_str(attrs_out, "UI0", &temp_str, &temp_len,
                                  WA_F_NONE);
    is_int(WA_ERR_NONE, s, "Retrieving UI0 as string works");
    is_string("12345", temp_str, "...with correct value");
    s = webauth_attr_list_get_uint32(attrs_out, "UI0", &temp_u32,
                                     WA_F_FMT_STR);
    is_int(WA_ERR_NONE, s, "Retrieving UI0 as a number works");
    is_int(12345, temp_u32, "...with correct value");
    s = webauth_attr_list_get_uint32(attrs_out, "HUI0", &temp_u32, 
                                     WA_F_FMT_STR | WA_F_FMT_HEX);
    is_int(WA_ERR_NONE, s, "Retrieving HUI0 as a number works");
    is_int(12345, temp_u32, "...with correct value");
    s = webauth_attr_list_get_uint32(attrs_out, "BUI0", &temp_u32, 
                                     WA_F_FMT_STR | WA_F_FMT_B64);
    is_int(WA_ERR_NONE, s, "Retrieving BUI0 as a number works");
    is_int(12345, temp_u32, "...with correct value");
    s = webauth_attr_list_get_uint32(attrs_out, "UI1", &temp_u32, WA_F_NONE);
    is_int(WA_ERR_NONE, s, "Retrieving UI1 as a number works");
    is_int(12345, temp_u32, "...with correct value");
    s = webauth_attr_list_get_uint32(attrs_out, "HUI1", &temp_u32, 
                                     WA_F_FMT_HEX);
    is_int(WA_ERR_NONE, s, "Retrieving HUI1 as a number works");
    is_int(12345, temp_u32, "...with correct value");
    s = webauth_attr_list_get_uint32(attrs_out, "BUI1", &temp_u32, 
                                     WA_F_FMT_B64);
    is_int(WA_ERR_NONE, s, "Retrieving BUI1 as a number works");
    is_int(12345, temp_u32, "...with correct value");

    /* Now check signed numbers, getting the string value first. */
    s = webauth_attr_list_get_str(attrs_out, "I0", &temp_str, &temp_len,
                                  WA_F_NONE);
    is_int(WA_ERR_NONE, s, "Retrieving I0 as a string works");
    is_string("-12345", temp_str, "...with correct value");
    s = webauth_attr_list_get_int32(attrs_out, "I0", &temp_32, WA_F_FMT_STR);
    is_int(WA_ERR_NONE, s, "Retrieving I0 as a number works");
    is_int(-12345, temp_32, "...with correct value");
    s = webauth_attr_list_get_int32(attrs_out, "HI0", &temp_32, 
                                    WA_F_FMT_STR | WA_F_FMT_HEX);
    is_int(WA_ERR_NONE, s, "Retrieving HI0 as a number works");
    is_int(-12345, temp_32, "...with correct value");
    s = webauth_attr_list_get_int32(attrs_out, "BI0", &temp_32, 
                                    WA_F_FMT_STR | WA_F_FMT_B64);
    is_int(WA_ERR_NONE, s, "Retrieving BI0 as a number works");
    is_int(-12345, temp_32, "...with correct value");
    s = webauth_attr_list_get_int32(attrs_out, "I1", &temp_32, WA_F_NONE);
    is_int(WA_ERR_NONE, s, "Retrieving I1 as a number works");
    is_int(-12345, temp_32, "...with correct value");
    s = webauth_attr_list_get_int32(attrs_out, "HI1", &temp_32, WA_F_FMT_HEX);
    is_int(WA_ERR_NONE, s, "Retrieving HI1 as a number works");
    is_int(-12345, temp_32, "...with correct value");
    s = webauth_attr_list_get_int32(attrs_out, "BI1", &temp_32, WA_F_FMT_B64);
    is_int(WA_ERR_NONE, s, "Retrieving BI1 as a number works");
    is_int(-12345, temp_32, "...with correct value");

    free(buff);
    webauth_attr_list_free(attrs_in);
    webauth_attr_list_free(attrs_out);

    return 0;
}
