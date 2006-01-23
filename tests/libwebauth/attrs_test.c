
#include "config.h"

#include <stdio.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "webauth.h"
#include "webauthtest.h"

#define BUFSIZE 2048
#define MAX_ATTRS 100

int main(int argc, char *argv[])
{
    char *buff;
    WEBAUTH_ATTR_LIST *attrs_in, *attrs_out;
    int len, i, rlen, s, f;
    unsigned char binary_data[BUFSIZE];
    uint32_t temp_u32;
    int32_t temp_32;
    char *temp_str;
    int temp_len;

    TEST_VARS;

    START_TESTS(116);

    for (i=0; i < sizeof(binary_data); i++) {
        binary_data[i] = i % 256;
    }
   
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

    TEST_OK2(WA_ERR_NONE, webauth_attr_list_find(attrs_in, "4", &f));
    TEST_OK2(f, 5);

    TEST_OK2(WA_ERR_NONE, webauth_attr_list_find(attrs_in, "bin", &f));
    TEST_OK2(f, 0);

    TEST_OK2(WA_ERR_NOT_FOUND, webauth_attr_list_find(attrs_in, "foobar", &f));
    TEST_OK2(f, -1);

    rlen = webauth_attrs_encoded_length(attrs_in);

    TEST_OK(rlen == 2192);

    buff = malloc(rlen+1);

    s = webauth_attrs_encode(attrs_in, buff, &len, rlen);

    TEST_OK(s == WA_ERR_NONE);
    TEST_OK(len == rlen);

    buff[len] = '\0';

    s = webauth_attrs_decode(buff, len, &attrs_out);
    TEST_OK(s == WA_ERR_NONE);

    TEST_OK(attrs_in->num_attrs == attrs_out->num_attrs);

    for (i=0; i < attrs_out->num_attrs; i++) {
        /*printf("decoded (%s) = (%s)\n", decoded_attrs[i].name,
          (char*)decoded_attrs[i].value);*/
        TEST_OK(strcmp(attrs_in->attrs[i].name, 
                       attrs_out->attrs[i].name) == 0);
        /*fprintf(stderr, "decoded attr %d name not equal\n", i);*/
        TEST_OK(attrs_in->attrs[i].length == attrs_out->attrs[i].length);
        /*fprintf(stderr, "decoded attr %d length not equal\n", i);*/
        TEST_OK(memcmp(attrs_in->attrs[i].value, 
                       attrs_out->attrs[i].value, 
                       attrs_in->attrs[i].length) == 0);
        /*fprintf(stderr, "decoded attr %d value not equal\n", i);*/
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
                                 WA_F_FMT_STR|WA_F_FMT_HEX);
    webauth_attr_list_add_uint32(attrs_in, "BUI0", 12345,
                                 WA_F_FMT_STR|WA_F_FMT_B64);

    webauth_attr_list_add_uint32(attrs_in, "UI1", 12345, WA_F_NONE);
    webauth_attr_list_add_uint32(attrs_in, "HUI1", 12345, WA_F_FMT_HEX);
    webauth_attr_list_add_uint32(attrs_in, "BUI1", 12345, WA_F_FMT_B64);

    webauth_attr_list_add_int32(attrs_in, "I0", -12345, WA_F_FMT_STR);
    webauth_attr_list_add_int32(attrs_in, "HI0", -12345,
                                 WA_F_FMT_STR|WA_F_FMT_HEX);
    webauth_attr_list_add_int32(attrs_in, "BI0", -12345,
                                 WA_F_FMT_STR|WA_F_FMT_B64);

    webauth_attr_list_add_int32(attrs_in, "I1", -12345, WA_F_NONE);
    webauth_attr_list_add_int32(attrs_in, "HI1", -12345, WA_F_FMT_HEX);
    webauth_attr_list_add_int32(attrs_in, "BI1", -12345, WA_F_FMT_B64);

    rlen = webauth_attrs_encoded_length(attrs_in);

    /* TEST_OK(rlen == 2192);*/

    buff = malloc(rlen+1);
    s = webauth_attrs_encode(attrs_in, buff, &len, rlen);

    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK(len == rlen);


    s = webauth_attrs_decode(buff, len, &attrs_out);
    TEST_OK2(WA_ERR_NONE, s);


    TEST_OK(attrs_in->num_attrs == attrs_out->num_attrs);

    s = webauth_attr_list_get_str(attrs_out, "0", &temp_str, &temp_len,
                              WA_F_NONE);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK(strcmp(temp_str, "hello") == 0);

    s = webauth_attr_list_get_str(attrs_out, "B0", &temp_str, &temp_len,
                              WA_F_NONE);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK(strcmp(temp_str, "aGVsbG8=") == 0);

    s = webauth_attr_list_get_str(attrs_out, "B0", &temp_str, &temp_len,
                              WA_F_FMT_B64);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK(strcmp(temp_str, "hello") == 0);


    s = webauth_attr_list_get_str(attrs_out, "H0", &temp_str, &temp_len,
                              WA_F_NONE);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK(strcmp(temp_str, "68656c6c6f") == 0);

    s = webauth_attr_list_get_str(attrs_out, "H0", &temp_str, &temp_len,
                              WA_F_FMT_HEX);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK(strcmp(temp_str, "hello") == 0);




    s = webauth_attr_list_get_str(attrs_out, "1", &temp_str, &temp_len,
                              WA_F_NONE|WA_F_COPY_VALUE);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK(strcmp(temp_str, "hello") == 0);
    free(temp_str);

    s = webauth_attr_list_get_str(attrs_out, "B1", &temp_str, &temp_len,
                              WA_F_NONE|WA_F_COPY_VALUE);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK(strcmp(temp_str, "aGVsbG8=") == 0);
    free(temp_str);

    s = webauth_attr_list_get_str(attrs_out, "B1", &temp_str, &temp_len,
                              WA_F_FMT_B64|WA_F_COPY_VALUE);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK(strcmp(temp_str, "hello") == 0);
    free(temp_str);

    s = webauth_attr_list_get_str(attrs_out, "H1", &temp_str, &temp_len,
                              WA_F_NONE|WA_F_COPY_VALUE);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK(strcmp(temp_str, "68656c6c6f") == 0);
    free(temp_str);

    s = webauth_attr_list_get_str(attrs_out, "H1", &temp_str, &temp_len,
                              WA_F_FMT_HEX|WA_F_COPY_VALUE);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK(strcmp(temp_str, "hello") == 0);
    free(temp_str);

    /* get hex value again, since we copied it should still be there */
    s = webauth_attr_list_get_str(attrs_out, "H1", &temp_str, &temp_len,
                                  WA_F_NONE);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK(strcmp(temp_str, "68656c6c6f") == 0);

    /* get string value first */
    s = webauth_attr_list_get_str(attrs_out, "UI0", &temp_str, &temp_len,
                                  WA_F_NONE);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK(strcmp(temp_str, "12345") == 0);

    s = webauth_attr_list_get_uint32(attrs_out, 
                                     "UI0", &temp_u32, WA_F_FMT_STR);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK2(12345, temp_u32);

    s = webauth_attr_list_get_uint32(attrs_out, "HUI0", &temp_u32, 
                                     WA_F_FMT_STR|WA_F_FMT_HEX);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK2(12345, temp_u32);

    s = webauth_attr_list_get_uint32(attrs_out, "BUI0", &temp_u32, 
                                     WA_F_FMT_STR|WA_F_FMT_B64);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK2(12345, temp_u32);


    s = webauth_attr_list_get_uint32(attrs_out, "UI1", &temp_u32, WA_F_NONE);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK2(12345, temp_u32);

    s = webauth_attr_list_get_uint32(attrs_out, "HUI1", &temp_u32, 
                                     WA_F_FMT_HEX);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK2(12345, temp_u32);

    s = webauth_attr_list_get_uint32(attrs_out, "BUI1", &temp_u32, 
                                     WA_F_FMT_B64);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK2(12345, temp_u32);


    /* get string value first */
    s = webauth_attr_list_get_str(attrs_out, "I0", &temp_str, &temp_len,
                                  WA_F_NONE);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK(strcmp(temp_str, "-12345") == 0);

    s = webauth_attr_list_get_int32(attrs_out, "I0", &temp_32, WA_F_FMT_STR);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK2(-12345, temp_32);

    s = webauth_attr_list_get_int32(attrs_out, "HI0", &temp_32, 
                                     WA_F_FMT_STR|WA_F_FMT_HEX);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK2(-12345, temp_32);

    s = webauth_attr_list_get_int32(attrs_out, "BI0", &temp_32, 
                                     WA_F_FMT_STR|WA_F_FMT_B64);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK2(-12345, temp_32);


    s = webauth_attr_list_get_int32(attrs_out, "I1", &temp_32, WA_F_NONE);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK2(-12345, temp_32);

    s = webauth_attr_list_get_int32(attrs_out, "HI1", &temp_32, 
                                     WA_F_FMT_HEX);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK2(-12345, temp_32);

    s = webauth_attr_list_get_int32(attrs_out, "BI1", &temp_32, 
                                     WA_F_FMT_B64);
    TEST_OK2(WA_ERR_NONE, s);
    TEST_OK2(-12345, temp_32);





    free(buff);
    webauth_attr_list_free(attrs_in);
    webauth_attr_list_free(attrs_out);

    END_TESTS;

    exit(NUM_FAILED_TESTS ? 1 : 0);
}
