

#include <stdlib.h>
#include <stdio.h>

#include "webauth.h"
#include "webauthtest.h"

#define BUFSIZE 2048
#define MAX_ATTRS 100

int main(int argc, char *argv[])
{
    unsigned char *buff;
    WEBAUTH_ATTR_LIST *attrs_in, *attrs_out;
    int len, i, rlen;
    int num_out;
    unsigned char binary_data[BUFSIZE];
    TEST_VARS;

    START_TESTS(54);

    for (i=0; i < sizeof(binary_data); i++) {
        binary_data[i] = i % 256;
    }
   
    attrs_in = webauth_attr_list_new(64);
    webauth_attr_list_add(attrs_in, "bin", binary_data, sizeof(binary_data));
    webauth_attr_list_add(attrs_in, "0", "1", 0);
    webauth_attr_list_add(attrs_in, "1", ";", 0);
    webauth_attr_list_add(attrs_in, "2", "", 0);
    webauth_attr_list_add(attrs_in, "3", ";a", 0);
    webauth_attr_list_add(attrs_in, "4", ";aaa", 0);
    webauth_attr_list_add(attrs_in, "5", "a;", 0);
    webauth_attr_list_add(attrs_in, "6", "aaa;", 0);
    webauth_attr_list_add(attrs_in, "7", ";aaa;", 0);
    webauth_attr_list_add(attrs_in, "8", "a;a", 0);
    webauth_attr_list_add(attrs_in, "9", "a;a;", 0);
    webauth_attr_list_add(attrs_in, "10", "a;a;;", 0);
    webauth_attr_list_add(attrs_in, "11", ";a;a;;", 0);
    webauth_attr_list_add(attrs_in, "12", ";;", 0);
    webauth_attr_list_add(attrs_in, "13", ";;;", 0);
    webauth_attr_list_add(attrs_in, "14", ";;;;a", 0);


    TEST_OK2(5, webauth_attr_list_find(attrs_in, "4"));
    TEST_OK2(0, webauth_attr_list_find(attrs_in, "bin"));
    TEST_OK2(WA_ERR_NOT_FOUND, webauth_attr_list_find(attrs_in, "foobar"));

    rlen = webauth_attrs_encoded_length(attrs_in);

    TEST_OK(rlen == 2184);

    buff = malloc(rlen+1);

    len = webauth_attrs_encode(attrs_in, buff, rlen);

    TEST_OK(len == rlen);

    buff[len] = '\0';

    num_out = webauth_attrs_decode(buff, len, &attrs_out);

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
    END_TESTS;

    free(buff);
    webauth_attr_list_free(attrs_in);
    webauth_attr_list_free(attrs_out);

    exit(NUM_FAILED_TESTS ? 1 : 0);
}
