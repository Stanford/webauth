#include <stdlib.h>
#include <stdio.h>

#include "webauth.h"
#include "webauthtest.h"

#define BUFSIZE 4096
#define MAX_ATTRS 128

int main(int argc, char *argv[])
{
    WEBAUTH_AES_KEY *key;
    unsigned char material[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
    WEBAUTH_ATTR_LIST *ain, *aout;
    int rlen, len, dnum_attrs, i;
    unsigned char *token;
    TEST_VARS;

    START_TESTS(17);

    ain = webauth_attr_list_new(32);
    webauth_attr_list_add(ain, WA_TK_TOKEN_TYPE, "id", 0);
    webauth_attr_list_add(ain, WA_TK_SUBJECT_AUTHENTICATOR, "webkdc", 0);
    webauth_attr_list_add(ain, WA_TK_SUBJECT, "krb5:schemers", 0);
    webauth_attr_list_add(ain, WA_TK_CREATION_TIME, "1", 0);
    webauth_attr_list_add(ain, WA_TK_EXPIRATION_TIME, "2", 0);

    key = webauth_key_create_aes(material, WA_AES_128);

    rlen = webauth_token_encoded_length(ain);

    token = malloc(rlen+1);
    len = webauth_token_create(ain, token, rlen, key);

    TEST_OK2(len, rlen);

    token[len] = '\0';

    //printf("token[%s]\n", token);
    /* now lets try and decode the token */
    aout = NULL;
    dnum_attrs = webauth_token_parse(token, len, &aout, key);

    TEST_OK2(aout->num_attrs, ain->num_attrs);
    for (i=0; i < ain->num_attrs; i++) {
        TEST_OK(strcmp(aout->attrs[i].name, ain->attrs[i].name)==0);
        TEST_OK(aout->attrs[i].length == ain->attrs[i].length);
        TEST_OK(memcmp(aout->attrs[i].value, ain->attrs[i].value, 
                       ain->attrs[i].length)==0);
    }

    webauth_attr_list_free(ain);
    webauth_attr_list_free(aout);
    free(token);
    webauth_key_destroy_aes(key);

    END_TESTS;
    exit(NUM_FAILED_TESTS ? 1 : 0);
}
