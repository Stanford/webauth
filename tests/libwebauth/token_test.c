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
    WEBAUTH_ATTR attrs[MAX_ATTRS];
    WEBAUTH_ATTR *wap;
    int num_attrs, rlen, len, dnum_attrs, i;
    unsigned char *token;
    TEST_VARS;

    START_TESTS(17);

    num_attrs = 0;
    WA_ATTR_STR(attrs[num_attrs++], WA_TK_TOKEN_TYPE, "id");
    WA_ATTR_STR(attrs[num_attrs++], WA_TK_SUBJECT_AUTHENTICATOR, "webkdc");
    WA_ATTR_STR(attrs[num_attrs++], WA_TK_SUBJECT, "krb5:schemers");
    WA_ATTR_STR(attrs[num_attrs++], WA_TK_CREATION_TIME, "1");
    WA_ATTR_STR(attrs[num_attrs++], WA_TK_EXPIRATION_TIME, "2");

    key = webauth_key_create_aes(material, WA_AES_128);

    rlen = webauth_token_encoded_length(attrs, num_attrs);

    token = malloc(rlen+1);
    len = webauth_token_create(attrs, num_attrs, token, rlen, key);

    TEST_OK2(len, rlen);

    token[len] = '\0';

    //printf("token[%s]\n", token);
    /* now lets try and decode the token */
    wap = NULL;
    dnum_attrs = webauth_token_parse(token, len, &wap, key);

    TEST_OK2(num_attrs, dnum_attrs);
    for (i=0; i < num_attrs; i++) {
        TEST_OK(strcmp(wap[i].name, attrs[i].name)==0);
        TEST_OK(wap[i].length == attrs[i].length);
        TEST_OK(memcmp(wap[i].value, attrs[i].value, attrs[i].length) == 0);
    }

    free(wap);
    free(token);
    webauth_key_destroy_aes(key);

    END_TESTS;
    exit(NUM_FAILED_TESTS ? 1 : 0);
}
