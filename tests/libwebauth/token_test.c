
#include "webauth.h"

#include <stdlib.h>
#include <stdio.h>

#define BUFSIZE 4096
#define MAX_ATTRS 128

int main(int argc, char *argv[])
{
    WEBAUTH_AES_KEY *key;
    unsigned char material[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
    WEBAUTH_ATTR attrs[MAX_ATTRS], dattrs[MAX_ATTRS];
    int num_attrs, len, dnum_attrs;
    unsigned char *token;

    num_attrs = 0;
    WA_ATTR_STR(attrs[num_attrs++], WA_TK_TOKEN_TYPE, "id");
    WA_ATTR_STR(attrs[num_attrs++], WA_TK_SUBJECT_AUTHENTICATOR, "webkdc");
    WA_ATTR_STR(attrs[num_attrs++], WA_TK_SUBJECT, "krb5:schemers");
    WA_ATTR_STR(attrs[num_attrs++], WA_TK_CREATION_TIME, "1");
    WA_ATTR_STR(attrs[num_attrs++], WA_TK_EXPIRATION_TIME, "2");

    key = webauth_key_create_aes(material, 16);

    len = webauth_token_encoded_length(attrs, num_attrs);
    printf("len = %d\n", len);


    token = malloc(len+1);
    len = webauth_token_create(attrs, num_attrs,
                               token, len,
                               key);
    token[len] = '\0';

    printf("token[%s]\n", token);
    /* now lets try and decode the token */
    dnum_attrs = webauth_token_parse(token, len,
                                     dattrs,
                                     MAX_ATTRS,
                                     key);
                              
    printf("%d\n", dnum_attrs);

    webauth_key_destroy_aes(key);

    return 0;
}
