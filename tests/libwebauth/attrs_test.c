
#include "webauth.h"

#include <stdlib.h>
#include <stdio.h>


#define BUFSIZE 2048
#define MAX_ATTRS 100

int main(int argc, char *argv[])
{
    unsigned char *buff;
    WEBAUTH_ATTR attrs[MAX_ATTRS];
    WEBAUTH_ATTR decoded_attrs[MAX_ATTRS];
    int len, i, rlen;
    int num_in, num_out1, num_out2;
    unsigned char binary_data[BUFSIZE];

    for (i=0; i < sizeof(binary_data); i++) {
        binary_data[i] = i % 256;
    }
   
    num_in=0;
    WA_ATTR_BIN(attrs[num_in++], "bin", binary_data, sizeof(binary_data));
    WA_ATTR_STR(attrs[num_in++], "0", "1");
    WA_ATTR_STR(attrs[num_in++], "1", ";");
    WA_ATTR_STR(attrs[num_in++], "2", "");
    WA_ATTR_STR(attrs[num_in++], "3", ";a");
    WA_ATTR_STR(attrs[num_in++], "4", ";aaa");
    WA_ATTR_STR(attrs[num_in++], "5", "a;");
    WA_ATTR_STR(attrs[num_in++], "6", "aaa;");
    WA_ATTR_STR(attrs[num_in++], "7", ";aaa;");
    WA_ATTR_STR(attrs[num_in++], "8", "a;a");
    WA_ATTR_STR(attrs[num_in++], "9", "a;a;");
    WA_ATTR_STR(attrs[num_in++], "10", "a;a;;");
    WA_ATTR_STR(attrs[num_in++], "11", ";a;a;;");
    WA_ATTR_STR(attrs[num_in++], "12", ";;");
    WA_ATTR_STR(attrs[num_in++], "13", ";;;");
    WA_ATTR_STR(attrs[num_in++], "14", ";;;;a");

    rlen = webauth_attrs_encoded_length(attrs, num_in);

    printf ("%d\n", rlen);

    buff = malloc(rlen+1);

    len = webauth_attrs_encode(attrs, num_in, buff, rlen);

    buff[len] = '\0';

    printf ("%d = webauth_attrs_encode\n", len);

    num_out1 = webauth_attrs_decode(buff, len, NULL, 0);


    printf ("%d = webauth_attrs_decode (NULL attrs)\n", num_out1);

    num_out2 = webauth_attrs_decode(buff, len, decoded_attrs, MAX_ATTRS);


    printf ("%d = webauth_attrs_decode\n", num_out2);

    for (i=0; i < num_out2; i++) {
        /*printf("decoded (%s) = (%s)\n", decoded_attrs[i].name,
          (char*)decoded_attrs[i].value);*/
        if (strcmp(attrs[i].name, decoded_attrs[i].name) != 0) {
            fprintf(stderr, "decoded attr %d name not equal\n", i);
        }
        if (attrs[i].length != decoded_attrs[i].length) {
            fprintf(stderr, "decoded attr %d length not equal\n", i);
        }
        if (memcmp(attrs[i].value, decoded_attrs[i].value, 
                   attrs[i].length) != 0) {
            fprintf(stderr, "decoded attr %d value not equal\n", i);
        }
    }

    return 0;
}
