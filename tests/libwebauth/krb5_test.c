#include <stdlib.h>
#include <stdio.h>

#include "webauth.h"
#include "webauthtest.h"

#define BUFSIZE 4096
#define MAX_ATTRS 128

void
usage()
{
    printf("usage: krb5_test {username} {password}\n");
    exit(1);
}
int main(int argc, char *argv[])
{
    int s, i;
    WEBAUTH_KRB5_CTXT *c;
    TEST_VARS;
    char *username, *password;

    if (argc != 3) {
        usage();
    }

    username = argv[1];
    password = argv[2];

    START_TESTS(10);

    for (i=0; i<1; i++) {
        s = webauth_krb5_init(&c);
        TEST_OK2(WA_ERR_NONE, s);

        s = webauth_krb5_init_creds_password(c, username, password, 
                                             "host", "keytab");

        TEST_OK2(WA_ERR_NONE, s);

        s = webauth_krb5_free(c);
        TEST_OK2(WA_ERR_NONE, s);
    }

    END_TESTS;
    exit(NUM_FAILED_TESTS ? 1 : 0);
}
