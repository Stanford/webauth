#include <stdlib.h>
#include <stdio.h>

#include "webauth.h"
#include "webauthtest.h"

#define BUFSIZE 4096
#define MAX_ATTRS 128

int main(int argc, char *argv[])
{
    int s;
    WEBAUTH_KRB5_CTXT *c;
    TEST_VARS;

    START_TESTS(10);

    s = webauth_krb5_init(&c);
    TEST_OK2(WA_ERR_NONE, s);

    s = webauth_krb5_free(c);
    TEST_OK2(WA_ERR_NONE, s);

    END_TESTS;
    exit(NUM_FAILED_TESTS ? 1 : 0);
}
