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
    unsigned char *sa;
    int salen;
    unsigned char *tgt;
    int tgtlen;
    time_t expiration;

    if (argc != 3) {
        usage();
    }

    username = argv[1];
    password = argv[2];

    START_TESTS(9);

    for (i=0; i<1; i++) {
        c = webauth_krb5_new();
        TEST_OK(c != NULL);

        s = webauth_krb5_init_via_password(c, username, password, 
                                           "host", "keytab");

        TEST_OK2(WA_ERR_NONE, s);

        sa = NULL;
        s = webauth_krb5_get_subject_auth(c, "lichen", "host", &sa, &salen);
        TEST_OK2(WA_ERR_NONE, s);


        s = webauth_krb5_verify_subject_auth(c, sa, salen, "host", "keytab");
        TEST_OK2(WA_ERR_NONE, s);

        if (sa != NULL) {
            free(sa);
        }

        tgt = NULL;
        s = webauth_krb5_export_tgt(c, &tgt, &tgtlen, &expiration);
        TEST_OK2(WA_ERR_NONE, s);

        s = webauth_krb5_free(c);
        TEST_OK2(WA_ERR_NONE, s);
        
        if (tgt != NULL) {
            c = webauth_krb5_new();
            TEST_OK(c != NULL);
            
            s = webauth_krb5_init_via_tgt(c, tgt, tgtlen);
            free(tgt);
            TEST_OK2(WA_ERR_NONE, s);

            s = webauth_krb5_free(c);
            TEST_OK2(WA_ERR_NONE, s);
        }
        
    }

    END_TESTS;
    exit(NUM_FAILED_TESTS ? 1 : 0);
}
