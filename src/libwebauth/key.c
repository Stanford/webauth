#include "webauthp.h"

#include <sys/types.h>
#include <time.h>
#include <netinet/in.h>
#include <inttypes.h>

/*
 * construct a new key. 
 */

WEBAUTH_KEY *
webauth_key_create(int type, const unsigned char *key, int len) 
{
    WEBAUTH_KEYP *k;

    assert(key != NULL);

    if (type != WA_AES_KEY) {
        return NULL;
    }

    if (len != WA_AES_128 && 
        len != WA_AES_192 &&
        len != WA_AES_256) {
        return NULL;
    }

    k = malloc(sizeof(WEBAUTH_KEYP));
    if (k == NULL) {
        return NULL;
    }

    k->data = malloc(len);
    if (k->data == NULL) {
        free(k);
        return NULL;
    }
    
    k->type = type;
    k->length = len;
    memcpy(k->data, key, len); 
    return (WEBAUTH_KEY*)k;
}

void
webauth_key_destroy(WEBAUTH_KEY *key) 
{
    WEBAUTH_KEYP *keyp = (WEBAUTH_KEYP*) key;
    assert(keyp != NULL);
    memset(keyp->data, 0, keyp->length);
    free(keyp->data);
    free(keyp);
}


/*
**  Local variables:
**  mode: c
**  c-basic-offset: 4
**  indent-tabs-mode: nil
**  end:
*/
