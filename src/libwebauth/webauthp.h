#ifndef _WEBAUTHP_H
#define _WEBAUTHP_H

/*
 * this is the more "private" version of libwebauth
 */

#include "conf.h"

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#elif HAVE_STRINGS_H
#include <strings.h>
#endif 

#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

/* XXX: autoconf */
#include <assert.h>

#include "webauth.h"

/******************** types ********************/


/* the private version of WEBAUTH_AES_KEY */

typedef struct {
    AES_KEY encryption;
    AES_KEY decryption;
} WEBAUTH_AES_KEYP;




#endif
