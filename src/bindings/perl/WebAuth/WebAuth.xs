#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

/* FIXME: should this be "webauth.h" and 
          should -I{top_srcdir}/src/libwebauth be added in Makefile.PL?" */

#include "../../../libwebauth/webauth.h"

MODULE = WebAuth        PACKAGE = WebAuth    PREFIX = webauth_

PROTOTYPES: ENABLE

int
webauth_base64_encoded_length(length)
    int length
PROTOTYPE: $
CODE:
{
    RETVAL = webauth_base64_encoded_length(length);
}
OUTPUT:
    RETVAL

int
webauth_base64_decoded_length(input)
    SV * input
PROTOTYPE: $
CODE:
{
    STRLEN n_input;
    unsigned char *p_input;
    p_input = SvPV(input, n_input);
    RETVAL = webauth_base64_decoded_length(p_input, n_input);
}
OUTPUT:
    RETVAL

void
webauth_base64_encode(input)
SV * input
PROTOTYPE: $
CODE:
{
    STRLEN n_input, n_output;
    int out_len, s;
    unsigned char *p_input;

    p_input = SvPV(input, n_input);
    out_len = webauth_base64_encoded_length(n_input);

    ST(0) = sv_2mortal(NEWSV(0, out_len));
    
    s = webauth_base64_encode(p_input, n_input, SvPVX(ST(0)), out_len);
    SvCUR_set(ST(0), out_len);
    SvPOK_only(ST(0));
}

void
webauth_base64_decode(input, ...)
SV * input
PROTOTYPE: $;$
CODE:
{
    STRLEN n_input, n_output;
    int out_len, s;
    unsigned char *p_input;

    p_input = SvPV(input, n_input);
    out_len = webauth_base64_decoded_length(p_input, n_input);
    if (out_len > 0) {
            ST(0) = sv_2mortal(NEWSV(0, out_len));
            s = webauth_base64_decode(p_input, n_input, SvPVX(ST(0)), out_len);
    } else {
      s = out_len;
    }

    if (items > 1) {
       sv_setiv(ST(1), s);
    }

    if (s < 0) {
        ST(0) = &PL_sv_undef;
    } else {
        SvCUR_set(ST(0), out_len);
        SvPOK_only(ST(0));
    }
}

BOOT:
{
#define IV_CONST(X) newCONSTSUB(stash, #X, newSViv(X))
#define STR_CONST(X) newCONSTSUB(stash, #X, newSVpv(X,0))

    HV *stash;
    /* constant subs for WebAuth */
    stash = gv_stashpv("WebAuth", TRUE);

    IV_CONST(WA_ERR_NO_ROOM);
    IV_CONST(WA_ERR_CORRUPT);
    IV_CONST(WA_ERR_NO_MEM);
    IV_CONST(WA_ERR_BAD_HMAC);
    IV_CONST(WA_ERR_RAND_FAILURE);
    IV_CONST(WA_ERR_NONE);
    IV_CONST(WA_AES_128);
    IV_CONST(WA_AES_192);
    IV_CONST(WA_AES_256);
    STR_CONST(WA_TK_APP_NAME);
    STR_CONST(WA_TK_CRED_DATA);
    STR_CONST(WA_TK_CRED_TYPE);
    STR_CONST(WA_TK_CREATION_TIME);
    STR_CONST(WA_TK_ERROR_CODE);
    STR_CONST(WA_TK_ERROR_MESSAGE);
    STR_CONST(WA_TK_EXPIRATION_TIME);
    STR_CONST(WA_TK_INACTIVITY_TIMEOUT);
    STR_CONST(WA_TK_SESSION_KEY);
    STR_CONST(WA_TK_LASTUSED_TIME);
    STR_CONST(WA_TK_PROXY_TYPE);
    STR_CONST(WA_TK_PROXY_DATA);
    STR_CONST(WA_TK_PROXY_OWNER);
    STR_CONST(WA_TK_POST_URL);
    STR_CONST(WA_TK_REQUEST_REASON);
    STR_CONST(WA_TK_REQUESTED_TOKEN_TYPE);
    STR_CONST(WA_TK_REQUESTED_TOKEN_HASH);
    STR_CONST(WA_TK_RETURN_URL);
    STR_CONST(WA_TK_SUBJECT);
    STR_CONST(WA_TK_SUBJECT_AUTHENTICATOR);
    STR_CONST(WA_TK_SERVICE_AUTHENTICATOR_NAME);
    STR_CONST(WA_TK_TOKEN_TYPE);
    STR_CONST(WA_TK_TOKEN_VERSION);
}

 /*
 **  Local variables:
 **  tab-width: 4
 **  indent-tabs-mode: nil
 **  end:
 */
