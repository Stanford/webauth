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

int
webauth_hex_encoded_length(length)
    int length
PROTOTYPE: $
CODE:
{
    RETVAL = webauth_hex_encoded_length(length);
}
OUTPUT:
    RETVAL

int
webauth_hex_decoded_length(length)
    int length
PROTOTYPE: $
CODE:
{
    RETVAL = webauth_hex_decoded_length(length);
}
OUTPUT:
    RETVAL


void
webauth_hex_encode(input)
SV * input
PROTOTYPE: $
CODE:
{
    STRLEN n_input, n_output;
    int out_len, s;
    unsigned char *p_input;

    p_input = SvPV(input, n_input);
    out_len = webauth_hex_encoded_length(n_input);

    ST(0) = sv_2mortal(NEWSV(0, out_len));
    
    s = webauth_hex_encode(p_input, n_input, SvPVX(ST(0)), out_len);
    SvCUR_set(ST(0), out_len);
    SvPOK_only(ST(0));
}

void
webauth_hex_decode(input, ...)
SV * input
PROTOTYPE: $;$
CODE:
{
    STRLEN n_input, n_output;
    int out_len, s;
    unsigned char *p_input;

    p_input = SvPV(input, n_input);
    out_len = webauth_hex_decoded_length(n_input);
    if (out_len > 0) {
            ST(0) = sv_2mortal(NEWSV(0, out_len));
            s = webauth_hex_decode(p_input, n_input, SvPVX(ST(0)), out_len);
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

void
webauth_attrs_encoded_length(attrs)
SV *attrs
PROTOTYPE: $
CODE:
{
    HV *h;
    HE *entry;
    SV *sv_val;
    int num_attrs, s;
    char *key, *val;
    I32 klen, i;
    STRLEN vlen;
    WEBAUTH_ATTR *c_attrs;

    if (!SvROK(attrs) || !(SvTYPE(SvRV(attrs)) == SVt_PVHV)) {
        croak("attrs must be reference to a hash");
    }

    h = (HV*)SvRV(attrs);

    num_attrs = hv_iterinit(h);

    c_attrs = malloc(sizeof(WEBAUTH_ATTR)*num_attrs);
    i = 0;
    while(sv_val = hv_iternextsv(h, &key, &klen)) {
        val = SvPV(sv_val, vlen);
        c_attrs[i].name = key;
        c_attrs[i].value = val;
        c_attrs[i].length = vlen;   
        i++;
    }

    s = webauth_attrs_encoded_length(c_attrs, num_attrs);
    free(c_attrs);
    ST(0) = sv_2mortal(newSViv(s));
}


void
webauth_attrs_encode(attrs)
SV *attrs
PROTOTYPE: $
CODE:
{
    HV *h;
    HE *entry;
    SV *sv_val;
    int num_attrs, s, out_len;
    char *key, *val;
    I32 klen, i;
    STRLEN vlen;
    WEBAUTH_ATTR *c_attrs;

    if (!SvROK(attrs) || !(SvTYPE(SvRV(attrs)) == SVt_PVHV)) {
        croak("attrs must be reference to a hash");
    }

    h = (HV*)SvRV(attrs);

    num_attrs = hv_iterinit(h);

    c_attrs = malloc(sizeof(WEBAUTH_ATTR)*num_attrs);
    i = 0;
    while(sv_val = hv_iternextsv(h, &key, &klen)) {
        val = SvPV(sv_val, vlen);
        c_attrs[i].name = key;
        c_attrs[i].value = val;
        c_attrs[i].length = vlen;   
        i++;
    }

    out_len = webauth_attrs_encoded_length(c_attrs, num_attrs);

    ST(0) = sv_2mortal(NEWSV(0, out_len));
    s = webauth_attrs_encode(c_attrs, num_attrs, SvPVX(ST(0)), out_len);
    free(c_attrs);
    if (s < 0) {
        /* this should never happen, since the only error is WA_ERR_NO_ROOM
           and we always have enough room */
        ST(0) = &PL_sv_undef;
    } else {
        SvCUR_set(ST(0), out_len);
        SvPOK_only(ST(0));
    }
}


void
webauth_attrs_decode(buffer,...)
SV *buffer
PROTOTYPE: $;$
CODE:
{
    STRLEN n_input;
    unsigned char *p_input;
    WEBAUTH_ATTR *c_attrs;
    int i, s, ok, num_attrs;
    HV *hv;

    p_input = SvPV(buffer, n_input);

    num_attrs = webauth_attrs_decode(p_input, n_input, NULL, 0);

    ok = (num_attrs > 0);
    if (ok) {
        c_attrs = malloc(sizeof(WEBAUTH_ATTR)*num_attrs);
        i = 0;
        s = webauth_attrs_decode(p_input, n_input, c_attrs, num_attrs);
        num_attrs = s;
        ok = (num_attrs > 0);
        if (ok) {
            hv = (HV*) sv_2mortal((SV*)newHV());
            for (i=0; i < num_attrs; i++) {
                hv_store(hv, c_attrs[i].name, strlen(c_attrs[i].name),
                         newSVpvn(c_attrs[i].value, c_attrs[i].length), 0);
            }       
        }
        free(c_attrs);
    }

    if (items > 1) {
       sv_setiv(ST(1), num_attrs);
    }

    if (ok) {
       ST(0) = newRV((SV*)hv);
    } else {
       ST(0) =  &PL_sv_undef;
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
