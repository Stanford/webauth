#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

/* FIXME: should this be "webauth.h" and 
          should -I{top_srcdir}/src/libwebauth be added in Makefile.PL?" */

#include "../../../libwebauth/webauth.h"

MODULE = WebAuth        PACKAGE = WebAuth    PREFIX = webauth_

PROTOTYPES: ENABLE

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
    IV_CONST(WA_ERR_BAD_KEY);
    IV_CONST(WA_ERR_KEYRING_OPENWRITE);
    IV_CONST(WA_ERR_KEYRING_WRITE);
    IV_CONST(WA_ERR_KEYRING_OPENREAD);
    IV_CONST(WA_ERR_KEYRING_READ);
    IV_CONST(WA_ERR_KEYRING_VERSION);
    IV_CONST(WA_ERR_NOT_FOUND);
    IV_CONST(WA_ERR_KRB5);
    IV_CONST(WA_ERR_LOGIN_FAILED);
    IV_CONST(WA_ERR_NONE);
    IV_CONST(WA_AES_KEY);
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
webauth_base64_decoded_length(input,...)
    SV * input
PROTOTYPE: $;$
CODE:
{
    STRLEN n_input;
    int len, s;
    unsigned char *p_input;
    p_input = SvPV(input, n_input);
    s = webauth_base64_decoded_length(p_input, n_input, &len);
    if (items > 1) {
       sv_setiv(ST(1), s);
    }
    RETVAL = len;
}
OUTPUT:
    RETVAL

void
webauth_base64_encode(input)
SV * input
PROTOTYPE: $
CODE:
{
    STRLEN n_input;
    int out_len, out_max, s;
    unsigned char *p_input;

    p_input = SvPV(input, n_input);
    out_max = webauth_base64_encoded_length(n_input);

    ST(0) = sv_2mortal(NEWSV(0, out_max));
    
    s = webauth_base64_encode(p_input, n_input, 
                              SvPVX(ST(0)), &out_len, out_max);
    SvCUR_set(ST(0), out_len);
    SvPOK_only(ST(0));
}

void
webauth_base64_decode(input, ...)
SV * input
PROTOTYPE: $;$
CODE:
{
    STRLEN n_input;
    int out_len, out_max, s;
    unsigned char *p_input;

    p_input = SvPV(input, n_input);
    s = webauth_base64_decoded_length(p_input, n_input, &out_max);
    if (s == WA_ERR_NONE) {
            ST(0) = sv_2mortal(NEWSV(0, out_max));
            s = webauth_base64_decode(p_input, n_input, 
                                      SvPVX(ST(0)), &out_len, out_max);
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
webauth_hex_decoded_length(length,...)
    int length
PROTOTYPE: $;$
CODE:
{
    int len, s;
    s = webauth_hex_decoded_length(length, &len);
    if (items > 1) {
       sv_setiv(ST(1), s);
    }
    RETVAL = len;
}
OUTPUT:
    RETVAL


void
webauth_hex_encode(input)
SV * input
PROTOTYPE: $
CODE:
{
    STRLEN n_input;
    int out_len, out_max, s;
    unsigned char *p_input;

    p_input = SvPV(input, n_input);
    out_max = webauth_hex_encoded_length(n_input);

    ST(0) = sv_2mortal(NEWSV(0, out_max));
    
    s = webauth_hex_encode(p_input, n_input, SvPVX(ST(0)), &out_len, out_max);
    SvCUR_set(ST(0), out_len);
    SvPOK_only(ST(0));
}

void
webauth_hex_decode(input, ...)
SV * input
PROTOTYPE: $;$
CODE:
{
    STRLEN n_input;
    int out_len, out_max, s;
    unsigned char *p_input;

    p_input = SvPV(input, n_input);
    s = webauth_hex_decoded_length(n_input, &out_max);
    if (s == WA_ERR_NONE) {
            ST(0) = sv_2mortal(NEWSV(0, out_max));
            s = webauth_hex_decode(p_input, n_input,
                                   SvPVX(ST(0)), &out_len, out_max);
    }

    if (items > 1) {
       sv_setiv(ST(1), s);
    }

    if (s != WA_ERR_NONE) {
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
    SV *sv_val;
    int num_attrs, s;
    char *key, *val;
    I32 klen;
    STRLEN vlen;
    WEBAUTH_ATTR_LIST *list;

    if (!SvROK(attrs) || !(SvTYPE(SvRV(attrs)) == SVt_PVHV)) {
        croak("attrs must be reference to a hash");
    }

    h = (HV*)SvRV(attrs);

    num_attrs = hv_iterinit(h);

    list = webauth_attr_list_new(num_attrs);
    if (list == NULL) {
        croak("can't create new attr list");
    }
    while((sv_val=hv_iternextsv(h, &key, &klen))) {
        val = SvPV(sv_val, vlen);
        webauth_attr_list_add(list, key, val, vlen);
    }

    s = webauth_attrs_encoded_length(list);
    webauth_attr_list_free(list);
    ST(0) = sv_2mortal(newSViv(s));
}

void
webauth_attrs_encode(attrs)
SV *attrs
PROTOTYPE: $
CODE:
{
    HV *h;
    SV *sv_val;
    int num_attrs, s, out_len, out_max;
    char *key, *val;
    I32 klen;
    STRLEN vlen;
    WEBAUTH_ATTR_LIST *list;

    if (!SvROK(attrs) || !(SvTYPE(SvRV(attrs)) == SVt_PVHV)) {
        croak("attrs must be reference to a hash");
    }

    h = (HV*)SvRV(attrs);

    num_attrs = hv_iterinit(h);

    list = webauth_attr_list_new(num_attrs);
    if (list == NULL) {
        croak("can't malloc attr list");
    }

    while((sv_val = hv_iternextsv(h, &key, &klen))) {
        val = SvPV(sv_val, vlen);
        webauth_attr_list_add(list, key, val, vlen);
    }

    out_max = webauth_attrs_encoded_length(list);

    ST(0) = sv_2mortal(NEWSV(0, out_max));
    s = webauth_attrs_encode(list, SvPVX(ST(0)), &out_len, out_max);
    webauth_attr_list_free(list);
    if (s != WA_ERR_NONE) {
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
    WEBAUTH_ATTR_LIST *list;
    int i, s;
    HV *hv;
    SV *copy = sv_2mortal(newSVsv(buffer));

    p_input = SvPV(copy, n_input);

    s = webauth_attrs_decode(p_input, n_input, &list);

    if (items > 1) {
       sv_setiv(ST(1), s);
    }

    if (s == WA_ERR_NONE) {
        hv = newHV();
        for (i=0; i < list->num_attrs; i++) {
            hv_store(hv, list->attrs[i].name, strlen(list->attrs[i].name),
                     newSVpvn(list->attrs[i].value, list->attrs[i].length), 0);
        }
        webauth_attr_list_free(list);
       ST(0) = sv_2mortal(newRV_noinc((SV*)hv));
    } else {
       ST(0) =  &PL_sv_undef;
    }
}

void
webauth_random_bytes(length)
    int length
PROTOTYPE: $
CODE:
{
    int s;
    ST(0) = sv_2mortal(NEWSV(0, length));
    s = webauth_random_bytes(SvPVX(ST(0)), length);
    if (s<0) {
        ST(0) = &PL_sv_undef;
    } else {
        SvCUR_set(ST(0), length);
        SvPOK_only(ST(0));
    }
}

void
webauth_random_key(length)
    int length
PROTOTYPE: $
CODE:
{
    int s;
    ST(0) = sv_2mortal(NEWSV(0, length));
    s = webauth_random_key(SvPVX(ST(0)), length);
    if (s<0) {
        ST(0) = &PL_sv_undef;
    } else {
        SvCUR_set(ST(0), length);
        SvPOK_only(ST(0));
    }
}

WEBAUTH_KEY *
webauth_key_create(type,key_material)
int type
SV * key_material
PROTOTYPE: $$
CODE:
{
    STRLEN n_input;
    unsigned char *p_input;
    p_input = SvPV(key_material, n_input);
    RETVAL = webauth_key_create(type, p_input, n_input);
}
OUTPUT:
    RETVAL


WEBAUTH_KEYRING *
webauth_keyring_read_file(path,...)
char *path
PROTOTYPE: $;$
CODE:
{
    WEBAUTH_KEYRING *ring;
    int s;
   
    s = webauth_keyring_read_file(path, &ring);
    if (items > 1) {
       sv_setiv(ST(1), s);
    }
    RETVAL = ring;
}
OUTPUT:
    RETVAL

int
webauth_keyring_write_file(ring,path)
WEBAUTH_KEYRING *ring
char *path
PROTOTYPE: $$
CODE:
{
    RETVAL = webauth_keyring_write_file(ring, path);
}
OUTPUT:
    RETVAL


WEBAUTH_KEYRING *
webauth_keyring_new(initial_capacity)
int initial_capacity
PROTOTYPE: $
CODE:
{
    RETVAL = webauth_keyring_new(initial_capacity);
}
OUTPUT:
    RETVAL


int
webauth_keyring_add(ring,creation_time,valid_from,valid_till,key)
WEBAUTH_KEYRING *ring
time_t creation_time
time_t valid_from
time_t valid_till
WEBAUTH_KEY *key
PROTOTYPE: $$$$$
CODE:
{
    WEBAUTH_KEY *copy;

    copy = webauth_key_copy(key);
    if (copy == NULL) {
        RETVAL = WA_ERR_NO_MEM;    
    } else {
        RETVAL = webauth_keyring_add(ring, creation_time, 
                                      valid_from, valid_till, copy);
        if (RETVAL != WA_ERR_NONE) {
            webauth_key_free(copy);
        }
    }
}
OUTPUT:
    RETVAL

void
webauth_token_create(attrs,hint,ring,...)
SV *attrs
time_t hint
WEBAUTH_KEYRING *ring
PROTOTYPE: $$$;$
CODE:
{
    HV *h;
    SV *sv_val;
    int num_attrs, s, out_len, out_max;
    char *akey, *val;
    I32 klen;
    STRLEN vlen;
    WEBAUTH_ATTR_LIST *list;

    if (!SvROK(attrs) || !(SvTYPE(SvRV(attrs)) == SVt_PVHV)) {
        croak("attrs must be reference to a hash");
    }

    h = (HV*)SvRV(attrs);

    num_attrs = hv_iterinit(h);

    list = webauth_attr_list_new(num_attrs);
    if (list == NULL) {
        croak("can't malloc attrs");
    }

    while((sv_val = hv_iternextsv(h, &akey, &klen))) {
        val = SvPV(sv_val, vlen);
        webauth_attr_list_add(list, akey, val, vlen);
    }

    out_max = webauth_token_encoded_length(list);
    ST(0) = sv_2mortal(NEWSV(0, out_max));
    s = webauth_token_create(list, hint, SvPVX(ST(0)), &out_len, out_max, ring);
    webauth_attr_list_free(list);

    if (items > 3) {
       sv_setiv(ST(3), s);
    }

    if (s != WA_ERR_NONE) {
        ST(0) = &PL_sv_undef;
    } else {
        SvCUR_set(ST(0), out_len);
        SvPOK_only(ST(0));
    }
}

void
webauth_token_parse(buffer,ring,...)
SV *buffer
WEBAUTH_KEYRING *ring
PROTOTYPE: $$;$
CODE:
{
    STRLEN n_input;
    unsigned char *p_input;
    WEBAUTH_ATTR_LIST *list;
    int i, num_attrs;
    HV *hv;
    SV *copy = sv_2mortal(newSVsv(buffer));

    p_input = SvPV(copy, n_input);

    num_attrs = webauth_token_parse(p_input, n_input, &list, ring);

    if (items > 2) {
       sv_setiv(ST(2), num_attrs);
    }

    if (num_attrs > 0) {
        hv = newHV();
        for (i=0; i < num_attrs; i++) {
            hv_store(hv, list->attrs[i].name, strlen(list->attrs[i].name),
                     newSVpvn(list->attrs[i].value, list->attrs[i].length), 0);
        }
        ST(0) = sv_2mortal(newRV_noinc((SV*)hv));
        webauth_attr_list_free(list);
    } else {
        ST(0) =  &PL_sv_undef;
    }
}

MODULE = WebAuth        PACKAGE = WEBAUTH_KEYPtr  PREFIX = webauth_

void
webauth_DESTROY(key)
    WEBAUTH_KEY *key
CODE:
    webauth_key_free(key);

MODULE = WebAuth        PACKAGE = WEBAUTH_KEYRINGPtr  PREFIX = webauth_

void
webauth_DESTROY(ring)
    WEBAUTH_KEYRING *ring
CODE:
    webauth_keyring_free(ring);

 /*
 **  Local variables:
 **  tab-width: 4
 **  indent-tabs-mode: nil
 **  end:
 */
