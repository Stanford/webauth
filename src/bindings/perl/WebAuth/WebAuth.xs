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

    IV_CONST(WA_ERR_NONE);
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
    IV_CONST(WA_ERR_INVALID_CONTEXT);
    IV_CONST(WA_ERR_LOGIN_FAILED);
    IV_CONST(WA_ERR_TOKEN_EXPIRED);
    IV_CONST(WA_ERR_TOKEN_STALE);

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
    STR_CONST(WA_TK_REQUESTED_TOKEN);
    STR_CONST(WA_TK_REQUESTED_TOKEN_EXPIRATION);
    STR_CONST(WA_TK_RETURN_URL);
    STR_CONST(WA_TK_SUBJECT);
    STR_CONST(WA_TK_SUBJECT_AUTHENTICATOR);
    STR_CONST(WA_TK_TOKEN_TYPE);
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

void
webauth_base64_decoded_length(input)
SV * input
PROTOTYPE: $
PPCODE:
{
    int len, s;

    STRLEN n_input;
    unsigned char *p_input;
    p_input = SvPV(input, n_input);
    s = webauth_base64_decoded_length(p_input, n_input, &len);

    EXTEND(SP,2);
    PUSHs(sv_2mortal(newSViv(s)));
    PUSHs(sv_2mortal(newSViv(len)));
}

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
webauth_base64_decode(input)
SV * input
PROTOTYPE: $
PPCODE:
{
    STRLEN n_input;
    int out_len, out_max, s;
    unsigned char *p_input;
    unsigned char *buff;

    p_input = SvPV(input, n_input);
    buff = NULL;

    s = webauth_base64_decoded_length(p_input, n_input, &out_max);
    if (s == WA_ERR_NONE) {
            buff = malloc(out_max);
            if (buff == NULL) {
                croak("can't create buffer");
            }
            s = webauth_base64_decode(p_input, n_input, 
                                      buff, &out_len, out_max);
    }

    EXTEND(SP,2);
    PUSHs(sv_2mortal(newSViv(s)));
    if (buff != NULL) {
        SV *output = sv_newmortal();
        sv_setpvn(output, buff, out_len);
        free(buff);
        PUSHs(output);
    } else {
        PUSHs(&PL_sv_undef);
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

void
webauth_hex_decoded_length(length)
    int length
PROTOTYPE: $
PPCODE:
{
    int len, s;
    s = webauth_hex_decoded_length(length, &len);
    EXTEND(SP,2);
    PUSHs(sv_2mortal(newSViv(s)));
    PUSHs(sv_2mortal(newSViv(len)));
}

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
webauth_hex_decode(input)
SV * input
PROTOTYPE: $
PPCODE:
{
    STRLEN n_input;
    int out_len, out_max, s;
    unsigned char *p_input, *buff;

    p_input = SvPV(input, n_input);
    s = webauth_hex_decoded_length(n_input, &out_max);
    if (s == WA_ERR_NONE) {
            buff = malloc(out_max);
            if (buff == NULL) {
                croak("can't create buffer");
            }
            s = webauth_hex_decode(p_input, n_input, buff, &out_len, out_max);
    }

    EXTEND(SP,2);
    PUSHs(sv_2mortal(newSViv(s)));
    if (buff != NULL) {
        SV *output = sv_newmortal();
        sv_setpvn(output, buff, out_len);
        free(buff);
        PUSHs(output);
    } else {
        PUSHs(&PL_sv_undef);
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
PPCODE:
{
    HV *h;
    SV *sv_val;
    int num_attrs, s, out_len, out_max;
    char *key, *val;
    I32 klen;
    STRLEN vlen;
    WEBAUTH_ATTR_LIST *list;
    SV *output;

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

    output = sv_2mortal(NEWSV(0, out_max));
    s = webauth_attrs_encode(list, SvPVX(output), &out_len, out_max);
    webauth_attr_list_free(list);
    if (s != WA_ERR_NONE) {
        output = &PL_sv_undef;
    } else {
        SvCUR_set(output, out_len);
        SvPOK_only(output);
    }

    EXTEND(SP,2);
    PUSHs(sv_2mortal(newSViv(s)));
    PUSHs(output);
}

void
webauth_attrs_decode(buffer)
SV *buffer
PROTOTYPE: $
PPCODE:
{
    STRLEN n_input;
    unsigned char *p_input;
    WEBAUTH_ATTR_LIST *list;
    int i, s;
    HV *hv;
    SV *copy = sv_2mortal(newSVsv(buffer));
    SV *output;

    p_input = SvPV(copy, n_input);

    s = webauth_attrs_decode(p_input, n_input, &list);

    if (s == WA_ERR_NONE) {
        hv = newHV();
        for (i=0; i < list->num_attrs; i++) {
            hv_store(hv, list->attrs[i].name, strlen(list->attrs[i].name),
                     newSVpvn(list->attrs[i].value, list->attrs[i].length), 0);
        }
        webauth_attr_list_free(list);
       output = sv_2mortal(newRV_noinc((SV*)hv));
    } else {
       output =  &PL_sv_undef;
    }
    EXTEND(SP,2);
    PUSHs(sv_2mortal(newSViv(s)));
    PUSHs(output);
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
    if (s != WA_ERR_NONE) {
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
    if (s != WA_ERR_NONE) {
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


void
webauth_keyring_read_file(path)
char *path
PROTOTYPE: $
PPCODE:
{
    WEBAUTH_KEYRING *ring;
    SV *output;
    int s;
   
    s = webauth_keyring_read_file(path, &ring);
    output = sv_newmortal();
    sv_setref_pv(output, "WEBAUTH_KEYRINGPtr", (void*)ring);
    EXTEND(SP,2);
    PUSHs(sv_2mortal(newSViv(s)));
    PUSHs(output);
}

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
webauth_token_create(attrs,hint,ring)
SV *attrs
time_t hint
WEBAUTH_KEYRING *ring
PROTOTYPE: $$$
PPCODE:
{
    HV *h;
    SV *sv_val;
    int num_attrs, s, out_len, out_max;
    char *akey, *val, *buff;
    I32 klen;
    STRLEN vlen;
    WEBAUTH_ATTR_LIST *list;
    SV *output;

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
    buff = malloc(out_max);
    if (buff == NULL) {
        croak("can't malloc token buffer");
    }
    s = webauth_token_create(list, hint, buff, &out_len, out_max, ring);
    webauth_attr_list_free(list);

    if (s != WA_ERR_NONE) {
        output = &PL_sv_undef;
    } else {
        output = sv_newmortal();
        sv_setpvn(output, buff, out_len);
    }
    free(buff);
    EXTEND(SP,2);
    PUSHs(sv_2mortal(newSViv(s)));
    PUSHs(output);
}

void
webauth_token_create_with_key(attrs,hint,key)
SV *attrs
time_t hint
WEBAUTH_KEY *key
PROTOTYPE: $$$
PPCODE:
{
    HV *h;
    SV *sv_val, *output;
    int num_attrs, s, out_len, out_max;
    char *akey, *val, *buff;
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
    buff = malloc(out_max);
    if (buff == NULL) {
        croak("can't malloc token buffer");
    }
    s = webauth_token_create_with_key(list, hint,buff, &out_len, out_max, key);
    webauth_attr_list_free(list);

    if (s != WA_ERR_NONE) {
        output = &PL_sv_undef;
    } else {
        output = sv_newmortal();
        sv_setpvn(output, buff, out_len);
    }
    free(buff);
    EXTEND(SP,2);
    PUSHs(sv_2mortal(newSViv(s)));
    PUSHs(output);
}

void
webauth_token_parse(buffer,ttl,ring)
SV *buffer
int ttl
WEBAUTH_KEYRING *ring
PROTOTYPE: $$$
PPCODE:
{
    STRLEN n_input;
    unsigned char *p_input;
    WEBAUTH_ATTR_LIST *list;
    int i, s;
    HV *hv;
    SV *output, *copy = sv_2mortal(newSVsv(buffer));

    p_input = SvPV(copy, n_input);

    s = webauth_token_parse(p_input, n_input, ttl, ring, &list);
    
    if (s == WA_ERR_NONE) {
        hv = newHV();
        for (i=0; i < list->num_attrs; i++) {
            hv_store(hv, list->attrs[i].name, strlen(list->attrs[i].name),
                     newSVpvn(list->attrs[i].value, list->attrs[i].length), 0);
        }
        output = sv_2mortal(newRV_noinc((SV*)hv));
        webauth_attr_list_free(list);
    } else {
        output =  &PL_sv_undef;
    }
    EXTEND(SP,2);
    PUSHs(sv_2mortal(newSViv(s)));
    PUSHs(output);
}

void
webauth_token_parse_with_key(buffer,ttl,key)
SV *buffer
int ttl
WEBAUTH_KEY *key
PROTOTYPE: $$$
PPCODE:
{
    STRLEN n_input;
    unsigned char *p_input;
    WEBAUTH_ATTR_LIST *list;
    int i, s;
    HV *hv;
    SV *output, *copy = sv_2mortal(newSVsv(buffer));

    p_input = SvPV(copy, n_input);

    s = webauth_token_parse_with_key(p_input, n_input, ttl, key, &list);

    if (s == WA_ERR_NONE) {
        hv = newHV();
        for (i=0; i < list->num_attrs; i++) {
            hv_store(hv, list->attrs[i].name, strlen(list->attrs[i].name),
                     newSVpvn(list->attrs[i].value, list->attrs[i].length), 0);
        }
        output = sv_2mortal(newRV_noinc((SV*)hv));
        webauth_attr_list_free(list);
    } else {
        output =  &PL_sv_undef;
    }
    EXTEND(SP,2);
    PUSHs(sv_2mortal(newSViv(s)));
    PUSHs(output);
}

void
webauth_krb5_new()
PROTOTYPE: 
PPCODE:
{
    WEBAUTH_KRB5_CTXT *ctxt;
    int s= webauth_krb5_new(&ctxt);
    SV *output = sv_newmortal();
    sv_setref_pv(output, "WEBAUTH_KRB5_CTXTPtr", (void*)ctxt);
    EXTEND(SP,2);
    PUSHs(sv_2mortal(newSViv(s)));
    PUSHs(output);
}


int
webauth_krb5_error_code(c)
WEBAUTH_KRB5_CTXT *c
PROTOTYPE: $
CODE:
{
    RETVAL = webauth_krb5_error_code(c);
}
OUTPUT:
    RETVAL

char *
webauth_krb5_error_message(c)
WEBAUTH_KRB5_CTXT *c
PROTOTYPE: $
CODE:
{
    RETVAL = (char*)webauth_krb5_error_message(c);
}
OUTPUT:
    RETVAL

int
webauth_krb5_init_via_password(c,name,password,keytab,...)
WEBAUTH_KRB5_CTXT *c
char *name
char *password
char *keytab
PROTOTYPE: $$$$;$
CODE:
{
    char *cred;
    if (items==5) {
        cred = (char *)SvPV(ST(4),PL_na);
    } else {
        cred = NULL;
    }
    RETVAL = webauth_krb5_init_via_password(c, name, password, keytab, cred);
}
OUTPUT:
    RETVAL

int
webauth_krb5_init_via_keytab(c,keytab,...)
WEBAUTH_KRB5_CTXT *c
char *keytab
PROTOTYPE: $$;$
CODE:
{
    char *cred;
    if (items==3) {
        cred = (char *)SvPV(ST(2),PL_na);
    } else {
        cred = NULL;
    }
    RETVAL = webauth_krb5_init_via_keytab(c, keytab, cred);
}
OUTPUT:
    RETVAL

int
webauth_krb5_init_via_tgt(c,tgt,...)
WEBAUTH_KRB5_CTXT *c
SV *tgt
PROTOTYPE: $$;$
CODE:
{
    char *cred;
    unsigned char *ptgt;
    int tgt_len;

    ptgt = SvPV(tgt, tgt_len);

    if (items==3) {
        cred = (char *)SvPV(ST(2),PL_na);
    } else {
        cred = NULL;
    }
    RETVAL = webauth_krb5_init_via_tgt(c, ptgt, tgt_len, cred);
}
OUTPUT:
    RETVAL

int
webauth_krb5_import_ticket(c,ticket)
WEBAUTH_KRB5_CTXT *c
SV *ticket
PROTOTYPE: $$
CODE:
{
    unsigned char *pticket;
    int ticket_len;

    pticket = SvPV(ticket, ticket_len);
    RETVAL = webauth_krb5_import_ticket(c, pticket, ticket_len);
}
OUTPUT:
    RETVAL

void
webauth_krb5_export_tgt(c)
WEBAUTH_KRB5_CTXT *c
PROTOTYPE: $
PPCODE:
{ 
    int s;      
    unsigned char *tgt;
    int tgt_len;
    time_t expiration;

    s = webauth_krb5_export_tgt(c, &tgt, &tgt_len, &expiration);
    EXTEND(SP,3);
    PUSHs(sv_2mortal(newSViv(s)));
    if (s == WA_ERR_NONE){
        SV *out = sv_newmortal();
        sv_setpvn(out, tgt, tgt_len);
        free(tgt);
        PUSHs(out);
        PUSHs(sv_2mortal(newSViv(expiration)));
    } else {
        PUSHs(&PL_sv_undef);
        PUSHs(&PL_sv_undef);
    }
}

void
webauth_krb5_service_principal(c,service,hostname)
WEBAUTH_KRB5_CTXT *c
char *service
char *hostname
PROTOTYPE: $$$
PPCODE:
{
    int s;
    char *server_princ;
    s = webauth_krb5_service_principal(c, service, 
                                       hostname, &server_princ);
    EXTEND(SP,2);
    PUSHs(sv_2mortal(newSViv(s)));
    if (s == WA_ERR_NONE){
        SV *out = sv_newmortal();
        sv_setpv(out, server_princ);
        PUSHs(out);
        free(server_princ);
    } else {
        PUSHs(&PL_sv_undef);
    }
}

void
webauth_krb5_get_principal(c)
WEBAUTH_KRB5_CTXT *c
PROTOTYPE: $
PPCODE:
{
    int s;
    char *princ;
    s = webauth_krb5_get_principal(c, &princ);

    EXTEND(SP,2);
    PUSHs(sv_2mortal(newSViv(s)));
    if (s == WA_ERR_NONE){
        SV *out = sv_newmortal();
        sv_setpv(out, princ);
        PUSHs(out);
        free(princ);
    } else {
        PUSHs(&PL_sv_undef);
    }
}

void
webauth_krb5_export_ticket(c,princ)
WEBAUTH_KRB5_CTXT *c
char *princ
PROTOTYPE: $$
PPCODE:
{       
    unsigned char *ticket;
    int ticket_len, s;
    time_t expiration;

    s = webauth_krb5_export_ticket(c, princ, &ticket,
                                        &ticket_len, &expiration);
    EXTEND(SP,3);
    PUSHs(sv_2mortal(newSViv(s)));
    if (s == WA_ERR_NONE){
        SV *out = sv_newmortal();
        sv_setpvn(out, ticket, ticket_len);
        free(ticket);
        PUSHs(out);
        PUSHs(sv_2mortal(newSViv(expiration)));
    } else {
        PUSHs(&PL_sv_undef);
        PUSHs(&PL_sv_undef);
    }
}

void
webauth_krb5_mk_req(c,princ)
WEBAUTH_KRB5_CTXT *c
char *princ
PROTOTYPE: $$
PPCODE:
{       
    unsigned char *req;
    int req_len, s;
    s = webauth_krb5_mk_req(c, princ, &req, &req_len);
    EXTEND(SP,2);
    PUSHs(sv_2mortal(newSViv(s)));
    if (s == WA_ERR_NONE){
        SV *out = sv_newmortal();
        sv_setpvn(out, req, req_len);
        free(req);
        PUSHs(out);
    } else {
        PUSHs(&PL_sv_undef);
    }
}

void
webauth_krb5_rd_req(c,request,keytab)
WEBAUTH_KRB5_CTXT *c
SV *request
char *keytab
PROTOTYPE: $$$
PPCODE:
{       
    unsigned char *req;
    char *client_princ;
    int req_len, s;
    req = SvPV(request, req_len);
    s = webauth_krb5_rd_req(c, req, req_len, keytab, &client_princ);

    EXTEND(SP,2);
    PUSHs(sv_2mortal(newSViv(s)));
    if (s == WA_ERR_NONE){
        SV *out = sv_newmortal();
        sv_setpv(out, client_princ);
        free(client_princ);
        PUSHs(out);
    } else {
        PUSHs(&PL_sv_undef);
    }
}

int
webauth_krb5_keep_cred_cache(c)
WEBAUTH_KRB5_CTXT *c
PROTOTYPE: $
CODE:
{       
    RETVAL = webauth_krb5_keep_cred_cache(c);
}
OUTPUT:
    RETVAL

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

MODULE = WebAuth        PACKAGE = WEBAUTH_KRB5_CTXTPtr  PREFIX = webauth_

void
webauth_DESTROY(ctxt)
    WEBAUTH_KRB5_CTXT *ctxt
CODE:
    webauth_krb5_free(ctxt);

 /*
 **  Local variables:
 **  tab-width: 4
 **  indent-tabs-mode: nil
 **  end:
 */
