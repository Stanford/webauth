#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

/* FIXME: should this be "webauth.h" and 
          should -I{top_srcdir}/src/libwebauth be added in Makefile.PL?" */

#include "../../../libwebauth/webauth.h"

void
webauth_croak(const char *detail, int s, WEBAUTH_KRB5_CTXT *c)
{
    HV *hv;
    SV *rv;

    hv = newHV();
    hv_store(hv, "status", 6, newSViv(s), 0);
    if (detail != NULL) {
        hv_store(hv, "detail", 6, newSVpv(detail,0), 0);
    }
    if (s == WA_ERR_KRB5 && c != NULL) {
        hv_store(hv, "krb5_ec", 7, newSViv(webauth_krb5_error_code(c)), 0);
        hv_store(hv, "krb5_em", 7, 
                  newSVpv(webauth_krb5_error_message(c),0), 0);
    }

	if (CopLINE(PL_curcop)) {
        hv_store(hv, "line", 4, newSViv(CopLINE(PL_curcop)), 0);
        hv_store(hv, "file", 4, newSVpv(CopFILE(PL_curcop), 0), 0);
    }
    rv = newRV_noinc((SV*)hv);
    sv_bless(rv, gv_stashpv("WebAuth::Exception", TRUE));
    sv_setsv(get_sv("@", TRUE), sv_2mortal(rv));
    croak(Nullch);
}

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
    STR_CONST(WA_TK_RETURN_URL);
    STR_CONST(WA_TK_SUBJECT);
    STR_CONST(WA_TK_SUBJECT_AUTH);
    STR_CONST(WA_TK_SUBJECT_AUTH_DATA);
    STR_CONST(WA_TK_TOKEN_TYPE);
    STR_CONST(WA_TK_WEBKDC_TOKEN);
}

char *
webauth_error_message(status)
    int status
PROTOTYPE: $
CODE:
{
    RETVAL = (char*) webauth_error_message(status);
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

    if (s != WA_ERR_NONE) 
        webauth_croak("webauth_base64_encode", s, NULL);

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
    int out_len, s;
    unsigned char *p_input;
    unsigned char *buff;
    SV *output;

    p_input = SvPV(input, n_input);
    buff = NULL;

    buff = malloc(n_input);
    if (buff == NULL) {
        croak("can't create buffer");
    }
    s = webauth_base64_decode(p_input, n_input, buff, &out_len, n_input);

    if (s != WA_ERR_NONE) {
       if (buff != NULL)
            free(buff);
       webauth_croak("webauth_base64_decode", s, NULL);
    }

    EXTEND(SP,1);
    output = sv_newmortal();
    sv_setpvn(output, buff, out_len);
    PUSHs(output);
    if (buff != NULL)
        free(buff);
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
    if (s != WA_ERR_NONE) 
        webauth_croak("webauth_hex_encode", s, NULL);
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
    SV *output;
    buff = NULL;

    p_input = SvPV(input, n_input);
    s = webauth_hex_decoded_length(n_input, &out_max);
    if (s != WA_ERR_NONE) 
        webauth_croak("webauth_hex_decoded_length", s, NULL);

    if (s == WA_ERR_NONE) {
            buff = malloc(out_max);
            if (buff == NULL) {
                croak("can't create buffer");
            }
            s = webauth_hex_decode(p_input, n_input, buff, &out_len, out_max);
    }


    if (s != WA_ERR_NONE) {
        if (buff != NULL) 
            free(buff);        
        webauth_croak("webauth_hex_decode", s, NULL);
    }

    EXTEND(SP,1);

    output = sv_newmortal();
    sv_setpvn(output, buff, out_len);
    PUSHs(output);

    if (buff != NULL) 
        free(buff);
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
        webauth_croak("webauth_attrs_encode", s, NULL);
    } else {
        SvCUR_set(output, out_len);
        SvPOK_only(output);
    }

    EXTEND(SP,1);
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

    if (s != WA_ERR_NONE)
        webauth_croak("webauth_attrs_decode", s, NULL);

    hv = newHV();
    for (i=0; i < list->num_attrs; i++) {
        hv_store(hv, list->attrs[i].name, strlen(list->attrs[i].name),
            newSVpvn(list->attrs[i].value, list->attrs[i].length), 0);
    }
    webauth_attr_list_free(list);
    output = sv_2mortal(newRV_noinc((SV*)hv));
    EXTEND(SP,1);
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
        webauth_croak("webauth_random_bytes", s, NULL);
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
        webauth_croak("webauth_random_key", s, NULL);
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
    if (RETVAL == NULL) {
        webauth_croak("webauth_key_create", WA_ERR_BAD_KEY, NULL);
    }
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
    if (s != WA_ERR_NONE) {
        webauth_croak("webauth_keyring_read_file", s, NULL);
    }
    output = sv_newmortal();
    sv_setref_pv(output, "WEBAUTH_KEYRINGPtr", (void*)ring);
    PUSHs(output);
}

void
webauth_keyring_write_file(ring,path)
WEBAUTH_KEYRING *ring
char *path
PROTOTYPE: $$
PPCODE:
{
    int s = webauth_keyring_write_file(ring, path);
    if (s != WA_ERR_NONE) {
        webauth_croak("webauth_keyring_write_file", s, NULL);
    }
}

WEBAUTH_KEYRING *
webauth_keyring_new(initial_capacity)
int initial_capacity
PROTOTYPE: $
CODE:
{
    RETVAL = webauth_keyring_new(initial_capacity);
    if (RETVAL == NULL) {
        webauth_croak("webauth_keyring_new", WA_ERR_NO_MEM, NULL);
    }
}
OUTPUT:
    RETVAL

void
webauth_keyring_add(ring,creation_time,valid_from,valid_till,key)
WEBAUTH_KEYRING *ring
time_t creation_time
time_t valid_from
time_t valid_till
WEBAUTH_KEY *key
PROTOTYPE: $$$$$
PPCODE:
{
    WEBAUTH_KEY *copy;
    int s;

    copy = webauth_key_copy(key);
    if (copy == NULL) {
        s = WA_ERR_NO_MEM;    
    } else {
        s = webauth_keyring_add(ring, creation_time, 
                                      valid_from, valid_till, copy);
        if (s != WA_ERR_NONE) {
            webauth_key_free(copy);
        }
    }
    if (s != WA_ERR_NONE) {
        webauth_croak("webauth_keyring_write_file", s, NULL);
    }
}

void
webauth_token_create(attrs,hint,key_or_ring)
SV *attrs
time_t hint
SV *key_or_ring
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
    int iskey;

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
	if (sv_derived_from(key_or_ring, "WEBAUTH_KEYRINGPtr")) {
        WEBAUTH_KEYRING *ring;
	    IV tmp = SvIV((SV*)SvRV(key_or_ring));
	    ring = INT2PTR(WEBAUTH_KEYRING *,tmp);
        s = webauth_token_create(list, hint, buff, &out_len, out_max, ring);
        iskey = 0;
    } else if (sv_derived_from(key_or_ring, "WEBAUTH_KEYPtr")) {
        WEBAUTH_KEY *key;
	    IV tmp = SvIV((SV*)SvRV(key_or_ring));
	    key = INT2PTR(WEBAUTH_KEY *,tmp);
        s = webauth_token_create_with_key(list, hint, buff, 
                                          &out_len, out_max, key);
        iskey = 1;
    } else {
        croak("key_or_ring must be a WEBAUTH_KEYRING or WEBAUTH_KEY");
    }

    webauth_attr_list_free(list);

    if (s != WA_ERR_NONE) {
        free(buff);
        webauth_croak(iskey ? 
                      "webauth_token_create_with_key" : "webauth_token_create",
                      s, NULL);    
    } else {
        output = sv_newmortal();
        sv_setpvn(output, buff, out_len);
    }
    free(buff);
    EXTEND(SP,1);
    PUSHs(output);
}

void
webauth_token_parse(buffer,ttl,key_or_ring)
SV *buffer
int ttl
SV *key_or_ring
PROTOTYPE: $$$
PPCODE:
{
    STRLEN n_input;
    unsigned char *p_input;
    WEBAUTH_ATTR_LIST *list;
    int i, s, iskey;
    HV *hv;
    SV *output;

    p_input = SvPV(buffer, n_input);

	if (sv_derived_from(key_or_ring, "WEBAUTH_KEYRINGPtr")) {
        WEBAUTH_KEYRING *ring;
	    IV tmp = SvIV((SV*)SvRV(key_or_ring));
	    ring = INT2PTR(WEBAUTH_KEYRING *,tmp);
        s = webauth_token_parse(p_input, n_input, ttl, ring, &list);
        iskey = 0;
    } else if (sv_derived_from(key_or_ring, "WEBAUTH_KEYPtr")) {
        WEBAUTH_KEY *key;
	    IV tmp = SvIV((SV*)SvRV(key_or_ring));
	    key = INT2PTR(WEBAUTH_KEY *,tmp);
        s = webauth_token_parse_with_key(p_input, n_input, ttl, key, &list);
        iskey = 1;
    } else {
        croak("key_or_ring must be a WEBAUTH_KEYRING or WEBAUTH_KEY");
    }
    
    if (s == WA_ERR_NONE) {
        hv = newHV();
        for (i=0; i < list->num_attrs; i++) {
            hv_store(hv, list->attrs[i].name, strlen(list->attrs[i].name),
                     newSVpvn(list->attrs[i].value, list->attrs[i].length), 0);
        }
        output = sv_2mortal(newRV_noinc((SV*)hv));
        webauth_attr_list_free(list);
    } else {
        webauth_croak(iskey ? 
                      "webauth_token_parse_with_key" : "webauth_token_parse", 
                      s, NULL);    
    }
    EXTEND(SP,1);
    PUSHs(output);
}

void
webauth_krb5_new()
PROTOTYPE: 
PPCODE:
{
    WEBAUTH_KRB5_CTXT *ctxt = NULL;
    int s = webauth_krb5_new(&ctxt);
    SV *output = sv_newmortal();
    sv_setref_pv(output, "WEBAUTH_KRB5_CTXTPtr", (void*)ctxt);
    if (ctxt == NULL) {
        webauth_croak("webauth_krb5_new", WA_ERR_NO_MEM, NULL);
    } else {
        if (s != WA_ERR_NONE) {
            webauth_croak("webauth_krb5_new", s, ctxt);
        }
    }
    EXTEND(SP,1);
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

void
webauth_krb5_init_via_password(c,name,password,keytab,...)
WEBAUTH_KRB5_CTXT *c
char *name
char *password
char *keytab
PROTOTYPE: $$$$;$
PPCODE:
{
    char *cred;
    int s;
    if (items==5) {
        cred = (char *)SvPV(ST(4),PL_na);
    } else {
        cred = NULL;
    }
    s = webauth_krb5_init_via_password(c, name, password, keytab, cred);
    if (s != WA_ERR_NONE) {
        webauth_croak("webauth_krb5_init_via_password", s, c);
    }
}

void
webauth_krb5_init_via_keytab(c,keytab,...)
WEBAUTH_KRB5_CTXT *c
char *keytab
PROTOTYPE: $$;$
PPCODE:
{
    int s;
    char *cred;
    if (items==3) {
        cred = (char *)SvPV(ST(2),PL_na);
    } else {
        cred = NULL;
    }
    s = webauth_krb5_init_via_keytab(c, keytab, cred);
    if (s != WA_ERR_NONE) {
        webauth_croak("webauth_krb5_init_via_keytab", s, c);
    }
}

void
webauth_krb5_init_via_tgt(c,tgt,...)
WEBAUTH_KRB5_CTXT *c
SV *tgt
PROTOTYPE: $$;$
PPCODE:
{
    char *cred;
    unsigned char *ptgt;
    int tgt_len, s;

    ptgt = SvPV(tgt, tgt_len);

    if (items==3) {
        cred = (char *)SvPV(ST(2),PL_na);
    } else {
        cred = NULL;
    }
    s = webauth_krb5_init_via_tgt(c, ptgt, tgt_len, cred);
    if (s != WA_ERR_NONE) {
        webauth_croak("webauth_krb5_init_via_keytab", s, c);
    }
}

void
webauth_krb5_import_ticket(c,ticket)
WEBAUTH_KRB5_CTXT *c
SV *ticket
PROTOTYPE: $$
PPCODE:
{
    unsigned char *pticket;
    int ticket_len, s;

    pticket = SvPV(ticket, ticket_len);
    s = webauth_krb5_import_ticket(c, pticket, ticket_len);
    if (s != WA_ERR_NONE) {
        webauth_croak("webauth_krb5_import_ticket", s, c);
    }
}

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
    if (s == WA_ERR_NONE){
        SV *out = sv_newmortal();
        sv_setpvn(out, tgt, tgt_len);
        free(tgt);
        EXTEND(SP,2);
        PUSHs(out);
        PUSHs(sv_2mortal(newSViv(expiration)));
    } else {
        free(tgt);
        webauth_croak("webauth_krb5_export_tgt", s, c);
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
    if (s == WA_ERR_NONE){
        SV *out = sv_newmortal();
        sv_setpv(out, server_princ);
        EXTEND(SP,1);
        PUSHs(out);
        free(server_princ);
    } else {
        free(server_princ);
        webauth_croak("webauth_krb5_service_principal", s, c);
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

    if (s == WA_ERR_NONE){
        SV *out = sv_newmortal();
        sv_setpv(out, princ);
        EXTEND(SP,1);
        PUSHs(out);
        free(princ);
    } else {
        free(princ);
        webauth_croak("webauth_krb5_get_principal", s, c);
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
    if (s == WA_ERR_NONE){
        SV *out = sv_newmortal();
        sv_setpvn(out, ticket, ticket_len);
        free(ticket);
        EXTEND(SP,2);
        PUSHs(out);
        PUSHs(sv_2mortal(newSViv(expiration)));
    } else {
        free(ticket);
        webauth_croak("webauth_krb5_export_ticket", s, c);
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

    if (s == WA_ERR_NONE){
        SV *out = sv_newmortal();
        sv_setpvn(out, req, req_len);
        free(req);
        EXTEND(SP,1);
        PUSHs(out);
    } else {
        free(req);
        webauth_croak("webauth_krb5_mk_req", s, c);
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

    if (s == WA_ERR_NONE){
        SV *out = sv_newmortal();
        sv_setpv(out, client_princ);
        free(client_princ);
        EXTEND(SP,1);
        PUSHs(out);
    } else {
        free(client_princ);
        webauth_croak("webauth_krb5_rd_req", s, c);
    }
}

void
webauth_krb5_keep_cred_cache(c)
WEBAUTH_KRB5_CTXT *c
PROTOTYPE: $
PPCODE:
{       
    int s = webauth_krb5_keep_cred_cache(c);
    if (s != WA_ERR_NONE)
        webauth_croak("webauth_krb5_rd_req", s, c);
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
