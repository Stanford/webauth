/* -*- c -*-
 * Perl XS bindings for the WebAuth library.
 *
 * Written by Roland Schemers
 * Copyright 2003, 2005, 2006, 2008, 2009, 2010
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "webauth.h"

#define IV_CONST(X) newCONSTSUB(stash, #X, newSViv(X))
#define STR_CONST(X) newCONSTSUB(stash, #X, newSVpv(X, 0))


static void
webauth_croak(const char *detail, int s, WEBAUTH_KRB5_CTXT *c)
{
    HV *hv;
    SV *rv;

    hv = newHV();
    (void) hv_store(hv, "status", 6, newSViv(s), 0);
    if (detail != NULL)
        (void) hv_store(hv, "detail", 6, newSVpv(detail,0), 0);
    if (s == WA_ERR_KRB5 && c != NULL) {
        (void) hv_store(hv, "krb5_ec", 7,
                        newSViv(webauth_krb5_error_code(c)), 0);
        (void) hv_store(hv, "krb5_em", 7,
                        newSVpv(webauth_krb5_error_message(c), 0), 0);
    }

    if (CopLINE(PL_curcop)) {
        (void) hv_store(hv, "line", 4, newSViv(CopLINE(PL_curcop)), 0);
        (void) hv_store(hv, "file", 4, newSVpv(CopFILE(PL_curcop), 0), 0);
    }
    rv = newRV_noinc((SV*)hv);
    sv_bless(rv, gv_stashpv("WebAuth::Exception", TRUE));
    sv_setsv(get_sv("@", TRUE), sv_2mortal(rv));
    croak(Nullch);
}


MODULE = WebAuth        PACKAGE = WebAuth    PREFIX = webauth_

PROTOTYPES: ENABLE

BOOT:
    HV *stash;

    /* Constant subs for WebAuth. */
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

    IV_CONST(WA_PEC_SERVICE_TOKEN_EXPIRED);
    IV_CONST(WA_PEC_SERVICE_TOKEN_INVALID);
    IV_CONST(WA_PEC_PROXY_TOKEN_EXPIRED);
    IV_CONST(WA_PEC_PROXY_TOKEN_INVALID);
    IV_CONST(WA_PEC_INVALID_REQUEST);
    IV_CONST(WA_PEC_UNAUTHORIZED);
    IV_CONST(WA_PEC_SERVER_FAILURE);
    IV_CONST(WA_PEC_REQUEST_TOKEN_STALE);
    IV_CONST(WA_PEC_REQUEST_TOKEN_INVALID);
    IV_CONST(WA_PEC_GET_CRED_FAILURE);
    IV_CONST(WA_PEC_REQUESTER_KRB5_CRED_INVALID);
    IV_CONST(WA_PEC_LOGIN_TOKEN_STALE);
    IV_CONST(WA_PEC_LOGIN_TOKEN_INVALID);
    IV_CONST(WA_PEC_LOGIN_FAILED);
    IV_CONST(WA_PEC_PROXY_TOKEN_REQUIRED);
    IV_CONST(WA_PEC_LOGIN_CANCELED);
    IV_CONST(WA_PEC_LOGIN_FORCED);
    IV_CONST(WA_PEC_USER_REJECTED);
    IV_CONST(WA_PEC_CREDS_EXPIRED);

    IV_CONST(WA_AES_KEY);
    IV_CONST(WA_AES_128);
    IV_CONST(WA_AES_192);
    IV_CONST(WA_AES_256);

    STR_CONST(WA_TK_APP_STATE);
    STR_CONST(WA_TK_COMMAND);
    STR_CONST(WA_TK_CRED_DATA);
    STR_CONST(WA_TK_CRED_SERVER);
    STR_CONST(WA_TK_CRED_TYPE);
    STR_CONST(WA_TK_CREATION_TIME);
    STR_CONST(WA_TK_ERROR_CODE);
    STR_CONST(WA_TK_ERROR_MESSAGE);
    STR_CONST(WA_TK_EXPIRATION_TIME);
    STR_CONST(WA_TK_SESSION_KEY);
    STR_CONST(WA_TK_LASTUSED_TIME);
    STR_CONST(WA_TK_PASSWORD);
    STR_CONST(WA_TK_PROXY_TYPE);
    STR_CONST(WA_TK_PROXY_DATA);
    STR_CONST(WA_TK_PROXY_SUBJECT);
    STR_CONST(WA_TK_REQUEST_OPTIONS);
    STR_CONST(WA_TK_REQUESTED_TOKEN_TYPE);
    STR_CONST(WA_TK_RETURN_URL);
    STR_CONST(WA_TK_SUBJECT);
    STR_CONST(WA_TK_SUBJECT_AUTH);
    STR_CONST(WA_TK_SUBJECT_AUTH_DATA);
    STR_CONST(WA_TK_TOKEN_TYPE);
    STR_CONST(WA_TK_USERNAME);
    STR_CONST(WA_TK_WEBKDC_TOKEN);


char *
webauth_error_message(status)
    int status
  PROTOTYPE: $
  CODE:
    RETVAL = (char*) webauth_error_message(status);
  OUTPUT:
    RETVAL


void
webauth_base64_encode(input)
    SV *input
  PROTOTYPE: $
  CODE:
    STRLEN n_input;
    size_t out_len, out_max;
    int s;
    char *p_input;

    p_input = SvPV(input, n_input);
    out_max = webauth_base64_encoded_length(n_input);

    ST(0) = sv_2mortal(NEWSV(0, out_max));

    s = webauth_base64_encode(p_input, n_input, SvPVX(ST(0)), &out_len,
                              out_max);

    if (s != WA_ERR_NONE)
        webauth_croak("webauth_base64_encode", s, NULL);

    SvCUR_set(ST(0), out_len);
    SvPOK_only(ST(0));


void
webauth_base64_decode(input)
    SV * input
  PROTOTYPE: $
  PPCODE:
    STRLEN n_input;
    size_t out_len;
    int s;
    char *p_input;
    char *buff;
    SV *output;

    p_input = SvPV(input, n_input);
    buff = NULL;

    buff = malloc(n_input);
    if (buff == NULL)
        croak("can't create buffer");
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


void
webauth_hex_encode(input)
    SV * input
  PROTOTYPE: $
  CODE:
    STRLEN n_input;
    size_t out_len, out_max;
    int s;
    char *p_input;

    p_input = SvPV(input, n_input);
    out_max = webauth_hex_encoded_length(n_input);

    ST(0) = sv_2mortal(NEWSV(0, out_max));
    s = webauth_hex_encode(p_input, n_input, SvPVX(ST(0)), &out_len, out_max);
    if (s != WA_ERR_NONE)
        webauth_croak("webauth_hex_encode", s, NULL);
    SvCUR_set(ST(0), out_len);
    SvPOK_only(ST(0));


void
webauth_hex_decode(input)
    SV * input
  PROTOTYPE: $
  PPCODE:
    STRLEN n_input;
    size_t out_len, out_max;
    int s;
    char *p_input, *buff;
    SV *output;
    buff = NULL;

    p_input = SvPV(input, n_input);
    s = webauth_hex_decoded_length(n_input, &out_max);
    if (s != WA_ERR_NONE)
        webauth_croak("webauth_hex_decoded_length", s, NULL);
    buff = malloc(out_max);
    if (buff == NULL)
        croak("can't create buffer");
    s = webauth_hex_decode(p_input, n_input, buff, &out_len, out_max);
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


void
webauth_attrs_encode(attrs)
    SV *attrs
  PROTOTYPE: $
  PPCODE:
    HV *h;
    SV *sv_val;
    size_t num_attrs, out_len, out_max;
    int s;
    char *key, *val;
    I32 klen;
    STRLEN vlen;
    WEBAUTH_ATTR_LIST *list;
    SV *output;

    if (!SvROK(attrs) || !(SvTYPE(SvRV(attrs)) == SVt_PVHV))
        croak("attrs must be reference to a hash");
    h = (HV *) SvRV(attrs);

    num_attrs = hv_iterinit(h);
    list = webauth_attr_list_new(num_attrs);
    if (list == NULL)
        croak("can't malloc attr list");

    while ((sv_val = hv_iternextsv(h, &key, &klen)) != NULL) {
        val = SvPV(sv_val, vlen);
        webauth_attr_list_add(list, key, val, vlen, WA_F_NONE);
    }

    out_max = webauth_attrs_encoded_length(list);
    output = sv_2mortal(NEWSV(0, out_max));
    s = webauth_attrs_encode(list, SvPVX(output), &out_len, out_max);
    webauth_attr_list_free(list);
    if (s != WA_ERR_NONE)
        webauth_croak("webauth_attrs_encode", s, NULL);
    else {
        SvCUR_set(output, out_len);
        SvPOK_only(output);
    }

    EXTEND(SP,1);
    PUSHs(output);


void
webauth_attrs_decode(buffer)
    SV *buffer
  PROTOTYPE: $
  PPCODE:
    size_t n_input;
    char *p_input;
    WEBAUTH_ATTR_LIST *list;
    size_t i;
    int s;
    HV *hv;
    SV *copy = sv_2mortal(newSVsv(buffer));
    SV *output;

    p_input = SvPV(copy, n_input);
    s = webauth_attrs_decode(p_input, n_input, &list);
    if (s != WA_ERR_NONE)
        webauth_croak("webauth_attrs_decode", s, NULL);

    hv = newHV();
    for (i = 0; i < list->num_attrs; i++)
        (void) hv_store(hv, list->attrs[i].name, strlen(list->attrs[i].name),
                        newSVpvn(list->attrs[i].value, list->attrs[i].length),
                        0);
    webauth_attr_list_free(list);
    output = sv_2mortal(newRV_noinc((SV*)hv));
    EXTEND(SP,1);
    PUSHs(output);


void
webauth_random_bytes(length)
    int length
  PROTOTYPE: $
  CODE:
    int s;

    ST(0) = sv_2mortal(NEWSV(0, length));
    s = webauth_random_bytes(SvPVX(ST(0)), length);
    if (s != WA_ERR_NONE)
        webauth_croak("webauth_random_bytes", s, NULL);
    else {
        SvCUR_set(ST(0), length);
        SvPOK_only(ST(0));
    }


void
webauth_random_key(length)
    int length
  PROTOTYPE: $
  CODE:
    int s;

    ST(0) = sv_2mortal(NEWSV(0, length));
    s = webauth_random_key(SvPVX(ST(0)), length);
    if (s != WA_ERR_NONE) {
        webauth_croak("webauth_random_key", s, NULL);
    } else {
        SvCUR_set(ST(0), length);
        SvPOK_only(ST(0));
    }


WEBAUTH_KEY *
webauth_key_create(type, key_material)
    int type
    SV *key_material
  PROTOTYPE: $$
  CODE:
    STRLEN n_input;
    char *p_input;

    p_input = SvPV(key_material, n_input);
    RETVAL = webauth_key_create(type, p_input, n_input);
    if (RETVAL == NULL)
        webauth_croak("webauth_key_create", WA_ERR_BAD_KEY, NULL);
  OUTPUT:
    RETVAL


void
webauth_keyring_read_file(path)
    char *path
  PROTOTYPE: $
  PPCODE:
    WEBAUTH_KEYRING *ring;
    SV *output;
    int s;

    s = webauth_keyring_read_file(path, &ring);
    if (s != WA_ERR_NONE)
        webauth_croak("webauth_keyring_read_file", s, NULL);
    output = sv_newmortal();
    sv_setref_pv(output, "WEBAUTH_KEYRINGPtr", (void*)ring);
    PUSHs(output);


void
webauth_keyring_write_file(ring, path)
    WEBAUTH_KEYRING *ring
    char *path
  PROTOTYPE: $$
  PPCODE:
    int s;

    s = webauth_keyring_write_file(ring, path);
    if (s != WA_ERR_NONE)
        webauth_croak("webauth_keyring_write_file", s, NULL);


WEBAUTH_KEYRING *
webauth_keyring_new(initial_capacity)
    size_t initial_capacity
  PROTOTYPE: $
  CODE:
    RETVAL = webauth_keyring_new(initial_capacity);
    if (RETVAL == NULL)
        webauth_croak("webauth_keyring_new", WA_ERR_NO_MEM, NULL);
  OUTPUT:
    RETVAL

void
webauth_keyring_add(ring, creation_time, valid_after, key)
    WEBAUTH_KEYRING *ring
    time_t creation_time
    time_t valid_after
    WEBAUTH_KEY *key
  PROTOTYPE: $$$$
  PPCODE:
    int s;

    s = webauth_keyring_add(ring, creation_time, valid_after, key);
    if (s != WA_ERR_NONE)
        webauth_croak("webauth_keyring_write_file", s, NULL);


void
webauth_token_create(attrs, hint, key_or_ring)
    SV *attrs
    time_t hint
    SV *key_or_ring
  PROTOTYPE: $$$
  PPCODE:
    HV *h;
    SV *sv_val;
    size_t num_attrs, out_len, out_max;
    int s;
    char *akey, *val, *buff;
    I32 klen;
    STRLEN vlen;
    WEBAUTH_ATTR_LIST *list;
    SV *output = NULL;
    int iskey;

    if (!SvROK(attrs) || !(SvTYPE(SvRV(attrs)) == SVt_PVHV))
        croak("attrs must be reference to a hash");
    h = (HV *) SvRV(attrs);

    num_attrs = hv_iterinit(h);
    list = webauth_attr_list_new(num_attrs);
    if (list == NULL)
        croak("can't malloc attrs");

    while ((sv_val = hv_iternextsv(h, &akey, &klen)) != NULL) {
        val = SvPV(sv_val, vlen);
        webauth_attr_list_add(list, akey, val, vlen, WA_F_NONE);
    }

    out_max = webauth_token_encoded_length(list);
    buff = malloc(out_max);
    if (buff == NULL)
        croak("can't malloc token buffer");
    if (sv_derived_from(key_or_ring, "WEBAUTH_KEYRINGPtr")) {
        WEBAUTH_KEYRING *ring;
        IV tmp = SvIV((SV *) SvRV(key_or_ring));

        ring = INT2PTR(WEBAUTH_KEYRING *, tmp);
        s = webauth_token_create(list, hint, buff, &out_len, out_max, ring);
        iskey = 0;
    } else if (sv_derived_from(key_or_ring, "WEBAUTH_KEYPtr")) {
        WEBAUTH_KEY *key;
        IV tmp = SvIV((SV *) SvRV(key_or_ring));

        key = INT2PTR(WEBAUTH_KEY *, tmp);
        s = webauth_token_create_with_key(list, hint, buff, &out_len,
                                          out_max, key);
        iskey = 1;
    } else
        croak("key_or_ring must be a WEBAUTH_KEYRING or WEBAUTH_KEY");

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


void
webauth_token_parse(buffer, ttl, key_or_ring)
    SV *buffer
    int ttl
    SV *key_or_ring
  PROTOTYPE: $$$
  PPCODE:
    STRLEN n_input;
    char *p_input;
    WEBAUTH_ATTR_LIST *list;
    int s, iskey;
    size_t i;
    HV *hv;
    SV *output = NULL;
    SV *copy = sv_2mortal(newSVsv(buffer));

    p_input = SvPV(copy, n_input);

    if (sv_derived_from(key_or_ring, "WEBAUTH_KEYRINGPtr")) {
        WEBAUTH_KEYRING *ring;
        IV tmp = SvIV((SV *) SvRV(key_or_ring));

        ring = INT2PTR(WEBAUTH_KEYRING *, tmp);
        s = webauth_token_parse(p_input, n_input, ttl, ring, &list);
        iskey = 0;
    } else if (sv_derived_from(key_or_ring, "WEBAUTH_KEYPtr")) {
        WEBAUTH_KEY *key;
        IV tmp = SvIV((SV *) SvRV(key_or_ring));

        key = INT2PTR(WEBAUTH_KEY *,tmp);
        s = webauth_token_parse_with_key(p_input, n_input, ttl, key, &list);
        iskey = 1;
    } else
        croak("key_or_ring must be a WEBAUTH_KEYRING or WEBAUTH_KEY");

    if (s == WA_ERR_NONE) {
        hv = newHV();
        for (i = 0; i < list->num_attrs; i++)
            (void) hv_store(hv, list->attrs[i].name,
                            strlen(list->attrs[i].name),
                            newSVpvn(list->attrs[i].value,
                                     list->attrs[i].length), 0);
        output = sv_2mortal(newRV_noinc((SV *) hv));
        webauth_attr_list_free(list);
    } else
        webauth_croak(iskey ?
                      "webauth_token_parse_with_key" : "webauth_token_parse",
                      s, NULL);
    EXTEND(SP,1);
    PUSHs(output);


void
webauth_krb5_new()
  PROTOTYPE:
  PPCODE:
    WEBAUTH_KRB5_CTXT *ctxt = NULL;
    int s;
    SV *output;

    s = webauth_krb5_new(&ctxt);
    output = sv_newmortal();
    sv_setref_pv(output, "WEBAUTH_KRB5_CTXTPtr", (void*)ctxt);
    if (ctxt == NULL)
        webauth_croak("webauth_krb5_new", WA_ERR_NO_MEM, NULL);
    else if (s != WA_ERR_NONE)
        webauth_croak("webauth_krb5_new", s, ctxt);
    EXTEND(SP,1);
    PUSHs(output);


int
webauth_krb5_error_code(c)
    WEBAUTH_KRB5_CTXT *c
  PROTOTYPE: $
  CODE:
    RETVAL = webauth_krb5_error_code(c);
  OUTPUT:
    RETVAL


char *
webauth_krb5_error_message(c)
    WEBAUTH_KRB5_CTXT *c
  PROTOTYPE: $
  CODE:
    RETVAL = (char *) webauth_krb5_error_message(c);
  OUTPUT:
    RETVAL

void
webauth_krb5_init_via_password(c, name, password, get_principal, keytab, \
                               server_principal, ...)
    WEBAUTH_KRB5_CTXT *c
    char *name
    char *password
    char *get_principal
    char *keytab
    char *server_principal
  PROTOTYPE: $$$$$$;$
  PPCODE:
    char *cred, *server_princ_out;
    int s;

    if (items == 7)
        cred = (char *) SvPV(ST(5), PL_na);
    else
        cred = NULL;
    if (server_principal && *server_principal == '\0')
       server_principal = NULL;
    if (get_principal && *get_principal == '\0')
       get_principal = NULL;
    if (keytab && *keytab == '\0')
       keytab = NULL;

    s = webauth_krb5_init_via_password(c, name, password, get_principal,
                                       keytab, server_principal, cred,
                                       &server_princ_out);
    if (s != WA_ERR_NONE)
        webauth_croak("webauth_krb5_init_via_password", s, c);
    else if (get_principal == NULL || keytab != NULL) {
        SV *out = sv_newmortal();
        sv_setpv(out, server_princ_out);
        EXTEND(SP,1);
        PUSHs(out);
        free(server_princ_out);
    }


void
webauth_krb5_change_password(c, pass, ...)
    WEBAUTH_KRB5_CTXT *c
    char *pass
  PROTOTYPE: $$;$
  PPCODE:
    int s;

    s = webauth_krb5_change_password(c, pass);
    if (s != WA_ERR_NONE)
        webauth_croak("webauth_krb5_change_password", s, c);


void
webauth_krb5_init_via_keytab(c, keytab, server_principal, ...)
    WEBAUTH_KRB5_CTXT *c
    char *keytab
    char *server_principal
  PROTOTYPE: $$$;$
  PPCODE:
    int s;
    char *cred;

    if (items == 4)
        cred = (char *) SvPV(ST(2), PL_na);
    else
        cred = NULL;
    if (server_principal && *server_principal == '\0')
       server_principal = NULL;

    s = webauth_krb5_init_via_keytab(c, keytab, server_principal, cred);
    if (s != WA_ERR_NONE)
        webauth_croak("webauth_krb5_init_via_keytab", s, c);


void
webauth_krb5_init_via_cred(c, cred, ...)
    WEBAUTH_KRB5_CTXT *c
    SV *cred
  PROTOTYPE: $$;$
  PPCODE:
    char *cc;
    char *pcred;
    size_t cred_len;
    int s;

    pcred = SvPV(cred, cred_len);

    if (items==3)
        cc = (char *) SvPV(ST(2), PL_na);
    else
        cc = NULL;
    s = webauth_krb5_init_via_cred(c, pcred, cred_len, cc);
    if (s != WA_ERR_NONE)
        webauth_croak("webauth_krb5_init_via_cred", s, c);


void
webauth_krb5_init_via_cache(c, ...)
    WEBAUTH_KRB5_CTXT *c
  PROTOTYPE: $;$
  PPCODE:
    char *cc;
    int s;

    if (items == 2)
        cc = (char *) SvPV(ST(1), PL_na);
    else
        cc = NULL;
    s = webauth_krb5_init_via_cache(c, cc);
    if (s != WA_ERR_NONE)
        webauth_croak("webauth_krb5_init_via_cache", s, c);


void
webauth_krb5_import_cred(c, cred)
    WEBAUTH_KRB5_CTXT *c
    SV *cred
  PROTOTYPE: $$
  PPCODE:
    char *pticket;
    size_t ticket_len;
    int s;

    pticket = SvPV(cred, ticket_len);
    s = webauth_krb5_import_cred(c, pticket, ticket_len);
    if (s != WA_ERR_NONE)
        webauth_croak("webauth_krb5_import_cred", s, c);


void
webauth_krb5_export_tgt(c)
    WEBAUTH_KRB5_CTXT *c
  PROTOTYPE: $
  PPCODE:
    int s;
    char *tgt;
    size_t tgt_len;
    time_t expiration;

    s = webauth_krb5_export_tgt(c, &tgt, &tgt_len, &expiration);
    if (s == WA_ERR_NONE) {
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


void
webauth_krb5_get_principal(c, local)
    WEBAUTH_KRB5_CTXT *c
    int local
  PROTOTYPE: $$
  PPCODE:
    int s;
    char *princ;

    s = webauth_krb5_get_principal(c, &princ, local);
    if (s == WA_ERR_NONE) {
        SV *out = sv_newmortal();

        sv_setpv(out, princ);
        EXTEND(SP,1);
        PUSHs(out);
        free(princ);
    } else {
        free(princ);
        webauth_croak("webauth_krb5_get_principal", s, c);
    }


void
webauth_krb5_export_ticket(c, princ)
    WEBAUTH_KRB5_CTXT *c
    char *princ
  PROTOTYPE: $$
  PPCODE:
    char *ticket = NULL;
    size_t ticket_len;
    int s;
    time_t expiration;

    s = webauth_krb5_export_ticket(c, princ, &ticket, &ticket_len,
                                   &expiration);
    if (s == WA_ERR_NONE) {
        SV *out = sv_newmortal();

        sv_setpvn(out, ticket, ticket_len);
        free(ticket);
        EXTEND(SP,2);
        PUSHs(out);
        PUSHs(sv_2mortal(newSViv(expiration)));
    } else {
        if (ticket != NULL)
            free(ticket);
        webauth_croak("webauth_krb5_export_ticket", s, c);
    }


void
webauth_krb5_mk_req(c, princ, ...)
    WEBAUTH_KRB5_CTXT *c
    char *princ
  PROTOTYPE: $$;$
  PPCODE:
    char *req, *in_data, *out_data;
    size_t in_len, req_len, out_len;
    int s;

    if (items == 3)
        in_data = SvPV(ST(2), in_len);
    else
        in_data = NULL;

    s = webauth_krb5_mk_req_with_data(c, princ, &req, &req_len, in_data,
                                      in_len, &out_data, &out_len);

    if (s == WA_ERR_NONE) {
        SV *req_out, *data_out;

        req_out = sv_newmortal();
        sv_setpvn(req_out, req, req_len);
        free(req);
        EXTEND(SP, items == 2 ? 1 : 2);
        PUSHs(req_out);
        if (items == 3) {
            data_out = sv_newmortal();
            sv_setpvn(data_out, out_data, out_len);
            free(out_data);
            PUSHs(data_out);
        }
    } else
        webauth_croak("webauth_krb5_mk_req", s, c);


void
webauth_krb5_rd_req(c, request, keytab, server_principal, local, ...)
    WEBAUTH_KRB5_CTXT *c
    SV *request
    char *keytab
    char *server_principal
    int local
  PROTOTYPE: $$$$$;$
  PPCODE:
    char *req, *in_data, *out_data;
    char *client_princ;
    size_t req_len, in_len, out_len;
    int s;

    req = SvPV(request, req_len);

    if (items == 6)
        in_data = SvPV(ST(5), in_len);
    else
        in_data = NULL;
    if (server_principal && *server_principal == '\0')
       server_principal = NULL;

    s = webauth_krb5_rd_req_with_data(c, req, req_len, keytab,
                                      server_principal, NULL, &client_princ,
                                      local, in_data, in_len, &out_data,
                                      &out_len);

    if (s == WA_ERR_NONE) {
        SV *out = sv_newmortal();

        sv_setpv(out, client_princ);
        free(client_princ);
        EXTEND(SP, items == 5 ? 1 : 2);
        PUSHs(out);
        if (items == 6) {
            SV *data_out = sv_newmortal();

            sv_setpvn(data_out, out_data, out_len);
            free(out_data);
            PUSHs(data_out);
        }
    } else {
        free(client_princ);
        webauth_croak("webauth_krb5_rd_req", s, c);
    }


void
webauth_krb5_keep_cred_cache(c)
    WEBAUTH_KRB5_CTXT *c
  PROTOTYPE: $
  PPCODE:
    int s;

    s = webauth_krb5_keep_cred_cache(c);
    if (s != WA_ERR_NONE)
        webauth_croak("webauth_krb5_rd_req", s, c);


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
