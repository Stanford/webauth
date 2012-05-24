/* -*- c -*-
 * Perl XS bindings for the WebAuth library.
 *
 * This is an XS source file, suitable for processing by xsubpp, that
 * generates Perl bindings for the libwebauth library.
 *
 * Currently, both the library API and this set of bindings leave a lot to be
 * desired.  They could be much more object-oriented than they currently are,
 * and the library is very low-level.  There is some work done on conversion
 * to a more object-oriented approach, but it's very incomplete and currently
 * only includes WebAuth::Keyring and closely-related classes.
 *
 * All abnormal errors are handled as exceptions, generated via webauth_croak,
 * rather than through error returns.
 *
 * Wrap all CODE and PPCODE segments in this file longer than a single line in
 * braces to reduce Emacs's c-mode confusion when trying to understand XS
 * constructs.
 *
 * Written by Roland Schemers
 * Copyright 2003, 2005, 2006, 2008, 2009, 2010, 2011, 2012
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

/* We cannot include config.h here because it conflicts with Perl. */
#include <portable/apr.h>

#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#include <webauth.h>
#include <webauth/basic.h>
#include <webauth/keys.h>
#include <webauth/tokens.h>

/*
 * These typedefs are needed for xsubpp to work its magic with type
 * translation to Perl objects.
 */
typedef struct webauth_context *                WebAuth;
typedef const struct webauth_key *              WebAuth__Key;
typedef const struct webauth_keyring_entry *    WebAuth__KeyringEntry;

/*
 * For WebAuth::Keyring, we need to stash a copy of the parent context
 * somewhere so that we don't require it as an argument to all methods.
 */
typedef struct {
    struct webauth_context *ctx;
    struct webauth_keyring *ring;
} *WebAuth__Keyring;

/* Used to generate the Perl glue for WebAuth constants. */
#define IV_CONST(X) newCONSTSUB(stash, #X, newSViv(X))
#define STR_CONST(X) newCONSTSUB(stash, #X, newSVpv(X, 0))

/*
 * Encoding and decoding magic for tokens.
 *
 * There are significant memory management challenges for how to handle the
 * token structs as Perl objects directly.  (For example, the structs
 * allocated via webauth_token_decode would be allocated entirely differently
 * than values set from Perl.)  It's therefore easier to have the Perl
 * expression of the token structs be Perl hash tables, which we can bless and
 * wrap with getters and setters written in Perl instead of XS.
 *
 * In order to avoid vast amounts of duplicate code, we define coding tables
 * for each token.  This maps the attribute names in the form of the hash keys
 * used in the Perl object to offsets into the relevant token struct and types
 * of the C data structure.  We can then use some (scary) C code to handle the
 * transcoding from C structs to Perl objects generically for all token types.
 *
 * All TYPE_DATA entries in the table must be followed by TYPE_DATALEN
 * entries.
 */
enum token_mapping_type {
    TYPE_STRING,
    TYPE_TIME,
    TYPE_DATA,
    TYPE_DATALEN,
    TYPE_ULONG
};
struct token_mapping {
    const char *key;
    size_t offset;
    enum token_mapping_type type;
};

/* Used to make the tables more readable. */
#define M(s, n, t) { (#n), offsetof(struct s, n), TYPE_ ## t }

/* Used to store or extract data from the struct. */
#define DATA_STRING(d, o)       *(const char **)  ((char *) (d) + (o))
#define DATA_TIME(d, o)         *(time_t *)       ((char *) (d) + (o))
#define DATA_DATA(d, o)         *(const void **)  ((char *) (d) + (o))
#define DATA_DATALEN(d, o)      *(size_t *)       ((char *) (d) + (o))
#define DATA_ULONG(d, o)        *(unsigned long *)((char *) (d) + (o))

/* App tokens. */
struct token_mapping token_mapping_app[] = {
    M(webauth_token_app, subject,         STRING),
    M(webauth_token_app, last_used,       TIME),
    M(webauth_token_app, session_key,     DATA),
    M(webauth_token_app, session_key_len, DATALEN),
    M(webauth_token_app, initial_factors, STRING),
    M(webauth_token_app, session_factors, STRING),
    M(webauth_token_app, loa,             ULONG),
    M(webauth_token_app, creation,        TIME),
    M(webauth_token_app, expiration,      TIME),
    { NULL, 0, 0 }
};

/* Cred tokens. */
struct token_mapping token_mapping_cred[] = {
    M(webauth_token_cred, subject,    STRING),
    M(webauth_token_cred, type,       STRING),
    M(webauth_token_cred, service,    STRING),
    M(webauth_token_cred, data,       DATA),
    M(webauth_token_cred, data_len,   DATALEN),
    M(webauth_token_cred, creation,   TIME),
    M(webauth_token_cred, expiration, TIME),
    { NULL, 0, 0 }
};

/* Error tokens. */
struct token_mapping token_mapping_error[] = {
    M(webauth_token_error, code,     ULONG),
    M(webauth_token_error, message,  STRING),
    M(webauth_token_error, creation, TIME),
    { NULL, 0, 0 }
};

/* Id tokens. */
struct token_mapping token_mapping_id[] = {
    M(webauth_token_id, subject,         STRING),
    M(webauth_token_id, auth,            STRING),
    M(webauth_token_id, auth_data,       DATA),
    M(webauth_token_id, auth_data_len,   DATALEN),
    M(webauth_token_id, initial_factors, STRING),
    M(webauth_token_id, session_factors, STRING),
    M(webauth_token_id, loa,             ULONG),
    M(webauth_token_id, creation,        TIME),
    M(webauth_token_id, expiration,      TIME),
    { NULL, 0, 0 }
};

/* Login tokens. */
struct token_mapping token_mapping_login[] = {
    M(webauth_token_login, username, STRING),
    M(webauth_token_login, password, STRING),
    M(webauth_token_login, otp,      STRING),
    M(webauth_token_login, creation, TIME),
    { NULL, 0, 0 }
};

/* Proxy tokens. */
struct token_mapping token_mapping_proxy[] = {
    M(webauth_token_proxy, subject,          STRING),
    M(webauth_token_proxy, type,             STRING),
    M(webauth_token_proxy, webkdc_proxy,     DATA),
    M(webauth_token_proxy, webkdc_proxy_len, DATALEN),
    M(webauth_token_proxy, initial_factors,  STRING),
    M(webauth_token_proxy, session_factors,  STRING),
    M(webauth_token_proxy, loa,              ULONG),
    M(webauth_token_proxy, creation,         TIME),
    M(webauth_token_proxy, expiration,       TIME),
    { NULL, 0, 0 }
};

/* Request tokens. */
struct token_mapping token_mapping_request[] = {
    M(webauth_token_request, type,            STRING),
    M(webauth_token_request, auth,            STRING),
    M(webauth_token_request, proxy_type,      STRING),
    M(webauth_token_request, state,           DATA),
    M(webauth_token_request, state_len,       DATALEN),
    M(webauth_token_request, return_url,      STRING),
    M(webauth_token_request, options,         STRING),
    M(webauth_token_request, initial_factors, STRING),
    M(webauth_token_request, session_factors, STRING),
    M(webauth_token_request, loa,             ULONG),
    M(webauth_token_request, command,         STRING),
    M(webauth_token_request, creation,        TIME),
    { NULL, 0, 0 }
};

/* WebKDC proxy tokens. */
struct token_mapping token_mapping_webkdc_proxy[] = {
    M(webauth_token_webkdc_proxy, subject,         STRING),
    M(webauth_token_webkdc_proxy, proxy_type,      STRING),
    M(webauth_token_webkdc_proxy, proxy_subject,   STRING),
    M(webauth_token_webkdc_proxy, data,            DATA),
    M(webauth_token_webkdc_proxy, data_len,        DATALEN),
    M(webauth_token_webkdc_proxy, initial_factors, STRING),
    M(webauth_token_webkdc_proxy, loa,             ULONG),
    M(webauth_token_webkdc_proxy, creation,        TIME),
    M(webauth_token_webkdc_proxy, expiration,      TIME),
    { NULL, 0, 0 }
};

/* WebKDC service tokens. */
struct token_mapping token_mapping_webkdc_service[] = {
    M(webauth_token_webkdc_service, subject,         STRING),
    M(webauth_token_webkdc_service, session_key,     DATA),
    M(webauth_token_webkdc_service, session_key_len, DATALEN),
    M(webauth_token_webkdc_service, creation,        TIME),
    M(webauth_token_webkdc_service, expiration,      TIME),
    { NULL, 0, 0 }
};


/*
 * Decode a token into a Perl hash.  This function doesn't know what type of
 * token is being decoded; it just takes an array of struct token_mapping, a
 * pointer to the token struct, and a Perl HV, and uses the rules in
 * token_mapping to move data into the HV.
 */
static void
map_token_to_hash(struct token_mapping mapping[], const void *token, HV *hash)
{
    size_t i, length;
    struct token_mapping *map;
    SV *value;
    const char *string;
    const void *data;
    unsigned long number;

    for (i = 0; mapping[i].key != NULL; i++) {
        map = &mapping[i];
        value = NULL;
        switch (map->type) {
        case TYPE_STRING:
            string = DATA_STRING(token, map->offset);
            if (string != NULL)
                value = newSVpv(string, 0);
            break;
        case TYPE_TIME:
            number = DATA_TIME(token, map->offset);
            if (number != 0)
                value = newSViv(number);
            break;
        case TYPE_DATA:
            data = DATA_DATA(token, map->offset);
            if (data != NULL) {
                length = DATA_DATALEN(token, mapping[i + 1].offset);
                value = newSVpvn(data, length);
            }
            break;
        case TYPE_DATALEN:
            /* Handled as part of TYPE_DATA. */
            break;
        case TYPE_ULONG:
            number = DATA_ULONG(token, map->offset);
            if (number != 0)
                value = newSViv(DATA_ULONG(token, map->offset));
            break;
        }
        if (value != NULL)
            if (hv_store(hash, map->key, strlen(map->key), value, 0) == NULL)
                croak("cannot store %s in hash", map->key);
    }
}


/*
 * Encode a Perl hash into a token struct.  This function doesn't know what
 * type of token is being encoded; it just takes an array of struct
 * token_mapping, a pointer to the token struct, and a Perl HV, and uses the
 * rules in token_mapping to move data from the HV into the struct.
 *
 * This does not check for attributes in the HV that don't correspond to valid
 * members of the struct.
 */
static void
map_hash_to_token(struct token_mapping mapping[], HV *hash, const void *token)
{
    size_t i;
    struct token_mapping *map;
    SV **value;
    STRLEN length;

    for (i = 0; mapping[i].key != NULL; i++) {
        map = &mapping[i];
        value = hv_fetch(hash, map->key, strlen(map->key), 0);
        if (value == NULL)
            continue;
        switch (map->type) {
        case TYPE_STRING:
            DATA_STRING(token, map->offset) = SvPV_nolen(*value);
            break;
        case TYPE_TIME:
            DATA_TIME(token, map->offset) = SvIV(*value);
            break;
        case TYPE_DATA:
            DATA_DATA(token, map->offset) = SvPV(*value, length);
            DATA_DATALEN(token, mapping[i + 1].offset) = length;
            break;
        case TYPE_DATALEN:
            /* Handled as part of TYPE_DATA. */
            break;
        case TYPE_ULONG:
            DATA_ULONG(token, map->offset) = SvIV(*value);
            break;
        }
    }
}


/*
 * Turn a WebAuth error into a Perl exception.
 */
static void
webauth_croak(struct webauth_context *ctx, const char *detail, int s,
              WEBAUTH_KRB5_CTXT *c)
{
    HV *hv;
    SV *rv;

    hv = newHV();
    (void) hv_store(hv, "status", 6, newSViv(s), 0);
    (void) hv_store(hv, "message", 7,
                    newSVpv(webauth_error_message(ctx, s), 0), 0);
    if (detail != NULL)
        (void) hv_store(hv, "detail", 6, newSVpv(detail, 0), 0);
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
    rv = newRV_noinc((SV *) hv);
    sv_bless(rv, gv_stashpv("WebAuth::Exception", TRUE));
    sv_setsv(get_sv("@", TRUE), sv_2mortal(rv));
    croak(Nullch);
}


/* XS code below this point. */

MODULE = WebAuth        PACKAGE = WebAuth    PREFIX = webauth_

PROTOTYPES: ENABLE


# Generate all the constant subs for all the exported WebAuth constants.
BOOT:
{
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
    IV_CONST(WA_ERR_INVALID);

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
    IV_CONST(WA_PEC_MULTIFACTOR_REQUIRED);
    IV_CONST(WA_PEC_MULTIFACTOR_UNAVAILABLE);
    IV_CONST(WA_PEC_LOGIN_REJECTED);
    IV_CONST(WA_PEC_LOA_UNAVAILABLE);

    IV_CONST(WA_KEY_AES);
    IV_CONST(WA_AES_128);
    IV_CONST(WA_AES_192);
    IV_CONST(WA_AES_256);

    STR_CONST(WA_TK_APP_STATE);
    STR_CONST(WA_TK_COMMAND);
    STR_CONST(WA_TK_CRED_DATA);
    STR_CONST(WA_TK_CRED_SERVICE);
    STR_CONST(WA_TK_CRED_TYPE);
    STR_CONST(WA_TK_CREATION_TIME);
    STR_CONST(WA_TK_ERROR_CODE);
    STR_CONST(WA_TK_ERROR_MESSAGE);
    STR_CONST(WA_TK_EXPIRATION_TIME);
    STR_CONST(WA_TK_INITIAL_FACTORS);
    STR_CONST(WA_TK_SESSION_KEY);
    STR_CONST(WA_TK_LOA);
    STR_CONST(WA_TK_LASTUSED_TIME);
    STR_CONST(WA_TK_OTP);
    STR_CONST(WA_TK_PASSWORD);
    STR_CONST(WA_TK_PROXY_DATA);
    STR_CONST(WA_TK_PROXY_SUBJECT);
    STR_CONST(WA_TK_PROXY_TYPE);
    STR_CONST(WA_TK_REQUEST_OPTIONS);
    STR_CONST(WA_TK_REQUESTED_TOKEN_TYPE);
    STR_CONST(WA_TK_RETURN_URL);
    STR_CONST(WA_TK_SUBJECT);
    STR_CONST(WA_TK_SUBJECT_AUTH);
    STR_CONST(WA_TK_SUBJECT_AUTH_DATA);
    STR_CONST(WA_TK_SESSION_FACTORS);
    STR_CONST(WA_TK_TOKEN_TYPE);
    STR_CONST(WA_TK_USERNAME);
    STR_CONST(WA_TK_WEBKDC_TOKEN);
}


WebAuth
new(class)
    const char *class
  PROTOTYPE: ;$
  PREINIT:
    struct webauth_context *ctx;
    int status;
  CODE:
{
    status = webauth_context_init(&ctx, NULL);
    if (status != WA_ERR_NONE)
        webauth_croak(NULL, "webauth_context_init", status, NULL);
    RETVAL = ctx;
}
  OUTPUT:
    RETVAL


void
DESTROY(self)
   WebAuth self
 CODE:
{
   if (self != NULL)
       webauth_context_free(self);
}


const char *
webauth_error_message(self, status)
    WebAuth self
    int status
  PROTOTYPE: $$
  CODE:
    RETVAL = webauth_error_message(self, status);
  OUTPUT:
    RETVAL


void
webauth_base64_encode(self, input)
    WebAuth self
    SV *input
  PROTOTYPE: $$
  CODE:
{
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
        webauth_croak(NULL, "webauth_base64_encode", s, NULL);

    SvCUR_set(ST(0), out_len);
    SvPOK_only(ST(0));
}


void
webauth_base64_decode(self, input)
    WebAuth self
    SV * input
  PROTOTYPE: $$
  PPCODE:
{
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
       webauth_croak(NULL, "webauth_base64_decode", s, NULL);
    }

    EXTEND(SP,1);
    output = sv_newmortal();
    sv_setpvn(output, buff, out_len);
    PUSHs(output);
    if (buff != NULL)
        free(buff);
}


void
webauth_hex_encode(self, input)
    WebAuth self
    SV * input
  PROTOTYPE: $$
  CODE:
{
    STRLEN n_input;
    size_t out_len, out_max;
    int s;
    char *p_input;

    p_input = SvPV(input, n_input);
    out_max = webauth_hex_encoded_length(n_input);

    ST(0) = sv_2mortal(NEWSV(0, out_max));
    s = webauth_hex_encode(p_input, n_input, SvPVX(ST(0)), &out_len, out_max);
    if (s != WA_ERR_NONE)
        webauth_croak(NULL, "webauth_hex_encode", s, NULL);
    SvCUR_set(ST(0), out_len);
    SvPOK_only(ST(0));
}


void
webauth_hex_decode(self, input)
    WebAuth self
    SV * input
  PROTOTYPE: $
  PPCODE:
{
    STRLEN n_input;
    size_t out_len, out_max;
    int s;
    char *p_input, *buff;
    SV *output;
    buff = NULL;

    p_input = SvPV(input, n_input);
    s = webauth_hex_decoded_length(n_input, &out_max);
    if (s != WA_ERR_NONE)
        webauth_croak(NULL, "webauth_hex_decoded_length", s, NULL);
    buff = malloc(out_max);
    if (buff == NULL)
        croak("can't create buffer");
    s = webauth_hex_decode(p_input, n_input, buff, &out_len, out_max);
    if (s != WA_ERR_NONE) {
        if (buff != NULL)
            free(buff);
        webauth_croak(NULL, "webauth_hex_decode", s, NULL);
    }

    EXTEND(SP,1);
    output = sv_newmortal();
    sv_setpvn(output, buff, out_len);
    PUSHs(output);

    if (buff != NULL)
        free(buff);
}


void
webauth_attrs_encode(self, attrs)
    WebAuth self
    SV *attrs
  PROTOTYPE: $$
  PPCODE:
{
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
        webauth_croak(NULL, "webauth_attrs_encode", s, NULL);
    else {
        SvCUR_set(output, out_len);
        SvPOK_only(output);
    }

    EXTEND(SP,1);
    PUSHs(output);
}


void
webauth_attrs_decode(self, buffer)
    WebAuth self
    SV *buffer
  PROTOTYPE: $$
  PPCODE:
{
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
        webauth_croak(NULL, "webauth_attrs_decode", s, NULL);

    hv = newHV();
    for (i = 0; i < list->num_attrs; i++)
        (void) hv_store(hv, list->attrs[i].name, strlen(list->attrs[i].name),
                        newSVpvn(list->attrs[i].value, list->attrs[i].length),
                        0);
    webauth_attr_list_free(list);
    output = sv_2mortal(newRV_noinc((SV*)hv));
    EXTEND(SP,1);
    PUSHs(output);
}


WebAuth::Key
key_create(self, type, size, key_material = NULL)
    WebAuth self
    enum webauth_key_type type
    enum webauth_key_size size
    const unsigned char *key_material
  PROTOTYPE: $$$;$
  PREINIT:
    struct webauth_key *key;
    int status;
  CODE:
{
    status = webauth_key_create(self, type, size, key_material, &key);
    if (status != WA_ERR_NONE)
        webauth_croak(self, "webauth_key_create", status, NULL);
    RETVAL = key;
}
  OUTPUT:
    RETVAL


WebAuth::Keyring
keyring_new(self, ks)
    WebAuth self
    SV *ks
  PROTOTYPE: $$
  PREINIT:
    WebAuth__Keyring ring;
  CODE:
{
    ring = malloc(sizeof(WebAuth__Keyring));
    if (ring == NULL)
        croak("cannot allocate memory");
    if (sv_isobject(ks) && sv_derived_from(ks, "WebAuth::Key")) {
        struct webauth_key *key;

        key = INT2PTR(struct webauth_key *, SvIV((SV *) SvRV(ks)));
        ring->ring = webauth_keyring_from_key(self, key);
    } else {
        ring->ring = webauth_keyring_new(self, SvIV(ks));
    }
    ring->ctx = self;
    RETVAL = ring;
}
  OUTPUT:
    RETVAL


WebAuth::Keyring
keyring_read(self, file)
    WebAuth self
    const char *file
  PROTOTYPE: $$
  PREINIT:
    WebAuth__Keyring ring;
    int status;
  CODE:
{
    ring = malloc(sizeof(WebAuth__Keyring));
    if (ring == NULL)
        croak("cannot allocate memory");
    status = webauth_keyring_read(self, file, &ring->ring);
    if (status != WA_ERR_NONE)
        webauth_croak(self, "webauth_keyring_read", status, NULL);
    ring->ctx = self;
    RETVAL = ring;
}
  OUTPUT:
    RETVAL


SV *
token_decode(self, input, ring)
    WebAuth self
    SV *input
    WebAuth::Keyring ring
  PROTOTYPE: $$$
  PREINIT:
    const char *encoded;
    struct webauth_token *token;
    int status;
    HV *hash;
    SV *object;
  CODE:
{
    encoded = SvPV_nolen(input);
    status = webauth_token_decode(self, WA_TOKEN_ANY, encoded, ring->ring,
                                  &token);
    if (status != WA_ERR_NONE)
        webauth_croak(self, "webauth_token_decode", status, NULL);
    hash = newHV();
    object = newRV_noinc((SV *) hash);
    switch (token->type) {
    case WA_TOKEN_APP:
        sv_bless(object, gv_stashpv("WebAuth::Token::App", GV_ADD));
        map_token_to_hash(token_mapping_app, &token->token.app, hash);
        break;
    case WA_TOKEN_CRED:
        sv_bless(object, gv_stashpv("WebAuth::Token::Cred", GV_ADD));
        map_token_to_hash(token_mapping_cred, &token->token.cred, hash);
        break;
    case WA_TOKEN_ERROR:
        sv_bless(object, gv_stashpv("WebAuth::Token::Error", GV_ADD));
        map_token_to_hash(token_mapping_error, &token->token.error, hash);
        break;
    case WA_TOKEN_ID:
        sv_bless(object, gv_stashpv("WebAuth::Token::Id", GV_ADD));
        map_token_to_hash(token_mapping_id, &token->token.id, hash);
        break;
    case WA_TOKEN_LOGIN:
        sv_bless(object, gv_stashpv("WebAuth::Token::Login", GV_ADD));
        map_token_to_hash(token_mapping_login, &token->token.login, hash);
        break;
    case WA_TOKEN_PROXY:
        sv_bless(object, gv_stashpv("WebAuth::Token::Proxy", GV_ADD));
        map_token_to_hash(token_mapping_proxy, &token->token.proxy, hash);
        break;
    case WA_TOKEN_REQUEST:
        sv_bless(object, gv_stashpv("WebAuth::Token::Request", GV_ADD));
        map_token_to_hash(token_mapping_request, &token->token.request, hash);
        break;
    case WA_TOKEN_WEBKDC_PROXY:
        sv_bless(object, gv_stashpv("WebAuth::Token::WebKDCProxy", GV_ADD));
        map_token_to_hash(token_mapping_webkdc_proxy,
                          &token->token.webkdc_proxy, hash);
        break;
    case WA_TOKEN_WEBKDC_SERVICE:
        sv_bless(object, gv_stashpv("WebAuth::Token::WebKDCService", GV_ADD));
        map_token_to_hash(token_mapping_webkdc_service,
                          &token->token.webkdc_service, hash);
        break;
    case WA_TOKEN_UNKNOWN:
    case WA_TOKEN_ANY:
    default:
        croak("unknown token type %d", token->type);
        break;
    }

    /*
     * Stash a reference to the context in the generated hash.  XS will have
     * automatically unwrapped a struct webauth_context from an SV for us in
     * the preamble, but we want to reuse the SV used by Perl, so store the
     * contents of our first argument directly.
     */
    if (hv_stores(hash, "ctx", ST(0)) == NULL)
        croak("cannot store context in hash");
    SvREFCNT_inc(ST(0));
    RETVAL = object;
}
  OUTPUT:
    RETVAL


void
webauth_krb5_new(self)
    WebAuth self
  PROTOTYPE: $
  PPCODE:
{
    WEBAUTH_KRB5_CTXT *ctxt = NULL;
    int s;
    SV *output;

    s = webauth_krb5_new(&ctxt);
    output = sv_newmortal();
    sv_setref_pv(output, "WEBAUTH_KRB5_CTXTPtr", (void*)ctxt);
    if (ctxt == NULL)
        webauth_croak(NULL, "webauth_krb5_new", WA_ERR_NO_MEM, NULL);
    else if (s != WA_ERR_NONE)
        webauth_croak(NULL, "webauth_krb5_new", s, ctxt);
    EXTEND(SP,1);
    PUSHs(output);
}


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
{
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
        webauth_croak(NULL, "webauth_krb5_init_via_password", s, c);
    else if (get_principal == NULL || keytab != NULL) {
        SV *out = sv_newmortal();
        sv_setpv(out, server_princ_out);
        EXTEND(SP,1);
        PUSHs(out);
        free(server_princ_out);
    }
}


void
webauth_krb5_change_password(c, pass, ...)
    WEBAUTH_KRB5_CTXT *c
    char *pass
  PROTOTYPE: $$;$
  PPCODE:
{
    int s;

    s = webauth_krb5_change_password(c, pass);
    if (s != WA_ERR_NONE)
        webauth_croak(NULL, "webauth_krb5_change_password", s, c);
}


void
webauth_krb5_init_via_keytab(c, keytab, server_principal, ...)
    WEBAUTH_KRB5_CTXT *c
    char *keytab
    char *server_principal
  PROTOTYPE: $$$;$
  PPCODE:
{
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
        webauth_croak(NULL, "webauth_krb5_init_via_keytab", s, c);
}


void
webauth_krb5_init_via_cred(c, cred, ...)
    WEBAUTH_KRB5_CTXT *c
    SV *cred
  PROTOTYPE: $$;$
  PPCODE:
{
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
        webauth_croak(NULL, "webauth_krb5_init_via_cred", s, c);
}


void
webauth_krb5_init_via_cache(c, ...)
    WEBAUTH_KRB5_CTXT *c
  PROTOTYPE: $;$
  PPCODE:
{
    char *cc;
    int s;

    if (items == 2)
        cc = (char *) SvPV(ST(1), PL_na);
    else
        cc = NULL;
    s = webauth_krb5_init_via_cache(c, cc);
    if (s != WA_ERR_NONE)
        webauth_croak(NULL, "webauth_krb5_init_via_cache", s, c);
}


void
webauth_krb5_import_cred(c, cred)
    WEBAUTH_KRB5_CTXT *c
    SV *cred
  PROTOTYPE: $$
  PPCODE:
{
    char *pticket;
    size_t ticket_len;
    int s;

    pticket = SvPV(cred, ticket_len);
    s = webauth_krb5_import_cred(c, pticket, ticket_len);
    if (s != WA_ERR_NONE)
        webauth_croak(NULL, "webauth_krb5_import_cred", s, c);
}


void
webauth_krb5_export_tgt(c)
    WEBAUTH_KRB5_CTXT *c
  PROTOTYPE: $
  PPCODE:
{
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
        webauth_croak(NULL, "webauth_krb5_export_tgt", s, c);
    }
}


void
webauth_krb5_get_principal(c, local)
    WEBAUTH_KRB5_CTXT *c
    int local
  PROTOTYPE: $$
  PPCODE:
{
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
        webauth_croak(NULL, "webauth_krb5_get_principal", s, c);
    }
}


void
webauth_krb5_export_ticket(c, princ)
    WEBAUTH_KRB5_CTXT *c
    char *princ
  PROTOTYPE: $$
  PPCODE:
{
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
        webauth_croak(NULL, "webauth_krb5_export_ticket", s, c);
    }
}


void
webauth_krb5_mk_req(c, princ, ...)
    WEBAUTH_KRB5_CTXT *c
    char *princ
  PROTOTYPE: $$;$
  PPCODE:
{
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
        webauth_croak(NULL, "webauth_krb5_mk_req", s, c);
}


void
webauth_krb5_rd_req(c, request, keytab, server_principal, local, ...)
    WEBAUTH_KRB5_CTXT *c
    SV *request
    char *keytab
    char *server_principal
    int local
  PROTOTYPE: $$$$$;$
  PPCODE:
{
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
        webauth_croak(NULL, "webauth_krb5_rd_req", s, c);
    }
}


void
webauth_krb5_keep_cred_cache(c)
    WEBAUTH_KRB5_CTXT *c
  PROTOTYPE: $
  PPCODE:
{
    int s;

    s = webauth_krb5_keep_cred_cache(c);
    if (s != WA_ERR_NONE)
        webauth_croak(NULL, "webauth_krb5_rd_req", s, c);
}


MODULE = WebAuth  PACKAGE = WebAuth::Key

enum webauth_key_type
type(self)
    WebAuth::Key self
  PROTOTYPE: $
  CODE:
    RETVAL = self->type;
  OUTPUT:
    RETVAL

enum webauth_key_size
length(self)
    WebAuth::Key self
  PROTOTYPE: $
  CODE:
    RETVAL = self->length;
  OUTPUT:
    RETVAL

SV *
data(self)
    WebAuth::Key self
  PROTOTYPE: $
  CODE:
    RETVAL = newSVpvn((const void *) self->data, self->length);
  OUTPUT:
    RETVAL


MODULE = WebAuth  PACKAGE = WebAuth::Keyring

void
DESTROY(self)
    WebAuth::Keyring self
  PROTOTYPE: $
  CODE:
    free(self);


void
add(self, creation, valid_after, key)
    WebAuth::Keyring self
    time_t creation
    time_t valid_after
    WebAuth::Key key
  PROTOTYPE: $$$$
  PREINIT:
    int s;
  PPCODE:
{
    webauth_keyring_add(self->ctx, self->ring, creation, valid_after, key);
    XSRETURN_YES;
}


WebAuth::Key
best_key(self, usage, hint)
    WebAuth::Keyring self
    enum webauth_key_usage usage
    time_t hint
  PROTOTYPE: $$$
  PREINIT:
    const struct webauth_key *key;
    int s;
  CODE:
{
    s = webauth_keyring_best_key(self->ctx, self->ring, usage, hint, &key);
    if (s == WA_ERR_NONE)
        RETVAL = key;
    else if (s == WA_ERR_NOT_FOUND)
        XSRETURN_UNDEF;
    else
        webauth_croak(self->ctx, "webauth_keyring_best_key", s, NULL);
}
  OUTPUT:
    RETVAL


void
entries(self)
    WebAuth::Keyring self
  PROTOTYPE: $
  PREINIT:
    struct webauth_keyring *ring;
  PPCODE:
{
    ring = self->ring;
    if (GIMME_V == G_ARRAY) {
        struct webauth_keyring_entry *e;
        SV *entry;
        size_t i;

        for (i = 0; i < (size_t) ring->entries->nelts; i++) {
            e = &APR_ARRAY_IDX(ring->entries, i, struct webauth_keyring_entry);
            entry = sv_newmortal();
            sv_setref_pv(entry, "WebAuth::KeyringEntry", e);
            SvREADONLY_on(entry);
            XPUSHs(entry);
        }
    } else {
        ST(0) = newSViv(ring->entries->nelts);
        sv_2mortal(ST(0));
        XSRETURN(1);
    }
}


void
remove(self, n)
    WebAuth::Keyring self
    size_t n
  PROTOTYPE: $$
  PREINIT:
    int s;
  PPCODE:
{
    s = webauth_keyring_remove(self->ctx, self->ring, n);
    if (s != WA_ERR_NONE)
        webauth_croak(self->ctx, "webauth_keyring_remove", s, NULL);
    XSRETURN_YES;
}


void
write(self, path)
    WebAuth::Keyring self
    char *path
  PROTOTYPE: $$
  PREINIT:
    int s;
  PPCODE:
{
    s = webauth_keyring_write(self->ctx, self->ring, path);
    if (s != WA_ERR_NONE)
        webauth_croak(self->ctx, "webauth_keyring_write_file", s, NULL);
    XSRETURN_YES;
}


MODULE = WebAuth        PACKAGE = WebAuth::KeyringEntry

time_t
creation(self)
    WebAuth::KeyringEntry self
  PROTOTYPE: $
  CODE:
    RETVAL = self->creation;
  OUTPUT:
    RETVAL


time_t
valid_after(self)
    WebAuth::KeyringEntry self
  PROTOTYPE: $
  CODE:
    RETVAL = self->valid_after;
  OUTPUT:
    RETVAL


WebAuth::Key
key(self)
    WebAuth::KeyringEntry self
  PROTOTYPE: $
  CODE:
    RETVAL = self->key;
  OUTPUT:
    RETVAL


MODULE = WebAuth        PACKAGE = WebAuth::Token

const char *
encode(self, ring)
    SV *self
    WebAuth::Keyring ring
  PROTOTYPE: $$
  PREINIT:
    HV *hash;
    SV **ctx_sv;
    IV ctx_iv;
    struct webauth_context *ctx;
    struct webauth_token token;
    int status;
    const char *output;
  CODE:
{
    if (!sv_derived_from(self, "WebAuth::Token"))
        croak("self is not of type WebAuth::Token");
    hash = (HV *) SvRV(self);

    /*
     * Pull the context from the hash.  Our typemap wraps the context by
     * storing it as the IV of the scalar, so we undo that wrapping here.
     */
    ctx_sv = hv_fetch(hash, "ctx", strlen("ctx"), 0);
    if (ctx_sv == NULL)
        croak("no WebAuth context in WebAuth::Token object");
    ctx_iv = SvIV((SV *) SvRV(*ctx_sv));
    ctx = INT2PTR(struct webauth_context *, ctx_iv);

    /* Copy our hash contents to the appropriate struct. */
    memset(&token, 0, sizeof(token));
    if (sv_derived_from(self, "WebAuth::Token::App")) {
        token.type = WA_TOKEN_APP;
        map_hash_to_token(token_mapping_app, hash, &token.token.app);
    } else if (sv_derived_from(self, "WebAuth::Token::Cred")) {
        token.type = WA_TOKEN_CRED;
        map_hash_to_token(token_mapping_cred, hash, &token.token.cred);
    } else if (sv_derived_from(self, "WebAuth::Token::Error")) {
        token.type = WA_TOKEN_ERROR;
        map_hash_to_token(token_mapping_error, hash, &token.token.error);
    } else if (sv_derived_from(self, "WebAuth::Token::Id")) {
        token.type = WA_TOKEN_ID;
        map_hash_to_token(token_mapping_id, hash, &token.token.id);
    } else if (sv_derived_from(self, "WebAuth::Token::Login")) {
        token.type = WA_TOKEN_LOGIN;
        map_hash_to_token(token_mapping_login, hash, &token.token.login);
    } else if (sv_derived_from(self, "WebAuth::Token::Proxy")) {
        token.type = WA_TOKEN_PROXY;
        map_hash_to_token(token_mapping_proxy, hash, &token.token.proxy);
    } else if (sv_derived_from(self, "WebAuth::Token::Request")) {
        token.type = WA_TOKEN_REQUEST;
        map_hash_to_token(token_mapping_request, hash, &token.token.request);
    } else if (sv_derived_from(self, "WebAuth::Token::WebKDCProxy")) {
        token.type = WA_TOKEN_WEBKDC_PROXY;
        map_hash_to_token(token_mapping_webkdc_proxy, hash,
                          &token.token.webkdc_proxy);
    } else if (sv_derived_from(self, "WebAuth::Token::WebKDCService")) {
        token.type = WA_TOKEN_WEBKDC_SERVICE;
        map_hash_to_token(token_mapping_webkdc_service, hash,
                          &token.token.webkdc_service);
    } else {
        croak("self is not a supported WebAuth::Token::* object");
    }

    /* Do the actual encoding. */
    status = webauth_token_encode(ctx, &token, ring->ring, &output);
    if (status != WA_ERR_NONE)
        webauth_croak(ctx, "webauth_token_encode", status, NULL);
    RETVAL = output;
}
  OUTPUT:
    RETVAL


MODULE = WebAuth        PACKAGE = WEBAUTH_KRB5_CTXTPtr  PREFIX = webauth_

void
webauth_DESTROY(ctxt)
    WEBAUTH_KRB5_CTXT *ctxt
  CODE:
    webauth_krb5_free(ctxt);
