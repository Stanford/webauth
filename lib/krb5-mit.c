/*
 * MIT Kerberos interface for WebAuth.
 *
 * This file is *included* (via the preprocessor) in krb5.c for systems that
 * use MIT Kerberos.  If you make any changes here, you probably also need to
 * make a corresponding change to krb5-heimdal.c for systems with Heimdal.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Based on the original Kerberos support code by Roland Schemers
 * Copyright 2002, 2003, 2006, 2009, 2010, 2012
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */


/*
 * Take a single Kerberos credential and serialize it into a buffer, using the
 * encoding required for putting it into tokens.  output will be a pointer to
 * newly allocated memory, and length will be set to the encoded length.
 * expiration will be set to the expiration time of the ticket.  Returns a
 * WA_ERR code.
 */
static int
encode_creds(struct webauth_context *ctx, struct webauth_krb5 *kc,
             krb5_creds *creds, void **output, size_t *length,
             time_t *expiration)
{
    int status;
    struct wai_krb5_cred data;

    /* Start by copying the credential data into our standard struct. */
    memset(&data, 0, sizeof(data));
    status = encode_principal(ctx, kc, creds->client, &data.client_principal);
    if (status != WA_ERR_NONE)
        return status;
    status = encode_principal(ctx, kc, creds->server, &data.server_principal);
    if (status != WA_ERR_NONE)
        return status;
    data.keyblock_enctype  = creds->keyblock.enctype;
    data.keyblock_data     = creds->keyblock.contents;
    data.keyblock_data_len = creds->keyblock.length;
    data.auth_time         = creds->times.authtime;
    data.start_time        = creds->times.starttime;
    data.end_time          = creds->times.endtime;
    if (expiration != NULL)
        *expiration = creds->times.endtime;
    data.renew_until       = creds->times.renew_till;
    data.is_skey           = creds->is_skey;
    data.flags             = creds->ticket_flags;
    if (creds->addresses != NULL) {
        size_t n, i, size;
        krb5_address *address;

        for (n = 0, address = *creds->addresses; address != NULL; address++)
            n++;
        data.address_count = n;
        size = n * sizeof(struct wai_krb5_cred_address);
        data.address = apr_palloc(kc->pool, size);
        for (i = 0; i < n; i++) {
            data.address[i].type = creds->addresses[i]->addrtype;
            data.address[i].data = creds->addresses[i]->contents;
            data.address[i].data_len = creds->addresses[i]->length;
        }
    }
    if (creds->ticket.length > 0) {
        data.ticket     = creds->ticket.data;
        data.ticket_len = creds->ticket.length;
    }
    if (creds->second_ticket.length > 0) {
        data.second_ticket     = creds->second_ticket.data;
        data.second_ticket_len = creds->second_ticket.length;
    }
    if (creds->authdata != NULL) {
        size_t n, i, size;
        krb5_authdata *authdata;

        for (n = 0, authdata = *creds->authdata; authdata != NULL; authdata++)
            n++;
        data.authdata_count = n;
        size = n * sizeof(struct wai_krb5_cred_authdata);
        data.authdata = apr_palloc(kc->pool, size);
        for (i = 0; i < n; i++) {
            data.authdata[i].type = creds->authdata[i]->ad_type;
            data.authdata[i].data = creds->authdata[i]->contents;
            data.authdata[i].data_len = creds->authdata[i]->length;
        }
    }

    /* All done.  Do the attribute encoding. */
    return wai_encode(ctx, kc->pool, wai_krb5_cred_encoding, &data, output,
                      length);
}


/*
 * Take a serialized Kerberos credential and decode it into a krb5_creds
 * structure.  creds will point to newly-allocated pool memory.
 *
 * Be very cautious of memory management here.  Nearly all of the credential
 * structure will be allocated from pool memory, and therefore the credential
 * must not be freed with the normal Kerberos memory calls.  However, the
 * client and server principals will be allocated by the Kerberos library and
 * will need to be freed.
 */
static int
decode_creds(struct webauth_context *ctx, struct webauth_krb5 *kc,
             const void *input, size_t length, krb5_creds *creds)
{
    struct wai_krb5_cred data;
    int status;
    size_t size, i;

    /*
     * Decode the input into the credential struct and then copy it into
     * the data structure used by the library.
     */
    memset(&data, 0, sizeof(data));
    status = wai_decode(ctx, wai_krb5_cred_encoding, input, length, &data);
    memset(creds, 0, sizeof(krb5_creds));
    if (data.client_principal != NULL) {
        status = decode_principal(ctx, kc, data.client_principal,
                                  &creds->client);
        if (status != WA_ERR_NONE)
            return status;
    }
    if (data.client_principal != NULL) {
        status = decode_principal(ctx, kc, data.server_principal,
                                  &creds->server);
        if (status != WA_ERR_NONE)
            return status;
    }
    creds->keyblock.magic = KV5M_KEYBLOCK;
    creds->keyblock.enctype = data.keyblock_enctype;
    creds->keyblock.contents = data.keyblock_data;
    creds->keyblock.length = data.keyblock_data_len;
    creds->times.authtime = data.auth_time;
    creds->times.starttime = data.start_time;
    creds->times.endtime = data.end_time;
    creds->times.renew_till = data.renew_until;
    creds->is_skey = data.is_skey;
    creds->ticket_flags = data.flags;
    if (data.address_count > 0) {
        size = (data.address_count + 1) * sizeof(krb5_address *);
        creds->addresses = apr_pcalloc(kc->pool, size);
        for (i = 0; i < data.address_count; i++) {
            creds->addresses[i] = apr_pcalloc(kc->pool, sizeof(krb5_address));
            creds->addresses[i]->magic = KV5M_ADDRESS;
            creds->addresses[i]->addrtype = data.address[i].type;
            creds->addresses[i]->contents = data.address[i].data;
            creds->addresses[i]->length = data.address[i].data_len;
        }
        creds->addresses[i] = NULL;
    }
    if (data.ticket != NULL) {
        creds->ticket.magic = KV5M_DATA;
        creds->ticket.data = data.ticket;
        creds->ticket.length = data.ticket_len;
    }
    if (data.second_ticket != NULL) {
        creds->second_ticket.magic = KV5M_DATA;
        creds->second_ticket.data = data.second_ticket;
        creds->second_ticket.length = data.second_ticket_len;
    }
    if (data.authdata_count > 0) {
        size = (data.authdata_count + 1) * sizeof(krb5_authdata *);
        creds->authdata = apr_pcalloc(kc->pool, size);
        for (i = 0; i < data.authdata_count; i++) {
            creds->authdata[i] = apr_palloc(kc->pool, sizeof(krb5_authdata));
            creds->authdata[i]->magic = KV5M_AUTHDATA;
            creds->authdata[i]->ad_type = data.authdata[i].type;
            creds->authdata[i]->contents = data.authdata[i].data;
            creds->authdata[i]->length = data.authdata[i].data_len;
        }
        creds->authdata[i] = NULL;
    }
    return WA_ERR_NONE;
}
