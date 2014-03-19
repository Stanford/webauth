/*
 * Heimdal Kerberos interface for WebAuth.
 *
 * This file is *included* (via the preprocessor) in krb5.c for systems that
 * use Heimdal Kerberos.  If you make any changes here, you probably also need
 * to make a corresponding change to krb5-mit.c for systems with MIT Kerberos.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2002, 2003, 2006, 2009, 2010, 2012, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */


/*
 * Reverse the order of the Kerberos credential flag bits.  This converts from
 * the Heimdal memory format to the format used in credential caches and
 * therefore on the wire by our code.
 */
static int32_t
swap_flag_bits(int32_t flags)
{
    int32_t result = 0;
    unsigned int i;

    for (i = 0; i < 32; i++) {
        result = (result << 1) | (flags & 1);
        flags = flags >> 1;
    }
    return result;
}


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
    int s;
    struct wai_krb5_cred data;

    /* Start by copying the credential data into our standard struct. */
    memset(&data, 0, sizeof(data));
    s = encode_principal(ctx, kc, creds->client, &data.client_principal);
    if (s != WA_ERR_NONE)
        return s;
    s = encode_principal(ctx, kc, creds->server, &data.server_principal);
    if (s != WA_ERR_NONE)
        return s;
    data.keyblock_enctype  = creds->session.keytype;
    data.keyblock_data     = creds->session.keyvalue.data;
    data.keyblock_data_len = creds->session.keyvalue.length;
    data.auth_time         = creds->times.authtime;
    data.start_time        = creds->times.starttime;
    data.end_time          = creds->times.endtime;
    if (expiration != NULL)
        *expiration = creds->times.endtime;
    data.renew_until       = creds->times.renew_till;
    if (creds->addresses.len > 0) {
        size_t i, size;

        data.address_count = creds->addresses.len;
        size = creds->addresses.len * sizeof(struct wai_krb5_cred_address);
        data.address = apr_palloc(kc->pool, size);
        for (i = 0; i < creds->addresses.len; i++) {
            data.address[i].type = creds->addresses.val[i].addr_type;
            data.address[i].data = creds->addresses.val[i].address.data;
            data.address[i].data_len = creds->addresses.val[i].address.length;
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
    if (creds->authdata.len > 0) {
        size_t i, size;

        data.authdata_count = creds->authdata.len;
        size = creds->authdata.len * sizeof(struct wai_krb5_cred_authdata);
        data.authdata = apr_palloc(kc->pool, size);
        for (i = 0; i < creds->authdata.len; i++) {
            data.authdata[i].type = creds->authdata.val[i].ad_type;
            data.authdata[i].data = creds->authdata.val[i].ad_data.data;
            data.authdata[i].data_len = creds->authdata.val[i].ad_data.length;
        }
    }

    /*
     * Flags are special.  MIT Kerberos's memory representation has the flag
     * bits with forwardable at the most significant end.  Heimdal's memory
     * representation has forwardable at the least significant end.  The
     * interchangeable data format is the MIT format, so we want to write them
     * that way on the wire.
     */
    data.flags = swap_flag_bits(creds->flags.i);

    /* All done.  Do the attribute encoding. */
    return wai_encode(ctx, wai_krb5_cred_encoding, &data, output, length);
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
    int s;
    size_t size, i;

    /*
     * Decode the input into the credential struct and then copy it into the
     * data structure used by the library.  is_skey is not supported by
     * Heimdal, so ignore it.
     */
    memset(&data, 0, sizeof(data));
    s = wai_decode(ctx, wai_krb5_cred_encoding, input, length, &data);
    if (s != WA_ERR_NONE)
        return s;
    memset(creds, 0, sizeof(krb5_creds));
    if (data.client_principal != NULL) {
        s = decode_principal(ctx, kc, data.client_principal, &creds->client);
        if (s != WA_ERR_NONE)
            return s;
    }
    if (data.client_principal != NULL) {
        s = decode_principal(ctx, kc, data.server_principal, &creds->server);
        if (s != WA_ERR_NONE)
            return s;
    }
    creds->session.keytype = data.keyblock_enctype;
    creds->session.keyvalue.data = data.keyblock_data;
    creds->session.keyvalue.length = data.keyblock_data_len;
    creds->times.authtime = data.auth_time;
    creds->times.starttime = data.start_time;
    creds->times.endtime = data.end_time;
    creds->times.renew_till = data.renew_until;
    if (data.address_count > 0) {
        creds->addresses.len = data.address_count;
        size = data.address_count * sizeof(krb5_address);
        creds->addresses.val = apr_pcalloc(kc->pool, size);
        for (i = 0; i < data.address_count; i++) {
            creds->addresses.val[i].addr_type = data.address[i].type;
            creds->addresses.val[i].address.data = data.address[i].data;
            creds->addresses.val[i].address.length = data.address[i].data_len;
        }
    }
    if (data.ticket != NULL) {
        creds->ticket.data = data.ticket;
        creds->ticket.length = data.ticket_len;
    }
    if (data.second_ticket != NULL) {
        creds->second_ticket.data = data.second_ticket;
        creds->second_ticket.length = data.second_ticket_len;
    }
    if (data.authdata_count > 0) {
        creds->authdata.len = data.authdata_count;
        size = data.authdata_count * sizeof(*creds->authdata.val);
        creds->authdata.val = apr_palloc(kc->pool, size);
        for (i = 0; i < data.authdata_count; i++) {
            creds->authdata.val[i].ad_type = data.authdata[i].type;
            creds->authdata.val[i].ad_data.data = data.authdata[i].data;
            creds->authdata.val[i].ad_data.length = data.authdata[i].data_len;
        }
    }

    /*
     * The portable representation of the flag bits has forwardable near the
     * most significant end.  Heimdal's memory representation has it at the
     * least significant end.  So normally we want to just swap the flag bits
     * when reading them off the wire.
     *
     * However, unfortunately, we used to store the flag bits on the wire in
     * memory format (causing lack of correct interoperability between Heimdal
     * and MIT).  Try to figure out if we did that by seeing if any of the
     * high flag bits are set and only swapping the bits if one of them is
     * set.  This relies on the fact that credentials always have at least one
     * flag set, and all the currently used flags are in the top half of the
     * wire encoding.
     *
     * WebAuth 4.4.0 and later will always write out the flag bits in the
     * correct order.  This code could theoretically be simplified to always
     * swap if nothing older is still in the wild.
     */
    if (data.flags & 0xffff0000)
        creds->flags.i = swap_flag_bits(data.flags);
    else
        creds->flags.i = data.flags;

    return WA_ERR_NONE;
}
