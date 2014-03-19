/*
 * Helper functions for parsing XML documents.
 *
 * These are internal helper functions used by other portions of the WebAuth
 * library when parsing XML documents.  They're not exposed as part of the
 * library API; they're only used by other parts of the library.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2011, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <apr_xml.h>

#include <lib/internal.h>
#include <webauth/basic.h>


/*
 * Given an XML element from an APR-Util XML parse, retrieve all of the
 * CDATA contents of that element, create a single pool-allocated string from
 * them all, and store it in the output variable.  Returns a status code.
 */
int
wai_xml_content(struct webauth_context *ctx, apr_xml_elem *e,
                const char **output)
{
    struct wai_buffer *buf;
    apr_text *text;

    buf = wai_buffer_new(ctx->pool);
    if (e->first_cdata.first != NULL)
        for (text = e->first_cdata.first; text != NULL; text = text->next) {
            if (text->text == NULL)
                continue;
            wai_buffer_append(buf, text->text, strlen(text->text));
        }
    if (buf->data == NULL || buf->data[0] == '\0') {
        wai_error_set(ctx, WA_ERR_REMOTE_FAILURE,
                      "XML element <%s> does not contain data", e->name);
        return WA_ERR_REMOTE_FAILURE;
    }
    *output = buf->data;
    return WA_ERR_NONE;
}
