/*
 * Helper functions for testing WebAuth code.
 *
 * Additional functions that are helpful for testing WebAuth code and have
 * knowledge of WebAuth functions and data structures.  In all of the token
 * comparison functions, each component of the tokens is compared as a
 * separate test result, since that makes problem reporting much clearer and
 * more helpful to the developer.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <tests/tap/basic.h>
#include <tests/tap/string.h>
#include <tests/tap/webauth.h>
#include <webauth/tokens.h>


/*
 * Check a token creation time.  Takes the wanted and seen creation times, and
 * if wanted is 0, expects a creation time within a range of 5 seconds old and
 * 1 second fast compared to the current time.
 */
static void
is_token_creation(time_t wanted, time_t seen, const char *format, ...)
{
    va_list args;
    time_t now;
    bool okay;

    if (wanted == 0) {
        now = time(NULL);
        okay = (seen >= now - 5 && seen <= now + 1);
    } else {
        okay = (wanted == seen);
    }
    if (!okay)
        printf("# wanted: %lu\n#   seen: %lu\n", (unsigned long) wanted,
               (unsigned long) seen);
    va_start(args, format);
    okv(okay, format, args);
    va_end(args);
}


/*
 * Compare two webkdc-factor tokens.
 */
void
is_token_webkdc_factor(const struct webauth_token_webkdc_factor *wanted,
                       const struct webauth_token_webkdc_factor *seen,
                       const char *format, ...)
{
    va_list args;
    char *message;

    va_start(args, format);
    bvasprintf(&message, format, args);
    va_end(args);
    if (seen == NULL) {
        ok_block(4, false, "%s is NULL", message);
        return;
    }
    is_string(wanted->subject, seen->subject, "%s subject", message);
    is_string(wanted->factors, seen->factors, "%s factors", message);
    is_token_creation(wanted->creation, seen->creation, "%s creation",
                      message);
    is_int(wanted->expiration, seen->expiration, "%s expiration", message);
    free(message);
}


/*
 * Compare two webkdc-proxy tokens.
 */
void
is_token_webkdc_proxy(const struct webauth_token_webkdc_proxy *wanted,
                      const struct webauth_token_webkdc_proxy *seen,
                      const char *format, ...)
{
    va_list args;
    char *message;

    va_start(args, format);
    bvasprintf(&message, format, args);
    va_end(args);
    if (seen == NULL) {
        ok_block(9, false, "%s is NULL", message);
        return;
    }
    is_string(wanted->subject, seen->subject, "%s subject", message);
    is_string(wanted->proxy_type, seen->proxy_type, "%s proxy type", message);
    is_string(wanted->proxy_subject, seen->proxy_subject, "%s proxy subject",
              message);
    if (wanted->data == NULL || seen->data == NULL)
        ok(wanted->data == seen->data, "%s proxy data", message);
    else
        ok(memcmp(wanted->data, seen->data, wanted->data_len) == 0,
           "%s proxy data", message);
    is_int(wanted->data_len, seen->data_len, "%s proxy data length", message);
    is_string(wanted->initial_factors, seen->initial_factors,
              "%s initial factors", message);
    is_int(wanted->loa, seen->loa, "%s level of assurance", message);
    is_token_creation(wanted->creation, seen->creation, "%s creation",
                      message);
    is_int(wanted->expiration, seen->expiration, "%s expiration", message);
    is_string(wanted->session_factors, seen->session_factors,
              "%s session factors", message);
    free(message);
}
