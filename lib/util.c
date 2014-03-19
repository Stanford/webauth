/*
 * General utility functions.
 *
 * A catch-all collection of functions that are used by various parts of the
 * WebAuth code and are therefore provided by the library, even though they
 * don't fit naturally into the WebAuth API structure.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Based on the original implementation by Roland Schemers
 * Copyright 2002, 2003, 2005, 2006, 2008, 2009, 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */
 
#include <config.h>
#include <portable/apr.h>
#include <portable/system.h>

#include <errno.h>
#include <limits.h>

#include <lib/internal.h>
#include <webauth/basic.h>
#include <webauth/util.h>


/*
 * Convert a time string to a count of seconds and stores the count in the
 * seconds argument.  On failure due to invalid input, return an error code.
 * This intentionally doesn't use the WebAuth context since we want to be able
 * to call it in situations where we don't have a WebAuth context.
 *
 * Currently, this function only allows a single number followed by a
 * modifier.
 */
int
webauth_parse_interval(const char *interval, unsigned long *seconds)
{
    char *end;
    char type;
    size_t length;
    unsigned long mult, value;

    length = strlen(interval);
    type = interval[length - 1];

    /* Convert the interval units to a multiplier. */
    switch (type) {
    case 's': mult = 1;                break;
    case 'm': mult = 60;               break;
    case 'h': mult = 60 * 60;          break;
    case 'd': mult = 60 * 60 * 24;     break;
    case 'w': mult = 60 * 60 * 24 * 7; break;
    default: return WA_ERR_INVALID;
    }

    /* Convert the actual number. */
    errno = 0;
    value = strtoul(interval, &end, 10);
    if (end != interval + length - 1 || (value == ULONG_MAX && errno != 0))
        return WA_ERR_INVALID;
    *seconds = value * mult;
    return WA_ERR_NONE;
}
