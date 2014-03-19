/*
 * General WebAuth utility functions.
 *
 * A catch-all collection of functions that are used by various parts of the
 * WebAuth code and are therefore provided by the library, even though they
 * don't fit naturally into the WebAuth API structure.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef WEBAUTH_UTIL_H
#define WEBAUTH_UTIL_H 1

#include <webauth/defines.h>

BEGIN_DECLS

/*
 * Convert a time string to a count of seconds and stores the count in the
 * seconds argument.  Returns a WebAuth status code.  Only a single number
 * followed by a unit is supported.  Currently supported units are s, m, h, d
 * (days), and w (weeks).
 */
int webauth_parse_interval(const char *interval, unsigned long *seconds)
    __attribute__((__nonnull__));

END_DECLS

#endif /* !WEBAUTH_UTIL_H */
