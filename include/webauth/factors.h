/*
 * WebAuth factor manipulation functions.
 *
 * These interfaces parse, unparse, and otherwise manipulate WebAuth
 * authentication factors, which are treated as an opaque data type by the
 * rest of the WebAuth code.  This includes various types of set math on
 * factors.
 *
 * In the following interfaces, one set of factors is said to "satisfy" a
 * factor if, for authentication purposes, the set of factors indicates that
 * authentication factor has been presented.  It "contains" a factor if that
 * specific factor is included in the set.  The difference is primarily around
 * random multifactor, where a multifactor factor satisfies random multifactor
 * even though the set containing a multifactor factor may not contain the
 * random multifactor factor.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2012, 2013, 2014
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

#ifndef WEBAUTH_FACTORS_H
#define WEBAUTH_FACTORS_H 1

#include <webauth/defines.h>

struct webauth_context;
struct webauth_factors;

/* Factor constants. */
#define WA_FA_COOKIE               "c"
#define WA_FA_DEVICE               "d"
#define WA_FA_HUMAN                "h"
#define WA_FA_KERBEROS             "k"
#define WA_FA_MOBILE_PUSH          "mp"
#define WA_FA_MULTIFACTOR          "m"
#define WA_FA_OTP                  "o"
#define WA_FA_PASSWORD             "p"
#define WA_FA_RANDOM_MULTIFACTOR   "rm"
#define WA_FA_UNKNOWN              "u"
#define WA_FA_VOICE                "v"
#define WA_FA_X509                 "x"

BEGIN_DECLS

/* Returns all of the factors as a newly-allocated array. */
WA_APR_ARRAY_HEADER_T *webauth_factors_array(struct webauth_context *,
                                             const struct webauth_factors *)
    __attribute__((__nonnull__(1)));

/*
 * Returns true if the provided factors contain the named factor and false
 * otherwise.
 */
int webauth_factors_contains(struct webauth_context *,
                             const struct webauth_factors *, const char *)
    __attribute__((__nonnull__(1, 3)));

/*
 * Given an array of factor strings (possibly NULL), create a new
 * pool-allocated webauth_factors struct and return it.  If the array is NULL,
 * the resulting factors struct will be empty.  This function does not
 * synthesize multifactor.
 */
struct webauth_factors *webauth_factors_new(struct webauth_context *,
                                            const WA_APR_ARRAY_HEADER_T *)
    __attribute__((__nonnull__(1)));

/*
 * Given a comma-separated string of factors, parse it into a new
 * pool-allocated webauth_factors struct.  Synthesize multifactor if the
 * factors represented by the string indicate a multifactor authentication.
 * The string may be NULL, in which case the resulting factors struct will be
 * empty.
 */
struct webauth_factors *webauth_factors_parse(struct webauth_context *,
                                              const char *)
    __attribute__((__nonnull__(1)));

/*
 * Given a webauth_factors struct, return its value as a comma-separated
 * string suitable for inclusion in a token.  The new string is
 * pool-allocated.  If the webauth_factors struct is NULL, returns NULL.
 */
char *webauth_factors_string(struct webauth_context *,
                             const struct webauth_factors *)
    __attribute__((__nonnull__(1)));

/*
 * Given two sets of factors (struct webauth_factors), return true if the
 * first set satisfies the second set, false otherwise.
 */
int webauth_factors_satisfies(struct webauth_context *,
                              const struct webauth_factors *,
                              const struct webauth_factors *)
    __attribute__((__nonnull__(1, 2)));

/*
 * Given two sets of factors (struct webauth_factors), return a new set of
 * factors formed by removing all factors from the first set that are present
 * in the second set.
 */
struct webauth_factors *
    webauth_factors_subtract(struct webauth_context *,
                             const struct webauth_factors *,
                             const struct webauth_factors *)
    __attribute__((__nonnull__(1)));

/*
 * Given two webauth_factors structs, create a new pool-allocated struct
 * representing the union of both.  Synthesize multifactor if the combined
 * webauth_factors structs represent a multifactor authentication.
 */
struct webauth_factors *
webauth_factors_union(struct webauth_context *ctx,
                      const struct webauth_factors *one,
                      const struct webauth_factors *two)
    __attribute__((__nonnull__(1)));

END_DECLS

#endif /* !WEBAUTH_FACTORS_H */
