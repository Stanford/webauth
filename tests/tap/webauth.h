/*
 * Helper functions for testing WebAuth code.
 *
 * Additional functions that are helpful for testing WebAuth code and have
 * knowledge of WebAuth functions and data structures.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#ifndef TAP_WEBAUTH_H
#define TAP_WEBAUTH_H 1

#include <config.h>
#include <tests/tap/macros.h>

struct webauth_token_error;
struct webauth_token_id;
struct webauth_token_proxy;
struct webauth_token_webkdc_factor;
struct webauth_token_webkdc_proxy;

BEGIN_DECLS

/* Compare two tokens of various types. */
void is_token_error(const struct webauth_token_error *wanted,
                    const struct webauth_token_error *seen,
                    const char *format, ...)
    __attribute__((__format__(printf, 3, 4)));
void is_token_id(const struct webauth_token_id *wanted,
                 const struct webauth_token_id *seen,
                 const char *format, ...)
    __attribute__((__format__(printf, 3, 4)));
void is_token_proxy(const struct webauth_token_proxy *wanted,
                    const struct webauth_token_proxy *seen,
                    const char *format, ...)
    __attribute__((__format__(printf, 3, 4)));
void is_token_webkdc_factor(const struct webauth_token_webkdc_factor *wanted,
                            const struct webauth_token_webkdc_factor *seen,
                            const char *format, ...)
    __attribute__((__format__(printf, 3, 4)));
void is_token_webkdc_proxy(const struct webauth_token_webkdc_proxy *wanted,
                           const struct webauth_token_webkdc_proxy *seen,
                           const char *format, ...)
    __attribute__((__format__(printf, 3, 4)));

END_DECLS

#endif /* !TAP_WEBAUTH_H */
