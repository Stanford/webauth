/*
 * Test time interval conversion.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2011, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <tests/tap/basic.h>
#include <webauth/basic.h>
#include <webauth/util.h>

/* A set of time interval values and their corresponding second amounts. */
static const struct {
    const char *interval;
    unsigned long seconds;
} tests[] = {
    { "0s",                 0 },
    { "30s",               30 },
    { "120s",             120 },
    { "0m",                 0 },
    { "1m",                60 },
    { "10m",              600 },
    { "0h",                 0 },
    { "1h",           60 * 60 },
    { "10h",     10 * 60 * 60 },
    { "0d",                 0 },
    { "1d",      24 * 60 * 60 },
    { "8d",  8 * 24 * 60 * 60 },
    { "0w",                 0 },
    { "1w",  7 * 24 * 60 * 60 },
    { "2w", 14 * 24 * 60 * 60 }
};

/* A set of invalid intervals that should result in error codes. */
static const char * const invalid[] = {
    "", "0", "30", "1m30s", "1ms", "5k", "asdf"
};


int
main(void)
{
    unsigned long value;
    size_t i;
    int s;

    plan(ARRAY_SIZE(tests) * 2 + ARRAY_SIZE(invalid) * 2);
    for (i = 0; i < ARRAY_SIZE(tests); i++) {
        s = webauth_parse_interval(tests[i].interval, &value);
        is_int(WA_ERR_NONE, s, "Parse %s", tests[i].interval);
        is_int(tests[i].seconds, value, "...with correct value");
    }
    for (i = 0; i < ARRAY_SIZE(invalid); i++) {
        value = i + 1;
        s = webauth_parse_interval(invalid[i], &value);
        is_int(WA_ERR_INVALID, s, "Parse invalid %s", invalid[i]);
        is_int(i + 1, value, "...and value doesn't change");
    }

    return 0;
}
