#ifndef _WEBAUTHP_H
#define _WEBAUTHP_H

/*
 * this is the more "private" version of libwebauth
 */

#include "conf.h"

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#elif HAVE_STRINGS_H
#include <strings.h>
#endif 

#if HAVE_INTTYPES_H
# include <inttypes.h>
#endif
#if HAVE_STDINT_H
# include <stdint.h>
#endif

#include <assert.h>

#include "webauth.h"

/* this used to have something in it, and probably will
   again once apache work starts */

/*
**  Local variables:
**  mode: c
**  c-basic-offset: 4
**  indent-tabs-mode: nil
**  end:
*/

#endif
