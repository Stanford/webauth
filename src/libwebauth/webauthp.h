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

int webauth_attr_list_add_uint32(WEBAUTH_ATTR_LIST *list,
                                 const char *name,
                                 uint32_t value);

int webauth_attr_list_add_int32(WEBAUTH_ATTR_LIST *list,
                                const char *name,
                                int32_t value);

int webauth_attr_list_add_time(WEBAUTH_ATTR_LIST *list, 
                               const char *name,
                               time_t value);

int webauth_attr_list_get_uint32(WEBAUTH_ATTR_LIST *list,
                                 const char *name,
                                 uint32_t *value);

int webauth_attr_list_get_int32(WEBAUTH_ATTR_LIST *list,
                                 const char *name,
                                 int32_t *value);

int webauth_attr_list_get_time(WEBAUTH_ATTR_LIST *list, 
                               const char *name,
                               time_t *value);

/*
**  Local variables:
**  mode: c
**  c-basic-offset: 4
**  indent-tabs-mode: nil
**  end:
*/

#endif
