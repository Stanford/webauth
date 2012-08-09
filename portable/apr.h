/*
 * Portability wrapper around APR headers.
 *
 * This header includes the following APR headers:
 *
 *     #include <apr_errno.h>
 *     #include <apr_general.h>
 *     #include <apr_pools.h>
 *     #include <apr_strings.h>
 *     #include <apr_tables.h>
 *
 * and then attempts to adjust for older versions of APR.
 *
 * The canonical version of this file is maintained in the rra-c-util package,
 * which can be found at <http://www.eyrie.org/~eagle/software/rra-c-util/>.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 *
 * The authors hereby relinquish any claim to any copyright that they may have
 * in this work, whether granted under contract or by operation of law or
 * international treaty, and hereby commit to the public, at large, that they
 * shall not, at any time in the future, seek to enforce any copyright in this
 * work against any person or entity, or prevent any person or entity from
 * copying, publishing, distributing or creating derivative works of this
 * work.
 */

#ifndef PORTABLE_APR_H
#define PORTABLE_APR_H 1

#include <apr_errno.h>
#include <apr_general.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>

/* APR 0.9's apr_tables.h doesn't include these macros. */
#ifndef APR_ARRAY_IDX
# define APR_ARRAY_IDX(ary,i,type) (((type *)(ary)->elts)[i])
#endif
#ifndef APR_ARRAY_PUSH
# define APR_ARRAY_PUSH(ary,type) (*((type *)apr_array_push(ary)))
#endif

#endif /* !PORTABLE_APR_H */
