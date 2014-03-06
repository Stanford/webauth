/*
 * Portability wrapper around APR headers.
 *
 * This header includes the following APR headers:
 *
 *     #include <apr_errno.h>
 *     #include <apr_file_info.h>
 *     #include <apr_file_io.h>
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
 * Written by Russ Allbery <eagle@eyrie.org>
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
#include <apr_file_info.h>
#include <apr_file_io.h>
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

/*
 * The older apr_file_io.h constants are deprecated, but APR 0.9 doesn't have
 * the new ones.  Define the new names in terms of the old if not already
 * defined.
 */
#ifndef APR_FOPEN_READ
# define APR_FOPEN_READ             APR_READ
# define APR_FOPEN_WRITE            APR_WRITE
# define APR_FOPEN_CREATE           APR_CREATE
# define APR_FOPEN_APPEND           APR_APPEND
# define APR_FOPEN_TRUNCATE         APR_TRUNCATE
# define APR_FOPEN_BINARY           APR_BINARY
# define APR_FOPEN_EXCL             APR_EXCL
# define APR_FOPEN_BUFFERED         APR_BUFFERED
# define APR_FOPEN_DELONCLOSE       APR_DELONCLOSE
# define APR_FOPEN_XTHREAD          APR_XTHREAD
# define APR_FOPEN_SHARELOCK        APR_SHARELOCK
# define APR_FOPEN_NOCLEANUP        APR_FILE_NOCLEANUP
# define APR_FOPEN_SENDFILE_ENABLED APR_SENDFILE_ENABLED
# define APR_FOPEN_LARGEFILE        APR_LARGEFILE
#endif

/* Likewise for the apr_file_info.h constants. */
#ifndef APR_FPROT_UREAD
# define APR_FPROT_USETID            APR_USETID
# define APR_FPROT_UREAD             APR_UREAD
# define APR_FPROT_UWRITE            APR_UWRITE
# define APR_FPROT_UEXECUTE          APR_UEXECUTE
# define APR_FPROT_GSETID            APR_GSETID
# define APR_FPROT_GREAD             APR_GREAD
# define APR_FPROT_GWRITE            APR_GWRITE
# define APR_FPROT_GEXECUTE          APR_GEXECUTE
# define APR_FPROT_WSTICKY           APR_WSTICKY
# define APR_FPROT_WREAD             APR_WREAD
# define APR_FPROT_WWRITE            APR_WWRITE
# define APR_FPROT_WEXECUTE          APR_WEXECUTE
# define APR_FPROT_OS_DEFAULT        APR_OS_DEFAULT
# define APR_FPROT_FILE_SOURCE_PERMS APR_FILE_SOURCE_PERMS
#endif

#endif /* !PORTABLE_APR_H */
