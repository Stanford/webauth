/** @file
 * webauth test harness macros
 *
 * this file contains some simple macros to emulate Perl's test
 * harness. FIXME: should move this to libwebauth or common so
 * other C tests can use it.
 */

#ifndef _WEBAUTHTESTS_H
#define _WEBAUTHTESTS_H

#define TEST_VARS \
  int _webauth_test_tot=0;\
  int _webauth_test_num=0;\
  int _webauth_test_fail=0

#define START_TESTS(num) \
    printf("1..%d\n", num);\
    _webauth_test_tot=num;

#define TEST_OK(x) \
    _webauth_test_num++; \
    if (x) { \
        printf("ok %d\n", _webauth_test_num);\
    } else { \
        printf("not ok %d\n# Failed test %d in %s at line %d\n", \
        _webauth_test_num, _webauth_test_num,  __FILE__, __LINE__);\
       _webauth_test_fail++; \
    }

#define TEST_OK2(x,y) \
    _webauth_test_num++; \
    if (x==y) { \
        printf("ok %d\n", _webauth_test_num);\
    } else { \
        printf("not ok %d\n", _webauth_test_num);\
        printf("# Test %d got: '%d' (%s at line %d)\n# Expected: '%d'\n", \
        _webauth_test_num, y,  __FILE__, __LINE__, x);\
       _webauth_test_fail++; \
    }

#define END_TESTS \
    if (_webauth_test_num != _webauth_test_tot) {\
        printf("# WARN: %d tests specified, %d tests run\n", \
               _webauth_test_tot, _webauth_test_num);\
    }

#define NUM_FAILED_TESTS (_webauth_test_fail)
#define NUM_PASSED_TESTS (_webauth_test_num - _webauth_test_fail)
#define TOT_NUM_TESTS (_webauth_test_tot)

#endif
