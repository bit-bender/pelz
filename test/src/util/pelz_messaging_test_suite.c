/*
 * pelz_messaging_suite.c
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <CUnit/CUnit.h>

#include "pelz_messaging_test_suite.h"
#include <pelz_log.h>

#include "sgx_urts.h"
#include "pelz_enclave.h"
#include "test_enclave_u.h"

// Adds all pelz messaging tests to main test runner.
int pelz_messaging_suite_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite, "Test Pelz signed CMS message creation",
                                 test_create_signed_data_msg))
  {
    return (1);
  }

  if (NULL == CU_add_test(suite, "Test Pelz signed CMS message verification",
                                 test_verify_signature))
  {
    return 1;
  }

  return (0);
}

void test_create_signed_data_msg(void)
{
  pelz_log(LOG_DEBUG, "Start create_signed_data_msg() functionality test");
}

void test_verify_signature(void)
{
  pelz_log(LOG_DEBUG, "Start verify_signature() functionality test");
}

