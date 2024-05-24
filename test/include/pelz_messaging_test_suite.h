/*
 * pelz_messaging_test_suite.h
 */

#ifndef PELZ_MESSAGING_SUITE_H_
#define PELZ_MESSAGING_SUITE_H_

#include "pelz_messaging.h"
#include <CUnit/CUnit.h>

// Adds all tests to suite in main test runner
int pelz_messaging_suite_add_tests(CU_pSuite suite);

// Tests
void test_create_signed_data_msg(void);
void test_verify_signature(void);

//void test_create_validate_signature_simple(void);
//void test_create_validate_signature(void);
//void test_verify_cert_chain(void);
//void test_verify_cert_chain_enclave(void);
//void test_invalid_cert_chain_enclave(void);

#endif /* PELZ_MESSAGING_SUITE_H_ */
