/*
 * pelz_messaging_test_suite.h
 */

#ifndef PELZ_MESSAGING_SUITE_H_
#define PELZ_MESSAGING_SUITE_H_

#include "pelz_messaging.h"
#include "ca_table.h"
#include "pelz_loaders.h"
#include <CUnit/CUnit.h>

// Adds all tests to suite in main test runner
int pelz_messaging_suite_add_tests(CU_pSuite suite);

// Tests
void test_create_pelz_asn1_msg(void);
void test_parse_pelz_asn1_msg(void);
void test_create_pelz_signed_msg(void);
void test_verify_pelz_signed_msg(void);
void test_create_pelz_enveloped_msg(void);
void test_decrypt_pelz_enveloped_msg(void);
void test_der_encode_pelz_msg(void);
void test_der_decode_pelz_msg(void);
void test_construct_deconstruct_pelz_msg(void);

//void test_create_validate_signature_simple(void);
//void test_create_validate_signature(void);
//void test_verify_cert_chain(void);
//void test_verify_cert_chain_enclave(void);
//void test_invalid_cert_chain_enclave(void);

#endif /* PELZ_MESSAGING_SUITE_H_ */
