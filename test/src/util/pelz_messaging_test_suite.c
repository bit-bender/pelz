/*
 * pelz_messaging_suite.c
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <CUnit/CUnit.h>

#include "pelz_messaging_test_suite.h"
#include "enclave_helper_functions.h"

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

  int result = 0;

  char *test_data = "Hello, pelz!";
  size_t test_data_len = (size_t) strlen(test_data);

  BIO *test_cert_bio = BIO_new_file("test/data/node_pub.pem", "r");
  if (test_cert_bio == NULL)
  {
    CU_FAIL("error creating BIO for reading test cert from file");
  }
  X509 *test_cert = PEM_read_bio_X509(test_cert_bio, NULL, 0, NULL);
  if (test_cert == NULL)
  {
    CU_FAIL("error creating test X509 certificate");
  }
  BIO_free(test_cert_bio);
  int test_der_cert_len = -1;
  uint8_t *test_der_cert = NULL;
  test_der_cert_len = i2d_X509(test_cert, &test_der_cert);
  if ((test_der_cert == NULL) || (test_der_cert_len <= 0))
  {
    CU_FAIL("error creating DER-formatted test certificate");
  }

  BIO * test_key_bio = BIO_new_file("test/data/node_priv.pem", "r");
  if (test_key_bio == NULL)
  {
    CU_FAIL("error creating BIO for reading test key from file");
  }
  EVP_PKEY * test_key = PEM_read_bio_PrivateKey(test_key_bio, NULL, 0, NULL);
  if (test_key == NULL)
  {
    CU_FAIL("error creating test EC private key for signing");
  }
  BIO_free(test_key_bio);
  size_t test_der_key_len = 0;
  uint8_t *test_der_key = NULL;
  test_der_key_len = (size_t) i2d_PrivateKey(test_key, &test_der_key);
  if ((test_der_key == NULL) || (test_der_key_len <= 0))
      
  {
    CU_FAIL("error creating DER-formatted test EC private key");
  }

  BIO * mismatch_key_bio = BIO_new_file("test/data/worker_priv.pem", "r");
  if (mismatch_key_bio == NULL)
  {
    CU_FAIL("error creating BIO for reading test key from file");
  }
  EVP_PKEY * mismatch_key = PEM_read_bio_PrivateKey(mismatch_key_bio, NULL, 0, NULL);
  if (mismatch_key == NULL)
  {
    CU_FAIL("error creating test EC private key for signing");
  }
  BIO_free(mismatch_key_bio);
  size_t mismatch_der_key_len = 0;
  uint8_t *mismatch_der_key = NULL;
  mismatch_der_key_len = (size_t) i2d_PrivateKey(mismatch_key, &mismatch_der_key);
  if ((mismatch_der_key == NULL) || (mismatch_der_key_len <= 0))
      
  {
    CU_FAIL("error creating DER-formatted test EC private key");
  }

  // valid test case should pass
  test_create_signed_data_msg_helper(eid,
                                     &result,
                                     test_data_len,
                                     (uint8_t *) test_data,
                                     (size_t) test_der_cert_len,
                                     test_der_cert,
                                     test_der_key_len,
                                     test_der_key);
  CU_ASSERT(result == MSG_TEST_SUCCESS);

  // NULL input data  pointer should fail
  test_create_signed_data_msg_helper(eid,
                                     &result,
                                     test_data_len,
                                     NULL,
                                     (size_t) test_der_cert_len,
                                     test_der_cert,
                                     test_der_key_len,
                                     test_der_key);
  CU_ASSERT(result == MSG_TEST_SIGN_FAILURE);
  
  // Empty input data buffer should fail
  test_create_signed_data_msg_helper(eid,
                                     &result,
                                     0,
                                     (uint8_t *) test_data,
                                     (size_t) test_der_cert_len,
                                     test_der_cert,
                                     test_der_key_len,
                                     test_der_key);
  CU_ASSERT(result == MSG_TEST_SIGN_FAILURE);
  
  // NULL cert should fail
  test_create_signed_data_msg_helper(eid,
                                     &result,
                                     test_data_len,
                                     (uint8_t *) test_data,
                                     (size_t) test_der_cert_len,
                                     NULL,
                                     test_der_key_len,
                                     test_der_key);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // NULL private signing key should fail
  test_create_signed_data_msg_helper(eid,
                                     &result,
                                     test_data_len,
                                     (uint8_t *) test_data,
                                     (size_t) test_der_cert_len,
                                     test_der_cert,
                                     test_der_key_len,
                                     NULL);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // Mismatched key/cert should fail
  test_create_signed_data_msg_helper(eid,
                                     &result,
                                     test_data_len,
                                     (uint8_t *) test_data,
                                     (size_t) test_der_cert_len,
                                     test_der_cert,
                                     mismatch_der_key_len,
                                     mismatch_der_key);
  CU_ASSERT(result == MSG_TEST_SIGN_FAILURE);
}

void test_verify_signature(void)
{
  pelz_log(LOG_DEBUG, "Start verify_signature() functionality test");
}

