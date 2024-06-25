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
  if (NULL == CU_add_test(suite, "Test pelz ASN.1 formatted message creation",
                                 test_create_pelz_asn1_msg))
  {
    return 1;
  }
  
  if (NULL == CU_add_test(suite, "Test pelz ASN.1 formatted message parsing",
                                 test_parse_pelz_asn1_msg))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "Test pelz signed CMS message creation",
                                 test_create_signed_data_msg))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "Test pelz signed CMS message verification",
                                 test_verify_signature))
  {
    return 1;
  }
  
  if (NULL == CU_add_test(suite, "Test pelz message DER encode functionality",
                                 test_der_encode_pelz_msg))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "Test pelz message DER decode functionality",
                                 test_der_decode_pelz_msg))
  {
    return 1;
  }

  return 0;
}


void test_create_pelz_asn1_msg(void)
{
  pelz_log(LOG_DEBUG, "Start create_pelz_asn1_msg() functionality test");

  int result = 0;

  // invalid (less than MSG_TYPE_MIN) message type should fail param checks
  test_create_pelz_asn1_msg_helper(eid,
                                   &result,
                                   MSG_TYPE_MIN - 1,
                                   AES_KEY_WRAP,
                                   15,
                                   (uint8_t *) "file://test.key",
                                   14,
                                   (uint8_t *) "Test,test,test",
                                   11,
                                   (uint8_t *) "some status");
  CU_ASSERT(result == MSG_TEST_CREATE_ERROR);

  // invalid (greater than MSG_TYPE_MAX) message type should fail param checks
  test_create_pelz_asn1_msg_helper(eid,
                                   &result,
                                   MSG_TYPE_MAX + 1,
                                   AES_KEY_WRAP,
                                   15,
                                   (uint8_t *) "file://test.key",
                                   14,
                                   (uint8_t *) "Test,test,test",
                                   11,
                                   (uint8_t *) "some status");
  CU_ASSERT(result == MSG_TEST_CREATE_ERROR);

  // invalid (less than REQ_TYPE_MIN) message type should fail param checks
  test_create_pelz_asn1_msg_helper(eid,
                                   &result,
                                   REQUEST,
                                   REQ_TYPE_MIN - 1,
                                   15,
                                   (uint8_t *) "file://test.key",
                                   14,
                                   (uint8_t *) "Test,test,test",
                                   11,
                                   (uint8_t *) "some status");
  CU_ASSERT(result == MSG_TEST_CREATE_ERROR);

  // invalid (greater than REQ_TYPE_MAX) message type should fail param checks
  test_create_pelz_asn1_msg_helper(eid,
                                   &result,
                                   REQUEST,
                                   REQ_TYPE_MAX + 1,
                                   15,
                                   (uint8_t *) "file://test.key",
                                   14,
                                   (uint8_t *) "Test,test,test",
                                   11,
                                   (uint8_t *) "some status");
  CU_ASSERT(result == MSG_TEST_CREATE_ERROR);

  // null KEK key ID input should fail param checks
  test_create_pelz_asn1_msg_helper(eid,
                                   &result,
                                   REQUEST,
                                   AES_KEY_WRAP,
                                   15,
                                   NULL,
                                   14,
                                   (uint8_t *) "Test,test,test",
                                   11,
                                   (uint8_t *) "some status");
  CU_ASSERT(result == MSG_TEST_CREATE_ERROR);

  // empty (zero-length) KEK key ID input should fail param checks
  test_create_pelz_asn1_msg_helper(eid,
                                   &result,
                                   REQUEST,
                                   AES_KEY_WRAP,
                                   0,
                                   (uint8_t *) "file://test.key",
                                   14,
                                   (uint8_t *) "Test,test,test",
                                   11,
                                   (uint8_t *) "some status");
  CU_ASSERT(result == MSG_TEST_CREATE_ERROR);

  // null data input should fail param checks
  test_create_pelz_asn1_msg_helper(eid,
                                   &result,
                                   REQUEST,
                                   AES_KEY_WRAP,
                                   15,
                                   (uint8_t *) "file://test.key",
                                   14,
                                   NULL,
                                   11,
                                   (uint8_t *) "some status");
  CU_ASSERT(result == MSG_TEST_CREATE_ERROR);

  // empty (zero-length) data input should fail param checks
  test_create_pelz_asn1_msg_helper(eid,
                                   &result,
                                   REQUEST,
                                   AES_KEY_WRAP,
                                   15,
                                   (uint8_t *) "file://test.key",
                                   0,
                                   (uint8_t *) "Test,test,test",
                                   11,
                                   (uint8_t *) "some status");
  CU_ASSERT(result == MSG_TEST_CREATE_ERROR);

  // null status input should fail param checks
  test_create_pelz_asn1_msg_helper(eid,
                                   &result,
                                   REQUEST,
                                   AES_KEY_WRAP,
                                   15,
                                   (uint8_t *) "file://test.key",
                                   14,
                                   (uint8_t *) "Test,test,test",
                                   11,
                                   NULL);
  CU_ASSERT(result == MSG_TEST_CREATE_ERROR);

  // empty (zero-length) status input should fail param checks
  test_create_pelz_asn1_msg_helper(eid,
                                   &result,
                                   REQUEST,
                                   AES_KEY_WRAP,
                                   15,
                                   (uint8_t *) "file://test.key",
                                   14,
                                   (uint8_t *) "Test,test,test",
                                   0,
                                   (uint8_t *) "some status");
  CU_ASSERT(result == MSG_TEST_CREATE_ERROR);

  // valid test case should pass
  test_create_pelz_asn1_msg_helper(eid,
                                   &result,
                                   REQUEST,
                                   AES_KEY_WRAP,
                                   15,
                                   (uint8_t *) "file://test.key",
                                   21,
                                   (uint8_t *) "ASN1 create test data",
                                   11,
                                   (uint8_t *) "some status");
  CU_ASSERT(result == MSG_TEST_SUCCESS);
}

void test_parse_pelz_asn1_msg(void)
{
  pelz_log(LOG_DEBUG, "Start parse_pelz_asn1_msg() functionality test");

  int result = 0;

  // invalid type field tag should result in parse error
  test_parse_pelz_asn1_msg_helper(eid,
                                  &result,
                                  RESPONSE,
                                  AES_KEY_UNWRAP,
                                  15,
                                  (uint8_t *) "file://test.key",
                                  20,
                                  (uint8_t *) "ASN1 parse test data",
                                  21,
                                  (uint8_t *) "some different status",
                                  PARSE_MOD_PELZ_MSG_TYPE_TAG_TEST);
  CU_ASSERT(result == (MSG_TEST_PARSE_ERROR + PELZ_MSG_TYPE_TAG_ERROR));

  // invalid message type field value (< MSG_TYPE_MIN) should error
  test_parse_pelz_asn1_msg_helper(eid,
                                  &result,
                                  RESPONSE,
                                  AES_KEY_UNWRAP,
                                  15,
                                  (uint8_t *) "file://test.key",
                                  20,
                                  (uint8_t *) "ASN1 parse test data",
                                  21,
                                  (uint8_t *) "some different status",
                                  PARSE_MOD_PELZ_MSG_MSG_TYPE_VAL_LO_TEST);
  CU_ASSERT(result == (MSG_TEST_PARSE_ERROR + PELZ_MSG_TYPE_PARSE_INVALID));

  // invalid message type field value (> MSG_TYPE_MAX) should error
  test_parse_pelz_asn1_msg_helper(eid,
                                  &result,
                                  RESPONSE,
                                  AES_KEY_UNWRAP,
                                  15,
                                  (uint8_t *) "file://test.key",
                                  20,
                                  (uint8_t *) "ASN1 parse test data",
                                  21,
                                  (uint8_t *) "some different status",
                                  PARSE_MOD_PELZ_MSG_MSG_TYPE_VAL_HI_TEST);
  CU_ASSERT(result == (MSG_TEST_PARSE_ERROR + PELZ_MSG_TYPE_PARSE_INVALID));

  // invalid request type field value (< REQ_TYPE_MIN) should error
  test_parse_pelz_asn1_msg_helper(eid,
                                  &result,
                                  RESPONSE,
                                  AES_KEY_UNWRAP,
                                  15,
                                  (uint8_t *) "file://test.key",
                                  20,
                                  (uint8_t *) "ASN1 parse test data",
                                  21,
                                  (uint8_t *) "some different status",
                                  PARSE_MOD_PELZ_MSG_REQ_TYPE_VAL_LO_TEST);
  CU_ASSERT(result == (MSG_TEST_PARSE_ERROR + PELZ_MSG_TYPE_PARSE_INVALID));

  // invalid request type field value (> REQ_TYPE_MAX) should error
  test_parse_pelz_asn1_msg_helper(eid,
                                  &result,
                                  RESPONSE,
                                  AES_KEY_UNWRAP,
                                  15,
                                  (uint8_t *) "file://test.key",
                                  20,
                                  (uint8_t *) "ASN1 parse test data",
                                  21,
                                  (uint8_t *) "some different status",
                                  PARSE_MOD_PELZ_MSG_REQ_TYPE_VAL_HI_TEST);
  CU_ASSERT(result == (MSG_TEST_PARSE_ERROR + PELZ_MSG_TYPE_PARSE_INVALID));

  // invalid key ID field tag should result in parse error
  test_parse_pelz_asn1_msg_helper(eid,
                                  &result,
                                  RESPONSE,
                                  AES_KEY_UNWRAP,
                                  15,
                                  (uint8_t *) "file://test.key",
                                  20,
                                  (uint8_t *) "ASN1 parse test data",
                                  21,
                                  (uint8_t *) "some different status",
                                  PARSE_MOD_PELZ_MSG_KEY_ID_TAG_TEST);
  CU_ASSERT(result == (MSG_TEST_PARSE_ERROR + PELZ_MSG_KEY_ID_TAG_ERROR));

  // invalid data field tag should result in parse error
  test_parse_pelz_asn1_msg_helper(eid,
                                  &result,
                                  RESPONSE,
                                  AES_KEY_UNWRAP,
                                  15,
                                  (uint8_t *) "file://test.key",
                                  20,
                                  (uint8_t *) "ASN1 parse test data",
                                  21,
                                  (uint8_t *) "some different status",
                                  PARSE_MOD_PELZ_MSG_DATA_TAG_TEST);
  CU_ASSERT(result == (MSG_TEST_PARSE_ERROR + PELZ_MSG_DATA_TAG_ERROR));

  // invalid status field tag should result in parse error
  test_parse_pelz_asn1_msg_helper(eid,
                                  &result,
                                  RESPONSE,
                                  AES_KEY_UNWRAP,
                                  15,
                                  (uint8_t *) "file://test.key",
                                  20,
                                  (uint8_t *) "ASN1 parse test data",
                                  21,
                                  (uint8_t *) "some different status",
                                  PARSE_MOD_PELZ_MSG_STATUS_TAG_TEST);
  CU_ASSERT(result == (MSG_TEST_PARSE_ERROR + PELZ_MSG_STATUS_TAG_ERROR));

  // valid message format/contents should parse successfully
  test_parse_pelz_asn1_msg_helper(eid,
                                  &result,
                                  RESPONSE,
                                  AES_KEY_UNWRAP,
                                  15,
                                  (uint8_t *) "file://test.key",
                                  20,
                                  (uint8_t *) "ASN1 parse test data",
                                  21,
                                  (uint8_t *) "some different status",
                                  PARSE_PELZ_MSG_BASIC_TEST);
  CU_ASSERT(result == MSG_TEST_SUCCESS);

}

void test_create_signed_data_msg(void)
{
  pelz_log(LOG_DEBUG, "Start create_signed_data_msg() functionality test");

  int result = 0;

  char *test_data = "Hello, pelz!";
  size_t test_data_len = (size_t) strlen(test_data);

  BIO *test_cert_bio = BIO_new_file("test/data/msg_test_req_pub.pem", "r");
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
  X509_free(test_cert);

  BIO * test_key_bio = BIO_new_file("test/data/msg_test_req_priv.pem", "r");
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
  EVP_PKEY_free(test_key);

  BIO * mismatch_key_bio;
  mismatch_key_bio = BIO_new_file("test/data/msg_test_resp_priv.pem", "r");
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
  EVP_PKEY_free(mismatch_key);

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

  // Clean-up
  free(test_der_cert);
  free(test_der_key);
  free(mismatch_der_key);
}

void test_verify_signature(void)
{
  pelz_log(LOG_DEBUG, "Start verify_signature() functionality test");

  int result = 0;

  char *test_data = "some signed data\0";
  size_t test_data_len = (size_t) (strlen(test_data) + 1);

  BIO *test_cert_bio = BIO_new_file("test/data/msg_test_req_pub.pem", "r");
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
  X509_free(test_cert);

  BIO * test_key_bio = BIO_new_file("test/data/msg_test_req_priv.pem", "r");
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
  EVP_PKEY_free(test_key);

  BIO *test_ca_cert_bio = BIO_new_file("test/data/ca_pub.pem", "r");
  if (test_ca_cert_bio == NULL)
  {
    CU_FAIL("error creating BIO for reading test CA cert from file");
  }
  X509 *test_ca_cert = PEM_read_bio_X509(test_ca_cert_bio, NULL, 0, NULL);
  if (test_ca_cert == NULL)
  {
    CU_FAIL("error creating X509 certificate for test CA");
  }
  BIO_free(test_ca_cert_bio);
  int test_der_ca_cert_len = -1;
  uint8_t *test_der_ca_cert = NULL;
  test_der_ca_cert_len = i2d_X509(test_ca_cert, &test_der_ca_cert);
  if ((test_der_ca_cert == NULL) || (test_der_ca_cert_len <= 0))
  {
    CU_FAIL("error creating DER-formatted test CA certificate");
  }
  X509_free(test_ca_cert);

  // NULL input data should run NULL signed message input test case
  test_verify_signature_helper(eid,
                               &result,
                               test_data_len,
                               NULL,
                               (size_t) test_der_cert_len,
                               test_der_cert,
                               test_der_key_len,
                               test_der_key,
                               (size_t) test_der_ca_cert_len,
                               NULL);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // NULL CA cert case should run remaining invalid parameter tests
  test_verify_signature_helper(eid,
                               &result,
                               test_data_len,
                               (uint8_t *) test_data,
                               (size_t) test_der_cert_len,
                               test_der_cert,
                               test_der_key_len,
                               test_der_key,
                               (size_t) test_der_ca_cert_len,
                               NULL);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // valid test data should invoke succcessful signature verification test case
  test_verify_signature_helper(eid,
                               &result,
                               test_data_len,
                               (uint8_t *) test_data,
                               (size_t) test_der_cert_len,
                               test_der_cert,
                               test_der_key_len,
                               test_der_key,
                               (size_t) test_der_ca_cert_len,
                               test_der_ca_cert);
  CU_ASSERT(result == MSG_TEST_SUCCESS);

  // Incorrect CA cert should fail
  test_verify_signature_helper(eid,
                               &result,
                               test_data_len,
                               (uint8_t *) test_data,
                               (size_t) test_der_cert_len,
                               test_der_cert,
                               test_der_key_len,
                               test_der_key,
                               (size_t) test_der_cert_len,
                               test_der_cert);
  CU_ASSERT(result == MSG_TEST_VERIFY_FAILURE);

  // Clean-up
  free(test_der_cert);
  free(test_der_key);
  free(test_der_ca_cert);
}

void test_der_encode_pelz_msg(void)
{
  pelz_log(LOG_DEBUG, "Start pelz message DER encoding functionality test");

  int result = 0;

  // test that NULL input message is handled as expected
  test_der_encode_pelz_msg_helper(eid,
                                  &result,
                                  REQUEST,
                                  AES_KEY_WRAP,
                                  15,
                                  (uint8_t *) "file://test.key",
                                  25,
                                  (uint8_t *) "ASN1 DER-encode test data",
                                  17,
                                  (uint8_t *) "DER-encode status",
                                  DER_ENCODE_PELZ_MSG_NULL_MSG_IN_TEST);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // test that NULL pointer to output buffer pointer is handled as expected
  test_der_encode_pelz_msg_helper(eid,
                                  &result,
                                  REQUEST,
                                  AES_KEY_WRAP,
                                  15,
                                  (uint8_t *) "file://test.key",
                                  25,
                                  (uint8_t *) "ASN1 DER-encode test data",
                                  17,
                                  (uint8_t *) "DER-encode status",
                                  DER_ENCODE_PELZ_MSG_NULL_OUT_BUF_TEST);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // basic test with valid (raw PELZ_MSG encoded) test input
  // should produce expected encoded result
  test_der_encode_pelz_msg_helper(eid,
                                  &result,
                                  REQUEST,
                                  AES_KEY_WRAP,
                                  15,
                                  (uint8_t *) "file://test.key",
                                  25,
                                  (uint8_t *) "ASN1 DER-encode test data",
                                  17,
                                  (uint8_t *) "DER-encode status",
                                  DER_ENCODE_RAW_PELZ_MSG_BASIC_TEST);
  CU_ASSERT(result == MSG_TEST_SUCCESS);

  // basic test (CMS encoded message input) with valid test input
  // should produce expected encoded result
  test_der_encode_pelz_msg_helper(eid,
                                  &result,
                                  REQUEST,
                                  AES_KEY_WRAP,
                                  15,
                                  (uint8_t *) "file://test.key",
                                  25,
                                  (uint8_t *) "ASN1 DER-encode test data",
                                  17,
                                  (uint8_t *) "DER-encode status",
                                  DER_ENCODE_CMS_PELZ_MSG_BASIC_TEST);
  CU_ASSERT(result == MSG_TEST_SUCCESS);
}

void test_der_decode_pelz_msg(void)
{
  pelz_log(LOG_DEBUG, "Start der_decode_pelz_msg() functionality test");

  int result = 0;

  // test that NULL pointer to input byte array is handled as expected
  test_der_decode_pelz_msg_helper(eid,
                                  &result,
                                  REQUEST,
                                  AES_KEY_WRAP,
                                  15,
                                  (uint8_t *) "file://test.key",
                                  25,
                                  (uint8_t *) "ASN1 DER-decode test data",
                                  17,
                                  (uint8_t *) "DER-decode status",
                                  DER_DECODE_PELZ_MSG_NULL_BYTES_IN_TEST);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // test that empty input byte array is handled as expected
  test_der_decode_pelz_msg_helper(eid,
                                  &result,
                                  REQUEST,
                                  AES_KEY_WRAP,
                                  15,
                                  (uint8_t *) "file://test.key",
                                  25,
                                  (uint8_t *) "ASN1 DER-decode test data",
                                  17,
                                  (uint8_t *) "DER-decode status",
                                  DER_DECODE_PELZ_MSG_EMPTY_BYTES_IN_TEST);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // test that negative length input byte array is handled as expected
  test_der_decode_pelz_msg_helper(eid,
                                  &result,
                                  REQUEST,
                                  AES_KEY_WRAP,
                                  15,
                                  (uint8_t *) "file://test.key",
                                  25,
                                  (uint8_t *) "ASN1 DER-decode test data",
                                  17,
                                  (uint8_t *) "DER-decode status",
                                  DER_DECODE_PELZ_MSG_NEG_BYTES_IN_LEN_TEST);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // basic test with valid input should produce expected message output
  test_der_decode_pelz_msg_helper(eid,
                                  &result,
                                  REQUEST,
                                  AES_KEY_WRAP,
                                  15,
                                  (uint8_t *) "file://test.key",
                                  25,
                                  (uint8_t *) "ASN1 DER-decode test data",
                                  17,
                                  (uint8_t *) "DER-decode status",
                                  DER_DECODE_RAW_PELZ_MSG_BASIC_TEST);
  CU_ASSERT(result == MSG_TEST_SUCCESS);

  // basic test with valid input should produce expected message output
  test_der_decode_pelz_msg_helper(eid,
                                  &result,
                                  REQUEST,
                                  AES_KEY_WRAP,
                                  15,
                                  (uint8_t *) "file://test.key",
                                  25,
                                  (uint8_t *) "ASN1 DER-decode test data",
                                  17,
                                  (uint8_t *) "DER-decode status",
                                  DER_DECODE_CMS_PELZ_MSG_BASIC_TEST);
  CU_ASSERT(result == MSG_TEST_SUCCESS);
}

