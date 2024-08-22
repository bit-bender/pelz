/*
 * pelz_messaging_suite.c
 */

#include "pelz_messaging_test_suite.h"


// Adds all pelz messaging tests to main test runner.
int pelz_messaging_suite_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite, "pelz ASN.1 formatted message creation",
                                 test_create_pelz_asn1_msg))
  {
    return 1;
  }
  
  if (NULL == CU_add_test(suite, "pelz ASN.1 formatted message parsing",
                                 test_parse_pelz_asn1_msg))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "pelz signed CMS message creation",
                                 test_create_pelz_signed_msg))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "pelz signed CMS message verification",
                                 test_verify_pelz_signed_msg))
  {
    return 1;
  }
  
  if (NULL == CU_add_test(suite, "pelz enveloped CMS message creation",
                                 test_create_pelz_enveloped_msg))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "pelz enveloped CMS message decryption",
                                 test_decrypt_pelz_enveloped_msg))
  {
    return 1;
  }
  
  if (NULL == CU_add_test(suite, "pelz message DER encode functionality",
                                 test_der_encode_pelz_msg))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "pelz message DER decode functionality",
                                 test_der_decode_pelz_msg))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "end-to-end pelz messaging functionality",
                                 test_construct_deconstruct_pelz_msg))
  {
    return 1;
  }

  return 0;
}


void test_create_pelz_asn1_msg(void)
{
  pelz_log(LOG_DEBUG, "Start ASN.1 pelz message creation tests");

  int result = MSG_TEST_UNKNOWN_ERROR;

  // specify test pelz test field values
  PELZ_MSG_TYPE test_msg_type = REQUEST;
  PELZ_REQ_TYPE test_req_type = KEY_WRAP;
  unsigned char *test_cipher = NULL;
  sprintf((char *) test_cipher, "AES/KeyWrap/RFC3394NoPadding/128");
  size_t test_cipher_size = strlen((char *) test_cipher);
  unsigned char *test_key_id = NULL;
  sprintf((char *) test_key_id, "file://test.key");
  size_t test_key_id_size = strlen((char *) test_key_id);
  unsigned char *test_data = NULL;
  sprintf((char *) test_data, "create ASN.1 message test data");
  size_t test_data_size = strlen((char *) test_data);
  unsigned char *test_status = NULL;
  sprintf((char *) test_status, "some kind of status");
  size_t test_status_size = strlen((char *) test_status);

  // invalid (less than MSG_TYPE_MIN) message type should fail param checks
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        MSG_TYPE_MIN - 1, test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_ASN1_CREATE_ERROR);

  // invalid (greater than MSG_TYPE_MAX) message type should fail param checks
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        MSG_TYPE_MAX + 1, test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_ASN1_CREATE_ERROR);

  // invalid (less than REQ_TYPE_MIN) message type should fail param checks
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        test_msg_type, REQ_TYPE_MIN - 1,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_ASN1_CREATE_ERROR);

  // invalid (greater than REQ_TYPE_MAX) message type should fail param checks
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        test_msg_type, REQ_TYPE_MAX + 1,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_ASN1_CREATE_ERROR);

  // null cipher input should fail param checks
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        test_msg_type, test_req_type,
                                        test_cipher_size, NULL,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_ASN1_CREATE_ERROR);

  // empty (zero-length) cipher input should fail param checks
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        test_msg_type, test_req_type,
                                        0, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_ASN1_CREATE_ERROR);

  // null KEK key ID input should fail param checks
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        test_msg_type, test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, NULL,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_ASN1_CREATE_ERROR);

  // empty (zero-length) KEK key ID input should fail param checks
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        test_msg_type, test_req_type,
                                        test_cipher_size, test_cipher,
                                        0, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_ASN1_CREATE_ERROR);

  // null data input should fail param checks
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        test_msg_type, test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, NULL,
                                        test_status_size, test_status,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_ASN1_CREATE_ERROR);

  // empty (zero-length) data input should fail param checks
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        test_msg_type, test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        0, test_data,
                                        test_status_size, test_status,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_ASN1_CREATE_ERROR);

  // null status input should fail param checks
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        test_msg_type, test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_ASN1_CREATE_ERROR);

  // empty (zero-length) status input should fail param checks
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        test_msg_type, test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        0, test_status,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_ASN1_CREATE_ERROR);

  // ASN.1 message creation test case with valid parameters should not error
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        test_msg_type, test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_OK);

  // Clean-up
  free(test_cipher);
  free(test_key_id);
  free(test_data);
  free(test_status);
}

void test_parse_pelz_asn1_msg(void)
{
  pelz_log(LOG_DEBUG, "Start parse_pelz_asn1_msg() functionality test");

  int result = MSG_TEST_UNKNOWN_ERROR;

  // specify test pelz test field values
  PELZ_MSG_TYPE test_msg_type = REQUEST;
  PELZ_REQ_TYPE test_req_type = KEY_WRAP;
  unsigned char *test_cipher = NULL;
  sprintf((char *) test_cipher, "AES/KeyWrap/RFC3394NoPadding/128");
  size_t test_cipher_size = strlen((char *) test_cipher);
  unsigned char *test_key_id = NULL;
  sprintf((char *) test_key_id, "file://test.key");
  size_t test_key_id_size = strlen((char *) test_key_id);
  unsigned char *test_data = NULL;
  sprintf((char *) test_data, "create ASN.1 message test data");
  size_t test_data_size = strlen((char *) test_data);
  unsigned char *test_status = NULL;
  sprintf((char *) test_status, "some kind of status");
  size_t test_status_size = strlen((char *) test_status);

  // invalid 'message type' field tag should result in parse error
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        test_msg_type, test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_INVALID_MSG_TYPE_TAG);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // invalid message type field value (< MSG_TYPE_MIN) should error
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        test_msg_type, test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_INVALID_MSG_TYPE_LO);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // invalid message type field value (> MSG_TYPE_MAX) should error
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        test_msg_type, test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_INVALID_MSG_TYPE_HI);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // invalid req_type field tag should result in parse error
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        test_msg_type, test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_INVALID_REQ_TYPE_TAG);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // invalid request type field value (< REQ_TYPE_MIN) should error
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        test_msg_type, test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_INVALID_REQ_TYPE_LO);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // invalid request type field value (> REQ_TYPE_MAX) should error
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        test_msg_type, test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_INVALID_REQ_TYPE_HI);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // invalid cipher field tag should result in parse error
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        test_msg_type, test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_INVALID_CIPHER_TAG);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // invalid key ID field tag should result in parse error
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        test_msg_type, test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_INVALID_KEY_ID_TAG);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // invalid data field tag should result in parse error
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        test_msg_type, test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_INVALID_DATA_TAG);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // invalid status field tag should result in parse error
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        test_msg_type, test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_INVALID_STATUS_TAG);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // valid (unmodified) message format/contents should parse successfully
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        test_msg_type, test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_OK);

  // Clean-up
  free(test_cipher);
  free(test_key_id);
  free(test_data);
  free(test_status);
}

void test_create_pelz_signed_msg(void)
{
  pelz_log(LOG_DEBUG, "Start create_pelz_signed_msg() functionality test");

  int result = MSG_TEST_UNKNOWN_ERROR;

  // specify test pelz test field values
  PELZ_MSG_TYPE test_msg_type = REQUEST;
  PELZ_REQ_TYPE test_req_type = KEY_WRAP;
  unsigned char *test_cipher = NULL;
  sprintf((char *) test_cipher, "AES/KeyWrap/RFC3394NoPadding/128");
  size_t test_cipher_size = strlen((char *) test_cipher);
  unsigned char *test_key_id = NULL;
  sprintf((char *) test_key_id, "file://test.key");
  size_t test_key_id_size = strlen((char *) test_key_id);
  unsigned char *test_data = NULL;
  sprintf((char *) test_data, "create signed message test data");
  size_t test_data_size = strlen((char *) test_data);
  unsigned char *test_status = NULL;
  sprintf((char *) test_status, "some kind of status");
  size_t test_status_size = strlen((char *) test_status);

  // create test cert/key inputs
  charbuf test_cert = { .chars = NULL, .len = 0 };
  charbuf test_priv = { .chars = NULL, .len = 0 };
  charbuf mismatch_priv = { .chars = NULL, .len = 0 };
  result = pem_cert_to_der("test/data/msg_test_req_pub.pem", &test_cert);
  if (result != 0)
  {
    CU_FAIL("DER cert from file (test/data/msg_test_req_pub.pem) error");
  }
  result = pem_priv_to_der("test/data/msg_test_req_priv.pem", &test_priv);
  if (result != 0)
  {
    CU_FAIL("DER key from file (test/data/msg_test_req_priv.pem) error");
  }
  result = pem_priv_to_der("test/data/msg_test_resp_priv.pem", &test_priv);
  if (result != 0)
  {
    CU_FAIL("DER key from file (test/data/msg_test_resp_priv.pem) error");
  }

  // NULL input data  pointer test case - invalid parameter should be handled
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        test_priv.len, test_priv.chars,
                                        test_cert.len, test_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_SIGN_NULL_BUF_IN);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // Empty input data buffer test cases - invalid parameter should be handled
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        test_priv.len, test_priv.chars,
                                        test_cert.len, test_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_SIGN_EMPTY_BUF_IN);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // Invalid size input data buffer test case - invalid parameter should be handled
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        test_priv.len, test_priv.chars,
                                        test_cert.len, test_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_SIGN_INVALID_SIZE_BUF_IN);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // NULL cert test case - invalid parameter should be handled
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        test_priv.len, test_priv.chars,
                                        test_cert.len, test_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_SIGN_NULL_CERT_IN);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // NULL private signing key should fail
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        test_priv.len, test_priv.chars,
                                        test_cert.len, test_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_SIGN_NULL_PRIV_IN);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // valid test case should pass
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        test_priv.len, test_priv.chars,
                                        test_cert.len, test_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_SIGN_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_OK);

  // Mismatched key/cert should fail
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        mismatch_priv.len, mismatch_priv.chars,
                                        test_cert.len, test_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_SIGN_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_SETUP_ERROR);

  // Clean-up
  free(test_cipher);
  free(test_key_id);
  free(test_data);
  free(test_status);
  free_charbuf(&test_cert);
  free_charbuf(&test_priv);
  free_charbuf(&mismatch_priv);
}

void test_verify_pelz_signed_msg(void)
{
  pelz_log(LOG_DEBUG, "Start verify_pelz_signed_msg() functionality test");

  int result = MSG_TEST_UNKNOWN_ERROR;

  // specify test pelz test field values
  PELZ_MSG_TYPE test_msg_type = REQUEST;
  PELZ_REQ_TYPE test_req_type = KEY_WRAP;
  unsigned char *test_cipher = NULL;
  sprintf((char *) test_cipher, "AES/KeyWrap/RFC3394NoPadding/128");
  size_t test_cipher_size = strlen((char *) test_cipher);
  unsigned char *test_key_id = NULL;
  sprintf((char *) test_key_id, "file://test.key");
  size_t test_key_id_size = strlen((char *) test_key_id);
  unsigned char *test_data = NULL;
  sprintf((char *) test_data, "verify signed message test data");
  size_t test_data_size = strlen((char *) test_data);
  unsigned char *test_status = NULL;
  sprintf((char *) test_status, "some kind of status");
  size_t test_status_size = strlen((char *) test_status);

  // create test cert/key inputs
  charbuf test_cert = { .chars = NULL, .len = 0 };
  charbuf test_priv = { .chars = NULL, .len = 0 };
  result = pem_cert_to_der("test/data/msg_test_req_pub.pem", &test_cert);
  if (result != 0)
  {
    CU_FAIL("DER cert from file (test/data/msg_test_req_pub.pem) error");
  }
  result = pem_priv_to_der("test/data/msg_test_req_priv.pem", &test_priv);
  if (result != 0)
  {
    CU_FAIL("DER key from file (test/data/msg_test_req_priv.pem) error");
  }

  // load CA cert into enclave table
  TableResponseStatus status;
  uint64_t handle = 0;

  if (pelz_load_file_to_enclave("test/data/ca_pub.der.nkl", &handle) == 0)
  {
    add_cert_to_table(eid, &status, CA_TABLE, handle);
    CU_ASSERT(status == OK);
    pelz_log(LOG_INFO, "CA Table add complete");
    handle = 0;
  }
  size_t ca_cnt = 0;
  table_id_count(eid, &status, CA_TABLE, &ca_cnt);
  pelz_log(LOG_DEBUG, "CA table size = %zu", ca_cnt);

  // NULL signed message input test case
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        test_priv.len, test_priv.chars,
                                        test_cert.len, test_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_VERIFY_NULL_MSG_IN);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // NULL output certificate double pointer test case
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        test_priv.len, test_priv.chars,
                                        test_cert.len, test_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_VERIFY_NULL_BUF_OUT);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // NULL output certificate test case
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        test_priv.len, test_priv.chars,
                                        test_cert.len, test_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_VERIFY_NULL_CERT_OUT);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // valid test data should invoke succcessful signature verification test case
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        test_priv.len, test_priv.chars,
                                        test_cert.len, test_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_VERIFY_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_OK);

  // Incorrect CA cert should fail
  if (empty_CA_table(eid, NULL) != 0)
  {
    CU_FAIL("error emptying CA table");
  }
  if (pelz_load_file_to_enclave("test/data/msg_test_req_pub.der.nkl",
                                &handle) == 0)
  {
    add_cert_to_table(eid, &status, CA_TABLE, handle);
    CU_ASSERT(status == OK);
    pelz_log(LOG_INFO, "CA Table add complete");
    handle = 0;
  }
  ca_cnt = 0;
  table_id_count(eid, &status, CA_TABLE, &ca_cnt);
  pelz_log(LOG_DEBUG, "CA table size = %zu", ca_cnt);

  result = pelz_enclave_msg_test_helper(eid, &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        test_priv.len, test_priv.chars,
                                        test_cert.len, test_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_VERIFY_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_VERIFY_ERROR);

  // Clean-up
  free(test_cipher);
  free(test_key_id);
  free(test_data);
  free(test_status);
  free_charbuf(&test_cert);
  free_charbuf(&test_priv);
  if (empty_CA_table(eid, NULL) != 0)
  {
    CU_FAIL("error emptying CA table");
  }
}

void test_create_pelz_enveloped_msg(void)
{
  pelz_log(LOG_DEBUG, "Start create_pelz_enveloped_msg() functionality test");

  int result = MSG_TEST_UNKNOWN_ERROR;

  // specify test pelz test field values
  PELZ_MSG_TYPE test_msg_type = REQUEST;
  PELZ_REQ_TYPE test_req_type = KEY_WRAP;
  unsigned char *test_cipher = NULL;
  sprintf((char *) test_cipher, "AES/KeyWrap/RFC3394NoPadding/128");
  size_t test_cipher_size = strlen((char *) test_cipher);
  unsigned char *test_key_id = NULL;
  sprintf((char *) test_key_id, "file://test.key");
  size_t test_key_id_size = strlen((char *) test_key_id);
  unsigned char *test_data = NULL;
  sprintf((char *) test_data, "create enveloped message test data");
  size_t test_data_size = strlen((char *) test_data);
  unsigned char *test_status = NULL;
  sprintf((char *) test_status, "some kind of status");
  size_t test_status_size = strlen((char *) test_status);

  // create test cert/key inputs
  charbuf test_sign_priv = { .chars = NULL, .len = 0 };
  charbuf test_verify_cert = { .chars = NULL, .len = 0 };
  charbuf test_encrypt_cert = { .chars = NULL, .len = 0 };
  charbuf test_decrypt_priv = { .chars = NULL, .len = 0 };
  result = pem_priv_to_der("test/data/msg_test_req_priv.pem", &test_sign_priv);
  if (result != 0)
  {
    CU_FAIL("DER key from file (test/data/msg_test_req_priv.pem) error");
  }
  result = pem_cert_to_der("test/data/msg_test_req_pub.pem", &test_verify_cert);
  if (result != 0)
  {
    CU_FAIL("DER cert from file (test/data/msg_test_req_pub.pem) error");
  }
  result = pem_cert_to_der("test/data/msg_test_resp_pub.pem",
                           &test_encrypt_cert);
  if (result != 0)
  {
    CU_FAIL("DER cert from file (test/data/msg_test_resp_pub.pem) error");
  }
  result = pem_priv_to_der("test/data/msg_test_resp_priv.pem",
                           &test_decrypt_priv);
  if (result != 0)
  {
    CU_FAIL("DER key from file (test/data/msg_test_resp_priv.pem) error");
  }

  // NULL input data should be handled as invalid parameter
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        test_sign_priv.len,
                                        test_sign_priv.chars,
                                        test_verify_cert.len,
                                        test_verify_cert.chars,
                                        test_encrypt_cert.len,
                                        test_encrypt_cert.chars,
                                        test_decrypt_priv.len,
                                        test_decrypt_priv.chars,
                                        CMS_ENCRYPT_NULL_BUF_IN);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // empty input data should be handled as invalid parameter
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        test_sign_priv.len,
                                        test_sign_priv.chars,
                                        test_verify_cert.len,
                                        test_verify_cert.chars,
                                        test_encrypt_cert.len,
                                        test_encrypt_cert.chars,
                                        test_decrypt_priv.len,
                                        test_decrypt_priv.chars,
                                        CMS_ENCRYPT_EMPTY_BUF_IN);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // invalid size input data should be handled as invalid parameter
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        test_sign_priv.len,
                                        test_sign_priv.chars,
                                        test_verify_cert.len,
                                        test_verify_cert.chars,
                                        test_encrypt_cert.len,
                                        test_encrypt_cert.chars,
                                        test_decrypt_priv.len,
                                        test_decrypt_priv.chars,
                                        CMS_ENCRYPT_INVALID_SIZE_BUF_IN);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // NULL input certificate should be handled as invalid parameter
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        test_sign_priv.len,
                                        test_sign_priv.chars,
                                        test_verify_cert.len,
                                        test_verify_cert.chars,
                                        test_encrypt_cert.len,
                                        test_encrypt_cert.chars,
                                        test_decrypt_priv.len,
                                        test_decrypt_priv.chars,
                                        CMS_ENCRYPT_NULL_CERT_IN);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // valid test case should pass
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        test_sign_priv.len,
                                        test_sign_priv.chars,
                                        test_verify_cert.len,
                                        test_verify_cert.chars,
                                        test_encrypt_cert.len,
                                        test_encrypt_cert.chars,
                                        test_decrypt_priv.len,
                                        test_decrypt_priv.chars,
                                        CMS_ENCRYPT_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_OK);
}

void test_decrypt_pelz_enveloped_msg(void)
{
  pelz_log(LOG_DEBUG, "Start decrypt_pelz_enveloped_msg() functionality test");

  int result = MSG_TEST_UNKNOWN_ERROR;

  // specify test pelz test field values
  PELZ_MSG_TYPE test_msg_type = REQUEST;
  PELZ_REQ_TYPE test_req_type = KEY_WRAP;
  unsigned char *test_cipher = NULL;
  sprintf((char *) test_cipher, "AES/KeyWrap/RFC3394NoPadding/128");
  size_t test_cipher_size = strlen((char *) test_cipher);
  unsigned char *test_key_id = NULL;
  sprintf((char *) test_key_id, "file://test.key");
  size_t test_key_id_size = strlen((char *) test_key_id);
  unsigned char *test_data = NULL;
  sprintf((char *) test_data, "create enveloped message test data");
  size_t test_data_size = strlen((char *) test_data);
  unsigned char *test_status = NULL;
  sprintf((char *) test_status, "some kind of status");
  size_t test_status_size = strlen((char *) test_status);

  // create test cert/key inputs
  charbuf test_sign_priv = { .chars = NULL, .len = 0 };
  charbuf test_verify_cert = { .chars = NULL, .len = 0 };
  charbuf test_encrypt_cert = { .chars = NULL, .len = 0 };
  charbuf test_decrypt_priv = { .chars = NULL, .len = 0 };
  result = pem_priv_to_der("test/data/msg_test_req_priv.pem", &test_sign_priv);
  if (result != 0)
  {
    CU_FAIL("DER key from file (test/data/msg_test_req_priv.pem) error");
  }
  result = pem_cert_to_der("test/data/msg_test_req_pub.pem", &test_verify_cert);
  if (result != 0)
  {
    CU_FAIL("DER cert from file (test/data/msg_test_req_pub.pem) error");
  }
  result = pem_cert_to_der("test/data/msg_test_resp_pub.pem",
                           &test_encrypt_cert);
  if (result != 0)
  {
    CU_FAIL("DER cert from file (test/data/msg_test_resp_pub.pem) error");
  }
  result = pem_priv_to_der("test/data/msg_test_resp_priv.pem",
                           &test_decrypt_priv);
  if (result != 0)
  {
    CU_FAIL("DER key from file (test/data/msg_test_resp_priv.pem) error");
  }

  // NULL input message test case
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        test_sign_priv.len,
                                        test_sign_priv.chars,
                                        test_verify_cert.len,
                                        test_verify_cert.chars,
                                        test_encrypt_cert.len,
                                        test_encrypt_cert.chars,
                                        test_decrypt_priv.len,
                                        test_decrypt_priv.chars,
                                        CMS_DECRYPT_NULL_MSG_IN);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // NULL output buffer test case
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        test_sign_priv.len,
                                        test_sign_priv.chars,
                                        test_verify_cert.len,
                                        test_verify_cert.chars,
                                        test_encrypt_cert.len,
                                        test_encrypt_cert.chars,
                                        test_decrypt_priv.len,
                                        test_decrypt_priv.chars,
                                        CMS_DECRYPT_NULL_BUF_OUT);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // NULL input private key test case
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        test_sign_priv.len,
                                        test_sign_priv.chars,
                                        test_verify_cert.len,
                                        test_verify_cert.chars,
                                        test_encrypt_cert.len,
                                        test_encrypt_cert.chars,
                                        test_decrypt_priv.len,
                                        test_decrypt_priv.chars,
                                        CMS_DECRYPT_NULL_PRIV);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // NULL input cert test case
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        test_sign_priv.len,
                                        test_sign_priv.chars,
                                        test_verify_cert.len,
                                        test_verify_cert.chars,
                                        test_encrypt_cert.len,
                                        test_encrypt_cert.chars,
                                        test_decrypt_priv.len,
                                        test_decrypt_priv.chars,
                                        CMS_DECRYPT_NULL_CERT);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // valid test data should invoke succcessful CMS decryption test case
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        test_sign_priv.len,
                                        test_sign_priv.chars,
                                        test_verify_cert.len,
                                        test_verify_cert.chars,
                                        test_encrypt_cert.len,
                                        test_encrypt_cert.chars,
                                        test_decrypt_priv.len,
                                        test_decrypt_priv.chars,
                                        CMS_DECRYPT_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_OK);

  // wrong input private decryption key test case
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher_size, test_cipher,
                                        test_key_id_size, test_key_id,
                                        test_data_size, test_data,
                                        test_status_size, test_status,
                                        test_sign_priv.len,
                                        test_sign_priv.chars,
                                        test_verify_cert.len,
                                        test_verify_cert.chars,
                                        test_encrypt_cert.len,
                                        test_encrypt_cert.chars,
                                        test_sign_priv.len,
                                        test_sign_priv.chars,
                                        CMS_DECRYPT_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_DECRYPT_ERROR);
}

void test_der_encode_pelz_msg(void)
{
  pelz_log(LOG_DEBUG, "Start pelz message DER encoding functionality test");

  TableResponseStatus status;
  uint64_t handle = 0;
  int result = -1;

  if (pelz_load_file_to_enclave("test/data/ca_pub.der.nkl", &handle) == 0)
  {
    add_cert_to_table(eid, &status, CA_TABLE, handle);
    CU_ASSERT(status == OK);
    pelz_log(LOG_INFO, "CA Table add complete");
    handle = 0;
  }
  size_t ca_cnt = 0;
  table_id_count(eid, &status, CA_TABLE, &ca_cnt);
  pelz_log(LOG_DEBUG, "CA table size = %zu", ca_cnt);

  BIO *test_req_cert_bio = BIO_new_file("test/data/msg_test_req_pub.pem", "r");
  if (test_req_cert_bio == NULL)
  {
    CU_FAIL("error creating BIO for reading test requestor cert from file");
  }
  X509 *test_req_cert = PEM_read_bio_X509(test_req_cert_bio, NULL, 0, NULL);
  if (test_req_cert == NULL)
  {
    CU_FAIL("error creating test X509 certificate for requestor");
  }
  BIO_free(test_req_cert_bio);
  size_t test_der_req_cert_len = 0;
  uint8_t *test_der_req_cert = NULL;
  test_der_req_cert_len = (size_t) i2d_X509(test_req_cert,
                                            &test_der_req_cert);
  if ((test_der_req_cert == NULL) || (test_der_req_cert_len == 0))
  {
    CU_FAIL("error creating DER-formatted test requestor certificate");
  }
  X509_free(test_req_cert);

  BIO * test_req_key_bio = BIO_new_file("test/data/msg_test_req_priv.pem", "r");
  if (test_req_key_bio == NULL)
  {
    CU_FAIL("error creating BIO for reading test requestor key from file");
  }
  EVP_PKEY * test_req_key = PEM_read_bio_PrivateKey(test_req_key_bio,
                                                    NULL,
                                                    0,
                                                    NULL);
  if (test_req_key == NULL)
  {
    CU_FAIL("error creating test requestor EC private key for signing");
  }
  BIO_free(test_req_key_bio);
  size_t test_der_req_key_len = 0;
  uint8_t *test_der_req_key = NULL;
  test_der_req_key_len = (size_t) i2d_PrivateKey(test_req_key,
                                                 &test_der_req_key);
  if ((test_der_req_key == NULL) || (test_der_req_key_len == 0))
  {
    CU_FAIL("error creating DER-formatted test requestor EC private key");
  }
  EVP_PKEY_free(test_req_key);

  BIO *test_resp_cert_bio = BIO_new_file("test/data/msg_test_resp_pub.pem", "r");
  if (test_resp_cert_bio == NULL)
  {
    CU_FAIL("error creating BIO for reading test responder cert from file");
  }
  X509 *test_resp_cert = PEM_read_bio_X509(test_resp_cert_bio, NULL, 0, NULL);
  if (test_resp_cert == NULL)
  {
    CU_FAIL("error creating test X509 certificate for responder");
  }
  BIO_free(test_resp_cert_bio);
  size_t test_der_resp_cert_len = 0;
  uint8_t *test_der_resp_cert = NULL;
  test_der_resp_cert_len = (size_t) i2d_X509(test_resp_cert,
                                             &test_der_resp_cert);
  if ((test_der_resp_cert == NULL) || (test_der_resp_cert_len == 0))
  {
    CU_FAIL("error creating DER-formatted test responder certificate");
  }
  X509_free(test_resp_cert);

  BIO * test_resp_key_bio = BIO_new_file("test/data/msg_test_resp_priv.pem", "r");
  if (test_resp_key_bio == NULL)
  {
    CU_FAIL("error creating BIO for reading test responder key from file");
  }
  EVP_PKEY * test_resp_key = PEM_read_bio_PrivateKey(test_resp_key_bio,
                                                     NULL,
                                                     0,
                                                     NULL);
  if (test_resp_key == NULL)
  {
    CU_FAIL("error creating test responder EC private key");
  }
  BIO_free(test_resp_key_bio);
  size_t test_der_resp_key_len = 0;
  uint8_t *test_der_resp_key = NULL;
  test_der_resp_key_len = (size_t) i2d_PrivateKey(test_resp_key,
                                                  &test_der_resp_key);
  if ((test_der_resp_key == NULL) || (test_der_resp_key_len == 0))
  {
    CU_FAIL("error creating DER-formatted test responder EC private key");
  }
  EVP_PKEY_free(test_resp_key);

  // ASN.1 DER encode: test that NULL input message is handled as expected
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        REQUEST, KEY_UNWRAP,
                                        32, (unsigned char *) "AES/KeyWrap/RFC3394NoPadding/128",
                                        15, (unsigned char *) "file://test.key",
                                        14, (unsigned char *) "Test,test,test",
                                        11, (unsigned char *) "some status",
                                        test_der_req_key_len, test_der_req_key,
                                        test_der_req_cert_len, test_der_req_cert,
                                        test_der_resp_cert_len, test_der_resp_cert,
                                        test_der_resp_key_len, test_der_resp_key,
                                        ASN1_CREATE_DER_ENCODE_NULL_MSG_IN);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // ASN.1 DER encode: test that NULL output buffer pointer is handled as expected
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        REQUEST, KEY_UNWRAP,
                                        32, (unsigned char *) "AES/KeyWrap/RFC3394NoPadding/128",
                                        15, (unsigned char *) "file://test.key",
                                        14, (unsigned char *) "Test,test,test",
                                        11, (unsigned char *) "some status",
                                        test_der_req_key_len, test_der_req_key,
                                        test_der_req_cert_len, test_der_req_cert,
                                        test_der_resp_cert_len, test_der_resp_cert,
                                        test_der_resp_key_len, test_der_resp_key,
                                        ASN1_CREATE_DER_ENCODE_NULL_BUF_OUT);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // ASN.1 DER encode: test with valid test input should produce expected encoded result
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        REQUEST, KEY_UNWRAP,
                                        32, (unsigned char *) "AES/KeyWrap/RFC3394NoPadding/128",
                                        15, (unsigned char *) "file://test.key",
                                        14, (unsigned char *) "Test,test,test",
                                        11, (unsigned char *) "some status",
                                        test_der_req_key_len, test_der_req_key,
                                        test_der_req_cert_len, test_der_req_cert,
                                        test_der_resp_cert_len, test_der_resp_cert,
                                        test_der_resp_key_len, test_der_resp_key,
                                        ASN1_CREATE_DER_ENCODE_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_OK);

  // DER encode signed CMS: test that NULL input message is handled as expected
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        REQUEST, KEY_UNWRAP,
                                        32, (unsigned char *) "AES/KeyWrap/RFC3394NoPadding/128",
                                        15, (unsigned char *) "file://test.key",
                                        14, (unsigned char *) "Test,test,test",
                                        11, (unsigned char *) "some status",
                                        test_der_req_key_len, test_der_req_key,
                                        test_der_req_cert_len, test_der_req_cert,
                                        test_der_resp_cert_len, test_der_resp_cert,
                                        test_der_resp_key_len, test_der_resp_key,
                                        CMS_SIGN_DER_ENCODE_NULL_MSG_IN);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // DER encode signed CMS: test that NULL input message is handled as expected
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        REQUEST, KEY_UNWRAP,
                                        32, (unsigned char *) "AES/KeyWrap/RFC3394NoPadding/128",
                                        15, (unsigned char *) "file://test.key",
                                        14, (unsigned char *) "Test,test,test",
                                        11, (unsigned char *) "some status",
                                        test_der_req_key_len, test_der_req_key,
                                        test_der_req_cert_len, test_der_req_cert,
                                        test_der_resp_cert_len, test_der_resp_cert,
                                        test_der_resp_key_len, test_der_resp_key,
                                        CMS_SIGN_DER_ENCODE_NULL_BUF_OUT);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // DER encode signed CMS: test valid input produces expected encoded result
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        REQUEST, KEY_UNWRAP,
                                        32, (unsigned char *) "AES/KeyWrap/RFC3394NoPadding/128",
                                        15, (unsigned char *) "file://test.key",
                                        14, (unsigned char *) "Test,test,test",
                                        11, (unsigned char *) "some status",
                                        test_der_req_key_len, test_der_req_key,
                                        test_der_req_cert_len, test_der_req_cert,
                                        test_der_resp_cert_len, test_der_resp_cert,
                                        test_der_resp_key_len, test_der_resp_key,
                                        CMS_SIGN_DER_ENCODE_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_OK);

  // DER encode enveloped CMS: test that NULL input message is handled as expected
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        REQUEST, KEY_UNWRAP,
                                        32, (unsigned char *) "AES/KeyWrap/RFC3394NoPadding/128",
                                        15, (unsigned char *) "file://test.key",
                                        14, (unsigned char *) "Test,test,test",
                                        11, (unsigned char *) "some status",
                                        test_der_req_key_len, test_der_req_key,
                                        test_der_req_cert_len, test_der_req_cert,
                                        test_der_resp_cert_len, test_der_resp_cert,
                                        test_der_resp_key_len, test_der_resp_key,
                                        CMS_ENCRYPT_DER_ENCODE_NULL_MSG_IN);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // DER encode enveloped CMS: test that NULL input message is handled as expected
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        REQUEST, KEY_UNWRAP,
                                        32, (unsigned char *) "AES/KeyWrap/RFC3394NoPadding/128",
                                        15, (unsigned char *) "file://test.key",
                                        14, (unsigned char *) "Test,test,test",
                                        11, (unsigned char *) "some status",
                                        test_der_req_key_len, test_der_req_key,
                                        test_der_req_cert_len, test_der_req_cert,
                                        test_der_resp_cert_len, test_der_resp_cert,
                                        test_der_resp_key_len, test_der_resp_key,
                                        CMS_ENCRYPT_DER_ENCODE_NULL_BUF_OUT);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // DER encode enveloped CMS: test valid input produces expected encoded result
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        REQUEST, KEY_UNWRAP,
                                        32, (unsigned char *) "AES/KeyWrap/RFC3394NoPadding/128",
                                        15, (unsigned char *) "file://test.key",
                                        14, (unsigned char *) "Test,test,test",
                                        11, (unsigned char *) "some status",
                                        test_der_req_key_len, test_der_req_key,
                                        test_der_req_cert_len, test_der_req_cert,
                                        test_der_resp_cert_len, test_der_resp_cert,
                                        test_der_resp_key_len, test_der_resp_key,
                                        CMS_ENCRYPT_DER_ENCODE_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_OK);
}

void test_der_decode_pelz_msg(void)
{
  pelz_log(LOG_DEBUG, "Start der_decode_pelz_msg() functionality test");

  TableResponseStatus status;
  uint64_t handle = 0;
  int result = -1;

  if (pelz_load_file_to_enclave("test/data/ca_pub.der.nkl", &handle) == 0)
  {
    add_cert_to_table(eid, &status, CA_TABLE, handle);
    CU_ASSERT(status == OK);
    pelz_log(LOG_INFO, "CA Table add complete");
    handle = 0;
  }
  size_t ca_cnt = 0;
  table_id_count(eid, &status, CA_TABLE, &ca_cnt);
  pelz_log(LOG_DEBUG, "CA table size = %zu", ca_cnt);

  BIO *test_req_cert_bio = BIO_new_file("test/data/msg_test_req_pub.pem", "r");
  if (test_req_cert_bio == NULL)
  {
    CU_FAIL("error creating BIO for reading test requestor cert from file");
  }
  X509 *test_req_cert = PEM_read_bio_X509(test_req_cert_bio, NULL, 0, NULL);
  if (test_req_cert == NULL)
  {
    CU_FAIL("error creating test X509 certificate for requestor");
  }
  BIO_free(test_req_cert_bio);
  size_t test_der_req_cert_len = 0;
  uint8_t *test_der_req_cert = NULL;
  test_der_req_cert_len = (size_t) i2d_X509(test_req_cert,
                                            &test_der_req_cert);
  if ((test_der_req_cert == NULL) || (test_der_req_cert_len == 0))
  {
    CU_FAIL("error creating DER-formatted test requestor certificate");
  }
  X509_free(test_req_cert);

  BIO * test_req_key_bio = BIO_new_file("test/data/msg_test_req_priv.pem", "r");
  if (test_req_key_bio == NULL)
  {
    CU_FAIL("error creating BIO for reading test requestor key from file");
  }
  EVP_PKEY * test_req_key = PEM_read_bio_PrivateKey(test_req_key_bio,
                                                    NULL,
                                                    0,
                                                    NULL);
  if (test_req_key == NULL)
  {
    CU_FAIL("error creating test requestor EC private key for signing");
  }
  BIO_free(test_req_key_bio);
  size_t test_der_req_key_len = 0;
  uint8_t *test_der_req_key = NULL;
  test_der_req_key_len = (size_t) i2d_PrivateKey(test_req_key,
                                                 &test_der_req_key);
  if ((test_der_req_key == NULL) || (test_der_req_key_len == 0))
  {
    CU_FAIL("error creating DER-formatted test requestor EC private key");
  }
  EVP_PKEY_free(test_req_key);

  BIO *test_resp_cert_bio = BIO_new_file("test/data/msg_test_resp_pub.pem", "r");
  if (test_resp_cert_bio == NULL)
  {
    CU_FAIL("error creating BIO for reading test responder cert from file");
  }
  X509 *test_resp_cert = PEM_read_bio_X509(test_resp_cert_bio, NULL, 0, NULL);
  if (test_resp_cert == NULL)
  {
    CU_FAIL("error creating test X509 certificate for responder");
  }
  BIO_free(test_resp_cert_bio);
  size_t test_der_resp_cert_len = 0;
  uint8_t *test_der_resp_cert = NULL;
  test_der_resp_cert_len = (size_t) i2d_X509(test_resp_cert,
                                             &test_der_resp_cert);
  if ((test_der_resp_cert == NULL) || (test_der_resp_cert_len == 0))
  {
    CU_FAIL("error creating DER-formatted test responder certificate");
  }
  X509_free(test_resp_cert);

  BIO * test_resp_key_bio = BIO_new_file("test/data/msg_test_resp_priv.pem", "r");
  if (test_resp_key_bio == NULL)
  {
    CU_FAIL("error creating BIO for reading test responder key from file");
  }
  EVP_PKEY * test_resp_key = PEM_read_bio_PrivateKey(test_resp_key_bio,
                                                     NULL,
                                                     0,
                                                     NULL);
  if (test_resp_key == NULL)
  {
    CU_FAIL("error creating test responder EC private key");
  }
  BIO_free(test_resp_key_bio);
  size_t test_der_resp_key_len = 0;
  uint8_t *test_der_resp_key = NULL;
  test_der_resp_key_len = (size_t) i2d_PrivateKey(test_resp_key,
                                                  &test_der_resp_key);
  if ((test_der_resp_key == NULL) || (test_der_resp_key_len == 0))
  {
    CU_FAIL("error creating DER-formatted test responder EC private key");
  }
  EVP_PKEY_free(test_resp_key);

  // ASN.1 DER decode: test NULL pointer to input byte array handled
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        REQUEST, KEY_UNWRAP,
                                        32, (unsigned char *) "AES/KeyWrap/RFC3394NoPadding/128",
                                        15, (unsigned char *) "file://test.key",
                                        14, (unsigned char *) "Test,test,test",
                                        11, (unsigned char *) "some status",
                                        test_der_req_key_len, test_der_req_key,
                                        test_der_req_cert_len, test_der_req_cert,
                                        test_der_resp_cert_len, test_der_resp_cert,
                                        test_der_resp_key_len, test_der_resp_key,
                                        ASN1_PARSE_DER_DECODE_NULL_BUF_IN);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // ASN.1 DER decode: test empty input byte array handled
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        REQUEST, KEY_UNWRAP,
                                        32, (unsigned char *) "AES/KeyWrap/RFC3394NoPadding/128",
                                        15, (unsigned char *) "file://test.key",
                                        14, (unsigned char *) "Test,test,test",
                                        11, (unsigned char *) "some status",
                                        test_der_req_key_len, test_der_req_key,
                                        test_der_req_cert_len, test_der_req_cert,
                                        test_der_resp_cert_len, test_der_resp_cert,
                                        test_der_resp_key_len, test_der_resp_key,
                                        ASN1_PARSE_DER_DECODE_EMPTY_BUF_IN);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // ASN.1 DER decode: test invalid decoded message format parameter handled
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        REQUEST, KEY_UNWRAP,
                                        32, (unsigned char *) "AES/KeyWrap/RFC3394NoPadding/128",
                                        15, (unsigned char *) "file://test.key",
                                        14, (unsigned char *) "Test,test,test",
                                        11, (unsigned char *) "some status",
                                        test_der_req_key_len, test_der_req_key,
                                        test_der_req_cert_len, test_der_req_cert,
                                        test_der_resp_cert_len, test_der_resp_cert,
                                        test_der_resp_key_len, test_der_resp_key,
                                        ASN1_PARSE_DER_DECODE_INVALID_FORMAT);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // ASN.1 DER decode: test valid input produces expected message output
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        REQUEST, KEY_UNWRAP,
                                        32, (unsigned char *) "AES/KeyWrap/RFC3394NoPadding/128",
                                        15, (unsigned char *) "file://test.key",
                                        14, (unsigned char *) "Test,test,test",
                                        11, (unsigned char *) "some status",
                                        test_der_req_key_len, test_der_req_key,
                                        test_der_req_cert_len, test_der_req_cert,
                                        test_der_resp_cert_len, test_der_resp_cert,
                                        test_der_resp_key_len, test_der_resp_key,
                                        ASN1_PARSE_DER_DECODE_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_OK);

  // DER decode to signed CMS: test NULL pointer to input byte array handled
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        REQUEST, KEY_UNWRAP,
                                        32, (unsigned char *) "AES/KeyWrap/RFC3394NoPadding/128",
                                        15, (unsigned char *) "file://test.key",
                                        14, (unsigned char *) "Test,test,test",
                                        11, (unsigned char *) "some status",
                                        test_der_req_key_len, test_der_req_key,
                                        test_der_req_cert_len, test_der_req_cert,
                                        test_der_resp_cert_len, test_der_resp_cert,
                                        test_der_resp_key_len, test_der_resp_key,
                                        CMS_VERIFY_DER_DECODE_NULL_BUF_IN);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // DER decode to signed CMS: test invalid decoded message format parameter handled
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        REQUEST, KEY_UNWRAP,
                                        32, (unsigned char *) "AES/KeyWrap/RFC3394NoPadding/128",
                                        15, (unsigned char *) "file://test.key",
                                        14, (unsigned char *) "Test,test,test",
                                        11, (unsigned char *) "some status",
                                        test_der_req_key_len, test_der_req_key,
                                        test_der_req_cert_len, test_der_req_cert,
                                        test_der_resp_cert_len, test_der_resp_cert,
                                        test_der_resp_key_len, test_der_resp_key,
                                        CMS_VERIFY_DER_DECODE_INVALID_FORMAT);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // DER decode to signed CMS: test valid input produces expected message output
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        REQUEST, KEY_UNWRAP,
                                        32, (unsigned char *) "AES/KeyWrap/RFC3394NoPadding/128",
                                        15, (unsigned char *) "file://test.key",
                                        14, (unsigned char *) "Test,test,test",
                                        11, (unsigned char *) "some status",
                                        test_der_req_key_len, test_der_req_key,
                                        test_der_req_cert_len, test_der_req_cert,
                                        test_der_resp_cert_len, test_der_resp_cert,
                                        test_der_resp_key_len, test_der_resp_key,
                                        CMS_VERIFY_DER_DECODE_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_OK);

  // DER decode to enveloped CMS: test NULL pointer to input byte array handled
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        REQUEST, KEY_UNWRAP,
                                        32, (unsigned char *) "AES/KeyWrap/RFC3394NoPadding/128",
                                        15, (unsigned char *) "file://test.key",
                                        14, (unsigned char *) "Test,test,test",
                                        11, (unsigned char *) "some status",
                                        test_der_req_key_len, test_der_req_key,
                                        test_der_req_cert_len, test_der_req_cert,
                                        test_der_resp_cert_len, test_der_resp_cert,
                                        test_der_resp_key_len, test_der_resp_key,
                                        CMS_DECRYPT_DER_DECODE_NULL_BUF_IN);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // DER decode to enveloped CMS: test invalid decoded message format parameter handled
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        REQUEST, KEY_UNWRAP,
                                        32, (unsigned char *) "AES/KeyWrap/RFC3394NoPadding/128",
                                        15, (unsigned char *) "file://test.key",
                                        14, (unsigned char *) "Test,test,test",
                                        11, (unsigned char *) "some status",
                                        test_der_req_key_len, test_der_req_key,
                                        test_der_req_cert_len, test_der_req_cert,
                                        test_der_resp_cert_len, test_der_resp_cert,
                                        test_der_resp_key_len, test_der_resp_key,
                                        CMS_DECRYPT_DER_DECODE_INVALID_FORMAT);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // DER decode to enveloped CMS: test valid input produces expected message output
  result = pelz_enclave_msg_test_helper(eid, &result,
                                        REQUEST, KEY_UNWRAP,
                                        32, (unsigned char *) "AES/KeyWrap/RFC3394NoPadding/128",
                                        15, (unsigned char *) "file://test.key",
                                        14, (unsigned char *) "Test,test,test",
                                        11, (unsigned char *) "some status",
                                        test_der_req_key_len, test_der_req_key,
                                        test_der_req_cert_len, test_der_req_cert,
                                        test_der_resp_cert_len, test_der_resp_cert,
                                        test_der_resp_key_len, test_der_resp_key,
                                        CMS_DECRYPT_DER_DECODE_FUNCTIONALITY);
  CU_ASSERT(result == MSG_TEST_OK);
}

void test_construct_deconstruct_pelz_msg(void)
{
  pelz_log(LOG_DEBUG, "Start end-to-end pelz message functionality test");

  int result = 0;

  char *test_cipher = "AES/KeyWrap/RFC3394NoPadding/128\0";
  size_t test_cipher_len = (size_t) strlen(test_cipher);
  char *test_key_id = "file://test_key.pem\0";
  size_t test_key_id_len = (size_t) strlen(test_key_id);
  char *test_data = "pelz end-to-end test message data\0";
  size_t test_data_len = (size_t) strlen(test_data);
  char *test_status = "pelz end-to-end test message status\0";
  size_t test_status_len = (size_t) strlen(test_status);

  // load CA certificate into table
  TableResponseStatus status;
  uint64_t handle = 0;
  if (pelz_load_file_to_enclave("test/data/ca_pub.der.nkl", &handle) == 0)
  {
    add_cert_to_table(eid, &status, CA_TABLE, handle);
    CU_ASSERT(status == OK);
    pelz_log(LOG_INFO, "CA Table add complete");
    handle = 0;
  }
  size_t ca_cnt = 0;
  table_id_count(eid, &status, CA_TABLE, &ca_cnt);
  CU_ASSERT(status == OK && ca_cnt == 1);

  // create DER-formatted test certs/keys for requestor and responder
  BIO *test_req_cert_bio = BIO_new_file("test/data/msg_test_req_pub.pem", "r");
  if (test_req_cert_bio == NULL)
  {
    CU_FAIL("error creating BIO for reading test requestor cert from file");
  }
  X509 *test_req_cert = PEM_read_bio_X509(test_req_cert_bio, NULL, 0, NULL);
  if (test_req_cert == NULL)
  {
    CU_FAIL("error creating test requestor X509 certificate");
  }
  BIO_free(test_req_cert_bio);
  int test_der_req_cert_len = -1;
  uint8_t *test_der_req_cert = NULL;
  test_der_req_cert_len = i2d_X509(test_req_cert, &test_der_req_cert);
  if ((test_der_req_cert == NULL) || (test_der_req_cert_len <= 0))
  {
    CU_FAIL("error creating DER-formatted test requestor certificate");
  }
  BIO *test_req_priv_bio = BIO_new_file("test/data/msg_test_req_priv.pem", "r");
  if (test_req_priv_bio == NULL)
  {
    CU_FAIL("error creating BIO to read test requestor private key from file");
  }
  EVP_PKEY *test_req_priv = PEM_read_bio_PrivateKey(test_req_priv_bio,
                                                    NULL,
                                                    0,
                                                    NULL);
  if (test_req_priv == NULL)
  {
    CU_FAIL("error creating test requestor EC private key");
  }
  BIO_free(test_req_priv_bio);
  int test_der_req_priv_len = -1;
  uint8_t *test_der_req_priv = NULL;
  test_der_req_priv_len = i2d_PrivateKey(test_req_priv, &test_der_req_priv);
  if ((test_der_req_priv == NULL) || (test_der_req_priv_len <= 0))
  {
    CU_FAIL("error creating DER-formatted test requestor private key");
  }
  BIO *test_resp_cert_bio = BIO_new_file("test/data/msg_test_resp_pub.pem",
                                         "r");
  if (test_resp_cert_bio == NULL)
  {
    CU_FAIL("error creating BIO for reading test responder cert from file");
  }
  X509 *test_resp_cert = PEM_read_bio_X509(test_resp_cert_bio, NULL, 0, NULL);
  if (test_resp_cert == NULL)
  {
    CU_FAIL("error creating test responder X509 certificate");
  }
  BIO_free(test_resp_cert_bio);
  int test_der_resp_cert_len = -1;
  uint8_t *test_der_resp_cert = NULL;
  test_der_resp_cert_len = i2d_X509(test_resp_cert, &test_der_resp_cert);
  if ((test_der_resp_cert == NULL) || (test_der_resp_cert_len <= 0))
  {
    CU_FAIL("error creating DER-formatted test responder certificate");
  }
  BIO *test_resp_priv_bio = BIO_new_file("test/data/msg_test_resp_priv.pem",
                                         "r");
  if (test_resp_priv_bio == NULL)
  {
    CU_FAIL("error creating BIO to read test responder private key from file");
  }
  EVP_PKEY *test_resp_priv = PEM_read_bio_PrivateKey(test_resp_priv_bio,
                                                    NULL,
                                                    0,
                                                    NULL);
  if (test_resp_priv == NULL)
  {
    CU_FAIL("error creating test responder EC private key");
  }
  BIO_free(test_resp_priv_bio);
  int test_der_resp_priv_len = -1;
  uint8_t *test_der_resp_priv = NULL;
  test_der_resp_priv_len = i2d_PrivateKey(test_resp_priv, &test_der_resp_priv);
  if ((test_der_resp_priv == NULL) || (test_der_resp_priv_len <= 0))
  {
    CU_FAIL("error creating DER-formatted test responder private key");
  }

  // test NULL pointer as input byte array parameter to "construct"
  test_end_to_end_pelz_msg_helper(eid,
                                  &result,
                                  REQUEST,
                                  KEY_WRAP,
                                  test_cipher_len,
                                  (uint8_t *) test_cipher,
                                  test_key_id_len,
                                  (uint8_t *) test_key_id,
                                  test_data_len,
                                  (uint8_t *) test_data,
                                  test_status_len,
                                  (uint8_t *) test_status,
                                  (size_t) test_der_req_cert_len,
                                  test_der_req_cert,
                                  (size_t) test_der_req_priv_len,
                                  test_der_req_priv,
                                  (size_t) test_der_resp_cert_len,
                                  test_der_resp_cert,
                                  (size_t) test_der_resp_priv_len,
                                  test_der_resp_priv,
                                  CONSTRUCT_PELZ_MSG_NULL_MSG_IN_TEST);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // test NULL pointer as input local certificate parameter to "construct"
  test_end_to_end_pelz_msg_helper(eid,
                                  &result,
                                  REQUEST,
                                  KEY_WRAP,
                                  test_cipher_len,
                                  (uint8_t *) test_cipher,
                                  test_key_id_len,
                                  (uint8_t *) test_key_id,
                                  test_data_len,
                                  (uint8_t *) test_data,
                                  test_status_len,
                                  (uint8_t *) test_status,
                                  (size_t) test_der_req_cert_len,
                                  test_der_req_cert,
                                  (size_t) test_der_req_priv_len,
                                  test_der_req_priv,
                                  (size_t) test_der_resp_cert_len,
                                  test_der_resp_cert,
                                  (size_t) test_der_resp_priv_len,
                                  test_der_resp_priv,
                                  CONSTRUCT_PELZ_MSG_NULL_LOCAL_CERT_TEST);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // test NULL pointer as input local private key parameter to "construct"
  test_end_to_end_pelz_msg_helper(eid,
                                  &result,
                                  REQUEST,
                                  KEY_WRAP,
                                  test_cipher_len,
                                  (uint8_t *) test_cipher,
                                  test_key_id_len,
                                  (uint8_t *) test_key_id,
                                  test_data_len,
                                  (uint8_t *) test_data,
                                  test_status_len,
                                  (uint8_t *) test_status,
                                  (size_t) test_der_req_cert_len,
                                  test_der_req_cert,
                                  (size_t) test_der_req_priv_len,
                                  test_der_req_priv,
                                  (size_t) test_der_resp_cert_len,
                                  test_der_resp_cert,
                                  (size_t) test_der_resp_priv_len,
                                  test_der_resp_priv,
                                  CONSTRUCT_PELZ_MSG_NULL_LOCAL_PRIV_TEST);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // test NULL pointer as input peer certificate parameter to "construct"
  test_end_to_end_pelz_msg_helper(eid,
                                  &result,
                                  REQUEST,
                                  KEY_WRAP,
                                  test_cipher_len,
                                  (uint8_t *) test_cipher,
                                  test_key_id_len,
                                  (uint8_t *) test_key_id,
                                  test_data_len,
                                  (uint8_t *) test_data,
                                  test_status_len,
                                  (uint8_t *) test_status,
                                  (size_t) test_der_req_cert_len,
                                  test_der_req_cert,
                                  (size_t) test_der_req_priv_len,
                                  test_der_req_priv,
                                  (size_t) test_der_resp_cert_len,
                                  test_der_resp_cert,
                                  (size_t) test_der_resp_priv_len,
                                  test_der_resp_priv,
                                  CONSTRUCT_PELZ_MSG_NULL_PEER_CERT_TEST);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // test NULL pointer as output byte array parameter to "construct"
  test_end_to_end_pelz_msg_helper(eid,
                                  &result,
                                  REQUEST,
                                  KEY_WRAP,
                                  test_cipher_len,
                                  (uint8_t *) test_cipher,
                                  test_key_id_len,
                                  (uint8_t *) test_key_id,
                                  test_data_len,
                                  (uint8_t *) test_data,
                                  test_status_len,
                                  (uint8_t *) test_status,
                                  (size_t) test_der_req_cert_len,
                                  test_der_req_cert,
                                  (size_t) test_der_req_priv_len,
                                  test_der_req_priv,
                                  (size_t) test_der_resp_cert_len,
                                  test_der_resp_cert,
                                  (size_t) test_der_resp_priv_len,
                                  test_der_resp_priv,
                                  CONSTRUCT_PELZ_MSG_NULL_OUT_BUF_TEST);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // test NULL pointer as input message byte array parameter to "deconstruct"
  test_end_to_end_pelz_msg_helper(eid,
                                  &result,
                                  REQUEST,
                                  KEY_WRAP,
                                  test_cipher_len,
                                  (uint8_t *) test_cipher,
                                  test_key_id_len,
                                  (uint8_t *) test_key_id,
                                  test_data_len,
                                  (uint8_t *) test_data,
                                  test_status_len,
                                  (uint8_t *) test_status,
                                  (size_t) test_der_req_cert_len,
                                  test_der_req_cert,
                                  (size_t) test_der_req_priv_len,
                                  test_der_req_priv,
                                  (size_t) test_der_resp_cert_len,
                                  test_der_resp_cert,
                                  (size_t) test_der_resp_priv_len,
                                  test_der_resp_priv,
                                  DECONSTRUCT_PELZ_MSG_NULL_MSG_IN_TEST);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // test NULL pointer as input local certificate parameter to "deconstruct"
  test_end_to_end_pelz_msg_helper(eid,
                                  &result,
                                  REQUEST,
                                  KEY_WRAP,
                                  test_cipher_len,
                                  (uint8_t *) test_cipher,
                                  test_key_id_len,
                                  (uint8_t *) test_key_id,
                                  test_data_len,
                                  (uint8_t *) test_data,
                                  test_status_len,
                                  (uint8_t *) test_status,
                                  (size_t) test_der_req_cert_len,
                                  test_der_req_cert,
                                  (size_t) test_der_req_priv_len,
                                  test_der_req_priv,
                                  (size_t) test_der_resp_cert_len,
                                  test_der_resp_cert,
                                  (size_t) test_der_resp_priv_len,
                                  test_der_resp_priv,
                                  DECONSTRUCT_PELZ_MSG_NULL_LOCAL_CERT_TEST);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // test NULL pointer as input local private key parameter to "deconstruct"
  test_end_to_end_pelz_msg_helper(eid,
                                  &result,
                                  REQUEST,
                                  KEY_WRAP,
                                  test_cipher_len,
                                  (uint8_t *) test_cipher,
                                  test_key_id_len,
                                  (uint8_t *) test_key_id,
                                  test_data_len,
                                  (uint8_t *) test_data,
                                  test_status_len,
                                  (uint8_t *) test_status,
                                  (size_t) test_der_req_cert_len,
                                  test_der_req_cert,
                                  (size_t) test_der_req_priv_len,
                                  test_der_req_priv,
                                  (size_t) test_der_resp_cert_len,
                                  test_der_resp_cert,
                                  (size_t) test_der_resp_priv_len,
                                  test_der_resp_priv,
                                  DECONSTRUCT_PELZ_MSG_NULL_LOCAL_PRIV_TEST);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // test NULL double pointer to peer cert output parameter for "deconstruct"
  test_end_to_end_pelz_msg_helper(eid,
                                  &result,
                                  REQUEST,
                                  KEY_WRAP,
                                  test_cipher_len,
                                  (uint8_t *) test_cipher,
                                  test_key_id_len,
                                  (uint8_t *) test_key_id,
                                  test_data_len,
                                  (uint8_t *) test_data,
                                  test_status_len,
                                  (uint8_t *) test_status,
                                  (size_t) test_der_req_cert_len,
                                  test_der_req_cert,
                                  (size_t) test_der_req_priv_len,
                                  test_der_req_priv,
                                  (size_t) test_der_resp_cert_len,
                                  test_der_resp_cert,
                                  (size_t) test_der_resp_priv_len,
                                  test_der_resp_priv,
                                  DECONSTRUCT_PELZ_MSG_NULL_PEER_CERT_TEST);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // test preallocated buffer for peer cert output parameter to "deconstruct"
  test_end_to_end_pelz_msg_helper(eid,
                                  &result,
                                  REQUEST,
                                  KEY_WRAP,
                                  test_cipher_len,
                                  (uint8_t *) test_cipher,
                                  test_key_id_len,
                                  (uint8_t *) test_key_id,
                                  test_data_len,
                                  (uint8_t *) test_data,
                                  test_status_len,
                                  (uint8_t *) test_status,
                                  (size_t) test_der_req_cert_len,
                                  test_der_req_cert,
                                  (size_t) test_der_req_priv_len,
                                  test_der_req_priv,
                                  (size_t) test_der_resp_cert_len,
                                  test_der_resp_cert,
                                  (size_t) test_der_resp_priv_len,
                                  test_der_resp_priv,
                                  DECONSTRUCT_PELZ_MSG_PREALLOC_PEER_CERT_TEST);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // test end-to-end "construct" then "deconstruct" pelz message
  test_end_to_end_pelz_msg_helper(eid,
                                  &result,
                                  REQUEST,
                                  KEY_WRAP,
                                  test_cipher_len,
                                  (uint8_t *) test_cipher,
                                  test_key_id_len,
                                  (uint8_t *) test_key_id,
                                  test_data_len,
                                  (uint8_t *) test_data,
                                  test_status_len,
                                  (uint8_t *) test_status,
                                  (size_t) test_der_req_cert_len,
                                  test_der_req_cert,
                                  (size_t) test_der_req_priv_len,
                                  test_der_req_priv,
                                  (size_t) test_der_resp_cert_len,
                                  test_der_resp_cert,
                                  (size_t) test_der_resp_priv_len,
                                  test_der_resp_priv,
                                  CONSTRUCT_DECONSTRUCT_PELZ_MSG_BASIC_TEST);
  CU_ASSERT(result == MSG_TEST_SUCCESS);
  pelz_log(LOG_DEBUG, "result = %d", result);

  // test end-to-end "construct" then "deconstruct" pelz message
  // with mismatched certificates and keys
  test_end_to_end_pelz_msg_helper(eid,
                                  &result,
                                  REQUEST,
                                  KEY_WRAP,
                                  test_cipher_len,
                                  (uint8_t *) test_cipher,
                                  test_key_id_len,
                                  (uint8_t *) test_key_id,
                                  test_data_len,
                                  (uint8_t *) test_data,
                                  test_status_len,
                                  (uint8_t *) test_status,
                                  (size_t) test_der_req_cert_len,
                                  test_der_req_cert,
                                  (size_t) test_der_resp_priv_len,
                                  test_der_resp_priv,
                                  (size_t) test_der_resp_cert_len,
                                  test_der_resp_cert,
                                  (size_t) test_der_req_priv_len,
                                  test_der_req_priv,
                                  CONSTRUCT_DECONSTRUCT_PELZ_MSG_BASIC_TEST);
  CU_ASSERT(result == MSG_TEST_SETUP_ERROR);

  // Clean-up
  if (empty_CA_table(eid, NULL) != 0)
  {
    CU_FAIL("error emptying CA table");
  }
  free(test_der_req_cert);
  free(test_der_req_priv);
  free(test_der_resp_cert);
  free(test_der_resp_priv);

}