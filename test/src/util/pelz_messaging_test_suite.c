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

  sgx_status_t retval;
  MsgTestStatus result = MSG_TEST_UNKNOWN_ERROR;

  // specify test pelz test field values
  PELZ_MSG_TYPE test_msg_type = REQUEST;
  PELZ_REQ_TYPE test_req_type = KEY_WRAP;

  charbuf test_cipher = { .chars = NULL, .len = 0 };
  test_cipher.chars = malloc(strlen("AES/KeyWrap/RFC3394NoPadding/128") + 1);
  sprintf((char *) test_cipher.chars, "AES/KeyWrap/RFC3394NoPadding/128");
  test_cipher.len = strlen("AES/KeyWrap/RFC3394NoPadding/128");

  charbuf test_key_id = { .chars = NULL, .len = 0 };
  test_key_id.chars = malloc(strlen("file://test.key") + 1);
  sprintf((char *) test_key_id.chars, "file://test.key");
  test_key_id.len = strlen("file://test.key");

  charbuf test_data = { .chars = NULL, .len = 0 };
  test_data.chars = malloc(strlen("create ASN.1 message test data") + 1);
  sprintf((char *) test_data.chars, "create ASN.1 message test data");
  test_data.len = strlen("create ASN.1 message test data");

  charbuf test_status = { .chars = NULL, .len = 0 };
  test_status.chars = malloc(strlen("create ASN.1 message status") + 1);
  sprintf((char *) test_data.chars, "create ASN.1 message status");
  test_data.len = strlen("create ASN.1 message status");

  // invalid (less than MSG_TYPE_MIN) message type should fail param checks
  pelz_enclave_msg_test_helper(eid, &retval,
                               MSG_TYPE_MIN - 1, test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_CREATE_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_ASN1_CREATE_ERROR);

  // invalid (greater than MSG_TYPE_MAX) message type should fail param checks
  pelz_enclave_msg_test_helper(eid, &retval,
                               MSG_TYPE_MAX + 1, test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_data.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_CREATE_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_ASN1_CREATE_ERROR);

  // invalid (less than REQ_TYPE_MIN) message type should fail param checks
  pelz_enclave_msg_test_helper(eid, &retval,
                               test_msg_type, REQ_TYPE_MIN - 1,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_CREATE_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_ASN1_CREATE_ERROR);

  // invalid (greater than REQ_TYPE_MAX) message type should fail param checks
  pelz_enclave_msg_test_helper(eid, &retval,
                               test_msg_type, REQ_TYPE_MAX + 1,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_CREATE_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_ASN1_CREATE_ERROR);

  // null cipher input should fail param checks
  pelz_enclave_msg_test_helper(eid, &retval,
                               test_msg_type, test_req_type,
                               test_cipher.len, NULL,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_CREATE_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_ASN1_CREATE_ERROR);

  // empty (zero-length) cipher input should fail param checks
  pelz_enclave_msg_test_helper(eid, &retval,
                               test_msg_type, test_req_type,
                               0, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_CREATE_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_ASN1_CREATE_ERROR);

  // null KEK key ID input should fail param checks
  pelz_enclave_msg_test_helper(eid, &retval,
                               test_msg_type, test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, NULL,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_CREATE_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_ASN1_CREATE_ERROR);

  // empty (zero-length) KEK key ID input should fail param checks
  pelz_enclave_msg_test_helper(eid, &retval,
                               test_msg_type, test_req_type,
                               test_cipher.len, test_cipher.chars,
                               0, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_CREATE_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_ASN1_CREATE_ERROR);

  // null data input should fail param checks
  pelz_enclave_msg_test_helper(eid, &retval,
                               test_msg_type, test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, NULL,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_CREATE_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_ASN1_CREATE_ERROR);

  // empty (zero-length) data input should fail param checks
  pelz_enclave_msg_test_helper(eid, &retval,
                               test_msg_type, test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               0, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_CREATE_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_ASN1_CREATE_ERROR);

  // null status input should fail param checks
  pelz_enclave_msg_test_helper(eid, &retval,
                               test_msg_type, test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_CREATE_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_ASN1_CREATE_ERROR);

  // empty (zero-length) status input should fail param checks
  pelz_enclave_msg_test_helper(eid, &retval,
                               test_msg_type, test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               0, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_CREATE_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_ASN1_CREATE_ERROR);

  // ASN.1 message creation test case with valid parameters should not error
  pelz_enclave_msg_test_helper(eid, &retval,
                               test_msg_type, test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_CREATE_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_OK);

  // Clean-up
  free_charbuf(&test_cipher);
  free_charbuf(&test_key_id);
  free_charbuf(&test_data);
  free_charbuf(&test_status);
}

void test_parse_pelz_asn1_msg(void)
{
  pelz_log(LOG_DEBUG, "Start parse_pelz_asn1_msg() functionality test");

  sgx_status_t retval;
  MsgTestStatus result = MSG_TEST_UNKNOWN_ERROR;

  // specify test pelz test field values
  PELZ_MSG_TYPE test_msg_type = REQUEST;
  PELZ_REQ_TYPE test_req_type = KEY_WRAP;

  charbuf test_cipher = { .chars = NULL, .len = 0 };
  test_cipher.chars = malloc(strlen("AES/KeyWrap/RFC3394NoPadding/128") + 1);
  sprintf((char *) test_cipher.chars, "AES/KeyWrap/RFC3394NoPadding/128");
  test_cipher.len = strlen("AES/KeyWrap/RFC3394NoPadding/128");

  charbuf test_key_id = { .chars = NULL, .len = 0 };
  test_key_id.chars = malloc(strlen("file://test.key") + 1);
  sprintf((char *) test_key_id.chars, "file://test.key");
  test_key_id.len = strlen("file://test.key");

  charbuf test_data = { .chars = NULL, .len = 0 };
  test_data.chars = malloc(strlen("parse ASN.1 message test data") + 1);
  sprintf((char *) test_data.chars, "parse ASN.1 message test data");
  test_data.len = strlen("parse ASN.1 message test data");

  charbuf test_status = { .chars = NULL, .len = 0 };
  test_status.chars = malloc(strlen("parse ASN.1 message status") + 1);
  sprintf((char *) test_data.chars, "parse ASN.1 message status");
  test_data.len = strlen("parse ASN.1 message status");

  // invalid 'message type' field tag should result in parse error
  pelz_enclave_msg_test_helper(eid, &retval,
                               test_msg_type, test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_PARSE_INVALID_MSG_TYPE_TAG,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // invalid message type field value (< MSG_TYPE_MIN) should error
  pelz_enclave_msg_test_helper(eid, &retval,
                               test_msg_type, test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_PARSE_INVALID_MSG_TYPE_LO,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // invalid message type field value (> MSG_TYPE_MAX) should error
  pelz_enclave_msg_test_helper(eid, &retval,
                               test_msg_type, test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_PARSE_INVALID_MSG_TYPE_HI,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // invalid req_type field tag should result in parse error
  pelz_enclave_msg_test_helper(eid, &retval,
                               test_msg_type, test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_PARSE_INVALID_REQ_TYPE_TAG,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // invalid request type field value (< REQ_TYPE_MIN) should error
  pelz_enclave_msg_test_helper(eid, &retval,
                               test_msg_type, test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_PARSE_INVALID_REQ_TYPE_LO,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // invalid request type field value (> REQ_TYPE_MAX) should error
  pelz_enclave_msg_test_helper(eid, &retval,
                               test_msg_type, test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_PARSE_INVALID_REQ_TYPE_HI,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // invalid cipher field tag should result in parse error
  pelz_enclave_msg_test_helper(eid, &retval,
                               test_msg_type, test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_PARSE_INVALID_CIPHER_TAG,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // invalid key ID field tag should result in parse error
  pelz_enclave_msg_test_helper(eid, &retval,
                               test_msg_type, test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_PARSE_INVALID_KEY_ID_TAG,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // invalid data field tag should result in parse error
  pelz_enclave_msg_test_helper(eid, &retval,
                               test_msg_type, test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_PARSE_INVALID_DATA_TAG,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // invalid status field tag should result in parse error
  pelz_enclave_msg_test_helper(eid, &retval,
                               test_msg_type, test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_PARSE_INVALID_STATUS_TAG,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // valid (unmodified) message format/contents should parse successfully
  pelz_enclave_msg_test_helper(eid, &retval,
                               test_msg_type, test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_PARSE_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_OK);

  // Clean-up
  free_charbuf(&test_cipher);
  free_charbuf(&test_key_id);
  free_charbuf(&test_data);
  free_charbuf(&test_status);
}

void test_create_pelz_signed_msg(void)
{
  pelz_log(LOG_DEBUG, "Start create_pelz_signed_msg() functionality test");

  sgx_status_t retval;
  MsgTestStatus result = MSG_TEST_UNKNOWN_ERROR;

  // specify test pelz test field values
  PELZ_MSG_TYPE test_msg_type = REQUEST;
  PELZ_REQ_TYPE test_req_type = KEY_WRAP;

  charbuf test_cipher = { .chars = NULL, .len = 0 };
  test_cipher.chars = malloc(strlen("AES/KeyWrap/RFC3394NoPadding/128") + 1);
  sprintf((char *) test_cipher.chars, "AES/KeyWrap/RFC3394NoPadding/128");
  test_cipher.len = strlen("AES/KeyWrap/RFC3394NoPadding/128");

  charbuf test_key_id = { .chars = NULL, .len = 0 };
  test_key_id.chars = malloc(strlen("file://test.key") + 1);
  sprintf((char *) test_key_id.chars, "file://test.key");
  test_key_id.len = strlen("file://test.key");

  charbuf test_data = { .chars = NULL, .len = 0 };
  test_data.chars = malloc(strlen("create signed message test data") + 1);
  sprintf((char *) test_data.chars, "create signed message test data");
  test_data.len = strlen("create signed message test data");

  charbuf test_status = { .chars = NULL, .len = 0 };
  test_status.chars = malloc(strlen("create signed message status") + 1);
  sprintf((char *) test_data.chars, "create signed message status");
  test_data.len = strlen("create signed message status");

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
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               test_priv.len, test_priv.chars,
                               test_cert.len, test_cert.chars,
                               0, NULL,
                               0, NULL,
                               CMS_SIGN_NULL_BUF_IN,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // Empty input data buffer test cases - invalid parameter should be handled
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               test_priv.len, test_priv.chars,
                               test_cert.len, test_cert.chars,
                               0, NULL,
                               0, NULL,
                               CMS_SIGN_EMPTY_BUF_IN,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // Invalid size input data buffer test case - invalid parameter should be handled
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               test_priv.len, test_priv.chars,
                               test_cert.len, test_cert.chars,
                               0, NULL,
                               0, NULL,
                               CMS_SIGN_INVALID_SIZE_BUF_IN,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // NULL cert test case - invalid parameter should be handled
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               test_priv.len, test_priv.chars,
                               test_cert.len, test_cert.chars,
                               0, NULL,
                               0, NULL,
                               CMS_SIGN_NULL_CERT_IN,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // NULL private signing key should fail
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               test_priv.len, test_priv.chars,
                               test_cert.len, test_cert.chars,
                               0, NULL,
                               0, NULL,
                               CMS_SIGN_NULL_PRIV_IN,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // valid test case should pass
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               test_priv.len, test_priv.chars,
                               test_cert.len, test_cert.chars,
                               0, NULL,
                               0, NULL,
                               CMS_SIGN_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_OK);

  // Mismatched key/cert should fail
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               mismatch_priv.len, mismatch_priv.chars,
                               test_cert.len, test_cert.chars,
                               0, NULL,
                               0, NULL,
                               CMS_SIGN_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_SETUP_ERROR);

  // Clean-up
  free_charbuf(&test_cipher);
  free_charbuf(&test_key_id);
  free_charbuf(&test_data);
  free_charbuf(&test_status);
  free_charbuf(&test_cert);
  free_charbuf(&test_priv);
  free_charbuf(&mismatch_priv);
}

void test_verify_pelz_signed_msg(void)
{
  pelz_log(LOG_DEBUG, "Start verify_pelz_signed_msg() functionality test");

  sgx_status_t retval = SGX_ERROR_UNEXPECTED;
  MsgTestStatus result = MSG_TEST_UNKNOWN_ERROR;

  // specify test pelz test field values
  PELZ_MSG_TYPE test_msg_type = REQUEST;
  PELZ_REQ_TYPE test_req_type = KEY_WRAP;

  charbuf test_cipher = { .chars = NULL, .len = 0 };
  test_cipher.chars = malloc(strlen("AES/KeyWrap/RFC3394NoPadding/128") + 1);
  sprintf((char *) test_cipher.chars, "AES/KeyWrap/RFC3394NoPadding/128");
  test_cipher.len = strlen("AES/KeyWrap/RFC3394NoPadding/128");

  charbuf test_key_id = { .chars = NULL, .len = 0 };
  test_key_id.chars = malloc(strlen("file://test.key") + 1);
  sprintf((char *) test_key_id.chars, "file://test.key");
  test_key_id.len = strlen("file://test.key");

  charbuf test_data = { .chars = NULL, .len = 0 };
  test_data.chars = malloc(strlen("verify signed message test data") + 1);
  sprintf((char *) test_data.chars, "verify signed message test data");
  test_data.len = strlen("verify signed message test data");

  charbuf test_status = { .chars = NULL, .len = 0 };
  test_status.chars = malloc(strlen("verify signed message status") + 1);
  sprintf((char *) test_data.chars, "verify signed message status");
  test_data.len = strlen("verify signed message status");

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

  // NULL signed message input test case
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               test_priv.len, test_priv.chars,
                               test_cert.len, test_cert.chars,
                               0, NULL,
                               0, NULL,
                               CMS_VERIFY_NULL_MSG_IN,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // NULL output certificate pointer test case
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               test_priv.len, test_priv.chars,
                               test_cert.len, test_cert.chars,
                               0, NULL,
                               0, NULL,
                               CMS_VERIFY_NULL_BUF_OUT,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // NULL output certificate test case
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               test_priv.len, test_priv.chars,
                               test_cert.len, test_cert.chars,
                               0, NULL,
                               0, NULL,
                               CMS_VERIFY_NULL_CERT_OUT,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // valid test data should invoke succcessful signature verification test case
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               test_priv.len, test_priv.chars,
                               test_cert.len, test_cert.chars,
                               0, NULL,
                               0, NULL,
                               CMS_VERIFY_FUNCTIONALITY,
                               &result);
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

  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               test_priv.len, test_priv.chars,
                               test_cert.len, test_cert.chars,
                               0, NULL,
                               0, NULL,
                               CMS_VERIFY_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_VERIFY_ERROR);

  // Clean-up
  free_charbuf(&test_cipher);
  free_charbuf(&test_key_id);
  free_charbuf(&test_data);
  free_charbuf(&test_status);
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

  sgx_status_t retval = SGX_ERROR_UNEXPECTED;
  MsgTestStatus result = MSG_TEST_UNKNOWN_ERROR;

  // specify test pelz test field values
  PELZ_MSG_TYPE test_msg_type = REQUEST;
  PELZ_REQ_TYPE test_req_type = KEY_WRAP;

  charbuf test_cipher = { .chars = NULL, .len = 0 };
  test_cipher.chars = malloc(strlen("AES/KeyWrap/RFC3394NoPadding/128") + 1);
  sprintf((char *) test_cipher.chars, "AES/KeyWrap/RFC3394NoPadding/128");
  test_cipher.len = strlen("AES/KeyWrap/RFC3394NoPadding/128");

  charbuf test_key_id = { .chars = NULL, .len = 0 };
  test_key_id.chars = malloc(strlen("file://test.key") + 1);
  sprintf((char *) test_key_id.chars, "file://test.key");
  test_key_id.len = strlen("file://test.key");

  charbuf test_data = { .chars = NULL, .len = 0 };
  test_data.chars = malloc(strlen("create enveloped message test data") + 1);
  sprintf((char *) test_data.chars, "create enveloped message test data");
  test_data.len = strlen("create enveloped message test data");

  charbuf test_status = { .chars = NULL, .len = 0 };
  test_status.chars = malloc(strlen("create enveloped message status") + 1);
  sprintf((char *) test_data.chars, "create enveloped message status");
  test_data.len = strlen("create enveloped message status");

  // create test cert/key inputs
  //   - sign_priv:    message creator's private key used to sign
  //   - verify_cert:  message creator's public key (certificate) used to verifye test cert/key inputs
  //   - encrypt_cert: message recipient's public key (certificate) used to encrypt
  //   - decrypt_priv: message recipients private key used to decrypt
  charbuf sign_priv = { .chars = NULL, .len = 0 };
  charbuf verify_cert = { .chars = NULL, .len = 0 };
  charbuf encrypt_cert = { .chars = NULL, .len = 0 };
  charbuf decrypt_priv = { .chars = NULL, .len = 0 };
  result = pem_priv_to_der("test/data/msg_test_req_priv.pem", &sign_priv);
  if (result != 0)
  {
    CU_FAIL("DER key from file (test/data/msg_test_req_priv.pem) error");
  }
  result = pem_cert_to_der("test/data/msg_test_req_pub.pem", &verify_cert);
  if (result != 0)
  {
    CU_FAIL("DER cert from file (test/data/msg_test_req_pub.pem) error");
  }
  result = pem_cert_to_der("test/data/msg_test_resp_pub.pem", &encrypt_cert);
  if (result != 0)
  {
    CU_FAIL("DER cert from file (test/data/msg_test_resp_pub.pem) error");
  }
  result = pem_priv_to_der("test/data/msg_test_resp_priv.pem", &decrypt_priv);
  if (result != 0)
  {
    CU_FAIL("DER key from file (test/data/msg_test_resp_priv.pem) error");
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

  // NULL input data should be handled as invalid parameter
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               CMS_ENCRYPT_NULL_BUF_IN,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // empty input data should be handled as invalid parameter
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               CMS_ENCRYPT_EMPTY_BUF_IN,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // invalid size input data should be handled as invalid parameter
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               CMS_ENCRYPT_INVALID_SIZE_BUF_IN,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // NULL input certificate should be handled as invalid parameter
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               CMS_ENCRYPT_NULL_CERT_IN,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // valid test case should pass
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               CMS_ENCRYPT_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_OK);

  // Clean-up
  free_charbuf(&test_cipher);
  free_charbuf(&test_key_id);
  free_charbuf(&test_data);
  free_charbuf(&test_status);
  free_charbuf(&sign_priv);
  free_charbuf(&verify_cert);
  free_charbuf(&encrypt_cert);
  free_charbuf(&decrypt_priv);
  if (empty_CA_table(eid, NULL) != 0)
  {
    CU_FAIL("error emptying CA table");
  }
}

void test_decrypt_pelz_enveloped_msg(void)
{
  pelz_log(LOG_DEBUG, "Start decrypt_pelz_enveloped_msg() functionality test");

  sgx_status_t retval = SGX_ERROR_UNEXPECTED;
  MsgTestStatus result = MSG_TEST_UNKNOWN_ERROR;

  // specify test pelz test field values
  PELZ_MSG_TYPE test_msg_type = REQUEST;
  PELZ_REQ_TYPE test_req_type = KEY_WRAP;

  charbuf test_cipher = { .chars = NULL, .len = 0 };
  test_cipher.chars = malloc(strlen("AES/KeyWrap/RFC3394NoPadding/128") + 1);
  sprintf((char *) test_cipher.chars, "AES/KeyWrap/RFC3394NoPadding/128");
  test_cipher.len = strlen("AES/KeyWrap/RFC3394NoPadding/128");

  charbuf test_key_id = { .chars = NULL, .len = 0 };
  test_key_id.chars = malloc(strlen("file://test.key") + 1);
  sprintf((char *) test_key_id.chars, "file://test.key");
  test_key_id.len = strlen("file://test.key");

  charbuf test_data = { .chars = NULL, .len = 0 };
  test_data.chars = malloc(strlen("create enveloped message test data") + 1);
  sprintf((char *) test_data.chars, "create enveloped message test data");
  test_data.len = strlen("create enveloped message test data");

  charbuf test_status = { .chars = NULL, .len = 0 };
  test_status.chars = malloc(strlen("create enveloped message status") + 1);
  sprintf((char *) test_data.chars, "create enveloped message status");
  test_data.len = strlen("create enveloped message status");

  // create test cert/key inputs
  //   - sign_priv:    message creator's private key used to sign
  //   - verify_cert:  message creator's public key (certificate) used to verifye test cert/key inputs
  //   - encrypt_cert: message recipient's public key (certificate) used to encrypt
  //   - decrypt_priv: message recipients private key used to decrypt
  charbuf sign_priv = { .chars = NULL, .len = 0 };
  charbuf verify_cert = { .chars = NULL, .len = 0 };
  charbuf encrypt_cert = { .chars = NULL, .len = 0 };
  charbuf decrypt_priv = { .chars = NULL, .len = 0 };
  result = pem_priv_to_der("test/data/msg_test_req_priv.pem", &sign_priv);
  if (result != 0)
  {
    CU_FAIL("DER key from file (test/data/msg_test_req_priv.pem) error");
  }
  result = pem_cert_to_der("test/data/msg_test_req_pub.pem", &verify_cert);
  if (result != 0)
  {
    CU_FAIL("DER cert from file (test/data/msg_test_req_pub.pem) error");
  }
  result = pem_cert_to_der("test/data/msg_test_resp_pub.pem", &encrypt_cert);
  if (result != 0)
  {
    CU_FAIL("DER cert from file (test/data/msg_test_resp_pub.pem) error");
  }
  result = pem_priv_to_der("test/data/msg_test_resp_priv.pem", &decrypt_priv);
  if (result != 0)
  {
    CU_FAIL("DER key from file (test/data/msg_test_resp_priv.pem) error");
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

  // NULL input message test case
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               CMS_DECRYPT_NULL_MSG_IN,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // NULL output buffer test case
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               CMS_DECRYPT_NULL_BUF_OUT,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // NULL input private key test case
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               CMS_DECRYPT_NULL_PRIV,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // NULL input cert test case
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               CMS_DECRYPT_NULL_CERT,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // valid test data should invoke succcessful CMS decryption test case
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               CMS_DECRYPT_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_OK);

  // wrong input private decryption key test case
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               sign_priv.len, sign_priv.chars,
                               CMS_DECRYPT_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_DECRYPT_ERROR);

  // Clean-up
  free_charbuf(&test_cipher);
  free_charbuf(&test_key_id);
  free_charbuf(&test_data);
  free_charbuf(&test_status);
  free_charbuf(&sign_priv);
  free_charbuf(&verify_cert);
  free_charbuf(&encrypt_cert);
  free_charbuf(&decrypt_priv);
  if (empty_CA_table(eid, NULL) != 0)
  {
    CU_FAIL("error emptying CA table");
  }
}

void test_der_encode_pelz_msg(void)
{
  pelz_log(LOG_DEBUG, "Start pelz message DER encoding functionality test");

  sgx_status_t retval = SGX_ERROR_UNEXPECTED;
  MsgTestStatus result = MSG_TEST_UNKNOWN_ERROR;

  // specify test pelz test field values
  PELZ_MSG_TYPE test_msg_type = REQUEST;
  PELZ_REQ_TYPE test_req_type = KEY_WRAP;

  charbuf test_cipher = { .chars = NULL, .len = 0 };
  test_cipher.chars = malloc(strlen("AES/KeyWrap/RFC3394NoPadding/128") + 1);
  sprintf((char *) test_cipher.chars, "AES/KeyWrap/RFC3394NoPadding/128");
  test_cipher.len = strlen("AES/KeyWrap/RFC3394NoPadding/128");

  charbuf test_key_id = { .chars = NULL, .len = 0 };
  test_key_id.chars = malloc(strlen("file://test.key") + 1);
  sprintf((char *) test_key_id.chars, "file://test.key");
  test_key_id.len = strlen("file://test.key");

  charbuf test_data = { .chars = NULL, .len = 0 };
  test_data.chars = malloc(strlen("create enveloped message test data") + 1);
  sprintf((char *) test_data.chars, "create enveloped message test data");
  test_data.len = strlen("create enveloped message test data");

  charbuf test_status = { .chars = NULL, .len = 0 };
  test_status.chars = malloc(strlen("create enveloped message status") + 1);
  sprintf((char *) test_data.chars, "create enveloped message status");
  test_data.len = strlen("create enveloped message status");

  // ASN.1 DER encode: test that NULL input message is handled as expected
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_CREATE_DER_ENCODE_NULL_MSG_IN,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // ASN.1 DER encode: test that NULL output buffer pointer is handled as expected
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_CREATE_DER_ENCODE_NULL_BUF_OUT,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // ASN.1 DER encode: test with valid test input should produce expected encoded result
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_CREATE_DER_ENCODE_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_OK);

  // load certificate for 'CA' that signed test keys
  TableResponseStatus status;
  uint64_t handle = 0;

  if (pelz_load_file_to_enclave("test/data/ca_pub.der.nkl", &handle) == 0)
  {
    add_cert_to_table(eid, &status, CA_TABLE, handle);
    CU_ASSERT(status == OK);
    pelz_log(LOG_INFO, "CA Table add complete");
    handle = 0;
  }

  // create test cert/key inputs
  //   - sign_priv:    message creator's private key used to sign
  //   - verify_cert:  message creator's public key (certificate) used to verify
  charbuf sign_priv = { .chars = NULL, .len = 0 };
  charbuf verify_cert = { .chars = NULL, .len = 0 };

  result = pem_priv_to_der("test/data/msg_test_req_priv.pem", &sign_priv);
  if (result != 0)
  {
    CU_FAIL("DER key from file (test/data/msg_test_req_priv.pem) error");
  }
  result = pem_cert_to_der("test/data/msg_test_req_pub.pem", &verify_cert);
  if (result != 0)
  {
    CU_FAIL("DER cert from file (test/data/msg_test_req_pub.pem) error");
  }

  // DER encode signed CMS: test that NULL input message is handled as expected
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               0, NULL,
                               0, NULL,
                               CMS_SIGN_DER_ENCODE_NULL_MSG_IN,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // DER encode signed CMS: test that NULL input message is handled as expected
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               0, NULL,
                               0, NULL,
                               CMS_SIGN_DER_ENCODE_NULL_BUF_OUT,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // DER encode signed CMS: test valid input produces expected encoded result
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               0, NULL,
                               0, NULL,
                               CMS_SIGN_DER_ENCODE_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_OK);

  // create test cert/key inputs
  //   - encrypt_cert: message recipient's public key (certificate) used to encrypt
  //   - decrypt_priv: message recipeients private key used to decrypt
  charbuf encrypt_cert = { .chars = NULL, .len = 0 };
  charbuf decrypt_priv = { .chars = NULL, .len = 0 };

  result = pem_cert_to_der("test/data/msg_test_resp_pub.pem", &encrypt_cert);
  if (result != 0)
  {
    CU_FAIL("DER cert from file (test/data/msg_test_resp_pub.pem) error");
  }
  result = pem_priv_to_der("test/data/msg_test_resp_priv.pem", &decrypt_priv);
  if (result != 0)
  {
    CU_FAIL("DER key from file (test/data/msg_test_resp_priv.pem) error");
  }

  // DER encode enveloped CMS: test that NULL input message is handled as expected
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               CMS_ENCRYPT_DER_ENCODE_NULL_MSG_IN,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // DER encode enveloped CMS: test that NULL input message is handled as expected
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               CMS_ENCRYPT_DER_ENCODE_NULL_BUF_OUT,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // DER encode enveloped CMS: test valid input produces expected encoded result
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               CMS_ENCRYPT_DER_ENCODE_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_OK);

  // Clean-up
  free_charbuf(&test_cipher);
  free_charbuf(&test_key_id);
  free_charbuf(&test_data);
  free_charbuf(&test_status);
  free_charbuf(&sign_priv);
  free_charbuf(&verify_cert);
  free_charbuf(&encrypt_cert);
  free_charbuf(&decrypt_priv);
  if (empty_CA_table(eid, NULL) != 0)
  {
    CU_FAIL("error emptying CA table");
  }
}

void test_der_decode_pelz_msg(void)
{
  pelz_log(LOG_DEBUG, "Start der_decode_pelz_msg() functionality test");

  sgx_status_t retval = SGX_ERROR_UNEXPECTED;
  MsgTestStatus result = MSG_TEST_UNKNOWN_ERROR;

  // specify test pelz test field values
  PELZ_MSG_TYPE test_msg_type = REQUEST;
  PELZ_REQ_TYPE test_req_type = KEY_WRAP;

  charbuf test_cipher = { .chars = NULL, .len = 0 };
  test_cipher.chars = malloc(strlen("AES/KeyWrap/RFC3394NoPadding/128") + 1);
  sprintf((char *) test_cipher.chars, "AES/KeyWrap/RFC3394NoPadding/128");
  test_cipher.len = strlen("AES/KeyWrap/RFC3394NoPadding/128");

  charbuf test_key_id = { .chars = NULL, .len = 0 };
  test_key_id.chars = malloc(strlen("file://test.key") + 1);
  sprintf((char *) test_key_id.chars, "file://test.key");
  test_key_id.len = strlen("file://test.key");

  charbuf test_data = { .chars = NULL, .len = 0 };
  test_data.chars = malloc(strlen("create enveloped message test data") + 1);
  sprintf((char *) test_data.chars, "create enveloped message test data");
  test_data.len = strlen("create enveloped message test data");

  charbuf test_status = { .chars = NULL, .len = 0 };
  test_status.chars = malloc(strlen("create enveloped message status") + 1);
  sprintf((char *) test_data.chars, "create enveloped message status");
  test_data.len = strlen("create enveloped message status");

  // ASN.1 DER decode: test NULL pointer to input byte array handled
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_PARSE_DER_DECODE_NULL_BUF_IN,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // ASN.1 DER decode: test empty input byte array handled
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_PARSE_DER_DECODE_EMPTY_BUF_IN,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // ASN.1 DER decode: test invalid decoded message format parameter handled
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_PARSE_DER_DECODE_INVALID_FORMAT,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // ASN.1 DER decode: test valid input produces expected message output
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               0, NULL,
                               ASN1_PARSE_DER_DECODE_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_OK);

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

  // create test cert/key inputs
  //   - sign_priv:    message creator's private key used to sign
  //   - verify_cert:  message creator's public key (certificate) used to verify
  charbuf sign_priv = { .chars = NULL, .len = 0 };
  charbuf verify_cert = { .chars = NULL, .len = 0 };

  result = pem_priv_to_der("test/data/msg_test_req_priv.pem", &sign_priv);
  if (result != 0)
  {
    CU_FAIL("DER key from file (test/data/msg_test_req_priv.pem) error");
  }
  result = pem_cert_to_der("test/data/msg_test_req_pub.pem", &verify_cert);
  if (result != 0)
  {
    CU_FAIL("DER cert from file (test/data/msg_test_req_pub.pem) error");
  }

  // DER decode to signed CMS: test NULL pointer to input byte array handled
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               0, NULL,
                               0, NULL,
                               CMS_VERIFY_DER_DECODE_NULL_BUF_IN,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // DER decode to signed CMS: test invalid decoded message format parameter handled
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               0, NULL,
                               0, NULL,
                               CMS_VERIFY_DER_DECODE_INVALID_FORMAT,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // DER decode to signed CMS: test valid input produces expected message output
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               0, NULL,
                               0, NULL,
                               CMS_VERIFY_DER_DECODE_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_OK);

  // create test cert/key inputs
  //   - encrypt_cert: message recipient's public key (certificate) used to encrypt
  //   - decrypt_priv: message recipeients private key used to decrypt
  charbuf encrypt_cert = { .chars = NULL, .len = 0 };
  charbuf decrypt_priv = { .chars = NULL, .len = 0 };

  result = pem_cert_to_der("test/data/msg_test_resp_pub.pem", &encrypt_cert);
  if (result != 0)
  {
    CU_FAIL("DER cert from file (test/data/msg_test_resp_pub.pem) error");
  }
  result = pem_priv_to_der("test/data/msg_test_resp_priv.pem", &decrypt_priv);
  if (result != 0)
  {
    CU_FAIL("DER key from file (test/data/msg_test_resp_priv.pem) error");
  }

  // DER decode to enveloped CMS: test NULL pointer to input byte array handled
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               CMS_DECRYPT_DER_DECODE_NULL_BUF_IN,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // DER decode to enveloped CMS: test invalid message format parameter handled
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               CMS_DECRYPT_DER_DECODE_INVALID_FORMAT,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // DER decode to enveloped CMS: test valid input produces expected message output
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               CMS_DECRYPT_DER_DECODE_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_OK);

  // Clean-up
  free_charbuf(&test_cipher);
  free_charbuf(&test_key_id);
  free_charbuf(&test_data);
  free_charbuf(&test_status);
  free_charbuf(&sign_priv);
  free_charbuf(&verify_cert);
  free_charbuf(&encrypt_cert);
  free_charbuf(&decrypt_priv);
  if (empty_CA_table(eid, NULL) != 0)
  {
    CU_FAIL("error emptying CA table");
  }
}

void test_construct_deconstruct_pelz_msg(void)
{
  pelz_log(LOG_DEBUG, "Start end-to-end pelz message functionality test");

  sgx_status_t retval = SGX_ERROR_UNEXPECTED;
  MsgTestStatus result = MSG_TEST_UNKNOWN_ERROR;

  // specify test pelz test field values
  PELZ_MSG_TYPE test_msg_type = REQUEST;
  PELZ_REQ_TYPE test_req_type = KEY_WRAP;

  charbuf test_cipher = { .chars = NULL, .len = 0 };
  test_cipher.chars = malloc(strlen("AES/KeyWrap/RFC3394NoPadding/128") + 1);
  sprintf((char *) test_cipher.chars, "AES/KeyWrap/RFC3394NoPadding/128");
  test_cipher.len = strlen("AES/KeyWrap/RFC3394NoPadding/128");

  charbuf test_key_id = { .chars = NULL, .len = 0 };
  test_key_id.chars = malloc(strlen("file://test.key") + 1);
  sprintf((char *) test_key_id.chars, "file://test.key");
  test_key_id.len = strlen("file://test.key");

  charbuf test_data = { .chars = NULL, .len = 0 };
  test_data.chars = malloc(strlen("create enveloped message test data") + 1);
  sprintf((char *) test_data.chars, "create enveloped message test data");
  test_data.len = strlen("create enveloped message test data");

  charbuf test_status = { .chars = NULL, .len = 0 };
  test_status.chars = malloc(strlen("create enveloped message status") + 1);
  sprintf((char *) test_data.chars, "create enveloped message status");
  test_data.len = strlen("create enveloped message status");

  // create test cert/key inputs
  //   - sign_priv:    message creator's private key used to sign
  //   - verify_cert:  message creator's public key (certificate) used to verifye test cert/key inputs
  //   - encrypt_cert: message recipient's public key (certificate) used to encrypt
  //   - decrypt_priv: message recipients private key used to decrypt
  charbuf sign_priv = { .chars = NULL, .len = 0 };
  charbuf verify_cert = { .chars = NULL, .len = 0 };
  charbuf encrypt_cert = { .chars = NULL, .len = 0 };
  charbuf decrypt_priv = { .chars = NULL, .len = 0 };
  result = pem_priv_to_der("test/data/msg_test_req_priv.pem", &sign_priv);
  if (result != 0)
  {
    CU_FAIL("DER key from file (test/data/msg_test_req_priv.pem) error");
  }
  result = pem_cert_to_der("test/data/msg_test_req_pub.pem", &verify_cert);
  if (result != 0)
  {
    CU_FAIL("DER cert from file (test/data/msg_test_req_pub.pem) error");
  }
  result = pem_cert_to_der("test/data/msg_test_resp_pub.pem", &encrypt_cert);
  if (result != 0)
  {
    CU_FAIL("DER cert from file (test/data/msg_test_resp_pub.pem) error");
  }
  result = pem_priv_to_der("test/data/msg_test_resp_priv.pem", &decrypt_priv);
  if (result != 0)
  {
    CU_FAIL("DER key from file (test/data/msg_test_resp_priv.pem) error");
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

  // test NULL pointer as input byte array parameter to "construct"
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               CONSTRUCT_NULL_MSG_DATA_IN,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // test NULL pointer as input local certificate parameter to "construct"
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               CONSTRUCT_NULL_CERT,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // test NULL pointer as input local private key parameter to "construct"
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               CONSTRUCT_NULL_PRIV,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // test NULL pointer as input peer certificate parameter to "construct"
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               CONSTRUCT_NULL_PEER_CERT,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // test NULL pointer as output byte array parameter to "construct"
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               CONSTRUCT_NULL_BUF_OUT,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // test "construct" pelz message functionality
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               CONSTRUCT_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_OK);

  // test NULL pointer as input message byte array parameter to "deconstruct"
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               DECONSTRUCT_NULL_MSG_IN,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // test NULL pointer as input local certificate parameter to "deconstruct"
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               DECONSTRUCT_NULL_CERT,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // test NULL pointer as input local private key parameter to "deconstruct"
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               DECONSTRUCT_NULL_PRIV,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // test NULL pointer to peer cert output parameter for "deconstruct"
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               DECONSTRUCT_NULL_PEER_CERT_OUT,
                               &result);
  CU_ASSERT(result == MSG_TEST_PARAM_HANDLING_OK);

  // test "deconstruct" pelz message functionality
  pelz_enclave_msg_test_helper(eid, &retval,
                               (uint8_t) test_msg_type,
                               (uint8_t) test_req_type,
                               test_cipher.len, test_cipher.chars,
                               test_key_id.len, test_key_id.chars,
                               test_data.len, test_data.chars,
                               test_status.len, test_status.chars,
                               sign_priv.len, sign_priv.chars,
                               verify_cert.len, verify_cert.chars,
                               encrypt_cert.len, encrypt_cert.chars,
                               decrypt_priv.len, decrypt_priv.chars,
                               DECONSTRUCT_FUNCTIONALITY,
                               &result);
  CU_ASSERT(result == MSG_TEST_OK);

  // Clean-up
  free_charbuf(&test_cipher);
  free_charbuf(&test_key_id);
  free_charbuf(&test_data);
  free_charbuf(&test_status);
  free_charbuf(&sign_priv);
  free_charbuf(&verify_cert);
  free_charbuf(&encrypt_cert);
  free_charbuf(&decrypt_priv);
  if (empty_CA_table(eid, NULL) != 0)
  {
    CU_FAIL("error emptying CA table");
  }
}