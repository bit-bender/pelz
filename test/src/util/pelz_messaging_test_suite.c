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

  charbuf test_cipher = new_charbuf(0);
  test_cipher.len = strlen("AES/KeyWrap/RFC3394NoPadding/128");
  test_cipher.chars = malloc(test_cipher.len + 1);
  sprintf((char *) test_cipher.chars, "AES/KeyWrap/RFC3394NoPadding/128");

  charbuf test_tag = new_charbuf(0);

  charbuf test_iv = new_charbuf(0);

  charbuf test_key_id = new_charbuf(0);
  test_key_id.len = strlen("file://test.key");
  test_key_id.chars = malloc(test_key_id.len + 1);
  sprintf((char *) test_key_id.chars, "file://test.key");

  charbuf test_data = new_charbuf(0);
  test_data.len = strlen("create ASN.1 message test data");
  test_data.chars = malloc(test_data.len + 1);
  sprintf((char *) test_data.chars, "create ASN.1 message test data");

  charbuf test_status = new_charbuf(0);
  test_status.len = strlen("create ASN.1 message status");
  test_status.chars = malloc(test_status.len + 1);
  sprintf((char *) test_status.chars, "create ASN.1 message status");

  // invalid (less than MSG_TYPE_MIN) message type should fail param checks
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        MSG_TYPE_MIN - 1, test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_ASN1_CREATE_ERROR));

  // invalid (greater than MSG_TYPE_MAX) message type should fail param checks
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        MSG_TYPE_MAX + 1, test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_data.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_ASN1_CREATE_ERROR));

  // invalid (less than REQ_TYPE_MIN) message type should fail param checks
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        test_msg_type, REQ_TYPE_MIN - 1,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_ASN1_CREATE_ERROR));

  // invalid (greater than REQ_TYPE_MAX) message type should fail param checks
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        test_msg_type, REQ_TYPE_MAX + 1,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_ASN1_CREATE_ERROR));

  // null cipher input should fail param checks
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        test_msg_type, test_req_type,
                                        test_cipher.len, NULL,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_ASN1_CREATE_ERROR));

  // empty (zero-length) cipher input should fail param checks
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        test_msg_type, test_req_type,
                                        0, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_ASN1_CREATE_ERROR));

  // NULL KEK key ID input should fail param checks
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        test_msg_type, test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, NULL,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_ASN1_CREATE_ERROR));

  // empty (zero-length) KEK key ID input should fail param checks
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        test_msg_type, test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        0, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_ASN1_CREATE_ERROR));

  // NULL data input should fail param checks
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        test_msg_type, test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, NULL,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_ASN1_CREATE_ERROR));

  // empty (zero-length) data input should fail param checks
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        test_msg_type, test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        0, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_ASN1_CREATE_ERROR));

  // NULL status input should fail param checks
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        test_msg_type, test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_ASN1_CREATE_ERROR));

  // empty (zero-length) status input should fail param checks
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        test_msg_type, test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        0, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_ASN1_CREATE_ERROR));

  // ASN.1 message creation test case with valid parameters should not error
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        test_msg_type, test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_OK));

  // Clean-up
  free_charbuf(&test_cipher);
  free_charbuf(&test_tag);
  free_charbuf(&test_iv);
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

  charbuf test_cipher = new_charbuf(0);
  test_cipher.len = strlen("AES/KeyWrap/RFC3394NoPadding/128");
  test_cipher.chars = malloc(test_cipher.len + 1);
  sprintf((char *) test_cipher.chars, "AES/KeyWrap/RFC3394NoPadding/128");

  charbuf test_tag = new_charbuf(0);

  charbuf test_iv = new_charbuf(0);

  charbuf test_key_id = new_charbuf(0);
  test_key_id.len = strlen("file://test.key");
  test_key_id.chars = malloc(test_key_id.len + 1);
  sprintf((char *) test_key_id.chars, "file://test.key");

  charbuf test_data = new_charbuf(0);
  test_data.len = strlen("parse ASN.1 message test data");
  test_data.chars = malloc(test_data.len + 1);
  sprintf((char *) test_data.chars, "parse ASN.1 message test data");

  charbuf test_status = new_charbuf(0);
  test_status.len = strlen("parse ASN.1 message status");
  test_status.chars = malloc(test_status.len + 1);
  sprintf((char *) test_status.chars, "parse ASN.1 message status");

  // invalid 'message type' field tag should result in parse error
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        test_msg_type, test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_INVALID_MSG_TYPE_TAG);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // invalid message type field value (< MSG_TYPE_MIN) should error
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        test_msg_type, test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_INVALID_MSG_TYPE_LO);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // invalid message type field value (> MSG_TYPE_MAX) should error
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        test_msg_type, test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_INVALID_MSG_TYPE_HI);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // invalid req_type field tag should result in parse error
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        test_msg_type, test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_INVALID_REQ_TYPE_TAG);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // invalid request type field value (< REQ_TYPE_MIN) should error
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        test_msg_type, test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_INVALID_REQ_TYPE_LO);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // invalid request type field value (> REQ_TYPE_MAX) should error
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        test_msg_type, test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_INVALID_REQ_TYPE_HI);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // invalid cipher field tag should result in parse error
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        test_msg_type, test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_INVALID_CIPHER_TAG);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // invalid key ID field tag should result in parse error
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        test_msg_type, test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_INVALID_KEY_ID_TAG);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // invalid data field tag should result in parse error
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        test_msg_type, test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_INVALID_DATA_TAG);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // invalid status field tag should result in parse error
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        test_msg_type, test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_INVALID_STATUS_TAG);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // valid (unmodified) message format/contents should parse successfully
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        test_msg_type, test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_OK));

  // Clean-up
  free_charbuf(&test_cipher);
  free_charbuf(&test_tag);
  free_charbuf(&test_iv);
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

  charbuf test_cipher = new_charbuf(0);
  test_cipher.len = strlen("AES/KeyWrap/RFC3394NoPadding/128");
  test_cipher.chars = malloc(test_cipher.len + 1);
  sprintf((char *) test_cipher.chars, "AES/KeyWrap/RFC3394NoPadding/128");

  charbuf test_tag = new_charbuf(0);

  charbuf test_iv = new_charbuf(0);

  charbuf test_key_id = new_charbuf(0);
  test_key_id.len = strlen("file://test.key");
  test_key_id.chars = malloc(test_key_id.len + 1);
  sprintf((char *) test_key_id.chars, "file://test.key");

  charbuf test_data = new_charbuf(0);
  test_data.len = strlen("create signed message test data");
  test_data.chars = malloc(test_data.len + 1);
  sprintf((char *) test_data.chars, "create signed message test data");

  charbuf test_status = new_charbuf(0);
  test_status.len = strlen("create signed message status");
  test_status.chars = malloc(test_status.len + 1);
  sprintf((char *) test_status.chars, "create signed message status");

  // create test cert/key inputs
  charbuf test_cert = new_charbuf(0);
  charbuf test_priv = new_charbuf(0);
  result = keypair_pem_to_der("test/data/msg_test_req_pub.pem",
                              "test/data/msg_test_req_priv.pem",
                              &test_cert,
                              &test_priv);
  if (result != 0)
  {
    CU_FAIL("error creating DER formatted cert/key pair");
  }

  charbuf diff_cert = new_charbuf(0);
  charbuf diff_priv = new_charbuf(0);
  result = keypair_pem_to_der("test/data/msg_test_resp_pub.pem",
                              "test/data/msg_test_resp_priv.pem",
                              &diff_cert,
                              &diff_priv);
  if (result != 0)
  {
    CU_FAIL("error creating DER formatted cert/key pair");
  }

  pelz_log(LOG_DEBUG, "before CMS_SIGN_NULL_BUF_IN test");

  // NULL input data  pointer test case - invalid parameter should be handled
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        test_priv.len, test_priv.chars,
                                        test_cert.len, test_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_SIGN_NULL_BUF_IN);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // Empty input data buffer test cases - invalid parameter should be handled
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        test_priv.len, test_priv.chars,
                                        test_cert.len, test_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_SIGN_EMPTY_BUF_IN);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // NULL cert test case - invalid parameter should be handled
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        test_priv.len, test_priv.chars,
                                        test_cert.len, test_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_SIGN_NULL_CERT_IN);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // NULL private signing key should fail
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        test_priv.len, test_priv.chars,
                                        test_cert.len, test_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_SIGN_NULL_PRIV_IN);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // valid test case should pass
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        test_priv.len, test_priv.chars,
                                        test_cert.len, test_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_SIGN_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_OK));

  // Mismatched key/cert should fail
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        test_priv.len, test_priv.chars,
                                        diff_cert.len, diff_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_SIGN_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_SETUP_ERROR));

  // Clean-up
  free_charbuf(&test_cipher);
  free_charbuf(&test_tag);
  free_charbuf(&test_iv);
  free_charbuf(&test_key_id);
  free_charbuf(&test_data);
  free_charbuf(&test_status);
  free_charbuf(&test_cert);
  free_charbuf(&test_priv);
  free_charbuf(&diff_cert);
  free_charbuf(&diff_priv);
}

void test_verify_pelz_signed_msg(void)
{
  pelz_log(LOG_DEBUG, "Start verify_pelz_signed_msg() functionality test");

  sgx_status_t retval = SGX_ERROR_UNEXPECTED;
  MsgTestStatus result = MSG_TEST_UNKNOWN_ERROR;

  // specify test pelz test field values
  PELZ_MSG_TYPE test_msg_type = REQUEST;
  PELZ_REQ_TYPE test_req_type = KEY_WRAP;

  charbuf test_cipher = new_charbuf(0);
  test_cipher.len = strlen("AES/KeyWrap/RFC3394NoPadding/128");
  test_cipher.chars = malloc(test_cipher.len + 1);
  sprintf((char *) test_cipher.chars, "AES/KeyWrap/RFC3394NoPadding/128");

  charbuf test_tag = new_charbuf(0);

  charbuf test_iv = new_charbuf(0);

  charbuf test_key_id = new_charbuf(0);
  test_key_id.len = strlen("file://test.key");
  test_key_id.chars = malloc(test_key_id.len + 1);
  sprintf((char *) test_key_id.chars, "file://test.key");

  charbuf test_data = new_charbuf(0);
  test_data.len = strlen("verify signed message test data");
  test_data.chars = malloc(test_data.len + 1);
  sprintf((char *) test_data.chars, "verify signed message test data");

  charbuf test_status = new_charbuf(0);
  test_status.len = strlen("verify signed message status");
  test_status.chars = malloc(test_status.len + 1);
  sprintf((char *) test_status.chars, "verify signed message status");

  // create test cert/key inputs
  charbuf test_cert = new_charbuf(0);
  charbuf test_priv = new_charbuf(0);
  result = keypair_pem_to_der("test/data/msg_test_req_pub.pem",
                              "test/data/msg_test_req_priv.pem",
                              &test_cert,
                              &test_priv);
  if (result != 0)
  {
    CU_FAIL("error creating DER formatted cert/key pair");
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
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        test_priv.len, test_priv.chars,
                                        test_cert.len, test_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_VERIFY_NULL_MSG_IN);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // NULL output certificate pointer test case
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        test_priv.len, test_priv.chars,
                                        test_cert.len, test_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_VERIFY_NULL_BUF_OUT);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // NULL output certificate test case
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        test_priv.len, test_priv.chars,
                                        test_cert.len, test_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_VERIFY_NULL_CERT_OUT);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // valid test data should invoke succcessful signature verification test case
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        test_priv.len, test_priv.chars,
                                        test_cert.len, test_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_VERIFY_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_OK));

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

  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        test_priv.len, test_priv.chars,
                                        test_cert.len, test_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_VERIFY_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_VERIFY_ERROR));

  // Clean-up
  free_charbuf(&test_cipher);
  free_charbuf(&test_tag);
  free_charbuf(&test_iv);
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

  charbuf test_cipher = new_charbuf(0);
  test_cipher.len = strlen("AES/KeyWrap/RFC3394NoPadding/128");
  test_cipher.chars = malloc(test_cipher.len + 1);
  sprintf((char *) test_cipher.chars, "AES/KeyWrap/RFC3394NoPadding/128");

  charbuf test_tag = new_charbuf(0);

  charbuf test_iv = new_charbuf(0);

  charbuf test_key_id = new_charbuf(0);
  test_key_id.len = strlen("file://test.key");
  test_key_id.chars = malloc(test_key_id.len + 1);
  sprintf((char *) test_key_id.chars, "file://test.key");

  charbuf test_data = new_charbuf(0);
  test_data.len = strlen("create enveloped message test data");
  test_data.chars = malloc(test_data.len + 1);
  sprintf((char *) test_data.chars, "create enveloped message test data");

  charbuf test_status = new_charbuf(0);
  test_status.len = strlen("create enveloped message status");
  test_status.chars = malloc(test_status.len + 1);
  sprintf((char *) test_status.chars, "create enveloped message status");

  // create test cert/key inputs
  //   - sign_priv:    message creator's private key used to sign
  //   - verify_cert:  message creator's public key (certificate) used to verifye test cert/key inputs
  //   - encrypt_cert: message recipient's public key (certificate) used to encrypt
  //   - decrypt_priv: message recipients private key used to decrypt
  charbuf sign_priv = new_charbuf(0);
  charbuf verify_cert = new_charbuf(0);
  result = keypair_pem_to_der("test/data/msg_test_req_pub.pem",
                              "test/data/msg_test_req_priv.pem",
                              &verify_cert,
                              &sign_priv);
  if (result != 0)
  {
    CU_FAIL("error creating DER formatted cert/key pair");
  }

  charbuf encrypt_cert = new_charbuf(0);
  charbuf decrypt_priv = new_charbuf(0);
  result = keypair_pem_to_der("test/data/msg_test_resp_pub.pem",
                              "test/data/msg_test_resp_priv.pem",
                              &encrypt_cert,
                              &decrypt_priv);
  if (result != 0)
  {
    CU_FAIL("error creating DER formatted cert/key pair");
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
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        CMS_ENCRYPT_NULL_BUF_IN);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // empty input data should be handled as invalid parameter
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        CMS_ENCRYPT_EMPTY_BUF_IN);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // NULL input certificate should be handled as invalid parameter
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        CMS_ENCRYPT_NULL_CERT_IN);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // valid test case should pass
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        CMS_ENCRYPT_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_OK));

  // Clean-up
  free_charbuf(&test_cipher);
  free_charbuf(&test_tag);
  free_charbuf(&test_iv);
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

  charbuf test_cipher = new_charbuf(0);
  test_cipher.len = strlen("AES/KeyWrap/RFC3394NoPadding/128");
  test_cipher.chars = malloc(test_cipher.len + 1);
  sprintf((char *) test_cipher.chars, "AES/KeyWrap/RFC3394NoPadding/128");

  charbuf test_tag = new_charbuf(0);

  charbuf test_iv = new_charbuf(0);

  charbuf test_key_id = new_charbuf(0);
  test_key_id.len = strlen("file://test.key");
  test_key_id.chars = malloc(test_key_id.len + 1);
  sprintf((char *) test_key_id.chars, "file://test.key");

  charbuf test_data = new_charbuf(0);
  test_data.len = strlen("decrypt enveloped message test data");
  test_data.chars = malloc(test_data.len + 1);
  sprintf((char *) test_data.chars, "decrypt enveloped message test data");

  charbuf test_status = new_charbuf(0);
  test_status.len = strlen("decrypt enveloped message status");
  test_status.chars = malloc(test_status.len + 1);
  sprintf((char *) test_status.chars, "decrypt enveloped message status");

  // create test cert/key inputs
  //   - sign_priv:    message creator's private key used to sign
  //   - verify_cert:  message creator's public key (certificate) used to verifye test cert/key inputs
  //   - encrypt_cert: message recipient's public key (certificate) used to encrypt
  //   - decrypt_priv: message recipients private key used to decrypt
  charbuf sign_priv = new_charbuf(0);
  charbuf verify_cert = new_charbuf(0);
  result = keypair_pem_to_der("test/data/msg_test_req_pub.pem",
                              "test/data/msg_test_req_priv.pem",
                              &verify_cert,
                              &sign_priv);
  if (result != 0)
  {
    CU_FAIL("error creating DER formatted cert/key pair");
  }

  charbuf encrypt_cert = new_charbuf(0);
  charbuf decrypt_priv = new_charbuf(0);
  result = keypair_pem_to_der("test/data/msg_test_resp_pub.pem",
                              "test/data/msg_test_resp_priv.pem",
                              &encrypt_cert,
                              &decrypt_priv);
  if (result != 0)
  {
    CU_FAIL("error creating DER formatted cert/key pair");
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
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        CMS_DECRYPT_NULL_MSG_IN);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // NULL output buffer test case
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        CMS_DECRYPT_NULL_BUF_OUT);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // NULL input private key test case
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        CMS_DECRYPT_NULL_PRIV);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // NULL input cert test case
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        CMS_DECRYPT_NULL_CERT);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // valid test data should invoke succcessful CMS decryption test case
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        CMS_DECRYPT_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_OK));

  // wrong input private decryption key test case
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        sign_priv.len, sign_priv.chars,
                                        CMS_DECRYPT_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_DECRYPT_ERROR));

  // Clean-up
  free_charbuf(&test_cipher);
  free_charbuf(&test_tag);
  free_charbuf(&test_iv);
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

  charbuf test_cipher = new_charbuf(0);
  test_cipher.len = strlen("AES/KeyWrap/RFC3394NoPadding/128");
  test_cipher.chars = malloc(test_cipher.len + 1);
  sprintf((char *) test_cipher.chars, "AES/KeyWrap/RFC3394NoPadding/128");

  charbuf test_tag = new_charbuf(0);

  charbuf test_iv = new_charbuf(0);

  charbuf test_key_id = new_charbuf(0);
  test_key_id.len = strlen("file://test.key");
  test_key_id.chars = malloc(test_key_id.len + 1);
  sprintf((char *) test_key_id.chars, "file://test.key");

  charbuf test_data = new_charbuf(0);
  test_data.len = strlen("DER-encode message test data");
  test_data.chars = malloc(test_data.len + 1);
  sprintf((char *) test_data.chars, "DER-encode message test data");

  charbuf test_status = new_charbuf(0);
  test_status.len = strlen("DER-encode message status");
  test_status.chars = malloc(test_status.len + 1);
  sprintf((char *) test_status.chars, "DER-encode message status");

  // ASN.1 DER encode: test that NULL input message is handled as expected
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_DER_ENCODE_NULL_MSG_IN);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // ASN.1 DER encode: test that NULL output buffer pointer is handled as expected
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_DER_ENCODE_NULL_BUF_OUT);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // ASN.1 DER encode: test that invalid format parameter is handled as expected
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_DER_ENCODE_INVALID_FORMAT);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // ASN.1 DER encode: test with valid test input should produce expected encoded result
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_CREATE_DER_ENCODE_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_OK));

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
  charbuf sign_priv = new_charbuf(0);
  charbuf verify_cert = new_charbuf(0);
  result = keypair_pem_to_der("test/data/msg_test_req_pub.pem",
                              "test/data/msg_test_req_priv.pem",
                              &verify_cert,
                              &sign_priv);
  if (result != 0)
  {
    CU_FAIL("error creating DER formatted cert/key pair");
  }

  // DER encode signed CMS: test that NULL input message is handled
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_SIGN_DER_ENCODE_NULL_MSG_IN);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // DER encode signed CMS: test that NULL input message is handled
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_SIGN_DER_ENCODE_NULL_BUF_OUT);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // DER encode signed CMS: test that invalid format parameter is handled
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_SIGN_DER_ENCODE_INVALID_FORMAT);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // DER encode signed CMS: test valid input produces expected encoded result
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_SIGN_DER_ENCODE_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_OK));

  // create test cert/key inputs
  //   - encrypt_cert: message recipient's public key (certificate) used to encrypt
  //   - decrypt_priv: message recipeients private key used to decrypt
  charbuf encrypt_cert = new_charbuf(0);
  charbuf decrypt_priv = new_charbuf(0);
  result = keypair_pem_to_der("test/data/msg_test_resp_pub.pem",
                              "test/data/msg_test_resp_priv.pem",
                              &encrypt_cert,
                              &decrypt_priv);
  if (result != 0)
  {
    CU_FAIL("error creating DER formatted cert/key pair");
  }

  // DER encode enveloped CMS: test that NULL input message is handled
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        CMS_ENCRYPT_DER_ENCODE_NULL_MSG_IN);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // DER encode enveloped CMS: test that NULL input message is handled
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        CMS_ENCRYPT_DER_ENCODE_NULL_BUF_OUT);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // DER encode enveloped CMS: test that invalid format parameter is handled
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        CMS_ENCRYPT_DER_ENCODE_INVALID_FORMAT);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // DER encode enveloped CMS: test valid input produces expected encoded result
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        CMS_ENCRYPT_DER_ENCODE_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_OK));

  // Clean-up
  free_charbuf(&test_cipher);
  free_charbuf(&test_tag);
  free_charbuf(&test_iv);
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

  charbuf test_cipher = new_charbuf(0);
  test_cipher.len = strlen("AES/KeyWrap/RFC3394NoPadding/128");
  test_cipher.chars = malloc(test_cipher.len + 1);
  sprintf((char *) test_cipher.chars, "AES/KeyWrap/RFC3394NoPadding/128");

  charbuf test_tag = new_charbuf(0);

  charbuf test_iv = new_charbuf(0);

  charbuf test_key_id = new_charbuf(0);
  test_key_id.len = strlen("file://test.key");
  test_key_id.chars = malloc(test_key_id.len + 1);
  sprintf((char *) test_key_id.chars, "file://test.key");

  charbuf test_data = new_charbuf(0);
  test_data.len = strlen("DER-decode message test data");
  test_data.chars = malloc(test_data.len + 1);
  sprintf((char *) test_data.chars, "DER-decode message test data");

  charbuf test_status = new_charbuf(0);
  test_status.len = strlen("DER-decode message status");
  test_status.chars = malloc(test_status.len + 1);
  sprintf((char *) test_status.chars, "DER-decode message status");

  // ASN.1 DER decode: test NULL pointer to input byte array handled
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_DER_DECODE_NULL_BUF_IN);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // ASN.1 DER decode: test empty input byte array handled
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_DER_DECODE_EMPTY_BUF_IN);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // ASN.1 DER decode: test invalid decoded message format parameter handled
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_DER_DECODE_INVALID_FORMAT);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // ASN.1 DER decode: test valid input produces expected message output
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        0, NULL,
                                        ASN1_PARSE_DER_DECODE_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_OK));

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
  //   - encrypt_cert: message recipient's public key (certificate) used to encrypt
  //   - decrypt_priv: message recipeients private key used to decrypt
  charbuf sign_priv = new_charbuf(0);
  charbuf verify_cert = new_charbuf(0);
  result = keypair_pem_to_der("test/data/msg_test_req_pub.pem",
                              "test/data/msg_test_req_priv.pem",
                              &verify_cert,
                              &sign_priv);
  if (result != 0)
  {
    CU_FAIL("error creating DER formatted cert/key pair");
  }

  // DER decode to signed CMS: test NULL pointer to input byte array handled
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_VERIFY_DER_DECODE_NULL_BUF_IN);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // DER decode to signed CMS: test empty input byte array handled
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_VERIFY_DER_DECODE_EMPTY_BUF_IN);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // DER decode to signed CMS: test invalid decoded message format parameter handled
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_VERIFY_DER_DECODE_INVALID_FORMAT);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // DER decode to signed CMS: test valid input produces expected message output
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        0, NULL,
                                        0, NULL,
                                        CMS_VERIFY_DER_DECODE_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_OK));

  charbuf encrypt_cert = new_charbuf(0);
  charbuf decrypt_priv = new_charbuf(0);
  result = keypair_pem_to_der("test/data/msg_test_resp_pub.pem",
                              "test/data/msg_test_resp_priv.pem",
                              &encrypt_cert,
                              &decrypt_priv);
  if (result != 0)
  {
    CU_FAIL("error creating DER formatted cert/key pair");
  }

  // DER decode to enveloped CMS: test NULL pointer to input byte array handled
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        CMS_DECRYPT_DER_DECODE_NULL_BUF_IN);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // DER decode to enveloped CMS: test invalid message format parameter handled
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        CMS_DECRYPT_DER_DECODE_INVALID_FORMAT);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // DER decode to enveloped CMS: test valid input produces expected message output
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        CMS_DECRYPT_DER_DECODE_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_OK));

  // Clean-up
  free_charbuf(&test_cipher);
  free_charbuf(&test_tag);
  free_charbuf(&test_iv);
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

  charbuf test_cipher = new_charbuf(0);
  test_cipher.len = strlen("AES/KeyWrap/RFC3394NoPadding/128");
  test_cipher.chars = malloc(test_cipher.len + 1);
  sprintf((char *) test_cipher.chars, "AES/KeyWrap/RFC3394NoPadding/128");

  charbuf test_tag = new_charbuf(0);

  charbuf test_iv = new_charbuf(0);

  charbuf test_key_id = new_charbuf(0);
  test_key_id.len = strlen("file://test.key");
  test_key_id.chars = malloc(test_key_id.len + 1);
  sprintf((char *) test_key_id.chars, "file://test.key");

  charbuf test_data = new_charbuf(0);
  test_data.len = strlen("(de)construct message test data");
  test_data.chars = malloc(test_data.len + 1);
  sprintf((char *) test_data.chars, "(de)construct message test data");

  charbuf test_status = new_charbuf(0);
  test_status.len = strlen("(de)construct message status");
  test_status.chars = malloc(test_status.len + 1);
  sprintf((char *) test_status.chars, "(de)construct message status");

  // create test cert/key inputs
  //   - sign_priv:    message creator's private key used to sign
  //   - verify_cert:  message creator's public key (certificate) used to verifye test cert/key inputs
  //   - encrypt_cert: message recipient's public key (certificate) used to encrypt
  //   - decrypt_priv: message recipients private key used to decrypt
  charbuf sign_priv = new_charbuf(0);
  charbuf verify_cert = new_charbuf(0);
  charbuf encrypt_cert = new_charbuf(0);
  charbuf decrypt_priv = new_charbuf(0);
  result = keypair_pem_to_der("test/data/msg_test_req_pub.pem",
                              "test/data/msg_test_req_priv.pem",
                              &verify_cert,
                              &sign_priv);
  if (result != 0)
  {
    CU_FAIL("error creating DER formatted cert/key pair");
  }

  result = keypair_pem_to_der("test/data/msg_test_resp_pub.pem",
                              "test/data/msg_test_resp_priv.pem",
                              &encrypt_cert,
                              &decrypt_priv);
  if (result != 0)
  {
    CU_FAIL("error creating DER formatted cert/key pair");
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

  // test NULL pointer as input local certificate parameter to "construct"
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        CONSTRUCT_NULL_CERT);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // test NULL pointer as input local private key parameter to "construct"
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        CONSTRUCT_NULL_PRIV);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // test NULL pointer as input peer certificate parameter to "construct"
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        CONSTRUCT_NULL_PEER_CERT);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // test NULL pointer as output byte array parameter to "construct"
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        CONSTRUCT_NULL_BUF_OUT);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // test "construct" pelz message functionality
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        CONSTRUCT_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_OK));

  // test NULL pointer as input message byte array parameter to "deconstruct"
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        DECONSTRUCT_NULL_MSG_IN);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // test NULL pointer as input local certificate parameter to "deconstruct"
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        DECONSTRUCT_NULL_CERT);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // test NULL pointer as input local private key parameter to "deconstruct"
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        DECONSTRUCT_NULL_PRIV);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // test NULL pointer to peer cert output parameter for "deconstruct"
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        DECONSTRUCT_NULL_PEER_CERT_OUT);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_PARAM_HANDLING_OK));

  // test "deconstruct" pelz message functionality
  retval = pelz_enclave_msg_test_helper(eid, (int *) &result,
                                        (uint8_t) test_msg_type,
                                        (uint8_t) test_req_type,
                                        test_cipher.len, test_cipher.chars,
                                        test_tag.len, test_tag.chars,
                                        test_iv.len, test_iv.chars,
                                        test_key_id.len, test_key_id.chars,
                                        test_data.len, test_data.chars,
                                        test_status.len, test_status.chars,
                                        sign_priv.len, sign_priv.chars,
                                        verify_cert.len, verify_cert.chars,
                                        encrypt_cert.len, encrypt_cert.chars,
                                        decrypt_priv.len, decrypt_priv.chars,
                                        DECONSTRUCT_FUNCTIONALITY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == MSG_TEST_OK));

  // Clean-up
  free_charbuf(&test_cipher);
  free_charbuf(&test_tag);
  free_charbuf(&test_iv);
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