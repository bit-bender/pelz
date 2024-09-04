/*
 * enclave_helper_functions.c
 */

#include "enclave_helper_functions.h"

X509  *deserialize_cert(const unsigned char *der_cert, long der_cert_size)
{
  if ((der_cert == NULL) || (der_cert_size <= 0))
  {
    pelz_sgx_log(LOG_ERR, "NULL/empty input DER-formatted X509 certificate")
    return NULL;
  }

  X509 *decoded_cert = X509_new();
  d2i_X509(&decoded_cert, &der_cert, der_cert_size);

  return decoded_cert;
}

EVP_PKEY *deserialize_pkey(const unsigned char *der_pkey, long der_pkey_size)
{
  if ((der_pkey == NULL) || (der_pkey_size == 0))
  {
    pelz_sgx_log(LOG_ERR, "NULL/empty input DER-formatted EVP_PKEY");
    return NULL;
  }

  EVP_PKEY *decoded_pkey = EVP_PKEY_new();
  d2i_PrivateKey(EVP_PKEY_EC, &decoded_pkey, &der_pkey, der_pkey_size);

  return decoded_pkey;
}

TableResponseStatus test_table_lookup(TableType type,
                                      charbuf id,
                                      size_t *index)
{
  return (table_lookup(type, id, index));
}

int test_aes_keywrap_3394nopad_encrypt(size_t key_len,
                                       unsigned char *key,
                                       size_t inData_len,
                                       unsigned char *inData,
                                       size_t *outData_len,
                                       unsigned char **outData)
{
  int ret = -1;
  unsigned char *output = NULL;
  size_t output_len = 0;

  cipher_data_t cipher_data_st;
  cipher_data_st.iv = NULL;
  cipher_data_st.iv_len = 0;
  cipher_data_st.tag = NULL;
  cipher_data_st.tag_len = 0;
  cipher_data_st.cipher = *outData;
  cipher_data_st.cipher_len = *outData_len;

  ret = pelz_aes_keywrap_3394nopad_encrypt(key, key_len, inData, inData_len, &cipher_data_st);
  *outData_len = output_len;
  if (output_len != 0)
  {
    ocall_malloc(*outData_len, outData);
    memcpy(*outData, output, *outData_len);
  }
  return (ret);
}

int test_aes_keywrap_3394nopad_decrypt(size_t key_len,
                                       unsigned char *key,
                                       size_t inData_len,
                                       unsigned char *inData,
                                       size_t *outData_len,
                                       unsigned char **outData)
{
  int ret = -1;
  unsigned char *output = NULL;
  size_t output_len = 0;

  cipher_data_t cipher_data_st;
  cipher_data_st.cipher = inData;
  cipher_data_st.cipher_len = inData_len;
  cipher_data_st.tag = NULL;
  cipher_data_st.tag_len = 0;
  cipher_data_st.iv = NULL;
  cipher_data_st.iv_len = 0;

  ret = pelz_aes_keywrap_3394nopad_decrypt(key, key_len, cipher_data_st, &output, &output_len);
  *outData_len = output_len;
  if (output_len != 0)
  {
    ocall_malloc(*outData_len, outData);
    memcpy(*outData, output, *outData_len);
  }
  return (ret);
}

MsgTestStatus pelz_asn1_msg_test_helper(MsgTestSelect test_select,
                                        PELZ_MSG_DATA msg_data_in,
                                        charbuf *der_asn1_msg_out)
{
  PelzMessagingStatus retval = PELZ_MSG_UNKNOWN_ERROR;
  bool invalid_param_test_case = false;

  PELZ_MSG *asn1_msg = NULL;

  switch (test_select)
  {
  // parse ASN.1 message test case: NULL input message (initialized to NULL)
  case ASN1_PARSE_NULL_MSG_IN:
    break;

  // all other test cases
  default:
    asn1_msg = create_pelz_asn1_msg(msg_data_in);
    if (asn1_msg == NULL)
    {
      return MSG_TEST_ASN1_CREATE_ERROR;
    }
    break;
  }

  // creaste ASN.1 message test case: if error, would not reach this point
  if (test_select == ASN1_CREATE_FUNCTIONALITY)
  {
    return MSG_TEST_OK;
  }

  // modify ASN.1 test message fields for invalid parse parameter tests
  switch(test_select)
  {
  // parse ASN.1 message test case: incorrect 'type' tag for 'message type'
  case ASN1_PARSE_INVALID_MSG_TYPE_TAG:
    asn1_msg->msg_type->type = V_ASN1_INTEGER;
    break;

  // parse ASN.1 message test case: invalid (too small) 'message type' value
  case ASN1_PARSE_INVALID_MSG_TYPE_LO:
    if (ASN1_ENUMERATED_set_int64(asn1_msg->msg_type,
                                  (int64_t) (MSG_TYPE_MIN-1)) != 1)
    {
      pelz_sgx_log(LOG_ERR, "error modifying ASN.1 message type field");
      PELZ_MSG_free(asn1_msg);
      return MSG_TEST_SETUP_ERROR;
    }
    break;

  // parse ASN.1 message test case: invalid (too large) 'message type' value
  case ASN1_PARSE_INVALID_MSG_TYPE_HI:
    if (ASN1_ENUMERATED_set_int64(asn1_msg->msg_type,
                                  (int64_t) (MSG_TYPE_MAX+1)) != 1)
    {
      pelz_sgx_log(LOG_ERR, "error modifying ASN.1 message type field");
      PELZ_MSG_free(asn1_msg);
      return MSG_TEST_SETUP_ERROR;
    }
    break;

  // parse ASN.1 message test case: incorrect 'type' tag for 'request type'
  case ASN1_PARSE_INVALID_REQ_TYPE_TAG:
    asn1_msg->req_type->type = V_ASN1_BOOLEAN;
    break;

  // parse ASN.1 message test case: invalid (too small) 'request type' value
  case ASN1_PARSE_INVALID_REQ_TYPE_LO:
    if (ASN1_ENUMERATED_set_int64(asn1_msg->req_type,
                                  (int64_t) (REQ_TYPE_MIN-1)) != 1)
    {
      pelz_sgx_log(LOG_ERR, "error modifying ASN.1 request type field");
      PELZ_MSG_free(asn1_msg);
      return MSG_TEST_SETUP_ERROR;
    }
    break;

  // parse ASN.1 message test case: invalid (too large) 'request type' value
  case ASN1_PARSE_INVALID_REQ_TYPE_HI:
    if (ASN1_ENUMERATED_set_int64(asn1_msg->req_type,
                                  (int64_t) (REQ_TYPE_MAX+1)) != 1)
    {
      pelz_sgx_log(LOG_ERR, "error modifying ASN.1 request type field");
      PELZ_MSG_free(asn1_msg);
      return MSG_TEST_SETUP_ERROR;
    }
    break;

  // parse ASN.1 message test case: invalid tag for 'cipher' field
  case ASN1_PARSE_INVALID_CIPHER_TAG:
    asn1_msg->cipher->type = V_ASN1_OCTET_STRING;
    break;

  // parse ASN.1 message test case: invalid tag for 'key ID' field
  case ASN1_PARSE_INVALID_KEY_ID_TAG:
    asn1_msg->key_id->type = V_ASN1_GENERALSTRING;
    break;

  // parse ASN.1 message test case: invalid tag for 'data' field
  case ASN1_PARSE_INVALID_DATA_TAG:
    asn1_msg->data->type = V_ASN1_UTF8STRING;
    break;

  // parse ASN.1 message test case: invalid tag for 'status' field
  case ASN1_PARSE_INVALID_STATUS_TAG:
    asn1_msg->status->type = V_ASN1_PRINTABLESTRING;
    break;

  // all other test cases: no modification of ASN.1 test message
  default:
    break;
  }

  // invoke PELZ_MSG ASN.1 parsing functionality
  PELZ_MSG_DATA parsed_test_msg_data;
  retval = parse_pelz_asn1_msg(asn1_msg, &parsed_test_msg_data);

  switch(test_select)
  {
  // parse ASN.1 test cases involving invalid tag for a message field
  case ASN1_PARSE_INVALID_MSG_TYPE_TAG:
  case ASN1_PARSE_INVALID_REQ_TYPE_TAG:
  case ASN1_PARSE_INVALID_CIPHER_TAG:
  case ASN1_PARSE_INVALID_KEY_ID_TAG:
  case ASN1_PARSE_INVALID_DATA_TAG:
  case ASN1_PARSE_INVALID_STATUS_TAG:
    PELZ_MSG_free(asn1_msg);
    if (retval == PELZ_MSG_ASN1_TAG_ERROR)
    {
      return MSG_TEST_PARAM_HANDLING_OK;
    }
    return MSG_TEST_PARAM_HANDLING_ERROR;
    break;

  // parse ASN.1 message test case: invalid (too small) 'message type' value
  case ASN1_PARSE_INVALID_MSG_TYPE_LO:
  case ASN1_PARSE_INVALID_MSG_TYPE_HI:
  case ASN1_PARSE_INVALID_REQ_TYPE_LO:
  case ASN1_PARSE_INVALID_REQ_TYPE_HI:
    PELZ_MSG_free(asn1_msg);
    if (retval == PELZ_MSG_ASN1_PARSE_INVALID_RESULT)
    {
      return MSG_TEST_PARAM_HANDLING_OK;
    }
    return MSG_TEST_PARAM_HANDLING_ERROR;
    break;

    // all other test cases: no modification of ASN.1 test message
  default:
    if (retval != PELZ_MSG_OK)
    {
      pelz_sgx_log(LOG_ERR, "parse of test message failed");
      PELZ_MSG_free(asn1_msg);
      return MSG_TEST_ASN1_PARSE_ERROR;
    }
  }

  // if no error returned, validate parsed output against original input data
  if ((parsed_test_msg_data.msg_type != msg_data_in.msg_type) ||
      (parsed_test_msg_data.req_type != msg_data_in.req_type) ||
      (memcmp(parsed_test_msg_data.cipher.chars,
              msg_data_in.cipher.chars,
              msg_data_in.cipher.len) != 0) ||
      (memcmp(parsed_test_msg_data.key_id.chars,
              msg_data_in.key_id.chars,
              msg_data_in.key_id.len) != 0) ||
      (memcmp(parsed_test_msg_data.data.chars,
              msg_data_in.data.chars,
              msg_data_in.data.len) != 0) ||
      (memcmp(parsed_test_msg_data.status.chars,
              msg_data_in.status.chars,
              msg_data_in.status.len) != 0))
  {
    pelz_sgx_log(LOG_ERR, "ASN.1 create input/parse output mismatch");
    PELZ_MSG_free(asn1_msg);
    return MSG_TEST_ASN1_CREATE_PARSE_MISMATCH;
  }

  // handle ASN.1 DER encode invalid parameter test cases
  switch (test_select)
  {
  // DER encode of ASN.1 pelz message: NULL input message test case
  case ASN1_CREATE_DER_ENCODE_NULL_MSG_IN:
    invalid_param_test_case = true;
    retval = der_encode_pelz_msg(NULL, der_asn1_msg_out, ASN1);
    break;

  // DER encode of ASN.1 pelz message: NULL output double pointer test case
  case ASN1_CREATE_DER_ENCODE_NULL_BUF_OUT:
    invalid_param_test_case = true;
    retval = der_encode_pelz_msg((const PELZ_MSG *) asn1_msg, NULL, ASN1);
    break;

  // DER encode of ASN.1 pelz message: invalid format test case
  case ASN1_CREATE_DER_ENCODE_INVALID_FORMAT:
    invalid_param_test_case = true;
    retval = der_encode_pelz_msg((const PELZ_MSG *) asn1_msg,
                                 der_asn1_msg_out,
                                 MSG_FORMAT_MAX + 1);
    break;

  // for all other test selections, DER encode input ASN.1 test message
  default:
    retval = der_encode_pelz_msg((const PELZ_MSG *) asn1_msg,
                                 der_asn1_msg_out,
                                 ASN1);
    if ((der_asn1_msg_out->chars == NULL) || (der_asn1_msg_out->len == 0))
    {
      pelz_sgx_log(LOG_ERR, "error DER-encoding test ASN.1 message");
      free_charbuf(der_asn1_msg_out);
      return MSG_TEST_ASN1_DER_ENCODE_ERROR;
    }
    break;
  }

  if (invalid_param_test_case)
  {
    PELZ_MSG_free(asn1_msg);
    if (retval == PELZ_MSG_INVALID_PARAM)
    {
      return MSG_TEST_PARAM_HANDLING_OK;
    }
    return MSG_TEST_PARAM_HANDLING_ERROR;
  }

  // roughly validate DER-encoded result by checking first few bytes

  int idx = 0;
  
  // DER encodes in a type-length-value format, so first byte is
  // the 'type' byte for the encoded PELZ_MSG sequence:
  //  - two MSBs represent class, both bits should be clear (Universal)
  //  - next MSB should be set as sequence is a 'constructed' value
  //  - five LSBs should contain tag (SEQUENCE = 16, 0x10, or 0b10000)
  // 0b00110000 = 0x30, therefore, is the expected value
  if (der_asn1_msg_out->chars[idx] != 0x30)
  {
    pelz_sgx_log(LOG_ERR, "DER-encode (ASN.1) mismatch - sequence tag");
    free_charbuf(der_asn1_msg_out);
    return MSG_TEST_ASN1_DER_ENCODE_RESULT_MISMATCH;
  }
  idx++;
  // Next is the sequence length (i.e., 2 bytes less than the encoded length).
  // If MSB is set, the length is encoded as a multibyte value and we simply
  // skip verification of this field in that case
  if ((der_asn1_msg_out->chars[idx] & 0x80) == 0)
  {
    pelz_sgx_log(LOG_DEBUG, "if");
    if (der_asn1_msg_out->chars[idx] != (der_asn1_msg_out->len - 2))
    {
      pelz_sgx_log(LOG_ERR, "DER-encode (ASN.1) mismatch - sequence length");
      free_charbuf(der_asn1_msg_out);
      return MSG_TEST_ASN1_DER_ENCODE_RESULT_MISMATCH;
    }
  }
  else
  {
    pelz_sgx_log(LOG_DEBUG, "else");
    idx += der_asn1_msg_out->chars[idx] & 0x7f;
  }
  idx++;
  // Next is the type for the first element in the PELZ_MSG sequence
  // (the 'msg_type' enumerated value)
  if (der_asn1_msg_out->chars[idx] != V_ASN1_ENUMERATED)
  {
    pelz_sgx_log(LOG_ERR, "DER-encode (ASN.1) mismatch - 'msg_type' tag");
    free_charbuf(der_asn1_msg_out);
    return MSG_TEST_ASN1_DER_ENCODE_RESULT_MISMATCH;
  }
  idx++;
  // Next is the length of the encoded 'msg_type'. Because the value is from
  // a small enumerated set of values, should be encoded as a single byte.
  if (der_asn1_msg_out->chars[idx] != 1)
  {
    pelz_sgx_log(LOG_ERR, "DER-encode (ASN.1) invalid - 'msg_type' length");
    free_charbuf(der_asn1_msg_out);
    return MSG_TEST_ASN1_DER_ENCODE_RESULT_MISMATCH;
  }
  idx++;
  // Next is the 'msg_type' enumerated value. Skip validation of this field
  // because we do not have this value readily available for comparison.
  idx++;
  // Next is the type for the second element in the PELZ_MSG sequence (the
  // req_type enumerated value)
  if (der_asn1_msg_out->chars[idx] != V_ASN1_ENUMERATED)
  {
    pelz_sgx_log(LOG_ERR, "DER-encode (ASN.1) mismatch - 'req_type' tag");
    free_charbuf(der_asn1_msg_out);
    return MSG_TEST_ASN1_DER_ENCODE_RESULT_MISMATCH;
  }
  idx++;
  // Next is the length of the encoded 'req_type'. Bbecause the value is from
  // a small enumerated set of values, should be single byte encoding.
  if (der_asn1_msg_out->chars[idx] != 1)
  {
    pelz_sgx_log(LOG_ERR, "DER-encode (ASN.1) invalid - 'req_type' length");
    free_charbuf(der_asn1_msg_out);
    return MSG_TEST_ASN1_DER_ENCODE_RESULT_MISMATCH;
  }

  // handle remaining ASN.1 DER encode/decode test cases
  PELZ_MSG *decoded_msg = NULL;

  switch (test_select)
  {
  // DER encode of ASN.1 pelz message: functionality (result validated above)
  case ASN1_CREATE_DER_ENCODE_FUNCTIONALITY:
    PELZ_MSG_free(asn1_msg);
    free_charbuf(der_asn1_msg_out);
    return MSG_TEST_OK;
    break;

  // DER decode of ASN.1 pelz message: invalid parameter test cases
  //   - NULL encoded input buffer test case
  //   - empty encoded input buffer test case
  //   - invalidly sized input buffer test case
  case ASN1_PARSE_DER_DECODE_NULL_BUF_IN:
    invalid_param_test_case = true;
    decoded_msg = der_decode_pelz_msg((charbuf) { .chars = NULL, .len = 1 },
                                      ASN1);
    break;

  case ASN1_PARSE_DER_DECODE_EMPTY_BUF_IN:
    invalid_param_test_case = true;
    der_asn1_msg_out->len = 0;
    decoded_msg = der_decode_pelz_msg(*der_asn1_msg_out, ASN1);
    break;

  case ASN1_PARSE_DER_DECODE_INVALID_FORMAT:
    invalid_param_test_case = true;
    decoded_msg = der_decode_pelz_msg(*der_asn1_msg_out, MSG_FORMAT_MAX + 1);   
    break;

  // all remaining test cases
  case ASN1_PARSE_DER_DECODE_FUNCTIONALITY:
  default:
    decoded_msg = der_decode_pelz_msg(*der_asn1_msg_out, ASN1);
    break;
  }

  // determine/return result for DER-decode invalid parameter test cases
  if (invalid_param_test_case)
  {
    PELZ_MSG_free(asn1_msg);
    free_charbuf(der_asn1_msg_out);
    if (decoded_msg == NULL)
    {
      return MSG_TEST_PARAM_HANDLING_OK;
    }
    PELZ_MSG_free(decoded_msg);
    return MSG_TEST_PARAM_HANDLING_ERROR;
  }

  // check for DER-decode error in valid parameter test cases
  if (decoded_msg == NULL)
  {
    PELZ_MSG_free(asn1_msg);
    free_charbuf(der_asn1_msg_out);
    return MSG_TEST_ASN1_DER_DECODE_ERROR;
  }

  // check validity (match against original input) of DER-decode result
  PELZ_MSG_DATA decoded_msg_data = { 0 };
  retval = parse_pelz_asn1_msg(decoded_msg, &decoded_msg_data);


  if ((decoded_msg_data.msg_type != msg_data_in.msg_type) ||
      (decoded_msg_data.req_type != msg_data_in.req_type) ||
      (decoded_msg_data.cipher.len != msg_data_in.cipher.len) ||
      (memcmp(decoded_msg_data.cipher.chars,
              msg_data_in.cipher.chars,
              decoded_msg_data.cipher.len) != 0) ||
      (decoded_msg_data.key_id.len != msg_data_in.key_id.len) ||
      (memcmp(decoded_msg_data.key_id.chars,
              msg_data_in.key_id.chars,
              decoded_msg_data.key_id.len) != 0) ||
      (decoded_msg_data.data.len != msg_data_in.data.len) ||
      (memcmp(decoded_msg_data.data.chars,
              msg_data_in.data.chars,
              decoded_msg_data.data.len) != 0) ||
      (decoded_msg_data.status.len != msg_data_in.status.len) ||
      (memcmp(decoded_msg_data.status.chars,
              msg_data_in.status.chars,
              decoded_msg_data.status.len) != 0))
  {
    PELZ_MSG_free(asn1_msg);
    free_charbuf(der_asn1_msg_out);
    PELZ_MSG_free(decoded_msg);
    PELZ_MSG_DATA_free(&decoded_msg_data);
    return MSG_TEST_ASN1_DER_DECODE_RESULT_MISMATCH;
  }

  // clean-up ASN.1 formatted messages (DER-decode result validation done)
  PELZ_MSG_free(asn1_msg);
  PELZ_MSG_free(decoded_msg);
  PELZ_MSG_DATA_free(&decoded_msg_data);

  // if DER-decode functionality test, DER-encoded output no longer needed
  if (test_select == ASN1_PARSE_DER_DECODE_FUNCTIONALITY)
  {
    free_charbuf(der_asn1_msg_out);
  }

  return MSG_TEST_OK;
}

MsgTestStatus pelz_signed_msg_test_helper(MsgTestSelect test_select,
                                          charbuf msg_data_in,
                                          EVP_PKEY *sign_priv,
                                          X509 *verify_cert,
                                          charbuf *der_signed_msg_out)
{
  PelzMessagingStatus retval = PELZ_MSG_UNKNOWN_ERROR;

  CMS_ContentInfo *signed_msg = CMS_ContentInfo_new();

  bool invalid_param_test_case = false;

  // handle tests for invalid parameters to create_pelz_signed_msg()
  switch (test_select)
  {
  // create signed CMS pelz message: NULL input data buffer test case
  case CMS_SIGN_NULL_BUF_IN:
    invalid_param_test_case = true;
    signed_msg = create_pelz_signed_msg((charbuf) { .chars = NULL, .len = 1 },
                                        verify_cert,
                                        sign_priv);
    break;

  // create signed CMS pelz message: empty input data buffer test case
  case CMS_SIGN_EMPTY_BUF_IN:
    invalid_param_test_case = true;
    msg_data_in.len = 0;
    signed_msg = create_pelz_signed_msg(msg_data_in,
                                        verify_cert,
                                        sign_priv);
    break;

  // create signed CMS pelz message: NULL input certificate test case
  case CMS_SIGN_NULL_CERT_IN:
    invalid_param_test_case = true;
    signed_msg = create_pelz_signed_msg(msg_data_in,
                                        NULL,
                                        sign_priv);
    break;

  // create signed CMS pelz message: NULL input private key test case
  case CMS_SIGN_NULL_PRIV_IN:
    invalid_param_test_case = true;
    signed_msg = create_pelz_signed_msg(msg_data_in,
                                        verify_cert,
                                        NULL);
    break;

  // create signed CMS message with DER-encoded pelz ASN.1 message payload
  // for all other cases
  default:
    signed_msg = create_pelz_signed_msg(msg_data_in,
                                        verify_cert,
                                        sign_priv);
    break;
  }

  // determine/return result for "sign" invalid parameter test cases
  if (invalid_param_test_case)
  {
    if (signed_msg == NULL)
    {
      pelz_sgx_log(LOG_DEBUG, "expected return");
      return MSG_TEST_PARAM_HANDLING_OK;
    }
    CMS_ContentInfo_free(signed_msg);
    return MSG_TEST_PARAM_HANDLING_ERROR;
  }

  // check that "sign" API call did not error for remaining cases
  if (signed_msg == NULL)
  {
    pelz_sgx_log(LOG_DEBUG, "NULL check failed for signed_msg");
    return MSG_TEST_SIGN_ERROR;
  }

  // verify that the newly created signed CMS message object is right "type"
  if (OBJ_obj2nid(CMS_get0_type(signed_msg)) != NID_pkcs7_signed)
  {
    CMS_ContentInfo_free(signed_msg);
    return MSG_TEST_SIGN_INVALID_RESULT;
  }

  // extract signed message content and check that it matches original input
  const ASN1_OCTET_STRING *signed_content = *(CMS_get0_content(signed_msg));
  if (signed_content == NULL)
  {
    CMS_ContentInfo_free(signed_msg);
    return MSG_TEST_SETUP_ERROR;
  }
  int signed_data_size = ASN1_STRING_length(signed_content);
  const unsigned char * signed_data = ASN1_STRING_get0_data(signed_content);
  if ((signed_data == NULL) || (signed_data_size <= 0))
  {
    CMS_ContentInfo_free(signed_msg);
    return MSG_TEST_SETUP_ERROR;
  }
  if ((signed_data_size != (int) msg_data_in.len) ||
      (memcmp(msg_data_in.chars, signed_data, (size_t) signed_data_size) != 0))
  {
    CMS_ContentInfo_free(signed_msg);
    return MSG_TEST_SIGN_INVALID_RESULT;
  }

  // if "create signed message functionality" test case, return result
  if (test_select == CMS_SIGN_FUNCTIONALITY)
  {
    CMS_ContentInfo_free(signed_msg);
    return MSG_TEST_OK;
  }

  // handle signed CMS message verification test cases
  X509 *cert_out = NULL;
  charbuf verify_data = new_charbuf(0);

  switch (test_select)
  {
  // verify signed CMS pelz message: NULL input message test case
  case CMS_VERIFY_NULL_MSG_IN:
    invalid_param_test_case = true;
    retval = verify_pelz_signed_msg(NULL,
                                    &cert_out,
                                    &verify_data);
    break;

  // verify signed CMS pelz message: NULL output cert double pointer test case
  case CMS_VERIFY_NULL_CERT_OUT:
    invalid_param_test_case = true;
    retval = verify_pelz_signed_msg(signed_msg,
                                    NULL,
                                    &verify_data);
    break;

  // verify signed CMS pelz message: NULL output data double pointer test case
  case CMS_VERIFY_NULL_BUF_OUT:
    invalid_param_test_case = true;
    retval = verify_pelz_signed_msg(signed_msg,
                                    &cert_out,
                                    NULL);
    break;

  // all other test case -verification API call with valid parameters
  default:
    retval = verify_pelz_signed_msg(signed_msg,
                                    &cert_out,
                                    &verify_data);
    if (retval != PELZ_MSG_OK)
    {
      free_charbuf(&verify_data);
      return MSG_TEST_VERIFY_ERROR;
    }
    break;
  }

  // if test case is for invalid parameter to "verify", return result
  if (invalid_param_test_case)
  {
    CMS_ContentInfo_free(signed_msg);
    free_charbuf(&verify_data);
    if (retval == PELZ_MSG_INVALID_PARAM)
    {
      return MSG_TEST_PARAM_HANDLING_OK;
    }
    return MSG_TEST_PARAM_HANDLING_ERROR;
  }

  // validate output of "verify" call
  if ((verify_data.len != msg_data_in.len) ||
      (memcmp(msg_data_in.chars, verify_data.chars, verify_data.len) != 0) ||
      (X509_cmp(cert_out, verify_cert) != 0))
  {
    CMS_ContentInfo_free(signed_msg);
    free_charbuf(&verify_data);
    return MSG_TEST_VERIFY_INVALID_RESULT;
  }
  free_charbuf(&verify_data);

  if (test_select == CMS_VERIFY_FUNCTIONALITY)
  {
    pelz_sgx_log(LOG_DEBUG, "passed CMS verification functionality test");
    CMS_ContentInfo_free(signed_msg);
    return MSG_TEST_OK;
  }

  // handle invalid parameter test cases for DER encoding of signed message
  switch (test_select)
  {
  // DER encode of signed CMS pelz message: NULL input message test case
  case CMS_SIGN_DER_ENCODE_NULL_MSG_IN:
    invalid_param_test_case = true;
    retval = der_encode_pelz_msg(NULL, der_signed_msg_out, CMS);
    break;

  // DER encode of signed CMS pelz message: NULL output double pointer test case
  case CMS_SIGN_DER_ENCODE_NULL_BUF_OUT:
    invalid_param_test_case = true;
    retval = der_encode_pelz_msg((const CMS_ContentInfo *) signed_msg,
                                 NULL,
                                 CMS);
    break;

  // DER encode of signed CMS pelz message: invalid format test case
  case CMS_SIGN_DER_ENCODE_INVALID_FORMAT:
    invalid_param_test_case = true;
    retval = der_encode_pelz_msg((const CMS_ContentInfo *) signed_msg,
                                 der_signed_msg_out,
                                 MSG_FORMAT_MIN - 1);
    break;

  // for all other test selections, DER encode input CMS test message
  default:
  retval = der_encode_pelz_msg((const CMS_ContentInfo *) signed_msg,
                               der_signed_msg_out,
                               CMS);
    break;
  }

  // if an invalid parameter to DER encode test case, return result
  if (invalid_param_test_case)
  {
    CMS_ContentInfo_free(signed_msg);
    free_charbuf(der_signed_msg_out);
    if (retval == PELZ_MSG_INVALID_PARAM)
    {
      return MSG_TEST_PARAM_HANDLING_OK;
    }
    return MSG_TEST_PARAM_HANDLING_ERROR;
  }

  // check for DER-encode error
  if ((der_signed_msg_out->chars == NULL) || (der_signed_msg_out->len == 0))
  {
    CMS_ContentInfo_free(signed_msg);
    free_charbuf(der_signed_msg_out);
    return MSG_TEST_CMS_DER_ENCODE_ERROR;
  }

  // roughly validate DER-encoded result by checking first byte

  // DER encodes in a type-length-value format, so first byte is
  // the 'type' byte for the encoded PELZ_MSG sequence:
  //  - two MSBs represent class, both bits should be clear (Universal)
  //  - next MSB should be set as sequence is a 'constructed' value
  //  - five LSBs should contain tag (SEQUENCE = 16, 0x10, or 0b10000)
  // 0b00110000 = 0x30, therefore, is the expected value
  if (der_signed_msg_out->chars[0] != 0x30)
  {
    pelz_sgx_log(LOG_ERR, "DER-encode (CMS) mismatch - sequence tag");
    CMS_ContentInfo_free(signed_msg);
    free_charbuf(der_signed_msg_out);
    return MSG_TEST_CMS_DER_ENCODE_RESULT_MISMATCH;
  }

  // handle remaining CMS signed message DER encode/decode test cases
  CMS_ContentInfo *decoded_msg = CMS_ContentInfo_new();
  switch (test_select)
  {
  // DER encode of CMS pelz message: functionality (result validated above)
  case CMS_SIGN_DER_ENCODE_FUNCTIONALITY:
    CMS_ContentInfo_free(signed_msg);
    free_charbuf(der_signed_msg_out);
    return MSG_TEST_OK;
    break;

  // DER decode of CMS pelz message: NULL encoded input buffer test case
  case CMS_VERIFY_DER_DECODE_NULL_BUF_IN:
    invalid_param_test_case = true;
    decoded_msg = der_decode_pelz_msg((charbuf) { .chars = NULL, .len = 127},
                                      CMS);
    break;

  // DER decode of ASN.1 pelz message: empty encoded input buffer test case
  case CMS_VERIFY_DER_DECODE_EMPTY_BUF_IN:
    invalid_param_test_case = true;
    der_signed_msg_out->len = 0;
    decoded_msg = der_decode_pelz_msg(*der_signed_msg_out, CMS);
    break;

  // DER decode of ASN.1 pelz message: invalid output message format test case
  case CMS_VERIFY_DER_DECODE_INVALID_FORMAT:
    invalid_param_test_case = true;
    decoded_msg = der_decode_pelz_msg(*der_signed_msg_out, MSG_FORMAT_MIN - 1);
    break;

  // for all other test selections, DER-decode CMS signed message
  default:
    decoded_msg = der_decode_pelz_msg(*der_signed_msg_out, CMS);
    break;
  }

  // if invalid parameter for CMS DER decode test case, result should be NULL
  if (invalid_param_test_case)
  {
    CMS_ContentInfo_free(signed_msg);
    free_charbuf(der_signed_msg_out);
    if (decoded_msg == NULL)
    {
      return MSG_TEST_PARAM_HANDLING_OK;
    }
    CMS_ContentInfo_free(decoded_msg);
    return MSG_TEST_PARAM_HANDLING_ERROR;
  }

  // with valid parameters, DER-decoded result should be non-NULL
  if (decoded_msg == NULL)
  {
    CMS_ContentInfo_free(signed_msg);
    free_charbuf(der_signed_msg_out);
    return MSG_TEST_CMS_DER_DECODE_ERROR;
  }

  // check the decoded result
  ASN1_STRING *input_cms_msg_payload = ASN1_STRING_dup(*(CMS_get0_content(signed_msg)));
  ASN1_STRING *decoded_cms_msg_payload = ASN1_STRING_dup(*(CMS_get0_content(decoded_msg)));
  CMS_ContentInfo_free(signed_msg);
  CMS_ContentInfo_free(decoded_msg);

  if (ASN1_STRING_cmp(decoded_cms_msg_payload,
                      input_cms_msg_payload) != 0)
  {
    pelz_sgx_log(LOG_ERR, "DER-decoded CMS message mismatch");
    ASN1_STRING_free(input_cms_msg_payload);
    ASN1_STRING_free(decoded_cms_msg_payload);
    free_charbuf(der_signed_msg_out);
    return MSG_TEST_CMS_DER_DECODE_RESULT_MISMATCH;
  }
  ASN1_STRING_free(input_cms_msg_payload);
  ASN1_STRING_free(decoded_cms_msg_payload);

  // if testing DER decode to signed message functionality, clean-up output
  if (test_select == CMS_VERIFY_DER_DECODE_FUNCTIONALITY)
  {
    free_charbuf(der_signed_msg_out);
  }

  return MSG_TEST_OK;
}

MsgTestStatus pelz_enveloped_msg_test_helper(MsgTestSelect test_select,
                                             charbuf msg_data_in,
                                             X509 *encrypt_cert,
                                             EVP_PKEY *decrypt_priv,
                                             charbuf *der_env_msg_out)
{
  PelzMessagingStatus retval = PELZ_MSG_UNKNOWN_ERROR;
  bool invalid_param_test_case = false;
  CMS_ContentInfo * env_msg = NULL;

  // handle tests for invalid parameters to create_pelz_enveloped_msg()
  switch (test_select)
  {
  // create enveloped CMS pelz message: NULL input data buffer test case
  case CMS_ENCRYPT_NULL_BUF_IN:
    invalid_param_test_case = true;
    env_msg = create_pelz_enveloped_msg((charbuf) { .chars = NULL, .len = 0 },
                                        encrypt_cert);
    break;

  // create enveloped CMS pelz message: empty input data buffer test case
  case CMS_ENCRYPT_EMPTY_BUF_IN:
    invalid_param_test_case = true;
    msg_data_in.len = 0;
    env_msg = create_pelz_enveloped_msg(msg_data_in, encrypt_cert);
    break;

  // create signed CMS pelz message: NULL input certificate test case
  case CMS_ENCRYPT_NULL_CERT_IN:
    invalid_param_test_case = true;
    env_msg = create_pelz_enveloped_msg(msg_data_in,
                                        NULL);
    break;

  // create signed CMS message with DER-encoded pelz ASN.1 message payload
  // test enveloped message creation using input/derived test data
  // for all other test cases
  default:
    env_msg = create_pelz_enveloped_msg(msg_data_in,
                                        encrypt_cert);
    if (env_msg == NULL)
    {
      return MSG_TEST_ENCRYPT_ERROR;
    }
    break;
  }

  // if an invalid parameter test case, clean-up and return result
  if (invalid_param_test_case)
  {
    if (env_msg == NULL)
    {
      return MSG_TEST_PARAM_HANDLING_OK;
    }
    CMS_ContentInfo_free(env_msg);
    return MSG_TEST_PARAM_HANDLING_ERROR;
  }

  // validate the message 'type' (authEnvelopedData)
  int test_msg_type = OBJ_obj2nid(CMS_get0_type(env_msg));
  if (test_msg_type != NID_id_smime_ct_authEnvelopedData)
  {
    CMS_ContentInfo_free(env_msg);
    return MSG_TEST_ENCRYPT_INVALID_RESULT;
  }

  // validate length of encrypted message content matches the length
  // of the input data and differs in content
  const ASN1_OCTET_STRING *env_content = *(CMS_get0_content(env_msg));
  if (env_content == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error extracting enveloped message content")
    CMS_ContentInfo_free(env_msg);
    return MSG_TEST_SETUP_ERROR;
  }
  int enc_data_size = ASN1_STRING_length(env_content);
  const uint8_t *enc_data = ASN1_STRING_get0_data(env_content);
  if ((enc_data == NULL) ||
      (enc_data_size != (int) msg_data_in.len) ||
      (memcmp(msg_data_in.chars, enc_data, msg_data_in.len) == 0))
  {
    CMS_ContentInfo_free(env_msg);
    return MSG_TEST_ENCRYPT_INVALID_RESULT;
  }

  // if CMS create enveloped message functionality test case - return success
  if (test_select == CMS_ENCRYPT_FUNCTIONALITY)
  {
    return MSG_TEST_OK;
  }

  charbuf decrypt_data = new_charbuf(0);

  switch (test_select)
  {
  case CMS_DECRYPT_NULL_MSG_IN:
    invalid_param_test_case = true;
    retval = decrypt_pelz_enveloped_msg(NULL,
                                        encrypt_cert,
                                        decrypt_priv,
                                        &decrypt_data);
    break;

  case CMS_DECRYPT_NULL_CERT:
    invalid_param_test_case = true;
    retval = decrypt_pelz_enveloped_msg(env_msg,
                                        NULL,
                                        decrypt_priv,
                                        &decrypt_data);
    break;

  case CMS_DECRYPT_NULL_PRIV:
    invalid_param_test_case = true;
    retval = decrypt_pelz_enveloped_msg(env_msg,
                                        encrypt_cert,
                                        NULL,
                                        &decrypt_data);
    break;

  case CMS_DECRYPT_NULL_BUF_OUT:
    invalid_param_test_case = true;
    retval = decrypt_pelz_enveloped_msg(env_msg,
                                        encrypt_cert,
                                        decrypt_priv,
                                        NULL);
    break;

  default:
    retval = decrypt_pelz_enveloped_msg(env_msg,
                                        encrypt_cert,
                                        decrypt_priv,
                                        &decrypt_data);
    break;
  }

  // compute return value if an invalid parameter test case
  if (invalid_param_test_case)
  {
    if (retval == PELZ_MSG_INVALID_PARAM)
    {
      return MSG_TEST_PARAM_HANDLING_OK;
    }
    CMS_ContentInfo_free(env_msg);
    return MSG_TEST_PARAM_HANDLING_ERROR;
  }

  // chack validity of decrypt result
  if ((retval != PELZ_MSG_OK) ||
      (decrypt_data.chars == NULL) ||
      (decrypt_data.len != msg_data_in.len) ||
      (memcmp(msg_data_in.chars,
              decrypt_data.chars,
              msg_data_in.len) != 0))
  {
    CMS_ContentInfo_free(env_msg);
    free_charbuf(&decrypt_data);
    return MSG_TEST_DECRYPT_ERROR;
  }

  // if decrypt functionality test, return success
  if (test_select == CMS_DECRYPT_FUNCTIONALITY)
  {
    CMS_ContentInfo_free(env_msg);
    free_charbuf(&decrypt_data);
    return MSG_TEST_OK;
  }

  // handle invalid parameter test cases for DER encoding of enveloped message
  switch (test_select)
  {
  // DER encode of enveloped CMS pelz message: NULL input message test case
  case CMS_ENCRYPT_DER_ENCODE_NULL_MSG_IN:
    invalid_param_test_case = true;
    retval = der_encode_pelz_msg(NULL, der_env_msg_out, CMS);
    break;

  // DER encode of enveloped message: NULL output double pointer test case
  case CMS_ENCRYPT_DER_ENCODE_NULL_BUF_OUT:
    invalid_param_test_case = true;
    retval = der_encode_pelz_msg((const CMS_ContentInfo *) env_msg, NULL, CMS);
    break;

  // DER encode of enveloped CMS pelz message: invalid format test case
  case CMS_ENCRYPT_DER_ENCODE_INVALID_FORMAT:
    invalid_param_test_case = true;
    retval = der_encode_pelz_msg((const CMS_ContentInfo *) env_msg,
                                 der_env_msg_out,
                                 MSG_FORMAT_MAX + 1);
    break;

  // for all other test selections, DER encode input CMS test message
  default:
    retval = der_encode_pelz_msg((const CMS_ContentInfo *) env_msg,
                                 der_env_msg_out,
                                 CMS);
    if ((der_env_msg_out->chars == NULL) || (der_env_msg_out->len == 0))
    {
      CMS_ContentInfo_free(env_msg);
      free_charbuf(der_env_msg_out);
      return MSG_TEST_CMS_DER_ENCODE_ERROR;
    }
    break;
  }

  // if an invalid parameter to DER encode test case, return result
  if (invalid_param_test_case)
  {
    CMS_ContentInfo_free(env_msg);
    free_charbuf(der_env_msg_out);
    if (retval == PELZ_MSG_INVALID_PARAM)
    {
      return MSG_TEST_PARAM_HANDLING_OK;
    }
    return MSG_TEST_PARAM_HANDLING_ERROR;
  }

  // roughly validate DER-encoded result by checking first few bytes

  int idx = 0;

  // DER encodes in a type-length-value format, so first byte is
  // the 'type' byte for the encoded PELZ_MSG sequence:
  //  - two MSBs represent class, both bits should be clear (Universal)
  //  - next MSB should be set as sequence is a 'constructed' value
  //  - five LSBs should contain tag (SEQUENCE = 16, 0x10, or 0b10000)
  // 0b00110000 = 0x30, therefore, is the expected value
  if (der_env_msg_out->chars[idx] != 0x30)
  {
    pelz_sgx_log(LOG_ERR, "DER-encode (CMS) mismatch - sequence tag");
    CMS_ContentInfo_free(env_msg);
    free_charbuf(der_env_msg_out);
    return MSG_TEST_CMS_DER_ENCODE_RESULT_MISMATCH;
  }
  idx++;
  // Next is the sequence length (i.e., 2 bytes less than the encoded length).
  // If MSB is set, the length is encoded as a multibyte value and we simply
  // skip verification of this field in that case
  if ((der_env_msg_out->chars[idx] & 0x80) == 0)
  {
    pelz_sgx_log(LOG_DEBUG, "if");
    if (der_env_msg_out->chars[idx] != (der_env_msg_out->len - 2))
    {
      pelz_sgx_log(LOG_ERR, "DER-encode (CMS) mismatch - sequence length");
      free_charbuf(der_env_msg_out);
      return MSG_TEST_CMS_DER_ENCODE_RESULT_MISMATCH;
    }
  }
  else
  {
    pelz_sgx_log(LOG_DEBUG, "else");
    idx += der_env_msg_out->chars[idx] & 0x7f;
  }
  idx++;
  // Next is the type for the first element in the
  // CMS encoded PELZ_MSG sequence, which should be the object
  // identifier (OID)
  if (der_env_msg_out->chars[idx] != V_ASN1_OBJECT)
  {
    pelz_sgx_log(LOG_ERR, "DER-encode (CMS) mismatch - OID tag");
    CMS_ContentInfo_free(env_msg);
    free_charbuf(der_env_msg_out);
    return MSG_TEST_CMS_DER_ENCODE_RESULT_MISMATCH;
  }

  // handle remaining CMS signed message DER encode/decode test cases
  CMS_ContentInfo *decoded_msg = NULL;
  switch (test_select)
  {
  // DER encode of CMS pelz message: functionality (result validated above)
  case CMS_ENCRYPT_DER_ENCODE_FUNCTIONALITY:
    CMS_ContentInfo_free(env_msg);
    free_charbuf(der_env_msg_out);
    return MSG_TEST_OK;
    break;

  // DER decode of CMS pelz message: NULL encoded input buffer test case
  case CMS_DECRYPT_DER_DECODE_NULL_BUF_IN:
    invalid_param_test_case = true;
    decoded_msg = der_decode_pelz_msg((charbuf) {.chars = NULL, .len = 32 },
                                      CMS);
    break;

  // DER decode of ASN.1 pelz message: empty encoded input buffer test case
  case CMS_DECRYPT_DER_DECODE_EMPTY_BUF_IN:
    invalid_param_test_case = true;
    der_env_msg_out->len = 0;
    decoded_msg = der_decode_pelz_msg(*der_env_msg_out, CMS);
    break;

  // DER decode of ASN.1 pelz message: invalid format paramter test case
  case CMS_DECRYPT_DER_DECODE_INVALID_FORMAT:
    invalid_param_test_case = true;
    decoded_msg = der_decode_pelz_msg(*der_env_msg_out, MSG_FORMAT_MIN - 1);
    break;

  // for all other test selections, DER-encode CMS signed message
  default:
    decoded_msg = der_decode_pelz_msg(*der_env_msg_out, CMS);
    if (decoded_msg == NULL)
    {
      CMS_ContentInfo_free(env_msg);
      free_charbuf(der_env_msg_out);
      return MSG_TEST_CMS_DER_DECODE_ERROR;
    }
    break;
  }

  // if invalid parameter for CMS DER decode test case, result should be NULL
  if (invalid_param_test_case)
  {
    CMS_ContentInfo_free(env_msg);
    free_charbuf(der_env_msg_out);
    if (decoded_msg == NULL)
    {
      return MSG_TEST_PARAM_HANDLING_OK;
    }
    CMS_ContentInfo_free(decoded_msg);
    return MSG_TEST_PARAM_HANDLING_ERROR;
  }

  // check the decoded result
  ASN1_OCTET_STRING **input_cms_msg_payload = CMS_get0_content(env_msg);
  ASN1_OCTET_STRING **decoded_cms_msg_payload = CMS_get0_content(decoded_msg);
  if (ASN1_OCTET_STRING_cmp(*decoded_cms_msg_payload,
                            *input_cms_msg_payload) != 0)
  {
    pelz_sgx_log(LOG_ERR, "DER-decoded CMS message mismatch");
    CMS_ContentInfo_free(env_msg);
    CMS_ContentInfo_free(decoded_msg);
    free_charbuf(der_env_msg_out);
    return MSG_TEST_CMS_DER_DECODE_RESULT_MISMATCH;
  }
  CMS_ContentInfo_free(env_msg);
  CMS_ContentInfo_free(decoded_msg);

  // if DER-decode of enveloped message functionality test case, clean-up
  if (test_select == CMS_DECRYPT_DER_DECODE_FUNCTIONALITY)
  {
    free_charbuf(der_env_msg_out); 
  }

  return MSG_TEST_OK;
}

MsgTestStatus pelz_constructed_msg_test_helper(MsgTestSelect test_select,
                                               PELZ_MSG_DATA msg_data,
                                               X509 *construct_cert,
                                               EVP_PKEY *construct_priv,
                                               X509 *deconstruct_cert,
                                               EVP_PKEY *deconstruct_priv)
{
  // check that input test parameters are completely and validly specified
  if (((test_select <= NULL_TEST) || (test_select > PELZ_MSG_END_TO_END)) ||
      (construct_cert == NULL) ||
      (construct_priv == NULL) ||
      (deconstruct_cert == NULL) ||
      (deconstruct_priv == NULL))
  {
    pelz_sgx_log(LOG_ERR, "NULL, empty, or invalid test input parameter");
    return MSG_TEST_INVALID_TEST_PARAMETER;
  }

  charbuf test_msg_buf = new_charbuf(0);
  PelzMessagingStatus retval = PELZ_MSG_UNKNOWN_ERROR;
  bool invalid_param_test_case = false;

  switch (test_select)
  {
  // NULL input certificate parameter to 'construct' case
  case CONSTRUCT_NULL_CERT:
    invalid_param_test_case = true;
    retval = construct_pelz_msg(msg_data,
                                NULL,
                                construct_priv,
                                deconstruct_cert,
                                &test_msg_buf);
    break;

  // NULL input local private key parameter to 'construct' case
  case CONSTRUCT_NULL_PRIV:
    invalid_param_test_case = true;
    retval = construct_pelz_msg(msg_data,
                                construct_cert,
                                NULL,
                                deconstruct_cert,
                                &test_msg_buf);
    break;

  // NULL input remote (peer) cert parameter to 'construct' case
  case CONSTRUCT_NULL_PEER_CERT:
    invalid_param_test_case = true;
    retval = construct_pelz_msg(msg_data,
                                construct_cert,
                                construct_priv,
                                NULL,
                                &test_msg_buf);
    break;

  // NULL output buffer parameter to 'construct' case
  case CONSTRUCT_NULL_BUF_OUT:
    invalid_param_test_case = true;
    retval = construct_pelz_msg(msg_data,
                                construct_cert,
                                construct_priv,
                                deconstruct_cert,
                                NULL);
    break;

  // for all other test cases, create test message
  default:
    retval = construct_pelz_msg(msg_data,
                                construct_cert,
                                construct_priv,
                                deconstruct_cert,
                                &test_msg_buf);
    if ((retval != PELZ_MSG_OK) ||
        (test_msg_buf.chars == NULL) ||
        (test_msg_buf.len == 0))
    {
      free_charbuf(&test_msg_buf);
      return MSG_TEST_CONSTRUCT_ERROR;
    }
    break;
  }

  if (invalid_param_test_case)
  {
    if (retval == PELZ_MSG_INVALID_PARAM)
    {
      return MSG_TEST_PARAM_HANDLING_OK;
    }
    return MSG_TEST_PARAM_HANDLING_ERROR;
  }

  // if message construction functionality test case, return success
  if (test_select == CONSTRUCT_FUNCTIONALITY)
  {
    free_charbuf(&test_msg_buf);
    return MSG_TEST_OK;
  }

  // declare/initialize some variables needed by some tests
  PELZ_MSG_DATA deconstructed_test_msg_data = { 0 };
  X509 *deconstructed_peer_cert = X509_new();

  switch (test_select)
  {
  // NULL input data buffer parameter to 'deconstruct' case
  case DECONSTRUCT_NULL_MSG_IN:
    invalid_param_test_case = true;
    retval = deconstruct_pelz_msg((charbuf) { .chars = NULL, .len = 23 },
                                  deconstruct_cert,
                                  deconstruct_priv,
                                  &deconstructed_peer_cert,
                                  &deconstructed_test_msg_data);
    break;

  // empty input data buffer parameter to 'deconstruct' case
  case DECONSTRUCT_EMPTY_MSG_IN:
    invalid_param_test_case = true;
    test_msg_buf.len = 0;
    retval = deconstruct_pelz_msg(test_msg_buf,
                                  deconstruct_cert,
                                  deconstruct_priv,
                                  &deconstructed_peer_cert,
                                  &deconstructed_test_msg_data);
    break;

  // NULL input certificate parameter to 'deconstruct' case
  case DECONSTRUCT_NULL_CERT:
    invalid_param_test_case = true;
    retval = deconstruct_pelz_msg(test_msg_buf,
                                  NULL,
                                  deconstruct_priv,
                                  &deconstructed_peer_cert,
                                  &deconstructed_test_msg_data);
    break;

  // NULL input local private key parameter to 'deconstruct' case
  case DECONSTRUCT_NULL_PRIV:
    invalid_param_test_case = true;
    retval = deconstruct_pelz_msg(test_msg_buf,
                                  deconstruct_cert,
                                  NULL,
                                  &deconstructed_peer_cert,
                                  &deconstructed_test_msg_data);
    break;

  // NULL remote (peer) cert output parameter to 'deconstruct' case
  case DECONSTRUCT_NULL_PEER_CERT_OUT:
    invalid_param_test_case = true;
    retval = deconstruct_pelz_msg(test_msg_buf,
                                  deconstruct_cert,
                                  deconstruct_priv,
                                  NULL,
                                  &deconstructed_test_msg_data);
    break;

  // for all other cases, call 'deconstruct' on valid set of parameters
  default:
    retval = deconstruct_pelz_msg(test_msg_buf,
                                  deconstruct_cert,
                                  deconstruct_priv,
                                  &deconstructed_peer_cert,
                                  &deconstructed_test_msg_data);
    break;
  }

  if (invalid_param_test_case)
  {
    if (retval == PELZ_MSG_INVALID_PARAM)
    {
      return MSG_TEST_PARAM_HANDLING_OK;
    }
    return MSG_TEST_PARAM_HANDLING_ERROR;
  }

  // check if deconstruction of pelz test message errored
  // or returned incomplete result
  if ((retval != PELZ_MSG_OK) ||
      (deconstructed_test_msg_data.cipher.chars == NULL) ||
      (deconstructed_test_msg_data.cipher.len == 0) ||
      (deconstructed_test_msg_data.key_id.chars == NULL) ||
      (deconstructed_test_msg_data.key_id.len == 0) ||
      (deconstructed_test_msg_data.data.chars == NULL) ||
      (deconstructed_test_msg_data.data.len == 0) ||
      (deconstructed_test_msg_data.status.chars == NULL) ||
      (deconstructed_test_msg_data.status.len == 0))
  {
    free_charbuf(&test_msg_buf);
    X509_free(deconstructed_peer_cert);
    free_charbuf(&deconstructed_test_msg_data.cipher);
    free_charbuf(&deconstructed_test_msg_data.key_id);
    free_charbuf(&deconstructed_test_msg_data.data);
    free_charbuf(&deconstructed_test_msg_data.status);
    return MSG_TEST_DECONSTRUCT_ERROR;
  }

  // done with DER encoded, constructed test message => clean-up
  free_charbuf(&test_msg_buf);

  // check peer certificate extracted from message against known copy
  if (X509_cmp(deconstructed_peer_cert, construct_cert) != 0)
  {
    X509_free(deconstructed_peer_cert);
    free_charbuf(&deconstructed_test_msg_data.cipher);
    free_charbuf(&deconstructed_test_msg_data.key_id);
    free_charbuf(&deconstructed_test_msg_data.data);
    free_charbuf(&deconstructed_test_msg_data.status);
    return MSG_TEST_DECONSTRUCT_INVALID_RESULT;
  }
  X509_free(deconstructed_peer_cert);

  // check the deconstructed result against the original input data
  if ((deconstructed_test_msg_data.msg_type != msg_data.msg_type) ||
      (deconstructed_test_msg_data.req_type != msg_data.req_type) ||
      (memcmp(deconstructed_test_msg_data.cipher.chars,
              msg_data.cipher.chars,
              deconstructed_test_msg_data.cipher.len) != 0) ||
      (memcmp(deconstructed_test_msg_data.key_id.chars,
              msg_data.key_id.chars,
              deconstructed_test_msg_data.key_id.len) != 0) ||
      (memcmp(deconstructed_test_msg_data.data.chars,
              msg_data.data.chars,
              deconstructed_test_msg_data.data.len) != 0) ||
      (memcmp(deconstructed_test_msg_data.status.chars,
              msg_data.status.chars,
              deconstructed_test_msg_data.status.len) != 0))
  {
    free_charbuf(&deconstructed_test_msg_data.cipher);
    free_charbuf(&deconstructed_test_msg_data.key_id);
    free_charbuf(&deconstructed_test_msg_data.data);
    free_charbuf(&deconstructed_test_msg_data.status);
    return MSG_TEST_DECONSTRUCT_INVALID_RESULT;
  }

  // clean-up
  free_charbuf(&deconstructed_test_msg_data.cipher);
  free_charbuf(&deconstructed_test_msg_data.key_id);
  free_charbuf(&deconstructed_test_msg_data.data);
  free_charbuf(&deconstructed_test_msg_data.status);

  return MSG_TEST_OK;
}

int pelz_enclave_msg_test_helper(uint8_t msg_type,
                                 uint8_t req_type,
                                 size_t cipher_size,
                                 unsigned char *cipher,
                                 size_t key_id_size,
                                 unsigned char *key_id,
                                 size_t msg_data_size,
                                 unsigned char *msg_data,
                                 size_t msg_status_size,
                                 unsigned char *msg_status,
                                 size_t der_sign_priv_size,
                                 unsigned char *der_sign_priv,
                                 size_t der_verify_cert_size,
                                 unsigned char *der_verify_cert,
                                 size_t der_encrypt_cert_size,
                                 unsigned char *der_encrypt_cert,
                                 size_t der_decrypt_priv_size,
                                 unsigned char *der_decrypt_priv,
                                 uint8_t test_select)
{
  PELZ_MSG_DATA test_msg_data = { .msg_type = (PELZ_MSG_TYPE) msg_type,
                                  .req_type = (PELZ_REQ_TYPE) req_type,
                                  .cipher = { .chars = cipher,
                                              .len = cipher_size },
                                  .key_id = { .chars = key_id,
                                              .len = key_id_size },
                                  .data = { .chars = msg_data,
                                            .len = msg_data_size },
                                  .status = { .chars = msg_status,
                                              .len = msg_status_size } };

  // create ASN.1 formatted pelz request message
  charbuf asn1_pelz_req = new_charbuf(0);
  MsgTestStatus ret = pelz_asn1_msg_test_helper((MsgTestSelect) test_select,
                                                 test_msg_data,
                                                 &asn1_pelz_req);

  switch (test_select)
  {
  // if an ASN.1 create/parse test selected, return result obtained
  case ASN1_CREATE_FUNCTIONALITY:
  case ASN1_CREATE_DER_ENCODE_NULL_MSG_IN:
  case ASN1_CREATE_DER_ENCODE_NULL_BUF_OUT:
  case ASN1_CREATE_DER_ENCODE_INVALID_FORMAT:
  case ASN1_CREATE_DER_ENCODE_FUNCTIONALITY:
  case ASN1_PARSE_NULL_MSG_IN:
  case ASN1_PARSE_INVALID_MSG_TYPE_TAG:
  case ASN1_PARSE_INVALID_MSG_TYPE_LO:
  case ASN1_PARSE_INVALID_MSG_TYPE_HI:
  case ASN1_PARSE_INVALID_REQ_TYPE_TAG:
  case ASN1_PARSE_INVALID_REQ_TYPE_LO:
  case ASN1_PARSE_INVALID_REQ_TYPE_HI:
  case ASN1_PARSE_INVALID_CIPHER_TAG:
  case ASN1_PARSE_INVALID_KEY_ID_TAG:
  case ASN1_PARSE_INVALID_DATA_TAG:
  case ASN1_PARSE_INVALID_STATUS_TAG:
  case ASN1_PARSE_FUNCTIONALITY:
  case ASN1_PARSE_DER_DECODE_NULL_BUF_IN:
  case ASN1_PARSE_DER_DECODE_EMPTY_BUF_IN:
  case ASN1_PARSE_DER_DECODE_INVALID_FORMAT:
  case ASN1_PARSE_DER_DECODE_FUNCTIONALITY:
    free_charbuf (&asn1_pelz_req);
    return ret;
    break;

  // otherwise, continue
  default:
    break;
  }

  // deserialize input DER-formatted requestor private key (sign key)
  EVP_PKEY *sign_priv = deserialize_pkey(der_sign_priv,
                                         (long) der_sign_priv_size);
  if (sign_priv == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error DER decoding EVP_PKEY");
    free_charbuf (&asn1_pelz_req);
    return MSG_TEST_SETUP_ERROR;
  }
  pelz_sgx_log(LOG_DEBUG, "deserialized sign_priv");

  // deserialize input DER-formatted requestor public cert (verify key)
  X509 *verify_cert = deserialize_cert(der_verify_cert,
                                       (long) der_verify_cert_size);
  if (verify_cert == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error DER decoding X509 certificate");
    free_charbuf (&asn1_pelz_req);
    EVP_PKEY_free(sign_priv);
    return  MSG_TEST_SETUP_ERROR;
  }
  pelz_sgx_log(LOG_DEBUG, "deserialized verify_cert");

  if (X509_check_private_key(verify_cert, sign_priv) != 1)
  {
    pelz_sgx_log(LOG_ERR, "sign/verify key/cert pairing error");
    free_charbuf (&asn1_pelz_req);
    EVP_PKEY_free(sign_priv);
    X509_free(verify_cert);
    return  MSG_TEST_SETUP_ERROR;
  }
  pelz_sgx_log(LOG_DEBUG, "checked sign_priv/verify_cert match");

  // create signed pelz request message
  charbuf der_signed_pelz_req = new_charbuf(0);
  ret = pelz_signed_msg_test_helper((MsgTestSelect) test_select,
                                     asn1_pelz_req,
                                     sign_priv,
                                     verify_cert,
                                     &der_signed_pelz_req);

  switch (test_select)
  {
  // if a CMS sign/verify test selected, return result
  case CMS_SIGN_NULL_BUF_IN:
  case CMS_SIGN_EMPTY_BUF_IN:
  case CMS_SIGN_NULL_CERT_IN:
  case CMS_SIGN_NULL_PRIV_IN:
  case CMS_SIGN_FUNCTIONALITY:
  case CMS_SIGN_DER_ENCODE_NULL_MSG_IN:
  case CMS_SIGN_DER_ENCODE_NULL_BUF_OUT:
  case CMS_SIGN_DER_ENCODE_INVALID_FORMAT:
  case CMS_SIGN_DER_ENCODE_FUNCTIONALITY:
  case CMS_VERIFY_NULL_MSG_IN:
  case CMS_VERIFY_NULL_CERT_OUT:
  case CMS_VERIFY_NULL_BUF_OUT:
  case CMS_VERIFY_FUNCTIONALITY:
  case CMS_VERIFY_DER_DECODE_NULL_BUF_IN:
  case CMS_VERIFY_DER_DECODE_EMPTY_BUF_IN:
  case CMS_VERIFY_DER_DECODE_INVALID_FORMAT:
  case CMS_VERIFY_DER_DECODE_FUNCTIONALITY:
    free_charbuf(&asn1_pelz_req);
    free_charbuf(&der_signed_pelz_req);
    EVP_PKEY_free(sign_priv);
    X509_free(verify_cert);
    return ret;
    break;

  // otherwise, continue
  default:
    break;
  }

  // deserialize input DER-formatted responder public cert (encrypt key)
  X509 *encrypt_cert = deserialize_cert(der_encrypt_cert,
                                        (long) der_encrypt_cert_size);
  if (encrypt_cert == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error DER decoding X509 certificate");
    free_charbuf(&asn1_pelz_req);
    free_charbuf(&der_signed_pelz_req);
    EVP_PKEY_free(sign_priv);
    X509_free(verify_cert);
    return  MSG_TEST_SETUP_ERROR;
  }

  // deserialize input DER-formatted responder private key (decrypt key)
  EVP_PKEY *decrypt_priv = deserialize_pkey(der_decrypt_priv,
                                            (long) der_decrypt_priv_size);
  if (decrypt_priv == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error DER decoding EVP_PKEY");
    free_charbuf(&asn1_pelz_req);
    free_charbuf(&der_signed_pelz_req);
    EVP_PKEY_free(sign_priv);
    X509_free(verify_cert);
    X509_free(encrypt_cert);
    return  MSG_TEST_SETUP_ERROR;
  }

  //if (X509_check_private_key(encrypt_cert, decrypt_priv) != 1)
  //{
  //  pelz_sgx_log(LOG_ERR, "encrypt/decrypt key/cert pairing error");
  //  free_charbuf(&asn1_pelz_req);
  //  free_charbuf(&der_signed_pelz_req);
  //  EVP_PKEY_free(sign_priv);
  //  X509_free(verify_cert);
  //  X509_free(encrypt_cert);
  //  EVP_PKEY_free(decrypt_priv);
  //  return  MSG_TEST_SETUP_ERROR;
  //}

  // create enveloped pelz request message
  charbuf der_enveloped_pelz_req = new_charbuf(0);
  ret = pelz_enveloped_msg_test_helper((MsgTestSelect) test_select,
                                       der_signed_pelz_req,
                                       encrypt_cert,
                                       decrypt_priv,
                                       &der_enveloped_pelz_req);

  switch (test_select)
  {
  // if a CMS encrypt/decrypt test selected, return result
  case CMS_ENCRYPT_NULL_BUF_IN:
  case CMS_ENCRYPT_EMPTY_BUF_IN:
  case CMS_ENCRYPT_NULL_CERT_IN:
  case CMS_ENCRYPT_FUNCTIONALITY:
  case CMS_ENCRYPT_DER_ENCODE_NULL_MSG_IN:
  case CMS_ENCRYPT_DER_ENCODE_NULL_BUF_OUT:
  case CMS_ENCRYPT_DER_ENCODE_INVALID_FORMAT:
  case CMS_ENCRYPT_DER_ENCODE_FUNCTIONALITY:
  case CMS_DECRYPT_NULL_MSG_IN:
  case CMS_DECRYPT_NULL_CERT:
  case CMS_DECRYPT_NULL_PRIV:
  case CMS_DECRYPT_NULL_BUF_OUT:
  case CMS_DECRYPT_FUNCTIONALITY:
  case CMS_DECRYPT_DER_DECODE_NULL_BUF_IN:
  case CMS_DECRYPT_DER_DECODE_EMPTY_BUF_IN:
  case CMS_DECRYPT_DER_DECODE_INVALID_FORMAT:
  case CMS_DECRYPT_DER_DECODE_FUNCTIONALITY:
    free_charbuf(&asn1_pelz_req);
    free_charbuf(&der_signed_pelz_req);
    free_charbuf(&der_enveloped_pelz_req);
    EVP_PKEY_free(sign_priv);
    X509_free(verify_cert);
    X509_free(encrypt_cert);
    EVP_PKEY_free(decrypt_priv);
    return ret;
    break;

  // otherwise, continue
  default:
    break;
  }

  // run construct/deconstruct message tests
  ret = pelz_constructed_msg_test_helper((MsgTestSelect) test_select,
                                          test_msg_data,
                                          verify_cert,
                                          sign_priv,
                                          encrypt_cert,
                                          decrypt_priv);

  // clean-up keys/certs
  EVP_PKEY_free(sign_priv);
  X509_free(verify_cert);
  X509_free(encrypt_cert);
  EVP_PKEY_free(decrypt_priv);

  // clean-up charbufs created locally
  free_charbuf(&asn1_pelz_req);
  free_charbuf(&der_signed_pelz_req);
  free_charbuf(&der_enveloped_pelz_req);

  return ret;
}