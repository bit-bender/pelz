/*
 * enclave_helper_functions.c
 */

#include "enclave_helper_functions.h"

#include "common_table.h"
#include "charbuf.h"

#include "sgx_trts.h"
#include "test_enclave_t.h"
#include "cipher/pelz_cipher.h"
#include "pelz_enclave_log.h"
#include "pelz_messaging.h"


X509  *deserialize_cert(unsigned char *der_cert, long der_cert_size)
{
  if ((der_cert == NULL) || (der_cert_size <= 0))
  {
    return NULL;
  }

  return d2i_X509(NULL,
                  (const unsigned char **) &der_cert,
                  der_cert_size);
}

EVP_PKEY *deserialize_pkey(unsigned char *der_pkey, long der_pkey_size)
{
  if ((der_pkey == NULL) || (der_pkey_size == 0))
  {
    return NULL;
  }

  return d2i_PrivateKey(EVP_PKEY_EC,
                        NULL,
                        (const unsigned char **) &der_pkey,
                        der_pkey_size);
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
                                        PELZ_MSG_DATA test_msg_data_in,
                                        PELZ_MSG *test_msg_out)
{
  // create ASN1 test message
  switch (test_select)
  {
  // parse ASN.1 message test case: NULL input message
  case ASN1_PARSE_NULL_MSG_IN:
    test_msg_out = NULL;
    break;

  // all other test cases
  default:
    test_msg_out = create_pelz_asn1_msg(&test_msg_data_in);
    if (test_msg_out == NULL)
    {
      return MSG_TEST_ASN1_CREATE_ERROR;
    }
    break;
  }

  // modify ASN.1 test message fields for invalid parse parameter tests
  switch(test_select)
  {
  // parse ASN.1 message test case: incorrect 'type' tag for 'message type'
  case ASN1_PARSE_INVALID_MSG_TYPE_TAG:
    test_msg->msg_type->type = V_ASN1_INTEGER;
    break;

  // parse ASN.1 message test case: invalid (too small) 'message type' value
  case ASN1_PARSE_INVALID_MSG_TYPE_LO:
    if (ASN1_ENUMERATED_set_int64(test_msg->msg_type,
                                  (int64_t) (MSG_TYPE_MIN-1)) != 1)
    {
      pelz_sgx_log(LOG_ERR, "error modifying ASN.1 message type field");
      return MSG_TEST_SETUP_ERROR;
    }
    break;

  // parse ASN.1 message test case: invalid (too large) 'message type' value
  case ASN1_PARSE_INVALID_MSG_TYPE_HI:
    if (ASN1_ENUMERATED_set_int64(test_msg->msg_type,
                                  (int64_t) (MSG_TYPE_MAX+1)) != 1)
    {
      pelz_sgx_log(LOG_ERR, "error modifying ASN.1 message type field");
      return MSG_TEST_SETUP_ERROR;
    }
    break;

  // parse ASN.1 message test case: incorrect 'type' tag for 'request type'
  case ASN1_PARSE_INVALID_REQ_TYPE_TAG:
    test_msg->req_type->type = V_ASN1_BOOLEAN;
    break;

  // parse ASN.1 message test case: invalid (too small) 'request type' value
  case ASN1_PARSE_INVALID_REQ_TYPE_LO:
    if (ASN1_ENUMERATED_set_int64(test_msg->req_type,
                                  (int64_t) (REQ_TYPE_MIN-1)) != 1)
    {
      pelz_sgx_log(LOG_ERR, "error modifying ASN.1 request type field");
      return MSG_TEST_SETUP_ERROR;
    }
    break;

  // parse ASN.1 message test case: invalid (too large) 'request type' value
  case ASN1_PARSE_INVALID_REQ_TYPE_HI:
    if (ASN1_ENUMERATED_set_int64(test_msg->req_type,
                                  (int64_t) (REQ_TYPE_MAX+1)) != 1)
    {
      pelz_sgx_log(LOG_ERR, "error modifying ASN.1 request type field");
      return MSG_TEST_SETUP_ERROR;
    }
    break;

  // parse ASN.1 message test case: invalid tag for 'cipher' field
  case ASN1_PARSE_INVALID_CIPHER_TAG:
    test_msg->cipher->type = V_ASN1_OCTET_STRING;
    break;

  // parse ASN.1 message test case: invalid tag for 'key ID' field
  case ASN1_PARSE_INVALID_KEY_ID_TAG:
    test_msg->key_id->type = V_ASN1_GENERALSTRING;
    break;

  // parse ASN.1 message test case: invalid tag for 'data' field
  case ASN1_PARSE_INVALID_DATA_TAG:
    test_msg->data->type = V_ASN1_UTF8STRING;
    break;

  // parse ASN.1 message test case: invalid tag for 'status' field
  case PARSE_MOD_PELZ_MSG_STATUS_TAG_TEST:
    test_msg->status->type = V_ASN1_PRINTABLESTRING;
    break;

  // all other test cases: no modification of ASN.1 test message
  default:
    break;
  }

  // invoke PELZ_MSG ASN.1 parsing functionality
  PELZ_MSG_DATA parsed_test_msg_data;
  int ret = parse_pelz_asn1_msg(test_msg, &parsed_test_msg_data);
  if (ret != 0)
  {
    pelz_sgx_log(LOG_ERR, "parse of test message failed");
    return MSG_TEST_ASN1_PARSE_ERROR;
  }

  // if no error returned, validate parsed output against original input data
  if ((parsed_test_msg_data.msg_type != test_msg_data_in.msg_type) ||
      (parsed_test_msg_data.req_type != test_msg_data_in.req_type) ||
      (memcmp(parsed_test_msg_data.cipher.chars,
              test_msg_data_in.cipher.chars,
              test_msg_data_in.cipher.len) != 0) ||
      (memcmp(parsed_test_msg_data.key_id.chars,
              test_msg_data_in.key_id.chars,
              test_msg_data_in.key_id.len) != 0) ||
      (memcmp(parsed_test_msg_data.data.chars,
              test_msg_data_in.data.chars,
              test_msg_data_in.data.len) != 0) ||
      (memcmp(parsed_test_msg_data.status.chars,
              test_msg_data_in.status.chars,
              test_msg_data_in.status.len) != 0))
  {
    pelz_sgx_log(LOG_ERR, "ASN.1 create input/parse output mismatch");
    return MSG_TEST_ASN1_CREATE_PARSE_MISMATCH;
  }

  return MSG_TEST_OK;
}

MsgTestStatus pelz_asn1_der_encode_decode_test_helper(MsgTestSelect test_select,
                                                      PELZ_MSG *asn1_msg_in,
                                                      charbuf *der_out)
{

  // handle ASN.1 DER encode invalid parameter test cases
  switch (test_select)
  {
  // DER encode of ASN.1 pelz message: NULL input message test case
  case ASN1_DER_ENCODE_NULL_MSG_IN:
    der_out->len = (size_t) der_encode_pelz_msg(NULL, &der_msg, ASN1);
    if (der_out->len != PELZ_MSG_INVALID_PARAM)
    {
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // DER encode of ASN.1 pelz message: NULL output double pointer test case
  case ASN1_DER_ENCODE_NULL_BUF_OUT:
    der_out->len = (size_t) der_encode_pelz_msg((const PELZ_MSG *) asn1_msg_in,
                                                NULL,
                                                ASN1);
    if (der_out->len != (size_t) PELZ_MSG_INVALID_PARAM)
    {
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // fall through for all other test selections
  default:
    break;
  }

  // DER encode input ASN.1 test message
  der_out->len = (size_t) der_encode_pelz_msg((const PELZ_MSG *) asn1_msg_in,
                                              &(der_out->chars),
                                              ASN1);
  if ((der_out->len == 0) || (der_out->chars == NULL))
  {
    pelz_sgx_log(LOG_ERR, "error DER-encoding test ASN.1 message");
    return MSG_TEST_DER_ENCODE_ERROR;
  }

  // roughly validate DER-encoded result by checking first few bytes

  // DER encodes in a type-length-value format, so first byte is
  // the 'type' byte for the encoded PELZ_MSG sequence:
  //  - two MSBs represent class, both bits should be clear (Universal)
  //  - next MSB should be set as sequence is a 'constructed' value
  //  - five LSBs should contain tag (SEQUENCE = 16, 0x10, or 0b10000)
  // 0b00110000 = 0x30, therefore, is the expected value
  if (der_out->chars[0] != 0x30)
  {
    pelz_sgx_log(LOG_ERR, "DER-encode (ASN.1) mismatch - sequence tag");
    free(der_out->chars);
    der_out->chars == NULL;
    return MSG_TEST_DER_ENCODE_RESULT_MISMATCH;
  }
  // second byte represents the sequence length (i.e., 2 bytes less
  // than the encoded length returned in retval, as first two bytes
  // are not included in this length value)
  if (der_out->chars[1] != (der_out->len - 2))
  {
    pelz_sgx_log(LOG_ERR, "DER-encode (ASN.1) mismatch - sequence length");
    free(der_out->chars);
    der_out->chars == NULL;
    return MSG_TEST_DER_ENCODE_RESULT_MISMATCH;
  }
  // third byte represents the type for the first element in the
  // PELZ_MSG sequence (the 'msg_type' enumerated value)
  if (der_out->chars[2] != V_ASN1_ENUMERATED)
  {
    pelz_sgx_log(LOG_ERR, "DER-encode (ASN.1) mismatch - 'msg_type' tag");
    free(der_out->chars);
    der_out->chars == NULL;
    return MSG_TEST_DER_ENCODE_RESULT_MISMATCH;
  }
  // fourth byte represents the length of the encoded 'msg_type'
  // because the value is from a small enumerated set of values,
  // the length should be one byte
  if (der_out->chars[3] != 1)
  {
    pelz_sgx_log(LOG_ERR, "DER-encode (ASN.1) invalid - 'msg_type' length");
    free(der_out->chars);
    der_out->chars == NULL;
    return MSG_TEST_DER_ENCODE_RESULT_MISMATCH;
  }
  // fifth byte should represent 'msg_type' enumerated value
  // (skip because we do not have this value readily available for comparison)
  // sixth byte represents the type for the second element in the
  // PELZ_MSG sequence (the req_type enumerated value)
  if (der_out->chars[5] != V_ASN1_ENUMERATED)
  {
    pelz_sgx_log(LOG_ERR, "DER-encode (ASN.1) mismatch - 'req_type' tag");
    free(der_out->chars);
    der_out->chars == NULL;
    return MSG_TEST_DER_ENCODE_RESULT_MISMATCH;
  }
  // seventh byte represents the length of the encoded 'req_type'
  // because the value is from a small enumerated set of values,
  // the length should be one byte
  if (der_out->chars[6] != 1)
  {
    pelz_sgx_log(LOG_ERR, "DER-encode (ASN.1) invalid - 'req_type' length");
    free(der_out->chars);
    der_out->chars == NULL;
    return MSG_TEST_DER_ENCODE_RESULT_MISMATCH;
  }

  // handle remaining ASN.1 DER encode/decode test cases
  PELZ_MSG *decoded_msg = NULL;
  switch (test_select)
  {
  // DER encode of ASN.1 pelz message: functionality (result validated above)
  case ASN1_DER_ENCODE_FUNCTIONALITY:
    return MSG_TEST_OK;
    break;

  // DER decode of ASN.1 pelz message: NULL encoded input buffer test case
  case ASN1_DER_DECODE_NULL_BUF_IN:
    decoded_msg = der_decode_pelz_msg(NULL,
                                      (long) der_out->len,
                                      ASN1);
    if (decoded_msg != NULL)
    {
      PELZ_MSG_free(decoded_msg);
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // DER decode of ASN.1 pelz message: empty encoded input buffer test case
  case ASN1_DER_DECODE_EMPTY_BUF_IN:
    decoded_msg = der_decode_pelz_msg(der_out->chars,
                                      0,
                                      ASN1);
    if (decoded_msg != NULL)
    {
      PELZ_MSG_free(decoded_msg);
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // DER decode of ASN.1 pelz message: invalidly sized input buffer test case
  case ASN1_DER_DECODE_INVALID_SIZE_BUF_IN:
    decoded_msg = der_decode_pelz_msg(der_out->chars,
                                      -1,
                                      ASN1);
    if (decoded_msg != NULL)
    {
      PELZ_MSG_free(decoded_msg);
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // DER decode of ASN.1 pelz message: functionality test
  case ASN1_DER_DECODE_FUNCTIONALITY:
    decoded_msg = der_decode_pelz_msg(der_out->chars,
                                      (long) der_out->len,
                                      ASN1);
    if (decoded_msg == NULL)
    {
      return MSG_TEST_DER_DECODE_ERROR;
    }
    if (PELZ_MSG_cmp((const PELZ_MSG *) decoded_msg,
                     (const PELZ_MSG *) asn1_msg_in) != 0)
    {
      return MSG_TEST_DER_DECODE_RESULT_MISMATCH;
    }
    break;

  // fall through for all other test selections
  default:
    break;
  }

  return MSG_TEST_OK;
}

MsgTestStatus pelz_signed_msg_test_helper(MsgTestSelect test_select,
                                          charbuf msg_data_in,
                                          X509 *sign_cert,
                                          EVP_PKEY *verify_priv,
                                          CMS_ContentInfo *signed_msg_out)
{
  // handle tests for invalid parameters to create_pelz_signed_msg()
  switch (test_select)
  {
  // create signed CMS pelz message: NULL input data buffer test case
  case CMS_CREATE_SIGNED_MSG_NULL_BUF_IN:
    signed_msg_out = create_pelz_signed_msg(NULL,
                                            (int) msg_data_in.len,
                                            sign_cert,
                                            verify_priv);
    free(der_msg);
    if (signed_msg_out != NULL)
    {
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // create signed CMS pelz message: empty input data buffer test case
  case CMS_CREATE_SIGNED_MSG_EMPTY_BUF_IN:
    signed_msg_out = create_pelz_signed_msg(msg_data_in.chars,
                                            0,
                                            sign_cert,
                                            verify_priv);
    free(der_msg);
    if (signed_msg_out != NULL)
    {
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // create signed CMS pelz message: invalid size input data buffer test case
  case CMS_CREATE_SIGNED_MSG_INVALID_SIZE_BUF_IN:
    signed_msg_out = create_pelz_signed_msg(msg_data_in.chars,
                                            -1,
                                            sign_cert,
                                            verify_priv);
    free(der_msg);
    if (signed_msg_out != NULL)
    {
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // create signed CMS pelz message: NULL input certificate test case
  case CMS_CREATE_SIGNED_MSG_NULL_CERT:
    signed_msg_out = create_pelz_signed_msg(msg_data_in.chars,
                                            (int) msg_data_in.len,
                                            NULL,
                                            verify_priv);
    free(der_msg);
    if (signed_msg_out != NULL)
    {
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // create signed CMS pelz message: NULL input private key test case
  case CMS_CREATE_SIGNED_MSG_NULL_PRIV:
    signed_msg_out = create_pelz_signed_msg(msg_data_in.chars,
                                            (int) msg_data_in.len,
                                            sign_cert,
                                            NULL);
                                      
    free(der_msg);
    if (signed_msg_out != NULL)
    {
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // fall through for all other test cases
  default:
    break;
  }

  // create signed CMS message with DER-encoded pelz ASN.1 message payload
  signed_msg_out = create_pelz_signed_msg(msg_data_in.chars),
                                          (int) msg_data_in.len,
                                          sign_cert,
                                          verify_priv);
  if (signed_msg_out == NULL)
  {
    return MSG_TEST_SIGN_ERROR;
  }

  // verify that the newly created signed CMS message object is right "type"
  if (OBJ_obj2nid(CMS_get0_type(signed_msg_out)) != NID_pkcs7_signed)
  {
    CMS_ContentInfo_free(signed_msg_out);
    signed_msg_out = NULL;
    return MSG_TEST_INVALID_SIGN_RESULT;
  }

  // extract signed message content and check that it matches original input
  const ASN1_OCTET_STRING *signed_content = *(CMS_get0_content(signed_msg_out));
  CMS_ContentInfo_free(sign_test_msg);
  if (signed_content == NULL)
  {
    CMS_ContentInfo_free(signed_msg_out);
    signed_msg_out = NULL;
    return MSG_TEST_SETUP_ERROR;
  }
  int signed_data_size = ASN1_STRING_length(signed_content);
  const unsigned char * signed_data = ASN1_STRING_get0_data(signed_content);
  if ((signed_data == NULL) || (signed_data_size <= 0))
  {
    CMS_ContentInfo_free(signed_msg_out);
    signed_msg_out = NULL;
    return MSG_TEST_SETUP_ERROR;
  }
  if ((signed_data_size != (int) msg_data_in.len) ||
      (memcmp(msg_data_in.chars, signed_data, signed_data_size) != 0))
  {
    CMS_ContentInfo_free(signed_msg_out);
    signed_msg_out = NULL;
    return MSG_TEST_INVALID_SIGN_RESULT;
  }

  // handle signed CMS message verification test cases
  X509 *cert_out = NULL;
  unsigned char *verify_data = NULL;
  int verify_data_size = -1;
  switch (test_select)
  {
  // verify signed CMS pelz message: NULL input message test case
  case CMS_VERIFY_SIGNED_MSG_NULL_MSG_IN:
    CMS_ContentInfo_free(signed_msg_out);
    signed_msg_out = NULL;
    verify_data_size = verify_pelz_signed_msg(signed_msg_out,
                                              &cert_out,
                                              &verify_data);
    if (verify_data_size != PELZ_MSG_PARAM_INVALID)
    {
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // verify signed CMS pelz message: NULL output cert double pointer test case
  case CMS_VERIFY_SIGNED_MSG_NULL_CERT_OUT:
    verify_data_size = verify_pelz_signed_msg(signed_msg_out,
                                              NULL,
                                              &verify_data);
    CMS_ContentInfo_free(signed_msg_out);
    signed_msg_out = NULL;
    if (verify_data_size != PELZ_MSG_PARAM_INVALID)
    {
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // verify signed CMS pelz message: NULL output data double pointer test case
  case CMS_VERIFY_SIGNED_MSG_NULL_DATA_OUT:
    verify_data_size = verify_pelz_signed_msg(signed_msg_out,
                                              &cert_out,
                                              NULL);
    CMS_ContentInfo_free(signed_msg_out);
    signed_msg_out = NULL;
    if (verify_data_size != PELZ_MSG_PARAM_INVALID)
    {
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // verify signed CMS pelz message: functionality test
  case CMS_VERIFY_SIGNED_MSG_FUNCTIONALITY:
    verify_data_size = verify_pelz_signed_msg(signed_msg_out,
                                              &cert_out,
                                              &verify_data);
    CMS_ContentInfo_free(signed_msg_out);
    signed_msg_out = NULL;

    if ((verify_data_size != (int) msg_data_in.len) ||
        (memcmp(msg_data_in.chars, verify_data, verify_data_size) != 0) ||
        (X509_cmp(cert_out, sign_cert) != 0))
    {
      return MSG_TEST_VERIFY_ERROR;
    }
    break;

  // fall through for all other test cases
  default:
    break;
  }

  return MSG_TEST_OK;
}

MsgTestStatus pelz_cms_der_encode_decode_test_helper(MsgTestSelect test_select,
                                                     CMS_ContentInfo *cms_msg_in,
                                                     charbuf *der_out)
{

  // handle CMS DER encode invalid parameter test cases
  switch (test_select)
  {
  // DER encode of signed CMS pelz message: NULL input message test case
  case CMS_DER_ENCODE_NULL_MSG_IN:
    der_out->len = (size_t) der_encode_pelz_msg(NULL, &der_msg, CMS);
    if (der_out->len != PELZ_MSG_INVALID_PARAM)
    {
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // DER encode of signed CMS pelz message: NULL output double pointer test case
  case CMS_DER_ENCODE_NULL_BUF_OUT:
    der_out->len = (size_t) der_encode_pelz_msg((const CMS_ContentInfo *) cms_msg_in,
                                                NULL,
                                                CMS);
    if (der_out->len != (size_t) PELZ_MSG_INVALID_PARAM)
    {
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // fall through for all other test selections
  default:
    break;
  }

  // DER encode input CMS test message
  der_out->len = (size_t) der_encode_pelz_msg((const CMS_ContentInfo *) cms_msg_in,
                                              &(der_out->chars),
                                              CMS);
  if ((der_out->len == 0) || (der_out->chars == NULL))
  {
    return MSG_TEST_DER_ENCODE_ERROR;
  }

  // roughly validate DER-encoded result by checking first few bytes

  // DER encodes in a type-length-value format, so first byte is
  // the 'type' byte for the encoded PELZ_MSG sequence:
  //  - two MSBs represent class, both bits should be clear (Universal)
  //  - next MSB should be set as sequence is a 'constructed' value
  //  - five LSBs should contain tag (SEQUENCE = 16, 0x10, or 0b10000)
  // 0b00110000 = 0x30, therefore, is the expected value
  if (der_out->chars[0] != 0x30)
  {
    pelz_sgx_log(LOG_ERR, "DER-encode (CMS) mismatch - sequence tag");
    free(der_out->chars);
    der_out->chars == NULL;
    return MSG_TEST_DER_ENCODE_RESULT_MISMATCH;
  }
  // second byte represents the sequence length (i.e., 2 bytes less
  // than the encoded length returned in retval, as first two bytes
  // are not included in this length value)
  if (der_out->chars[1] != (der_out->len - 2))
  {
    pelz_sgx_log(LOG_ERR, "DER-encode (CMS) mismatch - sequence length");
    free(der_out->chars);
    der_out->chars == NULL;
    return MSG_TEST_DER_ENCODE_RESULT_MISMATCH;
  }
  // third byte represents the type for the first element in the
  // CMS encoded PELZ_MSG sequence, which should be the object
  // identifier (OID)
  if (der_out->chars[2] != V_ASN1_OBJECT)
  {
    pelz_sgx_log(LOG_ERR, "DER-encode (CMS) mismatch - OID tag");
    return MSG_TEST_DER_ENCODE_RESULT_MISMATCH;
  }

  // handle remaining CMS DER encode/decode test cases
  CMS_ContentInfo *decoded_msg = NULL;
  ASN1_OCTET_STRING **input_cms_msg_payload = NULL;
  ASN1_OCTET_STRING **decoded_cms_msg_payload = NULL;
  switch (test_select)
  {
  // DER encode of CMS pelz message: functionality (result validated above)
  case CMS_DER_ENCODE_FUNCTIONALITY:
    return MSG_TEST_OK;
    break;

  // DER decode of CMS pelz message: NULL encoded input buffer test case
  case CMS_DER_DECODE_NULL_BUF_IN:
    decoded_msg = der_decode_pelz_msg(NULL,
                                      (long) der_out->len,
                                      CMS);
    if (decoded_msg != NULL)
    {
      CMS_ContentInfo_free(decoded_msg);
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // DER decode of ASN.1 pelz message: empty encoded input buffer test case
  case CMS_DER_DECODE_EMPTY_BUF_IN:
    decoded_msg = der_decode_pelz_msg(der_out->chars,
                                      0,
                                      CMS);
    if (decoded_msg != NULL)
    {
      CMS_ContentInfo_free(decoded_msg);
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // DER decode of CMS pelz message: invalidly sized input buffer test case
  case CMS_DER_DECODE_INVALID_SIZE_BUF_IN:
    decoded_msg = der_decode_pelz_msg(der_out->chars,
                                      -1,
                                      CMS);
    if (decoded_msg != NULL)
    {
      CMS_ContentInfo_free(decoded_msg);
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // DER decode of ASN.1 pelz message: functionality test
  case CMS_DER_DECODE_FUNCTIONALITY:
    decoded_msg = der_decode_pelz_msg(der_out->chars,
                                      (long) der_out->len,
                                      CMS);
    if (decoded_msg == NULL)
    {
      return MSG_TEST_DER_DECODE_ERROR;
    }
    input_cms_msg_payload = CMS_get0_content(cms_msg_in);
    decoded_cms_msg_payload = CMS_get0_content(decoded_msg);
    if (ASN1_OCTET_STRING_cmp(*decoded_cms_msg_payload,
                              *input_cms_msg_payload) != 0)
    {
      pelz_sgx_log(LOG_ERR, "DER-decoded CMS message mismatch");
      return MSG_TEST_DER_DECODE_RESULT_MISMATCH;
    }
    break;

  // fall through for all other test selections
  default:
    break;
  }

  return MSG_TEST_OK;
}

int test_create_pelz_enveloped_msg_helper(size_t test_data_in_len,
                                          uint8_t *test_data_in,
                                          size_t test_der_cert_len,
                                          const uint8_t *test_der_cert)
{
  // convert input DER-formatted key/cert byte arrays to internal format
  X509 *test_cert = NULL;
  if ((test_der_cert != NULL) && (test_der_cert_len != 0))
  {
    d2i_X509(&test_cert, &test_der_cert, (int) test_der_cert_len);
  }

  // if input parameters result in NULL/empty input data or NULL cert,
  // test that these invalid parameter cases are properly handled
  if ((test_data_in == NULL) || (test_data_in_len <= 0) || (test_cert == NULL))
  {
    CMS_ContentInfo *invalid_param_msg = NULL;
    invalid_param_msg = create_pelz_enveloped_msg(test_data_in,
                                                  (int) test_data_in_len,
                                                  test_cert);
    X509_free(test_cert);
    if (invalid_param_msg != NULL)
    {
      CMS_ContentInfo_free(invalid_param_msg);
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    CMS_ContentInfo_free(invalid_param_msg);
    return MSG_TEST_PARAM_HANDLING_OK;
  }

  // test enveloped message creation using input/derived test data
  CMS_ContentInfo *enveloped_test_msg = NULL;
  enveloped_test_msg = create_pelz_enveloped_msg(test_data_in,
                                                 (int) test_data_in_len,
                                                 test_cert);
  if (enveloped_test_msg == NULL)
  {
    X509_free(test_cert);
    return MSG_TEST_ENCRYPT_ERROR;
  }

  // validate the message 'type' (authEnvelopedData)
  int test_msg_type = OBJ_obj2nid(CMS_get0_type(enveloped_test_msg));
  if (test_msg_type != NID_id_smime_ct_authEnvelopedData)
  {
    X509_free(test_cert);
    CMS_ContentInfo_free(enveloped_test_msg);
    return MSG_TEST_INVALID_ENCRYPT_RESULT;
  }

  // validate length of encrypted message content matches the length
  // of the input data and differs in content
  const ASN1_OCTET_STRING *enveloped_content =
                             *(CMS_get0_content(enveloped_test_msg));
  if (enveloped_content == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error extracting enveloped message content")
    X509_free(test_cert);
    CMS_ContentInfo_free(enveloped_test_msg);
    return MSG_TEST_SETUP_ERROR;
  }
  int enc_data_len = -1;
  enc_data_len = ASN1_STRING_length(enveloped_content);
  const uint8_t *enc_data = ASN1_STRING_get0_data(enveloped_content);
  if ((enc_data == NULL) ||
      (enc_data_len != (int) test_data_in_len) ||
      (memcmp(test_data_in, enc_data, test_data_in_len) == 0))
  {
    pelz_sgx_log(LOG_DEBUG, "failed created CMS message content checks");
    X509_free(test_cert);
    CMS_ContentInfo_free(enveloped_test_msg);
    return MSG_TEST_INVALID_ENCRYPT_RESULT;
  }

  // clean-up
  X509_free(test_cert);
  CMS_ContentInfo_free(enveloped_test_msg);

  return MSG_TEST_OK;
}

int test_decrypt_pelz_enveloped_msg_helper(size_t test_data_in_len,
                                           uint8_t *test_data_in,
                                           size_t test_der_cert_len,
                                           const uint8_t *test_der_cert,
                                           size_t test_der_priv_len,
                                           const uint8_t *test_der_priv,
                                           uint8_t test_select)
{
  unsigned char *decrypt_data = NULL;
  int decrypt_data_len = -1;
  int result = MSG_TEST_UNKNOWN_ERROR;

  // convert input DER-formatted private key byte array to internal format
  EVP_PKEY *test_priv = deserialize_pkey(test_der_priv,
                                         (long) test_der_priv_len);
  if (test_priv == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error DER decoding EVP_PKEY");
    return MSG_TEST_SETUP_ERROR;
  }

  // convert input DER-formatted public cert byte array to internal format
  X509 *test_cert = deserialize_cert(test_der_cert,
                                     (long) test_der_cert_len);
  if (test_cert == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error DER decoding X509 certificate");
    EVP_PKEY_free(test_priv);
    return MSG_TEST_SETUP_ERROR;
  }

  // create authEnvelopedData CMS test message
  CMS_ContentInfo *enveloped_test_msg = NULL;
  enveloped_test_msg = create_pelz_enveloped_msg(test_data_in,
                                                 (int) test_data_in_len,
                                                 test_cert);
  if (enveloped_test_msg == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error creating enveloped CMS test message");
    EVP_PKEY_free(test_priv);
    X509_free(test_cert);
    return MSG_TEST_SETUP_ERROR;
  }
  // validate the message 'type' (authEnvelopedData)
  int test_msg_type = OBJ_obj2nid(CMS_get0_type(enveloped_test_msg));
  if (test_msg_type != NID_id_smime_ct_authEnvelopedData)
  {
    pelz_sgx_log(LOG_ERR, "created non-enveloped CMS test message");
    EVP_PKEY_free(test_priv);
    X509_free(test_cert);
    return MSG_TEST_SETUP_ERROR;
  }
  const ASN1_OCTET_STRING * encrypted_content =
                              *(CMS_get0_content(enveloped_test_msg));
  if (encrypted_content == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error extracting content from CMS test message");
    EVP_PKEY_free(test_priv);
    X509_free(test_cert);
    CMS_ContentInfo_free(enveloped_test_msg);
    return MSG_TEST_SETUP_ERROR;
  }
  int enc_data_len = -1;
  enc_data_len = ASN1_STRING_length(encrypted_content);
  const uint8_t *enc_data = ASN1_STRING_get0_data(encrypted_content);
  if ((enc_data == NULL) ||
      (enc_data_len != (int) test_data_in_len) ||
      (memcmp(test_data_in, enc_data, test_data_in_len) == 0))
  {
    pelz_sgx_log(LOG_ERR, "unexpected CMS test message content");
    EVP_PKEY_free(test_priv);
    X509_free(test_cert);
    CMS_ContentInfo_free(enveloped_test_msg);
    return MSG_TEST_SETUP_ERROR;
  }

  switch(test_select)
  {
  // valid set of parameters test case:
  //   - input certificate recommended, but should be optional
  case DECRYPT_PELZ_ENVELOPED_MSG_NULL_CERT_TEST:
  case DECRYPT_PELZ_ENVELOPED_MSG_BASIC_TEST:
    if (test_select == DECRYPT_PELZ_ENVELOPED_MSG_NULL_CERT_TEST)
    {
      decrypt_data_len = decrypt_pelz_enveloped_msg(enveloped_test_msg,
                                                    NULL,
                                                    test_priv,
                                                    &decrypt_data);
    }
    else
    {
      decrypt_data_len = decrypt_pelz_enveloped_msg(enveloped_test_msg,
                                                    test_cert,
                                                    test_priv,
                                                    &decrypt_data);
    }
    if ((decrypt_data == NULL) ||
        (decrypt_data_len != (int) test_data_in_len) ||
        (memcmp(test_data_in,
                decrypt_data,
                test_data_in_len) != 0))
    {
      result = MSG_TEST_DECRYPT_ERROR;
      break;
    }
    result = MSG_TEST_SUCCESS;
    break;

  // NULL input message should be handled as invalid parameter
  case DECRYPT_PELZ_ENVELOPED_MSG_NULL_IN_MSG_TEST:
    decrypt_data_len = decrypt_pelz_enveloped_msg(NULL,
                                                  test_cert,
                                                  test_priv,
                                                  &decrypt_data);
    if (decrypt_data_len != PELZ_MSG_PARAM_INVALID)
    {
      result = MSG_TEST_PARAM_HANDLING_ERROR;
      break;
    }
    result = MSG_TEST_PARAM_HANDLING_OK;
    break;

  // NULL double pointer to output buffer should be handled as invalid param
  case DECRYPT_PELZ_ENVELOPED_MSG_NULL_OUT_BUF_TEST:
    decrypt_data_len = decrypt_pelz_enveloped_msg(enveloped_test_msg,
                                                  test_cert,
                                                  test_priv,
                                                  NULL);
    if (decrypt_data_len != PELZ_MSG_PARAM_INVALID)
    {
      result = MSG_TEST_PARAM_HANDLING_ERROR;
      break;
    }
    result = MSG_TEST_PARAM_HANDLING_OK;
    break;

  // NULL private key input should be handled as invalid parameter
  case DECRYPT_PELZ_ENVELOPED_MSG_NULL_PRIV_TEST:
    decrypt_data_len = decrypt_pelz_enveloped_msg(enveloped_test_msg,
                                                  test_cert,
                                                  NULL,
                                                  &decrypt_data);
    if (decrypt_data_len != PELZ_MSG_PARAM_INVALID)
    {
      result = MSG_TEST_PARAM_HANDLING_ERROR;
      break;
    }
    result = MSG_TEST_PARAM_HANDLING_OK;
    break;

  default:
    pelz_sgx_log(LOG_ERR, "invalid test selection");
    result = MSG_TEST_SETUP_ERROR;
  }

  // clean-up
  EVP_PKEY_free(test_priv);
  X509_free(test_cert);
  CMS_ContentInfo_free(enveloped_test_msg);
  free(decrypt_data);

  return result;
}

int test_end_to_end_pelz_msg_helper(uint8_t test_msg_type,
                                    uint8_t test_req_type,
                                    size_t test_cipher_len,
                                    unsigned char * test_cipher,
                                    size_t test_key_id_len,
                                    unsigned char * test_key_id,
                                    size_t test_data_len,
                                    unsigned char * test_data,
                                    size_t test_status_len,
                                    unsigned char * test_status,
                                    size_t test_der_sign_cert_len,
                                    unsigned char * test_der_sign_cert,
                                    size_t test_der_sign_priv_len,
                                    unsigned char * test_der_sign_priv,
                                    size_t test_der_enc_cert_len,
                                    unsigned char * test_der_enc_cert,
                                    size_t test_der_enc_priv_len,
                                    unsigned char * test_der_enc_priv,
                                    uint8_t test_select)
{
  // check that input test parameters are completely and validly specified
  if (((test_msg_type < MSG_TYPE_MIN) || (test_msg_type > MSG_TYPE_MAX)) ||
      ((test_req_type < REQ_TYPE_MIN) || (test_req_type > REQ_TYPE_MAX)) ||
      ((test_cipher == NULL) || (test_cipher_len == 0)) ||
      ((test_key_id == NULL) || (test_key_id_len == 0)) ||
      ((test_data == NULL) || (test_data_len == 0)) ||
      ((test_status == NULL) || (test_status_len == 0)) ||
      ((test_der_sign_cert == NULL) || (test_der_sign_cert_len == 0)) ||
      ((test_der_sign_priv == NULL) || (test_der_sign_priv_len == 0)) ||
      ((test_der_enc_cert == NULL) || (test_der_enc_cert_len == 0)) ||
      ((test_der_enc_priv == NULL) || (test_der_enc_priv_len == 0)))
  {
    pelz_sgx_log(LOG_ERR, "NULL, empty, or invalid test input parameter");
    return MSG_TEST_INVALID_TEST_PARAMETER;
  }

  // assign specified test message values to PELZ_MSG_DATA struct
  PELZ_MSG_DATA test_msg_data_in = { .msg_type = (PELZ_MSG_TYPE) test_msg_type,
                                     .req_type = (PELZ_REQ_TYPE) test_req_type,
                                     .cipher = { .chars = test_cipher,
                                                 .len = test_cipher_len },
                                     .key_id = { .chars = test_key_id,
                                                 .len = test_key_id_len },
                                     .data =   { .chars = test_data,
                                                 .len = test_data_len },
                                     .status = { .chars = test_status,
                                                 .len = test_status_len } };

  // convert input DER-formatted key/cert byte arrays to internal format
  const unsigned char *temp_buf_ptr = test_der_sign_cert;
  X509 *test_sign_cert = d2i_X509(NULL,
                                  &temp_buf_ptr,
                                  (int) test_der_sign_cert_len);
  if (test_sign_cert == NULL)
  {
    pelz_sgx_log(LOG_ERR, "DER decode error: test cert for message signer");
    return MSG_TEST_SETUP_ERROR;
  }
  temp_buf_ptr = test_der_sign_priv;
  EVP_PKEY *test_sign_priv = d2i_PrivateKey(EVP_PKEY_EC,
                                            NULL,
                                            &temp_buf_ptr,
                                            (int) test_der_sign_priv_len);
  if (test_sign_priv == NULL)
  {
    pelz_sgx_log(LOG_ERR, "DER decode error: test key for message signer");
    X509_free(test_sign_cert);
    return MSG_TEST_SETUP_ERROR;
  }
  temp_buf_ptr = test_der_enc_cert;
  X509 *test_enc_cert = d2i_X509(NULL,
                                 &temp_buf_ptr,
                                 (int) test_der_enc_cert_len);
  if (test_enc_cert == NULL)
  {
    pelz_sgx_log(LOG_ERR, "DER decode error: test cert for message encryptor");
    X509_free(test_sign_cert);
    EVP_PKEY_free(test_sign_priv);
    return MSG_TEST_SETUP_ERROR;
  }
  temp_buf_ptr = test_der_enc_priv;
  EVP_PKEY *test_enc_priv = d2i_PrivateKey(EVP_PKEY_EC,
                                           NULL,
                                           &temp_buf_ptr,
                                           (int) test_der_enc_priv_len);
  if (test_enc_priv == NULL)
  {
    pelz_sgx_log(LOG_ERR, "DER decode error: test key for message encryptor");
    X509_free(test_sign_cert);
    EVP_PKEY_free(test_sign_priv);
    X509_free(test_enc_cert);
    return MSG_TEST_SETUP_ERROR;
  }

  charbuf test_msg_buf = { 0 };
  int ret = -1;

  switch (test_select)
  {
  // NULL input data parameter to 'construct' case
  case CONSTRUCT_PELZ_MSG_NULL_MSG_IN_TEST:
    ret = construct_pelz_msg(NULL,
                             test_sign_cert,
                             test_sign_priv,
                             test_enc_cert,
                             &test_msg_buf);
    X509_free(test_sign_cert);
    EVP_PKEY_free(test_sign_priv);
    X509_free(test_enc_cert);
    EVP_PKEY_free(test_enc_priv);
    if (ret != PELZ_MSG_PARAM_INVALID)
    {
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // NULL input local cert parameter to 'construct' case
  case CONSTRUCT_PELZ_MSG_NULL_LOCAL_CERT_TEST:
    ret = construct_pelz_msg(&test_msg_data_in,
                             NULL,
                             test_sign_priv,
                             test_enc_cert,
                             &test_msg_buf);
    X509_free(test_sign_cert);
    EVP_PKEY_free(test_sign_priv);
    X509_free(test_enc_cert);
    EVP_PKEY_free(test_enc_priv);
    if (ret != PELZ_MSG_PARAM_INVALID)
    {
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // NULL input local private key parameter to 'construct' case
  case CONSTRUCT_PELZ_MSG_NULL_LOCAL_PRIV_TEST:
    ret = construct_pelz_msg(&test_msg_data_in,
                             test_sign_cert,
                             NULL,
                             test_enc_cert,
                             &test_msg_buf);
    X509_free(test_sign_cert);
    EVP_PKEY_free(test_sign_priv);
    X509_free(test_enc_cert);
    EVP_PKEY_free(test_enc_priv);
    if (ret != PELZ_MSG_PARAM_INVALID)
    {
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // NULL input remote (peer) cert parameter to 'construct' case
  case CONSTRUCT_PELZ_MSG_NULL_PEER_CERT_TEST:
    ret = construct_pelz_msg(&test_msg_data_in,
                             test_sign_cert,
                             test_sign_priv,
                             NULL,
                             &test_msg_buf);
    X509_free(test_sign_cert);
    EVP_PKEY_free(test_sign_priv);
    X509_free(test_enc_cert);
    EVP_PKEY_free(test_enc_priv);
    if (ret != PELZ_MSG_PARAM_INVALID)
    {
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // NULL output buffer parameter to 'construct' case
  case CONSTRUCT_PELZ_MSG_NULL_OUT_BUF_TEST:
    ret = construct_pelz_msg(&test_msg_data_in,
                             test_sign_cert,
                             test_sign_priv,
                             test_enc_cert,
                             NULL);
    X509_free(test_sign_cert);
    EVP_PKEY_free(test_sign_priv);
    X509_free(test_enc_cert);
    EVP_PKEY_free(test_enc_priv);
    if (ret != PELZ_MSG_PARAM_INVALID)
    {
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // fall through for remaining valid test selections
  case CONSTRUCT_DECONSTRUCT_PELZ_MSG_BASIC_TEST:
  case DECONSTRUCT_PELZ_MSG_NULL_MSG_IN_TEST:
  case DECONSTRUCT_PELZ_MSG_NULL_LOCAL_CERT_TEST:
  case DECONSTRUCT_PELZ_MSG_NULL_LOCAL_PRIV_TEST:
  case DECONSTRUCT_PELZ_MSG_NULL_PEER_CERT_TEST:
  case DECONSTRUCT_PELZ_MSG_PREALLOC_PEER_CERT_TEST:
    break;

  // invalid test selection
  default:
    pelz_sgx_log(LOG_ERR, "invalid test selection");
    return MSG_TEST_SETUP_ERROR;
  }

  // create test message
  ret = construct_pelz_msg(&test_msg_data_in,
                           test_sign_cert,
                           test_sign_priv,
                           test_enc_cert,
                           &test_msg_buf);
  if ((test_msg_buf.chars == NULL) || (test_msg_buf.len <= 0))
  {
    pelz_sgx_log(LOG_ERR, "test message construction error");
    X509_free(test_sign_cert);
    EVP_PKEY_free(test_sign_priv);
    X509_free(test_enc_cert);
    EVP_PKEY_free(test_enc_priv);
    return MSG_TEST_SETUP_ERROR;
  }

  // declare/initialize some variables needed by some tests
  PELZ_MSG_DATA deconstructed_test_msg_data = { 0 };
  charbuf null_msg_buf = { .chars = NULL, .len = 0 };
  X509 *non_null_cert = X509_new();
  X509 *deconstructed_sign_cert = NULL;

  switch (test_select)
  {
  // NULL input data buffer parameter to 'deconstruct' case
  case DECONSTRUCT_PELZ_MSG_NULL_MSG_IN_TEST:
    ret = deconstruct_pelz_msg(null_msg_buf,
                               test_enc_cert,
                               test_enc_priv,
                               &deconstructed_sign_cert,
                               &deconstructed_test_msg_data);
    X509_free(test_sign_cert);
    EVP_PKEY_free(test_sign_priv);
    X509_free(test_enc_cert);
    EVP_PKEY_free(test_enc_priv);
    X509_free(non_null_cert);
    X509_free(deconstructed_sign_cert);
    if (ret != PELZ_MSG_PARAM_INVALID)
    {
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // NULL input local certificate parameter to 'deconstruct' case
  case DECONSTRUCT_PELZ_MSG_NULL_LOCAL_CERT_TEST:
    ret = deconstruct_pelz_msg(test_msg_buf,
                               NULL,
                               test_enc_priv,
                               &deconstructed_sign_cert,
                               &deconstructed_test_msg_data);
    X509_free(test_sign_cert);
    EVP_PKEY_free(test_sign_priv);
    X509_free(test_enc_cert);
    EVP_PKEY_free(test_enc_priv);
    X509_free(non_null_cert);
    X509_free(deconstructed_sign_cert);
    if (ret != PELZ_MSG_PARAM_INVALID)
    {
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // NULL input local private key parameter to 'deconstruct' case
  case DECONSTRUCT_PELZ_MSG_NULL_LOCAL_PRIV_TEST:
    ret = deconstruct_pelz_msg(test_msg_buf,
                               test_enc_cert,
                               NULL,
                               &deconstructed_sign_cert,
                               &deconstructed_test_msg_data);
    X509_free(test_sign_cert);
    EVP_PKEY_free(test_sign_priv);
    X509_free(test_enc_cert);
    EVP_PKEY_free(test_enc_priv);
    X509_free(non_null_cert);
    X509_free(deconstructed_sign_cert);
    if (ret != PELZ_MSG_PARAM_INVALID)
    {
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // NULL double pointer remote (peer) cert parameter to 'deconstruct' case
  case DECONSTRUCT_PELZ_MSG_NULL_PEER_CERT_TEST:
    ret = deconstruct_pelz_msg(test_msg_buf,
                               test_enc_cert,
                               test_enc_priv,
                               NULL,
                               &deconstructed_test_msg_data);
    X509_free(test_sign_cert);
    EVP_PKEY_free(test_sign_priv);
    X509_free(test_enc_cert);
    EVP_PKEY_free(test_enc_priv);
    X509_free(non_null_cert);
    if (ret != PELZ_MSG_PARAM_INVALID)
    {
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // Pointer to non-NULL pointer to remote (peer) cert param to 'decode" case
  case DECONSTRUCT_PELZ_MSG_PREALLOC_PEER_CERT_TEST:
    ret = deconstruct_pelz_msg(test_msg_buf,
                               test_enc_cert,
                               test_enc_priv,
                               &non_null_cert,
                               &deconstructed_test_msg_data);
    X509_free(test_sign_cert);
    EVP_PKEY_free(test_sign_priv);
    X509_free(test_enc_cert);
    EVP_PKEY_free(test_enc_priv);
    X509_free(non_null_cert);
    if (ret != PELZ_MSG_PARAM_INVALID)
    {
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  case CONSTRUCT_DECONSTRUCT_PELZ_MSG_BASIC_TEST:
    ret = deconstruct_pelz_msg(test_msg_buf,
                               test_enc_cert,
                               test_enc_priv,
                               &deconstructed_sign_cert,
                               &deconstructed_test_msg_data);
    X509_free(test_sign_cert);
    EVP_PKEY_free(test_sign_priv);
    X509_free(test_enc_cert);
    EVP_PKEY_free(test_enc_priv);
    X509_free(non_null_cert);
    X509_free(deconstructed_sign_cert);
    if (ret != PELZ_MSG_SUCCESS)
    {
      pelz_sgx_log(LOG_ERR, "deconstruct_pelz_msg() error");
      free_charbuf(&deconstructed_test_msg_data.cipher);
      free_charbuf(&deconstructed_test_msg_data.key_id);
      free_charbuf(&deconstructed_test_msg_data.data);
      free_charbuf(&deconstructed_test_msg_data.status);
      return ret;
    }
    if ((deconstructed_test_msg_data.msg_type != test_msg_data_in.msg_type) ||
        (deconstructed_test_msg_data.req_type != test_msg_data_in.req_type) ||
        (memcmp(deconstructed_test_msg_data.cipher.chars,
                test_msg_data_in.cipher.chars,
                deconstructed_test_msg_data.cipher.len) != 0) ||
        (memcmp(deconstructed_test_msg_data.key_id.chars,
                test_msg_data_in.key_id.chars,
                deconstructed_test_msg_data.key_id.len) != 0) ||
        (memcmp(deconstructed_test_msg_data.data.chars,
                test_msg_data_in.data.chars,
                deconstructed_test_msg_data.data.len) != 0) ||
        (memcmp(deconstructed_test_msg_data.status.chars,
                test_msg_data_in.status.chars,
                deconstructed_test_msg_data.status.len) != 0))
    {
      pelz_sgx_log(LOG_ERR, "deconstructed result mismatches original input");
      free_charbuf(&deconstructed_test_msg_data.cipher);
      free_charbuf(&deconstructed_test_msg_data.key_id);
      free_charbuf(&deconstructed_test_msg_data.data);
      free_charbuf(&deconstructed_test_msg_data.status);
      return MSG_TEST_INVALID_DECODE_RESULT;
    }
    free_charbuf(&deconstructed_test_msg_data.cipher);
    free_charbuf(&deconstructed_test_msg_data.key_id);
    free_charbuf(&deconstructed_test_msg_data.data);
    free_charbuf(&deconstructed_test_msg_data.status);
    return MSG_TEST_SUCCESS;
    break;

  default:
    pelz_sgx_log(LOG_ERR, "invalid test selection");
    return MSG_TEST_SETUP_ERROR;
  }

  // should never reach this statement
  return MSG_TEST_UNKNOWN_ERROR;
}

int pelz_enclave_msg_test_helper(uint8_t msg_type,
                                 uint8_t req_type,
                                 size_t cipher_size,
                                 unsigned char * cipher,
                                 size_t key_id_size,
                                 unsigned char * key_id,
                                 size_t msg_data_size,
                                 unsigned char * msg_data,
                                 size_t msg_status_size,
                                 unsigned char * msg_status,
                                 size_t der_sign_priv_size,
                                 unsigned char * der_sign_priv,
                                 size_t der_verify_cert_size,
                                 unsigned char * der_verify_cert,
                                 size_t der_encrypt_cert_size,
                                 unsigned char * der_encrypt_cert,
                                 size_t der_decrypt_priv_size,
                                 unsigned char * der_decrypt_priv,
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
  PELZ_MSG asn1_pelz_req = { 0 };
  MsgTestStatus ret = pelz_asn1_msg_test_helper((MsgTestSelect) test_select,
                                                 test_msg_data,
                                                 &asn1_pelz_req);

  switch (test_select)
  {
  // if an ASN.1 creation/parsing test selected, return result obtained
  case ASN1_CREATE_FUNCTIONALITY:
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
    return (int) ret;
    break;

  // otherwise, continue
  default:
    break;
  }

  // DER-encode ASN.1 formatted pelz request message
  charbuf der_asn1_pelz_req = { .chars = NULL, .len = 0 };
  ret = pelz_asn1_der_encode_decode_test_helper((MsgTestSelect) test_select,
                                                 &asn1_pelz_req],
                                                 &der_asn1_pelz_req);

  switch (test_select)
  {
  // if an ASN.1 DER encode/decode test selected, return obtained result
  case ASN1_DER_ENCODE_NULL_MSG_IN:
  case ASN1_DER_ENCODE_NULL_BUF_OUT:
  case ASN1_DER_ENCODE_FUNCTIONALITY:
  case ASN1_DER_DECODE_NULL_BUF_IN:
  case ASN1_DER_DECODE_EMPTY_BUF_IN:
  case ASN1_DER_DECODE_INVALID_SIZE_BUF_IN:
  case ASN1_DER_DECODE_FUNCTIONALITY:
    return (int) ret;
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
    return (int) MSG_TEST_SETUP_ERROR;
  }

  // deserialize input DER-formatted requestor public cert (verify key)
  X509 *verify_cert = deserialize_cert(der_verify_cert,
                                       (long) der_verify_cert_size);
  if (verify_cert == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error DER decoding X509 certificate");
    EVP_PKEY_free(sign_priv);
    return (int) MSG_TEST_SETUP_ERROR;
  }

  // create signed Cryptographic Message Syntax (CMS) pelz request message
  CMS_ContentInfo signed_pelz_req = { 0 };
  ret = pelz_signed_msg_test_helper((MsgTestSelect) test_select,
                                     &asn1_pelz_req,
                                     sign_cert,
                                     verify_priv,
                                     &signed_pelz_req);

  switch (test_select)
  {
  // if an ASN.1 DER encode or CMS sign/verify test selected, return result
  case CMS_CREATE_SIGNED_MSG_NULL_BUF_IN:
  case CMS_CREATE_SIGNED_MSG_EMPTY_BUF_IN:
  case CMS_CREATE_SIGNED_MSG_INVALID_SIZE_BUF_IN:
  case CMS_CREATE_SIGNED_MSG_NULL_CERT_IN:
  case CMS_CREATE_SIGNED_MSG_NULL_PRIV_IN:
  case CMS_CREATE_SIGNED_MSG_FUNCTIONALITY:
  case CMS_VERIFY_SIGNED_MSG_NULL_MSG_IN:
  case CMS_VERIFY_SIGNED_MSG_NULL_CERT_OUT:
  case CMS_VERIFY_SIGNED_MSG_NULL_BUF_OUT:
  case CMS_VERIFY_SIGNED_MSG_FUNCTIONALITY:
    return (int) ret;
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
    EVP_PKEY_free(sign_priv);
    X509_free(verify_cert);
    return (int) MSG_TEST_SETUP_ERROR;
  }

  // deserialize input DER-formatted responder private key (decrypt key)
  EVP_PKEY *decrypt_priv = deserialize_pkey(der_decrypt_priv,
                                         (long) der_decrypt_priv_size);
  if (decrypt_priv == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error DER decoding EVP_PKEY");
    EVP_PKEY_free(sign_priv);
    X509_free(verify_cert);
    X509_free(encrypt_cert);
    return (int) MSG_TEST_SETUP_ERROR;
  }


  // clean-up
  EVP_PKEY_free(sign_priv);
  X509_free(verify_cert);
  X509_free(encrypt_cert);
  EVP_PKEY_free(decrypt_priv);

  return (int) ret;
}