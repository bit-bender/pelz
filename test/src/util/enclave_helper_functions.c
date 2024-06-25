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

int test_create_pelz_asn1_msg_helper(uint16_t test_msg_type,
                                     uint16_t test_req_type,
                                     size_t test_key_id_len,
                                     unsigned char * test_key_id,
                                     size_t test_data_len,
                                     unsigned char * test_data,
                                     size_t test_status_len,
                                     unsigned char * test_status)
{
  PELZ_MSG_DATA test_msg_data_in = { .msg_type = test_msg_type,
                                     .req_type = test_req_type,
                                     .key_id = { .chars = test_key_id,
                                                 .len = test_key_id_len },
                                     .data = { .chars = test_data,
                                               .len = test_data_len },
                                     .status = { .chars = test_status,
                                                 .len = test_status_len } };

  PELZ_MSG * test_msg = create_pelz_asn1_msg (&test_msg_data_in);
  if (test_msg == NULL)
  {
    return MSG_TEST_CREATE_ERROR;
  }

  PELZ_MSG_DATA parsed_test_msg_data;

  int ret = parse_pelz_asn1_msg(test_msg, &parsed_test_msg_data);
  if (ret != 0)
  {
    pelz_sgx_log(LOG_ERR, "parse of test message failed");
    return MSG_TEST_SETUP_ERROR;
  }

  if ((parsed_test_msg_data.msg_type != test_msg_data_in.msg_type) ||
      (parsed_test_msg_data.req_type != test_msg_data_in.req_type) ||
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
    pelz_sgx_log(LOG_ERR, "created/parsed message mismatch");
    return MSG_TEST_CREATE_RESULT_MISMATCH;
  }

  return MSG_TEST_SUCCESS;
}

int test_parse_pelz_asn1_msg_helper(uint16_t test_msg_type,
                                    uint16_t test_req_type,
                                    size_t test_key_id_len,
                                    unsigned char * test_key_id,
                                    size_t test_data_len,
                                    unsigned char * test_data,
                                    size_t test_status_len,
                                    unsigned char * test_status,
                                    uint8_t test_select)
{
  // construct baseline PELZ_MSG
  PELZ_MSG_DATA test_msg_data_in = { .msg_type = test_msg_type,
                                     .req_type = test_req_type,
                                     .key_id = { .chars = test_key_id,
                                                 .len = test_key_id_len },
                                     .data = { .chars = test_data,
                                               .len = test_data_len },
                                     .status = { .chars = test_status,
                                                 .len = test_status_len } };

  PELZ_MSG * test_msg = create_pelz_asn1_msg (&test_msg_data_in);
  if (test_msg == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error creating test message to parse");
    return MSG_TEST_SETUP_ERROR;
  }

  uint64_t test_type_val = 0;
  switch(test_select)
  {
  // Basic test parses the test PELZ_MSG as specified (nothing to do here)
  case PARSE_PELZ_MSG_BASIC_TEST:
    break;

  // Test input message with incorrect 'type' tag
  case PARSE_MOD_PELZ_MSG_TYPE_TAG_TEST:
    test_msg->type->type = V_ASN1_ENUMERATED;
    break;

  // Test input message with invalid (too small) 'message type' value
  case PARSE_MOD_PELZ_MSG_MSG_TYPE_VAL_LO_TEST:
    test_type_val = (MSG_TYPE_MIN - 1) << 16;
    test_type_val += REQ_TYPE_MIN;
    if (ASN1_INTEGER_set_uint64(test_msg->type, test_type_val) != 1)
    {
      pelz_sgx_log(LOG_ERR, "error setting test message 'type'");
      return MSG_TEST_SETUP_ERROR;
    }
    break;

  // Test input message with invalid (too large) 'message type' value
  case PARSE_MOD_PELZ_MSG_MSG_TYPE_VAL_HI_TEST:
    test_type_val = (MSG_TYPE_MAX + 1) << 16;
    test_type_val += REQ_TYPE_MIN;
    if (ASN1_INTEGER_set_uint64(test_msg->type, test_type_val) != 1)
    {
      pelz_sgx_log(LOG_ERR, "error setting test message 'type'");
      return MSG_TEST_SETUP_ERROR;
    }
    break;

  // Test input message with invalid (too small) 'request type' value
  case PARSE_MOD_PELZ_MSG_REQ_TYPE_VAL_LO_TEST:
    test_type_val = MSG_TYPE_MIN << 16;
    test_type_val += REQ_TYPE_MIN - 1;
    if (ASN1_INTEGER_set_uint64(test_msg->type, test_type_val) != 1)
    {
      pelz_sgx_log(LOG_ERR, "error setting test message 'type'");
      return MSG_TEST_SETUP_ERROR;
    }
    break;

  // Test input message with invalid (too large) 'request type' value
  case PARSE_MOD_PELZ_MSG_REQ_TYPE_VAL_HI_TEST:
    test_type_val = MSG_TYPE_MIN << 16;
    test_type_val += REQ_TYPE_MAX + 1;
    if (ASN1_INTEGER_set_uint64(test_msg->type, test_type_val) != 1)
    {
      pelz_sgx_log(LOG_ERR, "error setting test message 'type'");
      return MSG_TEST_SETUP_ERROR;
    }
    break;

  // Test input message with incorrect 'key ID' tag
  case PARSE_MOD_PELZ_MSG_KEY_ID_TAG_TEST:
    test_msg->key_id->type = V_ASN1_GENERALSTRING;
    break;

  // Test input message with incorrect 'data' tag
  case PARSE_MOD_PELZ_MSG_DATA_TAG_TEST:
    test_msg->data->type = V_ASN1_UTF8STRING;
    break;

  // Test input message with incorrect 'status' tag
  case PARSE_MOD_PELZ_MSG_STATUS_TAG_TEST:
    test_msg->status->type = V_ASN1_PRINTABLESTRING;
    break;

  // Invalid test selection
  default:
    pelz_sgx_log(LOG_ERR, "invalid test selection");
    return MSG_TEST_SETUP_ERROR;
  }

  // test call to parse_pselz_asn1_msg()
  PELZ_MSG_DATA parsed_test_msg_data;
  int ret = parse_pelz_asn1_msg(test_msg, &parsed_test_msg_data);
  if (ret != PELZ_MSG_SUCCESS)
  {
    // provide error code (offset by MSG_TEST_PARSE_ERROR) to caller
    return MSG_TEST_PARSE_ERROR + ret;
  }

  // if parsed cleanly, check parsed result against the specified input values
  if ((parsed_test_msg_data.msg_type != test_msg_data_in.msg_type) ||
      (parsed_test_msg_data.req_type != test_msg_data_in.req_type) ||
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
    pelz_sgx_log(LOG_ERR, "parse result mismatches test message input");
    return MSG_TEST_PARSE_RESULT_MISMATCH;
  }

  return MSG_TEST_SUCCESS;
}


int test_der_encode_pelz_msg_helper(uint16_t test_msg_type,
                                    uint16_t test_req_type,
                                    size_t test_key_id_len,
                                    unsigned char * test_key_id,
                                    size_t test_data_len,
                                    unsigned char * test_data,
                                    size_t test_status_len,
                                    unsigned char * test_status,
                                    uint8_t test_select)
{
  PELZ_MSG_DATA test_msg_data_in = { .msg_type = test_msg_type,
                                     .req_type = test_req_type,
                                     .key_id = { .chars = test_key_id,
                                                 .len = test_key_id_len },
                                     .data = { .chars = test_data,
                                               .len = test_data_len },
                                     .status = { .chars = test_status,
                                                 .len = test_status_len } };

  int retval = -1;
  int index = 0;
  int verify_type_num_bytes = -1;
  int verify_type_byte_index = -1;
  uint64_t verify_type = 0;

  PELZ_MSG *test_msg = NULL;
  unsigned char *der_test_msg = NULL;
  int der_test_msg_len = -1;
  CMS_ContentInfo *cms_test_msg = NULL;
  uint8_t *der_cms_test_msg = NULL;

  // create input data required by the selected test
  //   - create test PELZ_MSG for all tests
  //   - create test CMS message to test DER-encode of CMS message
  test_msg = create_pelz_asn1_msg(&test_msg_data_in);
  if (test_msg == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error creating ASN.1 test message");
    return MSG_TEST_SETUP_ERROR;
  }
  if ((test_select == DER_ENCODE_CMS_PELZ_MSG_BASIC_TEST))
  {
    der_test_msg_len = der_encode_pelz_msg((const void *) test_msg,
                                           &der_test_msg,
                                           RAW);
    if ((der_test_msg_len <= 0) || (der_test_msg == NULL))
    {
      pelz_sgx_log(LOG_ERR, "error DER-encoding test ASN.1 message");
      return MSG_TEST_SETUP_ERROR;
    }
    BIO * cms_data_bio = BIO_new(BIO_s_mem());
    retval = BIO_write(cms_data_bio, der_test_msg, der_test_msg_len);
    if (retval != der_test_msg_len)
    {
      pelz_sgx_log(LOG_ERR, "BIO write error: CMS test message payload");
      BIO_free(cms_data_bio);
      return MSG_TEST_SETUP_ERROR;
    }
    cms_test_msg = CMS_data_create(cms_data_bio, CMS_BINARY);
    BIO_free(cms_data_bio);
    if (cms_test_msg == NULL)
    {
      pelz_sgx_log(LOG_ERR, "error creating CMS test message");
      return MSG_TEST_SETUP_ERROR;
    }
  }

  // perform test specified by the input 'test_select' test option parameter
  switch (test_select)
  {
  // Basic test: verify DER-encoding of caller specified PELZ_MSG is correct
  case DER_ENCODE_RAW_PELZ_MSG_BASIC_TEST:
    der_test_msg_len = der_encode_pelz_msg((const void *) test_msg,
                                           &der_test_msg,
                                           RAW);
    if ((der_test_msg_len <= 0) || (der_test_msg == NULL))
    {
      return (MSG_TEST_DER_ENCODE_ERROR + retval);
    }

    // DER encodes in a type-length-value format, so first byte is
    // the 'type' byte for the encoded PELZ_MSG sequence:
    //  - two MSBs represent class, both bits should be clear (Universal)
    //  - next MSB should be set as sequence is a 'constructed' value
    //  - five LSBs should contain tag (SEQUENCE = 16 or 0x10)
    if (der_test_msg[index++] != 0x30)
    {
      pelz_sgx_log(LOG_ERR, "DER-encode (raw) mismatch - sequence tag");
      return MSG_TEST_DER_ENCODE_RESULT_MISMATCH;
    }
    // second byte represents the sequence length (i.e., 2 bytes less
    // than the encoded length returned in retval, as first two bytes
    // are not included in this length value)
    if (der_test_msg[index++] != (der_test_msg_len - 2))
    {
      pelz_sgx_log(LOG_ERR, "DER-encode (raw) mismatch - sequence length");
      return MSG_TEST_DER_ENCODE_RESULT_MISMATCH;
    }
    // third byte represents the type for the first element in the
    // PELZ_MSG sequence (the msg/request type integer)
    if (der_test_msg[index++] != V_ASN1_INTEGER)
    {
      pelz_sgx_log(LOG_ERR, "DER-encode (raw) mismatch - 'type' tag");
      return MSG_TEST_DER_ENCODE_RESULT_MISMATCH;
    }
    // fourth byte represents the length of the encoded 'type' integer
    // 'type' integer value byte(s) then follow
    verify_type_num_bytes = der_test_msg[index++];
    if (verify_type_byte_index > 8)
    {
      pelz_sgx_log(LOG_ERR, "DER-encode (raw) invalid - 'type' length");
      return MSG_TEST_DER_ENCODE_RESULT_MISMATCH;
    }
    // next verify_type_num_bytes should represent 'type' integer
    verify_type_byte_index = verify_type_num_bytes - 1;
    while (verify_type_byte_index >= 0)
    {
      verify_type += der_test_msg[index++] << (verify_type_byte_index * 8);
      verify_type_byte_index--;
    }
    if ((int) verify_type != ((test_msg_data_in.msg_type << 16) +
                              (test_msg_data_in.req_type)))
    {
      pelz_sgx_log(LOG_ERR, "DER-encode (raw) mismatch - 'type' value");
      return MSG_TEST_DER_ENCODE_RESULT_MISMATCH;
    }
    // will assume correct encoding if no mismatch this far into message ...
    return MSG_TEST_SUCCESS;
    break;

  case DER_ENCODE_CMS_PELZ_MSG_BASIC_TEST:
    retval = der_encode_pelz_msg((const void *) cms_test_msg,
                                 &der_cms_test_msg,
                                 CMS);
    if ((retval <= 0) || (der_test_msg == NULL))
    {
      return (MSG_TEST_DER_ENCODE_ERROR + retval);
    }
    // DER encodes in a type-length-value format, so first byte is
    // the 'type' byte for the encoded CMS, PELZ_MSG sequence:
    //  - two MSBs represent class, both bits should be clear (Universal)
    //  - next MSB should be set as a 'constructed' value
    //  - five LSBs should contain tag (SEQUENCE = 16 or 0x10)
    if (der_cms_test_msg[index++] != 0x30)
    {
      pelz_sgx_log(LOG_ERR, "DER-encode (cms) mismatch - message tag");
      return MSG_TEST_DER_ENCODE_RESULT_MISMATCH;
    }
    // second byte represents the sequence length (i.e., 2 bytes less
    // than the encoded length returned in retval, as first two bytes
    // are not included in this length value)
    if (der_cms_test_msg[index++] != (retval - 2))
    {
      pelz_sgx_log(LOG_ERR, "DER-encode (cms) mismatch - message length");
      return MSG_TEST_DER_ENCODE_RESULT_MISMATCH;
    }
    // third byte represents the type for the first element in the
    // CMS encoded PELZ_MSG sequence, which should be the object
    // identifier (OID)
    if (der_cms_test_msg[index++] != V_ASN1_OBJECT)
    {
      pelz_sgx_log(LOG_ERR, "DER-encode (cms) mismatch - OID tag");
      return MSG_TEST_DER_ENCODE_RESULT_MISMATCH;
    }
    // the sequence should end in the DER-encoded PELZ_MSG payload
    index = retval - der_test_msg_len;
    for (int i = 0; i < der_test_msg_len; i++)
    {
      if (der_cms_test_msg[index + i] != der_test_msg[i])
      {
        pelz_sgx_log(LOG_ERR, "DER-encode (cms) mismatch - PELZ_MSG payload");
        return MSG_TEST_DER_ENCODE_RESULT_MISMATCH;
      }
    }
    return MSG_TEST_SUCCESS;
    break;

  // Check that NULL 'msg_in' input parameter is handled correctly
  case DER_ENCODE_PELZ_MSG_NULL_MSG_IN_TEST:
    retval = der_encode_pelz_msg(NULL,
                                 &der_test_msg,
                                 RAW);
    if (retval != PELZ_MSG_PARAM_INVALID)
    {
        pelz_sgx_log(LOG_ERR, "error handling NULL 'msg_in' input parameter");
        return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // Check that NULL pointer to pointer to output buffer is handled correctly
  case DER_ENCODE_PELZ_MSG_NULL_OUT_BUF_TEST:
    retval = der_encode_pelz_msg((const void *) test_msg,
                                 NULL,
                                 RAW);
    if (retval != PELZ_MSG_PARAM_INVALID)
    {
        pelz_sgx_log(LOG_ERR, "error handling NULL output buffer parameter");
        return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // invalid test selection
  default:
    pelz_sgx_log(LOG_ERR, "invalid test selection");
    return MSG_TEST_SETUP_ERROR;
  }

  // should never reach this statement
  return MSG_TEST_UNKNOWN_ERROR;
}

int test_der_decode_pelz_msg_helper(uint16_t test_msg_type,
                                    uint16_t test_req_type,
                                    size_t test_key_id_len,
                                    unsigned char * test_key_id,
                                    size_t test_data_len,
                                    unsigned char * test_data,
                                    size_t test_status_len,
                                    unsigned char * test_status,
                                    uint8_t test_select)
{
  PELZ_MSG_DATA test_msg_data_in = { .msg_type = test_msg_type,
                                     .req_type = test_req_type,
                                     .key_id = { .chars = test_key_id,
                                                 .len = test_key_id_len },
                                     .data = { .chars = test_data,
                                               .len = test_data_len },
                                     .status = { .chars = test_status,
                                                 .len = test_status_len } };

  PELZ_MSG *test_msg = NULL;
  unsigned char *der_test_msg = NULL;
  int der_test_msg_len = -1;
  CMS_ContentInfo *cms_test_msg = NULL;
  unsigned char *der_cms_test_msg = NULL;
  int der_cms_test_msg_len = -1;

  PELZ_MSG *decoded_test_msg = NULL;
  CMS_ContentInfo *decoded_cms_msg = NULL;

  PELZ_MSG_DATA parsed_decoded_test_msg_data;
  ASN1_OCTET_STRING **input_cms_msg_payload = NULL;
  ASN1_OCTET_STRING **decoded_cms_msg_payload = NULL;

  int ret = -1;

  // create test input based on caller input as requred by test selection
  //   - create and DER-encode test PELZ_MSG for all tests
  //   - create and DER-encode CMS formatted PELZ_MSG test message
  //     for test of DER-decode for CMS formatted messages
  test_msg = create_pelz_asn1_msg (&test_msg_data_in);
  if (test_msg == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error creating ASN.1 test message");
    return MSG_TEST_SETUP_ERROR;
  }
  der_test_msg_len = der_encode_pelz_msg((const void *) test_msg,
                                         &der_test_msg,
                                         RAW);
  if ((der_test_msg_len <= 0) || (der_test_msg == NULL))
  {
    pelz_sgx_log(LOG_ERR, "error DER-encoding ASN.1 test message");
    return MSG_TEST_SETUP_ERROR;
  }

  if ((test_select == DER_DECODE_CMS_PELZ_MSG_BASIC_TEST))
  {
    BIO * cms_data_bio = BIO_new(BIO_s_mem());
    ret = BIO_write(cms_data_bio, der_test_msg, der_test_msg_len);
    if (ret != der_test_msg_len)
    {
      pelz_sgx_log(LOG_ERR, "BIO write error: CMS test message payload");
      BIO_free(cms_data_bio);
      return MSG_TEST_SETUP_ERROR;
    }
    cms_test_msg = CMS_data_create(cms_data_bio, CMS_BINARY);
    BIO_free(cms_data_bio);
    if (cms_test_msg == NULL)
    {
      pelz_sgx_log(LOG_ERR, "error creating CMS test message");
      return MSG_TEST_SETUP_ERROR;
    }
    der_cms_test_msg_len = der_encode_pelz_msg((const void *) cms_test_msg,
                                               &der_cms_test_msg,
                                               CMS);
    if ((der_cms_test_msg_len <= 0) || (der_cms_test_msg == NULL))
    {
      pelz_sgx_log(LOG_ERR, "error DER-encoding CMS test message");
      return MSG_TEST_SETUP_ERROR;
    }
  }

  // test handling of invalid parameters (if caller selects this type of test)
  switch (test_select)
  {
  case DER_DECODE_RAW_PELZ_MSG_BASIC_TEST:
    decoded_test_msg = der_decode_pelz_msg(der_test_msg, der_test_msg_len, RAW);
    if (decoded_test_msg == NULL)
    {
      return MSG_TEST_DER_DECODE_ERROR;
    }
    ret = parse_pelz_asn1_msg(decoded_test_msg, &parsed_decoded_test_msg_data);
    if (ret != PELZ_MSG_SUCCESS)
    {
      pelz_sgx_log(LOG_ERR, "error parsing DER-decoded ASN.1 test message");
      return MSG_TEST_SETUP_ERROR;
    }
    if ((parsed_decoded_test_msg_data.msg_type != test_msg_data_in.msg_type) ||
        (parsed_decoded_test_msg_data.req_type != test_msg_data_in.req_type) ||
        (memcmp(parsed_decoded_test_msg_data.key_id.chars,
                test_msg_data_in.key_id.chars,
                test_msg_data_in.key_id.len) != 0) ||
        (memcmp(parsed_decoded_test_msg_data.data.chars,
                test_msg_data_in.data.chars,
                test_msg_data_in.data.len) != 0) ||
        (memcmp(parsed_decoded_test_msg_data.status.chars,
                test_msg_data_in.status.chars,
                test_msg_data_in.status.len) != 0))
    {
      pelz_sgx_log(LOG_ERR, "DER-decoded ASN.1 test message mismatch");
      return MSG_TEST_DER_DECODE_RESULT_MISMATCH;
    }
    return MSG_TEST_SUCCESS;
    break;

  case DER_DECODE_CMS_PELZ_MSG_BASIC_TEST:
    decoded_cms_msg = der_decode_pelz_msg(der_cms_test_msg, der_cms_test_msg_len, CMS);
    if (decoded_cms_msg == NULL)
    {
      return MSG_TEST_DER_DECODE_ERROR;
    }
    decoded_cms_msg_payload = CMS_get0_content(decoded_cms_msg);
    input_cms_msg_payload = CMS_get0_content(cms_test_msg);
    if (ASN1_OCTET_STRING_cmp(*decoded_cms_msg_payload,
                              *input_cms_msg_payload) != 0)
    {
      pelz_sgx_log(LOG_ERR, "DER-decoded CMS message mismatch");
      return MSG_TEST_DER_DECODE_RESULT_MISMATCH;
    }
    return MSG_TEST_SUCCESS;
    break;

  case DER_DECODE_PELZ_MSG_NULL_BYTES_IN_TEST:
    decoded_test_msg = der_decode_pelz_msg(NULL, der_test_msg_len, RAW);
    if (decoded_test_msg != NULL)
    {
      pelz_sgx_log(LOG_ERR, "error handling NULL 'bytes_in' input parameter");
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  case DER_DECODE_PELZ_MSG_EMPTY_BYTES_IN_TEST:
    decoded_test_msg = der_decode_pelz_msg(der_test_msg, 0, RAW);
    if (decoded_test_msg != NULL)
    {
      pelz_sgx_log(LOG_ERR, "error handling empty 'bytes_in' input parameter");
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  case DER_DECODE_PELZ_MSG_NEG_BYTES_IN_LEN_TEST:
    decoded_test_msg = der_decode_pelz_msg(der_test_msg, -1, RAW);
    if (decoded_test_msg != NULL)
    {
      pelz_sgx_log(LOG_ERR, "error handling 'bytes_in' with negative length");
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
    break;

  // invalid test selection
  default:
    pelz_sgx_log(LOG_ERR, "invalid test selection");
    return MSG_TEST_SETUP_ERROR;
  }

  // should never reach this
  return MSG_TEST_UNKNOWN_ERROR;
}

int test_create_signed_data_msg_helper(size_t test_data_in_len,
                                       uint8_t *test_data_in,
                                       size_t test_der_sign_cert_len,
                                       const uint8_t *test_der_sign_cert,
                                       size_t test_der_sign_priv_len,
                                       const uint8_t *test_der_sign_priv)
{
  // convert input DER-formatted key/cert byte arrays to internal format
  X509 *test_cert = NULL;
  if ((test_der_sign_cert != NULL) && (test_der_sign_cert_len != 0))
  {
    d2i_X509(&test_cert, &test_der_sign_cert, (int) test_der_sign_cert_len);
  }
  EVP_PKEY *test_priv = NULL;
  if ((test_der_sign_priv != NULL) && (test_der_sign_priv_len != 0))
  {
    d2i_PrivateKey(EVP_PKEY_EC,
                   &test_priv,
                   &test_der_sign_priv,
                   (int) test_der_sign_priv_len);
  }

  // if input parameters result in NULL cert and/or key,
  // test that these invalid parameter cases are properly handled
  if ((test_cert == NULL) || (test_priv == NULL))
  {
    CMS_ContentInfo *null_key_cert_msg = NULL;
    null_key_cert_msg = create_signed_data_msg((uint8_t *) "test data",
                                               9,
                                               test_cert,
                                               test_priv);
    if (null_key_cert_msg != NULL)
    {
        return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
  }

  CMS_ContentInfo *signed_msg = NULL;
  signed_msg = create_signed_data_msg(test_data_in,
                                      (int) test_data_in_len,
                                      test_cert,
                                      test_priv);

  if (signed_msg == NULL)
  {
    return MSG_TEST_SIGN_FAILURE;
  }

  if (OBJ_obj2nid(CMS_get0_type(signed_msg)) != NID_pkcs7_signed)
  {
    return MSG_TEST_INVALID_SIGN_RESULT;
  }

  ASN1_OCTET_STRING *signed_content = NULL;
  signed_content = *(CMS_get0_content(signed_msg));
  if (signed_content == NULL)
  {
    return MSG_TEST_SETUP_ERROR;
  }
  const unsigned char * signed_data = NULL;
  int signed_data_len = ASN1_STRING_length((const ASN1_STRING *) signed_content);
  signed_data = ASN1_STRING_get0_data((const ASN1_STRING *) signed_content);
  if ((signed_data == NULL) || (signed_data_len <= 0))
  {
    return MSG_TEST_SETUP_ERROR;
  }
  if ((signed_data_len != (int) test_data_in_len) ||
      (memcmp(test_data_in, signed_data, test_data_in_len) != 0))
  {
    return MSG_TEST_INVALID_SIGN_RESULT;
  }

  return MSG_TEST_SUCCESS;

}

int test_verify_signature_helper(size_t test_data_in_len,
                                 uint8_t *test_data_in,
                                 size_t test_der_sign_cert_len,
                                 const uint8_t *test_der_sign_cert,
                                 size_t test_der_sign_priv_len,
                                 const uint8_t *test_der_sign_priv,
                                 size_t test_der_ca_cert_len,
                                 const uint8_t *test_der_ca_cert)
{
  uint8_t *verify_data = NULL;
  int verify_data_len = -1;

  // convert input DER-formatted signing key byte array to internal format
  // need this to create signed test message
  EVP_PKEY *test_msg_priv = NULL;
  if ((test_der_sign_priv != NULL) && (test_der_sign_priv_len != 0))
  {
    d2i_PrivateKey(EVP_PKEY_EC,
                   &test_msg_priv,
                   &test_der_sign_priv,
                   (int) test_der_sign_priv_len);
  }
  if (test_msg_priv == NULL)
  {
    return MSG_TEST_SETUP_ERROR;
  }

  // convert input DER-formatted sign cert byte array to internal format
  // need this to created signed test message
  X509 *test_msg_cert = NULL;
  if ((test_der_sign_cert != NULL) && (test_der_sign_cert_len != 0))
  {
    d2i_X509(&test_msg_cert, &test_der_sign_cert, (int) test_der_sign_cert_len);
  }
  if (test_msg_cert == NULL)
  {
    return MSG_TEST_SETUP_ERROR;
  }

  // convert input DER-formatted CA cert byte array to internal format
  // if result is NULL cert, perform NULL cert parameter test
  X509 *test_ca_cert = NULL;
  if ((test_der_ca_cert != NULL) && (test_der_ca_cert_len != 0))
  {
    d2i_X509(&test_ca_cert, &test_der_ca_cert, (int) test_der_ca_cert_len);
  }

  // if test_data input is null or empty, perform null input msg test
  // and output buffer tests
  if ((test_data_in == NULL) || (test_data_in_len == 0))
  {

    verify_data_len = verify_signature(NULL,
                                       test_ca_cert,
                                       &verify_data);
    if (verify_data_len != PELZ_MSG_PARAM_INVALID)
    {
      return MSG_TEST_PARAM_HANDLING_ERROR;
    }
    return MSG_TEST_PARAM_HANDLING_OK;
  }

  // create signed test message
  CMS_ContentInfo *test_signed_msg = create_signed_data_msg(test_data_in,
                                                            (int) test_data_in_len,
                                                            test_msg_cert,
                                                            test_msg_priv);
  if (test_signed_msg == NULL)
  {
    return MSG_TEST_SETUP_ERROR;
  }

  // if CA cert is NULL, perform invalid parameter tests
  if (test_ca_cert == NULL)
  {
    int temp_result = MSG_TEST_PARAM_HANDLING_OK;

    // first test is that NULL CA cert returns invalid parameter error
    verify_data_len = verify_signature(test_signed_msg,
                                       NULL,
                                       &verify_data);
    if (verify_data_len != PELZ_MSG_PARAM_INVALID)
    {
      temp_result = MSG_TEST_PARAM_HANDLING_ERROR;
    }

    verify_data_len = verify_signature(test_signed_msg,
                                       test_ca_cert,
                                       NULL);
    if (verify_data_len != PELZ_MSG_PARAM_INVALID)
    {
      temp_result = MSG_TEST_PARAM_HANDLING_ERROR;
    }

    // second test is that NULL output data buffer double pointer errors
    verify_data_len = verify_signature(test_signed_msg,
                                       test_ca_cert,
                                       NULL);
    if (verify_data_len != PELZ_MSG_PARAM_INVALID)
    {
      temp_result = MSG_TEST_PARAM_HANDLING_ERROR;
    }

    // third test is that pre-allocated output buffer parameter returns error
    uint8_t * test_buf = malloc(1);
    uint8_t ** test_buf_ptr = &test_buf;
    verify_data_len = verify_signature(test_signed_msg,
                                       test_ca_cert,
                                       test_buf_ptr);
    if (verify_data_len != PELZ_MSG_PARAM_INVALID)
    {
      temp_result = MSG_TEST_PARAM_HANDLING_ERROR;
    }
    free(test_buf);

    return temp_result;
  }

  // perform signature verification test
  verify_data_len = verify_signature(test_signed_msg,
                                     test_ca_cert,
                                     &verify_data);
  if ((verify_data_len != (int) test_data_in_len) ||
      (memcmp(test_data_in, verify_data, test_data_in_len) != 0))
  {
    return MSG_TEST_VERIFY_FAILURE;
  }

  return MSG_TEST_SUCCESS;
}
