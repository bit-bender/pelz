#ifndef _ENCLAVE_HELPER_FUNCIONS_H_
#define _ENCLAVE_HELPER_FUNCTIONS_H_

typedef enum
{
  END_TO_END,
  ASN1_CREATE_FUNCTIONALITY,
  ASN1_PARSE_NULL_MSG_IN,
  ASN1_PARSE_INVALID_MSG_TYPE_TAG,
  ASN1_PARSE_INVALID_MSG_TYPE_LO,
  ASN1_PARSE_INVALID_MSG_TYPE_HI,
  ASN1_PARSE_INVALID_REQ_TYPE_TAG,
  ASN1_PARSE_INVALID_REQ_TYPE_LO,
  ASN1_PARSE_INVALID_REQ_TYPE_HI,
  ASN1_PARSE_INVALID_CIPHER_TAG,
  ASN1_PARSE_INVALID_KEY_ID_TAG,
  ASN1_PARSE_INVALID_DATA_TAG,
  ASN1_PARSE_INVALID_STATUS_TAG,
  ASN1_PARSE_FUNCTIONALITY,
  ASN1_DER_ENCODE_NULL_MSG_IN,
  ASN1_DER_ENCODE_NULL_BUF_OUT,
  ASN1_DER_ENCODE_FUNCTIONALITY,
  ASN1_DER_DECODE_NULL_BUF_IN,
  ASN1_DER_DECODE_EMPTY_BUF_IN,
  ASN1_DER_DECODE_INVALID_SIZE_BUF_IN,
  ASN1_DER_DECODE_FUNCTIONALITY,
  CMS_CREATE_SIGNED_MSG_NULL_BUF_IN,
  CMS_CREATE_SIGNED_MSG_EMPTY_BUF_IN,
  CMS_CREATE_SIGNED_MSG_INVALID_SIZE_BUF_IN,
  CMS_CREATE_SIGNED_MSG_NULL_CERT_IN,
  CMS_CREATE_SIGNED_MSG_NULL_PRIV_IN,
  CMS_CREATE_SIGNED_MSG_FUNCTIONALITY,
  CMS_VERIFY_SIGNED_MSG_NULL_MSG_IN,
  CMS_VERIFY_SIGNED_MSG_NULL_CERT_OUT,
  CMS_VERIFY_SIGNED_MSG_NULL_BUF_OUT,
  CMS_VERIFY_SIGNED_MSG_FUNCTIONALITY,
  CMS_DER_ENCODE_NULL_MSG_IN,
  CMS_DER_ENCODE_NULL_BUF_OUT,
  CMS_DER_ENCODE_FUNCTIONALITY,
  CMS_DER_DECODE_NULL_BUF_IN,
  CMS_DER_DECODE_EMPTY_BUF_IN,
  CMS_DER_DECODE_INVALID_SIZE_BUF_IN,
  CMS_DER_DECODE_FUNCTIONALITY,
} MsgTestSelect;


// test_construct_deconstruct_pelz_msg_helper() test select options
#define CONSTRUCT_DECONSTRUCT_PELZ_MSG_BASIC_TEST              0x01
#define CONSTRUCT_PELZ_MSG_NULL_MSG_IN_TEST                    0x02
#define CONSTRUCT_PELZ_MSG_NULL_LOCAL_CERT_TEST                0x03
#define CONSTRUCT_PELZ_MSG_NULL_LOCAL_PRIV_TEST                0x04
#define CONSTRUCT_PELZ_MSG_NULL_PEER_CERT_TEST                 0x05
#define CONSTRUCT_PELZ_MSG_NULL_OUT_BUF_TEST                   0x06
#define DECONSTRUCT_PELZ_MSG_NULL_MSG_IN_TEST                  0x07
#define DECONSTRUCT_PELZ_MSG_NULL_LOCAL_CERT_TEST              0x08
#define DECONSTRUCT_PELZ_MSG_NULL_LOCAL_PRIV_TEST              0x09
#define DECONSTRUCT_PELZ_MSG_NULL_PEER_CERT_TEST               0x0A
#define DECONSTRUCT_PELZ_MSG_PREALLOC_PEER_CERT_TEST           0x0B
#define SERVICE_PELZ_REQ_MSG_BASIC_TEST                        0x0C
#define SERVICE_PELZ_REQ_MSG_NULL_REQ_MSG_IN_TEST              0x0D
#define SERVICE_PELZ_REQ_MSG_NULL_RESP_MSG_OUT_TEST            0x0E

typedef enum
{
  MSG_TEST_OK = 0,
  MSG_TEST_UNKNOWN_ERROR = -1,
  MSG_TEST_INVALID_TEST_PARAMETER = -2,
  MSG_TEST_INVALID_TEST_SELECTION = -3,
  MSG_TEST_SETUP_ERROR = -4,
  MSG_TEST_ASN1_CREATE_ERROR = -5,
  MSG_TEST_ASN1_PARSE_ERROR = -6,
  MSG_TEST_ASN1_CREATE_PARSE_MISMATCH = -7,
  MSG_TEST_DER_ENCODE_RESULT_MISMATCH = -9,
  MSG_TEST_DER_DECODE_RESULT_MISMATCH = -10,
  MSG_TEST_PARAM_HANDLING_OK = -8,
  MSG_TEST_PARAM_HANDLING_ERROR = -9,
  MSG_TEST_PARSE_RESULT_MISMATCH = -10,
  MSG_TEST_SIGN_ERROR = -11,
  MSG_TEST_INVALID_SIGN_RESULT = -12,
  MSG_TEST_ENCRYPT_ERROR = -13,
  MSG_TEST_INVALID_ENCRYPT_RESULT = -13,
  MSG_TEST_INVALID_DECODE_RESULT = -15
} MsgTestStatus;

X509 *deserialize_cert(unsigned char *der_cert, long der_cert_size);
EVP_PKEY *deserialize_pkey(unsigned char *der_pkey, long der_pkey_size);

MsgTestStatus pelz_asn1_msg_test_helper(MsgTestSelect test_select,
                                        PELZ_MSG_DATA test_msg_data_in,
                                        PELZ_MSG *test_msg_out);

MsgTestStatus pelz_asn1_der_encode_decode_test_helper(MsgTestSelect test_select,
                                                      PELZ_MSG *asn1_msg_in,
                                                      charbuf *der_out);

MsgTestStatus pelz_signed_msg_test_helper(MsgTestSelect test_select,
                                          charbuf msg_data_in,
                                          X509 *sign_cert,
                                          EVP_PKEY *verify_priv,
                                          CMS_ContentInfo *signed_msg_out);

MsgTestStatus pelz_cms_der_encode_decode_test_helper(MsgTestSelect test_select,
                                                     CMS_ContentInfo *cms_msg_in,
                                                     charbuf *der_out);

#endif
