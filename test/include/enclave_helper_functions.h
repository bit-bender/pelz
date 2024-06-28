#ifndef _ENCLAVE_HELPER_FUNCIONS_H_
#define _ENCLAVE_HELPER_FUNCTIONS_H_

// test_der_encode_pelz_asn1_msg_helper() test select options
#define DER_ENCODE_ASN1_PELZ_MSG_BASIC_TEST               0x01
#define DER_ENCODE_CMS_PELZ_MSG_BASIC_TEST                0x02
#define DER_ENCODE_PELZ_MSG_NULL_MSG_IN_TEST              0x03
#define DER_ENCODE_PELZ_MSG_NULL_OUT_BUF_TEST             0x04

// test_der_decode_pelz_asn1_msg_helper() test select options
#define DER_DECODE_ASN1_PELZ_MSG_BASIC_TEST               0x01
#define DER_DECODE_CMS_PELZ_MSG_BASIC_TEST                0x02
#define DER_DECODE_PELZ_MSG_NULL_BYTES_IN_TEST            0x03
#define DER_DECODE_PELZ_MSG_EMPTY_BYTES_IN_TEST           0x04
#define DER_DECODE_PELZ_MSG_NEG_BYTES_IN_LEN_TEST         0x05

// test_parse_pelz_asn1_msg_helper() test select options
#define PARSE_PELZ_MSG_BASIC_TEST                         0x01
#define PARSE_MOD_PELZ_MSG_MSG_TYPE_TAG_TEST              0x02
#define PARSE_MOD_PELZ_MSG_MSG_TYPE_VAL_LO_TEST           0x03
#define PARSE_MOD_PELZ_MSG_MSG_TYPE_VAL_HI_TEST           0x04
#define PARSE_MOD_PELZ_MSG_REQ_TYPE_TAG_TEST              0x05
#define PARSE_MOD_PELZ_MSG_REQ_TYPE_VAL_LO_TEST           0x06
#define PARSE_MOD_PELZ_MSG_REQ_TYPE_VAL_HI_TEST           0x07
#define PARSE_MOD_PELZ_MSG_CIPHER_TAG_TEST                0x08
#define PARSE_MOD_PELZ_MSG_KEY_ID_TAG_TEST                0x09
#define PARSE_MOD_PELZ_MSG_DATA_TAG_TEST                  0x0A
#define PARSE_MOD_PELZ_MSG_STATUS_TAG_TEST                0x0B

#define MSG_TEST_SUCCESS 0

// helper detected pelz messaging test errors
#define MSG_TEST_UNKNOWN_ERROR                              -1
#define MSG_TEST_SETUP_ERROR                                -2
#define MSG_TEST_CREATE_RESULT_MISMATCH                     -3
#define MSG_TEST_DER_ENCODE_RESULT_MISMATCH                 -4
#define MSG_TEST_DER_DECODE_RESULT_MISMATCH                 -5
#define MSG_TEST_PARAM_HANDLING_OK                          -6
#define MSG_TEST_PARAM_HANDLING_ERROR                       -7
#define MSG_TEST_PARSE_RESULT_MISMATCH                      -8
#define MSG_TEST_INVALID_SIGN_RESULT                        -9
#define MSG_TEST_INVALID_ENCRYPT_RESULT                    -10

// pelz messaging test error "categories"
// (this value is used as a offset added to the
// error code returned by the function being tested)
#define MSG_TEST_CREATE_ERROR                             -128
#define MSG_TEST_PARSE_ERROR                              -256
#define MSG_TEST_DER_ENCODE_ERROR                         -384
#define MSG_TEST_DER_DECODE_ERROR                         -512
#define MSG_TEST_SIGN_ERROR                               -640
#define MSG_TEST_VERIFY_ERROR                             -768
#define MSG_TEST_ENCRYPT_ERROR                            -896
#define MSG_TEST_DECRYPT_ERROR                           -1024

#endif
