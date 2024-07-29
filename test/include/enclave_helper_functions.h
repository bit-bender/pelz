#ifndef _ENCLAVE_HELPER_FUNCIONS_H_
#define _ENCLAVE_HELPER_FUNCTIONS_H_

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

// test_verify_pelz_signed_msg_helper() test select options
#define VERIFY_PELZ_SIGNED_MSG_BASIC_TEST                 0x01
#define VERIFY_PELZ_SIGNED_MSG_NULL_IN_MSG_TEST           0x02
#define VERIFY_PELZ_SIGNED_MSG_NULL_OUT_CERT_TEST         0x03
#define VERIFY_PELZ_SIGNED_MSG_PREALLOC_OUT_CERT_TEST     0x04
#define VERIFY_PELZ_SIGNED_MSG_NULL_OUT_BUF_TEST          0x05
#define VERIFY_PELZ_SIGNED_MSG_PREALLOC_OUT_BUF_TEST      0x06

// test_decrypt_pelz_enveloped_msg_helper() test select options
#define DECRYPT_PELZ_ENVELOPED_MSG_BASIC_TEST             0x01
#define DECRYPT_PELZ_ENVELOPED_MSG_NULL_IN_MSG_TEST       0x02
#define DECRYPT_PELZ_ENVELOPED_MSG_NULL_OUT_BUF_TEST      0x03
#define DECRYPT_PELZ_ENVELOPED_MSG_NULL_CERT_TEST         0x04
#define DECRYPT_PELZ_ENVELOPED_MSG_NULL_PRIV_TEST         0x05

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

// test_construct_deconstruct_pelz_msg_helper() test select options
#define CONSTRUCT_DECONSTRUCT_PELZ_MSG_BASIC_TEST         0x01
#define CONSTRUCT_PELZ_MSG_NULL_MSG_IN_TEST               0x02
#define CONSTRUCT_PELZ_MSG_NULL_LOCAL_CERT_TEST           0x03
#define CONSTRUCT_PELZ_MSG_NULL_LOCAL_PRIV_TEST           0x04
#define CONSTRUCT_PELZ_MSG_NULL_PEER_CERT_TEST            0x05
#define CONSTRUCT_PELZ_MSG_NULL_OUT_BUF_TEST              0x06
#define DECONSTRUCT_PELZ_MSG_NULL_MSG_IN_TEST             0x07
#define DECONSTRUCT_PELZ_MSG_NULL_LOCAL_CERT_TEST         0x08
#define DECONSTRUCT_PELZ_MSG_NULL_LOCAL_PRIV_TEST         0x09
#define DECONSTRUCT_PELZ_MSG_NULL_PEER_CERT_TEST          0x0A
#define DECONSTRUCT_PELZ_MSG_PREALLOC_PEER_CERT_TEST      0x0B

// Normal termination pelz messaging helper 'success' code
#define MSG_TEST_SUCCESS 0

// helper detected pelz messaging test errors
#define MSG_TEST_UNKNOWN_ERROR                              -1
#define MSG_TEST_INVALID_TEST_PARAMETER                     -2
#define MSG_TEST_INVALID_TEST_SELECTION                     -3
#define MSG_TEST_SETUP_ERROR                                -4
#define MSG_TEST_CREATE_RESULT_MISMATCH                     -5
#define MSG_TEST_DER_ENCODE_RESULT_MISMATCH                 -6
#define MSG_TEST_DER_DECODE_RESULT_MISMATCH                 -7
#define MSG_TEST_PARAM_HANDLING_OK                          -8
#define MSG_TEST_PARAM_HANDLING_ERROR                       -9
#define MSG_TEST_PARSE_RESULT_MISMATCH                     -10
#define MSG_TEST_INVALID_SIGN_RESULT                       -11
#define MSG_TEST_INVALID_ENCRYPT_RESULT                    -12
#define MSG_TEST_INVALID_DECODE_RESULT                     -13

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
