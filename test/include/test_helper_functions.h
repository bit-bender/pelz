/*
 * test_helper_functions.h
 */

#ifndef TEST_HELPER_FUNCTIONS_H_
#define TEST_HELPER_FUNCTIONS_H_

#include <unistd.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "charbuf.h"
#include "pelz_log.h"

typedef enum
{
  NULL_TEST,
  ASN1_CREATE_FUNCTIONALITY,
  ASN1_CREATE_DER_ENCODE_NULL_MSG_IN,
  ASN1_CREATE_DER_ENCODE_NULL_BUF_OUT,
  ASN1_CREATE_DER_ENCODE_FUNCTIONALITY,
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
  ASN1_PARSE_DER_DECODE_NULL_BUF_IN,
  ASN1_PARSE_DER_DECODE_EMPTY_BUF_IN,
  ASN1_PARSE_DER_DECODE_INVALID_FORMAT,
  ASN1_PARSE_DER_DECODE_FUNCTIONALITY,
  CMS_SIGN_NULL_BUF_IN,
  CMS_SIGN_EMPTY_BUF_IN,
  CMS_SIGN_INVALID_SIZE_BUF_IN,
  CMS_SIGN_NULL_CERT_IN,
  CMS_SIGN_NULL_PRIV_IN,
  CMS_SIGN_FUNCTIONALITY,
  CMS_SIGN_DER_ENCODE_NULL_MSG_IN,
  CMS_SIGN_DER_ENCODE_NULL_BUF_OUT,
  CMS_SIGN_DER_ENCODE_FUNCTIONALITY,
  CMS_VERIFY_NULL_MSG_IN,
  CMS_VERIFY_NULL_CERT_OUT,
  CMS_VERIFY_NULL_BUF_OUT,
  CMS_VERIFY_FUNCTIONALITY,
  CMS_VERIFY_DER_DECODE_NULL_BUF_IN,
  CMS_VERIFY_DECODE_EMPTY_BUF_IN,
  CMS_VERIFY_DER_DECODE_INVALID_FORMAT,
  CMS_VERIFY_DER_DECODE_FUNCTIONALITY,
  CMS_ENCRYPT_NULL_BUF_IN,
  CMS_ENCRYPT_EMPTY_BUF_IN,
  CMS_ENCRYPT_INVALID_SIZE_BUF_IN,
  CMS_ENCRYPT_NULL_CERT_IN,
  CMS_ENCRYPT_FUNCTIONALITY,
  CMS_ENCRYPT_DER_ENCODE_NULL_MSG_IN,
  CMS_ENCRYPT_DER_ENCODE_NULL_BUF_OUT,
  CMS_ENCRYPT_DER_ENCODE_FUNCTIONALITY,
  CMS_DECRYPT_NULL_MSG_IN,
  CMS_DECRYPT_NULL_CERT,
  CMS_DECRYPT_NULL_PRIV,
  CMS_DECRYPT_NULL_BUF_OUT,
  CMS_DECRYPT_FUNCTIONALITY,
  CMS_DECRYPT_DER_DECODE_NULL_BUF_IN,
  CMS_DECRYPT_DECODE_EMPTY_BUF_IN,
  CMS_DECRYPT_DER_DECODE_INVALID_FORMAT,
  CMS_DECRYPT_DER_DECODE_FUNCTIONALITY,
  CONSTRUCT_NULL_MSG_DATA_IN,
  CONSTRUCT_NULL_CERT,
  CONSTRUCT_NULL_PRIV,
  CONSTRUCT_NULL_PEER_CERT,
  CONSTRUCT_NULL_BUF_OUT,
  CONSTRUCT_FUNCTIONALITY,
  DECONSTRUCT_NULL_MSG_IN,
  DECONSTRUCT_EMPTY_MSG_IN,
  DECONSTRUCT_INVALID_SIZE_MSG_IN,
  DECONSTRUCT_NULL_CERT,
  DECONSTRUCT_NULL_PRIV,
  DECONSTRUCT_NULL_PEER_CERT_OUT,
  DECONSTRUCT_NULL_MSG_DATA_OUT,
  DECONSTRUCT_FUNCTIONALITY,
  PELZ_MSG_END_TO_END,
} MsgTestSelect;

typedef enum
{
  MSG_TEST_OK = 0,
  MSG_TEST_UNKNOWN_ERROR = -1,
  MSG_TEST_INVALID_TEST_PARAMETER = -2,
  MSG_TEST_INVALID_TEST_SELECTION = -3,
  MSG_TEST_SETUP_ERROR = -4,
  MSG_TEST_PARAM_HANDLING_OK = -5,
  MSG_TEST_PARAM_HANDLING_ERROR = -6,
  MSG_TEST_ASN1_CREATE_ERROR = -7,
  MSG_TEST_ASN1_PARSE_ERROR = -8,
  MSG_TEST_ASN1_CREATE_PARSE_MISMATCH = -9,
  MSG_TEST_ASN1_DER_ENCODE_ERROR = -10,
  MSG_TEST_ASN1_DER_ENCODE_RESULT_MISMATCH = -11,
  MSG_TEST_ASN1_DER_DECODE_ERROR = -12,
  MSG_TEST_ASN1_DER_DECODE_RESULT_MISMATCH = -13,
  MSG_TEST_SIGN_ERROR = -14,
  MSG_TEST_SIGN_INVALID_RESULT = -15,
  MSG_TEST_VERIFY_ERROR = -16,
  MSG_TEST_VERIFY_INVALID_RESULT = -17,
  MSG_TEST_CMS_DER_ENCODE_ERROR = -18,
  MSG_TEST_CMS_DER_ENCODE_RESULT_MISMATCH = -19,
  MSG_TEST_CMS_DER_DECODE_ERROR = -20,
  MSG_TEST_CMS_DER_DECODE_RESULT_MISMATCH = -21,
  MSG_TEST_ENCRYPT_ERROR = -22,
  MSG_TEST_ENCRYPT_INVALID_RESULT = -23,
  MSG_TEST_DECRYPT_ERROR = 24,
  MSG_TEST_DECRYPT_INVALID_RESULT = -25,
  MSG_TEST_CONSTRUCT_ERROR = -26,
  MSG_TEST_CONSTRUCT_INVALID_RESULT = -27,
  MSG_TEST_DECONSTRUCT_ERROR = -28,
  MSG_TEST_DECONSTRUCT_INVALID_RESULT = -29
} MsgTestStatus;

/**
 * <pre>
 * This function creates a new charbuf that contains the contents of two
 * character strings
 * </pre>
 *
 * @param[in]  prefix     The character string of the key_id without current
 *                        working directory prefix (schema notation)
 *
 * @param[in]  postfix    The character string of the key_id with current
 *                        working directory postfix (file path)
 *
 * @return                charbuf copy of key_id with current working directory
 */
charbuf copy_CWD_to_id(const char *prefix, const char *postfix);

/**
 * <pre>
 * This function creates a charbuf containing a DER-formatted private
 * key. An EVP_PKEY struct is first created from the contents of a specified
 * PEM formatted file. That EVP_PKEY private key is then DER encoded.
 * </pre>
 *
 * @param[in]  priv_pem_fn   The character string specifying the file name of
 *                           the input PEM-formatted private key file.
 *
 * @param[out] der_priv_out  Pointer to the byte buffer (charbuf) where the
 *                           resultant DER-formatted private key will be placed
 *                           for use by the caller.
 *
 * @return                   zero (0) on success, one (1) on failure
 */
int pem_priv_to_der(char *priv_pem_fn, charbuf *der_priv_out);

/**
 * <pre>
 * This function creates a charbuf containing a DER-formatted certificate.
 * An X509 struct is first created from the contents of a specified
 * PEM formatted file. That X509 certificate is then DER encoded.
 * </pre>
 *
 * @param[in]  cert_pem_fn   The character string specifying the file name of
 *                           the input PEM-formatted certificate file.
 *
 * @param[out] der_cert_out  Pointer to the byte buffer (charbuf) where the
 *                           resultant DER-formatted certificate will be placed
 *                           for use by the caller.
 *
 * @return                   zero (0) on success, one (1) on failure
 */
int pem_cert_to_der(char *cert_pem_fn, charbuf *der_cert_out);

#endif /* TEST_HELPER_FUNCTIONS_H_ */
