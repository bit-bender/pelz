#include <string.h>
#include <stdio.h>

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/cms.h>

#include "pelz_messaging.h"

#include "ca_table.h"
#include "charbuf.h"
#include "common_table.h"
#include "kmyth_enclave_trusted.h"
#include "pelz_enclave.h"
#include "pelz_enclave_log.h"

DECLARE_ASN1_FUNCTIONS(PELZ_MSG);
DECLARE_ASN1_PRINT_FUNCTION(PELZ_MSG);

ASN1_SEQUENCE(PELZ_MSG) = {
  ASN1_SIMPLE(PELZ_MSG, msg_type, ASN1_ENUMERATED),
  ASN1_SIMPLE(PELZ_MSG, req_type, ASN1_ENUMERATED),
  ASN1_SIMPLE(PELZ_MSG, cipher, ASN1_UTF8STRING),
  ASN1_SIMPLE(PELZ_MSG, key_id, ASN1_UTF8STRING),
  ASN1_SIMPLE(PELZ_MSG, data, ASN1_OCTET_STRING),
  ASN1_SIMPLE(PELZ_MSG, status, ASN1_UTF8STRING),
} ASN1_SEQUENCE_END(PELZ_MSG);

IMPLEMENT_ASN1_FUNCTIONS(PELZ_MSG);
IMPLEMENT_ASN1_DUP_FUNCTION(PELZ_MSG);
IMPLEMENT_ASN1_PRINT_FUNCTION(PELZ_MSG);


PELZ_MSG * create_pelz_asn1_msg(PELZ_MSG_DATA * msg_data_in)
{
  // input parameter checks
  if ((msg_data_in->msg_type < MSG_TYPE_MIN) ||
      (msg_data_in->msg_type > MSG_TYPE_MAX))
  {
    pelz_sgx_log(LOG_ERR, "unsupported input message type");
    return NULL;
  }
  if ((msg_data_in->req_type < REQ_TYPE_MIN) ||
      (msg_data_in->req_type > REQ_TYPE_MAX))
  {
    pelz_sgx_log(LOG_ERR, "unsupported input request type");
    return NULL;
  }
  if ((msg_data_in->cipher.chars == NULL) ||
      (msg_data_in->cipher.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "NULL/empty cipher");
    return NULL;
  }
  if ((msg_data_in->key_id.chars == NULL) ||
      (msg_data_in->key_id.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "NULL/empty input key ID");
    return NULL;
  }
  if ((msg_data_in->data.chars == NULL) || (msg_data_in->data.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "NULL/empty input data buffer");
    return NULL;
  }
  if ((msg_data_in->status.chars == NULL) || (msg_data_in->status.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "NULL/empty message 'status' string");
    return NULL;
  }

  // construct test request (using ASN.1 specified format)
  PELZ_MSG * msg = PELZ_MSG_new();

  int64_t msg_type_val = msg_data_in->msg_type;
  if (ASN1_ENUMERATED_set_int64(msg->msg_type, msg_type_val) != 1)
  {
    pelz_sgx_log(LOG_ERR, "set 'msg_type' field error");
    return NULL;
  }

  int64_t req_type_val = msg_data_in->req_type;
  if (ASN1_ENUMERATED_set_int64(msg->req_type, req_type_val) != 1)
  {
    pelz_sgx_log(LOG_ERR, "set 'req_type' field error");
    return NULL;
  }
  if (ASN1_STRING_set(msg->cipher,
                      msg_data_in->cipher.chars,
                      (int) msg_data_in->cipher.len) != 1)
  {
    pelz_sgx_log(LOG_ERR, "set 'cipher' field error");
    return NULL;
  }
  if (ASN1_STRING_set(msg->key_id,
                      msg_data_in->key_id.chars,
                      (int) msg_data_in->key_id.len) != 1)
  {
    pelz_sgx_log(LOG_ERR, "set 'key ID' field error");
    return NULL;
  }
  if (ASN1_OCTET_STRING_set(msg->data,
                            msg_data_in->data.chars,
                            (int) msg_data_in->data.len) != 1)
  {
    pelz_sgx_log(LOG_ERR, "set 'data' field error");
    return NULL;
  }
  if (ASN1_STRING_set((ASN1_STRING *) msg->status,
                      msg_data_in->status.chars,
                      (int) msg_data_in->status.len) != 1)
  {
    pelz_sgx_log(LOG_ERR, "set 'status' field error");
    return NULL;
  }

  return msg;
}

int parse_pelz_asn1_msg(PELZ_MSG *msg_in, PELZ_MSG_DATA *parsed_msg_out)
{
  int tag = -1;
  PelzMessagingStatus error_code = PELZ_MSG_UNKNOWN_ERROR;

  // parse message type (msg_type) field
  tag = ASN1_STRING_type(msg_in->msg_type);
  if (tag != V_ASN1_ENUMERATED)
  {
    pelz_sgx_log(LOG_ERR, "invalid 'msg_type' field format");
    error_code = PELZ_MSG_MSG_TYPE_TAG_ERROR;
    return (int) error_code;
  }
  int retval = ASN1_ENUMERATED_get_int64((int64_t *) &(parsed_msg_out->msg_type),
                                         (const ASN1_ENUMERATED *) msg_in->msg_type);
  if (retval != 1)
  {
    pelz_sgx_log(LOG_ERR, "'msg_type' field parse error");
    error_code = PELZ_MSG_MSG_TYPE_PARSE_ERROR;
    unsigned long e = ERR_get_error();
    while (e != 0)
    {
      char estring[256] = { 0 };
      ERR_error_string_n(e, estring, 256);
      pelz_sgx_log(LOG_ERR, estring);
      e = ERR_get_error();
    }
    return (int) error_code;
  }
  if ((parsed_msg_out->msg_type < MSG_TYPE_MIN) ||
      (parsed_msg_out->msg_type > MSG_TYPE_MAX))
  {
    pelz_sgx_log(LOG_ERR, "parsed 'msg_type' unsupported");
    error_code = PELZ_MSG_MSG_TYPE_PARSE_INVALID;
    return (int) error_code;
  }

  // parse request type (req_type) field
  tag = ASN1_STRING_type(msg_in->req_type);
  if (tag != V_ASN1_ENUMERATED)
  {
    pelz_sgx_log(LOG_ERR, "invalid 'req_type' field format");
    error_code = PELZ_MSG_REQ_TYPE_TAG_ERROR;
    return (int) error_code;
  }
  retval = ASN1_ENUMERATED_get_int64((int64_t *) &(parsed_msg_out->req_type),
                                     (const ASN1_ENUMERATED *) msg_in->req_type);
  if (retval != 1)
  {
    pelz_sgx_log(LOG_ERR, "'req_type' field parse error");
    error_code = PELZ_MSG_REQ_TYPE_PARSE_ERROR;
    unsigned long e = ERR_get_error();
    while (e != 0)
    {
      char estring[256] = { 0 };
      ERR_error_string_n(e, estring, 256);
      pelz_sgx_log(LOG_ERR, estring);
      e = ERR_get_error();
    }
    return (int) error_code;
  }
  if ((parsed_msg_out->req_type < REQ_TYPE_MIN) ||
      (parsed_msg_out->req_type > REQ_TYPE_MAX))
  {
    pelz_sgx_log(LOG_ERR, "parsed 'req_type' unsupported");
    error_code = PELZ_MSG_REQ_TYPE_PARSE_INVALID;
    return (int) error_code;
  }

  // parse 'cipher' message field
  tag = ASN1_STRING_type(msg_in->cipher);
  if (tag != V_ASN1_UTF8STRING)
  {
    pelz_sgx_log(LOG_ERR, "invalid 'cipher' field format");
    error_code = PELZ_MSG_CIPHER_TAG_ERROR;
    return (int) error_code;
  }
  parsed_msg_out->cipher.len =
    (size_t) ASN1_STRING_to_UTF8(&(parsed_msg_out->cipher.chars),
                                 (const ASN1_STRING *) msg_in->cipher);
  if ((parsed_msg_out->cipher.chars == NULL) ||
      (parsed_msg_out->cipher.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "'cipher' field parse error");
    error_code = PELZ_MSG_CIPHER_PARSE_ERROR;
    unsigned long e = ERR_get_error();
    while (e != 0)
    {
      char estring[256] = { 0 };
      ERR_error_string_n(e, estring, 256);
      pelz_sgx_log(LOG_ERR, estring);
      e = ERR_get_error();
    }
    return (int) error_code;
  }

  // parse 'key ID' message field
  tag = ASN1_STRING_type(msg_in->key_id);
  if (tag != V_ASN1_UTF8STRING)
  {
    pelz_sgx_log(LOG_ERR, "invalid 'key ID' field format");
    error_code = PELZ_MSG_KEY_ID_TAG_ERROR;
    return (int) error_code;
  }
  parsed_msg_out->key_id.len =
    (size_t) ASN1_STRING_to_UTF8(&(parsed_msg_out->key_id.chars),
                                 (const ASN1_STRING *) msg_in->key_id);
  if ((parsed_msg_out->key_id.chars == NULL) ||
      (parsed_msg_out->key_id.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "'key ID' field parse error");
    error_code = PELZ_MSG_KEY_ID_PARSE_ERROR;
    unsigned long e = ERR_get_error();
    while (e != 0)
    {
      char estring[256] = { 0 };
      ERR_error_string_n(e, estring, 256);
      pelz_sgx_log(LOG_ERR, estring);
      e = ERR_get_error();
    }
    return (int) error_code;
  }

  // parse 'data' message field
  tag = ASN1_STRING_type(msg_in->data);
  if (tag != V_ASN1_OCTET_STRING)
  {
    pelz_sgx_log(LOG_ERR, "invalid 'data' field format");
    error_code = PELZ_MSG_DATA_TAG_ERROR;
    return (int) error_code;
  }
  parsed_msg_out->data.len = (size_t) ASN1_STRING_length(msg_in->data);
  parsed_msg_out->data.chars = calloc(parsed_msg_out->data.len + 1,
                                      sizeof(unsigned char));
  if (parsed_msg_out->data.chars == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error allocating memory for message 'data' field");
    error_code = PELZ_MSG_MALLOC_ERROR;
    return (int) error_code;
  }
  const unsigned char *parsed_data_bytes = ASN1_STRING_get0_data(msg_in->data);
  memcpy(parsed_msg_out->data.chars,
         parsed_data_bytes,
         parsed_msg_out->data.len);
  if ((parsed_msg_out->data.chars == NULL) || (parsed_msg_out->data.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "'data' field parse error");
    error_code = PELZ_MSG_DATA_PARSE_ERROR;
    unsigned long e = ERR_get_error();
    while (e != 0)
    {
      char estring[256] = { 0 };
      ERR_error_string_n(e, estring, 256);
      pelz_sgx_log(LOG_ERR, estring);
      e = ERR_get_error();
    }
    return (int) error_code;
  }

  // parse 'status' message field
  tag = ASN1_STRING_type(msg_in->status);
  if (tag != V_ASN1_UTF8STRING)
  {
    pelz_sgx_log(LOG_ERR, "invalid 'status' field format");
    error_code = PELZ_MSG_STATUS_TAG_ERROR;
    return (int) error_code;
  }
  parsed_msg_out->status.len =
    (size_t) ASN1_STRING_to_UTF8(&(parsed_msg_out->status.chars),
                                 (const ASN1_STRING *) msg_in->status);
  if ((parsed_msg_out->status.chars == NULL) ||
      (parsed_msg_out->status.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "'status' field parse error");
    error_code = PELZ_MSG_STATUS_PARSE_ERROR;
    unsigned long e = ERR_get_error();
    while (e != 0)
    {
      char estring[256] = { 0 };
      ERR_error_string_n(e, estring, 256);
      pelz_sgx_log(LOG_ERR, estring);
      e = ERR_get_error();
    }
    return (int) error_code;
  }

  // if this point is reached, the input message has been successfully parsed
  error_code = PELZ_MSG_OK;
  return (int) error_code;
}

CMS_ContentInfo *create_pelz_signed_msg(uint8_t *data_in,
                                        int data_in_len,
                                        X509 *sign_cert,
                                        EVP_PKEY *sign_priv)
{
  // validate function paramters provided by the caller
  //  - input data byte array must be valid (non-NULL and
  //    of valid, non-empty size)
  //  - signer's certificate and key must be specified (non-NULL)
  if ((data_in == NULL) ||
      (data_in_len <= 0) ||
      (sign_cert == NULL) ||
      (sign_priv == NULL))
  {
    pelz_sgx_log(LOG_ERR, "invalid parameter");
    return NULL;
  }

  // create BIO containing bytes to be signed and included as content
  // in the resulting signed data message
  BIO * data_in_bio = BIO_new_mem_buf(data_in, data_in_len);
  if (data_in_bio == NULL)
  {
    pelz_sgx_log(LOG_ERR, "BIO creation error");
    return NULL;
  }
  if (BIO_pending(data_in_bio) != data_in_len)
  {
    pelz_sgx_log(LOG_ERR, "BIO init error");
    BIO_free(data_in_bio);
    return NULL;
  }

  // create the signed CMS content
  CMS_ContentInfo *sign_result = NULL;
  unsigned int sign_flags = CMS_BINARY;
  sign_result = CMS_sign(sign_cert,
                         sign_priv,
                         NULL,
                         data_in_bio,
                         sign_flags);
  BIO_free(data_in_bio);
  if (sign_result == NULL)
  {
    pelz_sgx_log(LOG_ERR, "CMS_sign() error");
    unsigned long e = ERR_get_error();
    while (e != 0)
    {
      char estring[256] = { 0 };
      ERR_error_string_n(e, estring, 256);
      pelz_sgx_log(LOG_ERR, estring);
      e = ERR_get_error();
    }
    return NULL;
  }

  return sign_result;
}

int verify_pelz_signed_msg(CMS_ContentInfo *signed_msg_in,
                                             X509 **peer_cert,
                                             uint8_t **data_out)
{
  PelzMessagingStatus error_code = PELZ_MSG_UNKNOWN_ERROR;

  // validate input parameters
  if ((signed_msg_in == NULL) ||
      (peer_cert == NULL) ||
      (*peer_cert != NULL) ||
      (data_out == NULL) ||
      (*data_out != NULL))
  {
    pelz_sgx_log(LOG_ERR, "invalid input parameter");
    error_code = PELZ_MSG_INVALID_PARAM;
    return (int) error_code;
  }

  // check input CMS_ContentInfo struct has expected (signedData) content type
  CMS_ContentInfo *temp_cms_msg = signed_msg_in;
  const ASN1_OBJECT *temp_obj = CMS_get0_type(temp_cms_msg);
  if (OBJ_obj2nid(temp_obj) != NID_pkcs7_signed)
  {
    pelz_sgx_log(LOG_ERR, "payload not pkcs7-signedData");
    error_code = PELZ_MSG_VERIFY_CONTENT_TYPE_ERROR;
    return (int) error_code;
  }

  // create BIO to hold signature verification output data
  BIO * verify_out_bio = BIO_new(BIO_s_mem());

  // create a certificate store to facilitate validation of certificate(s)
  // contained in the CMS message being verified (i.e., need the certificate
  // for the Certification Authority that we are requiring any supplied
  // certificates to be signed by)
  X509_STORE *v_store = get_CA_cert_store();

  // use OpenSSL's CMS API to verify the signed message
  int ret = CMS_verify(signed_msg_in, NULL, v_store, NULL, verify_out_bio, 0);
  X509_STORE_free(v_store);
  if (ret != 1)
  {
    pelz_sgx_log(LOG_ERR, "CMS_verify() failed");
    error_code = PELZ_MSG_VERIFY_FAIL;
    unsigned long e = ERR_get_error();
    while (e != 0)
    {
      char estring[256] = { 0 };
      ERR_error_string_n(e, estring, 256);
      pelz_sgx_log(LOG_ERR, (char *) estring);
      e = ERR_get_error();
    }
    BIO_free(verify_out_bio);
    return (int) error_code;
  }

  // get the requestor's certificate from the signed message
  STACK_OF(X509) *signer_cert_stack = sk_X509_new_null();
  signer_cert_stack = CMS_get0_signers(signed_msg_in);
  if (sk_X509_num(signer_cert_stack) != 1)
  {
    pelz_sgx_log(LOG_ERR, "count of signer certs is not one, as expected");
    error_code = PELZ_MSG_VERIFY_SIGNER_CERT_ERROR;
    BIO_free(verify_out_bio);
    return (int) error_code;
  }
  *peer_cert = X509_new();
  *peer_cert = sk_X509_pop(signer_cert_stack);
  if (*peer_cert == NULL) 
  {
    pelz_sgx_log(LOG_ERR, "error extracting signer cert");
    error_code = PELZ_MSG_VERIFY_EXTRACT_SIGNER_CERT_ERROR;
    return (int) error_code;
  }

  int bio_data_size = BIO_pending(verify_out_bio);
  if (bio_data_size <= 0)
  {
    pelz_sgx_log(LOG_ERR, "invalid output BIO result");
    error_code = PELZ_MSG_VERIFY_RESULT_INVALID;
    BIO_free(verify_out_bio);
    return (int) error_code;
  }

  *data_out = (uint8_t *) calloc((size_t) bio_data_size, sizeof(uint8_t));
  if (*data_out == NULL)
  {
    pelz_sgx_log(LOG_ERR, "output buffer malloc error");
    error_code = PELZ_MSG_MALLOC_ERROR;
    BIO_free(verify_out_bio);
    return (int) error_code;
  }

  int data_out_size = BIO_read(verify_out_bio, *data_out, bio_data_size);
  if (data_out_size != bio_data_size)
  {
    pelz_sgx_log(LOG_ERR, "BIO_read() error");
    error_code = PELZ_MSG_BIO_READ_ERROR;
    free(*data_out);
    BIO_free(verify_out_bio);
    return (int) error_code;
  }

  BIO_free(verify_out_bio);

  pelz_sgx_log(LOG_DEBUG, "successful CMS signed message verification");

  return data_out_size;
}

CMS_ContentInfo *create_pelz_enveloped_msg(uint8_t *data_in,
                                           int data_in_len,
                                           X509 *encrypt_cert)
{
  // check input data is not NULL, empty, or of invalid length
  if ((data_in == NULL) || (data_in_len <= 0) || (encrypt_cert == NULL))
  {
    pelz_sgx_log(LOG_ERR, "invalid input parameter");
    return NULL;
  }

  STACK_OF(X509) * cert_stack = sk_X509_new_null();
  sk_X509_push(cert_stack, encrypt_cert);
  if (sk_X509_num(cert_stack) != 1)
  {
    pelz_sgx_log(LOG_ERR, "X509 certificate stack error");
    sk_X509_free(cert_stack);
    return NULL;
  }
  BIO *cms_enc_bio = BIO_new_mem_buf(data_in, data_in_len);

  CMS_ContentInfo *msg_out = CMS_encrypt(cert_stack,
                                         cms_enc_bio,
                                         EVP_aes_256_gcm(),
                                         CMS_BINARY);
  if (msg_out == NULL)
  {
    pelz_sgx_log(LOG_ERR, "CMS_encrypt() error");
    unsigned long e = ERR_get_error();
    while (e != 0)
    {
      char estring[256] = { 0 };
      ERR_error_string_n(e, estring, 256);
      pelz_sgx_log(LOG_ERR, estring);
      e = ERR_get_error();
    }
  }

  BIO_free(cms_enc_bio);
  sk_X509_free(cert_stack);
  return msg_out;
}

int decrypt_pelz_enveloped_msg(CMS_ContentInfo *enveloped_msg_in,
                               X509 *encrypt_cert,
                               EVP_PKEY *decrypt_priv,
                               uint8_t **data_out)
{
  PelzMessagingStatus error_code = PELZ_MSG_UNKNOWN_ERROR;

  // validate input parameters
  if ((enveloped_msg_in == NULL) ||
      (decrypt_priv == NULL) ||
      (data_out == NULL) ||
      ((data_out != NULL) && (*data_out != NULL)))
  {
    pelz_sgx_log(LOG_ERR,
                 "decrypt enveloped message: invalid input parameter");
    error_code = PELZ_MSG_INVALID_PARAM;
    return (int) error_code;
  }

  // check input CMS_ContentInfo struct has expected (authEnvelopedData) type
  CMS_ContentInfo *temp_cms_msg = enveloped_msg_in;
  const ASN1_OBJECT *temp_obj = CMS_get0_type(temp_cms_msg);
  if (OBJ_obj2nid(temp_obj) != NID_id_smime_ct_authEnvelopedData)
  {
    pelz_sgx_log(LOG_ERR,
                 "decrypt enveloped message: payload not authEnvelopedData");
    error_code = PELZ_MSG_CMS_DECRYPT_CONTENT_TYPE_ERROR;
    return (int) error_code;
  }

  // create BIO to hold decrypted message result
  BIO * decrypt_out_bio = BIO_new(BIO_s_mem());

  // decrypt input CMS enveloped message
  int decrypt_retval = CMS_decrypt(enveloped_msg_in,
                                   decrypt_priv,
                                   encrypt_cert,
                                   NULL,
                                   decrypt_out_bio,
                                   CMS_BINARY);
  if (decrypt_retval != 1)
  {
    pelz_sgx_log(LOG_ERR, "decrypt enveloped message: CMS_decrypt() error");
    error_code = PELZ_MSG_CMS_DECRYPT_FAIL;
    unsigned long e = ERR_get_error();
    while (e != 0)
    {
      char estring[256] = { 0 };
      ERR_error_string_n(e, estring, 256);
      pelz_sgx_log(LOG_ERR, estring);
      e = ERR_get_error();
    }
    return (int) error_code;
  }

  // read decrypted message bytes out of BIO
  int buf_size = BIO_pending(decrypt_out_bio);
  if (buf_size <= 0)
  {
    pelz_sgx_log(LOG_ERR,
                 "decrypt enveloped message: invalid output BIO result");
    error_code = PELZ_MSG_CMS_DECRYPT_RESULT_INVALID;
    BIO_free(decrypt_out_bio);
    return (int) error_code;
  }

  *data_out = calloc((size_t) buf_size, sizeof(uint8_t));
  if (*data_out == NULL)
  {
    pelz_sgx_log(LOG_ERR,
                 "decrypt enveloped message: output buffer malloc error");
    error_code = PELZ_MSG_MALLOC_ERROR;
    BIO_free(decrypt_out_bio);
    return (int) error_code;
  }

  int data_out_size = BIO_read(decrypt_out_bio, *data_out, buf_size);
  if (data_out_size != buf_size)
  {
    pelz_sgx_log(LOG_ERR, "decrypt enveloped message: BIO_read() error");
    error_code = PELZ_MSG_BIO_READ_ERROR;
    free(*data_out);
    BIO_free(decrypt_out_bio);
    return (int) error_code;
  }
  
  BIO_free(decrypt_out_bio);

  return data_out_size;
}

int der_encode_pelz_msg(const void *msg_in,
                        unsigned char **bytes_out,
                        MSG_FORMAT msg_format)
{
  PelzMessagingStatus error_code = PELZ_MSG_UNKNOWN_ERROR;
  int num_bytes_out = -1;

  // if NULL input message pointer passed in, nothing to encode
  if (msg_in == NULL)
  {
    pelz_sgx_log(LOG_ERR, "DER encode: NULL input message");
    error_code = PELZ_MSG_INVALID_PARAM;
    return (int) error_code;
  }

  // check output buffer pointer parameter passed
  //   - if pointer to output byte array pointer is NULL, error
  //   - if byte array previously allocated, free so we can allocate correctly
  if (bytes_out == NULL)
  {
    pelz_sgx_log(LOG_ERR, "DER encode: NULL output buffer pointer parameter");
    error_code = PELZ_MSG_INVALID_PARAM;
    return (int) error_code;
  }
  if (*bytes_out != NULL)
  {
    free(*bytes_out);
    *bytes_out = NULL;
  }

  // DER-encode input message
  switch (msg_format)
  {
  case ASN1:
    error_code = PELZ_MSG_DER_ENCODE_ASN1_ERROR;
    num_bytes_out = i2d_PELZ_MSG((const PELZ_MSG *) msg_in, bytes_out);
    break;
  case CMS:
    error_code = PELZ_MSG_DER_ENCODE_CMS_ERROR;
    num_bytes_out = i2d_CMS_ContentInfo((const CMS_ContentInfo *) msg_in, bytes_out);
    break;
  default:
    error_code = PELZ_MSG_INVALID_PARAM;
    return (int) error_code;
  }

  // check result
  if ((*bytes_out == NULL) || (num_bytes_out <= 0))
  {
    pelz_sgx_log(LOG_ERR, "DER encode: PELZ_MSG encode failed");
    unsigned long e = ERR_get_error();
    while (e != 0)
    {
      char estring[256] = { 0 };
      ERR_error_string_n(e, estring, 256);
      pelz_sgx_log(LOG_ERR, estring);
      e = ERR_get_error();
    }
    return (int) error_code;
  }

  return num_bytes_out;
}

void *der_decode_pelz_msg(const unsigned char *bytes_in,
                          long bytes_in_len,
                          MSG_FORMAT msg_format)
{
  void *msg_out = NULL;

  // handle invalid input byte array (NULL pointer, empty, or invalid length)
  if ((bytes_in == NULL) || (bytes_in_len <= 0))
  {
    pelz_sgx_log(LOG_ERR, "DER decode: invalid input byte buffer");
    return NULL;
  }

  switch(msg_format)
  {
  case ASN1:
    msg_out = (void *) d2i_PELZ_MSG(NULL, &bytes_in, bytes_in_len);
    break;
  case CMS:
    msg_out = (void *) d2i_CMS_ContentInfo(NULL, &bytes_in, bytes_in_len);
    break; 
  default:
    pelz_sgx_log(LOG_ERR, "DER decode: invalid output message format");
    return NULL;
  }

  if (msg_out == NULL)
  {
    pelz_sgx_log(LOG_ERR, "DER decode: PELZ_MSG decode failed");
    unsigned long e = ERR_get_error();
    while (e != 0)
    {
      char estring[256] = { 0 };
      ERR_error_string_n(e, estring, 256);
      pelz_sgx_log(LOG_ERR, estring);
      e = ERR_get_error();
    }
    return NULL;
  }

  return msg_out;
}

int deconstruct_pelz_msg(charbuf rcvd_msg_buf_in,
                         X509 *local_cert_in,
                         EVP_PKEY *local_priv_in,
                         X509 **peer_cert_out,
                         PELZ_MSG_DATA *msg_data_out)
{
  PelzMessagingStatus error_code = PELZ_MSG_UNKNOWN_ERROR;
  
  // check for NULL (or empty in one case) input parameters
  if((rcvd_msg_buf_in.chars == NULL) ||
     (rcvd_msg_buf_in.len == 0) ||
     (local_cert_in == NULL) ||
     (local_priv_in == NULL))
  {
    pelz_sgx_log(LOG_ERR, "NULL or empty input parameter");
    return (int) PELZ_MSG_INVALID_PARAM;
  }

  // check output parameter validity
  if ((peer_cert_out == NULL) ||
      (*peer_cert_out != NULL) ||
      (msg_data_out == NULL))
  {
    pelz_sgx_log(LOG_ERR, "invalid output parameter");
    error_code = PELZ_MSG_INVALID_PARAM;
    return (int) error_code;
  }

  // DER-decode signed, enveloped CMS pelz message
  CMS_ContentInfo *env_msg = NULL;
  const unsigned char *temp_buf = rcvd_msg_buf_in.chars;
  env_msg = (CMS_ContentInfo *) der_decode_pelz_msg(temp_buf,
                                                    (long) rcvd_msg_buf_in.len,
                                                    CMS);
  if (env_msg == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error DER-decoding enveloped pelz CMS message");
    error_code = PELZ_MSG_DER_DECODE_CMS_ERROR;
    return (int) error_code;
  }

  // CMS decrypt enveloped pelz message
  uint8_t *der_signed_msg = NULL;
  int der_signed_msg_len = -1;
  der_signed_msg_len = decrypt_pelz_enveloped_msg(env_msg,
                                                  local_cert_in,
                                                  local_priv_in,
                                                  &der_signed_msg);
  CMS_ContentInfo_free(env_msg);
  if ((der_signed_msg == NULL) || (der_signed_msg_len <= 0))
  {
    pelz_sgx_log(LOG_ERR, "error decrypting enveloped pelz CMS message");
    error_code = PELZ_MSG_CMS_DECRYPT_ERROR;
    return (int) error_code;
  }

  // DER-decode decrypted, signed CMS pelz message
  CMS_ContentInfo *signed_msg = NULL;
  signed_msg = (CMS_ContentInfo *) der_decode_pelz_msg(der_signed_msg,
                                                       der_signed_msg_len,
                                                       CMS);
  free(der_signed_msg);
  if (signed_msg == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error DER-decoding decrypted, signed pelz message");
    error_code = PELZ_MSG_DER_DECODE_CMS_ERROR;
    return (int) error_code;
  }

  // verify signed CMS pelz message
  uint8_t *der_asn1_msg = NULL;
  int der_asn1_msg_len = -1;
  der_asn1_msg_len = verify_pelz_signed_msg(signed_msg,
                                            peer_cert_out,
                                            &der_asn1_msg);
  CMS_ContentInfo_free(signed_msg);
  if ((der_asn1_msg == NULL) || (der_asn1_msg_len <= 0))
  {
    pelz_sgx_log(LOG_ERR, "error verifying signed pelz CMS message");
    error_code = PELZ_MSG_VERIFY_ERROR;
    return (int) error_code;
  }

  // DER-decode ASN.1 formatted pelz message
  PELZ_MSG *asn1_msg = NULL;
  temp_buf = der_asn1_msg;
  asn1_msg = (PELZ_MSG *) der_decode_pelz_msg(der_asn1_msg,
                                              (long) der_asn1_msg_len,
                                              ASN1);
  free(der_asn1_msg);
  if (asn1_msg == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error DER-decoding ASN.1 pelz message");
    error_code = PELZ_MSG_DER_DECODE_ASN1_ERROR;
    return (int) error_code;
  }

  // parse ASN.1 formatted pelz request message
  int parse_result = parse_pelz_asn1_msg(asn1_msg, msg_data_out);
  PELZ_MSG_free(asn1_msg);
  if (parse_result != PELZ_MSG_OK)
  {
    pelz_sgx_log(LOG_ERR, "error parsing ASN.1 pelz message");
    error_code = PELZ_MSG_ASN1_PARSE_ERROR;
    return (int) error_code;
  }

  
  return PELZ_MSG_OK;
}

int construct_pelz_msg(PELZ_MSG_DATA *msg_data_in,
                       X509 *local_cert_in,
                       EVP_PKEY *local_priv_in,
                       X509 *peer_cert_in,
                       charbuf *tx_msg_buf)
{
  // check that all input parameters are non-NULL pointers
  if ((msg_data_in == NULL) ||
      (local_cert_in == NULL) ||
      (local_priv_in == NULL) ||
      (peer_cert_in == NULL))
  {
    pelz_sgx_log(LOG_ERR, "NULL input parameter");
    return PELZ_MSG_INVALID_PARAM;
  }

  // check that the charbuf pointer is non-NULL and that its
  // output buffer is not pre-allocated
  if ((tx_msg_buf == NULL) || (tx_msg_buf->chars != NULL))
  {
    pelz_sgx_log(LOG_ERR, "invalid output buffer parameter");
    return PELZ_MSG_INVALID_PARAM;
  }

  // create ASN.1 formatted pelz response message
  PELZ_MSG *asn1_msg = NULL;
  asn1_msg = create_pelz_asn1_msg(msg_data_in);
  if (asn1_msg == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error creating ASN.1 pelz message");
    return PELZ_MSG_ASN1_CREATE_ERROR;
  }

  // DER-encode ASN.1 formatted pelz response message
  unsigned char *der_asn1_msg = NULL;
  int der_asn1_msg_len = -1;
  der_asn1_msg_len = der_encode_pelz_msg((const PELZ_MSG *) asn1_msg,
                                         &der_asn1_msg,
                                         ASN1);
  PELZ_MSG_free(asn1_msg);
  if ((der_asn1_msg == NULL) || (der_asn1_msg_len <= 0))
  {
    pelz_sgx_log(LOG_ERR, "error DER-encoding ASN.1 pelz message");
    return PELZ_MSG_SERIALIZE_ERROR;
  }

  // create signed CMS pelz response message
  CMS_ContentInfo *signed_message = NULL;
  signed_message = create_pelz_signed_msg(der_asn1_msg,
                                          der_asn1_msg_len,
                                          local_cert_in,
                                          local_priv_in);
  free(der_asn1_msg);
  if (signed_message == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error creating signed CMS pelz message");
    return PELZ_MSG_SIGN_ERROR;
  }

  // DER-encode signed CMS pelz response message
  unsigned char *der_signed_msg = NULL;
  int der_signed_msg_len = -1;
  der_signed_msg_len = der_encode_pelz_msg(
                         (const CMS_ContentInfo *) signed_message,
                         &der_signed_msg,
                         CMS);
  CMS_ContentInfo_free(signed_message);
  if ((der_signed_msg == NULL) || (der_signed_msg_len <= 0))
  {
    pelz_sgx_log(LOG_ERR, "error DER-encoding signed CMS pelz message");
    return PELZ_MSG_SERIALIZE_ERROR;
  }

  // CMS encrypt (create enveloped) pelz response message
  CMS_ContentInfo *enveloped_message = NULL;
  enveloped_message = create_pelz_enveloped_msg(der_signed_msg,
                                                der_signed_msg_len,
                                                peer_cert_in);
  free(der_signed_msg);
  if (enveloped_message == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error creating enveloped pelz CMS message");
    return PELZ_MSG_CMS_ENCRYPT_ERROR;
  }

  // DER-encode enveloped CMS pelz response message
  int ret = der_encode_pelz_msg((const CMS_ContentInfo *) enveloped_message,
                                 &(tx_msg_buf->chars),
                                 CMS);
  tx_msg_buf->len = (size_t) ret;
  CMS_ContentInfo_free(enveloped_message);
  if ((tx_msg_buf->chars == NULL) || (tx_msg_buf->len == 0))
  {
    pelz_sgx_log(LOG_ERR, "error DER-encoding enveloped CMS pelz response");
    return PELZ_MSG_SERIALIZE_ERROR;
  }

  return PELZ_MSG_OK;
}
