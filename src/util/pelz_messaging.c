#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/cms.h>

#include ENCLAVE_HEADER_TRUSTED
#include "kmyth_enclave_trusted.h"
#include "charbuf.h"
#include "pelz_messaging.h"
#include "pelz_enclave.h"
#include "common_table.h"
#include "ca_table.h"
#include "ecdh_util.h"
#include "pelz_enclave_log.h"

#include <string.h>
#include <stdio.h>

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


charbuf serialize_request(RequestType request_type, charbuf key_id, charbuf cipher_name, charbuf data, charbuf iv, charbuf tag, charbuf requestor_cert)
{
  uint64_t num_fields = 5;
  if(request_type == REQ_DEC_SIGNED || request_type == REQ_DEC)
  {
    // If there's a mismatch between NULL chars and length in tag or IV
    // that's an indication something odd is happening, so error out.
    if((iv.chars == NULL && iv.len != 0) ||
       (iv.chars != NULL && iv.len == 0) ||
       (tag.chars == NULL && tag.len != 0) ||
       (tag.chars != NULL && tag.len == 0))
    {
      return new_charbuf(0);
    }

    // Decrypt requests have 2 extra fields, IV and tag (which can be empty).
    num_fields = 7;
  }

  // If it's not a decrypt request there shouldn't be an IV or tag.
  else{
    if(tag.chars != NULL || tag.len != 0 || iv.chars != NULL || iv.len != 0)
    {
      return new_charbuf(0);
    }
  }
  uint64_t request_type_int = (uint64_t)request_type;

  uint64_t total_size = ((num_fields+1)*sizeof(uint64_t));
  if(total_size + key_id.len < total_size)
  {
    return new_charbuf(0);
  }
  total_size += key_id.len;

  if(total_size + cipher_name.len < total_size)
  {
    return new_charbuf(0);
  }
  total_size += cipher_name.len;

  if(total_size + data.len < total_size)
  {
    return new_charbuf(0);
  }
  total_size += data.len;

  if(total_size + iv.len < total_size)
  {
    return new_charbuf(0);
  }
  total_size += iv.len;

  if(total_size + tag.len < total_size)
  {
    return new_charbuf(0);
  }
  total_size += tag.len;

  if(total_size + requestor_cert.len < total_size)
  {
    return new_charbuf(0);
  }
  total_size += requestor_cert.len;

  charbuf serialized = new_charbuf(total_size);
  if(serialized.chars == NULL)
  {
    return serialized;
  }

  unsigned char* dst = serialized.chars;

  memcpy(dst, &total_size, sizeof(uint64_t));
  dst += sizeof(uint64_t);
  
  memcpy(dst, &request_type_int, sizeof(uint64_t));
  dst += sizeof(uint64_t);

  memcpy(dst, (uint64_t*)(&key_id.len), sizeof(uint64_t));
  dst += sizeof(uint64_t);

  memcpy(dst, key_id.chars, key_id.len);
  dst += key_id.len;

  memcpy(dst, (uint64_t*)(&cipher_name.len), sizeof(uint64_t));
  dst += sizeof(uint64_t);

  memcpy(dst, cipher_name.chars, cipher_name.len);
  dst += cipher_name.len;

  memcpy(dst, (uint64_t*)(&data.len), sizeof(uint64_t));
  dst += sizeof(uint64_t);

  memcpy(dst, data.chars, data.len);
  dst += data.len;

  // Decrypt requests always serialize iv and tag fields,
  // although they may be empty.
  if(request_type == REQ_DEC_SIGNED)
  {
    memcpy(dst, (uint64_t*)(&iv.len), sizeof(uint64_t));
    dst += sizeof(uint64_t);

    memcpy(dst, iv.chars, iv.len);
    dst += iv.len;

    memcpy(dst, (uint64_t*)(&tag.len), sizeof(uint64_t));
    dst += sizeof(uint64_t);

    memcpy(dst, tag.chars, tag.len);
    dst += tag.len;
  }

  memcpy(dst, (uint64_t*)(&requestor_cert.len), sizeof(uint64_t));
  dst += sizeof(uint64_t);

  memcpy(dst, requestor_cert.chars, requestor_cert.len);
  return serialized;
}

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

  // parse message type (msg_type) field
  tag = ASN1_STRING_type(msg_in->msg_type);
  if (tag != V_ASN1_ENUMERATED)
  {
    pelz_sgx_log(LOG_ERR, "invalid 'msg_type' field format");
    return PELZ_MSG_MSG_TYPE_TAG_ERROR;
  }
  int retval = ASN1_ENUMERATED_get_int64((int64_t *) &(parsed_msg_out->msg_type),
                                         (const ASN1_ENUMERATED *) msg_in->msg_type);
  if (retval != 1)
  {
    pelz_sgx_log(LOG_ERR, "'msg_type' field parse error");
    unsigned long e = ERR_get_error();
    while (e != 0)
    {
      char estring[256] = { 0 };
      ERR_error_string_n(e, estring, 256);
      pelz_sgx_log(LOG_ERR, estring);
      e = ERR_get_error();
    }
    return PELZ_MSG_MSG_TYPE_PARSE_ERROR;
  }
  if ((parsed_msg_out->msg_type < MSG_TYPE_MIN) ||
      (parsed_msg_out->msg_type > MSG_TYPE_MAX))
  {
    pelz_sgx_log(LOG_ERR, "parsed 'msg_type' unsupported");
    return PELZ_MSG_MSG_TYPE_PARSE_INVALID;
  }

  // parse request type (req_type) field
  tag = ASN1_STRING_type(msg_in->req_type);
  if (tag != V_ASN1_ENUMERATED)
  {
    pelz_sgx_log(LOG_ERR, "invalid 'req_type' field format");
    return PELZ_MSG_REQ_TYPE_TAG_ERROR;
  }
  retval = ASN1_ENUMERATED_get_int64((int64_t *) &(parsed_msg_out->req_type),
                                     (const ASN1_ENUMERATED *) msg_in->req_type);
  if (retval != 1)
  {
    pelz_sgx_log(LOG_ERR, "'req_type' field parse error");
    unsigned long e = ERR_get_error();
    while (e != 0)
    {
      char estring[256] = { 0 };
      ERR_error_string_n(e, estring, 256);
      pelz_sgx_log(LOG_ERR, estring);
      e = ERR_get_error();
    }
    return PELZ_MSG_REQ_TYPE_PARSE_ERROR;
  }
  if ((parsed_msg_out->req_type < REQ_TYPE_MIN) ||
      (parsed_msg_out->req_type > REQ_TYPE_MAX))
  {
    pelz_sgx_log(LOG_ERR, "parsed 'req_type' unsupported");
    return PELZ_MSG_REQ_TYPE_PARSE_INVALID;
  }

  // parse 'cipher' message field
  tag = ASN1_STRING_type(msg_in->cipher);
  if (tag != V_ASN1_UTF8STRING)
  {
    pelz_sgx_log(LOG_ERR, "invalid 'cipher' field format");
    return PELZ_MSG_CIPHER_TAG_ERROR;
  }
  parsed_msg_out->cipher.len =
    (size_t) ASN1_STRING_to_UTF8(&(parsed_msg_out->cipher.chars),
                                 (const ASN1_STRING *) msg_in->cipher);
  if ((parsed_msg_out->cipher.chars == NULL) ||
      (parsed_msg_out->cipher.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "'cipher' field parse error");
    unsigned long e = ERR_get_error();
    while (e != 0)
    {
      char estring[256] = { 0 };
      ERR_error_string_n(e, estring, 256);
      pelz_sgx_log(LOG_ERR, estring);
      e = ERR_get_error();
    }
    return PELZ_MSG_CIPHER_PARSE_ERROR;
  }

  // parse 'key ID' message field
  tag = ASN1_STRING_type(msg_in->key_id);
  if (tag != V_ASN1_UTF8STRING)
  {
    pelz_sgx_log(LOG_ERR, "invalid 'key ID' field format");
    return PELZ_MSG_KEY_ID_TAG_ERROR;
  }
  parsed_msg_out->key_id.len =
    (size_t) ASN1_STRING_to_UTF8(&(parsed_msg_out->key_id.chars),
                                 (const ASN1_STRING *) msg_in->key_id);
  if ((parsed_msg_out->key_id.chars == NULL) ||
      (parsed_msg_out->key_id.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "'key ID' field parse error");
    unsigned long e = ERR_get_error();
    while (e != 0)
    {
      char estring[256] = { 0 };
      ERR_error_string_n(e, estring, 256);
      pelz_sgx_log(LOG_ERR, estring);
      e = ERR_get_error();
    }
    return PELZ_MSG_KEY_ID_PARSE_ERROR;
  }

  // parse 'data' message field
  tag = ASN1_STRING_type(msg_in->data);
  if (tag != V_ASN1_OCTET_STRING)
  {
    pelz_sgx_log(LOG_ERR, "invalid 'data' field format");
    return PELZ_MSG_DATA_TAG_ERROR;
  }
  parsed_msg_out->data.len = (size_t) ASN1_STRING_length(msg_in->data);
  parsed_msg_out->data.chars = ASN1_STRING_get0_data(msg_in->data);
  if ((parsed_msg_out->data.chars == NULL) || (parsed_msg_out->data.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "'data' field parse error");
    unsigned long e = ERR_get_error();
    while (e != 0)
    {
      char estring[256] = { 0 };
      ERR_error_string_n(e, estring, 256);
      pelz_sgx_log(LOG_ERR, estring);
      e = ERR_get_error();
    }
    return PELZ_MSG_DATA_PARSE_ERROR;
  }

  // parse 'status' message field
  tag = ASN1_STRING_type(msg_in->status);
  if (tag != V_ASN1_UTF8STRING)
  {
    pelz_sgx_log(LOG_ERR, "invalid 'status' field format");
    return PELZ_MSG_STATUS_TAG_ERROR;
  }
  parsed_msg_out->status.len =
    (size_t) ASN1_STRING_to_UTF8(&(parsed_msg_out->status.chars),
                                 (const ASN1_STRING *) msg_in->status);
  if ((parsed_msg_out->status.chars == NULL) ||
      (parsed_msg_out->status.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "'status' field parse error");
    unsigned long e = ERR_get_error();
    while (e != 0)
    {
      char estring[256] = { 0 };
      ERR_error_string_n(e, estring, 256);
      pelz_sgx_log(LOG_ERR, estring);
      e = ERR_get_error();
    }
    return PELZ_MSG_STATUS_PARSE_ERROR;
  }

  return PELZ_MSG_SUCCESS;
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
  // validate input parameters
  if ((signed_msg_in == NULL) ||
      (peer_cert == NULL) ||
      (*peer_cert != NULL) ||
      (data_out == NULL) ||
      (*data_out != NULL))
  {
    pelz_sgx_log(LOG_ERR, "invalid input parameter");
    return PELZ_MSG_PARAM_INVALID;
  }

  // check input CMS_ContentInfo struct has expected (signedData) content type
  CMS_ContentInfo *temp_cms_msg = signed_msg_in;
  const ASN1_OBJECT *temp_obj = CMS_get0_type(temp_cms_msg);
  if (OBJ_obj2nid(temp_obj) != NID_pkcs7_signed)
  {
    pelz_sgx_log(LOG_ERR, "payload not pkcs7-signedData");
    return PELZ_MSG_VERIFY_CONTENT_ERROR;
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
    unsigned long e = ERR_get_error();
    while (e != 0)
    {
      char estring[256] = { 0 };
      ERR_error_string_n(e, estring, 256);
      pelz_sgx_log(LOG_ERR, (char *) estring);
      e = ERR_get_error();
    }
    BIO_free(verify_out_bio);
    return PELZ_MSG_VERIFY_FAIL;
  }

  // get the requestor's certificate from the signed message
  STACK_OF(X509) *signer_cert_stack = sk_X509_new_null();
  signer_cert_stack = CMS_get0_signers(signed_msg_in);
  if (sk_X509_num(signer_cert_stack) != 1)
  {
    pelz_sgx_log(LOG_ERR, "count of signer certs is not one, as expected");
    BIO_free(verify_out_bio);
    return PELZ_MSG_VERIFY_SIGNER_CERT_ERROR;
  }
  *peer_cert = X509_new();
  *peer_cert = sk_X509_pop(signer_cert_stack);
  if (*peer_cert == NULL) 
  {
    pelz_sgx_log(LOG_ERR, "error extracting signer cert");
    return PELZ_MSG_EXTRACT_SIGNER_CERT_ERROR;
  }

  int bio_data_size = BIO_pending(verify_out_bio);
  if (bio_data_size <= 0)
  {
    pelz_sgx_log(LOG_ERR, "invalid output BIO result");
    BIO_free(verify_out_bio);
    return PELZ_MSG_VERIFY_RESULT_INVALID;
  }

  *data_out = (uint8_t *) calloc((size_t) bio_data_size, sizeof(uint8_t));
  if (*data_out == NULL)
  {
    pelz_sgx_log(LOG_ERR, "output buffer malloc error");
    BIO_free(verify_out_bio);
    return PELZ_MSG_MALLOC_ERROR;
  }

  int data_out_size = BIO_read(verify_out_bio, *data_out, bio_data_size);
  if (data_out_size != bio_data_size)
  {
    pelz_sgx_log(LOG_ERR, "BIO_read() error");
    free(*data_out);
    BIO_free(verify_out_bio);
    return PELZ_MSG_BIO_READ_ERROR;
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

  // validate input parameters
  if ((enveloped_msg_in == NULL) ||
      (decrypt_priv == NULL) ||
      (data_out == NULL) ||
      ((data_out != NULL) && (*data_out != NULL)))
  {
    pelz_sgx_log(LOG_ERR,
                 "decrypt enveloped message: invalid input parameter");
    return PELZ_MSG_PARAM_INVALID;
  }

  // check input CMS_ContentInfo struct has expected (authEnvelopedData) type
  CMS_ContentInfo *temp_cms_msg = enveloped_msg_in;
  const ASN1_OBJECT *temp_obj = CMS_get0_type(temp_cms_msg);
  if (OBJ_obj2nid(temp_obj) != NID_id_smime_ct_authEnvelopedData)
  {
    pelz_sgx_log(LOG_ERR,
                 "decrypt enveloped message: payload not authEnvelopedData");
    return PELZ_MSG_DECRYPT_CONTENT_ERROR;
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
    unsigned long e = ERR_get_error();
    while (e != 0)
    {
      char estring[256] = { 0 };
      ERR_error_string_n(e, estring, 256);
      pelz_sgx_log(LOG_ERR, estring);
      e = ERR_get_error();
    }
    return PELZ_MSG_DECRYPT_FAIL;
  }

  // read decrypted message bytes out of BIO
  int buf_size = BIO_pending(decrypt_out_bio);
  if (buf_size <= 0)
  {
    pelz_sgx_log(LOG_ERR,
                 "decrypt enveloped message: invalid output BIO result");
    BIO_free(decrypt_out_bio);
    return PELZ_MSG_DECRYPT_RESULT_INVALID;
  }

  *data_out = calloc((size_t) buf_size, sizeof(uint8_t));
  if (*data_out == NULL)
  {
    pelz_sgx_log(LOG_ERR,
                 "decrypt enveloped message: output buffer malloc error");
    BIO_free(decrypt_out_bio);
    return PELZ_MSG_MALLOC_ERROR;
  }

  int data_out_size = BIO_read(decrypt_out_bio, *data_out, buf_size);
  if (data_out_size != buf_size)
  {
    pelz_sgx_log(LOG_ERR, "decrypt enveloped message: BIO_read() error");
    free(*data_out);
    BIO_free(decrypt_out_bio);
    return PELZ_MSG_BIO_READ_ERROR;
  }
  
  BIO_free(decrypt_out_bio);

  return data_out_size;
}

int der_encode_pelz_msg(const void *msg_in,
                        unsigned char **bytes_out,
                        MSG_FORMAT msg_format)
{
  int num_bytes_out = PELZ_MSG_UNKNOWN_ERROR;

  // if NULL input message pointer passed in, nothing to encode
  if (msg_in == NULL)
  {
    pelz_sgx_log(LOG_ERR, "DER encode: NULL input message");
    return PELZ_MSG_PARAM_INVALID;
  }

  // check output buffer pointer parameter passed
  //   - if pointer to byte array pointer is NULL, error
  //   - if byte array previously allocated, free so we can allocate correctly
  if (bytes_out == NULL)
  {
    pelz_sgx_log(LOG_ERR, "DER encode: NULL output buffer pointer parameter");
    return PELZ_MSG_PARAM_INVALID;
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
    num_bytes_out = i2d_PELZ_MSG((const PELZ_MSG *) msg_in, bytes_out);
    break;
  case CMS:
    num_bytes_out = i2d_CMS_ContentInfo((const CMS_ContentInfo *) msg_in, bytes_out);
    break;
  default:
    return PELZ_MSG_PARAM_INVALID;
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
    return PELZ_MSG_SERIALIZE_ERROR;
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

int decode_rcvd_pelz_request(charbuf rcvd_msg_buf,
                             X509 ** requestor_cert,
                             PELZ_MSG_DATA *decode_result)
{
  if((rcvd_msg_buf.chars == NULL) || (rcvd_msg_buf.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "Invalid received pelz request message buffer");
    return PELZ_MSG_PARAM_INVALID;
  }

  // DER-decode signed, enveloped CMS pelz request message
  CMS_ContentInfo *env_req = NULL;
  env_req = (CMS_ContentInfo *) der_decode_pelz_msg(
                                  (const unsigned char *) rcvd_msg_buf.chars,
                                  (long) rcvd_msg_buf.len,
                                  CMS);
  if (env_req == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error DER-decoding enveloped pelz CMS request");
    return PELZ_MSG_DESERIALIZE_ERROR;
  }

  // CMS decrypt enveloped pelz request message
  uint8_t *der_signed_req = NULL;
  int der_signed_req_len = -1;
  der_signed_req_len = decrypt_pelz_enveloped_msg(env_req,
                                                  pelz_id.cert,
                                                  pelz_id.private_pkey,
                                                  &der_signed_req);
  CMS_ContentInfo_free(env_req);
  if ((der_signed_req == NULL) || (der_signed_req_len <= 0))
  {
    pelz_sgx_log(LOG_ERR, "error decrypting enveloped pelz CMS request");
    return PELZ_MSG_DECRYPT_FAIL;
  }

  // DER-decode decrypted, signed CMS pelz request message
  CMS_ContentInfo *signed_req = NULL;
  signed_req = (CMS_ContentInfo *) der_decode_pelz_msg(
                                     (const unsigned char *) der_signed_req,
                                     (long) der_signed_req_len,
                                     CMS);
  free(der_signed_req);
  if (signed_req == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error DER-decoding decrypted, signed pelz request");
    return PELZ_MSG_DESERIALIZE_ERROR;
  }

  // verify signed CMS pelz request message
  uint8_t *der_asn1_req = NULL;
  int der_asn1_req_len = -1;
  der_asn1_req_len = verify_pelz_signed_msg(signed_req,
                                            requestor_cert,
                                            &der_asn1_req);
  CMS_ContentInfo_free(signed_req);
  if ((der_asn1_req == NULL) || (der_asn1_req_len <= 0))
  {
    pelz_sgx_log(LOG_ERR, "error verifying signed pelz CMS request");
    return PELZ_MSG_VERIFY_FAIL;
  }

  // DER-decode ASN.1 formatted pelz request message
  PELZ_MSG *asn1_req = NULL;
  asn1_req = (PELZ_MSG *) der_decode_pelz_msg(
                            (const unsigned char *) der_asn1_req,
                            (long) der_asn1_req_len,
                            ASN1);
  free(der_asn1_req);
  if (asn1_req == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error DER-decoding ASN.1 pelz request");
    return PELZ_MSG_DESERIALIZE_ERROR;
  }

  // parse ASN.1 formatted pelz request message
  int parse_result = parse_pelz_asn1_msg(asn1_req, decode_result);
  PELZ_MSG_free(asn1_req);
  if (parse_result != PELZ_MSG_SUCCESS)
  {
    pelz_sgx_log(LOG_ERR, "error parsing ASN.1 pelz request");
    return parse_result;
  }

  return PELZ_MSG_SUCCESS;
}

int encode_pelz_response(PELZ_MSG_DATA *resp_msg_data,
                         X509 *requestor_cert,
                         unsigned char **tx_msg_buf)
{
  // create ASN.1 formatted pelz response message
  PELZ_MSG *asn1_response = NULL;
  asn1_response = create_pelz_asn1_msg(resp_msg_data);
  if (asn1_response != PELZ_MSG_SUCCESS)
  {
    pelz_sgx_log(LOG_ERR, "error creating ASN.1 pelz response");
    return PELZ_MSG_ASN1_CREATE_ERROR;
  }

  // DER-encode ASN.1 formatted pelz response message
  unsigned char *der_asn1_resp = NULL;
  int der_asn1_resp_len = -1;
  der_asn1_resp_len = der_encode_pelz_msg((const PELZ_MSG *) asn1_response,
                                          &der_asn1_resp,
                                          ASN1);
  PELZ_MSG_free(asn1_response);
  if ((der_asn1_resp == NULL) || (der_asn1_resp_len <= 0))
  {
    pelz_sgx_log(LOG_ERR, "error DER-encoding ASN.1 pelz response");
    return PELZ_MSG_SERIALIZE_ERROR;
  }

  // create signed CMS pelz response message
  CMS_ContentInfo *signed_response = NULL;
  signed_response = create_pelz_signed_msg(der_asn1_resp,
                                           der_asn1_resp_len,
                                           pelz_id.cert,
                                           pelz_id.private_pkey);
  free(der_asn1_resp);
  if (signed_response == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error creating signed CMS pelz response");
    return PELZ_MSG_SIGN_ERROR;
  }

  // DER-encode signed CMS pelz response message
  unsigned char *der_signed_resp = NULL;
  int der_signed_resp_len = -1;
  der_signed_resp_len = der_encode_pelz_msg(
                          (const CMS_ContentInfo *) signed_response,
                          &der_signed_resp,
                          CMS);
  CMS_ContentInfo_free(signed_response);
  if ((der_signed_resp == NULL) || (der_signed_resp_len <= 0))
  {
    pelz_sgx_log(LOG_ERR, "error DER-encoding signed CMS pelz response");
    return PELZ_MSG_SERIALIZE_ERROR;
  }

  // CMS encrypt (create enveloped) pelz response message
  CMS_ContentInfo *enveloped_response = NULL;
  enveloped_response = create_pelz_enveloped_msg(der_signed_resp,
                                                 der_asn1_resp_len,
                                                 requestor_cert);
  free(der_signed_resp);
  if (enveloped_response == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error creating enveloped pelz CMS response");
    return PELZ_MSG_ENCRYPT_ERROR;
  }

  // DER-encode enveloped CMS pelz response message
  int tx_msg_buf_len = -1;
  der_signed_resp_len = der_encode_pelz_msg(
                          (const CMS_ContentInfo *) enveloped_response,
                          tx_msg_buf,
                          CMS);
  CMS_ContentInfo_free(enveloped_response);
  if ((*tx_msg_buf == NULL) || (tx_msg_buf_len <= 0))
  {
    pelz_sgx_log(LOG_ERR, "error DER-encoding enveloped CMS pelz response");
    return PELZ_MSG_SERIALIZE_ERROR;
  }

  return tx_msg_buf_len;
}

int validate_signature(RequestType request_type, charbuf key_id, charbuf cipher_name, charbuf data, charbuf iv, charbuf tag, charbuf signature, charbuf cert)
{
  int result = 1;
  X509* requestor_x509;
  EVP_PKEY *requestor_pubkey;
  charbuf serialized;

  const unsigned char* cert_ptr = cert.chars;

  // Check that we cans safely down-convert cert.len for the
  // d2i_x509 call.
  if(cert.len > (size_t)LONG_MAX)
  {
    return result;
  }
  requestor_x509 = d2i_X509(NULL, &cert_ptr, (long int)cert.len);
  if(requestor_x509 == NULL)
  {
    return result;
  }

  /* Check that the requestor's cert is signed by a known CA */
  if(validate_cert(requestor_x509) != 0)
  {
    pelz_sgx_log(LOG_ERR, "Requestor cert is not recognized");
    X509_free(requestor_x509);
    return result;
  }

  /* Now validate the signature over the request */
  requestor_pubkey = X509_get_pubkey(requestor_x509);
  if(requestor_pubkey == NULL)
  {
    X509_free(requestor_x509);
    return result;
  }

  serialized = serialize_request(request_type, key_id, cipher_name, data, iv, tag, cert);
  if(serialized.chars == NULL || serialized.len == 0)
  {
    X509_free(requestor_x509);
    EVP_PKEY_free(requestor_pubkey);
    return result;
  }

  // Check we can safely down-convert signature.len to hand it to ec_verify_buffer.
  if(signature.len > (size_t)UINT_MAX)
  {
    free_charbuf(&serialized);
    X509_free(requestor_x509);
    EVP_PKEY_free(requestor_pubkey);
    return result;
  }
  if(ec_verify_buffer(requestor_pubkey, serialized.chars, serialized.len, signature.chars, (unsigned int)signature.len) == EXIT_SUCCESS)
  {
    pelz_sgx_log(LOG_DEBUG, "Request signature matches");
    result = 0;
  }
  free_charbuf(&serialized);
  X509_free(requestor_x509);
  EVP_PKEY_free(requestor_pubkey);
  return result;
}
