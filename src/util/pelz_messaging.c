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
  ASN1_SIMPLE(PELZ_MSG, type, ASN1_INTEGER),
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
    pelz_sgx_log(LOG_ERR, "ASN.1 create: unsupported input message type");
    return NULL;
  }
  if ((msg_data_in->req_type < REQ_TYPE_MIN) ||
      (msg_data_in->req_type > REQ_TYPE_MAX))
  {
    pelz_sgx_log(LOG_ERR, "ASN.1 create: unsupported input request type");
    return NULL;
  }
  if ((msg_data_in->key_id.chars == NULL) ||
      (msg_data_in->key_id.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "ASN.1 create: NULL/empty input key ID");
    return NULL;
  }
  if ((msg_data_in->data.chars == NULL) || (msg_data_in->data.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "ASN.1 create: NULL/empty input data buffer");
    return NULL;
  }
  if ((msg_data_in->status.chars == NULL) || (msg_data_in->status.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "ASN.1 create: NULL/empty message status string");
    return NULL;
  }

  // construct test request (using ASN.1 specified format)
  PELZ_MSG * msg = PELZ_MSG_new();

  uint64_t type_val = msg_data_in->msg_type << 16;
  type_val += msg_data_in->req_type;
  if (ASN1_INTEGER_set_uint64(msg->type, type_val) != 1)
  {
    pelz_sgx_log(LOG_ERR, "ASN.1 create: set type field error");
    return NULL;
  }

  if (ASN1_STRING_set(msg->key_id,
                      msg_data_in->key_id.chars,
                      (int) msg_data_in->key_id.len) != 1)
  {
    pelz_sgx_log(LOG_ERR, "ASN.1 create: set 'key ID' field error");
    return NULL;
  }
  if (ASN1_OCTET_STRING_set(msg->data,
                            msg_data_in->data.chars,
                            (int) msg_data_in->data.len) != 1)
  {
    pelz_sgx_log(LOG_ERR, "ASN.1 create: set data field error");
    return NULL;
  }
  if (ASN1_STRING_set((ASN1_STRING *) msg->status,
                      msg_data_in->status.chars,
                      (int) msg_data_in->status.len) != 1)
  {
    pelz_sgx_log(LOG_ERR, "ASN.1 create: set status field error");
    return NULL;
  }

  return msg;
}

int parse_pelz_asn1_msg(PELZ_MSG *msg_in, PELZ_MSG_DATA *parsed_msg_out)
{
  // parse 'message type' and 'request type' message fields
  //  - message_type value is in bits 31..16
  //  - request type value is in bits 15..0
  uint64_t type_val = 0;
  int tag = ASN1_STRING_type(msg_in->type);
  if (tag != V_ASN1_INTEGER)
  {
    pelz_sgx_log(LOG_ERR, "ASN.1 parse: invalid 'type' field format");
    return PELZ_MSG_TYPE_TAG_ERROR;
  }
  int retval = ASN1_INTEGER_get_uint64(&type_val,
                                       (const ASN1_INTEGER *) msg_in->type);
  if (retval != 1)
  {
    pelz_sgx_log(LOG_ERR, "ASN.1 parse: 'type' field parse error");
    unsigned long e = ERR_get_error();
    while (e != 0)
    {
      char estring[256] = { 0 };
      ERR_error_string_n(e, estring, 256);
      pelz_sgx_log(LOG_ERR, estring);
      e = ERR_get_error();
    }
    return PELZ_MSG_TYPE_PARSE_ERROR;
  }
  parsed_msg_out->req_type = (uint16_t) type_val & 0xFFFF;
  type_val >>= 16;
  parsed_msg_out->msg_type = (uint16_t) type_val & 0xFFFF;
  if ((parsed_msg_out->msg_type < MSG_TYPE_MIN) ||
      (parsed_msg_out->msg_type > MSG_TYPE_MAX) ||
      (parsed_msg_out->req_type < REQ_TYPE_MIN) ||
      (parsed_msg_out->req_type > REQ_TYPE_MAX))
  {
    pelz_sgx_log(LOG_ERR, "ASN.1 parse: parsed 'type' result is unsupported");
    return PELZ_MSG_TYPE_PARSE_INVALID;
  }

  // parse 'key ID' message field
  tag = ASN1_STRING_type(msg_in->key_id);
  if (tag != V_ASN1_UTF8STRING)
  {
    pelz_sgx_log(LOG_ERR, "ASN.1 parse: invalid 'key ID' field format");
    return PELZ_MSG_KEY_ID_TAG_ERROR;
  }
  parsed_msg_out->key_id.len =
    (size_t) ASN1_STRING_to_UTF8(&(parsed_msg_out->key_id.chars),
                                 (const ASN1_STRING *) msg_in->key_id);
  if ((parsed_msg_out->key_id.chars == NULL) ||
      (parsed_msg_out->key_id.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "ASN.1 parse: 'key ID' field parse error");
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
    pelz_sgx_log(LOG_ERR, "ASN.1 parse: invalid 'data' field format");
    return PELZ_MSG_DATA_TAG_ERROR;
  }
  parsed_msg_out->data.len = (size_t) ASN1_STRING_length(msg_in->data);
  parsed_msg_out->data.chars = ASN1_STRING_get0_data(msg_in->data);
  if ((parsed_msg_out->data.chars == NULL) || (parsed_msg_out->data.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "ASN.1 parse: 'data' field parse error");
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
    pelz_sgx_log(LOG_ERR, "ASN.1 parse: invalid 'status' field format");
    return PELZ_MSG_STATUS_TAG_ERROR;
  }
  parsed_msg_out->status.len =
    (size_t) ASN1_STRING_to_UTF8(&(parsed_msg_out->status.chars),
                                 (const ASN1_STRING *) msg_in->status);
  if ((parsed_msg_out->status.chars == NULL) ||
      (parsed_msg_out->status.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "ASN.1 parse: 'status' field parse error");
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
  case RAW:
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
  case RAW:
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

CMS_ContentInfo *create_signed_data_msg(uint8_t *data_in,
                                        int data_in_len,
                                        X509 *signer_cert,
                                        EVP_PKEY *signer_priv)
{
  // validate function paramters provided by the caller
  //  - input data byte array must be valid (non-NULL and
  //    of valid, non-empty size)
  //  - signer's certificate and key must be specified (non-NULL)
  if ((data_in == NULL) ||
      (data_in_len <= 0) ||
      (signer_cert == NULL) ||
      (signer_priv == NULL))
  {
    pelz_sgx_log(LOG_ERR, "create_signed_data_msg(): invalid parameter");
    return NULL;
  }

  // create BIO containing bytes to be signed and included as content
  // in the resulting signed data message
  BIO * data_in_bio = BIO_new_mem_buf(data_in, data_in_len);
  if (data_in_bio == NULL)
  {
    pelz_sgx_log(LOG_ERR, "create_signed_data_msg(): BIO creation error");
    return NULL;
  }
  if (BIO_pending(data_in_bio) != data_in_len)
  {
    pelz_sgx_log(LOG_ERR, "create_signed_data_msg(): BIO init error");
    BIO_free(data_in_bio);
    return NULL;
  }

  // create the signed CMS content
  CMS_ContentInfo *sign_result = NULL;
  unsigned int sign_flags = CMS_BINARY;
  sign_result = CMS_sign(signer_cert,
                         signer_priv,
                         NULL,
                         data_in_bio,
                         sign_flags);
  EVP_PKEY_free(signer_priv);
  X509_free(signer_cert);
  BIO_free(data_in_bio);
  if (sign_result == NULL)
  {
    pelz_sgx_log(LOG_ERR, "create_signed_data_msg(): CMS_sign() error");
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

int verify_signature(CMS_ContentInfo *signed_msg_in,
                     X509 *ca_cert,
                     uint8_t **data_out)
{
  // validate input parameters
  if ((signed_msg_in == NULL) ||
      (ca_cert == NULL) ||
      (data_out == NULL) ||
      ((data_out != NULL) && (*data_out != NULL)))
  {
    pelz_sgx_log(LOG_ERR, "verify_signature(): invalid input parameter");
    return PELZ_MSG_PARAM_INVALID;
  }

  // create BIO to hold signature verification output data
  BIO * verify_out_bio = BIO_new(BIO_s_mem());

  // create a certificate store to facilitate validation of certificate(s)
  // contained in the CMS message being verified (i.e., need the certificate
  // for the Certification Authority that we are requiring any supplied
  // certificates to be signed by)
  X509_STORE *v_store = X509_STORE_new();
  X509_STORE_add_cert(v_store, ca_cert);

  // check that the CMS_ContentInfo struct being passed in is really a
  // CMS message with 'pkcs-signedData' content type

  CMS_ContentInfo *temp_cms_msg = signed_msg_in;
  const ASN1_OBJECT *temp_obj = CMS_get0_type(temp_cms_msg);
  if (OBJ_obj2nid(temp_obj) != NID_pkcs7_signed)
  {
    pelz_sgx_log(LOG_ERR, "object is not of type pkcs7-signedData");
    BIO_free(verify_out_bio);
    X509_STORE_free(v_store);
    return PELZ_MSG_VERIFY_CONTENT_ERROR;
  }

  // use OpenSSL's CMS API to verify the signed message
  int ret = CMS_verify(signed_msg_in, NULL, v_store, NULL, verify_out_bio, 0);
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
    X509_STORE_free(v_store);
    return PELZ_MSG_VERIFY_FAIL;
  }
  X509_STORE_free(v_store);

  int bio_data_size = BIO_pending(verify_out_bio);
  if (bio_data_size <= 0)
  {
    pelz_sgx_log(LOG_ERR, "invalid or empty data result of CMS_verify()");
    BIO_free(verify_out_bio);
    return PELZ_MSG_VERIFY_RESULT_INVALID;
  }

  if (data_out == NULL)
  {
    data_out = (uint8_t **) malloc(sizeof(uint8_t *));
    if (data_out == NULL)
    {
      pelz_sgx_log(LOG_ERR, "memory allocation of verified data buffer failed");
      BIO_free(verify_out_bio);
      return PELZ_MSG_MALLOC_ERROR;
    }
  }
  if (*data_out != NULL)
  {
    free(*data_out);
  }
  *data_out = (uint8_t *) calloc((size_t) bio_data_size, sizeof(uint8_t));
  if (*data_out == NULL)
  {
    pelz_sgx_log(LOG_ERR, "memory allocation of verified data buffer failed");
    BIO_free(verify_out_bio);
    return PELZ_MSG_MALLOC_ERROR;
  }

  int data_out_size = BIO_read(verify_out_bio, *data_out, bio_data_size);
  if (data_out_size <= 0)
  {
    pelz_sgx_log(LOG_ERR, "BIO_read() error");
    free(*data_out);
    BIO_free(verify_out_bio);
    return PELZ_MSG_BIO_READ_ERROR;
  }

  BIO_free(verify_out_bio);

  pelz_sgx_log(LOG_DEBUG, "verified received CMS signed request");

  return data_out_size;
}

int der_encode_pelz_cms_msg(const CMS_ContentInfo *msg_in,
                            unsigned char **bytes_out)
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
  num_bytes_out = i2d_CMS_ContentInfo(msg_in, bytes_out);
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

CMS_ContentInfo *der_decode_pelz_cms_msg(const unsigned char *bytes_in,
                                         long bytes_in_len)
{
  // handle invalid input byte array (NULL pointer, empty, or invalid length)
  if ((bytes_in == NULL) || (bytes_in_len <= 0))
  {
    pelz_sgx_log(LOG_ERR, "DER decode: invalid input byte buffer");
    return NULL;
  }

  CMS_ContentInfo *msg_out = d2i_CMS_ContentInfo(NULL, &bytes_in, bytes_in_len);
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
