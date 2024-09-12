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

#include ENCLAVE_HEADER_TRUSTED

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

void PELZ_MSG_DATA_free(PELZ_MSG_DATA *msg_data_in)
{
  free_charbuf(&(msg_data_in->cipher));
  free_charbuf(&(msg_data_in->key_id));
  free_charbuf(&(msg_data_in->data));
  free_charbuf(&(msg_data_in->status));
}

PELZ_MSG * create_pelz_asn1_msg(PELZ_MSG_DATA msg_data_in)
{
  // input parameter checks
  //   Note: cipher 'tag' and 'iv' fields can be NULL/empty
  if ((msg_data_in.msg_type < MSG_TYPE_MIN) ||
      (msg_data_in.msg_type > MSG_TYPE_MAX))
  {
    pelz_sgx_log(LOG_ERR, "unsupported input message type");
    return NULL;
  }
  if ((msg_data_in.req_type < REQ_TYPE_MIN) ||
      (msg_data_in.req_type > REQ_TYPE_MAX))
  {
    pelz_sgx_log(LOG_ERR, "unsupported input request type");
    return NULL;
  }
  if ((msg_data_in.cipher.chars == NULL) ||
      (msg_data_in.cipher.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "NULL/empty cipher");
    return NULL;
  }
  if ((msg_data_in.key_id.chars == NULL) ||
      (msg_data_in.key_id.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "NULL/empty input key ID");
    return NULL;
  }
  if ((msg_data_in.data.chars == NULL) || (msg_data_in.data.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "NULL/empty input data buffer");
    return NULL;
  }
  if ((msg_data_in.status.chars == NULL) || (msg_data_in.status.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "NULL/empty message 'status' string");
    return NULL;
  }

  // construct test request (using ASN.1 specified format)
  //   Note: setting NULL/empty 'tag' or 'iv' data should not error
  //         but make the ASN.1 octet string pointer parameter NULL
  PELZ_MSG *msg = PELZ_MSG_new();

  msg->msg_type = ASN1_ENUMERATED_new();
  int64_t msg_type_val = msg_data_in.msg_type;
  if (ASN1_ENUMERATED_set_int64(msg->msg_type, msg_type_val) != 1)
  {
    pelz_sgx_log(LOG_ERR, "set 'msg_type' field error");
    return NULL;
  }

  msg->req_type = ASN1_ENUMERATED_new();
  int64_t req_type_val = msg_data_in.req_type;
  if (ASN1_ENUMERATED_set_int64(msg->req_type, req_type_val) != 1)
  {
    pelz_sgx_log(LOG_ERR, "set 'req_type' field error");
    return NULL;
  }

  msg->cipher = ASN1_UTF8STRING_new();
  if (ASN1_STRING_set(msg->cipher,
                      msg_data_in.cipher.chars,
                      (int) msg_data_in.cipher.len) != 1)
  {
    pelz_sgx_log(LOG_ERR, "set 'cipher' field error");
    return NULL;
  }

  msg->tag = ASN1_OCTET_STRING_new();
  if (ASN1_OCTET_STRING_set(msg->tag,
                            msg_data_in.tag.chars,
                            (int) msg_data_in.tag.len) != 1)
  {
    pelz_sgx_log(LOG_ERR, "set 'tag' field error");
    return NULL;
  }

  msg->iv = ASN1_OCTET_STRING_new();
  if (ASN1_OCTET_STRING_set(msg->iv,
                            msg_data_in.iv.chars,
                            (int) msg_data_in.iv.len) != 1)
  {
    pelz_sgx_log(LOG_ERR, "set 'iv' field error");
    return NULL;
  }

  msg->key_id = ASN1_UTF8STRING_new();
  if (ASN1_STRING_set(msg->key_id,
                      msg_data_in.key_id.chars,
                      (int) msg_data_in.key_id.len) != 1)
  {
    pelz_sgx_log(LOG_ERR, "set 'key ID' field error");
    return NULL;
  }

  msg->data = ASN1_OCTET_STRING_new();
  if (ASN1_OCTET_STRING_set(msg->data,
                            msg_data_in.data.chars,
                            (int) msg_data_in.data.len) != 1)
  {
    pelz_sgx_log(LOG_ERR, "set 'data' field error");
    return NULL;
  }

  msg->status = ASN1_UTF8STRING_new();
  if (ASN1_STRING_set((ASN1_STRING *) msg->status,
                      msg_data_in.status.chars,
                      (int) msg_data_in.status.len) != 1)
  {
    pelz_sgx_log(LOG_ERR, "set 'status' field error");
    return NULL;
  }

  return msg;
}

PelzMessagingStatus parse_pelz_asn1_msg(PELZ_MSG *msg_in,
                                        PELZ_MSG_DATA *parsed_msg_out)
{
  pelz_sgx_log(LOG_DEBUG, "starting parse_pelz_asn1_msg()");
  int tag = -1;

  // parse message type (msg_type) field
  tag = ASN1_STRING_type(msg_in->msg_type);
  if (tag != V_ASN1_ENUMERATED)
  {
    pelz_sgx_log(LOG_ERR, "invalid 'msg_type' field format");
    return PELZ_MSG_ASN1_TAG_ERROR;
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
    return PELZ_MSG_ASN1_PARSE_ERROR;
  }
  if ((parsed_msg_out->msg_type < MSG_TYPE_MIN) ||
      (parsed_msg_out->msg_type > MSG_TYPE_MAX))
  {
    pelz_sgx_log(LOG_ERR, "parsed 'msg_type' unsupported");
    return PELZ_MSG_ASN1_PARSE_INVALID_RESULT;
  }

  // parse request type (req_type) field
  tag = ASN1_STRING_type(msg_in->req_type);
  if (tag != V_ASN1_ENUMERATED)
  {
    pelz_sgx_log(LOG_ERR, "invalid 'req_type' field format");
    return PELZ_MSG_ASN1_TAG_ERROR;
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
    return PELZ_MSG_ASN1_PARSE_ERROR;
  }
  if ((parsed_msg_out->req_type < REQ_TYPE_MIN) ||
      (parsed_msg_out->req_type > REQ_TYPE_MAX))
  {
    pelz_sgx_log(LOG_ERR, "parsed 'req_type' unsupported");
    return PELZ_MSG_ASN1_PARSE_INVALID_RESULT;
  }

  // parse 'cipher' message field
  tag = ASN1_STRING_type(msg_in->cipher);
  if (tag != V_ASN1_UTF8STRING)
  {
    pelz_sgx_log(LOG_ERR, "invalid 'cipher' field format");
    return PELZ_MSG_ASN1_TAG_ERROR;
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
    return PELZ_MSG_ASN1_PARSE_ERROR;
  }

  // parse cipher 'tag' message field
  if (msg_in->tag == NULL)
  {
    free_charbuf(&(parsed_msg_out->tag));
  }
  else
  {
    pelz_sgx_log(LOG_DEBUG, "else");
    tag = ASN1_STRING_type(msg_in->tag);
    if (tag != V_ASN1_OCTET_STRING)
    {
      pelz_sgx_log(LOG_ERR, "invalid cipher 'tag' field format");
      return PELZ_MSG_ASN1_TAG_ERROR;
    }
    parsed_msg_out->tag.len = (size_t) ASN1_STRING_length(msg_in->tag);
    if (parsed_msg_out->tag.len > 0)
    {
      parsed_msg_out->tag.chars = calloc(parsed_msg_out->tag.len + 1,
                                         sizeof(unsigned char));
      if (parsed_msg_out->tag.chars == NULL)
      {
        pelz_sgx_log(LOG_ERR, "error allocating memory for message 'tag' field");
        return PELZ_MSG_MALLOC_ERROR;
      }
      const unsigned char *parsed_tag_bytes = ASN1_STRING_get0_data(msg_in->tag);
      memcpy(parsed_msg_out->tag.chars,
             parsed_tag_bytes,
             parsed_msg_out->tag.len);
      if ((parsed_msg_out->tag.chars == NULL) || (parsed_msg_out->tag.len == 0))
      {
        pelz_sgx_log(LOG_ERR, "cipher 'tag' field parse error");
        unsigned long e = ERR_get_error();
        while (e != 0)
        {
          char estring[256] = { 0 };
          ERR_error_string_n(e, estring, 256);
          pelz_sgx_log(LOG_ERR, estring);
          e = ERR_get_error();
        }
        return PELZ_MSG_ASN1_PARSE_ERROR;
      }
    }
  }

  // parse cipher 'iv' message field
  if (msg_in->iv == NULL)
  {
    free_charbuf(&(parsed_msg_out->iv));
  }
  else
  {
    tag = ASN1_STRING_type(msg_in->iv);
    if (tag != V_ASN1_OCTET_STRING)
    {
      pelz_sgx_log(LOG_ERR, "invalid cipher 'iv' field format");
      return PELZ_MSG_ASN1_TAG_ERROR;
    }
    parsed_msg_out->iv.len = (size_t) ASN1_STRING_length(msg_in->iv);
    if (parsed_msg_out->iv.len > 0)
    {
      parsed_msg_out->iv.chars = calloc(parsed_msg_out->iv.len + 1,
                                        sizeof(unsigned char));
      if (parsed_msg_out->iv.chars == NULL)
      {
        pelz_sgx_log(LOG_ERR, "error allocating memory for message 'iv' field");
        return PELZ_MSG_MALLOC_ERROR;
      }
      const unsigned char *parsed_iv_bytes = ASN1_STRING_get0_data(msg_in->iv);
      memcpy(parsed_msg_out->iv.chars,
             parsed_iv_bytes,
             parsed_msg_out->iv.len);
      if ((parsed_msg_out->iv.chars == NULL) || (parsed_msg_out->iv.len == 0))
      {
        pelz_sgx_log(LOG_ERR, "cipher 'iv' field parse error");
        unsigned long e = ERR_get_error();
        while (e != 0)
        {
          char estring[256] = { 0 };
          ERR_error_string_n(e, estring, 256);
          pelz_sgx_log(LOG_ERR, estring);
          e = ERR_get_error();
        }
        return PELZ_MSG_ASN1_PARSE_ERROR;
      }
    }
  }

  // parse 'key ID' message field
  tag = ASN1_STRING_type(msg_in->key_id);
  if (tag != V_ASN1_UTF8STRING)
  {
    pelz_sgx_log(LOG_ERR, "invalid 'key ID' field format");
    return PELZ_MSG_ASN1_TAG_ERROR;
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
    return PELZ_MSG_ASN1_PARSE_ERROR;
  }

  // parse 'data' message field
  tag = ASN1_STRING_type(msg_in->data);
  if (tag != V_ASN1_OCTET_STRING)
  {
    pelz_sgx_log(LOG_ERR, "invalid 'data' field format");
    return PELZ_MSG_ASN1_TAG_ERROR;
  }
  parsed_msg_out->data.len = (size_t) ASN1_STRING_length(msg_in->data);
  parsed_msg_out->data.chars = calloc(parsed_msg_out->data.len + 1,
                                      sizeof(unsigned char));
  if (parsed_msg_out->data.chars == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error allocating memory for message 'data' field");
    return PELZ_MSG_MALLOC_ERROR;
  }
  const unsigned char *parsed_data_bytes = ASN1_STRING_get0_data(msg_in->data);
  memcpy(parsed_msg_out->data.chars,
         parsed_data_bytes,
         parsed_msg_out->data.len);
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
    return PELZ_MSG_ASN1_PARSE_ERROR;
  }

  // parse 'status' message field
  tag = ASN1_STRING_type(msg_in->status);
  if (tag != V_ASN1_UTF8STRING)
  {
    pelz_sgx_log(LOG_ERR, "invalid 'status' field format");
    return PELZ_MSG_ASN1_TAG_ERROR;
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
    return PELZ_MSG_ASN1_PARSE_ERROR;
  }

  // if this point is reached, the input message has been successfully parsed
  return PELZ_MSG_OK;
}

CMS_ContentInfo *create_pelz_signed_msg(charbuf msg_data_in,
                                        X509 *sign_cert,
                                        EVP_PKEY *sign_priv)
{
  // validate function paramters provided by the caller
  //  - input data byte array must be valid (non-NULL and
  //    of valid, non-empty size)
  //  - signer's certificate and key must be specified (non-NULL)
  if ((msg_data_in.chars == NULL) ||
      (msg_data_in.len == 0) ||
      (sign_cert == NULL) ||
      (sign_priv == NULL))
  {
    pelz_sgx_log(LOG_ERR, "invalid parameter");
    return NULL;
  }

  // create BIO containing bytes to be signed and included as content
  // in the resulting signed data message
  BIO * data_in_bio = BIO_new_mem_buf(msg_data_in.chars,
                                      (int) msg_data_in.len);
  if (data_in_bio == NULL)
  {
    pelz_sgx_log(LOG_ERR, "BIO creation error");
    return NULL;
  }
  if (BIO_pending(data_in_bio) != (int) msg_data_in.len)
  {
    pelz_sgx_log(LOG_ERR, "BIO init error");
    BIO_free(data_in_bio);
    return NULL;
  }

  // create the signed CMS content
  CMS_ContentInfo *sign_result = NULL;
  sign_result = CMS_sign(sign_cert,
                         sign_priv,
                         NULL,
                         data_in_bio,
                         CMS_BINARY);
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

PelzMessagingStatus verify_pelz_signed_msg(CMS_ContentInfo *signed_msg_in,
                                           X509 **peer_cert_out,
                                           charbuf *data_out)
{
  // validate input parameters
  // if output buffers pre-allocated, free and set to NULL
  if ((signed_msg_in == NULL) || (peer_cert_out == NULL) || (data_out == NULL))
  {
    pelz_sgx_log(LOG_ERR, "invalid input parameter");
    return PELZ_MSG_INVALID_PARAM;
  }
  if (*peer_cert_out != NULL)
  {
    X509_free(*peer_cert_out);
    *peer_cert_out = NULL;
  }
  if (data_out->chars != NULL)
  {
    free(data_out->chars);
    data_out->chars = NULL;
  }

  // check input CMS_ContentInfo struct has expected (signedData) content type
  CMS_ContentInfo *temp_cms_msg = signed_msg_in;
  const ASN1_OBJECT *temp_obj = CMS_get0_type(temp_cms_msg);
  if (OBJ_obj2nid(temp_obj) != NID_pkcs7_signed)
  {
    pelz_sgx_log(LOG_ERR, "payload not pkcs7-signedData");
    return PELZ_MSG_VERIFY_CONTENT_TYPE_ERROR;
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
    return PELZ_MSG_VERIFY_ERROR;
  }

  // get the signer's certificate from the signed message
  STACK_OF(X509) *signer_cert_stack = sk_X509_new_null();
  signer_cert_stack = CMS_get0_signers(signed_msg_in);
  if (sk_X509_num(signer_cert_stack) != 1)
  {
    pelz_sgx_log(LOG_ERR, "count of signer certs is not one, as expected");
    BIO_free(verify_out_bio);
    return PELZ_MSG_VERIFY_SIGNER_CERT_ERROR;
  }
  *peer_cert_out = X509_new();
  *peer_cert_out = sk_X509_pop(signer_cert_stack);
  if (*peer_cert_out == NULL) 
  {
    pelz_sgx_log(LOG_ERR, "error extracting signer cert");
    return PELZ_MSG_VERIFY_EXTRACT_SIGNER_CERT_ERROR;
  }

  // get size of data in signed message (in BIO now from 'verify' call)
  int bio_data_size = BIO_pending(verify_out_bio);
  if (bio_data_size <= 0)
  {
    pelz_sgx_log(LOG_ERR, "invalid output BIO result");
    BIO_free(verify_out_bio);
    return PELZ_MSG_VERIFY_INVALID_RESULT;
  }

  // allocate memory for output buffer to hold signed data
  data_out->chars = (unsigned char *) calloc((size_t) bio_data_size,
                                             sizeof(unsigned char));
  if (data_out->chars == NULL)
  {
    pelz_sgx_log(LOG_ERR, "output buffer malloc error");
    BIO_free(verify_out_bio);
    return PELZ_MSG_MALLOC_ERROR;
  }

  // put signed data in output buffer (read out of BIO)
  data_out->len = (size_t ) BIO_read(verify_out_bio, data_out->chars, bio_data_size);
  BIO_free(verify_out_bio);
  if ((int) data_out->len != bio_data_size)
  {
    pelz_sgx_log(LOG_ERR, "BIO_read() error");
    free(data_out->chars);
    return PELZ_MSG_BIO_READ_ERROR;
  }

  pelz_sgx_log(LOG_DEBUG, "successful CMS signed message verification");

  return PELZ_MSG_OK;
}

CMS_ContentInfo *create_pelz_enveloped_msg(charbuf msg_data_in,
                                           X509 *encrypt_cert)
{
  // check input data is not NULL, empty, or of invalid length
  if ((msg_data_in.chars == NULL) ||
      (msg_data_in.len == 0) ||
      (encrypt_cert == NULL))
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
  BIO *cms_enc_bio = BIO_new_mem_buf(msg_data_in.chars,
                                     (int) msg_data_in.len);

  CMS_ContentInfo *msg_out = CMS_ContentInfo_new();
  msg_out = CMS_encrypt(cert_stack,
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

PelzMessagingStatus decrypt_pelz_enveloped_msg(CMS_ContentInfo *enveloped_msg_in,
                                               X509 *encrypt_cert,
                                               EVP_PKEY *decrypt_priv,
                                               charbuf *data_out)
{
  // validate input parameters
  // (Note: the certificate containing the public encryption key is
  //        technically unnecessary, but we require it for consistency)
  if ((enveloped_msg_in == NULL) ||
      (encrypt_cert == NULL) ||
      (decrypt_priv == NULL) ||
      (data_out == NULL))
  {
    pelz_sgx_log(LOG_ERR,
                 "decrypt enveloped message: invalid input parameter");
    return PELZ_MSG_INVALID_PARAM;
  }

  // check input CMS_ContentInfo struct has expected (authEnvelopedData) type
  CMS_ContentInfo *temp_cms_msg = enveloped_msg_in;
  const ASN1_OBJECT *temp_obj = CMS_get0_type(temp_cms_msg);
  if (OBJ_obj2nid(temp_obj) != NID_id_smime_ct_authEnvelopedData)
  {
    pelz_sgx_log(LOG_ERR,
                 "decrypt enveloped message: payload not authEnvelopedData");
    return PELZ_MSG_DECRYPT_CONTENT_TYPE_ERROR;
  }

  // create BIO to hold decrypted message result
  BIO * decrypt_out_bio = BIO_new(BIO_s_mem());

  // decrypt input CMS enveloped message
  int retval = CMS_decrypt(enveloped_msg_in,
                           decrypt_priv,
                           encrypt_cert,
                           NULL,
                           decrypt_out_bio,
                           CMS_BINARY);
  if (retval != 1)
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
    return PELZ_MSG_DECRYPT_ERROR;
  }

  // read decrypted message bytes out of BIO
  int buf_size = BIO_pending(decrypt_out_bio);
  if (buf_size <= 0)
  {
    pelz_sgx_log(LOG_ERR,
                 "decrypt enveloped message: invalid output BIO result");
    BIO_free(decrypt_out_bio);
    return PELZ_MSG_DECRYPT_INVALID_RESULT;
  }

  data_out->chars = calloc((size_t) buf_size, sizeof(uint8_t));
  if (data_out->chars == NULL)
  {
    pelz_sgx_log(LOG_ERR,
                 "decrypt enveloped message: output buffer malloc error");
    BIO_free(decrypt_out_bio);
    return PELZ_MSG_MALLOC_ERROR;
  }

  data_out->len = (size_t) BIO_read(decrypt_out_bio,
                                    data_out->chars,
                                    buf_size);
  if ((int) (data_out->len) != buf_size)
  {
    pelz_sgx_log(LOG_ERR, "decrypt enveloped message: BIO_read() error");
    BIO_free(decrypt_out_bio);
    free(data_out->chars);
    data_out->chars = NULL;
    data_out->len = 0;
    return PELZ_MSG_BIO_READ_ERROR;
  }
  
  BIO_free(decrypt_out_bio);

  return PELZ_MSG_OK;
}

PelzMessagingStatus der_encode_pelz_msg(const void *msg_in,
                                        charbuf *der_bytes_out,
                                        MSG_FORMAT msg_format)
{
  // if NULL input message pointer passed in, nothing to encode
  if (msg_in == NULL)
  {
    pelz_sgx_log(LOG_ERR, "DER encode: NULL input message");
    return PELZ_MSG_INVALID_PARAM;
  }

  // check output buffer pointer parameter passed
  //   - if pointer to output byte array pointer is NULL, error
  //   - if byte array previously allocated, free so we can allocate correctly
  if (der_bytes_out == NULL)
  {
    pelz_sgx_log(LOG_ERR, "DER encode: NULL output buffer pointer parameter");
    return PELZ_MSG_INVALID_PARAM;
  }
  if (der_bytes_out->chars != NULL)
  {
    free_charbuf(der_bytes_out);
  }

  // DER-encode input message
  PelzMessagingStatus der_encode_error_status = PELZ_MSG_UNKNOWN_ERROR;
  int out_size = -1;
  switch (msg_format)
  {
  case ASN1:
    out_size = i2d_PELZ_MSG((const PELZ_MSG *) msg_in,
                            &(der_bytes_out->chars));
    der_encode_error_status = PELZ_MSG_DER_ENCODE_ASN1_ERROR;
    break;
  case CMS:
    out_size = i2d_CMS_ContentInfo((const CMS_ContentInfo *) msg_in,
                                   &(der_bytes_out->chars));
    der_encode_error_status = PELZ_MSG_DER_ENCODE_CMS_ERROR;
    break;
  default:
    return PELZ_MSG_INVALID_PARAM;
  }

  // check result
  der_bytes_out->len = (size_t) out_size;
  if ((der_bytes_out->chars == NULL) || (der_bytes_out->len == 0))
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
    return der_encode_error_status;
  }

  return PELZ_MSG_OK;
}

void *der_decode_pelz_msg(charbuf der_bytes_in,
                          MSG_FORMAT msg_format)
{
  // handle invalid input byte array (NULL pointer or empty input buffer)
  if ((der_bytes_in.chars == NULL) || (der_bytes_in.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "DER decode: invalid input byte buffer");
    return NULL;
  }

  // DER-decode into appropriate output message format (ASN.1 or CMS)
  const unsigned char *buf_in = der_bytes_in.chars;
  long buf_in_size = (long) der_bytes_in.len;
  void *msg_out = NULL;

  switch(msg_format)
  {
  case ASN1:
    msg_out = (void *) d2i_PELZ_MSG(NULL, &buf_in, buf_in_size);
    break;
  case CMS:
    msg_out = (void *) d2i_CMS_ContentInfo(NULL, &buf_in, buf_in_size);
    break; 
  default:
    pelz_sgx_log(LOG_ERR, "DER decode: invalid output message format");
    return NULL;
  }

  // check for decoding error
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

PelzMessagingStatus construct_pelz_msg(PELZ_MSG_DATA msg_data_in,
                                       X509 *local_cert_in,
                                       EVP_PKEY *local_priv_in,
                                       X509 *peer_cert_in,
                                       charbuf *tx_msg_buf)
{
  PelzMessagingStatus construct_status = PELZ_MSG_UNKNOWN_ERROR;

  // check that all input parameters are non-NULL pointers
  if ((local_cert_in == NULL) ||
      (local_priv_in == NULL) ||
      (peer_cert_in == NULL))
  {
    pelz_sgx_log(LOG_ERR, "NULL input parameter");
    return PELZ_MSG_INVALID_PARAM;
  }

  // check that the charbuf pointer is non-NULL
  // if the output buffer is pre-allocated, free it
  if (tx_msg_buf == NULL)
  {
    pelz_sgx_log(LOG_ERR, "invalid output buffer parameter");
    return PELZ_MSG_INVALID_PARAM;
  }
  if (tx_msg_buf->chars != NULL)
  {
    free_charbuf(tx_msg_buf);
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
  charbuf der_asn1_msg = { .chars = NULL, .len = 0 };
  construct_status = der_encode_pelz_msg(asn1_msg,
                                         &der_asn1_msg,
                                         ASN1);
  PELZ_MSG_free(asn1_msg);
  if ((construct_status != PELZ_MSG_OK) ||
      (der_asn1_msg.chars == NULL) ||
      (der_asn1_msg.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "error DER-encoding ASN.1 pelz message");
    return PELZ_MSG_DER_ENCODE_ASN1_ERROR;
  }

  // create signed CMS pelz response message
  CMS_ContentInfo *signed_message = NULL;
  signed_message = create_pelz_signed_msg(der_asn1_msg,
                                          local_cert_in,
                                          local_priv_in);
  free(der_asn1_msg.chars);
  if (signed_message == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error creating signed CMS pelz message");
    return PELZ_MSG_SIGN_ERROR;
  }

  // DER-encode signed CMS pelz response message
  charbuf der_signed_msg = { .chars = NULL, .len = 0 };
  construct_status = der_encode_pelz_msg(signed_message,
                                         &der_signed_msg,
                                         CMS);
  CMS_ContentInfo_free(signed_message);
  if ((construct_status != PELZ_MSG_OK) ||
      (der_signed_msg.chars == NULL) ||
      (der_signed_msg.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "error DER-encoding signed CMS pelz message");
    return PELZ_MSG_DER_ENCODE_CMS_ERROR;
  }

  // CMS encrypt (create enveloped) pelz response message
  CMS_ContentInfo *enveloped_message = NULL;
  enveloped_message = create_pelz_enveloped_msg(der_signed_msg,
                                                peer_cert_in);
  free(der_signed_msg.chars);
  if (enveloped_message == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error creating enveloped pelz CMS message");
    return PELZ_MSG_ENCRYPT_ERROR;
  }

  // DER-encode enveloped CMS pelz response message
  construct_status = der_encode_pelz_msg(enveloped_message,
                                         tx_msg_buf,
                                         CMS);
  CMS_ContentInfo_free(enveloped_message);
  if ((construct_status != PELZ_MSG_OK) ||
      (tx_msg_buf->chars == NULL) ||
      (tx_msg_buf->len == 0))
  {
    pelz_sgx_log(LOG_ERR, "error DER-encoding enveloped CMS pelz response");
    return PELZ_MSG_DER_ENCODE_CMS_ERROR;
  }

  return PELZ_MSG_OK;
}

PelzMessagingStatus deconstruct_pelz_msg(charbuf rcvd_msg_buf_in,
                                         X509 *local_cert_in,
                                         EVP_PKEY *local_priv_in,
                                         X509 **peer_cert_out,
                                         PELZ_MSG_DATA *msg_data_out)
{
  PelzMessagingStatus deconstruct_status = PELZ_MSG_UNKNOWN_ERROR;
  
  // check for NULL (or empty in one case) input parameters
  if((rcvd_msg_buf_in.chars == NULL) ||
     (rcvd_msg_buf_in.len == 0) ||
     (local_cert_in == NULL) ||
     (local_priv_in == NULL))
  {
    pelz_sgx_log(LOG_ERR, "NULL or empty input parameter");
    return PELZ_MSG_INVALID_PARAM;
  }

  // check output parameter validity
  if ((peer_cert_out == NULL) ||
      (msg_data_out == NULL))
  {
    pelz_sgx_log(LOG_ERR, "invalid output parameter");
    return PELZ_MSG_INVALID_PARAM;
  }

  // DER-decode signed, enveloped CMS pelz message
  CMS_ContentInfo *env_msg = NULL;
  env_msg = (CMS_ContentInfo *) der_decode_pelz_msg(rcvd_msg_buf_in,
                                                    CMS);
  if (env_msg == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error DER-decoding enveloped pelz CMS message");
    return PELZ_MSG_DER_DECODE_CMS_ERROR;
  }

  // CMS decrypt enveloped pelz message
  charbuf der_signed_msg = { .chars = NULL, .len = 0 };
  deconstruct_status = decrypt_pelz_enveloped_msg(env_msg,
                                                  local_cert_in,
                                                  local_priv_in,
                                                  &der_signed_msg);
  CMS_ContentInfo_free(env_msg);
  if ((deconstruct_status != PELZ_MSG_OK) ||
      (der_signed_msg.chars == NULL) ||
      (der_signed_msg.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "error decrypting enveloped pelz CMS message");
    return PELZ_MSG_DECRYPT_ERROR;
  }

  // DER-decode decrypted, signed CMS pelz message
  CMS_ContentInfo *signed_msg = NULL;
  signed_msg = (CMS_ContentInfo *) der_decode_pelz_msg(der_signed_msg,
                                                       CMS);
  free(der_signed_msg.chars);
  if (signed_msg == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error DER-decoding decrypted, signed pelz message");
    return PELZ_MSG_DER_DECODE_CMS_ERROR;
  }

  // verify signed CMS pelz message
  charbuf der_asn1_msg = { .chars = NULL, .len = 0 };
  deconstruct_status = verify_pelz_signed_msg(signed_msg,
                                              peer_cert_out,
                                              &der_asn1_msg);
  CMS_ContentInfo_free(signed_msg);
  if ((deconstruct_status != PELZ_MSG_OK) ||
      (der_asn1_msg.chars == NULL) ||
      (der_asn1_msg.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "error verifying signed pelz CMS message");
    return PELZ_MSG_VERIFY_ERROR;
  }

  // DER-decode ASN.1 formatted pelz message
  PELZ_MSG *asn1_msg = NULL;
  asn1_msg = (PELZ_MSG *) der_decode_pelz_msg(der_asn1_msg,
                                              ASN1);
  free(der_asn1_msg.chars);
  if (asn1_msg == NULL)
  {
    pelz_sgx_log(LOG_ERR, "error DER-decoding ASN.1 pelz message");
    return PELZ_MSG_DER_DECODE_ASN1_ERROR;
  }

  // parse ASN.1 formatted pelz request message
  deconstruct_status = parse_pelz_asn1_msg(asn1_msg, msg_data_out);
  PELZ_MSG_free(asn1_msg);
  if (deconstruct_status != PELZ_MSG_OK)
  {
    pelz_sgx_log(LOG_ERR, "error parsing ASN.1 pelz message");
    return PELZ_MSG_ASN1_PARSE_ERROR;
  }

  return PELZ_MSG_OK;
}

