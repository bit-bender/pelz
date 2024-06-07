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

#include <stdio.h>

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
    return VERIFY_SIG_INVALID_PARAMETER;
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
    return VERIFY_SIG_CONTENT_TYPE_ERROR;
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
    return VERIFY_SIG_VERIFY_ERROR;
  }
  X509_STORE_free(v_store);

  int bio_data_size = BIO_pending(verify_out_bio);
  if (bio_data_size <= 0)
  {
    pelz_sgx_log(LOG_ERR, "invalid or empty data result of CMS_verify()");
    BIO_free(verify_out_bio);
    return VERIFY_SIG_INVALID_DATA_RESULT;
  }

  if (data_out == NULL)
  {
    data_out = (uint8_t **) malloc(sizeof(uint8_t *));
    if (data_out == NULL)
    {
      pelz_sgx_log(LOG_ERR, "memory allocation of verified data buffer failed");
      BIO_free(verify_out_bio);
      return VERIFY_SIG_MALLOC_ERROR;   
    }
  }
  *data_out = (uint8_t *) calloc((size_t) bio_data_size, sizeof(uint8_t));
  if (*data_out == NULL)
  {
    pelz_sgx_log(LOG_ERR, "memory allocation of verified data buffer failed");
    BIO_free(verify_out_bio);
    return VERIFY_SIG_MALLOC_ERROR;
  }

  int data_out_size = BIO_read(verify_out_bio, *data_out, bio_data_size);
  if (data_out_size <= 0)
  {
    pelz_sgx_log(LOG_ERR, "BIO_read() error");
    free(*data_out);
    BIO_free(verify_out_bio);
    return VERIFY_SIG_BIO_READ_ERROR;
  }

  BIO_free(verify_out_bio);

  pelz_sgx_log(LOG_DEBUG, "verified received CMS signed request");

  return data_out_size;
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
