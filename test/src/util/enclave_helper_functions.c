/*
 * enclave_helper_functions.c
 */

#include "enclave_helper_functions.h"

#include "common_table.h"
#include "charbuf.h"

#include "sgx_trts.h"
#include "test_enclave_t.h"
#include "cipher/pelz_cipher.h"
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

int test_create_signed_data_msg_helper(size_t test_data_in_len,
                                       uint8_t *test_data_in,
                                       size_t test_der_sign_cert_len,
                                       const uint8_t *test_der_sign_cert,
                                       size_t test_der_sign_priv_len,
                                       const uint8_t *test_der_sign_priv)
{
  X509 *test_cert = NULL;
  if ((test_der_sign_cert != NULL) && (test_der_sign_cert_len != 0))
  {
    d2i_X509(&test_cert, &test_der_sign_cert, (int) test_der_sign_cert_len);
    if (test_cert == NULL)
    {
      return SIGN_TEST_INVALID_DER_CERT;
    }
  }

  EVP_PKEY *test_priv = NULL;
  if ((test_der_sign_priv != NULL) && (test_der_sign_priv_len != 0))
  {
    d2i_PrivateKey(EVP_PKEY_EC,
                   &test_priv,
                   &test_der_sign_priv,
                   (int) test_der_sign_priv_len);
    if (test_priv == NULL)
    {
      return SIGN_TEST_INVALID_DER_PRIV;
    }
  }

  CMS_ContentInfo *signed_msg = NULL;
  signed_msg = create_signed_data_msg(test_data_in,
                                      (int) test_data_in_len,
                                      test_cert,
                                      test_priv);

  if (signed_msg == NULL)
  {
    return SIGN_TEST_FAILURE;
  }

  if (OBJ_obj2nid(CMS_get0_type(signed_msg)) != NID_pkcs7_signed)
  {
    return SIGN_TEST_INVALID_RESULT;
  }

  ASN1_OCTET_STRING *signed_content = NULL;
  signed_content = *(CMS_get0_content(signed_msg));
  if (signed_content == NULL)
  {
    return SIGN_TEST_PARSE_ERROR;
  }
  const unsigned char * signed_data = NULL;
  signed_data = ASN1_STRING_get0_data((const ASN1_STRING *) signed_content);
  if (memcmp(test_data_in, signed_data, test_data_in_len) != 0)
  {
    return SIGN_TEST_INVALID_RESULT;
  }

  return SIGN_TEST_SUCCESS;

}