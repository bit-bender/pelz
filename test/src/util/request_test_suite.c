/*
 * request_test_suite.c
 */

#include "request_test_suite.h"


#include "test_helper_functions.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <charbuf.h>
#include <pelz_log.h>
#include <common_table.h>
#include <pelz_request_handler.h>

#include <openssl/x509.h>
#include <openssl/pem.h>

#include "test_defines.h"

#include "sgx_urts.h"
#include "pelz_enclave.h"
#include "test_enclave_u.h"
#include "kmyth/formatting_tools.h"
#include "ca_table.h"
#include "pelz_loaders.h"

const size_t cipher_list_size = 6;

const char* cipher_str[] = { "AES/KeyWrap/RFC3394NoPadding/256",
                             "AES/KeyWrap/RFC3394NoPadding/192",
                             "AES/KeyWrap/RFC3394NoPadding/128",
                             "AES/GCM/NoPadding/256",
                             "AES/GCM/NoPadding/192",
                             "AES/GCM/NoPadding/128" };

const char* cipher_key_id[] = { "file:/test/data/key1.txt",
                                "file:/test/data/key2.txt",
                                "file:/test/data/key3.txt",
                                "file:/test/data/key4.txt",
                                "file:/test/data/key5.txt",
                                "file:/test/data/key6.txt" };

// Bit of a kludge, we need the correct key lengths to test the
// encrypt/decrypt cycle, but the code to extract them from the cipher
// is only built in the enclave.
const size_t cipher_num_key_bytes[] = { 32, 24, 16, 32, 24, 16 };

// test key data sized for largest key length, will be truncated as needed
const char*  test_key_data = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";


int request_suite_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite,
                          "Test Pelz Request Handling",
                          test_request_handling))
  {
    return (1);
  }

  if (NULL == CU_add_test(suite,
                          "Test Pelz Service Pelz Request",
                          test_service_pelz_request_msg))
  {
    return 1;
  }

  return 0;
}

void test_request_handling(void)
{
  ReqTestStatus result = REQ_TEST_UNKNOWN_ERROR;
  sgx_status_t retval;

  pelz_log(LOG_DEBUG, "start request handler tests");

  TableResponseStatus table_status;

  // initialize the key table as empty
  table_destroy(eid, &table_status, KEY);

  charbuf test_cipher = new_charbuf(strlen(cipher_str[0]));
  memcpy(test_cipher.chars,
         (const unsigned char *) cipher_str[0],
         test_cipher.len);

  charbuf test_key_id = new_charbuf(strlen(cipher_key_id[0]));
  memcpy(test_key_id.chars,
         (const unsigned char *) cipher_key_id[0],
         test_key_id.len);

  // invalid parameter test: NULL input, wrap key ID
  retval = pelz_enclave_req_test_helper(eid,
                                        &result,
                                        test_cipher,
                                        test_key_id,
                                        (uint8_t) REQ_TEST_WRAP_NULL_KEY_ID);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == REQ_TEST_PARAM_HANDLING_OK));

  // invalid parameter test: empty (zero sized) input, wrap key ID
  retval = pelz_enclave_req_test_helper(eid,
                                        &result,
                                        test_cipher,
                                        test_key_id,
                                        (uint8_t) REQ_TEST_WRAP_EMPTY_KEY_ID);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == REQ_TEST_PARAM_HANDLING_OK));

  // invalid parameter test: NULL input, unwrap key ID
  retval = pelz_enclave_req_test_helper(eid,
                                        &result,
                                        test_cipher,
                                        test_key_id,
                                        (uint8_t) REQ_TEST_UNWRAP_NULL_KEY_ID);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == REQ_TEST_PARAM_HANDLING_OK));

  // invalid parameter test: empty (zero sized) input, unwrap key ID
  retval = pelz_enclave_req_test_helper(eid,
                                        &result,
                                        test_cipher,
                                        test_key_id,
                                        (uint8_t) REQ_TEST_UNWRAP_EMPTY_KEY_ID);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == REQ_TEST_PARAM_HANDLING_OK));

  // invalid parameter test: NULL input, wrap cipher name
  retval = pelz_enclave_req_test_helper(eid,
                                        &result,
                                        test_cipher,
                                        test_key_id,
                                        (uint8_t) REQ_TEST_WRAP_NULL_CIPHER_NAME);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == REQ_TEST_PARAM_HANDLING_OK));

  // invalid parameter test: empty (zero sized) input, wrap cipher name
  retval = pelz_enclave_req_test_helper(eid,
                                        &result,
                                        test_cipher,
                                        test_key_id,
                                        (uint8_t) REQ_TEST_WRAP_EMPTY_CIPHER_NAME);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == REQ_TEST_PARAM_HANDLING_OK));

  // invalid parameter test: non-empty, invalid input, wrap cipher name
  retval = pelz_enclave_req_test_helper(eid,
                                        &result,
                                        test_cipher,
                                        test_key_id,
                                        (uint8_t) REQ_TEST_WRAP_INVALID_CIPHER_NAME);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == REQ_TEST_PARAM_HANDLING_OK));

  // invalid parameter test: NULL input, unwrap cipher name
  retval = pelz_enclave_req_test_helper(eid,
                                        &result,
                                        test_cipher,
                                        test_key_id,
                                        (uint8_t) REQ_TEST_UNWRAP_NULL_CIPHER_NAME);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == REQ_TEST_PARAM_HANDLING_OK));

  // invalid parameter test: empty (zero sized) input, unwrap cipher name
  retval = pelz_enclave_req_test_helper(eid,
                                        &result,
                                        test_cipher,
                                        test_key_id,
                                        (uint8_t) REQ_TEST_UNWRAP_EMPTY_CIPHER_NAME);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == REQ_TEST_PARAM_HANDLING_OK));

  // invalid parameter test: non-empty, invalid input, wrap cipher name
  retval = pelz_enclave_req_test_helper(eid,
                                        &result,
                                        test_cipher,
                                        test_key_id,
                                        (uint8_t) REQ_TEST_UNWRAP_INVALID_CIPHER_NAME);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == REQ_TEST_PARAM_HANDLING_OK));

  // invalid parameter test: NULL input, wrap plaintext
  retval = pelz_enclave_req_test_helper(eid,
                                        &result,
                                        test_cipher,
                                        test_key_id,
                                        (uint8_t) REQ_TEST_WRAP_NULL_PT_IN);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == REQ_TEST_PARAM_HANDLING_OK));

  // invalid parameter test: empty (zero sized) input, wrap plaintext
  retval = pelz_enclave_req_test_helper(eid,
                                        &result,
                                        test_cipher,
                                        test_key_id,
                                        (uint8_t) REQ_TEST_WRAP_EMPTY_PT_IN);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == REQ_TEST_PARAM_HANDLING_OK));

  // invalid parameter test: NULL input, unwrap ciphertext
  retval = pelz_enclave_req_test_helper(eid,
                                        &result,
                                        test_cipher,
                                        test_key_id,
                                        (uint8_t) REQ_TEST_UNWRAP_NULL_CT_IN);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == REQ_TEST_PARAM_HANDLING_OK));

  // invalid parameter test: empty (zero sized) input, unwrap ciphertext
  retval = pelz_enclave_req_test_helper(eid,
                                        &result,
                                        test_cipher,
                                        test_key_id,
                                        (uint8_t) REQ_TEST_UNWRAP_EMPTY_CT_IN);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == REQ_TEST_PARAM_HANDLING_OK));

  // invalid parameter test: invalid (not loaded) input, wrapkey ID
  retval = pelz_enclave_req_test_helper(eid,
                                        &result,
                                        test_cipher,
                                        test_key_id,
                                        (uint8_t) REQ_TEST_WRAP_INVALID_KEY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == REQ_TEST_PARAM_HANDLING_OK));

  // invalid parameter test: invalid (not loaded) input, unwrap key ID
  retval = pelz_enclave_req_test_helper(eid,
                                        &result,
                                        test_cipher,
                                        test_key_id,
                                        (uint8_t) REQ_TEST_UNWRAP_INVALID_KEY);
  CU_ASSERT((retval == SGX_SUCCESS) && (result == REQ_TEST_PARAM_HANDLING_OK));

  // test encrypt/decrypt handler functionality for all test ciphers
  for (size_t cipher_index = 0;
       cipher_index < cipher_list_size;
       cipher_index++)
  {
    free(test_cipher.chars);
    test_cipher.len = strlen(cipher_str[cipher_index]);
    test_cipher.chars = calloc(test_cipher.len, sizeof(unsigned char));
    memcpy(test_cipher.chars,
           (const unsigned char *) cipher_str[cipher_index],
           test_cipher.len);

    charbuf test_key = new_charbuf(cipher_num_key_bytes[cipher_index]);
    memcpy(test_key.chars, test_key_data, test_key.len);

    free(test_key_id.chars);
    test_key_id.len = strlen(cipher_key_id[cipher_index]);
    test_key_id.chars = calloc(test_key_id.len, sizeof(unsigned char));
    if (test_key_id.chars == NULL)
    {
      CU_FAIL("error allocating memory for test key ID");
    }
    memcpy(test_key_id.chars,
           (const unsigned char *) cipher_key_id[cipher_index],
           test_key_id.len);

    key_table_add_key(eid,
                      &table_status,
                      test_key_id,
                      test_key);
    free_charbuf(&test_key);

    retval = pelz_enclave_req_test_helper(eid,
                                          &result,
                                          test_cipher,
                                          test_key_id,
                                          (uint8_t) REQ_TEST_WRAP_FUNCTIONALITY);
    CU_ASSERT((retval == SGX_SUCCESS) && (result == REQ_TEST_OK));

    retval = pelz_enclave_req_test_helper(eid,
                                          &result,
                                          test_cipher,
                                          test_key_id,
                                          (uint8_t) REQ_TEST_UNWRAP_FUNCTIONALITY);
    CU_ASSERT((retval == SGX_SUCCESS) && (result == REQ_TEST_OK));

    retval = pelz_enclave_req_test_helper(eid,
                                          &result,
                                          test_cipher,
                                          test_key_id,
                                          (uint8_t) REQ_TEST_WRAP_UNWRAP);
    CU_ASSERT((retval == SGX_SUCCESS) && (result == REQ_TEST_OK));

    if (table_delete(eid, &table_status, KEY, test_key_id) != 0)
    {
      CU_FAIL("error deleting test key from table");
    }
  }
  
  // clean-up key table (should already be empty)
  table_destroy(eid, &table_status, KEY);

}

void test_service_pelz_request_msg(void)
{
  // create requestor's test cert/key inputs
  //   - req_cert:  requestor's public key (certificate)
  //   - req_priv:  requestor's private key
  charbuf req_cert = new_charbuf(0);
  charbuf req_priv = new_charbuf(0);
  int ret = keypair_pem_to_der("test/data/msg_test_req_pub.pem",
                               "test/data/msg_test_req_priv.pem",
                               &req_cert,
                               &req_priv);
  if ((ret != 0) || (req_cert.chars == NULL) || (req_priv.chars == NULL))
  {
    CU_FAIL("error reading in test requestor key/cert from file");
  }

  // load CA cert into enclave table
  TableResponseStatus table_status;
  uint64_t priv_handle = 0, cert_handle = 0;

  if (pelz_load_file_to_enclave("test/data/ca_pub.der.nkl", &priv_handle) == 0)
  {
    add_cert_to_table(eid, &table_status, CA_TABLE, priv_handle);
    CU_ASSERT(table_status == OK);
    priv_handle = 0;
    pelz_log(LOG_INFO, "loaded correct CA certificate");
  }
  else
  {
    CU_FAIL("unable to load CA cert into enclave table");
  }

  // load private key and certificate for pelz service
  if(get_file_handle("test/data/msg_test_resp_priv.der.nkl", &priv_handle) &&
     get_file_handle("test/data/msg_test_resp_pub.der.nkl", &cert_handle))
  {
    private_pkey_init(eid, &table_status);
    CU_ASSERT(table_status == OK);
    private_pkey_add(eid, &table_status, priv_handle, cert_handle);
    CU_ASSERT(table_status == OK);
    pelz_log(LOG_INFO, "configured private key and cert for pelz service");
    priv_handle = 0;
    cert_handle = 0;
  }
  else
  {
    CU_FAIL("error configuring private key and cert for pelz service");
  }

  ReqTestStatus req_test_result = REQ_TEST_UNKNOWN_ERROR;
  sgx_status_t retval;

  // test service_pelz_request_msg() for all test ciphers
  for (size_t cipher_index = 0;
       cipher_index < cipher_list_size;
       cipher_index++)
  {
    charbuf test_cipher = new_charbuf(strlen(cipher_str[cipher_index]));
    memcpy(test_cipher.chars,
           (const unsigned char *) cipher_str[cipher_index],
           test_cipher.len);

    charbuf test_key_id = new_charbuf(strlen(cipher_key_id[cipher_index]));
    memcpy(test_key_id.chars,
           (const unsigned char *) cipher_key_id[cipher_index],
           test_key_id.len);

    charbuf test_key = new_charbuf(cipher_num_key_bytes[cipher_index]);
    memcpy(test_key.chars, test_key_data, test_key.len);

    key_table_add_key(eid,
                      &table_status,
                      test_key_id,
                      test_key);
    free_charbuf(&test_key);

    retval = pelz_enclave_service_test_helper(eid,
                                              &req_test_result,
                                              test_cipher,
                                              test_key_id,
                                              req_cert,
                                              req_priv);

    CU_ASSERT((retval == SGX_SUCCESS) && (req_test_result == REQ_TEST_OK));

    table_delete(eid, &table_status, KEY, test_key_id);
    if (table_status != OK)
    {
      CU_FAIL("error deleting test key from key table");
    }

    free_charbuf(&test_cipher);
    free_charbuf(&test_key_id);
  }

  free_charbuf(&req_cert);
  free_charbuf(&req_priv);

  if (empty_CA_table(eid, NULL) != 0)
  {
    CU_FAIL("error emptying CA table");
  }
}
