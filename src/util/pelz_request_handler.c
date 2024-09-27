#include "charbuf.h"
#include "pelz_request_handler.h"
#include "pelz_messaging.h"
#include "common_table.h"
#include "cipher/pelz_cipher.h"
#include "pelz_enclave_log.h"
#include "secure_socket_enclave.h"
#include "aes_gcm.h"

#include <openssl/rand.h>

#include "sgx_trts.h"
#include ENCLAVE_HEADER_TRUSTED

RequestResponseStatus service_pelz_request_msg(charbuf req_in,
                                               charbuf *resp_out)
{
  if((req_in.chars == NULL) || (req_in.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "Invalid pelz request message input buffer");
    return REQUEST_RESPONSE_BUFFER_ERROR;
  }

  if (resp_out->chars != NULL)
  {
    pelz_sgx_log(LOG_ERR, "Invalid pelz response message output buffer");
    return REQUEST_RESPONSE_BUFFER_ERROR;
  }

  // Deconstruct (decrypt, verify, parse) received pelz request
  X509 *requestor_cert = NULL;
  PELZ_MSG_DATA rcvd_req_data = { 0 };
  PelzMessagingStatus msg_status = PELZ_MSG_UNKNOWN_ERROR;

  msg_status = deconstruct_pelz_msg(req_in,
                                    pelz_id.cert,
                                    pelz_id.private_pkey,
                                    &requestor_cert,
                                    &rcvd_req_data);
  if (msg_status != PELZ_MSG_OK)
  {
    pelz_sgx_log(LOG_ERR, "deconstruct received pelz request error");
    return REQUEST_RESPONSE_MSG_DECONSTRUCT_ERROR;
  }

  PELZ_MSG_DATA response_data = { .msg_type = RESPONSE,
                                  .req_type = rcvd_req_data.req_type,
                                  .cipher = rcvd_req_data.cipher,
                                  .tag = new_charbuf(0),
                                  .iv = new_charbuf(0),
                                  .key_id = rcvd_req_data.key_id,
                                  .data = new_charbuf(0),
                                  .status = new_charbuf(0) };

  RequestResponseStatus handler_status = REQUEST_RESPONSE_UNKNOWN_ERROR;

  switch (response_data.req_type)
  {
  case KEY_WRAP:
    handler_status = pelz_encrypt_request_handler(response_data.key_id,
                                                  response_data.cipher,
                                                  rcvd_req_data.data,
                                                  &(response_data.data),
                                                  &(response_data.iv),
                                                  &(response_data.tag));
    break;
  case KEY_UNWRAP:
    handler_status = pelz_decrypt_request_handler(response_data.key_id,
                                                  response_data.cipher,
                                                  response_data.iv,
                                                  response_data.tag,
                                                  rcvd_req_data.data,
                                                  &(response_data.data));
    break;
  default:
    pelz_sgx_log(LOG_DEBUG, "invalid request type");
    break;
  }

  if (handler_status != REQUEST_RESPONSE_OK)
  {
    PELZ_MSG_DATA_free(&response_data);
    return handler_status;
  }

  msg_status = construct_pelz_msg(response_data,
                                  pelz_id.cert,
                                  pelz_id.private_pkey,
                                  requestor_cert,
                                  resp_out);
  if (msg_status != PELZ_MSG_OK)
  {
    PELZ_MSG_DATA_free(&response_data);
    return REQUEST_RESPONSE_MSG_CONSTRUCT_ERROR;
  }

  return REQUEST_RESPONSE_OK;
}


RequestResponseStatus pelz_encrypt_request_handler(charbuf key_id,
                                                   charbuf cipher_name,
                                                   charbuf plain_data_in,
                                                   charbuf *cipher_data_out,
                                                   charbuf *iv_out,
                                                   charbuf *tag_out)
{
  // check input plaintext is not NULL or empty
  if ((plain_data_in.chars == NULL) || (plain_data_in.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "plaintext data input NULL or empty");
    return REQUEST_RESPONSE_DATA_ERROR;
  }

  // use input 'cipher name' to create appropriate cipher_t struct
  unsigned char* cipher_name_string = NULL;
  cipher_name_string = null_terminated_string_from_charbuf(cipher_name);
  if(cipher_name_string == NULL)
  {
    pelz_sgx_log(LOG_ERR, "cipher name string missing");
    return REQUEST_RESPONSE_CIPHER_ERROR;
  }
  cipher_t cipher_struct;
  cipher_struct = pelz_get_cipher_t_from_string((char*) cipher_name_string);
  free(cipher_name_string);
  if(cipher_struct.cipher_name == NULL)
  {
    pelz_sgx_log(LOG_ERR, "cipher name in struct missing");
    return REQUEST_RESPONSE_CIPHER_ERROR;
  }

  // use input 'key ID' to retrieve table index for KEK
  size_t index;
  if(key_id.chars == NULL || key_id.len == 0)
  {
    pelz_sgx_log(LOG_ERR, "key ID missing");
    return REQUEST_RESPONSE_KEY_ID_ERROR;
  }
  pelz_sgx_log(LOG_DEBUG, "KEK Load Check");
  if (table_lookup(KEY, key_id, &index))
  {
    pelz_sgx_log(LOG_ERR, "KEK not loaded");
    return REQUEST_RESPONSE_KEK_NOT_LOADED;
  }

  // wrap (encrypt) input data
  cipher_data_t cipher_data_st;
  if (cipher_struct.encrypt_fn(key_table.entries[index].value.key.chars,
                               key_table.entries[index].value.key.len,
                               plain_data_in.chars,
                               plain_data_in.len,
                               &cipher_data_st))
  {
    pelz_sgx_log(LOG_ERR, "Wrap (encrypt) Error");
    free(cipher_data_st.cipher);
    free(cipher_data_st.iv);
    free(cipher_data_st.tag);
    return REQUEST_RESPONSE_WRAP_ERROR;
  }
  if ((cipher_data_st.cipher == NULL) || (cipher_data_st.cipher_len == 0))
  {
    pelz_sgx_log(LOG_ERR, "wrap (encrypt) produced NULL/empty CT buffer");
    free(cipher_data_st.cipher);
    free(cipher_data_st.tag);
    free(cipher_data_st.iv);
    return REQUEST_RESPONSE_WRAP_ERROR;
  }

  // Copy cipher_data_st.cipher to 'cipher_data_out' output parameter
  // (done first because it's the only one that should always be present)
  ocall_malloc(cipher_data_st.cipher_len, &cipher_data_out->chars);
  if (cipher_data_out->chars == NULL)
  {
    free(cipher_data_st.cipher);
    free(cipher_data_st.tag);
    free(cipher_data_st.iv);
    
    cipher_data_out->len = 0;
    pelz_sgx_log(LOG_ERR, "Cipher data allocation error");
    return REQUEST_RESPONSE_MALLOC_ERROR;
  }
  cipher_data_out->len = cipher_data_st.cipher_len;
  memcpy(cipher_data_out->chars, cipher_data_st.cipher, cipher_data_out->len);
  free(cipher_data_st.cipher);

  // create initialization vector (IV) output parameter
  if (cipher_data_st.iv_len > 0 && cipher_data_st.iv != NULL)
  {
    ocall_malloc(cipher_data_st.iv_len, &iv_out->chars);
    if (iv_out->chars == NULL)
    {
      ocall_free(cipher_data_out->chars, cipher_data_out->len);
      cipher_data_out->chars = NULL;
      cipher_data_out->len = 0;
      iv_out->len = 0;
      free(cipher_data_st.iv);
      free(cipher_data_st.tag);
      pelz_sgx_log(LOG_ERR, "IV allocation error");
      return REQUEST_RESPONSE_MALLOC_ERROR;
    }
    iv_out->len = cipher_data_st.iv_len;
    memcpy(iv_out->chars, cipher_data_st.iv, iv_out->len);
  }
  free(cipher_data_st.iv);

  // create cipher 'tag' output parameter
  if (cipher_data_st.tag_len > 0 && cipher_data_st.tag != NULL)
  {
    ocall_malloc(cipher_data_st.tag_len, &tag_out->chars);
    if (tag_out->chars == NULL)
    {
      pelz_sgx_log(LOG_ERR, "Tag allocation error");
      ocall_free(cipher_data_out->chars, cipher_data_out->len);
      cipher_data_out->chars = NULL;
      cipher_data_out->len = 0;
      ocall_free(iv_out->chars, iv_out->len);
      iv_out->chars = NULL;
      iv_out->len = 0;
      tag_out->len = 0;
      free(cipher_data_st.tag);
      return REQUEST_RESPONSE_MALLOC_ERROR;
    }
    tag_out->len = cipher_data_st.tag_len;
    memcpy(tag_out->chars, cipher_data_st.tag, tag_out->len);
  }
  free(cipher_data_st.tag);
  
  pelz_sgx_log(LOG_DEBUG, "Encrypt Request Handler - Successful Completion");
  return REQUEST_RESPONSE_OK;
}

RequestResponseStatus pelz_decrypt_request_handler(charbuf key_id,
                                                   charbuf cipher_name,
                                                   charbuf iv,
                                                   charbuf tag,
                                                   charbuf cipher_data_in,
                                                   charbuf *plain_data_out)
{
  pelz_sgx_log(LOG_DEBUG, "Decrypt Request Handler");

  charbuf plain_data_internal;
  size_t index;

  // use input 'cipher name' to create appropriate cipher_t struct
  unsigned char *cipher_name_string = NULL;
  cipher_name_string = null_terminated_string_from_charbuf(cipher_name);
  if (cipher_name_string == NULL)
  {
    pelz_sgx_log(LOG_ERR, "Cipher name string missing");
    return REQUEST_RESPONSE_CIPHER_ERROR;
  }
  cipher_t cipher_struct = { 0 };
  cipher_struct = pelz_get_cipher_t_from_string((char*)cipher_name_string);
  free(cipher_name_string);
  if (cipher_struct.cipher_name == NULL)
  {
    pelz_sgx_log(LOG_ERR, "Cipher Name in struct missing");
    return REQUEST_RESPONSE_CIPHER_ERROR;
  }

  // use input 'key ID' to retrieve table index for KEK
  if((key_id.chars == NULL) || (key_id.len == 0))
  {
    pelz_sgx_log(LOG_ERR, "Key ID missing");
    return REQUEST_RESPONSE_KEY_ID_ERROR;
  }
  pelz_sgx_log(LOG_DEBUG, "KEK Load Check");
  if (table_lookup(KEY, key_id, &index))
  {
    pelz_sgx_log(LOG_ERR, "KEK not loaded");
    return REQUEST_RESPONSE_KEK_NOT_LOADED;
  }

  // setup cipher data struct for unwrap (decrypt)
  cipher_data_t cipher_data_st;
  cipher_data_st.cipher = cipher_data_in.chars;
  cipher_data_st.cipher_len = cipher_data_in.len;
  cipher_data_st.iv = iv.chars;
  cipher_data_st.iv_len = iv.len;
  cipher_data_st.tag = tag.chars;
  cipher_data_st.tag_len = tag.len;

  pelz_sgx_log(LOG_DEBUG, "cipher unwrap (decrypt)");
  if (cipher_struct.decrypt_fn(key_table.entries[index].value.key.chars,
                               key_table.entries[index].value.key.len,
                               cipher_data_st,
                               &plain_data_internal.chars,
                               &plain_data_internal.len))
  {
    pelz_sgx_log(LOG_ERR, "unwrap (decrypt) error");
    return REQUEST_RESPONSE_UNWRAP_ERROR;
  }

  plain_data_out->len = plain_data_internal.len;
  ocall_malloc(plain_data_out->len, &plain_data_out->chars);
  if (plain_data_out->chars == NULL)
  {
    plain_data_out->len = 0;
    free_charbuf(&plain_data_internal);
    pelz_sgx_log(LOG_ERR, "Plain data missing");
    return REQUEST_RESPONSE_UNWRAP_ERROR;
  }
  memcpy(plain_data_out->chars, plain_data_internal.chars, plain_data_out->len);
  free_charbuf(&plain_data_internal);
  pelz_sgx_log(LOG_DEBUG, "Decrypt Request Handler Successful");
  return REQUEST_RESPONSE_OK;
}
