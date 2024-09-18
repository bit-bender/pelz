/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/* Note: much of this code is adapted from linux-sgx/SampleCode/
 *       LocalAttestation/EnclaveResponder/EnclaveMessageExchange.cpp
 */

#include "secure_socket_enclave.h"

#include ENCLAVE_HEADER_TRUSTED

// array of pointers to session info
dh_session_t *dh_sessions[MAX_SESSION_COUNT] = { 0 };

//Handle the request from Source Enclave for a session
ATTESTATION_STATUS session_request(sgx_dh_msg1_t *dh_msg1,
                                   uint32_t *session_id)
{
  dh_session_t *session_info;
  sgx_dh_session_t sgx_dh_session;
  sgx_status_t status = SGX_SUCCESS;

  if(!session_id || !dh_msg1)
  {
    return INVALID_PARAMETER_ERROR;
  }
  //Intialize the session as a session responder
  status = sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &sgx_dh_session);
  if(SGX_SUCCESS != status)
  {
    return status;
  }

  //get a new SessionID
  if ((status = (sgx_status_t) generate_session_id(session_id)) != SUCCESS)
      return status; //no more sessions available

  //Allocate session info and store in the tracker
  session_info = (dh_session_t *)calloc(1, sizeof(dh_session_t));
  if(!session_info)
  {
    return MALLOC_ERROR;
  }

  // memset(session_info, 0, sizeof(dh_session_t));
  session_info->session_id = *session_id;
  session_info->status = IN_PROGRESS;

  //Generate Message1 that will be returned to Source Enclave
  status = sgx_dh_responder_gen_msg1((sgx_dh_msg1_t*)dh_msg1, &sgx_dh_session);
  if (SGX_SUCCESS != status)
  {
    SAFE_FREE(session_info);
    return status;
  }
  memcpy(&session_info->in_progress.dh_session,
         &sgx_dh_session,
         sizeof(sgx_dh_session_t));
  dh_sessions[*session_id] = session_info;

  return status;
}

//Verify Message 2, generate Message3 and exchange Message 3 with Source Enclave
ATTESTATION_STATUS exchange_report(sgx_dh_msg2_t *dh_msg2,
                                   sgx_dh_msg3_t *dh_msg3,
                                   uint32_t session_id)
{

  sgx_key_128bit_t dh_aek;   // Session key
  dh_session_t *session_info;
  ATTESTATION_STATUS status = SUCCESS;
  sgx_dh_session_t sgx_dh_session;
  sgx_dh_session_enclave_identity_t initiator_identity;

  if (!dh_msg2 || !dh_msg3)
  {
    return INVALID_PARAMETER_ERROR;
  }

  memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
  do
  {
    //Retrieve the session information for the corresponding session id
    session_info = dh_sessions[session_id];

    if ((session_info == NULL) || (session_info->status != IN_PROGRESS))
    {
      status = INVALID_SESSION;
      break;
    }

    memcpy(&sgx_dh_session,
           &session_info->in_progress.dh_session,
           sizeof(sgx_dh_session_t));

    dh_msg3->msg3_body.additional_prop_length = 0;
    //Process message 2 from source enclave and obtain message 3
    sgx_status_t se_ret = sgx_dh_responder_proc_msg2(dh_msg2,
                                                     dh_msg3,
                                                     &sgx_dh_session,
                                                     &dh_aek,
                                                     &initiator_identity);
    if (SGX_SUCCESS != se_ret)
    {
      status = se_ret;
      break;
    }

    sgx_measurement_t *self_mr_signer = &dh_msg3->msg3_body.report.body.mr_signer;

    //Verify source enclave's trust
    if (verify_peer_enclave_trust(&initiator_identity, self_mr_signer) != SUCCESS)
    {
      return INVALID_SESSION;
    }

    //save the session ID, status and initialize the session nonce
    session_info->session_id = session_id;
    session_info->status = ACTIVE;
    session_info->active.counter = 0;
    memcpy(session_info->active.AEK, &dh_aek, sizeof(sgx_key_128bit_t));
    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
  } while(0);

  if (status != SUCCESS)
  {
    end_session(session_id);
  }

  return status;
}

//Process an incoming message and store data in the session object
ATTESTATION_STATUS secure_socket_pelz_request(uint32_t session_id,
                                              secure_message_t *req_in,
                                              size_t req_in_size,
                                              size_t max_payload_size,
                                              size_t max_resp_message_size,
                                              secure_message_t **resp_out,
                                              size_t *resp_out_size)
{
  // extract pelz request message from incoming local attestation message
  // (result storred to session state)
  ATTESTATION_STATUS result = handle_la_pelz_request_in(session_id,
                                                        req_in,
                                                        req_in_size);
  if (result != SUCCESS)
  {
    return result;
  }

  // get (copy) pelz requqest message from session state
  charbuf req_buf = new_charbuf(0);
  result = get_request_data(session_id,
                            (char **) &(req_buf.chars),
                            &(req_buf.len));
  if (result != SUCCESS)
  {
    return result;
  }

  // service received pelz request (generate appropriate pelz response)
  charbuf resp_buf = new_charbuf(0);

  RequestResponseStatus handler_result = service_pelz_request_msg(req_buf,
                                                                 &resp_buf);
  free_charbuf(&req_buf);
  if (handler_result != REQUEST_RESPONSE_OK)
  {
    free_charbuf(&resp_buf);
    return ERROR_REQUEST_SERVICE;
  }

  // save (copy) constructed pelz response message to session state
  result = save_response_data(session_id,
                              (char *) resp_buf.chars,
                              resp_buf.len);
  free_charbuf(&resp_buf);
  if (result != SUCCESS)
  {
    return result;
  }

  result = handle_la_pelz_response_out(session_id,
                                       max_payload_size,
                                       max_resp_message_size,
                                       resp_out,
                                       resp_out_size);
  if (result != SUCCESS)
  {
    pelz_sgx_log(LOG_ERR, "handle_outgoing_msg error");
    free(*resp_out);
    *resp_out = NULL;
    return result;
  }

  return SUCCESS;
}

ATTESTATION_STATUS handle_la_pelz_request_in(uint32_t session_id,
                                             secure_message_t *la_msg_in,
                                             size_t la_msg_in_size)
{
  dh_session_t *session_info;

  // retrieve the session information for the corresponding session id
  session_info = dh_sessions[session_id];
  if ((session_info == NULL) ||
      (session_info->status != ACTIVE))
  {
    return INVALID_SESSION;
  }

  uint8_t *decrypted_data = NULL;
  uint32_t decrypted_data_length = 0;

  sgx_status_t status;

  if ((la_msg_in == NULL) || (la_msg_in_size == 0))
  {
    return INVALID_PARAMETER_ERROR;
  }

  // set the decrypted data length to the payload size obtained from message
  decrypted_data_length = la_msg_in->message_aes_gcm_data.payload_size;

  // verify the size of the payload
  size_t header_size;
  size_t expected_payload_size;

  header_size = sizeof(secure_message_t);
  expected_payload_size = la_msg_in_size - header_size;
  if (expected_payload_size != decrypted_data_length)
  {
    return INVALID_PARAMETER_ERROR;
  }

  // allocate and initialize buffer to hold decrypted result
  decrypted_data = (uint8_t *) calloc(decrypted_data_length, sizeof(uint8_t));
  if (!decrypted_data)
  {
    return MALLOC_ERROR;
  }

  // decrypt the request message payload from source enclave
  status = sgx_rijndael128GCM_decrypt(
             &session_info->active.AEK,
             la_msg_in->message_aes_gcm_data.payload,
             decrypted_data_length,
             decrypted_data,
             (uint8_t *) (&(la_msg_in->message_aes_gcm_data.reserved)),
             sizeof(la_msg_in->message_aes_gcm_data.reserved),
             NULL,
             0,
             &la_msg_in->message_aes_gcm_data.payload_tag);

  if (status != SGX_SUCCESS)
  {
    SAFE_FREE(decrypted_data);
    return status;
  }

  // verify if the nonce obtained in the request is equal to the session nonce
  if ((*((uint32_t *) la_msg_in->message_aes_gcm_data.reserved) !=
                                        session_info->active.counter) ||
      (*((uint32_t *) la_msg_in->message_aes_gcm_data.reserved) >
                                        ((uint32_t) -2)))
  {
    SAFE_FREE(decrypted_data);
    return INVALID_PARAMETER_ERROR;
  }

  // store plaintext in session object
  if (session_info->request_data != NULL)
  {
    SAFE_FREE(session_info->request_data);
  }

  session_info->request_data = (char *) decrypted_data;
  session_info->request_data_length = decrypted_data_length;

  return SUCCESS;
}

// construct an outgoing message containing data stored in the session object
ATTESTATION_STATUS handle_la_pelz_response_out(uint32_t session_id,
                                               size_t max_payload_size,
                                               size_t resp_msg_max_size,
                                               secure_message_t **la_msg_out,
                                               size_t *la_msg_out_size)
{
  sgx_status_t status;
  dh_session_t *session_info;

  // retrieve the session information for the corresponding session id
  session_info = dh_sessions[session_id];
  if ((session_info == NULL) ||
      (session_info->status != ACTIVE) ||
      (session_info->response_data == NULL))
  {
    return INVALID_SESSION;
  }

  // retrieve the response message data from session state and validate
  char *resp_data = session_info->response_data;
  size_t resp_data_size = session_info->response_data_length;

  if ((resp_data_size > max_payload_size) || (resp_data_size == 0))
  {
    return OUT_BUFFER_LENGTH_ERROR;
  }

  // if output message buffer not NULL, free it (prepare for new contents)

  // calculate secure (local attestation) response message size
  size_t msg_out_size = sizeof(secure_message_t) + resp_data_size;

  if (msg_out_size > resp_msg_max_size)
  {
    return OUT_BUFFER_LENGTH_ERROR;
  }

  // allocate buffer for local attestation response back to the source enclave
  secure_message_t *msg_out = (secure_message_t *) calloc(msg_out_size, 1);
  if (msg_out == NULL)
  {
    return MALLOC_ERROR;
  }

  // build local attestation response message
  const uint32_t data2encrypt_length = (uint32_t) resp_data_size;
  msg_out->session_id = session_info->session_id;
  msg_out->message_aes_gcm_data.payload_size = data2encrypt_length;

  // increment the Session Nonce (Replay Protection)
  session_info->active.counter++;

  // set the updated session nonce as the response nonce
  memcpy(&(msg_out->message_aes_gcm_data.reserved),
         &session_info->active.counter,
         sizeof(session_info->active.counter));

  // prepare the response message with the encrypted payload
  status = sgx_rijndael128GCM_encrypt(
             &session_info->active.AEK,
             (uint8_t*) resp_data,
             data2encrypt_length,
             (uint8_t *) (&(msg_out->message_aes_gcm_data.payload)),
             (uint8_t *) (&(msg_out->message_aes_gcm_data.reserved)),
             sizeof(msg_out->message_aes_gcm_data.reserved),
             NULL,
             0,
             &(msg_out->message_aes_gcm_data.payload_tag));

  if(SGX_SUCCESS != status)
  {
    SAFE_FREE(msg_out);
    return status;
  }

  // assign local attestation response message to output parameter
  if (*la_msg_out != NULL)
  {
    SAFE_FREE(*la_msg_out);
  }
  *la_msg_out = msg_out;
  *la_msg_out_size = msg_out_size;

  return SUCCESS;
}

// respond to the request from the Source Enclave to close the session
ATTESTATION_STATUS end_session(uint32_t session_id)
{
  ATTESTATION_STATUS status = SUCCESS;
  dh_session_t *session_info;

  //Retrieve the session information for the corresponding session id
  session_info = dh_sessions[session_id];

  if (session_info == NULL)
  {
    status = INVALID_SESSION;
  }

  // erase the session information for the current session
  dh_sessions[session_id] = NULL;
  memset(session_info, 0, sizeof(dh_session_t));
  SAFE_FREE(session_info);

  return status;
}


// returns a new sessionID for the source destination session
ATTESTATION_STATUS generate_session_id(uint32_t *session_id)
{
  ATTESTATION_STATUS status = SUCCESS;

  if (!session_id)
  {
    return INVALID_PARAMETER_ERROR;
  }

  // find the first unused entry in the session info array, and use the index as the session id
  for (size_t i = 0; i < MAX_SESSION_COUNT; i++)
  {
    if (dh_sessions[i] == NULL)
    {
      // We know MAX_SESSION_COUNT does not exceed the UINT32_MAX (it's
      // hard coded at the top of this file) so the conversion here is safe.
      *session_id = (uint32_t) i;
      return status;
    }
  }

  status = NO_AVAILABLE_SESSION_ERROR;

  return status;
}

/* Function Description:
 *   this is to verify peer enclave's identity
 * For demonstration purpose, we verify below points:
 *   1. peer enclave's MRSIGNER is as expected
 *   2. peer enclave's PROD_ID is as expected
 *   3. peer enclave's attribute is reasonable that it should be INITIALIZED and without DEBUG attribute (except the project is built with DEBUG option)
 */
uint32_t verify_peer_enclave_trust(
           sgx_dh_session_enclave_identity_t* peer_enclave_identity,
           sgx_measurement_t *self_mr_signer)
{
  if (!peer_enclave_identity)
  {
    return INVALID_PARAMETER_ERROR;
  }

  // Check that both enclaves have the same MRSIGNER value
  if (memcmp((uint8_t *) &peer_enclave_identity->mr_signer,
             (uint8_t*) self_mr_signer,
             sizeof(sgx_measurement_t)))
  {
    return ENCLAVE_TRUST_ERROR;
  }

  if ((peer_enclave_identity->isv_prod_id != 0) ||
      (!(peer_enclave_identity->attributes.flags & SGX_FLAGS_INITTED)))
  {
    return ENCLAVE_TRUST_ERROR;
  }

  // check the enclave isn't loaded in enclave debug mode, except that the project is built for debug purpose
#if defined(NDEBUG)
  if (peer_enclave_identity->attributes.flags & SGX_FLAGS_DEBUG)
  {
    return ENCLAVE_TRUST_ERROR;
  }
#endif

  return SUCCESS;
}

ATTESTATION_STATUS get_request_data(uint32_t session_id,
                                    char **request_data,
                                    size_t *request_data_length)
{
  dh_session_t *session_info;

  // retrieve the session information for the corresponding session id
  session_info = dh_sessions[session_id];
  if ((session_info == NULL) ||
      (session_info->status != ACTIVE) ||
      (session_info->request_data == NULL) ||
      (session_info->request_data_length == 0))
  {
    return INVALID_SESSION;
  }

  // validate output request data buffer parameters
  if ((request_data == NULL) || (request_data_length == NULL))
  {
    return INVALID_PARAMETER_ERROR;
  }

  // get request data size
  size_t buf_size = session_info->request_data_length;

  // if output request data buffer passed in is not NULL/empty,
  // initialize to be that way
  if (*request_data != NULL)
  {
    SAFE_FREE(*request_data);
  }
  *request_data = calloc(buf_size, sizeof(uint8_t));
  if (*request_data == NULL)
  {
    return MALLOC_ERROR;
  }

  // assign response data/length to output parameters
  memcpy(*request_data, session_info->request_data, buf_size);
  *request_data_length = buf_size;

  return SUCCESS;
}

ATTESTATION_STATUS save_response_data(uint32_t session_id,
                                      char *response_data,
                                      size_t response_data_length)
{
  dh_session_t *session_info;

  // retrieve the session information for the corresponding session id
  session_info = dh_sessions[session_id];
  if ((session_info == NULL) ||
      (session_info->status != ACTIVE) ||
      (session_info->request_data == NULL))
  {
    return INVALID_SESSION;
  }

  if (session_info->response_data != NULL)
  {
    SAFE_FREE(session_info->response_data);
  }

  session_info->response_data = malloc(response_data_length);
  if (!session_info->response_data)
  {
    return MALLOC_ERROR;
  }

  memcpy(session_info->response_data, response_data, response_data_length);
  session_info->response_data_length = response_data_length;

  return SUCCESS;
}

uint32_t derive_protection_key(uint8_t *key_in,
                               size_t key_in_len,
                               uint8_t **key_out,
                               size_t key_out_len)
{
  EVP_PKEY_CTX *pctx;

  pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
  if (pctx == NULL)
  {
    return EXIT_FAILURE;
  }

  // initialize HKDF context
  if (EVP_PKEY_derive_init(pctx) != 1)
  {
    EVP_PKEY_CTX_free(pctx);
    return EXIT_FAILURE;
  }

  // set message digest for HKDF
  if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha512()) != 1)
  {
    EVP_PKEY_CTX_free(pctx);
    return EXIT_FAILURE;
  }

  // set 'salt' value for HKDF
  if (EVP_PKEY_CTX_set1_hkdf_salt(pctx,
                                  (const unsigned char *) HKDF_SALT,
                                  strlen(HKDF_SALT)) != 1)
  {
    EVP_PKEY_CTX_free(pctx);
    return EXIT_FAILURE;
  }

  // set input key value for HKDF
  if (EVP_PKEY_CTX_set1_hkdf_key(pctx, key_in, (int) key_in_len) != 1)
  {
    EVP_PKEY_CTX_free(pctx);
    return EXIT_FAILURE;
  }

  // derive key bits
  uint8_t *tmp_key_out = calloc(key_out_len, sizeof(uint8_t));
  size_t tmp_key_out_len = key_out_len;
  if (EVP_PKEY_derive(pctx, tmp_key_out, &tmp_key_out_len) != 1)
  {
    EVP_PKEY_CTX_free(pctx);
    free(tmp_key_out);
    return EXIT_FAILURE;
  }

  EVP_PKEY_CTX_free(pctx);

  if (tmp_key_out_len != key_out_len)
  {
    free(tmp_key_out);
    return EXIT_FAILURE;
  }

  *key_out = tmp_key_out;

  return EXIT_SUCCESS;
}

uint32_t get_protection_key(uint32_t session_id,
                            uint8_t **key_out,
                            size_t *key_size)
{
  dh_session_t *session_info;

  //Retrieve the session information for the corresponding session id
  session_info = dh_sessions[session_id];
  if((session_info == NULL) ||
     (session_info->status != ACTIVE) ||
     (session_info->request_data == NULL))
  {
    *key_size = 0;
    *key_out = NULL;
    return EXIT_FAILURE;
  }

  *key_size = sizeof(session_info->active.AEK);
  return derive_protection_key((uint8_t *) session_info->active.AEK,
                               *key_size,
                               key_out,
                               *key_size);
}
