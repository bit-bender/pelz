/*
 * @file secure_socket_enclave.h
 */

#ifndef INCLUDE_SECURE_SOCKET_ENCLAVE_H_
#define INCLUDE_SECURE_SOCKET_ENCLAVE_H_

#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_eid.h"
#include "sgx_ecp_types.h"
#include "sgx_thread.h"
#include "sgx_dh.h"
#include "sgx_tcrypto.h"

#include "charbuf.h"
#include "dh_error_codes.h"
#include "pelz_request_handler.h"
#include "secure_socket_ecdh.h"
#include "pelz_enclave_log.h"

#include ENCLAVE_HEADER_TRUSTED

#define MAX_SESSION_COUNT 16
#define HKDF_SALT "pelz"

ATTESTATION_STATUS generate_session_id(uint32_t *session_id);

uint32_t verify_peer_enclave_trust(
           sgx_dh_session_enclave_identity_t* peer_enclave_identity,
           sgx_measurement_t *self_mr_signer);

/**
 * <pre>
 * Perform attestation layer decryption on received secure socket
 * pelz request message to recover DER-encoded, CMS signed and enveloped
 * pelz request payload.
 * <pre>
 *
 * @param[in]  session_id       session identifier (number) for the
 *                              incoming request message being handled
 *
 * @param[in]  la_msg_in        a pointer to the incoming local attestation
 *                              pelz request message buffer
 *
 * @param[in]  la_msg_in_size   size of the received local attestion pelz
 *                              request message
 *
 * @return 0 on success, an error number indicating the type of error otherwise.
 */
ATTESTATION_STATUS handle_la_pelz_request_in(uint32_t session_id,
                                             secure_message_t *la_msg_in,
                                             size_t la_msg_in_size);

/**
 * <pre>
 * Construct an outgoing message containing data stored in the session object.
 * <pre>
 *
 * @param[in]  session_id              pointer to the session state for the
 *                                     outgoing response message being handled
 * @param[in]  max_payload_size        the maximum size of the outgoing message payload
 * @param[in]  resp_msg_max_size       the maximum size of the outgoing message
 * @param[out] resp_msg                a pointer to the constructed outgoing
 *                                     message, allocated inside the call
 * @param[out] resp_msg_size           the size of the constructed outgoing message
 *
 * @return 0 on success, an error number indicating the type of error otherwise.
 */
ATTESTATION_STATUS handle_la_pelz_response_out(uint32_t session_id,
                                               size_t max_payload_size,
                                               size_t resp_msg_max_size,
                                               secure_message_t **la_msg_out,
                                               size_t *la_msg_out_size);

uint32_t get_protection_key(uint32_t session_id,
                            uint8_t **key_out,
                            size_t *key_size);

ATTESTATION_STATUS get_request_data(uint32_t session_id,
                                    char **request_data,
                                    size_t *request_data_length);

ATTESTATION_STATUS save_response_data(uint32_t session_id,
                                      char *response_data,
                                      size_t response_data_length);

uint32_t derive_protection_key(uint8_t *key_in,
                               size_t key_in_len,
                               uint8_t **key_out,
                               size_t key_out_len);

#endif
