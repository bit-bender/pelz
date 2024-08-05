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
 * Process an incoming secure socket pelz request message.
 * <pre>
 *
 * @param[in] session_id        the session identifier
 * @param[in] req_message       a pointer to the incoming message
 * @param[in] req_message_size  the size of the incoming message
 *
 * @return 0 on success, an error number indicating the type of error otherwise.
 */
ATTESTATION_STATUS handle_incoming_msg(uint32_t session_id,
                                       secure_message_t *req_message,
                                       size_t req_message_size);

/**
 * <pre>
 * Construct an outgoing message containing data stored in the session object.
 * <pre>
 *
 * @param[in]  session_id              the session identifier
 * @param[in]  max_payload_size        the maximum size of the outgoing message payload
 * @param[in]  resp_message_max_size   the maximum size of the outgoing message
 * @param[out] resp_message            a pointer to the constructed outgoing message, allocated inside the call
 * @param[out] resp_message_size       the size of the constructed outgoing message
 *
 * @return 0 on success, an error number indicating the type of error otherwise.
 */
ATTESTATION_STATUS handle_outgoing_msg(uint32_t session_id,
                                       size_t max_payload_size,
                                       size_t resp_message_max_size,
                                       secure_message_t **resp_message,
                                       size_t *resp_message_size);

uint32_t get_protection_key(uint32_t session_id,
                            uint8_t **key_out,
                            size_t *key_size);

#endif
