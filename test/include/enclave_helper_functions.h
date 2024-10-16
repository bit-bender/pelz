#ifndef _ENCLAVE_HELPER_FUNCIONS_H_
#define _ENCLAVE_HELPER_FUNCTIONS_H_

#include <openssl/cms.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include "cipher/pelz_cipher.h"
#include "common_table.h"
#include "charbuf.h"
#include "pelz_enclave_log.h"
#include "pelz_messaging.h"

#include "sgx_trts.h"
#include "test_enclave_t.h"

#include "test_defines.h"

/**
 * <pre>
 * This function converts a DER-formatted certificate into an OpenSSL
 * X509 struct.
 * </pre>
 *
 * @param[in]  der_cert       charbuf (byte array and size) struct containing
 *                            DER-formatted data bytes for the certificate.
 *
 * @return                    pointer to converted X509 certificate on success,
 *                            NULL on failure
 */
X509 *deserialize_cert(charbuf der_cert);

/**
 * <pre>
 * This function converts a DER-formatted private key into an OpenSSL
 * EVP_PKEY struct.
 * </pre>
 *
 * @param[in]  der_pkey       charbuf (byte array and size) struct containing
 *                            DER-formatted data bytes for the private key.
 *
 * @return                    pointer to converted EVP_PKEY struct on success,
 *                            NULL on failure
 */
EVP_PKEY *deserialize_pkey(charbuf der_pkey);

/**
 * <pre>
 * This function coordinates testing of the ASN.1 message creation, parsing,
 * and DER encode/decode functionality, as well as the initial processing to
 * support follow-on messaging tests.
 * </pre>
 *
 * @param[in]  test_select       enumerated test selection input
 * 
 * @param[in]  msg_data_in       PELZ_MSG_DATA struct containing the input
 *                               data for the test message fields
 *
 * @param[out] der_asn1_msg_out  Pointer to character buffer (charbuf) holding
 *                               DER-encoded ASN.1 pelz test message produced
 *
 * @return                       MsgTestStatus value providing test
 *                               result information,
 */
MsgTestStatus pelz_asn1_msg_test_helper(MsgTestSelect test_select,
                                        PELZ_MSG_DATA msg_data_in,
                                        charbuf *der_asn1_msg_out);

/**
 * <pre>
 * This function coordinates testing of the signed CMS message creation
 * (signature), verification, and DER encode/decode functionality, as well
 * as support to follow-on messaging tests.
 * </pre>
 *
 * @param[in]  test_select         enumerated test selection input
 * 
 * @param[in]  msg_data_in         Character buffer (charbuf) containing the
 *                                 input data to be used as the test signed,
 *                                 CMS message payload.
 * 
 * @param[in]  sign_priv           pointer to EVP_PKEY struct containing test
 *                                 private key to be used for signing test
 *                                 message.
 * 
 * @param[in]  verify_cert         pointer to an X509 struct containing the
 *                                 certificate (public key) to be included
 *                                 within signed test message and used to
 *                                 verify signed test message
 *
 * @param[out] der_signed_msg_out  Pointer to character buffer (charbuf)
 *                                 holding DER-encoded, signed CMS pelz
 *                                 test message output
 *
 * @return                         MsgTestStatus value providing test
 *                                 result information,
 */
MsgTestStatus pelz_signed_msg_test_helper(MsgTestSelect test_select,
                                          charbuf msg_data_in,
                                          EVP_PKEY *sign_priv,
                                          X509 *verify_cert,
                                          charbuf *der_signed_msg_out);

/**
 * <pre>
 * This function coordinates testing of the enveloped CMS message creation
 * (encryption), decryption, and DER encode/decode functionality, as well
 * as support to follow-on messaging tests.
 * </pre>
 *
 * @param[in]  test_select         enumerated test selection input
 * 
 * @param[in]  msg_data_in         Character buffer (charbuf) containing the
 *                                 input data to be used as the test
 *                                 enveloped, CMS message payload.
 * 
 * @param[in]  encrypt_cert        pointer to X509 struct containing test
 *                                 certificate with the public key to be
 *                                 used for encrypting test message.
 * 
 * @param[in]  decrypt_priv        pointer to an EVP_PKEY struct containing
 *                                 private key) to be used to decrypt the
 *                                 enveloped test message 
 *
 * @param[out] der_env_msg_out     pointer to character buffer (charbuf) holding
 *                                 DER-encoded, enveloped (encrypted) pelz test
 *                                 message output
 *
 * @return                         MsgTestStatus value providing test
 *                                 information,
 */
MsgTestStatus pelz_enveloped_msg_test_helper(MsgTestSelect test_select,
                                             charbuf msg_data_in,
                                             X509 *encrypt_cert,
                                             EVP_PKEY *decrypt_priv,
                                             charbuf *der_env_msg_out);

/**
 * <pre>
 * This function coordinates testing of the high-level
 * "construct"/"deconstruct" (end-to-end) messaging functionality.
 * </pre>
 *
 * @param[in]  test_select         enumerated test selection input
 * 
  * @param[in]  msg_data_in        PELZ_MSG_DATA struct containing the input
 *                                 data for the test message fields
 * 
 * @param[in]  construct_cert      pointer to X509 struct containing test
 *                                 certificate with the public key of the
 *                                 test message creator (used to verify
 *                                 test message signature).
 * 
 * @param[in]  construct_priv      pointer to an EVP_PKEY struct containing
 *                                 private key for the test message creator
 *                                 (used to sign the test message).
 *
 * @param[in]  deconstruct_cert    pointer to X509 struct containing test
 *                                 certificate with the public key of the
 *                                 test message recipient (used to encrypt
 *                                 the test message).
 * 
 * @param[in]  deconstruct_priv    pointer to an EVP_PKEY struct containing
 *                                 private key for the test message recipient
 *                                 (used to decrypt the test message).
 *
 * @return                         MsgTestStatus value providing test
 *                                 result information
 */
MsgTestStatus pelz_constructed_msg_test_helper(MsgTestSelect test_select,
                                               PELZ_MSG_DATA msg_data,
                                               X509 *construct_cert,
                                               EVP_PKEY *construct_priv,
                                               X509 *deconstruct_cert,
                                               EVP_PKEY *deconstruct_priv);

#endif
