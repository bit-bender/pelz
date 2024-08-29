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

X509 *deserialize_cert(const unsigned char *der_cert, long der_cert_size);
EVP_PKEY *deserialize_pkey(const unsigned char *der_pkey, long der_pkey_size);

MsgTestStatus pelz_asn1_msg_test_helper(MsgTestSelect test_select,
                                        PELZ_MSG_DATA msg_data_in,
                                        charbuf *der_asn1_msg_out);

MsgTestStatus pelz_signed_msg_test_helper(MsgTestSelect test_select,
                                          charbuf msg_data_in,
                                          EVP_PKEY *sign_priv,
                                          X509 *verify_cert,
                                          charbuf *der_signed_msg_out);

MsgTestStatus pelz_enveloped_msg_test_helper(MsgTestSelect test_select,
                                             charbuf msg_data_in,
                                             X509 *encrypt_cert,
                                             EVP_PKEY *decrypt_priv,
                                             charbuf *der_env_msg_out);

MsgTestStatus pelz_constructed_msg_test_helper(MsgTestSelect test_select,
                                               PELZ_MSG_DATA msg_data,
                                               X509 *construct_cert,
                                               EVP_PKEY *construct_priv,
                                               X509 *deconstruct_cert,
                                               EVP_PKEY *deconstruct_priv,
                                               charbuf *expected_der_msg);

#endif
