#ifndef _ENCLAVE_HELPER_FUNCIONS_H_
#define _ENCLAVE_HELPER_FUNCTIONS_H_

#include "test_helper_functions.h"

X509 *deserialize_cert(unsigned char *der_cert, long der_cert_size);
EVP_PKEY *deserialize_pkey(unsigned char *der_pkey, long der_pkey_size);

MsgTestStatus pelz_asn1_msg_test_helper(MsgTestSelect test_select,
                                        PELZ_MSG_DATA msg_data_in,
                                        charbuf *der_asn1_msg_out);

MsgTestStatus pelz_signed_msg_test_helper(MsgTestSelect test_select,
                                          charbuf msg_data_in,
                                          X509 *sign_cert,
                                          EVP_PKEY *verify_priv,
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
