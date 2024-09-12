/*
 * pelz_request_handler.h
 */

#ifndef INCLUDE_PELZ_REQUEST_HANDLER_H_
#define INCLUDE_PELZ_REQUEST_HANDLER_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/cms.h>
#include <openssl/evp.h>

#include "charbuf.h"

//The maximum key length
#define MAX_KEY_LEN 1024
#define MAX_SOC_DATA_SIZE 1024

typedef enum
{ REQUEST_RESPONSE_OK,
  REQUEST_RESPONSE_UNKNOWN_ERROR,
  REQUEST_RESPONSE_BUFFER_ERROR,
  REQUEST_RESPONSE_MSG_TYPE_ERROR,
  REQUEST_RESPONSE_REQ_TYPE_ERROR,
  REQUEST_RESPONSE_CIPHER_ERROR,
  REQUEST_RESPONSE_KEY_ID_ERROR,
  REQUEST_RESPONSE_DATA_ERROR,
  REQUEST_RESPONSE_STATUS_ERROR,
  REQUEST_RESPONSE_IV_ERROR,
  REQUEST_RESPONSE_TAG_ERROR,
  REQUEST_RESPONSE_KEK_NOT_LOADED,
  REQUEST_RESPONSE_KEK_LOAD_ERROR,
  REQUEST_RESPONSE_WRAP_ERROR,
  REQUEST_RESPONSE_UNWRAP_ERROR,
  REQUEST_RESPONSE_MSG_CONSTRUCT_ERROR,
  REQUEST_RESPONSE_MSG_DECONSTRUCT_ERROR,
  REQUEST_RESPONSE_MALLOC_ERROR
} RequestResponseStatus;

/**
* <pre>
 * This function implements the high-level "servicing" of a received pelz
 * request within the SGX enclave. It deconstructs the received request,
 * performs the requested operation, and constructs the response to be
 * sent back to the requestor.
 * <pre>
 *
 * @param[in]  req_in      The byte buffer (charbuf) containing the
 *                         contents of the received pelz request message.
 *
 * @param[out] resp_out    Pointer to the byte buffer (charbuf) where the
 *                         contents of the pelz response message to be
 *                         sent back to the requestor will be placed.
 *                         As memory will be allocated as part of the
 *                         response message construction process, the
 *                         'chars' member of the charbuf member referenced
 *                         by this parameter should be NULL when passed
 *                         into this function.
 *
 * @return    REQUEST_OK on success,
 *            an error message indicating the type of error otherwise.
 */
RequestResponseStatus service_pelz_request_msg(charbuf req_in,
                                               charbuf *resp_out);

/**
 * <pre>
 * This function implements encrypt request handling by looking if pelz already has
 * the key and if not then adding the key to the key table. Along with the
 * key lookup, this function calls requested wrap service.
 * <pre>
 *
 * @param[in]  key_id          Byte buffer containing the key_id of the key
 *                             to be used for the request.
 *
 * @param[in]  cipher_name     Byte buffer containing the name of the cipher
 *                             used for the request.
 *
 * @param[in]  plain_data_in   Byte buffer containing the input data for
 *                             the encrypt (wrap) request.
 *
 * @param[out] cipher_data_out Pointer to byte buffer (charbuf) where the
 *                             the output result (ciphertext created inside
 *                             the call) will be returned. Memory will be
 *                             allocated as part of the call, therefore,
 *                             the 'chars' member of the struct passed into
 *                             this function should be NULL.
 *
 * @param[out] iv_out          Pointer to byte buffer (charbuf) where the
 *                             initialization vector (IV), if necessary,
 *                             will be returned. Memory will be allocated
 *                             as part of the call, therefore, the 'chars'
 *                             member of the struct passed into this function
 *                             should be NULL.
 *
 * @param[out] tag_out         Pointer to byte buffer (chabuf) where the
 *                             MAC tag produced by the encryption, if
 *                             necessary, will be returned. Memory will be
 *                             allocated as part of the call, therefore, the
 *                             'chars' member of the struct passed into this
 *                             function should be NULL.
 *
 * @return REQUEST_OK on success,
 *         an error message indicating the type of error otherwise.
 */
RequestResponseStatus pelz_encrypt_request_handler(charbuf key_id,
                                                   charbuf cipher_name,
                                                   charbuf plain_data_in,
                                                   charbuf *cipher_data_out,
                                                   charbuf *iv_out,
                                                   charbuf *tag_out);

/**
 * <pre>
 * This function implements decrypt handling by looking if pelz already has
 * the key and if not then adding the key to the key table. Along with the
 * key lookup, this function checks the request type then based on the request
 * type it calls the wrap or unwrap functions to return requested key value.
 * <pre>
 *
 * @param[in] key_id       the key_id of the key to be used for the request
 * @param[in] cipher_name  the name of the cipher used for the request
 * @param[in] iv           the iv used to encrypt the data, may be empty.
 * @param[in] tag          the MAC tag for the encryption, may be empty.
 * @param[in] cipher_data  the input data
 * @param[out] plain_data_out  a pointer to a charbuf to hold the output, will
 *                         be created inside the call
 *
 * @return REQUEST_OK on success, an error message indicating the type of
 *                    error otherwise.
 */
RequestResponseStatus pelz_decrypt_request_handler(charbuf key_id,
                                                   charbuf cipher_name,
                                                   charbuf iv,
                                                   charbuf tag,
                                                   charbuf cipher_data_in,
                                                   charbuf *plain_data_out);

#endif /* INCLUDE_PELZ_REQUEST_HANDLER_H_ */
