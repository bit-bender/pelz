#ifndef _PELZ_MESSAGING_H_
#define _PELZ_MESSAGING_H_

#ifdef __cplusplus
extern "C"
{
#endif
#include <openssl/cms.h>

#include "charbuf.h"
#include "pelz_request_handler.h"
#include "pelz_enclave.h"

#define VERIFY_SIG_UNKOWN_ERROR -1
#define VERIFY_SIG_INVALID_PARAMETER -2
#define VERIFY_SIG_CONTENT_TYPE_ERROR -3
#define VERIFY_SIG_VERIFY_ERROR -4
#define VERIFY_SIG_INVALID_DATA_RESULT -5
#define VERIFY_SIG_MALLOC_ERROR -6
#define VERIFY_SIG_BIO_READ_ERROR -7

/**
 * <pre>
 * Serializes request data so the signature can be validated.
 * </pre>
 *
 * The serialized data starts with:
 * 8 bytes little-endian encoding of the total size of the serialized request
 * 8 bytes encoding a uint64_t little-endian encoding of the request_type
 *
 * Then each field present is serialized as
 * 8 byte little-endian encoding of the field length
 * The field data 
 *
 * @param[in] request_type   The request type
 * @param[in] key_id         The key_id extracted from the request
 * @param[in] cipher_name    The cipher_name extracted from the request
 * @param[in] data           The data extracted from the request
 * @param[in] iv             The iv extracted from the request, may be empty
 * @param[in] tag            The tag extracted from the request, may be empty
 * @param[in] requestor_cert The requestor_cert extracted from the request
 *
 * @return a charbuf containing the serialized data, or an empty charbuf on error.
 */
  charbuf serialize_request(RequestType request_type, charbuf key_id, charbuf cipher_name, charbuf data, charbuf iv, charbuf tag, charbuf requestor_cert);

/**
 * <pre>
 * Creates a CMS message of type 'pkcs7-signedData' for the data contained
 * in the input data buffer (byte array).
 * </pre>
 *
 * @param[in] data_in        A byte array (uint8_t *) containing the input
 *                           data to be used for the creation of a CMS
 *                           "SignedData" message. Cannot be NULL or have
 *                           an invalid (negative) or empty (zero) length.
 * 
 * @param[in] data_in_len    An integer specifying the size (in bytes)
 *                           of the input byte buffer (data_in).
 *
 * @param[in] signer_cert    Pointer to X509 certificate for signer. This
 *                           cert will be incorporated in the CMS message
 *                           content so that the recipient can use it to
 *                           validate the message. This cert must be signed
 *                           by the Certificate Authority (CA) specified by
 *                           the recipient, as this cert will be validated.
 *
 * @param[in] signer_priv    Pointer to EVP_PKEY struct containing the
 *                           signer's private key that will be used to
 *                           create the signature.
 *
 * @return                   Pointer to the resultant CMS_ContentInfo struct
 *                           with 'pkcs7-signedData' content for the input
 *                           parameters provided by the caller. This struct
 *                           is allocated within this function, but must be
 *                           freed by the caller. A NULL pointer is returned
 *                           when an error is encountered.
 */
CMS_ContentInfo *create_signed_data_msg(uint8_t *data_in,
                                        int data_in_len,
                                        X509 *signer_cert,
                                        EVP_PKEY *signer_priv);
/**
 * <pre>
 * Verifies the signature for a CMS message of type 'pkcs7-signedData'
 * </pre>
 *
 * @param[in] signed_msg_in  The struct containing the CMS "SignedData"
 *                           content to be validated (pointer to a
 *                           CMS_ContentInfo struct with a content type
 *                           of 'pkcs7-signedData'). Cannot be NULL or
 *                           have a different content type.
 *
 * @param[in] ca_cert        Pointer to X509 certificate for CA that
 *                           requestor's cert must be signed by. Needed
 *                           to complete the certificate chain and validate
 *                           the peer's certificate embedded in the
 *                           CMS message.
 *
 * @param[out] data_out      Pointer to buffer that will hold the data
 *                           over which the signature was verified. The
 *                           buffer is allocated within this function and
 *                           must be freed by the caller. The caller must
 *                           pass in a pointer to a NULL pointer for a byte
 *                           array (uint8_t).
 *
 * @return number of data bytes allocated/written to the 'data_out' buffer
 *         on success; error code (negative integer) otherwise
 */
int verify_signature(CMS_ContentInfo *signed_msg_in,
                     X509 *ca_cert,
                     uint8_t **data_out);

/**
 * <pre>
 * Validates the signature from the request data
 * </pre>
 *
 * @param[in] request_type   The request type
 * @param[in] key_id         The key_id extracted from the request
 * @param[in] cipher_name    The cipher_name extracted from the request
 * @param[in] data           The data extracted from the request
 * @param[in] iv             The iv extracted from the request, may be empty
 * @param[in] tag            The tag extracted from the request, may be empty
 * @param[in] signature      The signature data extracted from the request
 * @param[in] requestor_cert The requestor_cert extracted from the request
 *
 * @return 0 if valid, 1 if invalid
 */
  int validate_signature(RequestType request_type, charbuf key_id, charbuf cipher_name, charbuf data, charbuf iv, charbuf tag, charbuf signature, charbuf cert);

#ifdef __cplusplus
}
#endif
#endif
