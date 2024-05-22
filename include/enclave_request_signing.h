#ifndef _ENCLAVE_REQUEST_SIGNING_H_
#define _ENCLAVE_REQUEST_SIGNING_H_

#ifdef __cplusplus
extern "C"
{
#endif
#include <openssl/cms.h>

#include "charbuf.h"
#include "pelz_request_handler.h"
#include "pelz_enclave.h"

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
 * Verifies the signature over the CMS request message
 * </pre>
 *
 * @param[in] rcvd_cms_signed_req    The struct containing the CMS "SignedData"
 *                                   content to be validated
 * @param[in] ca_cert                Pointer to X509 certificate for CA that
 *                                   requestor's cert must be signed by
 * @param[in] verified_req_data      Pointer to buffer that will hold the data
 *                                   over which the signature was verified
 * @param[in] verified_req_data_size Pointer to size, in bytes, of output data
 *                                   buffer
 *
 * @return 1 if valid, 0 if invalid
 */
int verify_request_signature(CMS_ContentInfo *rcvd_cms_signed_req,
                             X509 *ca_cert,
                             uint8_t **verified_req_data,
                             int *verified_req_data_size);

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
