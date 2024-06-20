#ifndef _PELZ_MESSAGING_H_
#define _PELZ_MESSAGING_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <openssl/cms.h>
#include <time.h>

#include "charbuf.h"
#include "pelz_request_handler.h"
#include "pelz_enclave.h"

typedef struct PELZ_MSG_DATA {
  uint16_t msg_type;
  uint16_t req_type;
  charbuf key_id;
  fixed_charbuf data;
  charbuf status;
} PELZ_MSG_DATA;

typedef struct PELZ_MSG {
  ASN1_INTEGER * type;
  ASN1_UTF8STRING * key_id;
  ASN1_OCTET_STRING * data;
  ASN1_UTF8STRING * status;
} PELZ_MSG;

enum PELZ_MSG_TYPE { MSG_TYPE_MIN = 1,
                     REQUEST = 1,
                     RESPONSE = 2,
                     MSG_TYPE_MAX = 2 };

enum PELZ_REQ_TYPE { REQ_TYPE_MIN = 1,
                     AES_KEY_WRAP = 1,
                     AES_KEY_UNWRAP = 2,
                     REQ_TYPE_MAX = 2 };

#define PELZ_MSG_SUCCESS 0

// General pelz messaging errors
#define PELZ_MSG_UNKNOWN_ERROR -1
#define PELZ_MSG_PARAM_INVALID -2
#define PELZ_MSG_MALLOC_ERROR -3
#define PELZ_MSG_BIO_READ_ERROR -4

// PELZ_MSG ASN.1 sequence create/parse errors
#define PELZ_MSG_TYPE_TAG_ERROR -16
#define PELZ_MSG_TYPE_PARSE_ERROR -17
#define PELZ_MSG_TYPE_PARSE_INVALID -18
#define PELZ_MSG_KEY_ID_TAG_ERROR -19
#define PELZ_MSG_KEY_ID_PARSE_ERROR -20
#define PELZ_MSG_KEY_ID_PARSE_INVALID -21
#define PELZ_MSG_DATA_TAG_ERROR -22
#define PELZ_MSG_DATA_PARSE_ERROR -23
#define PELZ_MSG_DATA_PARSE_INVALID -24
#define PELZ_MSG_STATUS_TAG_ERROR -25
#define PELZ_MSG_STATUS_PARSE_ERROR -26
#define PELZ_MSG_STATUS_PARSE_INVALID -27

// pelz messaging der encode/decode errors
#define PELZ_MSG_SERIALIZE_ERROR -32
#define PELZ_MSG_DESERIALIZE_ERROR -33

// pelz messaging sign/verify errors
#define PELZ_MSG_VERIFY_CONTENT_ERROR -48
#define PELZ_MSG_VERIFY_FAIL -49
#define PELZ_MSG_VERIFY_RESULT_INVALID -50

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
 * Creates an ASN.1 formatted pelz message (request or response).
 * </pre>
 *
 * @param[in] msg_data_in   PELZ_MSG_DATA struct containing data to be used
 *                          for constructing PELZ_MSG ASN.1 sequence:
 *
 *                            msg_type: Unsigned integer value representing
 *                                      the pelz message type (e.g.,
 *                                      1 = request, 2 = response)
 *
 *                            req_type: Unsigned integer value specifying
 *                                      the pelz request type (e.g.,
 *                                      1 = AES key wrap, 2 = AES key unwrap)
 *
 *                            key_id: Character buffer (charbuf) struct value
 *                                    used to specify the KEK ID (URL)
 *
 *                            data: Character buffer (charbuf) struct value
 *                                  used to specify the data payload for the
 *                                  message (e.g., plaintext key data to be
 *                                  wrapped, wrapped data for response,
 *                                  ciphertext key data to be unwrapped,
 *                                  unwrapped data for response, ...)
 *
 *                            status: Character buffer (charbuf) struct value
 *                                    used to specify the status string
 *                                    payload for the message (e.g., success
 *                                    or error information, ...)
 *
 * @return    Pointer to the resultant 'PELZ_MSG' ASN.1 message sequence.
 *            A NULL pointer is returned when an error is encountered.
 */
PELZ_MSG * create_pelz_asn1_msg(PELZ_MSG_DATA *msg_data_in);

/**
 * <pre>
 * Parses a PELZ_MSG ASN.1 sequesnce into a set of output parameters
 * containing the message field values.
 * </pre>
 *
 * @param[in] msg_in           Pointer to the input PELZ_MSG ASN.1 sequence
 *                             to be parsed.
 *
 * @param[out] parsed_msg_out  Pointer to the output PELZ_MSG_DATA struct to
 *                             hold the parsed message field values.
 *
 * @return                     Zero (0) on success, non-zero error code
 *                             on failure
 */
int parse_pelz_asn1_msg(PELZ_MSG *msg_in, PELZ_MSG_DATA *parsed_msg_out);

/**
 * <pre>
 * Encodes an input PELZ_MSG ASN.1 sequence using Distinguished Encoding
 * Rules (DER) formatting. In other words, this function serializes a
 * raw (unsigned, unencrypted) pelz message from an internal OpenSSL
 * format (PELZ_MSG) into a binary array of bytes (DER-formatted).
 * </pre>
 *
 * @param[in]  msg_in        A pointer to an ASN.1 formatted pelz message
 *                           (PELZ_MSG *) to be converted to a binary byte
 *                           array (DER) fprmat. Cannot be NULL.
 *
 * @param[out] bytes_out     A pointer to a pointer to the byte array where
 *                           the DER-formatted output bytes will be returned
 *                           to the caller. The byte array is allocated within
 *                           this function. Therefore, a NULL byte array
 *                           pointer should be passed in. The caller is
 *                           responsible for freeing this buffer when done
 *                           with it.
 *
 * @return number of data bytes allocated/written to the 'bytes_out' buffer
 *         on success; error code (negative integer) otherwise
 */
int der_encode_pelz_asn1_msg(const PELZ_MSG *msg_in, unsigned char **bytes_out);

/**
 * <pre>
 * Decodes an input DER-formatted byte array into its original internal
 * (PELZ_MSG ASN.1 sequence) format. In other words, this function
 * de-serializes a DER-encoded, raw (unsigned, unencrypted) pelz message
 * to enable parsing the message using a structured format.
 * </pre>
 *
 * @param[in] bytes_in      Pointer to the input buffer containing the
 *                          DER-formatted byte array
 *
 * @param[in] bytes_in_len  Size (in bytes) of the input byte buffer
 *
 * @return    Pointer to the resultant 'PELZ_MSG' ASN.1 message sequence.
 *            A NULL pointer is returned when an error is encountered.
 */
PELZ_MSG *der_decode_pelz_asn1_msg(const unsigned char *bytes_in,
                                   long bytes_in_len);

/**
 * <pre>
 * Creates a Cryptographic Message Syntax (CMS) message of type
 * 'pkcs7-signedData' for the data contained in the input data
 * buffer (byte array).
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
 * Encodes an input CMS_ContentInfo struct containing a 'pkcs7-signedData'
 * pelz message payload using Distinguished Encoding Rules (DER) formatting.
 * In other words, this function serializes a signed CMS pelz message from
 * an internal OpenSSL format (CMS_ContentInfo) into a binary array of bytes
 * (DER-formatted).
 * </pre>
 *
 * @param[in]  msg_in        Pointer to a CMS_ContentInfo struct specifying
 *                           the input CMS "SignedData" message.
 *                           Cannot be NULL.
 *
 * @param[out] bytes_out     A pointer to a pointer to the byte array where
 *                           the DER-formatted output bytes will be returned
 *                           to the caller. The byte array is allocated within
 *                           this function. Therefore, a NULL byte array
 *                           pointer should be passed in. The caller is
 *                           responsible for freeing this buffer when done
 *                           with it.
 *
 * @return number of data bytes allocated/written to the 'bytes_out' buffer
 *         on success; error code (negative integer) otherwise
 */
int der_encode_pelz_signed_msg(const CMS_ContentInfo *msg_in, unsigned char **bytes_out);

/**
 * <pre>
 * Decodes an input DER-formatted byte array into its original internal
 * signed pelz CMS message (CMS_ContentInfo) format. In other words, this
 * function de-serializes a DER-encoded, signed CMS pelz message
 * to enable parsing the message using a structured format.
 * </pre>
 *
 * @param[in] bytes_in      Pointer to the input buffer containing the
 *                          DER-formatted byte array
 *
 * @param[in] bytes_in_len  Size (in bytes) of the input byte buffer
 *
 * @return    Pointer to the resultant pelz signed CMS mesaage struct.
 *            A NULL pointer is returned when an error is encountered.
 */
CMS_ContentInfo *der_decode_pelz_signed_msg(const unsigned char *bytes_in,
                                            long bytes_in_len);

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
int validate_signature(RequestType request_type,
                       charbuf key_id,
                       charbuf cipher_name,
                       charbuf data,
                       charbuf iv,
                       charbuf tag,
                       charbuf signature,
                       charbuf cert);

#ifdef __cplusplus
}
#endif
#endif
