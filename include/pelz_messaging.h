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

typedef enum PELZ_MSG_TYPE { MSG_TYPE_MIN = 1,
                             REQUEST = 1,
                             RESPONSE = 2,
                             MSG_TYPE_MAX = 2 } PELZ_MSG_TYPE;

typedef enum PELZ_REQ_TYPE { REQ_TYPE_MIN = 1,
                             KEY_WRAP = 1,
                             KEY_UNWRAP = 2,
                             REQ_TYPE_MAX = 2 } PELZ_REQ_TYPE;

typedef struct PELZ_MSG_DATA {
  PELZ_MSG_TYPE msg_type;
  PELZ_REQ_TYPE req_type;
  charbuf cipher;
  charbuf key_id;
  fixed_charbuf data;
  charbuf status;
} PELZ_MSG_DATA;

typedef struct PELZ_MSG {
  ASN1_ENUMERATED * msg_type;
  ASN1_ENUMERATED * req_type;
  ASN1_UTF8STRING * cipher;
  ASN1_UTF8STRING * key_id;
  ASN1_OCTET_STRING * data;
  ASN1_UTF8STRING * status;
} PELZ_MSG;

typedef enum MSG_FORMAT { MSG_FORMAT_MIN = 1,
                          ASN1 = 1,
                          CMS = 2,
                          MSG_FORMAT_MAX = 2 } MSG_FORMAT;

#define PELZ_MSG_SUCCESS 0

// General pelz messaging errors
#define PELZ_MSG_UNKNOWN_ERROR -1
#define PELZ_MSG_PARAM_INVALID -2
#define PELZ_MSG_MALLOC_ERROR -3
#define PELZ_MSG_BIO_READ_ERROR -4

// PELZ_MSG ASN.1 sequence create/parse errors
#define PELZ_MSG_MSG_TYPE_TAG_ERROR -32
#define PELZ_MSG_MSG_TYPE_PARSE_ERROR -33
#define PELZ_MSG_MSG_TYPE_PARSE_INVALID -34
#define PELZ_MSG_REQ_TYPE_TAG_ERROR -35
#define PELZ_MSG_REQ_TYPE_PARSE_ERROR -36
#define PELZ_MSG_REQ_TYPE_PARSE_INVALID -37
#define PELZ_MSG_CIPHER_TAG_ERROR -38
#define PELZ_MSG_CIPHER_PARSE_ERROR -39
#define PELZ_MSG_CIPHER_PARSE_INVALID -40
#define PELZ_MSG_KEY_ID_TAG_ERROR -41
#define PELZ_MSG_KEY_ID_PARSE_ERROR -42
#define PELZ_MSG_KEY_ID_PARSE_INVALID -43
#define PELZ_MSG_DATA_TAG_ERROR -44
#define PELZ_MSG_DATA_PARSE_ERROR -45
#define PELZ_MSG_DATA_PARSE_INVALID -46
#define PELZ_MSG_STATUS_TAG_ERROR -47
#define PELZ_MSG_STATUS_PARSE_ERROR -48
#define PELZ_MSG_STATUS_PARSE_INVALID -49

// pelz messaging der encode/decode errors
#define PELZ_MSG_SERIALIZE_ERROR -64
#define PELZ_MSG_DESERIALIZE_ERROR -65

// pelz messaging sign/verify errors
#define PELZ_MSG_VERIFY_CONTENT_ERROR -96
#define PELZ_MSG_VERIFY_FAIL -97
#define PELZ_MSG_VERIFY_RESULT_INVALID -98

// pelz messaging CMS encrypt/decrypt errors
#define PELZ_MSG_DECRYPT_CONTENT_ERROR -128
#define PELZ_MSG_DECRYPT_FAIL -129
#define PELZ_MSG_DECRYPT_RESULT_INVALID -130

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
 * Creates a Cryptographic Message Syntax (CMS) message of type
 * 'signedData' for the data contained in the input data buffer
 * (byte array).
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
 * @param[in] sign_cert      Pointer to X509 certificate for signer. This
 *                           cert will be incorporated in the CMS message
 *                           content so that the recipient can use it to
 *                           validate the message. This cert must be signed
 *                           by the Certificate Authority (CA) specified by
 *                           the recipient, as this cert will be validated.
 *
 * @param[in] sign_priv      Pointer to EVP_PKEY struct containing the
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
CMS_ContentInfo *create_pelz_signed_msg(uint8_t *data_in,
                                        int data_in_len,
                                        X509 *sign_cert,
                                        EVP_PKEY *sign_priv);

/**
 * <pre>
 * Verifies the signature for a CMS message of type 'signedData'
 * </pre>
 *
 * @param[in] signed_msg_in  The struct containing the CMS "SignedData"
 *                           content to be validated (pointer to a
 *                           CMS_ContentInfo struct with a content type
 *                           of 'signedData'). Cannot be NULL or
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
int verify_pelz_signed_msg(CMS_ContentInfo *signed_msg_in,
                           X509 *ca_cert,
                           uint8_t **data_out);

/**
 * <pre>
 * Creates a Cryptographic Message Syntax (CMS) message of type
 * 'authEnvelopedData' for the data contained in the input data
 * buffer (byte array). As the cipher mode is AES-256 GCM, the
 * payload will be symmetrically encrypted. The encryption key
 * will be encrypted using the public key in the provided X509
 * certification input parameter and included in the message.
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
 * @param[in] encrypt_cert   Pointer to X509 certificate for the message
 *                           recipient. This cert will be incorporated in
 *                           the CMS message content. The recipient's private
 *                           key can then be used to unwrap the symmetric
 *                           encryption key and decrypt the message payload.
 *                           Although not needed to decrypt the message, this
 *                           cert is included to specify the recipient.
 * 
 * @return                   Pointer to the resultant CMS_ContentInfo struct
 *                           with 'pkcs7-signedData' content for the input
 *                           parameters provided by the caller. This struct
 *                           is allocated within this function, but must be
 *                           freed by the caller. A NULL pointer is returned
 *                           when an error is encountered.
 */
CMS_ContentInfo *create_pelz_enveloped_msg(uint8_t *data_in,
                                           int data_in_len,
                                           X509 *encrypt_cert);

/**
 * <pre>
 * Decrypts (unenvelops) a Cryptographic Message Syntax (CMS)
 * message of type 'authEnvelopedData'. As the cipher mode is
 * AES-256 GCM, the payload will be symmetrically decrypted.
 * The decryption key will be unwrapped using the provided
 * private asymmetric key.
 * </pre>
 *
 * @param[in]  enveloped_msg_in
 * 
 * @param[in]  encrypt_cert     Pointer to X509 certificate for the message
 *                              recipient. This cert will be incorporated in
 *                              the CMS message content. The recipient's private
 *                              key can then be used to unwrap the symmetric
 *                              encryption key and decrypt the message payload.
 *                              Although not needed to decrypt the message, this
 *                              cert can be included to specify the recipient.
 * 
 * @param[in]  decrypt_priv     Pointer to EVP_PKEY struct containing the
 *                              message creator's private key that will be
 *                              used to unwrap the symmetric key needed to
 *                              decrypt the message.
 *
 * @param[out] data_out         Pointer to the byte array where the decrypted
 *                              output data will be placed
 *
 * @return                      Pointer to the resultant CMS_ContentInfo struct
 *                              with 'authEnvelopedData' content for the input
 *                              parameters provided by the caller. This struct
 *                              is allocated within this function, but must be
 *                              freed by the caller. A NULL pointer is returned
 *                              when an error is encountered.
 */
int decrypt_pelz_enveloped_msg(CMS_ContentInfo *enveloped_msg_in,
                               X509 *encrypt_cert,
                               EVP_PKEY *decrypt_priv,
                               uint8_t **data_out);

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
 * @param[in]  msg_format    Enumerated type input to specify the format of
 *                           the input message to be formatted. Currently
 *                           supported values are: RAW and CMS.
 *
 * @return number of data bytes allocated/written to the 'bytes_out' buffer
 *         on success; error code (negative integer) otherwise
 */
int der_encode_pelz_msg(const void *msg_in,
                        unsigned char **bytes_out,
                        MSG_FORMAT msg_format);

/**
 * <pre>
 * Decodes an input DER-formatted byte array into its original internal
 * (PELZ_MSG ASN.1 sequence or CMS message) format. In other words, this
 * function de-serializes a DER-encoded, raw array of bytes to enable
 * parsing the message using a structured format.
 * </pre>
 *
 * @param[in]  bytes_in     Pointer to the input buffer containing the
 *                          DER-formatted byte array
 *
 * @param[in]  bytes_in_len Size (in bytes) of the input byte buffer
 * 
 * @param[in]  msg_format   Enumerated format specification indicating
 *                          what output format the DER-encoded input
 *                          buffer should be converted to. Currently
 *                          supported values are: RAW and CMS.
 *
 * @return    Pointer to the resultant internally formatted struct value.
 *            A NULL pointer is returned when an error is encountered.
 */
void *der_decode_pelz_msg(const unsigned char *bytes_in,
                          long bytes_in_len,
                          MSG_FORMAT msg_format);

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
