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

typedef enum
{
  MSG_TYPE_MIN = 1,
  REQUEST = 1,
  RESPONSE = 2,
  MSG_TYPE_MAX = 2
} PELZ_MSG_TYPE;

typedef enum
{
  REQ_TYPE_MIN = 1,
  KEY_WRAP = 1,
  KEY_UNWRAP = 2,
  REQ_TYPE_MAX = 2
} PELZ_REQ_TYPE;

typedef enum
{
  MSG_FORMAT_MIN = 1,
  ASN1 = 1,
  CMS = 2,
  MSG_FORMAT_MAX = 2
} MSG_FORMAT;

typedef enum
{
  // general messaging error(s)
  PELZ_MSG_OK = 0,
  PELZ_MSG_UNKNOWN_ERROR = -1,
  PELZ_MSG_INVALID_PARAM = -2,
  PELZ_MSG_MALLOC_ERROR = -3,
  PELZ_MSG_BIO_READ_ERROR = -4,

  // ASN.1 message creation error(s)
  PELZ_MSG_ASN1_CREATE_ERROR = -32,
  PELZ_MSG_ASN1_CREATE_INVALID_RESULT = -33,

  // ASN.1 message parse error(s)
  PELZ_MSG_ASN1_TAG_ERROR = -65,
  PELZ_MSG_ASN1_PARSE_ERROR = -64,
  PELZ_MSG_ASN1_PARSE_INVALID_RESULT = -66,

  // DER encode (serialization) error(s)
  PELZ_MSG_DER_ENCODE_ASN1_ERROR = -97,
  PELZ_MSG_DER_ENCODE_ASN1_RESULT_MISMATCH = -98,
  PELZ_MSG_DER_ENCODE_CMS_ERROR = -99,
  PELZ_MSG_DER_ENCODE_CMS_RESULT_MISMATCH = -100,

  // DER decode (deserialization) error(s)
  PELZ_MSG_DER_DECODE_ASN1_ERROR = -129,
  PELZ_MSG_DER_DECODE_CMS_ERROR = -130,

  // message signature error(s)
  PELZ_MSG_SIGN_ERROR = -160,
  PELZ_MSG_SIGN_INVALID_RESULT = -161,

  // message signature verification error(s)
  PELZ_MSG_VERIFY_ERROR = -192,
  PELZ_MSG_VERIFY_CONTENT_TYPE_ERROR = -193,
  PELZ_MSG_VERIFY_INVALID_RESULT = -195,
  PELZ_MSG_VERIFY_SIGNER_CERT_ERROR = -196,
  PELZ_MSG_VERIFY_EXTRACT_SIGNER_CERT_ERROR = -197,

  // CMS encrypt error(s)
  PELZ_MSG_ENCRYPT_ERROR = -224,
  PELZ_MSG_ENCRYPT_INVALID_RESULT = -225,

  // CMS decrypt error(s)
  PELZ_MSG_DECRYPT_ERROR = -256,
  PELZ_MSG_DECRYPT_CONTENT_TYPE_ERROR = -257,
  PELZ_MSG_DECRYPT_INVALID_RESULT = -259
} PelzMessagingStatus;



typedef struct PELZ_MSG_DATA
{
  PELZ_MSG_TYPE msg_type;
  PELZ_REQ_TYPE req_type;
  charbuf cipher;
  charbuf key_id;
  charbuf data;
  charbuf status;
} PELZ_MSG_DATA;

typedef struct PELZ_MSG
{
  ASN1_ENUMERATED *msg_type;
  ASN1_ENUMERATED *req_type;
  ASN1_UTF8STRING *cipher;
  ASN1_UTF8STRING *key_id;
  ASN1_OCTET_STRING *data;
  ASN1_UTF8STRING *status;
} PELZ_MSG;

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
PELZ_MSG * create_pelz_asn1_msg(PELZ_MSG_DATA msg_data_in);

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
 * @return                     Zero (PELZ_MSG_OK = 0) on successful parse,
 *                             enumerated (negative) error code otherwise
 */
PelzMessagingStatus parse_pelz_asn1_msg(PELZ_MSG *msg_in,
                                        PELZ_MSG_DATA *parsed_msg_out);

/**
 * <pre>
 * Creates a Cryptographic Message Syntax (CMS) message of type
 * 'signedData' for the data contained in the input data buffer
 * (byte array).
 * </pre>
 *
 * @param[in] msg_data_in     A byte buffer (charbuf) containing the input
 *                           data to be used for the creation of a CMS
 *                           "SignedData" message.
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
CMS_ContentInfo *create_pelz_signed_msg(charbuf msg_data_in,
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
 * @param[in] peer_cert_out  Pointer to X509 certificate for message signer
 *                           included in the received message. If the message
 *                           was a request, the public key in this certificate
 *                           will be needed to encrypt the response message
 *                           that will be returned.
 *
 * @param[out] data_out      Pointer to buffer that will hold the data
 *                           over which the signature was verified. The
 *                           buffer is allocated within this function and
 *                           must be freed by the caller.
 *
 * @return                   Zero (PELZ_MSG_OK = 0) on successful verification,
 *                           enumerated (negative) error code otherwise
 */
PelzMessagingStatus verify_pelz_signed_msg(CMS_ContentInfo *signed_msg_in,
                                           X509 **peer_cert_out,
                                           charbuf *data_out);

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
 * @param[in] msg_data_in    A byte buffer (charbuf) containing the input
 *                           data to be used for the creation of a CMS
 *                           "SignedData" message..
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
CMS_ContentInfo *create_pelz_enveloped_msg(charbuf msg_data_in,
                                           X509 *encrypt_cert);

/**
 * <pre>
 * Decrypts (un-envelops) a Cryptographic Message Syntax (CMS)
 * message of type 'authEnvelopedData'. As the cipher mode is
 * AES-256 GCM, the payload will be symmetrically decrypted.
 * The decryption key used will be unwrapped first using the
 * provided private asymmetric key.
 * </pre>
 *
 * @param[in]  enveloped_msg_in Pointer to the input CMS_ContentInfo struct
 *                              containing the enveloped CMS message to be
 *                              decrypted.
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
 * @param[out] data_out         Pointer to  the byte buffer (charbuf) where the
 *                              decrypted output message data will be placed.
 *
 * @return                      Zero (PELZ_MSG_OK = 0) on successful decryption,
 *                              enumerated (negative) error code otherwise
 */
PelzMessagingStatus decrypt_pelz_enveloped_msg(CMS_ContentInfo *enveloped_msg_in,
                                               X509 *encrypt_cert,
                                               EVP_PKEY *decrypt_priv,
                                               charbuf *data_out);

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
 *                           array (DER) format. Cannot be NULL.
 *
 * @param[out] der_bytes_out A pointer to a byte buffer (charbuf) where the
 *                           DER-formatted output bytes will be returned to
 *                           the caller. The byte array is allocated within
 *                           this function. The caller is responsible for
 *                           freeing this buffer when done with it.
 *
 * @param[in]  msg_format    Enumerated type input to specify the format of
 *                           the input message to be formatted. Currently
 *                           supported values are: RAW and CMS.
 *
 * @return                   Zero (PELZ_MSG_OK = 0) on successful DER encode,
 *                           enumerated (negative) error code otherwise
 */
PelzMessagingStatus der_encode_pelz_msg(const void *msg_in,
                                        charbuf *der_bytes_out,
                                        MSG_FORMAT msg_format);

/**
 * <pre>
 * Decodes an input DER-formatted byte array into its original internal
 * (PELZ_MSG ASN.1 sequence or CMS message) format. In other words, this
 * function de-serializes a DER-encoded, raw array of bytes to enable
 * parsing the message using a structured format.
 * </pre>
 *
 * @param[in]  der_bytes_in Input byte buffer (charbuf) containing the
 *                          DER-formatted bytes to be decoded.
 *
 * @param[in]  msg_format   Enumerated format specification indicating
 *                          what output format the DER-encoded input
 *                          buffer should be converted to. Currently
 *                          supported values are: RAW and CMS.
 *
 * @return                  Pointer to the resultant internally formatted
 *                          struct value. A NULL pointer is returned when
 *                          an error is encountered.
 */
void *der_decode_pelz_msg(charbuf der_bytes_in,
                          MSG_FORMAT msg_format);

/**
 * <pre>
 * Constructs input pelz message data and creates a DER-formatted byte array
 * that can be sent (transmitted) to the recipient matching the identity in
 * the specified peer certificate input parameter.
 * 
 * This functions "constructs" the message by performing the following
 * sequence of steps:
 *
 *   - create ASN.1 formatted message sequence
 *
 *   - DER-encode (serialize) the ASN.1 formatted message
 *
 *   - create a signed CMS message containing the DER encoded ASN.1 message
 *
 *   - DER encode (serialize) the CMS signed message
 *
 *   - create an enveloped (encrypted) CMS messsage containing the DER encoded
 *     signed CMS message bytes
 *
 *   - DER encode (serialize) the enveloped CMS message bytes
 *
 * </pre>
 *
 * @param[in]  msg_data_in     Pointer to the input data for the pelz message
 *                             to be contstructed. This must be a pointer,
 *                             therefore, to a PELZ_MSG_DATA struct that has
 *                             been pre-populated with the desired values for
 *                             each of the ASN.1 formatted PELZ_MSG "fields".
 *
 * @param[in]  local_cert_in   Pointer to the sender's local certificate,
 *                             to be included with the message to enable
 *                             signature verification by the recipient.
 *                             This certificate must be signed by the
 *                             appropriate CA in order to avoid its
 *                             rejection by the recipient.
 *
 * @param[in]  local_priv_in   Pointer to the sender's private key, to be
 *                             used in providing a signature as a component
 *                             of the encoded pelz message.
 *
 * @param[in]  peer_cert_in    Pointer to the receipient's X509 certificate.
 *                             The public key in this certificate is needed
 *                             to encrypt the message in a manner that only
 *                             the recipient can decrypt (i.e. using the
 *                             private key held by the recipient).
 * 
 * @param[in]  tx_msg_buf      Pointer to 'charbuf' struct containing
 *                             DER-encoded byte array representing the
 *                             signed, encrypted, pelz message data in
 *                             a format ready to be sent to a recipient.
 *
 * @return                     Zero (0 = PELZ_MSG_SUCCESS) on success;
 *                             error code (negative integer) otherwise
 */
PelzMessagingStatus construct_pelz_msg(PELZ_MSG_DATA msg_data_in,
                                       X509 *local_cert_in,
                                       EVP_PKEY *local_priv_in,
                                       X509 *peer_cert_in,
                                       charbuf *tx_msg_buf);


/**
 * <pre>
 * Deconstructs a DER-formatted byte array containing received pelz
 * message data and extracts the public X509 certificate for the
 * message sender.
 * </pre>
 *
 * This functions "deconstructs" the message by performing the following
 * sequence of steps:
 *
 *   - DER decode (de-serialize) the received message into an 'enveloped'
 *     CMS message struct
 *
 *   - decrypt (un-envelop) the CMS 'enveloped' message
 *
 *   - DER decode (de-serialize) the decrypted message payload into a
 *     signed CMS message
 *
 *   - verify the signature over and extract the the CMS signed message data
 *
 *   - DER decode (de-serialize) the verified message payload into an ASN.1
 *     formatted message (PELZ_MSG) sequence
 *
 *   - parse the ASN.1 formatted message sequence into a PELZ_MSG_DATA struct
 *     containing all fo the parsed message data values
 *
 * @param[in]  rcvd_msg_buf    Pointer to the input buffer containing the
 *                             DER-formatted byte array representing the
 *                             received, encrypted, signed, pelz message
 *                             data.
 *
 * @param[in]  local_cert_in   Pointer to the message recipient's (local)
 *                             X509 certificate. It contains the public key
 *                             that should have been used to encrypt the
 *                             received enveloped message.
 *
 * @param[in]  local_priv_in   Pointer to the message recipient's (local)
 *                             private key. This private key is needed to
 *                             decrypt the received enveloped message.
 *
 * @param[out] peer_cert_out   Double pointer to message sender's (peer)
 *                             X509 certificate extracted from the received
 *                             signed message.
 *
 * @param[out] msg_data_out    Pointer to decrypted, signature verified,
 *                             and parsed pelz message data struct
 *                             (PELZ_MSG_DATA *).
 *
 * @return                     Zero (PELZ_MSG_SUCCESS = 0) on success;
 *                             error code (negative integer) otherwise
 */
PelzMessagingStatus deconstruct_pelz_msg(charbuf rcvd_msg_buf,
                                         X509 *local_cert_in,
                                         EVP_PKEY *local_priv_in,
                                         X509 **peer_cert_out,
                                         PELZ_MSG_DATA *msg_data_out);

#ifdef __cplusplus
}
#endif
#endif
