/*
 * test_helper_functions.h
 */

#ifndef TEST_HELPER_FUNCTIONS_H_
#define TEST_HELPER_FUNCTIONS_H_

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "charbuf.h"

/**
 * <pre>
 * This function creates a new charbuf that contains the contents of two
 * character strings
 * </pre>
 *
 * @param[in]  prefix     The character string of the key_id without current
 *                        working directory prefix (schema notation)
 *
 * @param[in]  postfix    The character string of the key_id with current
 *                        working directory postfix (file path)
 *
 * @return                charbuf copy of key_id with current working directory
 */
charbuf copy_CWD_to_id(const char *prefix, const char *postfix);

/**
 * <pre>
 * This function creates a charbuf containing a DER-formatted private
 * key. An EVP_PKEY struct is first created from the contents of a specified
 * PEM formatted file. That EVP_PKEY private key is then DER encoded.
 * </pre>
 *
 * @param[in]  priv_pem_fn   The character string specifying the file name of
 *                           the input PEM-formatted private key file.
 *
 * @param[out] der_priv_out  Pointer to the byte buffer (charbuf) where the
 *                           resultant DER-formatted private key will be placed
 *                           for use by the caller.
 *
 * @return                   zero (0) on success, one (1) on failure
 */
int pem_priv_to_der(char *priv_pem_fn, charbuf *der_priv_out);

/**
 * <pre>
 * This function creates a charbuf containing a DER-formatted certificate.
 * An X509 struct is first created from the contents of a specified
 * PEM formatted file. That X509 certificate is then DER encoded.
 * </pre>
 *
 * @param[in]  cert_pem_fn   The character string specifying the file name of
 *                           the input PEM-formatted certificate file.
 *
 * @param[out] der_cert_out  Pointer to the byte buffer (charbuf) where the
 *                           resultant DER-formatted certificate will be placed
 *                           for use by the caller.
 *
 * @return                   zero (0) on success, one (1) on failure
 */
int pem_cert_to_der(char *cert_pem_fn, charbuf *der_cert_out);

#endif /* TEST_HELPER_FUNCTIONS_H_ */
