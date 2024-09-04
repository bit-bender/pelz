/*
 * test_helper_functions.h
 */

#ifndef TEST_HELPER_FUNCTIONS_H_
#define TEST_HELPER_FUNCTIONS_H_

#include <unistd.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "charbuf.h"
#include "pelz_log.h"

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
 * This function creates two DER-formatted character buffers (charbufs), one
 * containing a certificate and one containing a private key. These provide
 * a matched public/private key pair.
 * </pre>
 *
 * @param[in]  cert_pem_fn   The character string specifying the file name of
 *                           the input PEM-formatted certificate file.
 *
 * @param[in]  priv_pem_fn   The character string specifying the file name of
 *                           the input PEM-formatted private key file.
 *
 * @param[out] der_priv_out  Pointer to the byte buffer (charbuf) where the
 *                           resultant DER-formatted private key will be placed
 *                           for use by the caller.
 *
 * @param[out] der_cert_out  Pointer to the byte buffer (charbuf) where the
 *                           resultant DER-formatted certificate will be placed
 *                           for use by the caller.
 *
 * @return                   zero (0) on success, one (1) on failure
 */
int keypair_pem_to_der(char *cert_pem_fn,
                       char *priv_pem_fn,
                       charbuf *der_cert_out,
                       charbuf *der_priv_out);

#endif /* TEST_HELPER_FUNCTIONS_H_ */
