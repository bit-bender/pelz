/*
 * test_helper_functions.c
 */

#include "test_helper_functions.h"

charbuf copy_CWD_to_id(const char *prefix, const char *postfix)
{
  charbuf newBuf;
  char *pointer;
  char cwd[100];

  pointer = getcwd(cwd, sizeof(cwd));
  if (pointer == NULL)
  {
    pelz_log(LOG_ERR, "Get Current Working Directory Failure");
    newBuf = new_charbuf(0);
    return (newBuf);
  }
  newBuf = new_charbuf(strlen(prefix) + strlen(cwd) + strlen(postfix));
  memcpy(newBuf.chars, prefix, strlen(prefix));
  memcpy(&newBuf.chars[strlen(prefix)], cwd, strlen(cwd));
  memcpy(&newBuf.chars[strlen(prefix) + strlen(cwd)], postfix, strlen(postfix));
  return (newBuf);
}

int pem_priv_to_der(char *priv_pem_fn, charbuf *der_priv_out)
{
  BIO * priv_bio = BIO_new_file(priv_pem_fn, "r");
  if (priv_bio == NULL)
  {
    pelz_log(LOG_ERR, "error creating BIO for reading private key from file");
    return 1;
  }
  EVP_PKEY * priv = PEM_read_bio_PrivateKey(priv_bio, NULL, 0, NULL);
  if (priv == NULL)
  {
    pelz_log(LOG_ERR, "error reading private key from file (%s)", priv_pem_fn);
    return 1;
  }
  BIO_free(priv_bio);
  der_priv_out->len = (size_t) i2d_PrivateKey(priv, &(der_priv_out->chars));
  if ((der_priv_out->chars == NULL) || (der_priv_out->len == 0))
  {
    pelz_log(LOG_ERR, "error creating DER-formatted private key");
    return 1;
  }
  EVP_PKEY_free(priv);

  return 0;
}

int pem_cert_to_der(char *cert_pem_fn, charbuf *der_cert_out)
{
  // use PEM file data to create X509 certificate
  BIO *cert_bio = BIO_new_file(cert_pem_fn, "r");
  if (cert_bio == NULL)
  {
    pelz_log(LOG_ERR, "error creating BIO for reading certficate from file");
    return 1;
  }
  X509 *cert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);
  if (cert == NULL)
  {
    pelz_log(LOG_ERR, "error reading X509 cert from file (%s)", cert_pem_fn);
    return 1;
  }
  BIO_free(cert_bio);

  // DER-format X509 certificate
  der_cert_out->len = (size_t) i2d_X509(cert, &(der_cert_out->chars));
  if ((der_cert_out->chars == NULL) || (der_cert_out->len == 0))
  {
    pelz_log(LOG_ERR, "error creating DER-formatted certificate");
    return 1;
  }
  X509_free(cert);

  return 0;
}
