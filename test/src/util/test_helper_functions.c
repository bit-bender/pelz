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

int priv_pem_to_der(char *priv_pem_fn, charbuf *der_priv_out)
{
  FILE *pem_fp = fopen(priv_pem_fn, "r");
  if (pem_fp == NULL)
  {
    pelz_log(LOG_ERR, "error opening private key file (%s)", priv_pem_fn);
    return 1;
  }

  pelz_log(LOG_DEBUG, "opened PEM key file");

  EVP_PKEY *priv = PEM_read_PrivateKey(pem_fp, NULL, 0, NULL);
  pelz_log(LOG_DEBUG, "created EVP_PKEY");

  der_priv_out->len = (size_t) i2d_PrivateKey(priv, &(der_priv_out->chars));
  if ((der_priv_out->chars == NULL) || (der_priv_out->len == 0))
  {
    pelz_log(LOG_ERR, "error creating DER-formatted private key");
    return 1;
  }
  pelz_log(LOG_DEBUG,"DER-encoded key (%zu bytes)", der_priv_out->len);

  EVP_PKEY_free(priv);

  return 0;
}

int cert_pem_to_der(char *cert_pem_fn, charbuf *der_cert_out)
{
  FILE *pem_fp = fopen(cert_pem_fn, "r");
  if (pem_fp == NULL)
  {
    pelz_log(LOG_ERR, "error opening X509 certificate file (%s)", cert_pem_fn);
    return 1;
  }

  pelz_log(LOG_DEBUG, "opened PEM cert file");

  X509 *cert = PEM_read_X509(pem_fp, NULL, 0, NULL);
  pelz_log(LOG_DEBUG, "created X509");

  der_cert_out->len = (size_t) i2d_X509(cert, &(der_cert_out->chars));
  if ((der_cert_out->chars == NULL) || (der_cert_out->len == 0))
  {
    pelz_log(LOG_ERR, "error creating DER-formatted X509 certificate");
    return 1;
  }
  pelz_log(LOG_DEBUG,"DER-encoded cert (%zu bytes)", der_cert_out->len);

  X509_free(cert);

  return 0;
}
