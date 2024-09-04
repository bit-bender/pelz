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

int keypair_pem_to_der(char *cert_pem_fn,
                       char *priv_pem_fn,
                       charbuf *der_cert_out,
                       charbuf *der_priv_out)
{
  FILE *pem_fp = fopen(cert_pem_fn, "r");
  if (pem_fp == NULL)
  {
    pelz_log(LOG_ERR, "error opening X509 certificate file (%s)", cert_pem_fn);
    return 1;
  }
  X509 *cert = X509_new();
  PEM_read_X509(pem_fp, &cert, 0, NULL);
  fclose(pem_fp);

  pem_fp = fopen(priv_pem_fn, "r");
  if (pem_fp == NULL)
  {
    pelz_log(LOG_ERR, "error opening private key file (%s)", priv_pem_fn);
    return 1;
  }
  EVP_PKEY *priv = EVP_PKEY_new();
  PEM_read_PrivateKey(pem_fp, &priv, 0, NULL);
  fclose(pem_fp);

  if (X509_check_private_key(cert, priv) != 1)
  {
    pelz_log(LOG_ERR, "cert/private key pairing error");
    return 1;
  }
  pelz_log(LOG_DEBUG, "created matched certificate/private key from PEM file");

  der_cert_out->len = (size_t) i2d_X509(cert, &(der_cert_out->chars));
  if ((der_cert_out->chars == NULL) || (der_cert_out->len == 0))
  {
    pelz_log(LOG_ERR, "error creating DER-formatted X509 certificate");
    return 1;
  }
  pelz_log(LOG_DEBUG,"DER-encoded cert (%zu bytes)", der_cert_out->len);

  der_priv_out->len = (size_t) i2d_PrivateKey(priv, &(der_priv_out->chars));
  if ((der_priv_out->chars == NULL) || (der_priv_out->len == 0))
  {
    pelz_log(LOG_ERR, "error creating DER-formatted private key");
    return 1;
  }
  pelz_log(LOG_DEBUG,"DER-encoded key (%zu bytes)", der_priv_out->len);

  X509_free(cert);
  EVP_PKEY_free(priv);

  return 0;
}
