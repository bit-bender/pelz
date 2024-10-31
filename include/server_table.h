#ifndef _SERVER_TABLE_H_
#define _SERVER_TABLE_H_

#include <openssl/x509.h>

typedef struct {
  EVP_PKEY *private_pkey;
  X509 *cert;
  char *common_name;
} pelz_identity_t;

X509 *get_service_cert(void);
EVP_PKEY *get_service_priv(void);

#endif
