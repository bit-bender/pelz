/*
 * pelz_request_handler.h
 */

#ifndef INCLUDE_PELZ_REQUEST_HANDLER_H_
#define INCLUDE_PELZ_REQUEST_HANDLER_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/cms.h>
#include <openssl/evp.h>

#include "charbuf.h"

//The maxim key length
#define MAX_KEY_LEN 1024
#define MAX_SOC_DATA_SIZE 1024

typedef enum
{ REQ_UNK, REQ_ENC, REQ_DEC, REQ_ENC_SIGNED, REQ_DEC_SIGNED, REQ_ENC_PROTECTED, REQ_DEC_PROTECTED } RequestType;

typedef enum
{ REQUEST_OK,
  KEK_NOT_LOADED,
  KEK_LOAD_ERROR,
  KEY_OR_DATA_ERROR,
  ENCRYPT_ERROR,
  DECRYPT_ERROR,
  MESSAGE_TYPE_ERROR,
  REQUEST_TYPE_ERROR,
  CHARBUF_ERROR,
  DER_DECODE_ERROR,
  DER_ENCODE_ERROR,
  CMS_DECRYPT_ERROR,
  CMS_ENCRYPT_ERROR,
  CMS_VERIFY_ERROR,
  CMS_SIGN_ERROR,
  SIGNATURE_ERROR
} RequestResponseStatus;

#endif /* INCLUDE_PELZ_REQUEST_HANDLER_H_ */
