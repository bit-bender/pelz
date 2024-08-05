/*
 * @file secure_socket_enclave.h
 */

#ifndef INCLUDE_UNSECURE_SOCKET_ENCLAVE_H_
#define INCLUDE_UNSECURE_SOCKET_ENCLAVE_H_

#include <stdint.h>
#include <string.h>

#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_eid.h"
#include "sgx_ecp_types.h"
#include "sgx_thread.h"

#include "charbuf.h"
#include "pelz_request_handler.h"
#include "pelz_enclave_log.h"

#include ENCLAVE_HEADER_TRUSTED

#endif
