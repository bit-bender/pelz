#include <string.h>

#include "charbuf.h"
#include "pelz_request_handler.h"
#include "pelz_enclave_log.h"

#include "unsecure_socket_enclave.h"

#include ENCLAVE_HEADER_TRUSTED

//Process an incoming message and store data in the session object
uint32_t handle_unsecure_socket_msg(unsigned char *req_msg_in,
                                    size_t req_msg_in_size,
                                    unsigned char **resp_msg_out,
                                    size_t *resp_msg_out_size)

{
  if((req_msg_in == NULL) || (req_msg_in_size == 0))
  {
    pelz_sgx_log(LOG_ERR, "Invalid pelz request message input buffer");
    return (uint32_t) REQUEST_RESPONSE_BUFFER_ERROR;
  }

  if (resp_msg_out == NULL)
  {
    pelz_sgx_log(LOG_ERR, "Invalid pelz response message output buffer");
    return (uint32_t) REQUEST_RESPONSE_BUFFER_ERROR;
  }

  charbuf req_buf = { .chars = req_msg_in, .len = req_msg_in_size };
  charbuf resp_buf = { .chars = *resp_msg_out, .len = *resp_msg_out_size };
  RequestResponseStatus result = service_pelz_request_msg(req_buf, &resp_buf);

  return (uint32_t) result;
}
