#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <kmyth/formatting_tools.h>

#include "charbuf.h"
#include "pelz_log.h"
#include "pelz_socket.h"
#include "key_load.h"
#include "pelz_request_handler.h"
#include "pelz_service.h"
#include "unsecure_socket_thread.h"

#include "sgx_urts.h"
#include "pelz_enclave.h"
#include ENCLAVE_HEADER_UNTRUSTED

#define BUFSIZE 1024
#define MODE 0600

static void *unsecure_process_wrapper(void *arg)
{
  unsecure_socket_process(arg);
  pthread_exit(NULL);
}

void *unsecure_socket_thread(void *arg)
{
  ThreadArgs *threadArgs = (ThreadArgs *) arg;
  int port = threadArgs->port;
  int max_requests = threadArgs->max_requests;
  pthread_mutex_t lock = threadArgs->lock;

  ThreadArgs processArgs;
  pthread_t ustid[max_requests];
  int socket_id = 0;
  int socket_listen_id;

  //Initializing Socket
  if (pelz_key_socket_init(max_requests, port, &socket_listen_id))
  {
    pelz_log(LOG_ERR, "Socket Initialization Error");
    return NULL;
  }
  pelz_log(LOG_DEBUG, "Unsecure socket on port %d created with listen_id of %d", port, socket_listen_id);

  do
  {
    if (pelz_key_socket_accept(socket_listen_id, &socket_id))
    {
      pelz_log(LOG_ERR, "Socket Client Connection Error");
      continue;
    }

    if (socket_id == 0)         //This is to reset the while loop if select() times out
    {
      continue;
    }
    pelz_log(LOG_DEBUG, "Unsecure socket connection accepted");

    if (socket_id > max_requests)
    {
      pelz_log(LOG_WARNING, "%d::Over max socket requests.", socket_id);
      pelz_key_socket_close(socket_id);
      continue;
    }

    processArgs.lock = lock;
    processArgs.socket_id = socket_id;
    if (pthread_create(&ustid[socket_id], NULL, unsecure_process_wrapper, &processArgs) != 0)
    {
      pelz_log(LOG_WARNING, "%d::Failed to create thread.", socket_id);
      pelz_key_socket_close(socket_id);
      continue;
    }

    pelz_log(LOG_INFO, "Unsecure Socket Thread %d, %d", (int) ustid[socket_id], socket_id);
  }
  while (socket_listen_id >= 0 && socket_id <= (max_requests + 1) && global_pipe_reader_active);
  
  pelz_log(LOG_DEBUG, "unsecure socket (%d) teardown", socket_listen_id);
  pelz_key_socket_teardown(&socket_listen_id);

  return NULL;
}

void *unsecure_socket_process(void *arg)
{
  ThreadArgs *processArgs = (ThreadArgs *) arg;
  int new_socket = processArgs->socket_id;
  pthread_mutex_t lock = processArgs->lock;

  charbuf request;
  charbuf response;
  sgx_status_t ecall_ret;
  uint32_t status;

  while (!pelz_key_socket_check(new_socket))
  {
    //Receiving request and Error Checking
    if (pelz_key_socket_recv(new_socket, &request))
    {
      pelz_log(LOG_ERR, "%d::Error Receiving Request", new_socket);
      while (!pelz_key_socket_check(new_socket))
      {
        continue;
      }
      pelz_key_socket_close(new_socket);
      return NULL;
    }

    pelz_log(LOG_DEBUG, "%d::Request & Length: %.*s, %d", new_socket, (int) request.len, request.chars, (int) request.len);

    pthread_mutex_lock(&lock);
    ecall_ret = unsecure_socket_pelz_request(eid,
                                             &status,
                                             request.chars,
                                             request.len,
                                             &response.chars,
                                             &response.len);
    pthread_mutex_unlock(&lock);
    if ((ecall_ret != SGX_SUCCESS) || (status != 0))
    {
      pelz_log(LOG_ERR, "pelz request handling (unsecure socket) error");
      return NULL;
    }

    pelz_log(LOG_DEBUG, "%d::Message & Length: %.*s, %d",
                        new_socket,
                        (int) response.len,
                        response.chars,
                        (int) response.len);
    // Send processed request back to client
    if (pelz_key_socket_send(new_socket, response))
    {
      pelz_log(LOG_ERR, "%d::Socket Send Error", new_socket);
      free_charbuf(&response);
      while (!pelz_key_socket_check(new_socket))
      {
        continue;
      }
      pelz_key_socket_close(new_socket);
      return NULL;
    }
    free_charbuf(&response);
  }
  pelz_key_socket_close(new_socket);
  return NULL;
}

