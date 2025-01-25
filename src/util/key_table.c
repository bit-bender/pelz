/*
 * key_table.c
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include <common_table.h>
#include <charbuf.h>
#include <pelz_enclave_log.h>

#include "sgx_trts.h"
#include ENCLAVE_HEADER_TRUSTED
#include "sgx_retrieve_key_impl.h"
#include "server_table.h"

TableResponseStatus key_table_add_key(charbuf key_id, charbuf key)
{
  Entry tmp_entry;

  if (key_table.mem_size >= MAX_MEM_SIZE)
  {
    pelz_sgx_log(LOG_ERR, "key table memory allocation exceeds limit");
    return ERR_MEM;
  }

  tmp_entry.id = copy_chars_from_charbuf(key_id, 0);
  tmp_entry.value.key = copy_chars_from_charbuf(key, 0);

  Entry *temp;

  if ((temp = (Entry *) realloc(key_table.entries,
                                (key_table.num_entries + 1) *
                                sizeof(Entry))) == NULL)
  {
    pelz_sgx_log(LOG_ERR, "key list space reallocation error");
    free_charbuf(&tmp_entry.id);
    secure_free_charbuf(&tmp_entry.value.key);
    return ERR_REALLOC;
  }
  else
  {
    key_table.entries = temp;
  }

  key_table.entries[key_table.num_entries] = tmp_entry;
  key_table.num_entries++;
  key_table.mem_size = key_table.mem_size +
                       ((tmp_entry.value.key.len * sizeof(char)) +
                       (tmp_entry.id.len * sizeof(char)) +
                       (2 * sizeof(size_t)));
  pelz_sgx_log(LOG_INFO, "added key to key table");
  return OK;
}

TableResponseStatus key_table_add_from_handle(charbuf key_id, uint64_t handle)
{
  TableResponseStatus status;
  charbuf key;
  uint8_t *data;
  size_t data_size = 0;

  if (key_table.mem_size >= MAX_MEM_SIZE)
  {
    pelz_sgx_log(LOG_ERR, "Key Table memory allocation greater then specified limit.");
    return ERR_MEM;
  }

  data_size = retrieve_from_unseal_table(handle, &data);
  if (data_size == 0)
  {
    pelz_sgx_log(LOG_ERR, "Failure to retrieve data from unseal table.");
    return RET_FAIL;
  }

  key = new_charbuf(data_size);
  if (data_size != key.len)
  {
    pelz_sgx_log(LOG_ERR, "Charbuf creation error.");
    return ERR_BUF;
  }
  memcpy(key.chars, data, key.len);

  status = key_table_add_key(key_id, key);
  return status;
}

TableResponseStatus key_table_add_from_server(charbuf key_id,
                                              charbuf server_cn,
                                              charbuf port,
                                              charbuf server_key_id)
{
  TableResponseStatus status;
  charbuf key;
  size_t server_index = 0;
  int ret;
  unsigned char *retrieved_key_id = NULL;
  size_t retrieved_key_id_len = 0;
  uint8_t *retrieved_key;
  size_t retrieved_key_len = 0;

  pelz_sgx_log(LOG_DEBUG, "Add key from server to key table");
  if (key_table.mem_size >= MAX_MEM_SIZE)
  {
    pelz_sgx_log(LOG_ERR, "Key Table memory allocation greater then specified limit.");
    return ERR_MEM;
  }

  if (table_lookup(SERVER, server_cn, &server_index))
  {
    pelz_sgx_log(LOG_ERR, "Server ID not found");
    return NO_MATCH;
  }
  pelz_sgx_log(LOG_DEBUG, "Server name lookup success");

  if (pelz_id.private_pkey == NULL || pelz_id.cert == NULL)
  {
    pelz_sgx_log(LOG_ERR, "Private key not found");
    return NO_MATCH;
  }
  pelz_sgx_log(LOG_DEBUG, "Found private key");

  // determine server's network node name from server certificate
  char *msg = NULL;
  unsigned char *temp_san = NULL;
  size_t temp_san_size = 0;
  unsigned char *server_dns = NULL;
  size_t server_dns_size = 0;
  unsigned char *server_ip = NULL;
  size_t server_ip_size = 0;
 
  // parse Subject Alternative Names (SANs) specified in the server cert
  //   - retrieve first DNS SAN encountered (if present)
  //   - retrieve first IP address SAN encountered (if present)
  GENERAL_NAMES *sans = NULL;
  X509 *server_cert = server_table.entries[server_index].value.cert;
  sans = (GENERAL_NAMES *) X509_get_ext_d2i(server_cert,
                                            NID_subject_alt_name,
                                            0,
                                            0);
  int san_count = sk_GENERAL_NAME_num(sans);

  // if SANs specified in certificate, work through them in index order
  for (int i = 0; i < san_count; i++)
	{
		GENERAL_NAME* entry = sk_GENERAL_NAME_value(sans, i);

		switch (entry->type)
    {
    case GEN_DNS:
      temp_san_size = (size_t) ASN1_STRING_to_UTF8(&temp_san,
                                                   entry->d.dNSName);
      if (temp_san_size > 0)
      {
        msg = calloc(temp_san_size + 64, sizeof(char));
        if (msg == NULL)
        {
          pelz_sgx_log(LOG_ERR, "calloc error: log message buffer");
          return MEM_ALLOC_FAIL;
        }
        if (server_dns == NULL)
        {
          server_dns_size = temp_san_size + 1;
          server_dns = calloc(server_dns_size, sizeof(unsigned char));
          if (server_dns == NULL)
          {
            pelz_sgx_log(LOG_ERR, "calloc error: server DNS SAN string");
            return MEM_ALLOC_FAIL;
          }
          snprintf((char *) server_dns,
                   server_dns_size,
                   "%s",
                   (char *) temp_san);
          snprintf(msg,
                  (server_dns_size + 63),
                  "DNS SAN (index = %d) retrieved: %s",
                  i,
                  (char *) server_dns);
          pelz_sgx_log(LOG_DEBUG, msg);
        }
        else
        {
          snprintf(msg,
                  (temp_san_size + 63),
                  "DNS SAN (index = %d) ignored: %s",
                  i,
                  (char *) temp_san);
          pelz_sgx_log(LOG_DEBUG, msg);
        }
        free(msg);
        msg = NULL;
      }
      free(temp_san);
      temp_san = NULL;
      temp_san_size = 0;
      break;

    case GEN_IPADD:
      switch (entry->d.ip->length)
      {
      case 4:
        temp_san = calloc(16, sizeof(unsigned char));
        if (temp_san == NULL)
        {
          pelz_sgx_log(LOG_ERR, "calloc error: SAN string buffer");
          return MEM_ALLOC_FAIL;
        }
        snprintf((char *) temp_san,
                 16,
                 "%d.%d.%d.%d",
                 entry->d.ip->data[0],
                 entry->d.ip->data[1],
                 entry->d.ip->data[2],
                 entry->d.ip->data[3]);
        break;

      case 16:
        temp_san = calloc(40, sizeof(unsigned char));
        if (temp_san == NULL)
        {
          pelz_sgx_log(LOG_ERR, "calloc error: SAN string buffer");
          return MEM_ALLOC_FAIL;
        }
        snprintf((char *) temp_san,
                 40,
                 "%X:%X:%X:%X:%X:%X:%X:%X",
                 (entry->d.ip->data[0] << 8 | entry->d.ip->data[1]),
                 (entry->d.ip->data[2] << 8 | entry->d.ip->data[3]),
                 (entry->d.ip->data[4] << 8 | entry->d.ip->data[5]),
                 (entry->d.ip->data[6] << 8 | entry->d.ip->data[7]),
                 (entry->d.ip->data[8] << 8 | entry->d.ip->data[9]),
                 (entry->d.ip->data[10] << 8 | entry->d.ip->data[11]),
                 (entry->d.ip->data[12] << 8 | entry->d.ip->data[13]),
                 (entry->d.ip->data[14] << 8 | entry->d.ip->data[15]));
        break;

      default:
        msg = calloc(64, sizeof(char));
        if (msg == NULL)
        {
          pelz_sgx_log(LOG_ERR, "error allocating log message buffer");
          return MEM_ALLOC_FAIL;
        }
        snprintf(msg,
                 63,
                 "IP address SAN (index = %d) with invalid length (%d)",
                 i,
                 entry->d.ip->length);
        pelz_sgx_log(LOG_DEBUG, msg);
        free(msg);
        msg = NULL;
        continue;
      }

      temp_san_size = strlen((char *) temp_san);
      msg = calloc(temp_san_size + 64, sizeof (unsigned char));
      if (msg == NULL)
      {
        pelz_sgx_log(LOG_ERR, "calloc error: log message buffer");
        return MEM_ALLOC_FAIL;
      }
      if (server_ip == NULL)
      {
        server_ip_size = temp_san_size + 1;
        server_ip = calloc(server_ip_size, sizeof(unsigned char));
        if (server_ip == NULL)
        {
          pelz_sgx_log(LOG_ERR, "calloc error: server IP address SAN string");
          return MEM_ALLOC_FAIL;
        }
        snprintf((char *) server_ip,
                 server_ip_size,
                 "%s",
                 (char *) temp_san);
        snprintf(msg,
                (server_ip_size + 63),
                "IP address SAN (index = %d) retrieved: %s",
                i,
                (char *) server_ip);
        pelz_sgx_log(LOG_DEBUG, msg);
      }
      else
      {
        snprintf(msg,
                (temp_san_size + 63),
                "IP address SAN (index = %d) ignored: %s",
                i,
                (char *) temp_san);
        pelz_sgx_log(LOG_DEBUG, msg);
      }
      free(temp_san);
      temp_san = NULL;
      temp_san_size = 0;
      break;

    default:
      msg = calloc(64, sizeof(char));
      if (msg == NULL)
      {
        pelz_sgx_log(LOG_ERR, "calloc error: log message buffer");
        return MEM_ALLOC_FAIL;
      }
      snprintf(msg,
               63,
               "non-DNS, non-IPADD SAN (index = %d) ignored",
               i);
      pelz_sgx_log(LOG_DEBUG, msg);
      free(msg);
      msg = NULL;

    }
  }

  // construct null terminated server name and port strings
  // as the socket calls require. Assign server's "network name"
  // in the following order:
  //   1. if IP address SAN retrieved, use it first
  //   2. if DNS SAN retrieved, use it next
  //   3. if no valid SANs, use the common name (CN)
  unsigned char *server_name = NULL;
  size_t server_name_size = 0;
  unsigned char *server_port = NULL;
  size_t server_port_size = 0;

  if (server_ip == NULL)
  {
    if (server_dns == NULL)
    {
      server_name = null_terminated_string_from_charbuf(server_cn);
      server_name_size = server_cn.len + 1;
    }
    else
    {
      server_name = (unsigned char *) server_dns;
      server_name_size = (size_t) server_dns_size;
    }
  }
  else
  {
    server_name = (unsigned char *) server_ip;
    server_name_size = (size_t) server_ip_size;
    if (server_dns != NULL)
    {
      free(server_dns);
      server_dns = NULL;
      server_dns_size = 0;
    }
  }
  server_port = null_terminated_string_from_charbuf(port);
  server_port_size = port.len + 1;

  pelz_sgx_log(LOG_DEBUG, (const char *) server_name);
  pelz_sgx_log(LOG_DEBUG, (const char *) server_port);

  //the +1 is used for the len of common_name to account for the null terminater added to server_name
  ret = enclave_retrieve_key(pelz_id.private_pkey,
                             pelz_id.cert,
                             server_table.entries[server_index].value.cert,
                             (const char *) server_name,
                             server_name_size,
                             (const char *) server_port,
                             server_port_size,
                             server_key_id.chars,
                             server_key_id.len,
                             &retrieved_key_id,
                             &retrieved_key_id_len,
                             &retrieved_key,
                             &retrieved_key_len);
  if (ret)
  {
    pelz_sgx_log(LOG_ERR, "Retrieve Key function failure");
    return RET_FAIL;
  }
  pelz_sgx_log(LOG_DEBUG, "Retrieve Key from Server");

  if (server_key_id.len != retrieved_key_id_len || memcmp(retrieved_key_id, server_key_id.chars, retrieved_key_id_len) != 0)
  {	
    pelz_sgx_log(LOG_ERR, "Retrieved Key Invalid Key ID");
    return RET_FAIL;
  }

  if (retrieved_key_len == 0  || retrieved_key == NULL)
  {
    pelz_sgx_log(LOG_ERR, "Retrieved Key Invalid");
    return RET_FAIL;
  }	  

  key = new_charbuf(retrieved_key_len);
  if (retrieved_key_len != key.len)
  {
    pelz_sgx_log(LOG_ERR, "Charbuf creation error.");
    return ERR_BUF;
  }
  memcpy(key.chars, retrieved_key, key.len);
  status = key_table_add_key(key_id, key);
  pelz_sgx_log(LOG_DEBUG, "Successfully added key from server to key table");
  return status;
}
