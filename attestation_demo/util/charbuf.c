/*
 * charbuf.c
 */

#include <unistd.h>
#include <stdint.h>
#include <string.h>

#include "charbuf.h"

charbuf new_charbuf(size_t len)
{
  charbuf newBuf;

  newBuf.len = 0;
  newBuf.chars = NULL;

  if (len > 0 && len < SIZE_MAX)
  {
    newBuf.chars = (unsigned char *) malloc(len);
    if (newBuf.chars != NULL)
    {
      newBuf.len = len;
    }
  }
  return newBuf;
}

void free_charbuf(charbuf * buf)
{
  if (buf != NULL)
  {
    free(buf->chars);
    buf->chars = NULL;
    buf->len = 0;
  }
}
