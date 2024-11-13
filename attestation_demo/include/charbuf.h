/*
 * charbuf.h
 */

#ifndef INCLUDE_CHARBUF_H_
#define INCLUDE_CHARBUF_H_

#include <stdlib.h>

typedef struct charbuffer
{
  unsigned char *chars;
  size_t len;
} charbuf;

/**
 * <pre>
 * Takes a struct charbuf and allocates memory of len then sets charbuf len to @pram[in] len.
 * </pre>
 *
 * @param[in] len Length of new char array, must be smaller than SIZE_MAX.
 *
 * @return the initialized charbuf
 */
charbuf new_charbuf(size_t len);

/**
 * <pre>
 * Takes a struct charbuf and frees the memory allocation then sets the values to null and 0.
 * </pre>
 *
 * @param[in] buf The charbuf to be freed and cleared
 *
 * @return freed and clear charbuf buf
 */
void free_charbuf(charbuf * buf);

#endif /* INCLUDE_CHARBUF_H_ */
