/*
Hook into the scrypt encrypt data feature using a key derevied from a passcode.

By: Eric Semle
*/

#include <stdio.h>

#include "scryptenc.h"
#include "enc.h"

int Enc(const uint8_t * key, size_t keylen, uint8_t * outbuf, const uint8_t * passwd, size_t passwdlen, const uint8_t* salt, size_t saltlen, uint32_t rounds, uint32_t memcost) {
  return scryptenc_buf_saltlen((uint8_t *) key, keylen,
                               (uint8_t *) outbuf,
                               (uint8_t *) passwd, passwdlen,
                               (uint8_t *) salt, saltlen,
                              rounds, memcost);
}