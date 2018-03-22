/*
Hook into the scrypt encrypt data feature using a key derevied from a passcode.

By: Eric Semle
*/

#include <nan.h>
#include <node.h>

#include "scrypt_common.h"

//
// Scrypt is a C library and there needs c linkings
//
extern "C" {
  #include "enc.h"
}

using namespace v8;

//
// Synchronous Scrypt params
//
NAN_METHOD(encSync) {
  //
  // Arguments from JavaScript
  //
  const uint8_t* key_ptr = reinterpret_cast<uint8_t*>(node::Buffer::Data(info[0]));
  const size_t key_size = node::Buffer::Length(info[0]);
  const uint8_t* passwd_ptr = reinterpret_cast<uint8_t*>(node::Buffer::Data(info[1]));
  const size_t passwd_size = node::Buffer::Length(info[1]);
  const uint8_t* salt_ptr = reinterpret_cast<uint8_t*>(node::Buffer::Data(info[2]));
  const size_t salt_size = node::Buffer::Length(info[2]);
  const size_t hash_size = info[3]->IntegerValue();
  const NodeScrypt::Params params = info[4]->ToObject();

  //
  // Variable Declaration
  //
  Local<Value> hash_result = Nan::NewBuffer(static_cast<uint32_t>(hash_size)).ToLocalChecked();
  uint8_t* hash_ptr = reinterpret_cast<uint8_t*>(node::Buffer::Data(hash_result));

  //
  // Scrypt enc
  //
  const int result = Enc(key_ptr, key_size, hash_ptr, passwd_ptr, passwd_size, salt_ptr, salt_size, params.r, params.p);

  //
  // Error handling
  //
  if (result) {
    Nan::ThrowError(NodeScrypt::ScryptError(result));
  }

  info.GetReturnValue().Set(hash_result);
}
