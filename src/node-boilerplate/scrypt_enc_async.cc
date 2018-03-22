/*
Hook into the scrypt encrypt data feature using a key derevied from a passcode.

By: Eric Semle
*/

#include <nan.h>
#include <node.h>

#include "scrypt_common.h"

#include "scrypt_enc_async.h"

//
// Scrypt is a C library and there needs c linkings
//
extern "C" {
  #include "enc.h"
}

using namespace v8;

//
// Scrypt Encrypt Function
//
void ScryptEncAsyncWorker::Execute() {
  result = Enc(key_ptr, key_size, hash_ptr, passwd_ptr, passwd_size, salt_ptr, salt_size, params.r, params.p);
}

void ScryptEncAsyncWorker::HandleOKCallback() {
  Nan::HandleScope scope;

  Local<Value> argv[] = {
    Nan::Null(),
    GetFromPersistent("ScryptPeristentObject")->ToObject()->Get(Nan::New("HashBuffer").ToLocalChecked())
  };

  callback->Call(2, argv);
}

//
// Asynchronous Scrypt Params
//
NAN_METHOD(enc) {
  Nan::AsyncQueueWorker(new ScryptEncAsyncWorker(info));
}