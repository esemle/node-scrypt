/*
Hook into the scrypt encrypt data feature using a key derevied from a passcode.

By: Eric Semle
*/

#ifndef _SCRYPTENCASYNC_
#define _SCRYPTENCASYNC_

#include "scrypt_async.h"

class ScryptEncAsyncWorker : public ScryptAsyncWorker {
  public:
    ScryptEncAsyncWorker(Nan::NAN_METHOD_ARGS_TYPE info) :
      ScryptAsyncWorker(new Nan::Callback(info[5].As<v8::Function>())),
      key_ptr(reinterpret_cast<uint8_t*>(node::Buffer::Data(info[0]))),
      key_size(node::Buffer::Length(info[0])),
      passwd_ptr(reinterpret_cast<uint8_t*>(node::Buffer::Data(info[1]))),
      passwd_size(node::Buffer::Length(info[1])),
      salt_ptr(reinterpret_cast<uint8_t*>(node::Buffer::Data(info[2]))),
      salt_size(node::Buffer::Length(info[2])),
      hash_size(info[3]->IntegerValue()),
      params(info[4]->ToObject())
    {
      ScryptPeristentObject = Nan::New<v8::Object>();
      ScryptPeristentObject->Set(Nan::New("KeyBuffer").ToLocalChecked(), info[0]);
      ScryptPeristentObject->Set(Nan::New("PasswordBuffer").ToLocalChecked(), info[1]);
      ScryptPeristentObject->Set(Nan::New("HashBuffer").ToLocalChecked(), Nan::NewBuffer(static_cast<uint32_t>(hash_size)).ToLocalChecked());
      ScryptPeristentObject->Set(Nan::New("SaltBuffer").ToLocalChecked(), info[2]);
      SaveToPersistent("ScryptPeristentObject", ScryptPeristentObject);

      hash_ptr = reinterpret_cast<uint8_t*>(node::Buffer::Data(ScryptPeristentObject->Get(Nan::New("HashBuffer").ToLocalChecked())));
    };

    void Execute();
    void HandleOKCallback();

  private:
   const uint8_t* key_ptr;
   const size_t key_size;
   const uint8_t* passwd_ptr;
   const size_t passwd_size;
   const uint8_t* salt_ptr;
   const size_t salt_size;

   const size_t hash_size;
   const NodeScrypt::Params params;
    
   uint8_t* hash_ptr;
};

#endif /* _SCRYPTENCASYNC_ */
