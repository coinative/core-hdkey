#include <node.h>
#include <node_buffer.h>
#include <nan.h>
#include "./derive.h"

#include <openssl/ecdsa.h>
#include <openssl/evp.h>

using namespace v8;
using namespace node;

void InitAll(Handle<Object> exports) {
  exports->Set(NanNew<String>("derivePrivate"),
    NanNew<FunctionTemplate>(DerivePrivate)->GetFunction());

  exports->Set(NanNew<String>("derivePublic"),
    NanNew<FunctionTemplate>(DerivePublic)->GetFunction());
}

NAN_METHOD(DerivePrivate) {
  NanScope();

  if (args.Length() != 2) {
    return NanThrowError("requires IL and prv");
  }
  if (!Buffer::HasInstance(args[0])) {
    return NanThrowError("IL must be of type Buffer");
  }
  if (Buffer::Length(args[0]) != 32) {
    return NanThrowError("IL must have length 32");
  }
  if (!Buffer::HasInstance(args[1])) {
    return NanThrowError("prv must be of type Buffer");
  }
  if (Buffer::Length(args[1]) != 32) {
    return NanThrowError("prv must have length 32");
  }

  Handle<Object> IL_buf = args[0]->ToObject();
  Handle<Object> prv_buf = args[1]->ToObject();
  const unsigned char *IL_data = (const unsigned char*)Buffer::Data(IL_buf);
  const unsigned char *prv_data = (const unsigned char*)Buffer::Data(prv_buf);

  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *IL = BN_bin2bn(&IL_data[0], 32, NULL),
    *prv = BN_bin2bn(&prv_data[0], 32, NULL),
    *order = BN_new(),
    *ki = BN_new();
  EC_KEY *ec = EC_KEY_new_by_curve_name(NID_secp256k1);
  const EC_GROUP *group = EC_KEY_get0_group(ec);

  EC_GROUP_get_order(group, order, ctx);

  BN_mod_add(ki, IL, prv, order, ctx);

  unsigned char *ki_data = (unsigned char *)malloc(32);
  BN_bn2bin(ki, &ki_data[0]);

  EC_KEY_free(ec);
  BN_clear_free(IL);
  BN_clear_free(prv);
  BN_clear_free(order);
  BN_clear_free(ki);
  BN_CTX_free(ctx);

  NanReturnValue(NanNewBufferHandle((char *)ki_data, 32));
}

NAN_METHOD(DerivePublic) {
  NanScope();

  if (args.Length() != 2) {
    return NanThrowError("requires IL and pub");
  }
  if (!Buffer::HasInstance(args[0])) {
    return NanThrowError("IL must be of type Buffer");
  }
  if (Buffer::Length(args[0]) != 32) {
    return NanThrowError("IL must have length 32");
  }
  if (!Buffer::HasInstance(args[1])) {
    return NanThrowError("pub must be of type Buffer");
  }
  if (Buffer::Length(args[1]) != 33) {
    return NanThrowError("pub must have length 33");
  }

  Handle<Object> IL_buf = args[0]->ToObject();
  Handle<Object> pub_buf = args[1]->ToObject();
  const unsigned char *IL_data = (const unsigned char*)Buffer::Data(IL_buf);
  const unsigned char *pub_data = (const unsigned char*)Buffer::Data(pub_buf);

  BN_CTX *ctx = BN_CTX_new();;
  BIGNUM *IL = BN_bin2bn(&IL_data[0], 32, NULL);;
  EC_KEY *ec = EC_KEY_new_by_curve_name(NID_secp256k1);;
  const EC_GROUP *group = EC_KEY_get0_group(ec);;
  EC_POINT *r = EC_POINT_new(group);

  o2i_ECPublicKey(&ec, &pub_data, 33);
  const EC_POINT *pubPoint = EC_KEY_get0_public_key(ec);

  EC_POINT_mul(group, r, IL, NULL, NULL, ctx);
  EC_POINT_add(group, r, r, pubPoint, ctx);

  Buffer *rbuf = Buffer::New(33);
  EC_POINT_point2oct(group, r, POINT_CONVERSION_COMPRESSED, (unsigned char *)Buffer::Data(rbuf), 33, ctx);

  EC_POINT_free(r);
  EC_KEY_free(ec);
  BN_clear_free(IL);
  BN_CTX_free(ctx);

  NanReturnValue(rbuf->handle_);
}

NODE_MODULE(derive, InitAll)
