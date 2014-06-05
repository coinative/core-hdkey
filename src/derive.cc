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

  const unsigned char *IL_data = (const unsigned char*)Buffer::Data(args[0]->ToObject());
  const unsigned char *prv_data = (const unsigned char*)Buffer::Data(args[1]->ToObject());

  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *IL = BN_bin2bn(IL_data, 32, NULL),
    *kpar = BN_bin2bn(prv_data, 32, NULL),
    *n = BN_new(),
    *ki = BN_new();
  EC_KEY *ec = EC_KEY_new_by_curve_name(NID_secp256k1);
  const EC_GROUP *group = EC_KEY_get0_group(ec);
  EC_GROUP_get_order(group, n, ctx);

  // IL + kpar (mod n)
  BN_mod_add(ki, IL, kpar, n, ctx);

  Handle<Object> ki_buf = NanNewBufferHandle(32);
  BN_bn2bin(ki, (unsigned char*)Buffer::Data(ki_buf));

  EC_KEY_free(ec);
  BN_clear_free(IL);
  BN_clear_free(kpar);
  BN_clear_free(n);
  BN_clear_free(ki);
  BN_CTX_free(ctx);

  NanReturnValue(ki_buf);
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
  if (Buffer::Length(args[1]) != 65) {
    return NanThrowError("pub must have length 65");
  }

  const unsigned char *IL_data = (const unsigned char*)Buffer::Data(args[0]->ToObject());
  const unsigned char *pub_data = (const unsigned char*)Buffer::Data(args[1]->ToObject());

  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *IL = BN_bin2bn(IL_data, 32, NULL);
  EC_KEY *ec = EC_KEY_new_by_curve_name(NID_secp256k1);
  const EC_GROUP *group = EC_KEY_get0_group(ec);
  EC_POINT *Ki = EC_POINT_new(group);

  // Get Kpar from public key data
  o2i_ECPublicKey(&ec, &pub_data, 65);
  const EC_POINT *Kpar = EC_KEY_get0_public_key(ec);

  // Ki = point(IL) / (IL * G)
  EC_POINT_mul(group, Ki, IL, NULL, NULL, ctx);
  // Ki = Ki + Kpar
  EC_POINT_add(group, Ki, Ki, Kpar, ctx);

  Handle<Object> Ki_buf = NanNewBufferHandle(65);
  EC_POINT_point2oct(group, Ki, POINT_CONVERSION_UNCOMPRESSED, (unsigned char*)Buffer::Data(Ki_buf), 65, ctx);

  EC_POINT_free(Ki);
  EC_KEY_free(ec);
  BN_clear_free(IL);
  BN_CTX_free(ctx);

  NanReturnValue(Ki_buf);
}

NODE_MODULE(derive, InitAll)
