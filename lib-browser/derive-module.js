var Key = require('satoshi-key');
var sjcl = require('satoshi-sjcl');
var ecc = sjcl.ecc;
var curve = ecc.curves.k256;
var b = sjcl.bitArray;

var toBits = sjcl.codec.bytes.toBits;
var toBytes = sjcl.codec.bytes.fromBits;
var bn = function (buffer) {
  return sjcl.bn.fromBits(toBits(buffer));
};

function pubToPoint(pubUncompressed) {
  var x = new Buffer(33);
  var y = new Buffer(33);
  x[0] = 0;
  y[0] = 0;
  pubUncompressed.copy(x, 1, 1, 33);
  pubUncompressed.copy(y, 1, 33, 65);
  return ecc.curves.k256.fromBits(new ecc.point(curve, bn(x), bn(y)).toBits());
};

exports.derivePrivate = function (IL, prv) {
  IL = bn(IL);
  if (IL.greaterEquals(curve.r)) return;
  prv = bn(prv);
  var ki = IL.add(prv).mod(curve.r);
  if (ki.equals(0)) return;

  return new Buffer(toBytes(ki.toBits()));
};

exports.derivePublic = function (IL, pubUncompressed) {
  IL = bn(IL);
  if (IL.greaterEquals(curve.r)) return;
  var pubPoint = pubToPoint(pubUncompressed);

  var ILMult = curve.G.mult(IL);
  var Ki = pubPoint.toJac().add(ILMult).toAffine();

  var x = toBytes(Ki.x.toBits());
  var y = toBytes(Ki.y.toBits());
  return new Buffer([0x04].concat(x, y));
};
