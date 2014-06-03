var Key = require('core-key');
var sjcl = require('core-sjcl');
var ecc = sjcl.ecc;
var curve = ecc.curves.k256;
var b = sjcl.bitArray;

var toBits = sjcl.codec.bytes.toBits;
var toBytes = sjcl.codec.bytes.fromBits;
var bn = function (buffer) {
  return sjcl.bn.fromBits(toBits(buffer));
};

var _0x00 = [b.partial(8, 0x00)];
var _0x02 = [b.partial(8, 0x02)];
var Q = new sjcl.bn('3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c');

function pubToPoint(pub) {
  var even = b.bitSlice(pub, 0, 8);
  var xBits = b.concat(_0x00, b.bitSlice(pub, 8, 256 + 8));
  var yBits = b.concat(_0x00, b.bitSlice(pub, 256 + 8));

  var x = sjcl.bn.fromBits(xBits);
  var y = sjcl.bn.fromBits(yBits);

  // Decompress Y if necessary
  if (y.equals(0) && curve.field.modulus.mod(new sjcl.bn(4)).equals(new sjcl.bn(3))) {
    // y^2 = x^3 + ax^2 + b, so we need to perform sqrt to recover y
    var ySquared = curve.b.add(x.mul(curve.a.add(x.square())));
    var y = ySquared.powermod(Q, curve.field.modulus);

    if (y.mod(2).equals(0) !== b.equal(even, _0x02)) {
      y = curve.field.modulus.sub(y);
    }
  }
  // reserialise curve here, expection is thrown when point is not on curve.
  return ecc.curves.k256.fromBits(new ecc.point(curve, x, y).toBits());
};

exports.derivePrivate = function (IL, prv) {
  IL = bn(IL);
  if (IL.greaterEquals(curve.r)) return;
  prv = bn(prv);
  var ki = IL.add(prv).mod(curve.r);
  if (ki.equals(0)) return;

  return new Buffer(toBytes(ki.toBits()));
};

exports.derivePublic = function (IL, pub) {
  IL = bn(IL);
  if (IL.greaterEquals(curve.r)) return;
  pub = pubToPoint(toBits(pub));
  var ILMult = curve.G.mult(IL);
  var Ki = new ecc.point(curve, pub.toJac().add(ILMult).toAffine().x, ILMult.toJac().add(pub).toAffine().y);

  var even = Ki.y.mod(2).equals(0);
  var enc = [even ? 0x02 : 0x03].concat(toBytes(Ki.x.toBits()));

  return new Buffer(enc);
};
