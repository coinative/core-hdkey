var Address = require('core-address');
var base58 = require('core-base58');
var derive = require('./derive-module');
var hmacsha512 = require('core-hash').hmacsha512;
var hash160 = require('core-hash').hash160;
var Key = require('core-key');

function parseExtendedKey(xkey) {
  var data = base58.decodeCheck(xkey);
  if (!data || data.length !== 78) {
    throw new Error('invalid data or checksum');
  }
  var version = HDKey.versions[data.readUInt32BE(0)];
  if (!version) {
    throw new Error('unknown version');
  }

  var options = {
    network: version.network,
    depth: data.readUInt8(4),
    parent: data.slice(5, 9),
    index: data.readUInt32BE(9),
    chain: data.slice(13, 45)
  };

  if (version.type === 'prv') {
    // Discard the prefixed 0x00 byte
    options.prv = data.slice(46, 78);
  } else {
    options.pub = data.slice(45, 78);
  }

  return options;
}

function deriveFromMasterSeed(seed) {
  var masterSeed = hmacsha512(new Buffer('Bitcoin seed'), seed);
  return {
    chain: masterSeed.slice(32),
    prv: masterSeed.slice(0, 32)
  };
}

function HDKey(data) {
  if (!data) {
    throw new Error('no data');
  }
  if (typeof data === 'string') {
    return new HDKey(parseExtendedKey(data));
  }
  this.network = data.network || 'mainnet';
  if (Buffer.isBuffer(data.seed)) {
    return new HDKey(deriveFromMasterSeed(data.seed));
  }
  if (!(data.chain && data.chain.length === 32)) {
    throw new Error('invalid chain code');
  }
  if (!(data.prv && data.prv.length === 32) && !(data.pub && (data.pub.length >= 33 && data.pub.length <= 65 ))) {
    throw new Error('invalid keys');
  }

  this.chain = data.chain;
  if (data.prv) {
    this.prv = data.prv;
    this.key = new Key({ prv: data.prv });
  } else {
    this.key = new Key({ pub: data.pub });
  }
  this.pub = this.key.pub;
  this.id = hash160(this.pub);
  this.fingerprint = this.id.slice(0, 4);
  this.parent = data.parent || new Buffer([0, 0, 0, 0]);
  this.depth = data.depth || 0;
  this.index = data.index || 0;
}

HDKey.prototype.getAddress = function () {
  return new Address(this.id, 'pubkeyhash', this.network);
};

HDKey.prototype.derive = function (index) {
  var hardened = index >= HDKey.HARDENED_START;
  var data = new Buffer(37);
  if (hardened) {
    if (!this.prv) {
      throw new Error('Cannot derive hardened child without a private key');
    }
    data[0] = 0;
    this.prv.copy(data, 1, 0, 32);
  } else {
    this.pub.copy(data, 0, 0, 33);
  }
  data.writeUInt32BE(index, 33);

  var I = hmacsha512(this.chain, data);
  var IL = I.slice(0, 32);
  var IR = I.slice(32);

  var child = {
    chain: IR,
    network: this.network,
    depth: this.depth + 1,
    parent: this.fingerprint,
    index: index
  };

  if (this.prv) {
    child.prv = derive.derivePrivate(IL, this.prv);
  } else {
    child.pub = derive.derivePublic(IL, this.key._point || this.pub);
  }
  return new HDKey(child);
};

HDKey.prototype.deriveHardened = function (index) {
  return this.derive(HDKey.HARDENED_START + index);
};

HDKey.prototype.toBuffer = function (prv) {
  if (prv && !this.prv) {
    throw new Error('not private key');
  }
  var buffer = new Buffer(78);
  buffer.writeUInt32BE(HDKey.networks[this.network][prv ? 'prv' : 'pub'], 0);
  buffer.writeUInt8(this.depth, 4);
  this.parent.copy(buffer, 5, 0, 4);
  buffer.writeUInt32BE(this.index, 9);
  this.chain.copy(buffer, 13, 0, 32);
  if (prv) {
    buffer[45] = 0;
    this.prv.copy(buffer, 46, 0, 32);
  } else {
    this.pub.copy(buffer, 45, 0, 33);
  }
  return buffer;
};

HDKey.prototype.toString = function (prv) {
  return base58.encodeCheck(this.toBuffer(prv));
};

HDKey.isValid = function (data) {
  try {
    new HDKey(data);
    return true;
  } catch (e) {
    return false;
  }
};

HDKey.networks = {
  mainnet: {
    prv: 0x0488ade4,
    pub: 0x0488b21e
  },
  testnet: {
    prv: 0x04358394,
    pub: 0x043587cf
  }
};

Object.defineProperty(HDKey, 'versions', {
  get: function () {
    var networks = HDKey.networks;
    return Object.keys(networks).reduce(function (versions, network) {
      Object.keys(networks[network]).forEach(function (type) {
        var version = networks[network][type];
        versions[version] = { network: network, type: type };
      });
      return versions;
    }, {});
  }
});

HDKey.HARDENED_START = 0x80000000;

module.exports = HDKey;
