var HDKey = require('../');
var base58 = require('core-base58');

function hex(hex) { return new Buffer(hex, 'hex'); };

describe('HDKey', function () {
  describe('default properties', function () {
    var hdkey = new HDKey({
      chain: hex('04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f'),
      pub: hex('0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2')
    });
    it('should default version to mainnet', function () {
      expect(hdkey.network).to.equal('mainnet');
    });

    it('should default to compressed keys', function () {
      expect(hdkey._key.compressed).to.be.true;
    });

  });

  describe('invalid constructor arguments', function () {
    var chain = hex('0000000000000000000000000000000000000000000000000000000000000000');

    it('no data', function () {
      expect(function () { new HDKey() }).to.throw();
    });

    it('invalid chain code', function () {
      expect(function () { new HDKey({ chain: [] }) }).to.throw('invalid chain code');
    });

    it('invalid keys', function () {
      expect(function () { new HDKey({ chain: chain }) }).to.throw('invalid keys');
    });

    it ('invalid public key (not on the curve)', function () {
      expect(function () {
        new HDKey({
          chain: chain,
          pub: Buffer.concat([new Buffer([0]), chain])
        });
      }).to.throw('invalid public key');
      expect(function () {
        new HDKey({
          chain: chain,
          pub: Buffer.concat([new Buffer([0]), chain, chain])
        });
      }).to.throw('invalid public key');
    });
  });

  describe('isValid', function () {
    it ('valid keys', function () {
      expect(HDKey.isValid('xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8')).to.be.true;
      expect(HDKey.isValid('xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi')).to.be.true;
    });

    it('invalid keys', function () {
      expect(HDKey.isValid('ypub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8')).to.be.false;
      expect(HDKey.isValid('yprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi')).to.be.false;
    });
  });

  describe('public derivation (Test Vector 1 - m/0H/1/2H)', function () {
    var hdkey = new HDKey({
      chain: hex('04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f'),
      pub: hex('0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2'),
      depth: 3
    });

    it('m/0H/1/2H/2', function () {
      var derived = hdkey.derive(2);
      expect(derived.toString()).to.equal('xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV');
    });

    it('m/0H/1/2H/2/1000000000', function () {
      var derived = hdkey.derive(2).derive(1000000000);
      expect(derived.toString()).to.equal('xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy');
    });
  });

  describe('mainnet (chain+pub)', function () {
    var hdkey = new HDKey({
      chain: hex('9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271'),
      pub: hex('04fe9764ba6f1cc2102c394cd558ef463d25f509ff936abf4ad81f84e8f4773848755b64f5c32e6aa5e461e241133475250182e29c1d3c89d7b5478a4569a389db')
    });
    var xpubkey = hdkey.toBuffer();

    it('should generate valid address', function () {
      expect(hdkey.address.toString()).equal('16TCjdfJrdZb7Xw7UCbpws9FaCvjn9aEA6');
    });

    it('can derive new public key with public key derivation (< 0x80000000)', function () {
      var child = hdkey.derive(1);
      expect(child.parent).to.deep.equal(hdkey.fingerprint);
      expect(child.depth).to.equal(hdkey.depth + 1);
      expect(child.index).to.equal(1);
    });

    it('should throw error on public key by private dervivation (> 0x80000000)', function () {
      expect(function () { hdkey.derive(1 + 0x80000000) }).to.throw('Cannot derive hardened child without a private key');
    });

    it('serialized hex xpubkey should conform to BIP32 spec', function () {
      expect(xpubkey.slice(0, 4).toString('hex')).equal('0488b21e'); // 4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
      expect(xpubkey.slice(4, 5).toString('hex')).equal('00'); // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants
      expect(xpubkey.slice(5, 9).toString('hex')).equal('00000000');
      expect(xpubkey.slice(9, 13).toString('hex')).equal('00000000'); // child index
      expect(xpubkey.slice(13, 45).toString('hex')).equal('9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271'); //chain codes
      expect(xpubkey.slice(45, 78).toString('hex')).equal('03fe9764ba6f1cc2102c394cd558ef463d25f509ff936abf4ad81f84e8f4773848'); // compressed pub key
    });
  });

  describe('mainnet (xpubkey)', function () {
    var hdkey = HDKey('xpub661MyMwAqRbcFqSvGjzP9GyNMfkZQVfoPFwY7PknFsDiBHmtKtt89uBachDqCGrJkCorkYgwMAScotJfJJzLxtLRuoNgsZULWaTSHGt2E18');
    var xpubkey = hdkey.toBuffer();

    it('should generate valid addresses', function () {
      expect(hdkey.address.toString()).equal('13t8adp97X5vrzmWWJfhrtxH3CbaJJGjqS');
    });

    it('can derive new public key with public key derivation (< 0x80000000)', function () {
      var child = hdkey.derive(1);
      expect(child.parent).to.deep.equal(hdkey.fingerprint);
      expect(child.depth).to.equal(hdkey.depth + 1);
      expect(child.index).to.equal(1);
    });

    it('should throw error on public key by private dervivation (> 0x80000000)', function () {
      expect(function () { hdkey.derive(1 + 0x80000000) }).to.throw('Cannot derive hardened child without a private key');
    });

    it('serialized hex xpubkey should conform to BIP32 spec', function () {
      expect(xpubkey.slice(0, 4).toString('hex')).equal('0488b21e'); // 4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
      expect(xpubkey.slice(4, 5).toString('hex')).equal('00'); // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants
      expect(xpubkey.slice(5, 9).toString('hex')).equal('00000000');
      expect(xpubkey.slice(9, 13).toString('hex')).equal('00000000'); // child index
      expect(xpubkey.slice(13, 45).toString('hex')).equal('81e79e3eab011fec94262a7d8619f7dcf09c4192312d59e10518402ae0ad18ed'); //chain codes
      expect(xpubkey.slice(45, 78).toString('hex')).equal('03d5162875f5337e594c3f8d966719a93f95677d6311c74dfcd4b65a4c1259150e'); // compressed pub key
    });
  });
});
