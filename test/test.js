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
      expect(hdkey.getAddress().toString()).equal('16TCjdfJrdZb7Xw7UCbpws9FaCvjn9aEA6');
    });

    it('can derive new public key with public key derivation (< 0x80000000)', function () {
      var child = hdkey.derive(1);
      expect(child.parent).to.deep.equal(hdkey.fingerprint);
      expect(child.depth).to.equal(hdkey.depth + 1);
      expect(child.index).to.equal(1);
    });

    it('should throw error on public key by private dervivation (>= 0x80000000)', function () {
      expect(function () { hdkey.derive(0x80000000) }).to.throw('Cannot derive hardened child without a private key');
    });

    it('serialized hex xpubkey should conform to BIP32 spec', function () {
      expect(xpubkey.slice(0, 4).toString('hex')).equal('0488b21e');
      expect(xpubkey.slice(4, 5).toString('hex')).equal('00');
      expect(xpubkey.slice(5, 9).toString('hex')).equal('00000000');
      expect(xpubkey.slice(9, 13).toString('hex')).equal('00000000');
      expect(xpubkey.slice(13, 45).toString('hex')).equal('9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271');
      expect(xpubkey.slice(45, 78).toString('hex')).equal('03fe9764ba6f1cc2102c394cd558ef463d25f509ff936abf4ad81f84e8f4773848');
    });
  });

  describe('mainnet (xpubkey)', function () {
    var hdkey = HDKey('xpub661MyMwAqRbcFqSvGjzP9GyNMfkZQVfoPFwY7PknFsDiBHmtKtt89uBachDqCGrJkCorkYgwMAScotJfJJzLxtLRuoNgsZULWaTSHGt2E18');
    var xpubkey = hdkey.toBuffer();

    it('should generate valid address', function () {
      expect(hdkey.getAddress().toString()).equal('13t8adp97X5vrzmWWJfhrtxH3CbaJJGjqS');
    });

    it('can derive new public key with public key derivation (< 0x80000000)', function () {
      var child = hdkey.derive(1);
      expect(child.parent).to.deep.equal(hdkey.fingerprint);
      expect(child.depth).to.equal(hdkey.depth + 1);
      expect(child.index).to.equal(1);
    });

    it('should throw error on public key by private dervivation (>= 0x80000000)', function () {
      expect(function () { hdkey.derive(0x80000000) }).to.throw('Cannot derive hardened child without a private key');
    });

    it('serialized hex xpubkey should conform to BIP32 spec', function () {
      expect(xpubkey.slice(0, 4).toString('hex')).equal('0488b21e');
      expect(xpubkey.slice(4, 5).toString('hex')).equal('00');
      expect(xpubkey.slice(5, 9).toString('hex')).equal('00000000');
      expect(xpubkey.slice(9, 13).toString('hex')).equal('00000000');
      expect(xpubkey.slice(13, 45).toString('hex')).equal('81e79e3eab011fec94262a7d8619f7dcf09c4192312d59e10518402ae0ad18ed');
      expect(xpubkey.slice(45, 78).toString('hex')).equal('03d5162875f5337e594c3f8d966719a93f95677d6311c74dfcd4b65a4c1259150e');
    });
  });

  describe('mainnet (xprvkey)', function () {
    var hdkey = HDKey('xprv9x6CNcVVo6MbqTgRwxV782YKjykcdgKvFCXiarNeuz9A9djwf8RmVKbm1UZEao55zWUFdZjUxLnEBYSYzPfRXg3aFeuSmkAmR4g799tr7XP');
    var xprvkey = hdkey.toBuffer(true);
    var xpubkey = hdkey.toBuffer();

    it('should generate correct xpubkey', function () {
      expect(hdkey.toString()).to.equal('xpub6B5Yn82PdTuu3wku3z27VAV4J1b7393mcRTKPEnGUKg92S56Cfk237vErincMLgL3X1agVnbfiUPgMNicAvNXvvBorVf8oKi5i8DEq46PSU');
    });

    it('should generate valid address', function () {
      expect(hdkey.getAddress().toString()).equal('13NT9tp2AvtXY3Mp8gcxSUNcPC6AnDPB69');
    });

    it('should generate index 1', function () {
      expect(hdkey.index).to.equal(1);
    });

    it('can derive new private key with private derivation', function () {
      var child = hdkey.derive(1);
      expect(child.parent).to.deep.equal(hdkey.fingerprint);
      expect(child.index).to.equal(1);
      expect(child.depth).to.equal(hdkey.depth + 1);
    });

    it('can derive new private key with hardened private key derivation (>= 0x80000000)', function () {
      var child = hdkey.derive(0x80000000);
      expect(child.parent).to.deep.equal(hdkey.fingerprint);
      expect(child.index).to.equal(2147483648);
      expect(child.depth).to.equal(hdkey.depth + 1);
    });

    it('can derive new public key with public key derivation (< 0x80000000)', function () {
      var child = hdkey.derive(1);
      expect(child.parent).to.deep.equal(hdkey.fingerprint);
      expect(child.index).to.equal(1);
      expect(child.depth).to.equal(hdkey.depth + 1);
    });

    it('serialized xprvkey should conform to BIP32 spec', function () {
      expect(xprvkey.slice(0, 4).toString('hex')).equal('0488ade4');
      expect(xprvkey.slice(4, 5).toString('hex')).equal('02');
      expect(xprvkey.slice(5, 9).toString('hex')).equal('b2134185');
      expect(xprvkey.slice(9, 13).toString('hex')).equal('00000001');
      expect(xprvkey.slice(13, 45).toString('hex')).equal('bef58a946d16c8c175041bde4006b73434b3524f6317935506f944b379e874de');
      expect(xprvkey.slice(45, 78).toString('hex')).equal('007ed609b5aa631927227a1bd5b7e870d4d9ac158a35c286031b7bdb507e2a42a0');
    });

    it('serialized xpubkey should conform to BIP32 spec', function () {
      expect(xpubkey.slice(0, 4).toString('hex')).equal('0488b21e');
      expect(xpubkey.slice(4, 5).toString('hex')).equal('02');
      expect(xpubkey.slice(5, 9).toString('hex')).equal('b2134185');
      expect(xpubkey.slice(9, 13).toString('hex')).equal('00000001');
      expect(xpubkey.slice(13, 45).toString('hex')).equal('bef58a946d16c8c175041bde4006b73434b3524f6317935506f944b379e874de');
      expect(xpubkey.slice(45, 78).toString('hex')).equal('02157ff2eb722cb80f3d4836a6d47623727a396bc8afcaf854072bab7862db052f');
    });
  });

  describe('testnet (chain+pub)', function () {
    var hdkey = new HDKey({
      chain: hex('9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271'),
      pub: hex('048819FA4D69BCEB1BCBF0EC9E605FED325D63472EF703E31290B9B278DA3FC88C994DB69A4B2EEB1EE93664462B2EAD0709A8D3BF46DA9C7081A17B8EF7468882'),
      network: 'testnet'
    });
    var xpubkey = hdkey.toBuffer();

    it('should generate valid address', function () {
      expect(hdkey.getAddress().toString()).equal('mjYBku4aaSgzG3FXZb9MmDRTDSuCXM3auM');
    });

    it('can derive new public key with public key derivation (< 0x80000000)', function () {
      var child = hdkey.derive(1);
      expect(child.parent).to.deep.equal(hdkey.fingerprint);
      expect(child.index).to.equal(1);
      expect(child.depth).to.equal(hdkey.depth + 1);
    });

    it('should throw error on public key by private dervivation (>= 0x80000000)', function () {
      expect(function () { hdkey.derive(0x80000000) }).to.throw('Cannot derive hardened child without a private key');
    });

    it('serialized hex xpubkey should conform to BIP32 spec', function () {
      expect(xpubkey.slice(0, 4).toString('hex')).equal('043587cf');
      expect(xpubkey.slice(4, 5).toString('hex')).equal('00');
      expect(xpubkey.slice(5, 9).toString('hex')).equal('00000000');
      expect(xpubkey.slice(9, 13).toString('hex')).equal('00000000');
      expect(xpubkey.slice(13, 45).toString('hex')).equal('9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271');
      expect(xpubkey.slice(45, 78).toString('hex')).equal('028819fa4d69bceb1bcbf0ec9e605fed325d63472ef703e31290b9b278da3fc88c');
    });
  });

  describe('testnet (tpubkey)', function () {
    var hdkey = new HDKey('tpubD6NzVbkrYhZ4XpGe4x9QtGpMstk7H6AuHS2MvoUuQm8qvkppT6xEyB669TJRiMq1hTiFCmVqtosYdvYRWjaL9H2aeYMMi6hvEShHjBATKa8');
    var xpubkey = hdkey.toBuffer();

    it('should generate valid address', function () {
      expect(hdkey.getAddress().toString()).equal('mypmLG7CkR589AvDw7C5zi4UjWDyGdVm8Q');
    });

    it('can derive new public key with public key derivation (< 0x80000000)', function () {
      var child = hdkey.derive(1);
      expect(child.parent).to.deep.equal(hdkey.fingerprint);
      expect(child.index).to.equal(1);
      expect(child.depth).to.equal(hdkey.depth + 1);
    });

    it('should throw error on public key by private dervivation (> 0x80000000)', function () {
      expect(function () { hdkey.derive(0x80000000) }).to.throw('Cannot derive hardened child without a private key');
    });

    it('serialized hex xpubkey should conform to BIP32 spec', function () {
      expect(xpubkey.slice(0, 4).toString('hex')).equal('043587cf');
      expect(xpubkey.slice(4, 5).toString('hex')).equal('00');
      expect(xpubkey.slice(5, 9).toString('hex')).equal('00000000');
      expect(xpubkey.slice(9, 13).toString('hex')).equal('00000000');
      expect(xpubkey.slice(13, 45).toString('hex')).equal('9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271');
      expect(xpubkey.slice(45, 78).toString('hex')).equal('029181cd57ea5f3f9b8f9f7d899845dc32846d0919fafff8242021c658787c4d73');
    });
  });

  describe('testnet (tprvkey)', function () {
    var hdkey = new HDKey('tprv8diKvhCKB3daUuYVf7rFg9efLQKz66E2Qc1prDcmWX14aLPWTJZspYdikNcpe9xRzLbR21BmDsAb8aDsjK7SG7wvLC7uEupNUnchSzuuQQf');
    var xprvkey = hdkey.toBuffer(true);
    var xpubkey = hdkey.toBuffer();

    it('should generate valid address', function () {
      expect(hdkey.getAddress().toString()).equal('muuo1M9dzVXxpd4YV3deSyTwmKY3dhCWLY');
    });

    it('should generate index 1', function () {
      expect(hdkey.index).to.equal(1);
    });

    it('can derive new private key with hardened private key derivation (>= 0x80000000)', function () {
      var child = hdkey.derive(0x80000000);

      expect(child.parent).to.deep.equal(hdkey.fingerprint);
      expect(child.index).to.equal(2147483648);
      expect(child.depth).to.equal(hdkey.depth + 1);
    });

    it('can derive new public key with public key derivation (< 0x80000000)', function () {
      var child = hdkey.derive(1);
      expect(child.parent).to.deep.equal(hdkey.fingerprint);
      expect(child.index).to.equal(1);
      expect(child.depth).to.equal(hdkey.depth + 1);
    });

    it('serialized xprvkey should conform to BIP32 spec', function () {
      expect(xprvkey.slice(0, 4).toString('hex')).equal('04358394');
      expect(xprvkey.slice(4, 5).toString('hex')).equal('02');
      expect(xprvkey.slice(5, 9).toString('hex')).equal('236c336e');
      expect(xprvkey.slice(9, 13).toString('hex')).equal('00000001');
      expect(xprvkey.slice(13, 45).toString('hex')).equal('bb151535c5a19d8de99a34ffbf9acde8fc47039d1f2d4b3a7de07a7f10c2e7c6');
      expect(xprvkey.slice(45, 78).toString('hex')).equal('00678cf93753a5ecd3ad5108cc0e1737d0af4f0662186b2e57b2adc185eaa92a17');
    });

    it('serialized xpubkey should conform to BIP32 spec', function () {
      expect(xpubkey.slice(0, 4).toString('hex')).equal('043587cf');
      expect(xpubkey.slice(4, 5).toString('hex')).equal('02');
      expect(xpubkey.slice(5, 9).toString('hex')).equal('236c336e');
      expect(xpubkey.slice(9, 13).toString('hex')).equal('00000001');
      expect(xpubkey.slice(13, 45).toString('hex')).equal('bb151535c5a19d8de99a34ffbf9acde8fc47039d1f2d4b3a7de07a7f10c2e7c6');
      expect(xpubkey.slice(45, 78).toString('hex')).equal('0270f8766030de843ff194e3e20a42ba7a52840a15f1d4dd3d21acc48af278be53');
    });
  });
});
