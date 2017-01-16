# encoding: ascii-8bit

module Graphene

  # Elliptic Curve key as used in bitcoin.
  class Key

    attr_reader :key

    # Generate a new keypair.
    #  Graphene::Key.generate
    def self.generate(opts={compressed: true})
      k = new(nil, nil, opts); k.generate; k
    end

    # Import private key from base58 fromat as described in
    # https://en.bitcoin.it/wiki/Private_key#Base_58_Wallet_Import_format and
    # https://en.bitcoin.it/wiki/Base58Check_encoding#Encoding_a_private_key.
    # See also #to_base58
    def self.from_base58(str)
      hex = Graphene.decode_base58(str)
      compressed = hex.size == 74 # graphene
      version, key, checksum = hex.unpack("a2a64a8")
      raise "Invalid version"   unless version == Graphene.network[:privkey_version]
      raise "Invalid checksum"  unless Graphene.checksum(version + key) == checksum
      key = new(key, nil, compressed)
    end

    def ==(other)
      self.priv == other.priv
    end

    # Create a new key with given +privkey+ and +pubkey+.
    #  Graphene::Key.new
    #  Graphene::Key.new(privkey)
    #  Graphene::Key.new(nil, pubkey)
    def initialize(privkey = nil, pubkey = nil, opts={compressed: true})
      compressed = opts.is_a?(Hash) ? opts.fetch(:compressed, true) : opts
      @key = Graphene.bitcoin_elliptic_curve
      @pubkey_compressed = pubkey ? self.class.is_compressed_pubkey?(pubkey) : compressed
      set_priv(privkey)  if privkey
      set_pub(pubkey, @pubkey_compressed)  if pubkey
    end

    # Generate new priv/pub key.
    def generate
      @key.generate_key
    end

    # Get the private key (in hex).
    def priv
      return nil  unless @key.private_key
      @key.private_key.to_hex.rjust(64, '0')
    end

    # Set the private key to +priv+ (in hex).
    def priv= priv
      set_priv(priv)
      regenerate_pubkey
    end

    # Get the public key (in hex).
    # In case the key was initialized with only
    # a private key, the public key is regenerated.
    def pub
      regenerate_pubkey unless @key.public_key
      return nil        unless @key.public_key
      @pubkey_compressed ? pub_compressed : pub_uncompressed
    end

    def pub_compressed
      @key.public_key.group.point_conversion_form = :compressed
      @key.public_key.to_hex.rjust(66, '0')
    end

    def pub_uncompressed
      @key.public_key.group.point_conversion_form = :uncompressed
      @key.public_key.to_hex.rjust(130, '0')
    end

    def compressed
      @pubkey_compressed
    end

    # Set the public key (in hex).
    def pub= pub
      set_pub(pub)
    end

    # Get the hash160 of the public key.
    def hash160
      Graphene.hash160(pub)
    end

    def hash512
      Graphene.hash512(pub)
    end

    def addr_hash160
      Graphene.hash160_to_address(hash160)
    end
    # Get the address corresponding to the public key.
    # def addr
    #   Graphene.hash160_to_address(hash160)
    # end

    # address with public key
    # graphene use hash512 to get public key
    def addr
      Graphene.hash512_to_address(hash512)
    end

    def addr_uncompressed
      Graphene.hash512_to_address(Graphene.hash512(pub_uncompressed))
    end

    def addr_compressed
      Graphene.hash512_to_address(Graphene.hash512(pub_compressed))
    end

    # public key string with prefix
    # be default, return compressed pubkey
    # can pass in pubhex to convert, either compressed or uncompressed
    #
    # @exmaple:
    #   key.pubkey # default
    #   key.pubkey(false) # return uncompressed prefix publick key
    def pub_str(compressed = true)
      Graphene.g_encode_address(compressed ? pub_compressed : pub_uncompressed)
    end
    alias_method :pubkey, :pub_str

    # convert prefix base58 pubkey back to hex
    def self.pub_str_to_hex(str)
      Graphene.grapheneBase58CheckDecode(str)
    end

    # Sign +data+ with the key.
    #  key1 = Graphene::Key.generate
    #  sig = key1.sign("some data")
    def sign(data)
      Graphene.sign_data(key, data)
    end

    # Verify signature +sig+ for +data+.
    #  key2 = Graphene::Key.new(nil, key1.pub)
    #  key2.verify("some data", sig)
    def verify(data, sig)
      regenerate_pubkey unless @key.public_key
      sig = Graphene::OpenSSL_EC.repack_der_signature(sig)
      if sig
        @key.dsa_verify_asn1(data, sig)
      else
        false
      end
    end


    def sign_message(message)
      Graphene.sign_message(priv, pub, message)['signature']
    end

    def verify_message(signature, message)
      Graphene.verify_message(addr, signature, message)
    end

    def self.verify_message(address, signature, message)
      Graphene.verify_message(address, signature, message)
    end

    # Thanks to whoever wrote http://pastebin.com/bQtdDzHx
    # for help with compact signatures
    #
    # Given +data+ and a compact signature (65 bytes, base64-encoded to
    # a larger string), recover the public components of the key whose
    # private counterpart validly signed +data+.
    #
    # If the signature validly signed +data+, create a new Key
    # having the signing public key and address. Otherwise return nil.
    #
    # Be sure to check that the returned Key matches the one you were
    # expecting! Otherwise you are merely checking that *someone* validly
    # signed the data.
    def self.recover_compact_signature_to_key(data, signature_base64)
      signature = signature_base64.unpack("m0")[0]
      return nil if signature.size != 65

      version = signature.unpack('C')[0]
      return nil if version < 27 or version > 34

      compressed = (version >= 31) ? (version -= 4; true) : false

      hash = Graphene.bitcoin_signed_message_hash(data)
      pub_hex = Graphene::OpenSSL_EC.recover_public_key_from_signature(hash, signature, version-27, compressed)
      return nil unless pub_hex

      Key.new(nil, pub_hex)
    end

    # Export private key to base58 format.
    # See also Key.from_base58
    def to_base58
      data = Graphene.network[:privkey_version] + priv
      data += "01"  if @pubkey_compressed
      hex  = data + Graphene.checksum(data)
      Graphene.int_to_base58( hex.to_i(16) )
    end

    # Export private key to bip38 (non-ec-multiply) format as described in
    # https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
    # See also Key.from_bip38
    def to_bip38(passphrase)
      flagbyte = compressed ? "\xe0" : "\xc0"

      # addresshash = Digest::SHA256.digest( Digest::SHA256.digest( self.addr ) )[0...4]
      addresshash = Digest::SHA256.digest( Digest::SHA256.digest( addr_hash160 ) )[0...4]

      require 'scrypt' unless defined?(::SCrypt::Engine)
      buf = SCrypt::Engine.__sc_crypt(passphrase, addresshash, 16384, 8, 8, 64)
      derivedhalf1, derivedhalf2 = buf[0...32], buf[32..-1]

      aes = proc{|k,a,b|
        cipher = OpenSSL::Cipher::AES.new(256, :ECB); cipher.encrypt; cipher.padding = 0; cipher.key = k
        cipher.update (a.to_i(16) ^ b.bth.to_i(16)).to_s(16).rjust(32, '0').htb
      }

      encryptedhalf1 = aes.call(derivedhalf2, self.priv[0...32], derivedhalf1[0...16])
      encryptedhalf2 = aes.call(derivedhalf2, self.priv[32..-1], derivedhalf1[16..-1])

      encrypted_privkey = "\x01\x42" + flagbyte + addresshash + encryptedhalf1 + encryptedhalf2
      encrypted_privkey += Digest::SHA256.digest( Digest::SHA256.digest( encrypted_privkey ) )[0...4]

      encrypted_privkey = Graphene.encode_base58( encrypted_privkey.bth )
    end

    # Import private key from bip38 (non-ec-multiply) fromat as described in
    # https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
    # See also #to_bip38
    def self.from_bip38(encrypted_privkey, passphrase)
      version, flagbyte, addresshash, encryptedhalf1, encryptedhalf2, checksum =
        [ Graphene.decode_base58(encrypted_privkey) ].pack("H*").unpack("a2aa4a16a16a4")
      compressed = (flagbyte == "\xe0") ? true : false

      raise "Invalid version"   unless version == "\x01\x42"
      raise "Invalid checksum"  unless Digest::SHA256.digest(Digest::SHA256.digest(version + flagbyte + addresshash + encryptedhalf1 + encryptedhalf2))[0...4] == checksum

      require 'scrypt' unless defined?(::SCrypt::Engine)
      buf = SCrypt::Engine.__sc_crypt(passphrase, addresshash, 16384, 8, 8, 64)
      derivedhalf1, derivedhalf2 = buf[0...32], buf[32..-1]

      aes = proc{|k,a|
        cipher = OpenSSL::Cipher::AES.new(256, :ECB); cipher.decrypt; cipher.padding = 0; cipher.key = k
        cipher.update(a)
      }

      decryptedhalf2 = aes.call(derivedhalf2, encryptedhalf2)
      decryptedhalf1 = aes.call(derivedhalf2, encryptedhalf1)

      priv = decryptedhalf1 + decryptedhalf2
      priv = (priv.bth.to_i(16) ^ derivedhalf1.bth.to_i(16)).to_s(16).rjust(64, '0')
      key = Graphene::Key.new(priv, nil, compressed)

      # if Digest::SHA256.digest( Digest::SHA256.digest( key.addr ) )[0...4] != addresshash
      if Digest::SHA256.digest( Digest::SHA256.digest( key.addr_hash160 ) )[0...4] != addresshash
        raise "Invalid addresshash! Password is likely incorrect."
      end

      key
    end

    # Import private key from warp fromat as described in
    # https://github.com/keybase/warpwallet
    # https://keybase.io/warp/
    def self.from_warp(passphrase, salt="", compressed=false)
      require 'scrypt' unless defined?(::SCrypt::Engine)
      s1 = SCrypt::Engine.scrypt(passphrase+"\x01", salt+"\x01", 2**18, 8, 1, 32)
      s2 = OpenSSL::PKCS5.pbkdf2_hmac(passphrase+"\x02", salt+"\x02", 2**16, 32, OpenSSL::Digest::SHA256.new)
      s3 = s1.bytes.zip(s2.bytes).map{|a,b| a ^ b }.pack("C*")

      key = Graphene::Key.new(s3.bth, nil, compressed)
      # [key.addr, key.to_base58, [s1,s2,s3].map{|i| i.unpack("H*")[0] }, compressed]
      key
    end


    protected

    # Regenerate public key from the private key.
    def regenerate_pubkey
      return nil unless @key.private_key
      set_pub(Graphene::OpenSSL_EC.regenerate_key(priv)[1], @pubkey_compressed)
    end

    # Set +priv+ as the new private key (converting from hex).
    def set_priv(priv)
      @key.private_key = OpenSSL::BN.from_hex(priv)
    end

    # Set +pub+ as the new public key (converting from hex).
    def set_pub(pub, compressed = nil)
      @pubkey_compressed = compressed == nil ? self.class.is_compressed_pubkey?(pub) : compressed
      @key.public_key = OpenSSL::PKey::EC::Point.from_hex(@key.group, pub)
    end

    def self.is_compressed_pubkey?(pub)
      ["02","03"].include?(pub[0..1])
    end

  end

end

