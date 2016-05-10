# encoding: ascii-8bit

module Graphene
  module Memo
    #
    # The shared secret is generated such that::
    #
    #        Pub(Alice) * Priv(Bob) = Pub(Bob) * Priv(Alice)
    #
    #
    # @param priv: Key instance or wif
    # @param pub_str: gbase58 encoded public key str, such as GPH56EzLTXkis55hBsompVXmSdnayG3afDNFmsCLohPh6rSNzkzhs
    # @returns shared_secret
    #
    def self.get_shared_secret(priv, pub)
      priv = get_private_key(priv)
      pub  = get_public_key(pub)

      # get OpenSSL::BN
      priv_bn = priv.key.private_key
      # get OpenSSL::PKey::Point
      pub_point = pub.key.public_key

      # priv * pub
      mul = pub_point.mul(priv_bn)
      hex = mul.to_hex

      # remove prefix 4
      # cut remaining in half and take point x
      # x_hex = hex[1..(hex.size-1)/2]
      # secret = "0" * (64-x_hex.size) + x_hex
      secret = hex[1..64]

      secret
    end

    #
    # encode plain message to encoded message
    #
    # @param priv[Key|String]: private key or wif of sender
    # @param pub[Key|String]: public key or pub_str of receiver
    # @param nonce[Integer]: random
    # @param plain[String]: plain message to encode
    #
    # @returns String
    def self.encode_memo(priv, pub, nonce, plain)
      # prepare plain
      # raw = plain.force_encoding("utf-8")
      raw = plain # do not need to force to utf-8
      checksum = Digest::SHA256.digest(raw)
      raw = checksum[0...4] + raw

      # message padding 16
      padding_num = 16
      pads = padding_num - raw.length % padding_num
      raw = raw + [pads].pack("C*") * pads if pads

      # get shared_secret
      shared_secret_hex = get_shared_secret(priv, pub)

      # init aes
      cipher = init_aes(shared_secret_hex, nonce, true)

      encrypted = cipher.update(raw)# + cipher.final
      encrypted.bth
    end

    #
    # decode encoded message to plain
    #
    # @param priv[Key|String]: private key or wif of receiver
    # @param pub[Key|String]: public key or pub_str of sender
    # @param nonce[Integer]: random
    # @param message[String]: encoded message to decode
    #
    # @returns String
    def self.decode_memo(priv, pub, nonce, message)
      # prepare message
      raw = message.htb

      # get shared_secret
      shared_secret_hex = get_shared_secret(priv, pub)

      # init aes
      cipher = init_aes(shared_secret_hex, nonce, false)
      decrypted = cipher.update(raw) + cipher.final

      decrypted[4..-1]
    end

    #
    # initialize aes instance
    #
    # @param shared_secret_hex[hex]
    # @param nonce[Integer]
    # @param encrypt[Boolean]
    #
    # @returns [OpenSSL::Cipher::AES]
    def self.init_aes(shared_secret_hex, nonce, encrypt = true)
      # extract key and iv from shared_secret
      ss = Graphene.sha512 shared_secret_hex
      seed = nonce.to_s + ss

      seed_digest = Digest::SHA512.hexdigest seed

      key, iv = seed_digest[0...64].htb, seed_digest[64...96].htb

      cipher = OpenSSL::Cipher::AES.new(256, :CBC)
      if encrypt
        cipher.encrypt
      else
        cipher.decrypt
      end
      cipher.key = key
      cipher.iv = iv

      cipher
    end

    def self.get_private_key(priv)
      # if priv is not a key instance, try to treat it as wif
      if !priv.is_a?(Graphene::Key)
        priv = Graphene::Key.from_base58(priv)
      end

      priv
    end

    def self.get_public_key(pub)
      # if pub is not a key instance, try to treat it as a pub_str
      if !pub.is_a?(Graphene::Key)
        pub_hex = Graphene::Key.pub_str_to_hex(pub)
        pub = Graphene::Key.new(nil, pub_hex)
      end

      pub
    end
  end
end