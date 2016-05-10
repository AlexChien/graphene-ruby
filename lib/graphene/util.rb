# encoding: ascii-8bit

require 'graphene/protocol'

module Util

  def address_version; Graphene.network[:address_version]; end
  def p2sh_version; Graphene.network[:p2sh_version]; end
  def address_prefix; Graphene.network[:address_prefix]; end

  # hash160 is a 20 bytes (160bits) rmd610-sha256 hexdigest.
  def hash160(hex)
    bytes = [hex].pack("H*")
    Digest::RMD160.hexdigest Digest::SHA256.digest(bytes)
  end

  def hash512(hex)
    bytes = [hex].pack("H*")
    Digest::RMD160.hexdigest Digest::SHA512.digest(bytes)
  end

  # checksum is a 4 bytes sha256-sha256 hexdigest.
  def checksum(hex)
    b = [hex].pack("H*") # unpack hex
    Digest::SHA256.hexdigest( Digest::SHA256.digest(b) )[0...8]
  end

  def g_checksum(hex)
    b = [hex].pack("H*") # unpack hex
    checksum = Digest::RMD160.digest(b)[0...4]
    checksum.unpack("H*")[0]
  end

  # verify base58 checksum for given +base58+ data.
  def base58_checksum?(base58)
    hex = decode_base58(base58) rescue nil
    return false unless hex
    checksum( hex[0...42] ) == hex[-8..-1]
  end
  alias :address_checksum? :base58_checksum?

  # verify base58 checksum for graphene based +base58+ data.
  # if address_prefix is found, remove it first
  def g_base58_checksum?(base58)
    base58 = remove_prefix(base58)

    hex = decode_base58(base58) rescue nil
    return false unless hex
    g_checksum( hex[0...hex.size-8] ) == hex[-8..-1]
  end
  alias :g_address_checksum? :g_base58_checksum?

  # remove prefix if there's any
  def remove_prefix(base58)
    if base58[0...address_prefix.size] == address_prefix.upcase
      base58[address_prefix.size..-1]
    else
      base58
    end
  end

  def grapheneBase58CheckEncode(hex)
    bytes = [hex].pack("H*")
    checksum = Digest::RMD160.digest(bytes)[0...4]
    result = hex + checksum.unpack("H*")[0]
    return encode_base58(result)
  end

  # check if given +address+ is valid.
  # this means having a correct version byte, length and checksum.
  def valid_address?(address)
    hex = decode_base58(address) rescue nil
    return false unless hex && hex.bytesize == 50
    return false unless [address_version, p2sh_version].include?(hex[0...2])
    address_checksum?(address)
  end

  # check if given +pubkey+ is valid.
  def valid_pubkey?(pubkey)
    ::OpenSSL::PKey::EC::Point.from_hex(bitcoin_elliptic_curve.group, pubkey)
    true
  rescue ::OpenSSL::PKey::EC::Point::Error
    false
  end

  # get hash160 for given +address+. returns nil if address is invalid.
  def hash160_from_address(address)
    return nil  unless valid_address?(address)
    decode_base58(address)[2...42]
  end

  # get type of given +address+.
  def address_type(address)
    return nil unless valid_address?(address)
    case decode_base58(address)[0...2]
    when address_version; :hash160
    when p2sh_version;    :p2sh
    end
  end

  def sha256(hex)
    Digest::SHA256.hexdigest([hex].pack("H*"))
  end

  def sha512(hex)
    Digest::SHA512.hexdigest([hex].pack("H*"))
  end

  def hash512_to_address(hex)
    g_encode_address hex, address_prefix
  end

  def hash160_to_address(hex)
    encode_address hex, address_version
  end

  def hash160_to_p2sh_address(hex)
    encode_address hex, p2sh_version
  end

  def encode_address(hex, version)
    hex = version + hex
    encode_base58(hex + checksum(hex))
  end

  def grapheneBase58CheckEncode(hex)
    bytes = [hex].pack("H*")
    checksum = Digest::RMD160.digest(bytes)[0...4]
    result = hex + checksum.unpack("H*")[0]
    return encode_base58(result)
  end

  def grapheneBase58CheckDecode(base58)
    # raise "Invalid checksum" unless Digest::RMD160.digest([hex].pack("H*"))[0...4] == [checksum].pack("H*")
    raise "Invalid checksum" unless g_base58_checksum?(base58)

    decoded = decode_base58(remove_prefix(base58))
    hex     = decoded[0...-8]

    return hex
  end

  def g_encode_address(hex, version=nil)
    version = address_prefix unless version
    return version.upcase + encode_base58(hex + g_checksum(hex))
  end

  def pubkey_to_address(pubkey)
    hash160_to_address( hash160(pubkey) )
  end

  def pubkeys_to_p2sh_multisig_address(m, *pubkeys)
    redeem_script = Graphene::Script.to_p2sh_multisig_script(m, *pubkeys).last
    return Graphene.hash160_to_p2sh_address(Graphene.hash160(redeem_script.hth)), redeem_script
  end

  def int_to_base58(int_val, leading_zero_bytes=0)
    alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    base58_val, base = '', alpha.size
    while int_val > 0
      int_val, remainder = int_val.divmod(base)
      base58_val = alpha[remainder] + base58_val
    end
    base58_val
  end

  def base58_to_int(base58_val)
    alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    int_val, base = 0, alpha.size
    base58_val.reverse.each_char.with_index do |char,index|
      raise ArgumentError, 'Value not a valid Base58 String.' unless char_index = alpha.index(char)
      int_val += char_index*(base**index)
    end
    int_val
  end

  def encode_base58(hex)
    leading_zero_bytes  = (hex.match(/^([0]+)/) ? $1 : '').size / 2
    ("1"*leading_zero_bytes) + int_to_base58( hex.to_i(16) )
  end

  def decode_base58(base58_val)
    s = base58_to_int(base58_val).to_s(16); s = (s.bytesize.odd? ? '0'+s : s)
    s = '' if s == '00'
    leading_zero_bytes = (base58_val.match(/^([1]+)/) ? $1 : '').size
    s = ("00"*leading_zero_bytes) + s  if leading_zero_bytes > 0
    s
  end
  alias_method :base58_to_hex, :decode_base58

  # target compact bits (int) to bignum hex
  def decode_compact_bits(bits)
    bytes = Array.new(size=((bits >> 24) & 255), 0)
    bytes[0] = (bits >> 16) & 255 if size >= 1
    bytes[1] = (bits >>  8) & 255 if size >= 2
    bytes[2] = (bits      ) & 255 if size >= 3
    bytes.pack("C*").unpack("H*")[0].rjust(64, '0')
  end

  # target bignum hex to compact bits (int)
  def encode_compact_bits(target)
    bytes = ::OpenSSL::BN.new(target, 16).to_mpi
    size = bytes.size - 4
    nbits = size << 24
    nbits |= (bytes[4] << 16) if size >= 1
    nbits |= (bytes[5] <<  8) if size >= 2
    nbits |= (bytes[6]      ) if size >= 3
    nbits
  end

  def decode_target(target_bits)
    case target_bits
    when Fixnum
      [ decode_compact_bits(target_bits).to_i(16), target_bits ]
    when String
      [ target_bits.to_i(16), encode_compact_bits(target_bits) ]
    end
  end

  def bitcoin_elliptic_curve
    ::OpenSSL::PKey::EC.new("secp256k1")
  end

  def generate_key
    key = bitcoin_elliptic_curve.generate_key
    inspect_key( key )
  end

  def inspect_key(key)
    [ key.private_key_hex, key.public_key_hex ]
  end

  def generate_address
    prvkey, pubkey = generate_key
    [ pubkey_to_address(pubkey), prvkey, pubkey, hash160(pubkey) ]
  end

  def bitcoin_hash(hex)
    Digest::SHA256.digest(
      Digest::SHA256.digest( [hex].pack("H*").reverse )
    ).reverse.bth
  end

  def bitcoin_byte_hash(bytes)
    Digest::SHA256.digest(Digest::SHA256.digest(bytes))
  end

  def bitcoin_mrkl(a, b); bitcoin_hash(b + a); end

  def block_hash(prev_block, mrkl_root, time, bits, nonce, ver)
    h = "%08x%08x%08x%064s%064s%08x" %
          [nonce, bits, time, mrkl_root, prev_block, ver]
    bitcoin_hash(h)
  end

  # get merkle tree for given +tx+ list.
  def hash_mrkl_tree(tx)
    return [nil]  if tx != tx.uniq
    chunks = [ tx.dup ]
    while chunks.last.size >= 2
      chunks << chunks.last.each_slice(2).map {|a, b| bitcoin_mrkl( a, b || a ) }
    end
    chunks.flatten
  end

  # get merkle branch connecting given +target+ to the merkle root of +tx+ list
  def hash_mrkl_branch(tx, target)
    return [ nil ]  if tx != tx.uniq
    branch, chunks = [], [ tx.dup ]
    while chunks.last.size >= 2
      chunks << chunks.last.each_slice(2).map {|a, b|
        hash = bitcoin_mrkl( a, b || a )
        next hash  unless [a, b].include?(target)
        branch << (a == target ? (b || a) : a)
        target = hash
      }
    end
    branch
  end

  # get merkle root from +branch+ and +target+.
  def mrkl_branch_root(branch, target, idx)
    branch.each do |hash|
      a, b = *( idx & 1 == 0 ? [target, hash] : [hash, target] )
      idx >>= 1;
target = bitcoin_mrkl( a, b )
    end
    target
  end

  def sign_data(key, data)
    sig = nil
    loop {
      sig = key.dsa_sign_asn1(data)
      sig = if Graphene::Script.is_low_der_signature?(sig)
              sig
            else
              Graphene::OpenSSL_EC.signature_to_low_s(sig)
            end

      buf = sig + [Graphene::Script::SIGHASH_TYPE[:all]].pack("C") # is_der_signature expects sig + sighash_type format
      if Graphene::Script.is_der_signature?(buf)
        break
      else
        p ["Graphene#sign_data: invalid der signature generated, trying again.", data.unpack("H*")[0], sig.unpack("H*")[0]]
      end
    }
    return sig
  end

  def verify_signature(hash, signature, public_key)
    key  = bitcoin_elliptic_curve
    key.public_key = ::OpenSSL::PKey::EC::Point.from_hex(key.group, public_key)
    signature = Graphene::OpenSSL_EC.repack_der_signature(signature)
    if signature
      key.dsa_verify_asn1(hash, signature)
    else
      false
    end
  rescue ::OpenSSL::PKey::ECError, ::OpenSSL::PKey::EC::Point::Error, ::OpenSSL::BNError
    false
  end

  def open_key(private_key, public_key=nil)
    key  = bitcoin_elliptic_curve
    key.private_key = ::OpenSSL::BN.from_hex(private_key)
    public_key = regenerate_public_key(private_key) unless public_key
    key.public_key  = ::OpenSSL::PKey::EC::Point.from_hex(key.group, public_key)
    key
  end

  def regenerate_public_key(private_key)
    Graphene::OpenSSL_EC.regenerate_key(private_key)[1]
  end

  def bitcoin_signed_message_hash(message)
    message = message.dup.force_encoding('binary')

    magic = "Graphene Signed Message:\n"
    buf = Graphene::Protocol.pack_var_int(magic.bytesize) + magic
    buf << Graphene::Protocol.pack_var_int(message.bytesize) + message

    Digest::SHA256.digest(Digest::SHA256.digest(buf))
  end

  def sign_message(private_key_hex, public_key_hex, message)
    hash = bitcoin_signed_message_hash(message)
    signature = Graphene::OpenSSL_EC.sign_compact(hash, private_key_hex, public_key_hex)
    { 'address' => pubkey_to_address(public_key_hex), 'message' => message, 'signature' => [ signature ].pack("m0") }
  end

  def verify_message(address, signature, message)
    signature = signature.unpack("m0")[0] rescue nil # decode base64
    return false unless valid_address?(address)
    return false unless signature
    return false unless signature.bytesize == 65
    hash = bitcoin_signed_message_hash(message)
    pubkey = Graphene::OpenSSL_EC.recover_compact(hash, signature)
    pubkey_to_address(pubkey) == address if pubkey
  end

  # shows the total number of Graphenes in circulation, reward era and reward in that era.
  def blockchain_total_btc(height)
    reward, interval = Graphene.network[:reward_base], Graphene.network[:reward_halving]
    total_btc = reward
    reward_era, remainder = (height).divmod(interval)
    reward_era.times{
      total_btc += interval * reward
      reward = reward / 2
    }
    total_btc += remainder * reward
    [total_btc, reward_era+1, reward, height]
  end

end