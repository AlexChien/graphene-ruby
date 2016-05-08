require 'spec_helper'
require 'pry'
describe Graphene::Key do

  before do
    # pybitcointool example
    @key_data = {
      # :priv => "20991828d456b389d0768ed7fb69bf26b9bb87208dd699ef49f10481c20d3e18",
      # :pub => "035fcb2fb2802b024f371cc22bc392268cc579e47e7936e0d1f05064e6e1103b8a"
      priv_hex: "3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6",
      priv_dec: "26563230048437957592232553826663696440606756685920117476832299673293013768870",
      priv_wif: "5JG9hT3beGTJuUAmCQEmNaxAuMacCTfXuw1R3FCXig23RQHMr4K",
      priv_compressed: "3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa601",
      priv_wif_compressed: "KyBsPXxTuVD82av65KZkrGrWi5qLMah5SdNq6uftawDbgKa2wv6S",
      pub_xy: {
        x: "41637322786646325214887832269588396900663353932545912953362782457239403430124L",
        y: "16388935128781238405526710466724741593761085120864331449066658622400339362166L"
      },
      pub_hex: "045c0de3b9c8ab18dd04e3511243ec2952002dbfadc864b9628910169d9b9b00ec243bcefdd4347074d44bd7356d6a53c495737dd96295e2a9374bf5f02ebfc176",
      pub_compressed_hex: "025c0de3b9c8ab18dd04e3511243ec2952002dbfadc864b9628910169d9b9b00ec",
      address: "1thMirt546nngXqyPEz532S8fLwbozud8",
      address_compressed: "14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3"

    }

    # python-graphene example
    @key_data = {
      priv_hex: "20991828d456b389d0768ed7fb69bf26b9bb87208dd699ef49f10481c20d3e18",
      priv_dec: "14744505498247679578629998240401744750478068521024330599095720965782507437592",
      priv_wif: "5J4eFhjREJA7hKG6KcvHofHMXyGQZCDpQE463PAaKo9xXY6UDPq",
      priv_compressed: "20991828d456b389d0768ed7fb69bf26b9bb87208dd699ef49f10481c20d3e1801",
      priv_wif_compressed: "KxK5RtnDwgjEYwbcVBYDAwyBdhLzy6XaDWcdFWqG5xiY5cwSTYQX",
      pub_xy: {
        x: "53385527898705784600580657836384684066273125615755813081866169867465227799345L",
        y: "34495591809371035933093680469629474441195970526694264888866173919627939899339L"
      },
      pub_hex: "0476072354654f7f12aaa513a302dac8ff52d7df2c81fce1ebf1dfa5e139b48b314c43d0251bf5a21e87fbde66648466ca327d4c82053168d1c0cdee21de1b67cb",
      pub_compressed_hex: "0376072354654f7f12aaa513a302dac8ff52d7df2c81fce1ebf1dfa5e139b48b31",
      pub_str: "GPH3aQmSbCHEYpNjiX1RfAs8fTtPjYocFR16QtVZhHqPvRCMAe6reMyPbAs2Sy9oP5S1ABWQczceosHnBo7jke7Bu5UVRwQEe",
      pub_str_compressed: "GPH7jDPoMwyjVH5obFmqzFNp4Ffp7G2nvC7FKFkrMBpo7Sy4uq5Mj", # compressed
      address: "GPH4RBkAizFGGFHividvzryY4QBfgC8BYeAj",
      address_compressed: "GPH8DvGQqzbgCR5FHiNsFf8kotEXr8VKD3mR",
      Uncompressed_BTC:  "1GRujmJ58xusy4i74e1jtBcHs3w6mdRxH3",
      Compressed_BTC:  "1G7zhfzEE5NzSjgfvgD6FwQTQoEgQxmtHF"

    }
    @key = Graphene::Key.new(@key_data[:priv_hex], @key_data[:pub_compressed_hex], false)
  end

  it "should generate a key" do
    k = Graphene::Key.generate
    expect(k.priv.size).to eq 64
    expect(k.pub.size).to eq 66
    expect(k.compressed).to be true

    k = Graphene::Key.generate(compressed: true)
    expect(k.priv.size).to eq 64
    expect(k.pub.size).to eq 66
    expect(k.compressed).to be true

    k = Graphene::Key.generate(true)
    expect(k.priv.size).to eq 64
    expect(k.pub.size).to eq 66
    expect(k.compressed).to be true

    k = Graphene::Key.generate(compressed: false)
    expect(k.priv.size).to eq 64
    expect(k.pub.size).to eq 130
    expect(k.compressed).to be false

    k = Graphene::Key.generate(false)
    expect(k.priv.size).to eq 64
    expect(k.pub.size).to eq 130
    expect(k.compressed).to be false
  end

  it "should create empty key" do
    k = Graphene::Key.new
    expect(k.priv).to be_nil
    expect(k.pub).to be_nil
    expect(k.compressed).to be true
  end

  it "should create key from priv + pub" do
    k = Graphene::Key.new(@key_data[:priv_hex], @key_data[:pub_compressed_hex])
    expect(k.priv).to eq @key_data[:priv_hex]
    expect(k.pub).to eq @key_data[:pub_compressed_hex]
  end

  it "should create key from only priv" do
    k = Graphene::Key.new(@key_data[:priv_hex])
    expect(k.priv).to eq @key_data[:priv_hex]
    expect(k.pub).to eq @key_data[:pub_compressed_hex]
  end

  it "should create key from only pub" do
    k = Graphene::Key.new(nil, @key_data[:pub_compressed_hex])
    expect(k.pub).to eq @key_data[:pub_compressed_hex]
  end

  it "should set public key" do
    k = Graphene::Key.new
    k.pub = @key_data[:pub_compressed_hex]
    expect(k.pub).to eq @key_data[:pub_compressed_hex]
  end

  it "should set private key" do
    k = Graphene::Key.new
    k.priv = @key_data[:priv_hex]
    expect(k.priv).to eq @key_data[:priv_hex]
    expect(k.pub).to eq @key_data[:pub_compressed_hex]
  end

  it "grapheneBase58CheckEncode" do
    a = Graphene.grapheneBase58CheckEncode("0376072354654f7f12aaa513a302dac8ff52d7df2c81fce1ebf1dfa5e139b48b31")
    expect(a).to eq "7jDPoMwyjVH5obFmqzFNp4Ffp7G2nvC7FKFkrMBpo7Sy4uq5Mj"
  end

  it "g_base58_checksum" do
    [
      "7jDPoMwyjVH5obFmqzFNp4Ffp7G2nvC7FKFkrMBpo7Sy4uq5Mj", #hash512
      "GPH8DvGQqzbgCR5FHiNsFf8kotEXr8VKD3mR", #address compressed
      "GPH4RBkAizFGGFHividvzryY4QBfgC8BYeAj" #address
    ].each do |address|
      expect(Graphene.g_base58_checksum?(address)).to be true
      expect(Graphene.g_address_checksum?(address)).to be true
    end
  end

  it "should get pubkey" do
    expect(@key.pubkey).to eq @key_data[:pub_str_compressed]
    @key.instance_eval { @pubkey_compressed = false }
    expect(@key.pubkey).to eq @key_data[:pub_str]
  end

  it "should get addr" do
    expect(@key.addr).to eq @key_data[:address_compressed]
    @key.instance_eval { @pubkey_compressed = false }
    expect(@key.addr).to eq @key_data[:address]
  end

  it "should sign data", :skip do
    expect(@key.sign("foobar").size).to be >= 69
  end

  it "should verify signature using public key", :skip do
    sig = @key.sign("foobar")
    key = Graphene::Key.new(nil, @key.pub)
    expect(key.verify("foobar", sig)).to be true
  end

  it "should verify signature using private key", :skip do
    sig = @key.sign("foobar")
    key = Graphene::Key.new(@key.priv)
    expect(key.verify("foobar", sig)).to be true
  end

  it "recovers public keys from compact signatures", :skip do
    tests = [
        # normal
      { address: "16vqGo3KRKE9kTsTZxKoJKLzwZGTodK3ce",
        signature: "HPDs1TesA48a9up4QORIuub67VHBM37X66skAYz0Esg23gdfMuCTYDFORc6XGpKZ2/flJ2h/DUF569FJxGoVZ50=",
        message: "test message",
        expected: true },

        # different message
      { address: "16vqGo3KRKE9kTsTZxKoJKLzwZGTodK3ce",
        signature: "HPDs1TesA48a9up4QORIuub67VHBM37X66skAYz0Esg23gdfMuCTYDFORc6XGpKZ2/flJ2h/DUF569FJxGoVZ50=",
        message: "not what I signed",
        expected: false },

        # different address
      { address: "1JbYZRKyysprVjSSBobs8LX6QVjzsscQNU",
        signature: "HPDs1TesA48a9up4QORIuub67VHBM37X66skAYz0Esg23gdfMuCTYDFORc6XGpKZ2/flJ2h/DUF569FJxGoVZ50=",
        message: "test message",
        expected: false },

        # compressed
      { address: "18uitB5ARAhyxmkN2Sa9TbEuoGN1he83BX",
        signature: "IMAtT1SjRyP6bz6vm5tKDTTTNYS6D8w2RQQyKD3VGPq2i2txGd2ar18L8/nvF1+kAMo5tNc4x0xAOGP0HRjKLjc=",
        message: "testtest",
        expected: true },
      ]
   tests.each do | test |
      key = Graphene::Key.recover_compact_signature_to_key(test[:message], test[:signature])
      expect(test[:expected]).to be (key.addr == test[:address])
    end
  end

  it "should export private key in base58 format" do
    Graphene.network = :graphene
    str = Graphene::Key.new(@key_data[:priv_hex], nil, false).to_base58
    expect(str).to eq @key_data[:priv_wif]
    Graphene.network = :bitshares
    str = Graphene::Key.new(@key_data[:priv_hex], nil, false).to_base58
    expect(str).to eq @key_data[:priv_wif]
    Graphene.network = :graphene
  end

  it "should import private key in base58 format" do
    Graphene.network = :graphene
    key = Graphene::Key.from_base58(@key_data[:priv_wif])
    expect(key.priv).to eq @key_data[:priv_hex]
    expect(key.addr).to eq @key_data[:address]
    Graphene.network = :bitshares
    key = Graphene::Key.from_base58(@key_data[:priv_wif])
    expect(key.priv).to eq @key_data[:priv_hex]
    expect(key.addr).to eq @key_data[:address].gsub(/^GPH/,"BTS")
    Graphene.network = :graphene
  end

  it "should export private key in compressed base58 format" do
    Graphene.network = :graphene
    expect(Graphene::Key.new(@key_data[:priv_hex],
      nil, true).to_base58).to eq @key_data[:priv_wif_compressed]
    Graphene.network = :bitshares
    expect(Graphene::Key.new(@key_data[:priv_hex],
      nil, true).to_base58).to eq @key_data[:priv_wif_compressed]
    Graphene.network = :graphene
  end

  it "should import private key in compressed base58 format" do
    Graphene.network = :graphene
    key = Graphene::Key.from_base58(@key_data[:priv_wif_compressed])
    expect(key.priv).to eq @key_data[:priv_hex]
    expect(key.pub).to eq @key_data[:pub_compressed_hex]
    expect(key.compressed).to be true
    expect(key.addr).to eq @key_data[:address_compressed]
    Graphene.network = :bitshares
    key = Graphene::Key.from_base58(@key_data[:priv_wif_compressed])
    expect(key.priv).to eq @key_data[:priv_hex]
    expect(key.pub).to eq @key_data[:pub_compressed_hex]
    expect(key.addr).to eq @key_data[:address_compressed].gsub(/GPH/, "BTS")
    Graphene.network = :graphene
  end

  it "should handle compressed and uncompressed pubkeys" do
    compressed   = @key_data[:pub_compressed_hex]
    uncompressed = @key_data[:pub_hex]
    expect(Graphene::Key.new(nil, compressed).compressed).to be true
    expect(Graphene::Key.new(nil, compressed).pub).to eq compressed
    expect(Graphene::Key.new(nil, compressed).addr).to eq @key_data[:address_compressed]
    expect(Graphene::Key.new(nil, uncompressed).compressed).to be false
    expect(Graphene::Key.new(nil, uncompressed).pub).to eq uncompressed
    expect(Graphene::Key.new(nil, uncompressed).addr).to eq @key_data[:address]

    key = Graphene::Key.new(nil, compressed)
    expect(key.pub_compressed).to eq compressed
    expect(key.pub_uncompressed).to eq uncompressed

    # sig = @key.sign(msg="foobar")
    # expect(Graphene::Key.new(nil, @key.pub_compressed  ).verify(msg, sig)).to eq true
    # expect(Graphene::Key.new(nil, @key.pub_uncompressed).verify(msg, sig)).to eq true

    k = Graphene::Key.new(nil, nil)
    k.instance_eval{ set_pub("025c0de3b9c8ab18dd04e3511243ec2952002dbfadc864b9628910169d9b9b00ec") }
    expect(k.compressed).to be true

    k = Graphene::Key.new(nil, nil)
    k.instance_eval{ set_pub("0476072354654f7f12aaa513a302dac8ff52d7df2c81fce1ebf1dfa5e139b48b314c43d0251bf5a21e87fbde66648466ca327d4c82053168d1c0cdee21de1b67cb") }
    expect(k.compressed).to be false
  end

  it "should handle private key in bip38 (non-ec-multiply) format", :skip do
    k = Graphene::Key.from_base58("5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR")
    expect(k.to_bip38("TestingOneTwoThree")).to eq "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg"

    k = Graphene::Key.from_bip38("6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg", "TestingOneTwoThree")
    expect(k.to_base58).to eq "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR"

    k = Graphene::Key.from_base58("5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5")
    expect(k.to_bip38("Satoshi")).to eq "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq"

    k = Graphene::Key.from_bip38("6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq", "Satoshi")
    expect(k.to_base58).to eq "5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5"

    k = Graphene::Key.from_base58("L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP")
    expect(k.to_bip38("TestingOneTwoThree")).to eq "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo"

    k = Graphene::Key.from_bip38("6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo", "TestingOneTwoThree")
    expect(k.to_base58).to eq "L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP"

    k = Graphene::Key.from_base58("KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7")
    expect(k.to_bip38("Satoshi")).to eq "6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7"

    k = Graphene::Key.from_bip38("6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7", "Satoshi")
    expect(k.to_base58).to eq "KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7"
  end

  it "should generate private key from warp format", :skip do
    k = Graphene::Key.from_warp("ER8FT+HFjk0", "7DpniYifN6c")
    expect(k.addr).to eq "1J32CmwScqhwnNQ77cKv9q41JGwoZe2JYQ"
    expect(k.to_base58).to eq "5JfEekYcaAexqcigtFAy4h2ZAY95vjKCvS1khAkSG8ATo1veQAD"

    k = Graphene::Key.from_warp("YqIDBApDYME", "G34HqIgjrIc")
    expect(k.addr).to eq "19aKBeXe2mi4NbQRpYUrCLZtRDHDUs9J7J"
    expect(k.to_base58).to eq "5KUJA5iZ2zS7AXkU2S8BiBVY3xj6F8GspLfWWqL9V7CajXumBQV"

    k = Graphene::Key.from_warp("FPdAxCygMJg", "X+qaSwhUYXw")
    expect(k.addr).to eq "14Pqeo9XNRxjtKFFYd6TvRrJuZxVpciS81"
    expect(k.to_base58).to eq "5JBAonQ4iGKFJxENExZghDtAS6YB8BsCw5mwpHSvZvP3Q2UxmT1"
  end

end


begin
  describe "Graphene::OpenSSL_EC" do
    Graphene::OpenSSL_EC

    it 'resolves public from private key' do
      privkey = ["56e28a425a7b588973b5db962a09b1aca7bdc4a7268cdd671d03c52a997255dc"].pack("H*")
      pubkey =  ["04324c6ebdcf079db6c9209a6b715b955622561262cde13a8a1df8ae0ef030eaa1552e31f8be90c385e27883a9d82780283d19507d7fa2e1e71a1d11bc3a52caf3"].pack("H*")

     expect(Graphene::OpenSSL_EC.regenerate_key(privkey)).to eq [privkey, pubkey].map{ | i | i.unpack("H*")[0] }

      [
        ["b51386f8275d49d8d30287d7b1afa805790bdd1fe8b13d22d25928c67ea55d02", "0470305ae5278a22499980286d9c513861d89e7b7317c8b891c554d5c8fdd256b03daa0340be4104f8c84cfa98f0da8f16567fcdd3a00fd993adbbe91695671a56"],
        ["d8ebece51adc5fb99dd6994bcb8fa1221d01576fd76af9134ab36f8d4698b55c", "047503421850d3a6eecb7c9de33b367c4d3f96a34ff257ad0c34e234e29f3672525c6b4353ce6fdc9de3f885fdea798982e2252e610065dbdb62cd8cab1fe45822"],
        ["c95c79fb0cc1fe47b384751df0627be40bbe481ec94eeafeb6dc40e94c40de43", "04b746ca07e718c7ca26d4eeec037492777f48bb5c750e972621698f699f530535c0ffa96dad581102d0471add88e691af85955d1fd42f68506f8092fddfe0c47a"],
        ["5b61f807cc938b0fd3ec8f6006737d0002ceca09f296204138c4459de8a856f6", "0487357bf30c13d47d955666f42f87690cfd18be96cc74cda711da74bf76b08ebc6055aba30680e6288df14bda68c781cbf71eaad096c3639e9724c5e26f3acf54"]
     ].each{ | key |
        privkey, pubkey = [ key.first ].pack("H*")
        expect(Graphene::OpenSSL_EC.regenerate_key(privkey)).to eq key
      }

      expect(250.times.map{
        keypair = Graphene.generate_key;
        Graphene::OpenSSL_EC.regenerate_key(keypair.first) == keypair
       }.all?).to be true
    end

    it 'recover public key from compact signature' do
      args = [
        "\x12&\x17\x9D\xDFc\x83\xFB\xCFQ\x02\xC9I%8\xB7 ls\x9A\xE7\x9E\xB0d@\x8C*\xBDg\xD3\x9B\xED",
        "\x1C\xF0\xEC\xD57\xAC\x03\x8F\x1A\xF6\xEAx@\xE4H\xBA\xE6\xFA\xEDQ\xC13~\xD7\xEB\xAB$\x01\x8C\xF4\x12\xC86\xDE\a_2\xE0\x93`1NE\xCE\x97\x1A\x92\x99\xDB\xF7\xE5'h\x7F\rAy\xEB\xD1I\xC4j\x15g\x9D",
        1, false
      ]
      expected = "047840b97f46d4c32c62119f9e069172272592ec7741a3aec81e339b87387350740dce89837c8332910f349818060b66070b94e8bb11442d49d3f6c0d7f31ba6a6"

      # 10_000.times{                               | n                                         | # enable for memory leak testing |
      #   puts 'RAM USAGE: ' + `pmap #{Process.pid} | tail -1`[10,40].strip if (n % 1_000) == 0 |                                  |
      expect(Graphene::OpenSSL_EC.recover_public_key_from_signature(*args)).to eq expected
      # }
    end

=begin
    it 'sign and verify text messages' do
      [
        ["5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj", false],
        ["5KC4ejrDjv152FGwP386VD1i2NYc5KkfSMyv1nGy1VGDxGHqVY3", false],
        ["Kwr371tjA9u2rFSMZjTNun2PXXP3WPZu2afRHTcta6KxEUdm1vEw", true],
        ["L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g", true],
     ].each{ | privkey_base58,expected_compression |
        k = Graphene::Key.from_base58(privkey_base58)
        expect(k.compressed).to eq expected_compression
        k2 = Graphene::Key.new(nil, k.pub)
        expect(k2.compressed).to eq expected_compression
       16.times{ | n |
          msg = "Very secret message %d: 11" % n
          signature = k.sign_message(msg)
          expect(k2.verify_message(signature, msg)).to eq true
          expect(Graphene::Key.verify_message(k.addr, signature, msg)).to eq true
        }
      }
    end
=end

  end
rescue LoadError
end
