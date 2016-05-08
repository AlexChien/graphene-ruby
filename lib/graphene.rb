# encoding: ascii-8bit

require 'digest/sha2'
require 'digest/rmd160'
require 'openssl'
require 'securerandom'

require 'graphene/protocol/rpc'
require 'graphene/protocol/ws'
require 'graphene/actor/base_actor'

module Graphene
  autoload :Protocol,   'graphene/protocol'
  autoload :P,          'graphene/protocol'
  autoload :Script,     'graphene/script'
  autoload :VERSION,    'graphene/version'
  autoload :Logger,     'graphene/logger'
  autoload :Key,        'graphene/key'
  # autoload :Builder,    'graphene/builder'

  require 'graphene/util'
  extend Util

  module  BinaryExtensions
    # bin-to-hex
    def bth; unpack("H*")[0]; end
    # hex-to-bin
    def htb; [self].pack("H*"); end

    def htb_reverse; htb.reverse; end
    def hth; unpack("H*")[0]; end
    def reverse_hth; reverse.hth; end
  end

  class ::String
    include Graphene::BinaryExtensions
  end

  module ::OpenSSL
    class BN
      def self.from_hex(hex); new(hex, 16); end
      def to_hex; to_i.to_s(16); end
      def to_mpi; to_s(0).unpack("C*"); end
    end
    class PKey::EC
      def private_key_hex; private_key.to_hex.rjust(64, '0'); end
      def public_key_hex;  public_key.to_hex.rjust(130, '0'); end
      def pubkey_compressed?; public_key.group.point_conversion_form == :compressed; end
    end
    class PKey::EC::Point
      def self.from_hex(group, hex)
        new(group, BN.from_hex(hex))
      end
      def to_hex; to_bn.to_hex; end
      def self.bn2mpi(hex) BN.from_hex(hex).to_mpi; end
      def ec_add(point); self.class.new(group, OpenSSL::BN.from_hex(OpenSSL_EC.ec_add(self, point))); end
    end
  end

  autoload :OpenSSL_EC, "graphene/ffi/openssl"
  autoload :Secp256k1, "graphene/ffi/secp256k1"

  @network = :graphene

  def self.network
    # Store the copy of network options so we can modify them in tests without breaking the defaults
    @network_options ||= NETWORKS[@network].dup
  end

  def self.network_name
    @network
  end

  def self.network_project
    @network_project
  end

  def self.network=(name)
    raise "Network descriptor '#{name}' not found."  unless NETWORKS[name.to_sym]
    @network_options = nil # clear cached parameters
    @network = name.to_sym
    @network_project = network[:project] rescue nil
    @network
  end

  [:graphene, :bitshares].each do |n|
    instance_eval "def #{n}?; network_project == :#{n}; end"
  end

  # maximum size of a block (in bytes)
  MAX_BLOCK_SIZE = 1_000_000

  # soft limit for new blocks
  MAX_BLOCK_SIZE_GEN = MAX_BLOCK_SIZE/2

  # maximum number of signature operations in a block
  MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE / 50

  # maximum number of orphan transactions to be kept in memory
  MAX_ORPHAN_TRANSACTIONS = MAX_BLOCK_SIZE/100

  # Threshold for lock_time: below this value it is interpreted as block number, otherwise as UNIX timestamp.
  LOCKTIME_THRESHOLD = 500000000 # Tue Nov  5 00:53:20 1985 UTC

  # maximum integer value
  UINT32_MAX = 0xffffffff
  INT_MAX = 0xffffffff # deprecated name, left here for compatibility with existing users.

  # number of confirmations required before coinbase tx can be spent
  COINBASE_MATURITY = 100

  # interval (in blocks) for difficulty retarget
  RETARGET_INTERVAL = 2016
  RETARGET = 2016 # deprecated constant

  # interval (in blocks) for mining reward reduction
  REWARD_DROP = 210_000

  CENT =   1_000
  COIN = 100_000

  MIN_FEE_MODE     = [ :block, :relay, :send ]

  NETWORKS = {
    graphene: {
      project: :graphene,
      magic_head: "\xF9\xBE\xB4\xD9", #check
      address_version: "", #check
      address_prefix: "GPH",
      # p2sh_version: "05", #check
      privkey_version: "80",
      # extended_privkey_version: "0488ade4", #check
      # extended_pubkey_version: "0488b21e", #check
      default_port: 1776,
      protocol_version: 70001, #check
      coinbase_maturity: 100, #check
      # reward_base: 50 * COIN,
      # reward_halving: 210_000,
      # retarget_interval: 2016,
      # retarget_time: 1209600, # 2 weeks
      target_spacing: 3, # block interval
      max_money: 21_000_000 * COIN,
      min_tx_fee: 10_000, #check
      min_relay_tx_fee: 10_000, #check
      free_tx_bytes: 1_000, #check
      dust: CENT, #check
      per_dust_fee: false, #check
      # bip34_height: 227931,
      dns_seeds: [],
      genesis_hash: "8796dc9de67e7a118bc89c4a9b42a24c5bbd68f3b7d185aea7250ce1ec485059", #chain id
      alert_pubkeys: [],
      known_nodes: [],
      checkpoints: {},
      expires_in: 15 # tx expiration time, seconds
    }
  }

  NETWORKS[:bitshares] = NETWORKS[:graphene].merge({
    project: :bitshares,
    address_prefix: "BTS",
    genesis_hash: "4018d7844c78f6a6c41c6a552b898022310fc5dec06da467ee7905a8dad512c8"
  })

  module Blockchain
    module Space
      RELATIVE_PROTOCOL = 0
      PROTOCOL          = 1
      IMPLEMENTATION    = 2
    end

    module Apis
        DATABASE           = "database"
        NETWORK_BROADCAST  = "network_broadcast_api"
        NETWORK_NODE       = "network_node_api"
        HISTORY            = "history"
    end

    OBJECT_TYPE = {
      "NULL"                             => "1.0.%d",
      "BASE"                             => "1.1.%d",
      "ACCOUNT"                          => "1.2.%d",
      "ASSET"                            => "1.3.%d",
      "FORCE_SETTLEMENT"                 => "1.4.%d",
      "COMMITTEE_MEMBER"                 => "1.5.%d",
      "WITNESS"                          => "1.6.%d",
      "LIMIT_ORDER"                      => "1.7.%d",
      "CALL_ORDER"                       => "1.8.%d",
      "CUSTOM"                           => "1.9.%d",
      "PROPOSAL"                         => "1.10.%d",
      "OPERATION_HISTORY"                => "1.11.%d",
      "WITHDRAW_PERMISSION"              => "1.12.%d",
      "VESTING_BALANCE"                  => "1.13.%d",
      "WORKER"                           => "1.14.%d",
      "BALANCE"                          => "1.15.%d",
      "GLOBAL_PROPERTY"                  => "2.0.%d",
      "DYNAMIC_GLOBAL_PROPERTY"          => "2.1.%d",
      "RESERVED0"                        => "2.2.%d",
      "ASSET_DYNAMIC_DATA"               => "2.3.%d",
      "ASSET_BITASSET_DATA"              => "2.4.%d",
      "ACCOUNT_BALANCE"                  => "2.5.%d",
      "ACCOUNT_STATISTICS"               => "2.6.%d",
      "TRANSACTION"                      => "2.7.%d",
      "BLOCK_SUMMARY"                    => "2.8.%d",
      "ACCOUNT_TRANSACTION_HISTORY"      => "2.9.%d",
      "BLINDED_BALANCE"                  => "2.10.%d",
      "CHAIN_PROPERTY"                   => "2.11.%d",
      "WITNESS_SCHEDULE"                 => "2.12.%d",
      "BUDGET_RECORD"                    => "2.13.%d"
    }
  end
end