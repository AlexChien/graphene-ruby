module Graphene
  module Blockchain
    module Space
      RELATIVE_PROTOCOL = 0
      PROTOCOL          = 1
      IMPLEMENTATION    = 2
    end

    module Apis
        DATABASE           = "database"
        NETWORK_BROADCAST  = "network_broadcast"
        NETWORK_NODE       = "network_node"
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