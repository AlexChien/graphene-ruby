module Graphene
  module RPC
    module Subscription
      # subscription related methods

      # subscribe to generic notifications
      def subscribe_to_objects
        set_subscribe_callback({ api_id: database_id, params: [ identifier, true] })
      end

      # subscribe to pending transactions
      def subscribe_to_pending_transactions
        set_pending_transaction_callback({ api_id: database_id, params: [ identifier] })
      end

      # notify when a future block arrives
      #
      # TODO:
      # weird behavior:
      #   it's returning notification every block since subscription
      #   with target block id and current block hash which keeps changing
      #   and keeps doing that even target block has passed
      #   cannot distinguish if target block is reached unless get_block hash
      #   this is not expected behavior
      #   {"method":"notice","params":[191125,["0002ea93917aecc4a9626142d725854b35211e80"]]}
      #
      def subscribe_to_future_block(block_id)
        set_block_applied_callback({ api_id: database_id, params: [block_id] })
      end

      # subscribe to market
      #
      # @param quote: quota asset id
      # @param base: base asset id
      #
      # receives notification like below
      #   {"method":"notice","params":[identifier,[["order_object_id"]]]}
      #
      def subscribe_to_market(quote_asset_id, base_asset_id)
        # due to low level method uses the same method name
        # we invoke direct request method
        request('subscribe_to_market', { api_id: database_id, params: [identifier, quote_asset_id, base_asset_id]})
      end

      # get accounts and subscribe to their changes if param subscribe is true
      #
      # TODO:
      # don't see any notifications coming in, need to investigate why
      def subscribe_to_accounts(names_or_ids, subscribe = true)
        get_full_accounts({api_id: database_id, params: [names_or_ids, subscribe]})
      end

      # cancel all subsciptions and stop receiving notifications
      def cancel_all_subscriptions
        request('cancel_all_subscriptions', { api_id: database_id, params: []})
      end


    end
  end
end