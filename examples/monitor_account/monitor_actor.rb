# require File.expand_path('../../graphene', __FILE__)
lib = File.expand_path("../../../lib/", __FILE__)
$LOAD_PATH.unshift lib unless $LOAD_PATH.include?(lib)
require 'graphene'

module Graphene
  module Actor
    class MonitorActor < BaseActor
      ACTOR_NAME = "MonitorActor"

      attr_reader :ws

      # array of objects to monitor and its callback method name or block
      # [[object_id_or_name: method_name or block], [object2 array]]
      attr_accessor :monitored_objects

      def initialize(ws, objects_to_monitor, options = {})
        super(ws, options)

        @monitored_objects = objects_to_monitor || {}
        @callbacks = {
          on_subscribe_callback:  :on_subscribe_callback,
          on_pending_transaction: :on_pending_transaction,
          on_block_appied:        :on_block_appied
        }
      end

      def update(evt_type, data = nil)
        callback = @callbacks[evt_type.to_sym]
        callback = method(callback) if callback.is_a?(String) || callback.is_a?(Symbol)

        case evt_type
        when 'on_subscribe_callback'
          if data.size > 0
            data.first.each do |d|
              puts d[:id]
              if true || @monitored_objects[:account_ids].include?(d[:id])
                callback.call(d)
              end
            end
          end
        when "on_pending_transaction"
          on_pending_transaction(data)
        when 'on_block_appied'
          on_block_appied(data)
        end
      end

      # @param data[Object]: instead of array, data is object within the notice raw data
      def on_subscribe_callback(data)
        log "on_subscribe: #{data}"
      end

      def on_pending_transaction
        log "on_pending_transaction"
      end

      def on_block_appied
        log "on_block_appied"
      end

      def obj_id(name, instance)
        objects = Graphene::Blockchain::OBJECT_TYPE

        raise Error, 'object_id does not exist' unless objects[name.upcase!]

        objects[name]%instance
      end

      def set_object_callback(evt_type, &block)
        @callbacks[evt_type.to_sym] = block if block_given?
      end

    end
  end
end

if $0 == __FILE__
  # require File.expand_path('../../../graphene', __FILE__)
  # require File.expand_path('../../actor/base_actor', __FILE__)
  # require File.expand_path('../../actor/echo_actor', __FILE__)
  require 'pry'

  puts "Graphene API test.."
  ws = Graphene::Protocol::WS.new('ws://localhost:8090', 'user', 'password', echo_off: true)

  monitored_objects = {
    account_ids: ['1.2.9960','2.8.23719'],
    block_applied: []
  }
  actor = Graphene::Actor::MonitorActor.new(ws, monitored_objects)

  actor.set_object_callback("on_subscribe_callback") do |data|
    puts "block callback #{data}"
  end
  begin
    ws.connect
  rescue Exception => e
    binding.pry
  end
end