require 'graphene'

module Graphene
  module Actor
    # Base Actor with essential methods
    # any implementation class should extend this class and implement details
    # start from onlogin method, which means WebSocket is connected and logged in
    class BaseActor
      ACTOR_NAME = "BaseActor"

      attr_accessor :ws

      # Observer of WebService subscription
      #
      # @param ws[WS]: websocket instance
      # @param options: additional options
      #   echo_off[Boolean]: whether output log message, default false
      #   ignore_errors[Boolean]: raise Error or not, default false
      #   logger[Logger]: logger object for message output, default nil, to stdout
      #   instance_name[String]: identifier of this instance, default to ACTOR_NAME
      def initialize(ws, options = {})
        @options = {
          echo_off:       false,
          ignore_errors:  false,
          logger:         nil,
          instance_name:  ACTOR_NAME
        }.merge(options)

        @callback_id = 0
        @callbacks = {}

        @ws = ws
        @ws.add_observer(self)
      end

      # WebSocket is ready, we can do our stuff here
      # call apis and subscribe to objects
      def onlogin
        log "BaseActor onlogin"

        # connect_to_api(Graphene::Blockchain::Apis::DATABASE)
      end

      # When there's data update from WebService, this method will be called
      #
      # @param evt_type[String]: [onlogin, onmessage, onerror, onclose]
      # @param data[Object]: event data object, data structure see process_message method
      def update(evt_type, data = nil)
        case evt_type
        when "onlogin"
          onlogin
        when 'onmessage'
          process_message(data)
        when 'onclose', 'onerror'
          # do nothing now
        end
      end

      # data structure of data
      # data: {
      #   request:{id, method, params},
      #   cb_obj:{callback_id, observer},
      #   data:{response}
      # }
      def process_message(data = nil)
        log "BaseActor: #{data}"
        return unless concerned?(data)

        callback = @callbacks[data[:cb_obj][:callback_id]]
        self.send callback[:method], data, callback[:params]
      end

      # check if this is message i'm interested in
      # when sending messages to WebSocket, will append actor instance_name to callback object
      # when response is received, we will check if the response's callback object has our
      # instance name, discard any response that are not oriented from us
      def concerned?(data)
        data[:cb_obj][:observer] == to_s &&
        @callbacks.has_key?(data[:cb_obj][:callback_id])
      rescue Exception => e
        false
      end

      # output helper message to logger/stdout
      def log(s)
        return if @options[:echo_off]

        if @options[:logger] && @options[:logger].respond_to?(:info) then
          @options[:logger].info s
        else
          puts s
        end
      end

      # shortcut for instance name
      def to_s
        @options[:instance_name]
      end

    end
  end
end