require 'json'
require 'observer'
require 'websocket-eventmachine-client'

module Graphene
  module Protocol

    class WS
      include Observable

      class Error < RuntimeError; end

      attr_reader :options

      def initialize(api_uri, username, password, options = {})
        @options = {
          echo_off:  false,
          logger:    nil
        }.merge(options)

        @uri = api_uri
        @username = username
        @password = password

        # api name and id mapping
        @api_ids    = {}

        # request ids and their req objects
        @request_id = 0
        @requests = {}

        # subscription ids
        @callback_id = 0
        @callbacks = {}
      end

      def connect
        # EM.epoll
        EM.run do
          @ws = WebSocket::EventMachine::Client.connect(:uri => @uri)
          @ws.onopen     {             onopen               }
          @ws.onmessage  { |msg, type| onmessage(msg, type) }
          @ws.onclose    { |code, msg| onclose(code, msg)   }
          @ws.onerror    { |err|       onerror(err)         }
        end
      end

      def login
        log "WS_LOGIN"
        exec( [1, "login", [@username, @password]], { method: "onlogin" } )
      end

      def connect_to_api(api_type)
        @callback_id += 1
        @callbacks[@callback_id.to_s] = {
          method: "register_api_id",
          params: [api_type]
        }

        exec(
          [1, api_type, []], @callbacks[@callback_id.to_s]
        )
      end

      def register_api_id(response)
        api_id              = response[:result]
        api_type            = response[:cb_obj][:params][0]

        @api_ids[api_type.to_sym] = api_id
        # self.send callback
        subscribe_to_objects(api_type)
      end

      def exec(params, cb_obj = nil)
        @request_id += 1

        req = {
          request: {
            id: @request_id.to_s,
            method: "call",
            params: params
          },
          cb_obj: cb_obj
        }

        @requests[@request_id.to_s] = req

        log "SEND: #{req[:request]}"
        @ws.send JSON.dump(req[:request])
      end

      def onmessage(msg, type)
        log "WS_ONMESSAGE: #{msg} | #{type}"

        response = JSON.parse(msg, symbolize_names: true)
        request_id = response[:id].to_s

        if response[:error]
          raise Error, "error_occurred", response
        end

        # normal interaction will include request_id
        # otherwise it's notice
        unless request_id.empty?
          req = @requests[request_id]
          req[:response] = response if req

          # callback
          if req && req[:cb_obj]
            self.send req[:cb_obj][:method], req
          end
        else
          on_subscribe_callback(response)
        end
      end

      def notify(evt_type, data = nil)
        log "WS_NOTIFY"

        changed
        notify_observers(evt_type, data)
      end

      def onlogin(req)
        log "WS_ONLOGIN: #{req}"

        # login successful
        response = req[:response]
        if response[:result] === true
          connect_to_api(Graphene::Blockchain::Apis::DATABASE)
        else
          raise Error, 'login_failed'
        end
      end

      # only support database api_type for now
      def subscribe_to_objects(api_type)
        return unless api_type == Graphene::Blockchain::Apis::DATABASE

        # subscribe to objects
        @callback_id += 1
        @callbacks[@callback_id.to_s] = { method: :check_subscription_result, callback_id: @callback_id }
        exec(
          [@api_ids[Graphene::Blockchain::Apis::DATABASE], 'set_subscribe_callback', [@callback_id,true]],
          @callbacks[@callback_id.to_s]
        )
      end

      # if subscription failed, remove subscription id
      def check_subscription_result(req)
        log "check_subscription_result"
        response = req[:response]
        cb_obj   = req[:cb_obj]

        unless response[:result] === true
          @callbacks.delete(cb_obj[:callback_id])
        else
          raise Error, "callback_id_not_found"
        end
      end

      def on_subscribe_callback(res)
        callback_id, data = res[:params]

        # if callback id exists
        if @callbacks[callback_id.to_s]
          notify('on_subscribe_callback', data)
        end
      end

      # will not notify observers about onopen event
      # they shouldn't care about this detail
      # they should be interested in onlogin event,
      # when that occurs they can start to deal with the node
      def onopen
        log "WS_ONOPEN"
        @request_id = 1

        # notify('onopen')
        login
      end

      def onclose(code, msg)
        log "WS_ONCLOSE"
        notify('onclose', {code:code, msg:msg})
      end

      def onerror(err)
        log "WS_ONERROR"
        notify('onerror', {err: err})
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

    end
  end
end