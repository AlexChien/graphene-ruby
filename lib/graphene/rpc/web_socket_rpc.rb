require_relative './json_rpc'
require_relative './subscription'
require 'websocket-eventmachine-client'

module Graphene
  module RPC
    #
    # API 0: stateless apis called via rpc instance (id = 0)
    # API 1: login and get api calls (id = 1), return varrious API ids
    # API n: access various api with their according id (id = n)
    #
    # all unexplicated defined methods are caught by method_missing method
    # in format like below
    #
    #   func_name({api_id:id, params:[param1, param2], callback: callback_func})
    #
    class WebSocketRpc < JsonRpc
      include Graphene::RPC::Subscription

      def initialize(api_uri, username, password, options = {})
        @username = username
        @password = password

        # request map
        @requests = {}

        # api_ids map
        @api_ids  = {}

        # setup some shorthand func
        %w(database network_broadcast network_node history).each do |name|
          instance_eval "def #{name}_id; return instance_variable_get('@api_ids').values_at('#{name}').first; end"
        end

        super(api_uri, username, password, options)
      end

      # override and do nothing
      # connection setup is moved to connect method
      def init_connection(url, username, password); end

      def connect
        if @uri.scheme == 'https' || @uri.scheme == 'wss'
          @uri.scheme = 'https'; rpc_uri = @uri.to_s
          @uri.scheme = 'wss';   ws_uri = @uri.to_s
        else
          @uri.scheme = 'http'; rpc_uri = @uri.to_s
          @uri.scheme = 'ws';   ws_uri = @uri.to_s
        end

        log.debug { "connect to: #{@uri.to_s}"}

        # setup rpc connection for sync call
        @rpc = JsonRpc.new(rpc_uri, @username, @password, @options)

        # setup ws connection for async call
        @conn = ::WebSocket::EventMachine::Client.connect(uri: ws_uri)

        @conn.onopen    { onopen }
        @conn.onmessage { |msg, type| onmessage(msg, type) }
        @conn.onclose   { |code, reason| onclose(code, reason) }
      end

      def get_account(name_or_id)
        if is_object_id?(name_or_id)
          (rpc_exec 'get_objects', [name_or_id])[0]
        else
          (rpc_exec 'get_account_by_name', name_or_id)[0]
        end
      end

      def get_asset(name_or_id)
        if is_object_id?(name_or_id)
          (rpc_exec 'get_objects', [name_or_id])[0]
        else
          (rpc_exec 'lookup_asset_symbols', [name_or_id])[0]
        end
      end

      def is_object_id?(param)
        param.split('.').length == 3
      end

      # async call using rpc
      # only accessible to API 0 cateogory calls (stateless calls)
      def rpc_exec(method, args)
        @rpc.send method, args
      end

      # connection established
      # now start do stuffs
      #   login
      #   subscribe to apis
      #
      def onopen
        log.info { "onopen" }
        login({ params: [@username, @password], api_id: 1, callback: self.method(:onlogin) })
      end

      # login
      def onlogin(resp)
        if resp[:result]
          log.info {"Login Success"}
          get_api_ids
        else
          log.info {"Login Failed"}
          raise Unauthorized, "Login Failed"
        end
      end

      # register and fetch remote id for each api
      def get_api_ids
        cb = {api_id: 1, callback: self.method(:on_get_api_id)}

        database(cb)
        history(cb)
        network_broadcast(cb)

        # this by default is disabled by api-access.json
        # we don't need it normally
        # network_node(cb)
      end

      # fill api_ids map
      def on_get_api_id(resp)
        req_id = resp[:id]

        api_name = @requests[req_id.to_s][:request][:params][1]
        @api_ids[api_name.downcase.to_s] = resp[:result]

        puts @api_ids


        if api_name == "database"
          subscribe_to_objects
          # subscribe_to_accounts(["init0", "init2"], true)
          # subscribe_to_accounts(["1.2.100", "1.2.102"], true)
          # subscribe_to_pending_transactions
          # subscribe_to_future_block("191125")
          subscribe_to_market('1.3.0', '1.3.660')

          # EM.add_timer(5) do
          #   cancel_all_subscriptions
          # end
        end

      end

      # given api name and return id
      def api_id(api_name)
        @api_ids[api_name.downcase.to_s]
      end

      def onmessage(msg, type)
        log.info { "receive: #{msg} [#{type}]" }

        response = JSON.parse(msg, symbolize_names: true)
          request_id = response[:id].to_s
          method_id  = response[:method].to_s

        log.debug { response[:error] } if response[:error]

        # after subscribing, response returns a null result
        # don't need to go futher down
        return if response[:result].nil?

        # normal interaction will include request_id
        # otherwise it's notice
        if request_id.present?
          req = @requests[request_id]

          # callback
          if req && cb = req[:callback]
            # cb[:response] = response
            cb.call(response)
          else
            # just drop it
            log.debug {"Foreign Response ID: no callback defined"}
          end

        # Run registered call backs for individual object notices
        elsif method_id.present?
          puts "notice"
          # on_subscribe_callback(response)
        end

      end

      #
      # @options[Object]: {api_id, params}
      #
      # @exmaple:
      #   request(login, {params: ['user', 'password'], api_id: 1, callback: self.onlogin})
      #
      def request(method, options = [])
        # binding.pry if method == 'get_full_accounts'
        # options = options.length == 1 ? options[0] : options

        req_id = call_id.to_s
        api_id = options[:api_id] || 1

        req = {
          request: {
            id: req_id,
            method: "call",
            params: [api_id, method, options[:params] || []]
          },
          callback: options[:callback]
        }

        @requests[req_id] = req

        EM.next_tick do
          log.info { "send: #{req[:request]}" }
          @conn.send JSON.dump(req[:request])
        end
      end

      def method_missing(name, *args)
        if args.length > 1
          params = args
        else
          params = args[0]
        end

        params = { params: params.is_a?(Array) ? params : [params] } unless params.is_a? Hash
        params = { api_id: 1 }.merge(params)

        request(name.to_s, params )
      end

      # clean up logic goes here
      def onclose(code, reason)
        log.info { "disconnected with status code: #{code}" }

        EM.stop
      end

      def log_level
        :debug
      end

      # subscription handle
      # we use call_id to present subscription handle
      # it will increase automatically
      # with each specific subscribe call
      #   call_id = identfier + 1
      # because internal counter is auto incremented
      def identifier
        call_id
      end

    end
  end
end

if $0 == __FILE__
  $:.unshift( File.expand_path("../../..", __FILE__) )
  require 'graphene'
  require 'graphene/rpc'
  require 'graphene/rpc/json_rpc'
  # require 'eventmachine'

  class KeyboardHandler < EM::Connection
    include EM::Protocols::LineText2

    attr_reader :ws

    def initialize(ws)
      puts "keyboard inited"
      @ws = ws
    end

    def receive_data(data)
      puts "data: #{data}"
    end

    def receive_line(data)
      puts "line: #{data}"
      @ws.send data
    end
  end

  module KH
    def receive_data data
      puts ">#{data}"
    end
  end

  puts "Graphene WebSocketRpc test.."

  begin

    # EM.epoll
    EM.run do
      # trap("TERM") { stop }
      # trap("INT")  { stop }

        wsrpc = Graphene::RPC::WebSocketRpc.new('ws://127.0.0.1:8099', 'user', 'pass', nolog: false)
        wsrpc.connect




      # EM.open_keyboard(KeyboardHandler, wsrpc)
      # EM.open_keyboard(KH)
    end

  rescue Graphene::RPC::WebSocketRpc::Error => e
    puts "error occured"
    puts e.class
    puts e
  rescue Exception => e
    puts "Uncaptured"
    puts e.class
    puts e.backtrace
  end
end