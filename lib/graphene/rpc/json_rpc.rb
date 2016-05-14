# encoding: ascii-8bit

require 'net/http'
require 'uri'
require 'json'

module Graphene
  module RPC
    class JsonRpc

      class Error < RuntimeError; end

      attr_reader :options

      def initialize(api_uri, username, password, options = {})
        @options = {
          log_level:  log_level,
          nolog:      false
        }.merge(options)

        @call_id = 0
        @uri = URI(api_uri)

        init_connection(@uri, username, password)
      end

      def init_connection(uri, username, password)
        @conn = Net::HTTP::Post.new(@uri)
        @conn.content_type = 'application/json'
        @conn.basic_auth username, password
      end

      def request(method, params = nil)
        params = params || []
        log.info { "request: #{method} #{params.join(' ')}" }
        result = nil
        Net::HTTP.start(@uri.hostname, @uri.port) do |http|
          @conn.body = { method: method, params: params, id: call_id }.to_json
          log.debug { "request.body: " + @conn.body }

          response = http.request(@conn)
          log.debug { "response.body: " + response.body }

          begin
            result = JSON.parse(response.body)
          rescue
            log.error { "error parsing response: #{response.body}" }
            raise Error, 'error parsing response', response.body
          end

          if result['error']
            log.error { "#{result['error']}" }
            process_error(method, params, result['error'])
          else
            log.info { "OK: #{result['result']}" }
          end
        end

        return result['result']

      rescue Errno::ECONNREFUSED => e
        log.error { "Connection Refused" }
        raise Graphene::RPC::ConnRefused, "Connection Error"
      # rescue Unauthorized
      end

      def method_missing(name, *args)
        request(name.to_s, args)
      end

      def call_id
        @call_id += 1
      end

      # handle better error
      # TODO: to distinct different senarios
      # is_locked: wallet locked exception
      # rec && rec->name == account_name_or_id: account not found
      # Insufficient Balance: insufficient balance
      def process_error(method, params, error)
        # case error
        # when /self\.is_locked/
        #
        # when
        #
        # end
        raise Error, JSON.pretty_generate(error), "#{method} #{params ? params.join(' ') : ''}"
      end



      def log
        return @log if @log
        return (@log = (stub=Object.new; def stub.method_missing(*a); end; stub)) if @options[:nolog]
        @logger ||= Graphene::Logger.create(log_name, log_level)
        @log = Graphene::Logger::LogWrapper.new("#{@uri.host}:#{@uri.port}", @logger)
      end

      def log_name
        self.class.to_s.split('::').last.to_sym
      end

      def log_level
        @log_level || :debug
      end

    end
  end
end

if $0 == __FILE__
  $:.unshift( File.expand_path("../../..", __FILE__) )
  require 'graphene'
  require 'graphene/rpc'

  puts "Graphene API test.."
  rpc = Graphene::RPC::JsonRpc.new('http://localhost:8093/rpc', 'user', 'pass', nolog: true)

  begin
    puts rpc.info
    puts rpc.get_account('boombastic')
    puts rpc.list_my_accounts.map{ |acct| acct["name"] }
    # puts rpc.transfer('init0', 'init1', 10, 'CORE', '', true)

  rescue Graphene::RPC::JsonRpc::Error => e
    puts "error occured"
    puts e.class
    puts e
  rescue Exception => e
    puts "Uncaptured"
    puts e.class
    puts e
  end
end