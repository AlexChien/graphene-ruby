require 'net/http'
require 'uri'
require 'json'

module Graphene
  module Protocol

    class RPC

      class Error < RuntimeError; end

      attr_reader :options

      def initialize(api_uri, username, password, options = {})
        @options = {
          echo_off:       false,
          ignore_errors:  false,
          logger:         nil,
          instance_name:  "graphene_rpc"
        }.merge(options)

        @uri = URI(api_uri)
        @req = Net::HTTP::Post.new(@uri)
        @req.content_type = 'application/json'
        @req.basic_auth username, password
      end

      def log(s)
        return if @options[:echo_off]

        if @options[:logger] && @options[:logger].respond_to?(:info) then
          @options[:logger].info s
        else
          puts s
        end
      end

      def request(method, params = nil)
        params = params || []
        log "[#{@options[:instance_name]}] request: #{method} #{params.join(' ')}"
        result = nil
        Net::HTTP.start(@uri.hostname, @uri.port) do |http|
          @req.body = { method: method, params: params, id: 0 }.to_json
          response = http.request(@req)

          result = JSON.parse(response.body)
          # TODO: capture and throw proper errors
          # is_locked: wallet locked exception
          # rec && rec->name == account_name_or_id: account not found
          # Insufficient Balance: insufficient balance
          if result['error']
            log "error: #{result['error']}"
            unless @options[:ignore_errors]
              raise Error, JSON.pretty_generate(result['error']), "#{method} #{params ? params.join(' ') : ''}"
            else
              @options[:logger].info JSON.pretty_generate(result['error'])
            end
          else
            log 'ok'
          end
        end

        return result['result']
      end

      def method_missing(name, *params)
        request(name.to_s, params)
      end

    end
  end
end

if $0 == __FILE__
  puts "Graphene API test.."
  rpc = Graphene::Protocol::RPC.new('http://localhost:8093/rpc', 'user', 'pass', echo_off: true)

  begin
    # puts rpc.gethelp('unlock')
    puts rpc.info
    puts rpc.get_account('boombastic')
    puts rpc.list_my_accounts.map{ |acct| acct["name"] }
  rescue Graphene::Protocol::RPC::Error => e
    puts "error occured"
    puts e.class
    puts e
  rescue Exception => e
    puts "other error occured"
    puts e
  end
end