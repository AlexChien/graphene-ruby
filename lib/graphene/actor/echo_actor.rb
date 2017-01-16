module Graphene
  module Actor
    # simple echo message actor
    class EchoActor < BaseActor
      ACTOR_NAME = "EchoActor"

      class Error < RuntimeError; end

      attr_accessor :ws

      def initialize(ws, options = {})
        super(ws, options)
      end

      def update(evt_type, data = nil)
        log "EchoActor update: #{evt_type} | #{data}"
        if self.respond_to? evt_type
          self.send(evt_type, data)
        else
          raise Error, 'not_implemented' if !@options[:ignore_errors]
        end
      end

      def onlogin(data = nil)
        log "onlogin"
      end

      def onping(data = nil)
        log "onping: #{data[:msg]}"
      end

      def onpong(msg)
        log "onpong: #{msg}"
      end

      def onclose(code, msg)
        log "onclose: #{code}|#{msg}"
      end

      def onerror(e)
        log "onerror: #{e}"
      end

      def onmessage(msg, data)
        log "onmessage: #{msg}|#{data}"
      end

    end
  end
end