module Graphene
  module RPC

    autoload :JsonRpc,        'rpc/json_rpc'
    autoload :WebSocketRpc,   'rpc/web_socket_rpc'
    autoload :WebSocket,      'rpc/web_socket'
    autoload :WebSocket,      'rpc/subscription'

    class ConnRefused   < RuntimeError; end
    class Unauthorized  < RuntimeError; end
  end
end