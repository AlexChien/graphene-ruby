h1. Warning

This is still an early experiment work in progress, codes are far from
production quality, use at your own risk.

you need to have private testnet setup

RPC API sample
rpc = Graphene::Protocol::Rpc.new('localhost', 8093, 'user', 'pass', echo_off: true)
rpc.help
rpc.gethelp('transfer')
rpc.info
