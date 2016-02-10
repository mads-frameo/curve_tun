-module(curve_tun).

-export([
         connect/2, connect/3, connect/4,
         listen/2,
         transport_accept/1,
         handshake/3, handshake/4,
         accept/1, accept/2,
         send/2, close/1, recv/1, recv/2, controlling_process/2, metadata/1,          peername/1, setopts/2, peer_public_key/1
]).

-include("curve_tun_api.hrl").

%% --------------------------------------------------

-spec connect(host() | port(), [connect_option()]) -> {ok, #curve_tun_socket{}} |
					      {error, reason()}.
-spec connect(host() | port(), [connect_option()] | inet:port_number(),
	      timeout() | list()) ->
		     {ok, #curve_tun_socket{}} | {error, reason()}.
-spec connect(host() | port(), inet:port_number(), list(), timeout()) ->
		     {ok, #curve_tun_socket{}} | {error, reason()}.

connect(Host, Opts) when is_list(Opts) ->
    connect(Host, Opts, infinity).

connect(Port, Opts, Timeout) when is_port(Port), is_list(Opts) ->
    curve_tun_connection:connect(Port, Opts, Timeout);

connect(Host, Port, Opts) when is_integer(Port), is_list(Opts) ->
    connect(Host, Port, Opts, infinity).

connect(Host, Port, Opts, Timeout) ->
    curve_tun_connection:connect(Host, Port, Opts, Timeout).


%% --------------------------------------------------

-spec listen(inet:port_number(), [listen_option()]) ->
    {ok, #curve_tun_socket{}} | {error, reason()}.

listen(Port, Opts) ->
    curve_tun_connection:listen(Port, Opts).

%%--------------------------------------------------------------------
-spec transport_accept(#curve_tun_lsock{}) -> {ok, #curve_tun_socket{}} |
					{error, reason()}.
-spec transport_accept(#curve_tun_lsock{}, timeout()) -> {ok, #curve_tun_socket{}} |
						   {error, reason()}.

transport_accept(LSock) ->
    transport_accept(LSock, infinity).

transport_accept(LSock, Timeout) ->
    curve_tun_connection:transport_accept(LSock, Timeout).

%%--------------------------------------------------------------------

-spec handshake(#curve_tun_socket{},
                client | server,
                timeout()) ->
    ok | {error, reason()}.

handshake(Sock, Role, Timeout) when Role =:= client; Role =:= server ->
    curve_tun_connection:handshake(Sock, Role, Timeout).

-spec handshake(port(), client|server, [curve_tun_option()], timeout) ->
    {ok, #curve_tun_socket{}} | {error, reason()}.
handshake(Port, Role, Options, Timeout) when Role =:= client; Role =:= server ->
    curve_tun_connection:handshake(Port, Role, Options, Timeout).


%%--------------------------------------------------------------------
%% does transport_accept + handshake(server).

accept(LSock) ->
    curve_tun_connection:accept(LSock).

accept(LSock, Timeout) ->
    curve_tun_connection:accept(LSock, Timeout).

send(Sock, Msg) ->
    curve_tun_connection:send(Sock, Msg).

close(Sock) ->
    curve_tun_connection:close(Sock).

recv(Sock) ->
    curve_tun_connection:recv(Sock).

recv(Sock, Timeout) ->
    curve_tun_connection:recv(Sock, Timeout).

peername(Sock) ->
    curve_tun_connection:peername(Sock).

peer_public_key(Sock) ->
    curve_tun_connection:peer_public_key(Sock).

controlling_process(Sock, Pid) ->
    curve_tun_connection:controlling_process(Sock, Pid).

metadata(Sock) ->
    curve_tun_connection:metadata(Sock).

setopts(Sock, Opts) ->
    curve_tun_connection:setopts(Sock, Opts).

