-module(curve_tun_connection).
-behaviour(gen_fsm).

-export([connect/3, connect/4, transport_accept/2, handshake/3, handshake/4, accept/1, accept/2, listen/2, send/2, close/1,
         recv/1, recv/2, controlling_process/2,
         metadata/1,
         peername/1, setopts/2, peer_public_key/1
        ]).

%% Private callbacks
-export([start_fsm/2, start_link/3]).

%% FSM callbacks
-export([init/1, code_change/4, terminate/3, handle_info/3, handle_event/3, handle_sync_event/4]).

-export([
	connected/2, connected/3,
	awaiting_cookie/2, awaiting_cookie/3,
        awaiting_ready/2, awaiting_ready/3,
	ready/2, ready/3
]).

-include("curve_tun_api.hrl").

%% Maximal number of messages that can be sent on the line before we crash.
%% I don't expect code to ever hit this limit. As an example, you exhaust this in
%% a year if you manage to send 584 billion messages per second on a single
%% connection.
-define(COUNT_LIMIT, 18446744073709551616 - 1).

-define(UCS_FISH,    16#f0, 16#9f, 16#90, 16#9f).

-define(TELL_TAG,    ?UCS_FISH, "TELL"). %% please reveal public permanent key
-define(WELCOME_TAG, ?UCS_FISH, "WELC"). %% provide public ephemeral key
-define(HELLO_TAG,   ?UCS_FISH, "HELO"). %% 
-define(COOKIE_TAG,  ?UCS_FISH, "COOK").
-define(VOUCH_TAG,   ?UCS_FISH, "VOCH").
-define(READY_TAG,   ?UCS_FISH, "REDY").
-define(MESSAGE_TAG, ?UCS_FISH, "MESG").
-define(BYE_TAG,     ?UCS_FISH, "BYE!").

%%
%% tries to mimick the behavior of public methods for ssl
%%

connect(Port, Options, Timeout)
  when is_port(Port),
       is_list(Options),
       ((Timeout =:= infinity) orelse is_integer(Timeout)) ->
    { TcpOpts, TunOptions } = filter_options(Options),
    ok = gen_tcp:setopts(Port, TcpOpts),
    connect2(Port, TcpOpts, TunOptions, Timeout).

connect(Address, Port, Options, Timeout) ->
    { TcpOpts, TunOptions } = filter_options(Options),
    BeforeTime = erlang:now(),
    case gen_tcp:connect(Address, Port, [{active, false} | TcpOpts ], Timeout) of
        {ok, Socket} ->
            case millis_left(BeforeTime, Timeout) of
                0 ->
                    ok = gen_tcp:close(Socket),
                    {error, timeout};
                TimeLeft ->
                    connect2(Socket, [], TunOptions, TimeLeft)
            end;
        {error,_}=Err ->
            Err
    end.

connect2(Port, TcpOpts, TunOpts, Timeout) when is_port(Port) ->
    ok = gen_tcp:setopts( Port, TcpOpts ),
    {ok, Pid} = start_fsm( Port, TunOpts ),
    ok = gen_tcp:controlling_process( Port, Pid ),
    Socket = #curve_tun_socket{ pid = Pid },
    case handshake(Socket, client, Timeout) of
        ok ->
            {ok, Socket};
        {error,_}=Err ->
            Err
    end.

listen(Port, Opts) when is_list(Opts) ->
    {TcpOpts, TunOptions} = filter_options(Opts),
    Options = [binary, {packet, 2}, {active, false} | TcpOpts],
    case gen_tcp:listen(Port, Options) of
        {ok, LSock} ->
            {ok, #curve_tun_lsock { lsock = LSock, options=TunOptions }};
        {error,_}=Err ->
            Err
    end.

accept(LSock=#curve_tun_lsock{}, Timeout) ->
    BeforeTime = erlang:now(),
    case transport_accept( LSock, Timeout ) of
        {ok, Socket} ->
            case millis_left(BeforeTime, Timeout) of
                0 ->
                    ok = close(Socket),
                    {error, timeout};
                TimeLeft ->
                    case handshake(Socket, server, TimeLeft) of
                        ok ->
                            {ok, Socket};
                        {error, _}=Err ->
                            Err
                    end
            end;
        {error, _}=Err ->
            Err
    end;
accept(LSock, Timeout) when is_port(LSock) ->
    ok = gen_tcp:setopts(LSock, [{active, false}, binary, {packet, 2}]),
    accept(#curve_tun_lsock{ lsock=LSock, options = [] }, Timeout).

accept(LSock) ->
    accept(LSock, infinity).

transport_accept(#curve_tun_lsock { lsock = LSock, options=TunOptions }, Timeout) ->
    case gen_tcp:accept( LSock, Timeout ) of
        {ok, Socket} ->
            wrap(Socket, TunOptions);
        {error, Reason} ->
            {error, Reason}
    end.

-spec handshake(#curve_tun_socket{}, client|server, non_neg_integer() | infinity) -> ok | {error, term()}.
handshake(#curve_tun_socket{ pid = Pid }, Role, Timeout) when Role =:= client; Role =:= server ->
    sync_send_event(Pid, {handshake, Role, Timeout}).

-spec handshake(port(), client|server, [curve_tun_option()], timeout) ->
    {ok, #curve_tun_socket{}} | {error, reason()}.

handshake(Socket, Role, TunOptions, Timeout) when is_port(Socket) ->
    case filter_options(TunOptions) of
        {[], Options} ->
            {ok, TunSocket} = wrap(Socket, Options),
            case handshake(TunSocket, Role, Timeout) of
                ok ->
                    {ok, TunSocket};
                {error,_}=Err ->
                    Err
            end;
        _ ->
            {error, {badarg, TunOptions}}
    end.

wrap(#curve_tun_socket{} = Socket, _) ->
    {ok, Socket};
wrap(Socket, Options) when is_port(Socket) ->
    ok = inet:setopts(Socket, [binary, {packet, 2}, {active, false}]),
    {ok, Pid} = start_fsm(Socket, Options),
    ok = gen_tcp:controlling_process(Socket, Pid),
    {ok, #curve_tun_socket{ pid = Pid }}.

send(#curve_tun_socket { pid = Pid }, Msg) ->
    sync_send_event(Pid, {send, Msg}).

recv(#curve_tun_socket { pid = Pid }, Timeout) ->
    sync_send_event(Pid, {recv, Timeout}).

recv(State) ->
    recv(State, infinity).

peer_public_key(#curve_tun_socket{ pid=Pid }) ->
    sync_send_all_state_event(Pid, peer_public_key).

peername(#curve_tun_socket { pid = Pid }) ->
    sync_send_all_state_event(Pid, peername);
peername(Sock) when is_port(Sock) ->
    inet:peername(Sock).

setopts(#curve_tun_socket{ pid=Pid}, Opts) ->
    sync_send_event(Pid, {setopts, Opts}).

close(#curve_tun_socket { pid = Pid }) ->
    case sync_send_all_state_event(Pid, close) of
        {error, closed} ->
            ok;
        Other ->
            Other
    end.

controlling_process(#curve_tun_socket { pid = Pid }, Controller) ->
    sync_send_all_state_event(Pid, {controlling_process, Controller}).

metadata(#curve_tun_socket{ pid=Pid}) ->
    sync_send_event(Pid, metadata).

%% @private
start_fsm(Socket, Options) ->
    Controller = self(),
    curve_tun_connection_sup:start_child([Controller, Socket, Options]).

%% @private
start_link(Controller, Socket, Options) ->
    gen_fsm:start_link(?MODULE, [Controller, Socket, Options], []).

%% @private
init([Controller,Socket,Options]) ->
    Ref = erlang:monitor(process, Controller),
    State = #{
      vault      => curve_tun_vault_dummy,
      registry   => curve_tun_simple_registry,
      controller => {Controller, Ref},
      socket     => Socket,
      restbin    => <<>>,

      c          => 0,
      rc         => 0,

      packet => 0,
      metadata => [],
      active => false
    },

    %% apply options
    State2 = lists:foldl(fun({K,V}, S) ->
                                 maps:put(K,V,S);
                            (K, S) when is_atom(K) ->
                                 maps:put(K, true, S)
                         end,
                         State,
                         Options),

    {ok, ready, State2}.


%% @private
ready({handshake, client, Timeout},
      From,
      #{ socket := Socket, peer_public_key := S }=State) ->
    Timer = start_timer(Timeout, handshake),
    #{ public := EC, secret := ECs } = enacl:box_keypair(),
    case gen_tcp:send(Socket, e_hello(S, EC, ECs, 0)) of
        ok ->
            ok = inet:setopts(Socket, [{active, once}]),
            {next_state, awaiting_cookie, State#{ %
                                            ephemeral_public_key => EC,
                                            ephemeral_secret_key => ECs,
                                            side => client,
                                            from => From,
                                            timer => Timer }};
        {error, Reason} ->
            {stop, normal, reply({error, Reason}, State)}
    end;
ready({handshake, client, Timeout},
      From, #{ socket := Socket }=State) ->
    Timer = start_timer(Timeout, handshake),
    case gen_tcp:send(Socket, e_tell()) of
        ok ->
            ok = inet:setopts(Socket, [{active, once}]),
            {next_state, awaiting_welcome, State#{
                                            side => client,
                                            from => From,
                                            timer => Timer }};
        {error, Reason} ->
            {stop, normal, reply({error, Reason}, State)}
    end;
ready({handshake, server, Timeout }, From, #{ socket := Socket } = State) ->
    Timer = start_timer(Timeout, handshake),
    ok = inet:setopts(Socket, [{active, once}]),
    {next_state, awaiting_hello, State#{ side => server,
                                         from => From,
                                         timer => Timer }}.

ready(_Msg, State) ->
    {stop, argh, State}.

awaiting_cookie(_Msg, _From, State) ->
    {stop, {unexpected_message, _Msg}, State}.

awaiting_cookie(_Msg, _) ->
    {stop, argh, ready}.

awaiting_ready(_Msg, _From, _State) ->
    {stop, argh, ready}.

awaiting_ready(_Msg, _) ->
    {stop, argh, ready}.

connected(_M, State) ->
    {stop, argh, State}.

connected({recv, Timeout}, From, #{ recv_queue := Q } = State) ->
    Timer = start_timer(Timeout, {sync_recv, From}),
    process_recv_queue(State#{ recv_queue := queue:in(#{ type=>sync_recv, from => From, timer => Timer}, Q) });
connected({send, M}, _From, #{ socket := Socket, ephemeral_secret_key := Ks, peer_ephemeral_public_key := P, c := NonceCount, side := Side, packet := Packet } = State) ->
    case gen_tcp:send(Socket, e_msg(encode_packet(Packet, M), Side, NonceCount, P, Ks)) of
         ok -> {reply, ok, connected, State#{ c := NonceCount + 1}};
         {error, _Reason} = Err -> {reply, Err, connected, State}
    end;
connected(metadata, _From, #{ rmd := MetaData } = State) ->
    {reply, {ok, MetaData}, connected, State};
connected(peername, _From, #{socket := Socket} = State) ->
    {reply, inet:peername(Socket), connected, State};
connected({setopts, Opts}, From, #{socket := Socket} = State) ->
    case lists:foldl(fun(_, E={_, _}) -> E;
                        ({packet, N}, S) when N == 0; N == 1; N == 2; N == 4 ->
                             S#{ packet => N };
                        ({packet, raw}, S) ->
                             S#{ packet => 0 };
                        (binary, S) -> S;
                        (O={nodelay, _}, S) ->
                             case inet:setopts(Socket, [O]) of
                                 ok -> S;
                                 E={error, _} -> {E,S}
                             end;
                        ({active, Val}, S) when Val =:= true; Val =:= false; Val =:= once ->
                             S#{ active => Val };
                        (Opt, S) ->
                             {{error, {unknown_opt, Opt}}, S}
                     end,
                     State,
                     Opts) of
        {E,State2} ->
            gen_fsm:reply(From, E),
            process_recv_queue(State2);
        State2 ->
            gen_fsm:reply(From, ok),
            process_recv_queue(State2)
    end.



handle_sync_event({controlling_process, Controller}, {PrevController, _Tag}, Statename,
        #{ controller := {PrevController, MRef} } = State) ->
    erlang:demonitor(MRef, [flush]),
    NewRef = erlang:monitor(process, Controller),
    {reply, ok, Statename, State#{ controller := {Controller, NewRef}}};
handle_sync_event({controlling_process, _Controller}, _From, Statename, State) ->
    {reply, {error, not_owner}, Statename, State};
handle_sync_event(close, _From, _StateName, #{ socket:=Socket } = State) ->
    gen_tcp:close(Socket),
    {stop, normal, ok, maps:remove(socket, State) };
handle_sync_event(peername, From, Statename, #{ socket := Socket }=State) ->
    gen_fsm:reply(From, inet:peername(Socket)),
    {next_state, Statename, State};
handle_sync_event(peer_public_key, From, Statename, #{ peer_public_key := Key }=State) ->
    gen_fsm:reply(From, {ok, Key}),
    {next_state, Statename, State};
handle_sync_event(peer_public_key, From, Statename, State) ->
    gen_fsm:reply(From, undefined),
    {next_state, Statename, State};
handle_sync_event(Event, _From, Statename, State) ->
    error_logger:info_msg("Unknown sync_event ~p in state ~p", [Event, Statename]),
    {next_state, Statename, State}.

handle_event(Event, Statename, State) ->
    error_logger:info_msg("Unknown event ~p in state ~p", [Event, Statename]),
    {next_state, Statename, State}.

handle_info({'DOWN', _Ref, process, Pid, _Info}, _Statename, #{ controller := Pid, socket := Socket } = State) ->
    ok = gen_tcp:close(Socket),
    {stop, normal, maps:remove(socket, State)};
handle_info({tcp, Sock, Data}, Statename, #{ socket := Sock } = State) ->
    handle_tcp(Data, Statename, State);
handle_info({tcp_closed, Sock}, _Statename, #{ socket := Sock } = State) ->
    {stop, {shutdown, transport_closed}, maps:remove(socket, handle_unrecv_data(State))};
handle_info({tcp_error, Sock, Reason}, _Statename, #{ socket := Sock } = State) ->
    {stop, {shutdown, {transport_error, Reason}}, maps:remove(socket, handle_unrecv_data(State))};
handle_info({timer, handshake}, _Statename, State) ->
    {stop, normal, reply({error, timeout}, State)};
handle_info({timer, {sync_recv, From}}, Statename, #{ recv_queue := Q } = State) ->
    gen_fsm:reply(From, {error, timeout}),
    NewQ = queue:from_list(lists:filter(fun(#{ from := F }) when F =:= From -> false;
                                           (_) -> true
                                        end,
                                       queue:to_list(Q))),
    {next_state, Statename, State#{ recv_queue => NewQ }};
handle_info(Info, Statename, State) ->
    error_logger:info_msg("Unknown info msg ~p in state ~p", [Info, Statename]),
    {next_state, Statename, State}.


terminate(_Reason, _Statename, State) ->

    case maps:find(socket, State) of
        {ok, Sock} -> gen_tcp:close(Sock);
        error -> ok
    end,

    handle_unrecv_data(State),
    ok.

code_change(_OldVsn, Statename, State, _Aux) ->
    {ok, Statename, State}.

%% INTERNAL HANDLERS

handle_unrecv_data(#{ recv_queue := Q, controller := {Controller,_}, active := Active } = State) ->

    %% reply {error, closed} to all sync callers
    [ gen_fsm:reply(Receiver, {error, closed})
      || #{ type := sync_recv, from := Receiver } <- queue:to_list(Q) ],

    case Active of
        false ->
            ok;
        _     ->
            erlang:send(Controller, {curve_tun_closed, {curve_tun_socket,self()}})
    end,
    State#{ recv_queue=>queue:new(), active => true };
handle_unrecv_data(State) ->
    State.

unpack_cookie(<<Nonce:16/binary, Cookie/binary>>) ->
    CNonce = lt_nonce(minute_k, Nonce),
    Keys = curve_tun_cookie:recent_keys(),
    unpack_cookie_(Keys, CNonce, Cookie).
    
unpack_cookie_([], _, _) -> {error, ecookie};
unpack_cookie_([K | Ks], CNonce, Cookie) ->
    case enacl:secretbox_open(Cookie, CNonce, K) of
        {ok, <<EC:32/binary, ESs:32/binary>>} -> {ok, EC, ESs};
        {error, failed_verification} ->
            unpack_cookie_(Ks, CNonce, Cookie)
    end.

reply(M, #{ from := From } = State) ->
    State2 = case maps:find(timer, State) of
                 {ok, Timer} ->
                     cancel_timer(Timer),
                     maps:remove(timer, State);
                 error ->
                     State
             end,
    gen_fsm:reply(From, M),
    maps:remove(from, State2).
    
%% @doc process_recv_queue/1 sends messages back to waiting receivers
%% Analyze the current waiting receivers and the buffer state. If there is a receiver for the buffered
%% message, then send the message back the receiver.
%% @end
process_recv_queue(#{ recv_queue := Q, buf := Buf, socket := Sock, controller := {Controller,_}, active := Active } = State) ->
%    io:format(user, "process_queue(~p)~n", [State]),
    case {queue:out(Q), Buf} of

        {{{value, _Receiver}, _Q2}, undefined} ->
            ok = inet:setopts(Sock, [{active, once}]),
            {next_state, connected, State};
        {_, undefined} when Active =/= false ->
            ok = inet:setopts(Sock, [{active, once}]),
            {next_state, connected, State};

        {{{value, #{ type := sync_recv, from := Receiver, timer := Timer }}, Q2}, Msg} ->
            cancel_timer(Timer),
            gen_fsm:reply(Receiver, {ok, Msg}),
            process_recv_queue(State#{ recv_queue := Q2, buf := undefined });

        {_, Msg} when Active == true ->
            AM = {curve_tun, {curve_tun_socket,self()}, Msg},
            erlang:send(Controller, AM),
            ok = inet:setopts(Sock, [{active, once}]),
            process_recv_queue(State#{ buf := undefined });

        {_, Msg} when Active == once ->
            AM = {curve_tun, {curve_tun_socket,self()}, Msg},
            erlang:send(Controller, AM),
            process_recv_queue(State#{ active := false, buf := undefined });

        {_, _} ->
            {next_state, connected, State}
    end.

handle_msg(?COUNT_LIMIT, _Box, _State) -> exit(count_limit);
handle_msg(N, Box, #{
                peer_ephemeral_public_key := P,
                ephemeral_secret_key := Ks,
                buf := undefined,
                side := Side,
                rc := N,
                packet := Packet,
                restbin := Old } = State) ->
    Nonce = case Side of
                client -> st_nonce(msg, server, N);
                server -> st_nonce(msg, client, N)
            end,
    {ok, Payload} = enacl:box_open(Box, Nonce, P, Ks),
    case erlang:decode_packet(Packet, All = <<Old/binary, Payload/binary>>, []) of
        {ok, Msg, Rest} ->
            process_recv_queue(State#{ buf := Msg, restbin := Rest, rc := N+1 });
        {more, _} ->
            process_recv_queue(State#{ restbin := All, rc := N+1 });
        {error, Reason} ->
            {stop, {error, Reason}, State}
    end.

handle_vouch(_, N, _, #{ rc := RC } = State) when N < RC ->
    {stop, {bad_nonce, N}, State};
handle_vouch(K, N, Box, #{ c := C, socket := Sock, vault := Vault, registry := Registry, metadata := MDOut } = State) ->
    case unpack_cookie(K) of
        {ok, EC, ESs} ->
            Nonce = st_nonce(initiate, client, N),
            {ok, <<ClientPK:32/binary, NonceLT:16/binary, Vouch:48/binary, MetaData/binary>>} = enacl:box_open(Box, Nonce, EC, ESs),
            true = Registry:verify(Sock, ClientPK),
            VNonce = lt_nonce(client, NonceLT),
            {ok, <<EC:32/binary>>} = Vault:box_open(Vouch, VNonce, ClientPK),

            case MetaData of
                <<>> -> % client didn't send meta data
                    %% Everything seems to be in order, go to connected state
                    begin_connected(ClientPK, ESs, EC, [], C, N+1, State);
                _ ->
                    MDIn = d_metadata(MetaData),
                    case gen_tcp:send(Sock, e_ready(MDOut, C, EC, ESs)) of
                        ok ->
                            %% Everything seems to be in order, go to connected state
                            begin_connected(ClientPK, ESs, EC, MDIn, C+1, N+1, State);
                        {error, _Reason} = Err ->
                            {stop, Err, State}
                    end
            end;

        {error, _Reason} = Err ->
            {stop, Err, State}

    end.

begin_connected(ClientPK, ESs, EC, MDIn, C, RC, State) ->
    NState = State#{
               recv_queue => queue:new(),
               buf => undefined,
               rmd => MDIn,
               ephemeral_secret_key => ESs,
               peer_public_key => ClientPK,
               peer_ephemeral_public_key => EC,
               c => C,
               rc => RC,
               side => server,
               active => false },
    process_recv_queue(reply(ok, NState)).


handle_cookie(N, Box, #{ ephemeral_public_key := EC, ephemeral_secret_key := ECs, peer_public_key := S, socket := Socket, vault := Vault, md := MD } = State) ->
    Nonce = lt_nonce(server, N),
    {ok, <<ES:32/binary, K/binary>>} = enacl:box_open(Box, Nonce, S, ECs),
    case gen_tcp:send(Socket, e_vouch(K, EC, S, Vault, 1, ES, ECs, MD)) of
        ok ->
            ok = inet:setopts(Socket, [{active, once}]),
            {next_state, awaiting_ready, State#{
			peer_ephemeral_public_key => ES,
			recv_queue => queue:new(),
			buf => undefined,
			c => 2,
			side => client,
			rc => 2 }};
        {error, _Reason} = Err ->
            {stop, normal, reply(Err, State)}
    end.

handle_ready(N, _, State = #{ rc := N2 }) when N < N2 ->
    {stop, bad_nonce, State};
handle_ready(N, Box, State = #{
                       ephemeral_secret_key := Ks,
                       peer_ephemeral_public_key := P,
                       rc := N2,
                       side := client,
                       socket := Sock }) when N >= N2 ->
    Nonce = st_nonce(ready, server, N),
    {ok, MetaData} = enacl:box_open(Box, Nonce, P, Ks),
    ServersMD = d_metadata(MetaData),
    %% deal with server's MD
    ok = inet:setopts(Sock, [{active, once}]),
    {next_state, connected, reply(ok, State#{ rc := N+1, rmd => ServersMD })}.

handle_hello(EC, Box, #{ vault := Vault, socket := Socket, side := server } = State) ->

    STNonce = st_nonce(hello, client, 0),
    {ok, <<0:512/integer>>} = Vault:box_open(Box, STNonce, EC),

    %% Once ES is in the hands of the client, the server doesn't need it anymore
    #{ public := ES, secret := ESs } = enacl:box_keypair(),
    case  gen_tcp:send(Socket, e_cookie(EC, ES, ESs, Vault)) of
        ok ->
            ok = inet:setopts(Socket, [{active, once}]),
            {next_state, awaiting_vouch, State};
        {error, Reason} ->
            {stop, normal, {error, Reason}, State}
    end.

handle_tell(#{ socket := Socket, side := server, vault := Vault } = State) ->
    PK = Vault:public_key(),
    case gen_tcp:send(Socket, e_welcome(PK)) of
        ok ->
            ok = inet:setopts(Socket, [{active, once}]),
            {next_state, awaiting_hello, State};
        {error, Reason} ->
            {stop, normal, {error, Reason}, State}
    end.

handle_welcome(S, #{ socket := Socket, side := client } = State) ->
    #{ public := EC, secret := ECs } = enacl:box_keypair(),
    case gen_tcp:send(Socket, e_hello(S, EC, ECs, 0)) of
        ok ->
            ok = inet:setopts(Socket, [{active, once}]),
            {next_state, awaiting_cookie, State#{
                                            ephemeral_public_key => EC,
                                            ephemeral_secret_key => ECs,
                                            c => 1,
                                            rc => 0
                                           }};
        {error, Reason} ->
            {stop, normal, reply({error, Reason}, State)}
    end.

handle_tcp(Data, StateName, State) ->
    case {d_packet(Data), StateName} of
        {{msg, N, Box}, connected} -> handle_msg(N, Box, State);
        {{vouch, K, N, Box}, awaiting_vouch} -> handle_vouch(K, N, Box, State);
        {{cookie, N, Box}, awaiting_cookie} -> handle_cookie(N, Box, State);
        {{ready, N, Box}, awaiting_ready} -> handle_ready(N, Box, State);
        {{hello, EC, 0, Box}, awaiting_hello} -> handle_hello(EC, Box, State);
        {{welcome, S}, awaiting_welcome} -> handle_welcome(S, State);
        {tell, awaiting_hello} -> handle_tell(State)
    end.


%% NONCE generation
%%
%% There are two types of nonces: short-term (st) and long-term (lt)

st_nonce(hello, client, N) -> <<"CurveCP-client-H", N:64/integer>>;
st_nonce(initiate, client, N) -> <<"CurveCP-client-I", N:64/integer>>;
st_nonce(msg, client, N) -> <<"CurveCP-client-M", N:64/integer>>;
st_nonce(hello, server, N) -> <<"CurveCP-server-H", N:64/integer>>;
st_nonce(initiate, server, N) -> <<"CurveCP-server-I", N:64/integer>>;
st_nonce(msg, server, N) -> <<"CurveCP-server-M", N:64/integer>>;
st_nonce(ready, server, N) -> <<"CurveCP-server-R", N:64/integer>>.

lt_nonce(minute_k, N) -> <<"minute-k", N/binary>>;
lt_nonce(client, N) -> <<"CurveCPV", N/binary>>;
lt_nonce(server, N) -> <<"CurveCPK", N/binary>>.

   
%% COMMAND GENERATION
%% 
%% The e_* functions produce messages for the wire. They are kept here
%% for easy perusal. Note that while the arguments are terse, they do have
%% meaning since they reflect the meaning of the protocol specification. For
%% instance, the argument ECs means (E)phermeral (C)lient (s)ecret key.
e_tell() ->
    <<?TELL_TAG>>.

e_welcome(PK) ->
    <<?WELCOME_TAG, PK/binary>>.

e_hello(S, EC, ECs, N) ->
    Nonce = st_nonce(hello, client, N),
    Box = enacl:box(binary:copy(<<0>>, 64), Nonce, S, ECs),
    <<?HELLO_TAG, EC:32/binary, N:64/integer, Box/binary>>.

e_cookie(EC, ES, ESs, Vault) ->
    Ts = curve_tun_cookie:current_key(),
    SafeNonce = Vault:safe_nonce(),
    CookieNonce = lt_nonce(minute_k, SafeNonce),

    KBox = enacl:secretbox(<<EC:32/binary, ESs:32/binary>>, CookieNonce, Ts),
    K = <<SafeNonce:16/binary, KBox/binary>>,
    BoxNonce = lt_nonce(server, SafeNonce),
    Box = Vault:box(<<ES:32/binary, K/binary>>, BoxNonce, EC),
    <<?COOKIE_TAG, SafeNonce:16/binary, Box/binary>>.

e_vouch(Kookie, VMsg, S, Vault, N, ES, ECs, MD) when byte_size(Kookie) == 96 ->
    NonceBase = Vault:safe_nonce(),

    %% Produce the box for the vouch
    VouchNonce = lt_nonce(client, NonceBase),
    VouchBox = Vault:box(VMsg, VouchNonce, S),
    C = Vault:public_key(),
    
    STNonce = st_nonce(initiate, client, N),
    MetaData = e_metadata(MD),
    Box = enacl:box(<<C:32/binary, NonceBase/binary, VouchBox:48/binary, MetaData/binary>>, STNonce, ES, ECs),
    <<?VOUCH_TAG, Kookie/binary, N:64/integer, Box/binary>>.

e_ready(MetaData, NonceCount, PK, SK) ->
    Nonce = st_nonce(ready, server, NonceCount),
    Box = enacl:box(e_metadata(MetaData), Nonce, PK, SK),
    <<?READY_TAG, NonceCount:64/integer, Box/binary>>.

e_msg(M, Side, NonceCount, PK, SK) ->
    Nonce = st_nonce(msg, Side, NonceCount),
    Box = enacl:box(M, Nonce, PK, SK),
    <<?MESSAGE_TAG, NonceCount:64/integer, Box/binary>>.

%% PACKET DECODING
%%
%% To make it easy to understand what is going on, keep the packet decoder
%% close the to encoding of messages. The above layers then handle the
%% semantics of receiving and sending commands/packets over the wire
d_packet(<<?MESSAGE_TAG, N:64/integer, Box/binary>>) ->
    {msg, N, Box};
d_packet(<<?VOUCH_TAG, K:96/binary, N:64/integer, Box/binary>>) ->
    {vouch, K, N, Box};
d_packet(<<?COOKIE_TAG, N:16/binary, Box/binary>>) ->
    {cookie, N, Box};
d_packet(<<?HELLO_TAG, EC:32/binary, N:64/integer, Box/binary>>) ->
    {hello, EC, N, Box};
d_packet(<<?READY_TAG, N:64/integer, Box/binary>>) ->
    {ready, N, Box};
d_packet(<<?TELL_TAG>>) ->
    tell;
d_packet(<<?WELCOME_TAG, S:32/binary>>) ->
    {welcome, S};
d_packet(Bin) ->
    {unknown, Bin}.
    

%% METADATA CODING
d_metadata(<<>>) ->
    [];
d_metadata(<<N, Rest/binary>>) ->
    d_metadata(N, Rest, []).

d_metadata(0, <<>>, L) ->
    lists:reverse(L);
d_metadata(N, <<K:8, Key:K/binary, V:16, Value:V/binary, Rest/binary>>, L) ->
    d_metadata(N-1, Rest, [{Key,Value}|L]).

e_metadata(List) when length(List) < 16#100 ->
    N = length(List),
    erlang:iolist_to_binary( [ N | e_metadata(List, []) ] ).

e_metadata([], Data) ->
    Data;
e_metadata([{Key,Value}|Rest], Data)
  when byte_size(Key) < 16#100,
       byte_size(Value) < 16#10000 ->
    K = byte_size(Key),
    V = byte_size(Value),
    e_metadata(Rest, [<< K:8, Key/binary, V:16, Value/binary >> | Data ]).


%% Handle options.  This splits options into socket options and curve_tun options.

filter_options(List) ->
    Curve = lists:filter(fun is_curve_option/1, List),
    Tcp   = lists:filter(fun is_tcp_option/1, List),
    {Tcp, Curve}.

is_tcp_option(Opt) ->
    not is_curve_option(Opt).

is_curve_option(Opt) ->
    case Opt of
        {K,_} ->
            lists:member(K, [active, metadata, packet, peer_public_key, key]);
        _ ->
            false
    end.


%% UTILITY

sync_send_all_state_event(FsmPid, Event) ->
    try gen_fsm:sync_send_all_state_event(FsmPid, Event, infinity)
    catch
 	exit:{noproc, _} ->
 	    {error, closed};
	exit:{normal, _} ->
	    {error, closed};
	exit:{{shutdown, _},_} ->
	    {error, closed}
    end.

sync_send_event(FsmPid, Event) ->
    sync_send_event(FsmPid, Event, infinity).

sync_send_event(FsmPid, Event, Timeout) ->
    try gen_fsm:sync_send_event(FsmPid, Event, Timeout)
    catch
 	exit:{noproc, _} ->
 	    {error, closed};
	exit:{normal, _} ->
	    {error, closed};
	exit:{{shutdown, _},_} ->
	    {error, closed}
    end.

start_timer(infinity, _) ->
    undefined;
start_timer(Timeout, Event) ->
    erlang:send_after(Timeout, self(), {timer, Event}).

cancel_timer(undefined) ->
    ok;
cancel_timer(Timer) ->
    erlang:cancel_timer(Timer),
    ok.

encode_packet(0, Bin) when is_binary(Bin) ->
    Bin;
encode_packet(1, Bin) when byte_size(Bin) < 16#FF ->
    Len = byte_size(Bin),
    <<Len:8, Bin/binary>>;
encode_packet(2, Bin) when byte_size(Bin) < 16#FFFF->
    Len = byte_size(Bin),
    <<Len:16, Bin/binary>>;
encode_packet(4, Bin) when byte_size(Bin) < 16#FFFFFFFF ->
    Len = byte_size(Bin),
    <<Len:32, Bin/binary>>.

millis_left(_BeforeTime, infinity) ->
    infinity;
millis_left(BeforeTime, Timeout) ->
    max(0, Timeout - (timer:now_diff(erlang:now(), BeforeTime) div 1000)).
