-module(curve_tun_connection).
-behaviour(gen_fsm).

-export([connect/3, connect/4, transport_accept/1, handshake/2, accept/1, accept/2, listen/2, start/2, send/2, close/1,
         recv/1, recv/2, controlling_process/2,
         metadata/1, 
         peername/1, setopts/2, peer_public_key/1
        ]).

%% Private callbacks
-export([start_fsm/1, start_link/2]).

%% FSM callbacks
-export([init/1, code_change/4, terminate/3, handle_info/3, handle_event/3, handle_sync_event/4]).

-export([
	connected/2, connected/3,
	awaiting_cookie/2, awaiting_cookie/3,
        awaiting_ready/2, awaiting_ready/3,
	ready/2, ready/3
]).

-record(curve_tun_lsock, { lsock :: port (), options :: list() }).

-record(curve_tun_socket, { pid :: pid() }).

%% Maximal number of messages that can be sent on the line before we crash.
%% I don't expect code to ever hit this limit. As an example, you exhaust this in
%% a year if you manage to send 584 billion messages per second on a single
%% connection.
-define(COUNT_LIMIT, 18446744073709551616 - 1).

-define(UCS_FISH,    16#f0, 16#9f, 16#90, 16#9f).

-define(TELL_TAG,    ?UCS_FISH, "TELL").
-define(WELCOME_TAG, ?UCS_FISH, "WELC").
-define(HELLO_TAG,   ?UCS_FISH, "HELO").
-define(COOKIE_TAG,  ?UCS_FISH, "COOK").
-define(VOUCH_TAG,   ?UCS_FISH, "VOCH").
-define(READY_TAG,   ?UCS_FISH, "REDY").
-define(MESSAGE_TAG, ?UCS_FISH, "MESG").
-define(BYE_TAG,     ?UCS_FISH, "BYE!").

connect(Address, Port, Options, Timeout) ->
    connect(Address, Port, [{timeout, Timeout}|Options]).

connect(Address, Port, Options) ->
    {SocketOpts, TunOptions = #{ timeout := Timeout }} = filter_options(Options),
    AbsTimeout = abs_timeout(Timeout),
    case gen_tcp:connect(Address, Port, SocketOpts, Timeout) of
        {ok, Socket} ->
            start(Socket, TunOptions#{ mode => client, abs_timeout => AbsTimeout });
        Err ->
            Err
    end.

listen(Port, Opts) ->
    {SocketOpts, TunOptions} = filter_options(Opts),
    Options = [binary, {packet, 2}, {active, false} | SocketOpts],
    case gen_tcp:listen(Port, Options) of
        {ok, LSock} -> {ok, #curve_tun_lsock { lsock = LSock, options=TunOptions }};
        {error, Reason} -> {error, Reason}
    end.

accept(#curve_tun_lsock { lsock = LSock, options=TunOptions=#{ timeout:=Timeout } }) ->
    AbsTimeout = abs_timeout(Timeout),
    case gen_tcp:accept( LSock ) of
        {ok, Socket} ->
            start(Socket, TunOptions#{ mode => server, abs_timeout => AbsTimeout });
        {error, Reason} ->
            {error, Reason}
    end.
accept(#curve_tun_lsock{ lsock=LSock, options=TunOptions }, Timeout) ->
    accept(#curve_tun_lsock{ lsock=LSock, options=TunOptions#{ timeout => Timeout }}).


transport_accept(#curve_tun_lsock { lsock = LSock, options=TunOptions }) ->
    case gen_tcp:accept( LSock ) of
        {ok, Socket} ->
            ok = inet:setopts(Socket, [{nodelay, true}, binary,
                                       {packet, 2}, {active, false}]),
            {ok, Pid} = start_fsm(Socket),
            ok = gen_tcp:controlling_process(Socket, Pid),
            case sync_send_event(Pid, {set_options, TunOptions}) of
                ok ->
                    {ok, #curve_tun_socket{ pid = Pid }};
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

handshake(#curve_tun_socket{ pid = Pid }, #{mode :=_ } = Options) ->
    TimeOut = case Options of
                  #{ timeout := TO } -> TO;
                  _ -> infinity
              end,
    sync_send_event(Pid, {handshake,
                          Options#{ timeout=>TimeOut,
                                    abs_timeout=>abs_timeout(TimeOut) }}).

start(Socket, Options) when is_map(Options) ->
    ok = inet:setopts(Socket, [{nodelay, true}, binary, {packet, 2}, {active, false}]),
    {ok, Pid} = start_fsm(Socket),
    ok = gen_tcp:controlling_process(Socket, Pid),
    case sync_send_event(Pid, {start, Options}) of
        ok ->
            {ok, #curve_tun_socket{ pid = Pid }};
        {error, Reason} ->
            {error, Reason}
    end;
start(Socket, Opts) when is_list(Opts) ->
    { _SocketOpts, TunOptions=#{ timeout := Timeout } } = filter_options(Opts),
    start(Socket, TunOptions#{ abs_timeout => abs_timeout(Timeout) });
start(Socket, Opts) when is_integer(Opts) ->
    { _SocketOpts, TunOptions} = filter_options([]),
    start(Socket, TunOptions#{ abs_timeout => abs_timeout(Opts) }).


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
start_fsm(Socket) ->
    Controller = self(),
    curve_tun_connection_sup:start_child([Controller, Socket]).

%% @private
start_link(Controller, Socket) ->
    gen_fsm:start_link(?MODULE, [Controller, Socket], []).

%% @private
init([Controller,Socket]) ->
    Ref = erlang:monitor(process, Controller),
    State = #{
        vault => curve_tun_vault_dummy,
        registry => curve_tun_simple_registry,
        controller => {Controller, Ref},
        socket => Socket,
        metadata => []
    },
    {ok, ready, State}.


%% @private
ready({set_options, Options}, From, State) ->
    gen_fsm:reply(From, ok),
    State2 = lists:foldl(fun({K,V}, S) ->
                                 maps:put(K,V,S)
                         end,
                         State,
                         maps:to_list(Options)),
    {next_state, ready, State2};
ready({handshake, #{ mode := client, metadata := MD, peer_public_key := S, abs_timeout := AbsTimeout }}, From, #{socket := Socket }=State) ->
    Timer = start_timer(unabs_timeout(AbsTimeout), handshake),
    #{ public := EC, secret := ECs } = enacl:box_keypair(),
    case gen_tcp:send(Socket, e_hello(S, EC, ECs, 0)) of
        ok ->
            ok = inet:setopts(Socket, [{active, once}]),
            {next_state, awaiting_cookie, State#{
                                            peer_lt_public_key => S,
                                            public_key => EC,
                                            secret_key => ECs,
                                            socket => Socket,
                                            from => From,
                                            timer => Timer,
                                            md => MD }};
        {error, Reason} ->
            {stop, normal, reply({error, Reason}, State)}
    end;
ready({handshake, Opts=#{ mode := server, abs_timeout := AbsTimeout }}, From, 
 #{ socket := Socket } = State) ->
    Timer = start_timer(unabs_timeout(AbsTimeout), handshake),
    ok = inet:setopts(Socket, [{active, once}]),
    {next_state, awaiting_hello, State#{ socket => Socket,
                                         md => case maps:find(metadata, Opts) of {ok, MD} -> MD; error -> [] end,
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
connected({send, M}, _From, #{ socket := Socket, secret_key := Ks, peer_public_key := P, c := NonceCount, side := Side } = State) ->
    Len = byte_size(M),
    case gen_tcp:send(Socket, e_msg(<<Len:16, M/binary>>, Side, NonceCount, P, Ks)) of
         ok -> {reply, ok, connected, State#{ c := NonceCount + 1}};
         {error, _Reason} = Err -> {reply, Err, connected, State}
    end;
connected(metadata, _From, #{ rmd := MetaData } = State) ->
    {reply, {ok, MetaData}, connected, State};
connected(peername, _From, #{socket := Socket} = State) ->
    {reply, inet:peername(Socket), connected, State};
connected({setopts, Opts}, From, #{socket := Socket} = State) ->
    case lists:foldl(fun(_, E={_, _}) -> E;
                        ({packet, 2}, S) -> S;
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
    [ gen_fsm:reply(Receiver, {error, closed}) || #{ type := sync_recv, from := Receiver } <- queue:to_list(Q) ],

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
	peer_public_key := P,
	secret_key := Ks,
	buf := undefined,
	side := Side,
	rc := N } = State) ->
    Nonce = case Side of
                client -> st_nonce(msg, server, N);
                server -> st_nonce(msg, client, N)
            end,
    {ok, <<Len:16, Msg:Len/binary>>} = enacl:box_open(Box, Nonce, P, Ks),
    process_recv_queue(State#{ buf := Msg, rc := N+1 }).

handle_vouch(K, 1, Box, #{ socket := Sock, vault := Vault, registry := Registry, md := MDOut } = State) ->
    case unpack_cookie(K) of
        {ok, EC, ESs} ->
            Nonce = st_nonce(initiate, client, 1),
            {ok, <<C:32/binary, NonceLT:16/binary, Vouch:48/binary, MetaData/binary>>} = enacl:box_open(Box, Nonce, EC, ESs),
            true = Registry:verify(Sock, C),
            VNonce = lt_nonce(client, NonceLT),
            {ok, <<EC:32/binary>>} = Vault:box_open(Vouch, VNonce, C),

            case MetaData of
                <<>> -> % client didn't send meta data
                    %% Everything seems to be in order, go to connected state
                    NState = State#{ recv_queue => queue:new(), buf => undefined, rmd => [],
                                     secret_key => ESs, peer_public_key => EC, c => 3, rc => 2, side => server, active => false },
                    process_recv_queue(reply(ok, NState));
                _ ->
                    MDIn = d_metadata(MetaData),
                    case gen_tcp:send(Sock, e_ready(MDOut, 2, EC, ESs)) of
                        ok ->
                            %% Everything seems to be in order, go to connected state
                            NState = State#{ recv_queue => queue:new(), buf => undefined, rmd => MDIn,
                                             secret_key => ESs, peer_public_key => EC, c => 3, rc => 2, side => server, active => false },
                            process_recv_queue(reply(ok, NState));
                        {error, _Reason} = Err ->
                            {stop, Err, State}
                    end
            end;

        {error, _Reason} = Err ->
            {stop, Err, State}

    end.

handle_cookie(N, Box, #{ public_key := EC, secret_key := ECs, peer_lt_public_key := S, socket := Socket, vault := Vault, md := MD } = State) ->
    Nonce = lt_nonce(server, N),
    {ok, <<ES:32/binary, K/binary>>} = enacl:box_open(Box, Nonce, S, ECs),
    case gen_tcp:send(Socket, e_vouch(K, EC, S, Vault, 1, ES, ECs, MD)) of
        ok ->
            ok = inet:setopts(Socket, [{active, once}]),
            {next_state, awaiting_ready, State#{
			peer_public_key => ES,
			recv_queue => queue:new(),
			buf => undefined,
			c => 2,
			side => client,
			rc => 2 }};
        {error, _Reason} = Err ->
            {stop, normal, reply(Err, State)}
    end.

handle_ready(N, Box, State = #{
                       secret_key := Ks,
                       peer_public_key := P,
                       rc := N,
                       side := client,
                       socket := Sock }) ->
    Nonce = st_nonce(ready, server, N),
    {ok, MetaData} = enacl:box_open(Box, Nonce, P, Ks),
    ServersMD = d_metadata(MetaData),
    %% deal with server's MD
    ok = inet:setopts(Sock, [{active, once}]),
    {next_state, connected, reply(ok, State#{ rc := N+1, rmd => ServersMD })}.

handle_hello(EC, Box, #{ vault := Vault, socket := Socket } = State) ->

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


handle_tcp(Data, StateName, State) ->
    case {d_packet(Data), StateName} of
        {{msg, N, Box}, connected} -> handle_msg(N, Box, State);
        {{vouch, K, N, Box}, awaiting_vouch} -> handle_vouch(K, N, Box, State);
        {{cookie, N, Box}, awaiting_cookie} -> handle_cookie(N, Box, State);
        {{ready, N, Box}, awaiting_ready} -> handle_ready(N, Box, State);
        {{hello, EC, 0, Box}, awaiting_hello} -> handle_hello(EC, Box, State)
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
    filter_options(List, [], #{ metadata=>[], timeout => infinity, mode => client, active => false }).

filter_options([], SO, CTO) ->
    {lists:reverse(SO), CTO};
filter_options([KV={K,V}|Rest], SocketOpts, CurveOpts) ->
    case lists:member(K, [metadata, peer_public_key, timeout, mode, active]) of
        true ->
            filter_options(Rest, SocketOpts, maps:put(K,V,CurveOpts));
        false ->
            filter_options(Rest, [KV|SocketOpts], CurveOpts)
    end;
filter_options([K|Rest], SocketOpts, CurveOpts) ->
    case lists:member(K, [server, client]) of
        true ->
            filter_options(Rest, SocketOpts, maps:put(mode,K,CurveOpts));
        false ->
            filter_options(Rest, [K|SocketOpts], CurveOpts)
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

abs_timeout(infinity) ->
    infinity;
abs_timeout(Millis) when Millis > 0 ->
    now_ms(erlang:now()) + Millis.

unabs_timeout(infinity) ->
    infinity;
unabs_timeout(Absolute) ->
    max(0, Absolute - now_ms(erlang:now())).

now_ms({MegaSecs,Secs,MicroSecs}) ->
    (MegaSecs*1000000 + Secs)*1000 + (MicroSecs div 1000).
