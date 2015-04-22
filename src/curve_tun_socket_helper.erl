-module(curve_tun_socket_helper).
-behaviour(gen_fsm).

-export([async_connect/3, async_accept/1]).

%% FSM callbacks
-export([init/1, code_change/4, terminate/3, handle_info/3, handle_event/3, handle_sync_event/4]).

-export([
	ready/3
]).

async_connect(Host, Port, Options) ->
    {ok, Pid} = gen_fsm:start_link(?MODULE, [self()], []),
    gen_fsm:sync_send_event(Pid, {connect, Host, Port, Options}).

async_accept(LSock) ->
    {ok, Pid} = gen_fsm:start_link(?MODULE, [self()], []),
    gen_fsm:sync_send_event(Pid, {accept, LSock}).

init([Owner]) ->
    Ref = erlang:monitor(process, Owner),
    {ok, ready, #{ owner=>Owner, ref=>Ref }}.

ready({accept, ListenSock}, From, State=#{ owner:=Owner }) ->
    gen_fsm:reply(From, ok),
    case gen_tcp:accept(ListenSock) of
        {ok, Socket} ->
            ok = gen_tcp:controlling_process(Socket, Owner),
            gen_fsm:send_event(Owner, {accept, {ok, Socket}}),
            {stop, normal, State};
        {error, Reason} ->
            gen_fsm:send_event(Owner, {accept, {error, Reason}})
    end,
    {stop, normal, State};

ready({connect, Host, Port, Options}, From, #{ owner:=Owner} = State) ->
    gen_fsm:reply(From, ok),
    case gen_tcp:connect(Host, Port, Options) of
        {ok, Socket} ->
            ok = gen_tcp:controlling_process(Socket, Owner),
            gen_fsm:send_event(Owner, {connect, {ok, Socket}}),
            {stop, normal, State};
        {error, Reason} ->
            gen_fsm:send_event(Owner, {connect, {error, Reason}})
    end,
    {stop, normal, State}.


code_change(_,_,_,_) ->
    ok.

terminate(_,_,_) ->
    ok.

handle_info(_,_,_) ->
    ok.

handle_event(_,_,_) ->
    ok.

handle_sync_event(_,_,_,_) ->
    ok.




