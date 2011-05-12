%%%----------------------------------------------------------------------
%%% Copyright Grey Area 2011
%%% 
%%% Worker connects to the APN server and sends push notification
%%% PDUs. Sockets are kept open and worker recovers from stale
%%% sockets.
%%% ----------------------------------------------------------------------

-module(apnsender_worker).
-author('Teemu Ikonen <teemu@lifelineventures.com>').
-behaviour(gen_server).

-export([start_link/1, stop/0, init/1, handle_call/3, handle_cast/2,
	 handle_info/2, terminate/2, code_change/3]).

-record(state, {pool, sock, trid, monitor, conf}).

%% Push message expiration time in seconds
-define(PUSH_EXPIRY, 3600).

%% connection timeout to the APN server
-define(CONN_TIMEOUT, 5000).

-define(SSL_OPTS, {mode, binary}).

start_link(Args) -> gen_server:start_link(?MODULE, Args, []).
stop() -> gen_server:cast(?MODULE, stop).

%% initialize worker and reads configuration from the
%% arguments. Connection to APN is not created here, because it's
%% needed only on first push message.
init(Args) ->
    process_flag(trap_exit, true),
    Pool = proplists:get_value(pool, Args),
    Hostname = proplists:get_value(hostname, Args),
    Port = proplists:get_value(port, Args),
    Cert = proplists:get_value(cert_file, Args),
    Key = proplists:get_value(key_file, Args),

    %NOTE! Find the certs under duality!
    Dir = code:lib_dir(duality, priv),
    error_logger:info_msg("apnsender cert path ~p", [Dir]),

    CertPath = filename:join([Dir, Cert]),
    KeyPath = filename:join([Dir, Key]),

    Conf = {Hostname, Port, CertPath, KeyPath},
    {ok, #state{sock=null, pool=Pool, trid=0, conf=Conf}}.

%% Receive error PDU from the Apple. Peer sends it only for first
%% error, and closes socket. If all goes well, we don't receive
%% anything but it still needs to handle socket closing gracefully
%% (e.g. on timeout).
recv(Pid) ->
    receive
	{ssl, Sock, <<Command, Status, TrID:32/big>>} ->
	    %% error PDU received, log error and close socket.
	    error_logger:error_msg("apnsender: Received", 
				   [Command, Status, TrID]),
	    ssl:close(Sock),
	    gen_server:cast(Pid, socketdied);
	{ssl_closed, _Sock} ->
	    gen_server:cast(Pid, socketdied);
	{_event, _Event} ->
	    error_logger:error_msg("apnsender: Unknown", [_event, _Event]);
	{_event, _Sock, _Data} ->
	    error_logger:error_msg("apnsender: Unknown PDU", [_event, _Data])
    end.

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

%% write APN PDU to the socket
write_pdus(Sock, TrID, [PushToken|Rest], Payload) ->
    {MSeconds,Seconds,_} = erlang:now(),
    Expiry = MSeconds * 1000000 + Seconds + ?PUSH_EXPIRY,
    Packet = [<<1:8, TrID:32/big, Expiry:32/big, % header
		(erlang:byte_size(PushToken)):16/big, PushToken/binary>>, % token
	      Payload], % payload
    case ssl:send(Sock, Packet) of
	ok -> write_pdus(Sock, TrID + 1, Rest, Payload);
	{error, _Error} ->
	    %% socket write error
	    error_logger:error_msg("apnsender: PDU write failed", [_Error]), 
	    {error, TrID}
    end;
write_pdus(_, TrID, [], _) ->
    {ok, TrID}.

%% Encodes payload to binary
prepare_payload(Message, JSonObj) ->
    Payload = mochijson:encode({struct, 
				[
				 {"aps", {struct, [{"alert", Message}]}},
				 {"app", JSonObj}
				]
			       }),
    BPayload = erlang:list_to_binary(Payload),
    case erlang:byte_size(BPayload) of 
	Length when Length > 255 ->
	    {error, Length}; 
	Length ->
	    {ok,  <<Length:16/big, BPayload/binary>>}
    end.

handle_push(Sock, TrID, PushTokens, Message, JSonObj, State) ->
    %% check payload length
    case prepare_payload(Message, JSonObj) of
	{ok, Payload} ->
	    case write_pdus(Sock, TrID, PushTokens, Payload) of
		{ok, NewTrID} ->
		    {noreply, State#state{sock=Sock, trid=NewTrID}};
		{error, NewTrID} ->
		    %% In rare cases the socket server has died before
		    %% we call this, this will cause error and worker
		    %% process exit. (The message target does not
		    %% exists anymore). Pool will restart worker when
		    %% this happens.
		    ssl:close(Sock),
		    {noreply, State#state{sock=null, trid=NewTrID}}
	    end;
	{error, Length} ->
	    error_logger:error_msg("apnsender: Payload too long", 
				   [Length, Message, JSonObj]),
	    {noreply, State}
    end.

%% socket lost, remove it from the state
handle_cast(socketdied, State) ->
    {noreply, State#state{sock=null}};    
%% push handler that creates a socket if it doesn't exist
handle_cast({push, PushTokens, Message, JSonObj}, 
	    #state{sock=null, trid=TrID, conf=Conf}=State) ->
    {Hostname, Port, Cert, Key} = Conf,
    Options = [{certfile, Cert}, {keyfile, Key}, ?SSL_OPTS],
    case ssl:connect(Hostname, Port, Options, ?CONN_TIMEOUT) of
	{ok, Sock} -> 
	    Pid = self(),
	    ssl:controlling_process(Sock, spawn(fun() -> recv(Pid) end)),
	    handle_push(Sock, TrID, PushTokens, Message, JSonObj, State);
	{error, Error} ->
	    error_logger:error_msg("apnsender: SSL Connect failed", Error),
	    {noreply, State}
    end;
%% push handler with live socket
handle_cast({push, PushTokens, Message, JSonObj}, 
	    #state{sock=Sock, trid=TrID}=State) ->
    handle_push(Sock, TrID, PushTokens, Message, JSonObj, State);
handle_cast({monitor, Pid}, State) ->
    MonitorRef = erlang:monitor(process, Pid),
    {noreply, State#state{monitor=MonitorRef}};
handle_cast(demonitor, #state{monitor=null}=State) ->
    {noreply, State};
handle_cast(demonitor, #state{monitor=MonitorRef}=State) ->
    erlang:demonitor(MonitorRef),
    {noreply, State#state{monitor=null}};
handle_cast(stop, State) ->
    {stop, shutdown, State};
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'DOWN', _, _, _, _}, #state{pool=Pool}=State) ->
    gen_fsm:send_event(Pool, {checkin, self()}),
    {noreply, State};
handle_info({'EXIT', _, _}, State) ->
    {stop, shutdown, State};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{sock=null}) ->
    ok;
terminate(_Reason, #state{sock=Sock}) ->
    ssl:close(Sock),
    ok;
terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
