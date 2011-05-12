%%%----------------------------------------------------------------------
%%% Copyright Grey Area 2011
%%% 
%%% Application implements a gateway to the Apple Push Notification
%%% service. The workers that create SSL connections and write PDU's
%%% are managed by the poolboy module.
%%% ----------------------------------------------------------------------

-module(apnsender).
-author('Teemu Ikonen <teemu@lifelineventures.com>').
-behaviour(application).
-behaviour(supervisor).

-export([start/0, stop/0, start/2, stop/1, init/1, send_push/3]).

start() -> application:start(?MODULE).
stop()  -> application:stop(?MODULE).

start(_Type, _Args) ->
    supervisor:start_link({local, apnsender_sup}, ?MODULE, []).
stop(_State) -> ok.

init([]) ->
    %% Initialize worker pool
    {ok, Pools} = application:get_env(apnsender, pools),
    PoolSpecs = lists:map(fun({PoolName, PoolConfig}) ->
				  Args = [{name, {local, PoolName}}, 
					  {worker_module, apnsender_worker}]
				      ++ PoolConfig,
				  {PoolName, {poolboy, start_link, [Args]},
				   permanent, 5000, worker, [poolboy]}
			  end, Pools),
    {ok, {{one_for_all, 10, 10}, PoolSpecs}}.

%% Sends push notification message to list of pushtokens
%% Args: PushTokens is list of 32 byte binaries
%%       Message is a string (should be less than 128 bytes)
%%       JSonObj is object accepted by mochijson:encode
%% Returns: ok (errors are masked and logged) 
send_push([<<PushToken:32/binary-unit:8>> |Rest], Message, JSonObj) -> 
    Worker = poolboy:checkout(senderpool),
    gen_server:cast(Worker, {push, [PushToken|Rest], Message, JSonObj}),
    poolboy:checkin(senderpool, Worker),
    ok.
