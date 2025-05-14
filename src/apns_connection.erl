%%% @doc This gen_statem handles the APNs Connection.
%%%
%%% Copyright 2017 Erlang Solutions Ltd.
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%% @end
%%% @copyright Inaka <hello@inaka.net>
%%%
-module(apns_connection).
-author("Felipe Ripoll <felipe@inakanetworks.com>").

-behaviour(gen_statem).

%% API
-export([ start_link/2
        , default_connection/2
        , name/1
        , host/1
        , port/1
        , keyfile/1
        , type/1
        , gun_pid/1
        , close_connection/1
        , push_notification/4
        , wait_apns_connection_up/1
        ]).

%% gen_statem callbacks
-export([ init/1
        , callback_mode/0
        , open_origin/3
        , open_common/3
        , await_up/3
        , connected/3
        , down/3
        , code_change/4
        ]).

%% for spawn/3
-export([ reply_errors_and_cancel_timers/2 ]).

-export_type([ name/0
             , host/0
             , port/0
             , path/0
             , connection/0
             , notification/0
             , type/0
             ]).

-type name()         :: atom().
-type host()         :: string() | inet:ip_address().
-type path()         :: string().
-type notification() :: binary().
-type type()         :: token.

-type connection()   :: #{ name       := name()
                         , keyfile    => path()
                         , timeout    => integer()
                         , type       := type()
                         }.

-type stream_data() :: #{ from := {pid(), term()}
                        , stream := gun:stream_ref()
                        , timer := reference()
                        , status := non_neg_integer()
                        , headers := gun:req_headers()
                        , body := binary()
                        }.

-opaque state()      :: #{ connection      := connection()
                         , gun_pid         => pid()
                         , gun_streams     => #{gun:stream_ref() => stream_data()}
                         , max_gun_streams := non_neg_integer()
                         , gun_monitor     => reference()
                         , gun_connect_ref => reference()
                         , client          := pid()
                         , backoff         := non_neg_integer()
                         , backoff_ceiling := non_neg_integer()
                         }.

-export_type([state/0]).

%%%===================================================================
%%% API
%%%===================================================================

%% @doc starts the gen_statem
-spec start_link(connection(), pid()) ->
  {ok, Pid :: pid()} | ignore | {error, Reason :: term()}.
start_link(#{name := undefined} = Connection, Client) ->
  gen_statem:start_link(?MODULE, {Connection, Client}, []);
start_link(Connection, Client) ->
  Name = name(Connection),
  gen_statem:start_link({local, Name}, ?MODULE, {Connection, Client}, []).

%% @doc Builds a connection() map from the environment variables.
-spec default_connection(type(), name()) -> connection().
default_connection(token, ConnectionName) ->
  Env = application:get_env(apns, env, development),
  Timeout = application:get_env(apns, timeout, 5000),

  {ok, PrivKey} = application:get_env(apns, token_keyfile),
  {ok, TokenID} = application:get_env(apns, token_kid),
  {ok, TeamID} = application:get_env(apns, team_id),

  #{ name       => ConnectionName
   , env        => Env
   , token_kid  => list_to_binary(TokenID)
   , team_id    => list_to_binary(TeamID)
   , token_file => PrivKey
   , jwt_token  => <<"">>
   , jwt_iat    => 0
   , timeout    => Timeout
   , type       => token
  }.

%% @doc Close the connection with APNs gracefully
-spec close_connection(name() | pid()) -> ok.
close_connection(ConnectionId) ->
  gen_statem:cast(ConnectionId, stop).

%% @doc Returns the gun's connection PID. This function is only used in tests.
-spec gun_pid(name() | pid()) -> pid().
gun_pid(ConnectionId) ->
  gen_statem:call(ConnectionId, gun_pid).

%% @doc Pushes notification to certificate APNs connection.
-spec push_notification( name() | pid()
                       , apns:device_id()
                       , notification()
                       , apns:headers()) -> apns:response() | {error, not_connection_owner}.
push_notification(ConnectionId, DeviceId, Notification, Headers) ->
  gen_statem:call(ConnectionId, {push_notification, DeviceId, Notification, Headers}).
%% @doc Waits until the APNS connection is up.
%%
%% Note that this function does not need to be called before
%% sending push notifications, since they will be queued up
%% and sent when the connection is established.
-spec wait_apns_connection_up(pid()) -> ok.
wait_apns_connection_up(Server) ->
  gen_statem:call(Server, wait_apns_connection_up, infinity).

%%%===================================================================
%%% gen_statem callbacks
%%%===================================================================

-spec callback_mode() -> state_functions.
callback_mode() -> state_functions.

-spec init({connection(), pid()})
  -> { ok
     , open_origin
     , State :: state()
     , {next_event, internal, init}
     }.
init({Connection, Client}) ->
  StateData = #{ connection      => Connection
               , client          => Client
               , gun_streams     => #{}
               , max_gun_streams => 1
               , backoff         => 1
               , backoff_ceiling => application:get_env(apns, backoff_ceiling, 10)
               },
  {ok, open_origin, StateData,
    {next_event, internal, init}}.

-spec open_origin(_, _, _) -> _.
open_origin(internal, _, #{connection := Connection} = StateData) ->
  Host = host(Connection),
  Port = port(Connection),
  TlsOpts = tls_opts(Connection),
  Http2Opts = http2_opts(),
  {next_state, open_common, StateData,
    {next_event, internal, { Host
                           , Port
                           , #{ protocols      => [http2]
                              , http2_opts     => Http2Opts
                              , tls_opts       => TlsOpts
                              , retry          => 0
                              }}}}.

%% This function exists only to make Elvis happy.
%% I do not think it makes things any easier to read.
-spec open_common(_, _, _) -> _.
open_common(internal, {Host, Port, Opts}, StateData) ->
  {ok, GunPid} = gun:open(Host, Port, Opts),
  GunMon = monitor(process, GunPid),
  {next_state, await_up,
    StateData#{gun_pid => GunPid, gun_monitor => GunMon},
    {state_timeout, 15000, open_timeout}}.

-spec await_up(_, _, _) -> _.
await_up(info, {gun_up, GunPid, http2}, #{gun_pid := GunPid} = StateData) ->
  {next_state, connected, StateData,
    {next_event, internal, on_connect}};
await_up(EventType, EventContent, StateData) ->
  handle_common(EventType, EventContent, ?FUNCTION_NAME, StateData, postpone).

-spec connected(_, _, _) -> _.
connected(internal, on_connect, #{client := Client}) ->
  Client ! {connection_up, self()},
  keep_state_and_data;
connected( {call, From}
         , {push_notification, DeviceId, Notification, Headers0}
         , StateData) ->
  #{ connection := Connection0
   , gun_pid := GunPid
   , gun_streams := Streams0
   , max_gun_streams := MaxStreams} = StateData,
  StreamAllowed = stream_allowed(maps:size(Streams0), MaxStreams),
  if
    not StreamAllowed ->
        {keep_state_and_data, {reply, From, {error, {overload, maps:size(Streams0), MaxStreams}}}};
    true ->
      #{timeout := Timeout} = Connection0,
      Connection = verify_token(Connection0),
      Headers = add_authorization_header(Headers0, auth_token(Connection0)),
      StreamRef = send_push(GunPid, DeviceId, Headers, Notification),
      Tmr = erlang:send_after(Timeout, self(), {timeout, GunPid, StreamRef}),
      StreamData = #{ from => From
                    , stream => StreamRef
                    , timer => Tmr
                    , status => 200 %% b4 we know real status
                    , headers => []
                    , body => <<>> },
      Streams1 = Streams0#{StreamRef => StreamData},
      {keep_state, StateData#{gun_streams => Streams1, connection => Connection}}
  end;
connected({call, From}, wait_apns_connection_up, _) ->
  {keep_state_and_data, {reply, From, ok}};
connected({call, From}, Event, _) when Event =/= gun_pid ->
  {keep_state_and_data, {reply, From, {error, bad_call}}};
connected( info
         , {gun_response, GunPid, StreamRef, fin, Status, Headers}
         , #{gun_pid := GunPid} = StateData0) ->
  %% got response without body
  #{gun_streams := Streams0} = StateData0,
  #{StreamRef := StreamData} = Streams0,
  #{from := From} = StreamData,
  Streams1 = maps:remove(StreamRef, Streams0),
  gun:cancel(GunPid, StreamRef), %% final response, closing stream
  gen_statem:reply(From, {Status, Headers, no_body}),
  {keep_state, StateData0#{gun_streams => Streams1}};
connected( info
         , {gun_response, GunPid, StreamRef, nofin, Status, Headers}
         , #{gun_pid := GunPid} = StateData0) ->
  %% update status & headers
  #{gun_streams := Streams0} = StateData0,
  #{StreamRef := StreamState0} = Streams0,
  StreamState1 = StreamState0#{status => Status, headers => Headers},
  Streams1 = Streams0#{StreamRef => StreamState1},
  {keep_state, StateData0#{gun_streams => Streams1}};
connected( info
         , {gun_data, GunPid, StreamRef, fin, Data}
         , #{gun_pid := GunPid} = StateData0) ->
  %% got data, finally
  #{gun_streams := Streams0} = StateData0,
  #{StreamRef := StreamData} = Streams0,
  #{from := From, status := Status, headers := H, body := B0} = StreamData,
  Streams1 = maps:remove(StreamRef, Streams0),
  gun:cancel(GunPid, StreamRef), %% final, closing stream
  gen_statem:reply(From, {Status, H, <<B0/binary, Data/binary>>}),
  {keep_state, StateData0#{gun_streams => Streams1}};
connected( info
         , {gun_data, GunPid, StreamRef, nofin, Data}
         , #{gun_pid := GunPid} = StateData0) ->
  %% add data to buffer, still waiting
  #{gun_streams := Streams0} = StateData0,
  #{StreamRef := StreamState0} = Streams0,
  #{body := B0} = StreamState0,
  StreamState1 = StreamState0#{body => <<B0/binary, Data/binary>>},
  Streams1 = Streams0#{StreamRef => StreamState1},
  {keep_state, StateData0#{gun_streams => Streams1}};
connected( info
         , {gun_error, GunPid, StreamRef, Reason}
         , #{gun_pid := GunPid} = StateData0) ->
  %% answering with error, remove entry
  #{gun_streams := Streams0} = StateData0,
  case maps:get(StreamRef, Streams0, null) of
    null ->
      %% nothing todo
      {keep_state, StateData0};
    StreamData ->
      #{from := From} = StreamData,
      gen_statem:reply(From, {error, Reason}),
      Streams1 = maps:remove(StreamRef, Streams0),
      gun:cancel(GunPid, StreamRef),
      {keep_state, StateData0#{gun_streams => Streams1}}
    end;
connected( info
         , {gun_error, GunPid, Reason}
         , #{gun_pid := GunPid} = StateData0) ->
  %% answer with error for all streams, remove all entries, going to reconnect
  #{gun_streams := Streams} = StateData0,
  spawn(apns_connection, reply_errors_and_cancel_timers, [Streams, Reason]),
  {next_state, down, StateData0#{gun_streams => #{}},
    {next_event, internal, {down, ?FUNCTION_NAME, Reason}}};
connected( info
         , {timeout, GunPid, StreamRef}
         , #{gun_pid := GunPid, gun_streams := Streams0} = StateData0) ->
  %% gun pid matches, we have to answer {error, timeout}
  case maps:find(StreamRef, Streams0) of
    {ok, StreamData} ->
      #{from := From} = StreamData,
      gen_statem:reply(From, {error, timeout}),
      Streams1 = maps:remove(StreamRef, Streams0),
      gun:cancel(GunPid, StreamRef),
      {keep_state, StateData0#{gun_streams => Streams1}};
    error ->
      %% cant find stream data by stream ref?
      %% may be just answered and removed,
      %% ignoring
      {keep_state, StateData0}
    end;
connected(info,
          {timeout, _GunPid, _StreamRef},
          StateData0) ->
  %% timeout from different connection?
  %% ignoring
  {keep_state, StateData0};
connected( info
         , {gun_notify, GunPid, settings_changed, Settings}
         , #{gun_pid := GunPid, max_gun_streams := MaxStreams0} = StateData0) ->
    %% settings received, if contains max_concurrent_streams, update it
    MaxStreams1 = maps:get(max_concurrent_streams, Settings, MaxStreams0),
    {keep_state, StateData0#{max_gun_streams => MaxStreams1}};
connected(EventType, EventContent, StateData) ->
  handle_common(EventType, EventContent, ?FUNCTION_NAME, StateData, drop).

-spec down(_, _, _) -> _.
down(internal
    , _
    , #{ gun_pid         := GunPid
       , gun_monitor     := GunMon
       , client          := Client
       , backoff         := Backoff
       , backoff_ceiling := Ceiling
       }) ->
  true = demonitor(GunMon, [flush]),
  gun:close(GunPid),
  Client ! {reconnecting, self()},
  Sleep = backoff(Backoff, Ceiling) * 1000,
  {keep_state_and_data, {state_timeout, Sleep, backoff}};
down(state_timeout, backoff, StateData) ->
  {next_state, open_origin, StateData,
    {next_event, internal, init}};
down(EventType, EventContent, StateData) ->
  handle_common(EventType, EventContent, ?FUNCTION_NAME, StateData, postpone).

-spec handle_common(_, _, _, _, _) -> _.
handle_common({call, From}, gun_pid, _, #{gun_pid := GunPid}, _) ->
  {keep_state_and_data, {reply, From, GunPid}};
handle_common(cast, stop, _, _, _) ->
  {stop, normal};
handle_common( info
             , {'DOWN', GunMon, process, GunPid, Reason}
             , StateName
             , #{gun_pid := GunPid, gun_monitor := GunMon} = StateData0
             , _) ->
  %% gun died, answering with errors, cleanup entries
  #{gun_streams := Streams} = StateData0,
  spawn(apns_connection, reply_errors_and_cancel_timers, [Streams, Reason]),
  {next_state, down, StateData0#{gun_streams => #{}},
    {next_event, internal, {down, StateName, Reason}}};
handle_common( state_timeout
             , EventContent
             , StateName
             , #{gun_pid := GunPid} = StateData
             , _) ->
  gun:close(GunPid),
  {next_state, down, StateData,
    {next_event, internal, {state_timeout, StateName, EventContent}}};
handle_common(_, _, _, _, postpone) ->
  {keep_state_and_data, postpone};
handle_common(_, _, _, _, drop) ->
  keep_state_and_data.

-spec code_change(OldVsn :: term() | {down, term()}
                 , StateName
                 , StateData
                 , Extra :: term()
                 ) -> {ok, StateName, StateData}.
code_change(_OldVsn, StateName, StateData, _Extra) ->
  {ok, StateName, StateData}.

%%%===================================================================
%%% Connection getters/setters Functions
%%%===================================================================
verify_token(#{jwt_token := <<"">>} = Connection) ->
  update_token(Connection);
verify_token(#{jwt_iat := Iat} = Connection) ->
  Now = apns_utils:epoch(),
  if (Now - Iat - 3500) > 0 -> update_token(Connection);
     true -> Connection
  end.

update_token(#{token_kid := KeyId,
               team_id := TeamId,
               token_file := PrivKey} = Connection) ->
  Iat = apns_utils:epoch(),
  Token = apns_utils:generate_token(KeyId, TeamId, PrivKey, Iat),
  Connection#{jwt_token => Token, jwt_iat => Iat}.

-spec name(connection()) -> name().
name(#{name := ConnectionName}) ->
  ConnectionName.

-spec host(connection()) -> host().
host(#{env := development}) ->
  "api.development.push.apple.com";
host(_) ->
  "api.push.apple.com".

-spec port(connection()) -> inet:port_number().
port(_) -> 443.

-spec keyfile(connection()) -> path().
keyfile(#{keyfile := Keyfile}) ->
  Keyfile.

-spec type(connection()) -> type().
type(#{type := Type}) ->
  Type.

tls_opts(_) ->
  % CaCertFile = filename:join([code:priv_dir(apns), "GeoTrust_Global_CA.pem"]),
    [{server_name_indication, disable},
     {crl_check, false},
     {verify, verify_none}].

http2_opts() ->
      %% we need to know settings (from APN server), gun expects map
      #{notify_settings_changed => true}.

%%%===================================================================
%%% Internal Functions
%%%===================================================================

-spec(stream_allowed(StreamsCount :: non_neg_integer(),
                     MaxStreams :: non_neg_integer() | infinity) ->
    boolean()).
stream_allowed(_StreamsCount, infinity) -> true;
stream_allowed(StreamsCount, MaxStreams) ->
  StreamsCount < MaxStreams.


-spec get_headers(apns:headers()) -> list().
get_headers(Headers) ->
  List = [ {<<"apns-id">>, apns_id}
         , {<<"apns-expiration">>, apns_expiration}
         , {<<"apns-priority">>, apns_priority}
         , {<<"apns-topic">>, apns_topic}
         , {<<"apns-collapse-id">>, apns_collapse_id}
         , {<<"apns-push-type">>, apns_push_type}
         , {<<"authorization">>, apns_auth_token}
         ],
  F = fun({ActualHeader, Key}) ->
    case maps:find(Key, Headers) of
      error -> [];
      {ok, Value} -> [{ActualHeader, Value}]
    end
  end,
  lists:flatmap(F, List).

-spec get_device_path(apns:device_id()) -> binary().
get_device_path(DeviceId) ->
  <<"/3/device/", DeviceId/binary>>.

-spec auth_token(connection()) -> binary().
auth_token(#{jwt_token := Token}) ->
  Token.

-spec add_authorization_header(apns:headers(), apns:token()) -> apns:headers().
add_authorization_header(Headers, Token) ->
  Headers#{apns_auth_token => <<"bearer ", Token/binary>>}.

-spec send_push(pid(), apns:device_id(), apns:headers(), notification()) ->
  gun:stream_ref().
send_push(GunPid, DeviceId, HeadersMap, Notification) ->
  Headers = get_headers(HeadersMap),
  Path = get_device_path(DeviceId),
  gun:post(GunPid, Path, Headers, Notification).

-spec backoff(non_neg_integer(), non_neg_integer()) -> non_neg_integer().
backoff(N, Ceiling) ->
  case (math:pow(2, N) - 1) of
    R when R > Ceiling ->
      Ceiling;
    NextN ->
      NString = float_to_list(NextN, [{decimals, 0}]),
      list_to_integer(NString)
  end.

%%%===================================================================
%%% spawn/3 functions
%%%===================================================================
-spec reply_errors_and_cancel_timers(map(), term()) -> ok.
reply_errors_and_cancel_timers(Streams, Reason) ->
  [reply_error_and_cancel_timer(From, Reason, Tmr) ||
    #{from := From, timer := Tmr} <- maps:values(Streams)],
  ok.

-spec reply_error_and_cancel_timer(From :: {pid(), term()}, Reason :: term(),
                                   Tmr :: reference()) -> ok.
reply_error_and_cancel_timer(From, Reason, Tmr) ->
    erlang:cancel_timer(Tmr),
    gen_statem:reply(From, {error, Reason}).