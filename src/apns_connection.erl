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

-include("apns.hrl").

%% API
-export([ start_link/2
        , default_connection/2
        , new_apns_id/0
        , name/1
        , host/1
        , port/1
        , keyfile/1
        , type/1
        , gun_pid/1
        , close_connection/1
        , push_notification/4
        , wait_apns_connection_up/1
        , generate_token/4
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
-type env()          :: development | production.
-type path()         :: string().
-type notification() :: binary().
-type type()         :: token.
-type connection()   :: #{ name       := name()
                         , env        := env()
                         , apple_port := inet:port_number()
                         , keyfile    => path()
                         , timeout    => integer()
                         }.

-type state()        :: #{ connection      := connection()
                         , gun_pid         => pid()
                         , gun_monitor     => reference()
                         , gun_connect_ref => reference()
                         , client          := pid()
                         , backoff         := non_neg_integer()
                         , backoff_ceiling := non_neg_integer()
                         }.

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
  Port = application:get_env(apns, apple_port, 443),
  Timeout = application:get_env(apns, timeout, 5000),
  FeedBack = application:get_env(apns, feedback, undefined),

  {ok, PrivKey} = application:get_env(apns, token_keyfile),
  {ok, TokenID} = application:get_env(apns, token_kid),
  {ok, TeamID} = application:get_env(apns, team_id),
  
  #{ name       => ConnectionName
   , env        => Env
   , apple_port => Port
   , token_kid  => list_to_binary(TokenID)
   , team_id    => list_to_binary(TeamID)
   , token_file => PrivKey
   , jwt_token  => <<"">>
   , jwt_iat    => 0
   , timeout    => Timeout
   , feedback   => FeedBack
  }.

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
  Token = generate_token(KeyId, TeamId, PrivKey, Iat),
  Connection#{jwt_token => Token, jwt_iat => Iat}.

generate_token(KeyId, TeamId, PrivKey, Iat) ->
  Algorithm = <<"ES256">>,

  Header = apns_utils:encode_json([ {alg, Algorithm}, {kid, KeyId} ]),
  Payload = apns_utils:encode_json([ {iss, TeamId}, {iat, Iat} ]),

  HeaderEncoded = base64:encode(Header, #{padding => false, mode => urlsafe}),
  PayloadEncoded = base64:encode(Payload, #{padding => false, mode => urlsafe}),
  
  DataEncoded = <<HeaderEncoded/binary, $., PayloadEncoded/binary>>,
  Signature = apns_utils:sign(DataEncoded, PrivKey),
  <<DataEncoded/binary, $., Signature/binary>>.

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
                       , apns:headers()) -> ok.
push_notification(ConnectionId, DeviceId, Notification, Headers) ->
  gen_statem:cast(ConnectionId, {push_notification, DeviceId, Notification, Headers}).

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
  quickrand:seed(),
  StateData = #{ connection      => Connection
               , client          => Client
               , backoff         => 1
               , backoff_ceiling => application:get_env(apns, backoff_ceiling, 10)
               },
  {ok, open_origin, StateData,
    {next_event, internal, init}}.

-spec open_origin(_, _, _) -> _.
open_origin(internal, _, #{connection := Connection} = StateData) ->
  Host = host(Connection),
  Port = port(Connection),
  TransportOpts = transport_opts(Connection),
  {next_state, open_common, StateData,
    {next_event, internal, { Host
                           , Port
                           , #{ protocols      => [http2]
                              , tls_opts       => TransportOpts
                              , retry          => 0
                              }}}}.

%% This function exists only to make Elvis happy.
%% I do not think it makes things any easier to read.
-spec open_common(_, _, _) -> _.
open_common(internal, {Host, Port, Opts}, StateData) ->
  ?DEBUG("open_common ~p~n", [{Host, Port, Opts}]),
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
connected({call, From}, wait_apns_connection_up, _) ->
  {keep_state_and_data, {reply, From, ok}};
connected({call, From}, Event, _) when Event =/= gun_pid ->
  {keep_state_and_data, {reply, From, {error, bad_call}}};

connected( cast
         , {push_notification, DeviceId, Notification, Headers}
         , StateData) ->

  #{connection := Connection, gun_pid := GunConn} = StateData,

  Conn = verify_token(Connection),
  Headers1 = add_authorization_header(Headers, auth_token(Conn)),
  Headers2 = case maps:get(apns_id, Headers1, undefined) of
    undefined ->
        Headers1#{apns_id => new_apns_id()};
    _ ->
        Headers1
  end,
    
  HdrsList = get_headers(Headers2),
  Path = get_device_path(DeviceId),
  _StreamRef = gun:post(GunConn, Path, HdrsList, Notification),

  StateData1 = StateData#{connection => Conn},
  {keep_state, StateData1};

connected( info
         , {gun_response, _, _, fin, Status, Headers}
         , StateData) ->
        
  % ApnsId = find_header_val(Headers, apns_id),
  
  ?DEBUG("apns_connection: response1: ~p~n", [{Status, Headers}]),  
  
  {keep_state, StateData};

connected( info
         , {gun_response, _, StreamRef, nofin, Status, Headers}
         , StateData) ->
  #{connection := Connection, gun_pid := GunConn} = StateData,
  #{name := Proc, timeout := Timeout, feedback := Feedback} = Connection,
  ApnsId = find_header_val(Headers, apns_id),

  case gun:await_body(GunConn, StreamRef, Timeout) of
      {ok, Body} ->
          ?DEBUG("apns_connection: response2: ~p~n", [{Status, Headers, ApnsId, Body, Feedback}]),
          case Feedback of
            {M, F} ->
              catch M:F(Proc, ApnsId, Status, decode_reason(Body));
            _ ->
              ok
          end;
      {error, Reason} ->
        ?ERROR_MSG("apns_connection: error reading body ~p~n", [{Status, Headers, Reason}])
  end,
  {keep_state, StateData};

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
             , #{gun_pid := GunPid, gun_monitor := GunMon} = StateData
             , _) ->
  {next_state, down, StateData,
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
decode_reason(<<"">>) -> <<"">>;
decode_reason(Body) -> 
  case catch apns_utils:decode_json(Body) of
    #{<<"reason">> := R} -> R;
    _ -> <<"">>
  end.

-spec name(connection()) -> name().
name(#{name := ConnectionName}) ->
  ConnectionName.

host(#{env := development}) ->
  "api.development.push.apple.com";
host(_) ->
  "api.push.apple.com".

-spec port(connection()) -> inet:port_number().
port(#{apple_port := Port}) ->
  Port.

-spec keyfile(connection()) -> path().
keyfile(#{keyfile := Keyfile}) ->
  Keyfile.

-spec auth_token(connection()) -> binary().
auth_token(#{jwt_token := Token}) ->
  Token.

new_apns_id() ->
  uuid:uuid_to_string(uuid:get_v4(), binary_standard).

type(_) -> token.

transport_opts(_) ->
    CaCertFile = filename:join([code:priv_dir(apns), "GeoTrust_Global_CA.pem"]),
    [{cacertfile, CaCertFile},
     {server_name_indication, disable},
     {crl_check, false},
     {verify, verify_none}].

%%%===================================================================
%%% Internal Functions
%%%===================================================================


-spec get_headers(apns:headers()) -> list().
get_headers(Headers) ->
  List = [ {<<"apns-id">>, apns_id, undefined}
         , {<<"apns-expiration">>, apns_expiration, <<"0">>}
         , {<<"apns-priority">>, apns_priority, <<"5">>}
         , {<<"apns-topic">>, apns_topic, undefined}
         , {<<"apns-push-type">>, apns_push_type, <<"alert">>}
         , {<<"apns-collapse-id">>, apns_collapse_id, undefined}
         , {<<"authorization">>, apns_auth_token, undefined}
         ],
  F = fun({ActualHeader, Key, Def}) ->
      case {Key, maps:get(Key, Headers, Def)} of
          {_, undefined} -> [];
          {_, Value} -> [{ActualHeader, Value}]
    end
  end,
  lists:flatmap(F, List).

find_header_val(Headers, apns_id) -> find_header_val(Headers, <<"apns-id">>);
find_header_val(Headers, apns_unique_id) -> find_header_val(Headers, <<"apns-unique-id">>);

find_header_val(Headers, Key) when is_list(Headers) ->
  case lists:keysearch(Key, 1, Headers) of
    {value, {_, Val}} -> Val;
    _ -> undefined
  end;
find_header_val(Headers, Key) when is_map(Headers) ->
  maps:get(Key, Headers, undefined).

-spec get_device_path(apns:device_id()) -> binary().
get_device_path(DeviceId) ->
  <<"/3/device/", DeviceId/binary>>.

-spec add_authorization_header(apns:headers(), apnd:token()) -> apns:headers().
add_authorization_header(Headers, Token) ->
  Headers#{apns_auth_token => <<"bearer ", Token/binary>>}.


-spec backoff(non_neg_integer(), non_neg_integer()) -> non_neg_integer().
backoff(N, Ceiling) ->
  case (math:pow(2, N) - 1) of
    R when R > Ceiling ->
      Ceiling;
    NextN ->
      NString = float_to_list(NextN, [{decimals, 0}]),
      list_to_integer(NString)
  end.
