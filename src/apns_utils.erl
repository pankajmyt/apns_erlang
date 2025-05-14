%%% @doc Contains util functions.
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
-module(apns_utils).
-author("Felipe Ripoll <felipe@inakanetworks.com>").

% API
-export([ sign/2
        , epoch/0
        , encode_json/1
        , decode_json/1
        , generate_token/4
        ]).


%%%===================================================================
%%% API
%%%===================================================================
generate_token(KeyId, TeamId, PrivKey, Iat) ->
  Algorithm = <<"ES256">>,

  Header = encode_json(#{alg => Algorithm, kid => KeyId}),
  Payload = encode_json(#{iss => TeamId, iat => Iat}),

  HeaderEncoded = base64:encode(Header, #{padding => false, mode => urlsafe}),
  PayloadEncoded = base64:encode(Payload, #{padding => false, mode => urlsafe}),
  
  DataEncoded = <<HeaderEncoded/binary, $., PayloadEncoded/binary>>,
  Signature = sign(DataEncoded, PrivKey),
  <<DataEncoded/binary, $., Signature/binary>>.

%% Signs the given binary.
-spec sign(binary(), string()) -> binary().
sign(Data, KeyPath) ->
  Command = "printf '" ++
            binary_to_list(Data) ++
            "' | openssl dgst -binary -sha256 -sign " ++ KeyPath ++ " | base64",
  {0, Result} = apns_os:cmd(Command),
  strip_b64(list_to_binary(Result)).

encode_json(Data) ->
  iolist_to_binary(json:encode(Data)).

decode_json(Binary) ->
  json:decode(Binary).

%% Retrieves the epoch date.
-spec epoch() -> integer().
epoch() ->
  {M, S, _} = os:timestamp(),
  M * 1000000 + S.

%% Remove newline and equality characters
-spec strip_b64(binary()) -> binary().
strip_b64(BS) ->
  binary:list_to_bin(binary:split(BS, [<<"\n">>, <<"=">>], [global])).
