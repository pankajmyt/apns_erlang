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

-include_lib("public_key/include/public_key.hrl").

% API
-export([ epoch/0
        , encode_json/1
        , decode_json/1
        , generate_token/4
        ]).


%%%===================================================================
%%% API
%%%===================================================================

urlencode_digit($/) -> $_;
urlencode_digit($+) -> $-;
urlencode_digit(D)  -> D.

base64_encode(Data) ->
  Data1 = base64_encode_strip(lists:reverse(base64:encode_to_string(Data))),
  << << (urlencode_digit(D)) >> || <<D>> <= Data1 >>.
base64_encode_strip([$=|Rest]) ->
  base64_encode_strip(Rest);
base64_encode_strip(Result) ->
  list_to_binary(lists:reverse(Result)).

generate_token(KeyId, TeamId, PrivKey, Iat) ->

  Header = base64_encode(encode_json(#{alg => <<"ES256">>, kid => KeyId})),
  Payload = base64_encode(encode_json(#{iss => TeamId, iat => Iat})),

  {ok, FileData} = file:read_file(PrivKey),

  ECPrivateKeyPem1 = case public_key:pem_decode(FileData) of
    [_, ECPrivateKeyPem] -> ECPrivateKeyPem;
    [ECPrivateKeyPem] -> ECPrivateKeyPem
  end,

  ECPrivateKey = public_key:pem_entry_decode(ECPrivateKeyPem1),
  
  Input = <<Header/binary, ".", Payload/binary>>,

  Signature = base64_encode(public_key:sign(Input, sha256, ECPrivateKey)),

  <<Input/binary, ".", Signature/binary>>.

encode_json(Data) ->
  iolist_to_binary(json:encode(Data)).

decode_json(Binary) ->
  json:decode(Binary).

%% Retrieves the epoch date.
-spec epoch() -> integer().
epoch() ->
  {M, S, _} = os:timestamp(),
  M * 1000000 + S.
