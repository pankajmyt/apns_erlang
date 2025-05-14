
# Apns Erlang

Provider for Apple Push Notificaion services (APNs)

## Supports

- OTP 27
- Apns token key file based auth. For older auths look for version < 2.8.0

### How to run

- Clone into folder `apns`
- Edit config/sys.config & `make run`

### Add to project

You can use `apns_erlang` as a dependency in your rebar.config:

    {deps , [
        {apns, ".*", {git, "https://github.com/pankajsoni19/apns_erlang", {tag, "3.0.0"}}}
    ]}.

### Configure

In your sys.config file, add `apns` block.

```erlang
{
...
 {apns, [
   {env, development | production},
   {token_keyfile,    "p8 file path"},
   {token_kid,        "team_kid"},
   {team_id,          "team_id"},
   {feedback,         {Module, Function}},

   default_headers...
     ]},
 }
}
```

### How to use

```erlang

payload() ->
 #{
  aps => #{
   alert => #{
    title => <<"hi">>
   }
  }
 }.

default_headers() ->
 #{
  apns_id    => apns_connection:new_apns_id(),
  apns_expiration  => <<"0">>,
  apns_priority   => <<"10">>,
  apns_topic   => <<"app bundle id">>,
  apns_push_type  => <<"alert">>,
  apns_collapse_id => <<"collapse-key">>
 }.
apns:connect(token, ProcName).
{Status, Headers, no_body} | {Status, Headers, binary()} | { error, Reason} | {error, timeout}
= apns:push_notification(ProcName, DeviceId, payload(), default_headers()).
apns:close_connection(ProcName).
```

- Status -> [Apns Status Response Codes](https://developer.apple.com/documentation/usernotifications/handling-notification-responses-from-apns)
- Reason default -> <<"">> or `Error string` column from Status

### Links

- [handling-notification-responses-from-apns](https://developer.apple.com/documentation/usernotifications/handling-notification-responses-from-apns)

----

Copyright (c) 2017 Erlang Solutions Ltd. <support@inaka.net>, released under the Apache 2 license
