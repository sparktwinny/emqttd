%%%-----------------------------------------------------------------------------
%%% Copyright (c) 2012-2015 eMQTT.IO, All Rights Reserved.
%%%
%%% Permission is hereby granted, free of charge, to any person obtaining a copy
%%% of this software and associated documentation files (the "Software"), to deal
%%% in the Software without restriction, including without limitation the rights
%%% to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
%%% copies of the Software, and to permit persons to whom the Software is
%%% furnished to do so, subject to the following conditions:
%%%
%%% The above copyright notice and this permission notice shall be included in all
%%% copies or substantial portions of the Software.
%%%
%%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
%%% OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
%%% SOFTWARE.
%%%-----------------------------------------------------------------------------
%%% @doc Authentication with username and password
%%%
%%% @author Feng Lee <feng@emqtt.io>
%%%-----------------------------------------------------------------------------
-module(emqttd_auth_username).

-include("emqttd.hrl").

-include("emqttd_cli.hrl").

%% CLI callbacks
-export([cli/1]).

-behaviour(emqttd_auth_mod).

-export([add_user/2, remove_user/1,
    lookup_user/1, all_users/0]).

%% emqttd_auth callbacks
-export([init/1, check/3, description/0]).

-define(AUTH_USERNAME_TAB, mqtt_auth_username).

-record(?AUTH_USERNAME_TAB, {username, password}).

%%%=============================================================================
%%% CLI
%%%=============================================================================

cli(["add", Username, Password]) ->
    ?PRINT("~p~n", [add_user(list_to_binary(Username), list_to_binary(Password))]);

cli(["del", Username]) ->
    ?PRINT("~p~n", [remove_user(list_to_binary(Username))]);

cli(_) ->
    ?USAGE([{"users add <Username> <Password>", "add user"},
        {"users del <Username>", "delete user"}]).

%%%=============================================================================
%%% API
%%%=============================================================================

%%------------------------------------------------------------------------------
%% @doc Add user
%% @end
%%------------------------------------------------------------------------------
-spec add_user(binary(), binary()) -> {atomic, ok} | {aborted, any()}.
add_user(Username, Password) ->
    User = #?AUTH_USERNAME_TAB{username = Username, password = hash(Password)},
    mnesia:transaction(fun mnesia:write/1, [User]).

%%------------------------------------------------------------------------------
%% @doc Lookup user by username
%% @end
%%------------------------------------------------------------------------------
-spec lookup_user(binary()) -> list().
lookup_user(Username) ->
    mnesia:dirty_read(?AUTH_USERNAME_TAB, Username).

%%------------------------------------------------------------------------------
%% @doc Remove user
%% @end
%%------------------------------------------------------------------------------
-spec remove_user(binary()) -> {atomic, ok} | {aborted, any()}.
remove_user(Username) ->
    mnesia:transaction(fun mnesia:delete/1, [{?AUTH_USERNAME_TAB, Username}]).

%%------------------------------------------------------------------------------
%% @doc All usernames
%% @end
%%------------------------------------------------------------------------------
-spec all_users() -> list().
all_users() ->
    mnesia:dirty_all_keys(?AUTH_USERNAME_TAB).

%%%=============================================================================
%%% emqttd_auth callbacks
%%%=============================================================================
init(Opts) ->
    mnesia:create_table(?AUTH_USERNAME_TAB, [
        {disc_copies, [node()]},
        {attributes, record_info(fields, ?AUTH_USERNAME_TAB)}]),
    mnesia:add_table_copy(?AUTH_USERNAME_TAB, node(), disc_copies),
    emqttd_ctl:register_cmd(users, {?MODULE, cli}, []),
    {ok, Opts}.

check(#mqtt_client{username = undefined}, _Password, _Opts) ->
    {error, "Username undefined"};
check(_User, undefined, _Opts) ->
    {error, "Password undefined"};
check(Cli = #mqtt_client{username = UsernameT}, Password, _Opts) ->

    io:format("UserName:~p, Password:~p ~n", [UsernameT, Password]),

    <<H, T/binary>> = UsernameT,
    %%첫 문자가 '{' 즉 JSON의 첫 문자인지 확인한다. 물론 어쩌다 우연히 틀린 사이퍼를 해독해도
    %% '{' 가 나타날 일이 있지만 그래도 예외처리는 할 수 있기때문에 이것으로만 검증한다.
    Username = case H of
                   123 -> %% '{' 에 해당한다.
                       UsernameT;
                   _ ->


                       Crypt = tw_util:decode_web_safe_base64(UsernameT),
                       tw_crypto:decrypt_public_encrypted_message(Crypt)
                   %%                 catch
                   %%
                   %%
                   %%                   Er1:Error2 ->
                   %%
                   %%
                   %%                     lager:error("-------(!![Error while process:Er:~p,Error:~p,StackT1:~p]!!)-------", [tw_util:to_list(Er1), Error2, erlang:get_stacktrace()])
                   %%
                   %%                 end

               end,
    io:format("UserName after:~p~n", [Username]),
    Map = jsx:decode(Username, [return_maps]),
    io:format("map??:~p ~n", [Cli]),
    Type = binary_to_list(maps:get(<<"type">>, Map, <<"">>)),
    ForceLogin = binary_to_list(maps:get(<<"force_login">>, Map, <<"">>)),
    %%[aesKey]
    AesKey = binary_to_list(maps:get(<<"aes_key">>, Map, <<"">>)),


    DD = case emqttd_cm:lookup(tw_util:to_binary(Cli#mqtt_client.client_id)) of
             undefined -> ok;
             Client when ForceLogin =/= <<"true">> ->

                 {Peer, Port} = Client#mqtt_client.peername,
                 {Peer2, Port2} = Cli#mqtt_client.peername,
                 lager:info("Connnecting Peer::~p, EXISTPEER:~p ~n", [Cli#mqtt_client.peername,  Client#mqtt_client.peername]),
                 case Peer of
                     Peer2 -> duplicated;
                     _ -> ok
                 end
         end,


    Result = case Type of
                 "idpw" ->
                     UserId = binary_to_list(maps:get(<<"user_id">>, Map, undefined)),
                     %%[todo:나중에 여기서 암호를 받아오기]
                     %%Password = binary_to_list(maps:get(<<"password">>, Map, undefined)),
                     tw_user:mqttCheckByUserIdAndPassword(UserId, Password, Cli#mqtt_client.client_id);
                 "pndv" ->
                     DeviceId = binary_to_list(maps:get(<<"device_id">>, Map, undefined)),
                     PhoneNumber = binary_to_list(maps:get(<<"phone_number">>, Map, undefined)),
                     tw_user:mqttCheckByPhoneNumberAndDeviceId(PhoneNumber, DeviceId, Cli#mqtt_client.client_id);
                 _ ->

                     io:format("failed!"),
                     fail

             end,

    lager:info("UserName:~p, Password:~p ~n", [Username, Password]),
    lager:info("-------(<>[MQTT RESULT:~p]<>)-------", [Result]),
    case Result of
        fail ->
            case Type of
                "idpw" ->
                    io:format("id/pw check failed");
                "pndv" ->
                    io:format("phone/deviceId:check failed");
                _ ->
                    io:format("wrong type:~p ~n", [Type])

            end,
            {error, "Cannot find user"};

        _ ->
            try

                %%[aesKey]

                case AesKey of
                    undefined -> ok;
                    _ ->
                        HKey = tw_util:decode_web_safe_base64(tw_util:to_binary(AesKey)),
                        io:format("Insert AESKEY:~p,ClientID:~p~n", [AesKey, HKey]),
                        ets:insert(aes_key_list, {Cli#mqtt_client.client_id, HKey})
                end

            catch

                error:badarg ->


                    StackList = erlang:get_stacktrace(),


                    lager:error("-------(!![error:~p,arg:~p,StackT1:~p]!!)-------", [error, badarg, StackList]);
                Er:Error ->

                    StackList = erlang:get_stacktrace(),


                    lager:error("-------(!![Error while process:Er:~p,Error:~p,StackT1:~p]!!)-------", [tw_util:to_list(Er), Error, StackList])

            end,


            lager:info("DD:~p", [DD]),
            case DD of
                ok ->


                    ok;
                duplicated ->

                    io:format("ok!2~n"),
                    {error, "Duplicated ip"}
            end

    end.


description() ->
    "Username password authentication module".

%%%=============================================================================
%%% Internal functions
%%%=============================================================================

hash(Password) ->
    SaltBin = salt(),
    <<SaltBin/binary, (md5_hash(SaltBin, Password))/binary>>.

md5_hash(SaltBin, Password) ->
    erlang:md5(<<SaltBin/binary, Password/binary>>).

salt() ->
    {A1, A2, A3} = now(),
    random:seed(A1, A2, A3),
    Salt = random:uniform(16#ffffffff),
    <<Salt:32>>.

