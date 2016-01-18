%%%-------------------------------------------------------------------
%%% @author psw
%%% @copyright (C) 2016, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 18. 1월 2016 오후 3:54
%%%-------------------------------------------------------------------
-module(emqttd_tw).
-author("psw").
-include("emqttd.hrl").

-include("emqttd_protocol.hrl").
%% API
-export([publish_internal/5]).

validate(qos, Qos) ->
  (Qos >= ?QOS_0) and (Qos =< ?QOS_2);

validate(topic, Topic) ->
  emqttd_topic:validate({name, Topic}).

publish_internal(ClientId, Qos, Retain, Topic, Message) ->
  Payload = Message,
  case {validate(qos, Qos), validate(topic, Topic)} of
    {true, true} ->
      Msg = emqttd_message:make(ClientId, Qos, Topic, Payload),
      emqttd_pubsub:publish(Msg#mqtt_message{retain = Retain}),
      {ok, 0};
    {false, _} ->
      {fail, "BAD QOS"};
    {_, false} ->
      {fail, "BAD TOPIC"}
  end.