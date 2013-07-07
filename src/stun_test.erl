-module(stun_test).

-export([public_test/0]).

bind_msg() ->
    Msg = stun_proto:make_message(1, request,
                                  random:uniform(1 bsl 96),
                                  [{'SOFTWARE', <<"test">>}]),
    stun_proto:encode(Msg).

do_test_udp(Addr, Port) -> do_test(Addr, Port, gen_udp).

do_test_tcp(Addr, Port) -> do_test(Addr, Port, gen_tcp).

do_test_tls(Addr, Port) -> do_test(Addr, Port, ssl).

do_test(Addr, Port, Mod) ->
    Res = case Mod of
	    gen_udp -> Mod:open(0, [binary, {active, false}]);
	    _ ->
		Mod:connect(Addr, Port, [binary, {active, false}], 1000)
	  end,
    case Res of
      {ok, Sock} ->
	  if Mod == gen_udp ->
		 Mod:send(Sock, Addr, Port, bind_msg());
	     true -> Mod:send(Sock, bind_msg())
	  end,
	  case Mod:recv(Sock, 0, 5000) of
	    {ok, {_, _, Data}} -> try_dec(Data);
	    {ok, Data} -> try_dec(Data);
	    Err -> io:format("err: ~p~n", [Err])
	  end,
	  Mod:close(Sock);
      Err -> io:format("err: ~p~n", [Err])
    end.

try_dec(Data) ->
    case stun_proto:decode(Data) of
      {ok, Msg, _} -> io:format("got:~n~p~n", [Msg]);
      Err -> io:format("err: ~p~n", [Err])
    end.

public_servers() ->
    [
    {"stun.l.google.com", 19302, 3478, 5349},
    {"stun1.l.google.com", 19302, 3478, 5349},
    {"stun2.l.google.com", 19302, 3478, 5349},
    {"stun3.l.google.com", 19302, 3478, 5349},
    {"stun4.l.google.com", 19302, 3478, 5349},

        {"stun.ekiga.net", 3478, 3478, 5349},
     {"stun.ideasip.com", 3478, 3478, 5349},
     {"stun.softjoys.com", 3478, 3478, 5349},
     {"stun.voipbuster.com", 3478, 3478, 5349},
     {"stun.voxgratia.org", 3478, 3478, 5349},
     {"stunserver.org", 3478, 3478, 5349},
     {"stun.sipgate.net", 10000, 10000, 5349},
     {"numb.viagenie.ca", 3478, 3478, 5349},
     {"stun.ipshka.com", 3478, 3478, 5349}].

public_test() ->
    ssl:start(),
    lists:foreach(fun ({Addr, UDPPort, TCPPort, TLSPort}) ->
			  io:format("trying ~s:~p on UDP... ", [Addr, UDPPort]),
			  do_test_udp(Addr, UDPPort),
			  io:format("trying ~s:~p on TCP... ", [Addr, TCPPort]),
			  do_test_tcp(Addr, TCPPort),
			  io:format("trying ~s:~p on TLS... ", [Addr, TLSPort]),
			  do_test_tls(Addr, TLSPort)
		  end,
		  public_servers()).
