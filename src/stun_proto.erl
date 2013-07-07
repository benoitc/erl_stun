-module(stun_proto).

-export([make_message/4]).
-export([decode/1,
         encode/1]).

-include("stun.hrl").

make_message(Method, Class, TransactionId, Attrs) ->
    #stun{method = Method,
          class = Class,
          transaction_id = TransactionId,
          attrs=Attrs}.

decode(<< 0:2, Type:14, Len:16, Magic:32, TransactionId:96,
         Body:Len/binary, Tail/binary >>) ->
    decode(Type, Magic, TransactionId, Body, Tail);
decode(<< 0:2, _/binary >>) -> more;
decode(<<>>) -> {error, empty};
decode(_) -> {error, no_stun_msg}.

encode(#stun{method=Method, class=Class, magic=Magic,
             transaction_id=TransactionId, attrs=Attrs}=Msg) ->
    Type = stun_type(Class, Method),
    EncodedAttrs = encode_attrs(Attrs, Msg, []),
    Len = byte_size(EncodedAttrs),
    << 0:2, Type:14, Len:16, Magic:32, TransactionId:96,
      EncodedAttrs/binary >>.


decode(Type, Magic, TransactionId, Body, Tail) ->
    Method = stun_method(Type),
    Class = stun_class(Type),

    case decode_attrs(Body, #stun{method=Method,
                                  class=Class,
                                  magic=Magic,
                                  transaction_id=TransactionId,
                                  attrs=[]}) of
        {ok, Msg} ->
            {ok, Msg, Tail};
        Error ->
            Error
    end.

encode_attrs([], _, Acc) ->
    iolist_to_binary(lists:reverse(Acc));
encode_attrs([{'MAPPED-ADDRESS', Addr} | Rest], Msg, Acc) ->
    Attr = encode_attr(1, encode_addr(Addr)),
    encode_attrs(Rest, Msg, [Attr | Acc]);
encode_attrs([{'USERNAME', Val} | Rest], Msg, Acc) ->
    encode_attrs(Rest, Msg, [encode_attr(6, Val) | Acc]);
encode_attrs([{'ERROR-CODE', {Code, Reason}} | Rest], Msg, Acc) ->
    Class = Code div 100,
    Num = Code rem 100,
    ErrorBin = <<0:21, Class:3, Num:8, Reason/binary>>,
    encode_attrs(Rest, Msg, [encode_attr(9, ErrorBin) | Acc]);
encode_attrs([{'UNKNOWN-ATTRIBUTES', Attrs} | Rest], Msg, Acc) ->
    AttrsBin = iolist_to_binary([<<Attr:16>> || Attr <- Attrs]),
    encode_attrs(Rest, Msg, [encode_attr(10, AttrsBin) | Acc]);
encode_attrs([{'REALM', Val} | Rest], Msg, Acc) ->
    encode_attrs(Rest, Msg, [encode_attr(20, Val) | Acc]);
encode_attrs([{'NONCE', Val} | Rest], Msg, Acc) ->
    encode_attrs(Rest, Msg, [encode_attr(21, Val) | Acc]);
encode_attrs([{'XOR-MAPPED-ADDRESS', Addr} | Rest], Msg, Acc) ->
    Attr = encode_attr(32, encode_xor_addr(Addr, Msg)),
    encode_attrs(Rest, Msg, [Attr | Acc]);
encode_attrs([{'SOFTWARE', Val} | Rest], Msg, Acc) ->
    encode_attrs(Rest, Msg, [encode_attr(32802, Val) | Acc]);
encode_attrs([{'ALTERNATE-SERVER', Addr} | Rest], Msg, Acc) ->
    Attr = encode_attr(32803, encode_addr(Addr)),
    encode_attrs(Rest, Msg, [Attr | Acc]);
encode_attrs([_ | Rest], Msg, Acc) ->
    encode_attrs(Rest, Msg, Acc).

encode_attr(Type, Val) ->
    Len = byte_size(Val),
    Padding = padding(Len),
    << Type:16, Len:16, Val/binary, 0:Padding >>.

encode_addr({{A1, A2, A3, A4}, Port}) ->
    << 0, 1, Port:16, A1, A2, A3, A4 >>;

encode_addr({{A1, A2, A3, A4, A5, A6, A7, A8}, Port}) ->
    << 0, 2, Port:16, A1:16, A2:16, A3:16, A4:16, A5:16,  A6:16, A7:16,
      A8:16 >>.

encode_xor_addr({{A1, A2, A3, A4}, Port}, #stun{magic=Magic}) ->
    XorPort = Port bxor (Magic bsr 16),
    <<Addr:32>> = << A1, A2, A3, A4 >>,
    XorAddr = Addr bxor Magic,
    << 0, 1, XorPort:16, XorAddr:32 >>;

encode_xor_addr({{A1, A2, A3, A4, A5, A6, A7, A8}, Port},
                #stun{magic=Magic, transaction_id=TransactionId}) ->
    XorPort = Port bxor (Magic bsr 16),
    <<Addr:128>> = <<  A1:16, A2:16, A3:16, A4:16, A5:16,  A6:16, A7:16,
                     A8:16 >>,
    XorAddr = Addr bxor (Magic bsl 96 bor TransactionId),
    << 0, 2, XorPort:16, XorAddr:128 >>;
encode_xor_addr(_, _) ->
    <<>>.
%%
%% decode functions
%%

decode_attrs(<<>>, Msg) ->
    {ok, Msg};
decode_attrs(<< Type:16, Len:16, Rest/binary >>, Msg) ->
    Padding = padding(Len),
    << Val:Len/binary, _:Padding, Tail/binary >> = Rest,
    decode_attr(Type, Val, Tail, Msg).



%% mapped address
decode_attr(1, << _, Familly, Port:16, Addr/binary >>, Tail,
            #stun{attrs=Attrs}=Msg) ->
    Ip = decode_addr(Familly, Addr),
    decode_attrs(Tail, Msg#stun{attrs=[{'MAPPED-ADDRESS', {Ip, Port}}
                                          |Attrs]});

%% USERNAME key
decode_attr(6, Val, Tail, #stun{attrs=Attrs}=Msg) ->
    decode_attrs(Tail, Msg#stun{attrs=[{'USERNANE', Val} | Attrs]});

%% MESSAGE integrity key
decode_attr(8, Val, Tail, #stun{attrs=Attrs}=Msg) ->
    decode_attrs(Tail, Msg#stun{attrs=[{'MESSAGE_INTEGRITY', Val} |
                                       Attrs]});

%% ERROR CODE
decode_attr(9, <<_:21, Class:3, Number:8, Reason/binary>> , Tail,
            #stun{attrs=Attrs}=Msg) ->

    if Class >= 3, Class =< 6, Number >= 0, Number =< 99 ->
            Code = Class * 100 + Number,
            decode_attrs(Tail, Msg#stun{attrs=[{'ERROR-CODE', {Code, Reason}}
                                                  | Attrs]});
        true ->
            {error, bad_attr}
    end;

decode_attr(10, Val, Tail, #stun{attrs=Attrs}=Msg) ->
    case decode_unknown_attrs(Val, []) of
        {error, _}=Error -> Error;
        UnknownAttrs ->
            decode_attrs(Tail, Msg#stun{attrs=[{'UNKNOWN-ATTRIBUTES',
                                                   UnknownAttrs} |
                                                  Attrs]})
    end;

%% REALM key
decode_attr(20, Val, Tail, #stun{attrs=Attrs}=Msg) ->
    decode_attrs(Tail, Msg#stun{attrs=[{'REALM', Val} | Attrs]});

%% REALM key
decode_attr(21, Val, Tail, #stun{attrs=Attrs}=Msg) ->
    decode_attrs(Tail, Msg#stun{attrs=[{'NONCE', Val} | Attrs]});

%% xor mapped address
decode_attr(32, <<_, Family, Port:16, XorAddr/binary>>, Tail,
            #stun{attrs=Attrs}=Msg) ->
    Ip = decode_xor_addr(Family, XorAddr, Msg),
    decode_attrs(Tail, Msg#stun{attrs=[{'XOR-MAPPED-ADDRESS', {Ip, Port}}
                                          |Attrs]});

%% SOFTWARE key
decode_attr(32802, Val, Tail, #stun{attrs=Attrs}=Msg) ->
    Val1 = iolist_to_binary(binary_to_list(Val)),

    decode_attrs(Tail, Msg#stun{attrs=[{'SOFTWARE', Val1} | Attrs]});


%% Alternate server
decode_attr(32803, <<_, Family, Port:16, Addr/binary>>, Tail,
            #stun{attrs=Attrs}=Msg) ->
    Ip = decode_addr(Family, Addr),
    decode_attrs(Tail, Msg#stun{attrs=[{'ALTERNATE_SERVER', {Ip,  Port}}
                                          | Attrs]});

%% FINGERPRINT
decode_attr(32808, Val, Tail, #stun{attrs=Attrs}=Msg) ->
    decode_attrs(Tail, Msg#stun{attrs=[{'FINGERPRINT', Val} | Attrs]});

decode_attr(Type, _Val, _Tail, _Msg)
        when Type =:= 1 orelse Type =:= 10 orelse Type =:= 32803 ->
    {error, bad_attr};

decode_attr(_Type, _Val, Tail, Msg) ->
    decode_attrs(Tail, Msg).

stun_method(Type) ->
    Type band 15872 bsr 2 bor (Type band 224 bsr 1) bor Type band 15.

stun_class(Type) ->
    Class = Type band 256 bsr 7 bor (Type band 16 bsr 4),
    case Class of
        0 -> request;
        1 -> indication;
        2 -> response;
        3 -> response_error
    end.

stun_type(Class, Method) when is_atom(Class) ->
    Class1 = case Class of
        request -> 0;
        indication -> 1;
        response -> 2;
        response_error -> 3
    end,
    stun_type(Class1, Method);
stun_type(Class, Method) ->
    Method band 3968 bsl 2 bor (Method band 112 bsl 1) bor Method band
    15 bor (Class band 2 bsl 7 bor (Class band 1 bsl 4)).

decode_addr(1, <<A1, A2, A3, A4>>) ->
    {A1, A2, A3, A4};
decode_addr(2,  <<A1:16, A2:16, A3:16, A4:16, A5:16, A6:16, A7:16,
                     A8:16>>) ->
    {A1, A2, A3, A4, A5, A6, A7, A8}.

decode_xor_addr(1, <<XorAddr:32>>, #stun{magic=Magic}) ->
    Addr = XorAddr bxor Magic,
    decode_addr(1, <<Addr:32>>);
decode_xor_addr(2, <<XorAddr:128>>, #stun{magic=Magic,
                                          transaction_id=TransactionId}) ->
    Addr = XorAddr bxor (Magic bsl 96 bor TransactionId),
    decode_addr(2, <<Addr:128>>).

decode_unknown_attrs(<<Attr:16, Tail/binary>>, Acc) ->
    decode_unknown_attrs(Tail, [Attr | Acc]);
decode_unknown_attrs(<<>>, Acc) -> lists:reverse(Acc);
decode_unknown_attrs(_, _) -> {error, bad_attr}.

-ifdef(STUN_RFC_3489).
padding(_Len) -> 0.).
-else.
padding(Len) ->
    case Len rem 4 of
        0 -> 0;
        N -> 8 * (4 - N)
    end.
-endif.
