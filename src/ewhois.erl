-module(ewhois).

-export([start/0]).
-export([query/1]).
-export([query/2]).
-export([is_available/1]).
-export([is_available/2]).

-define(IANAHOST, "whois.iana.org").
-define(TIMEOUT, 15000).
-define(PORT, 43).
-define(OPTS, [{port, ?PORT}, {timeout, ?TIMEOUT}]).

start() ->
    application:start(ewhois),
    load_config().

load_config() ->
    {ok, FileName} = application:get_env(ewhois, config),
    case file:consult(FileName) of
        {ok,[[{ewhois, Proplist}]]} ->
            [application:set_env(ewhois, Section, Config) || {Section, Config} <- Proplist],
            ok;
        Other ->
            Other
    end.

query(Domain) ->
    query(Domain, ?OPTS).

query(Domain, Opts) when is_binary(Domain), is_list(Opts) ->
    Nic = proplists:get_value(nic, Opts, get_nic(Domain)),
    case send_query(Domain, Nic, Opts) of
        {ok, Reply} ->
            response(Reply, Opts);
        {error, Reason} ->
            {error, Reason}
    end.


is_available(Domain) ->
    is_available(Domain, undefined).

is_available(Domain, eurodns) ->
    {ok, EuroDNSConf} = application:get_env(portal, eurodns),
    URL = proplists:get_value(url, EuroDNSConf),
    UserName = proplists:get_value(username, EuroDNSConf),
    Password = proplists:get_value(password, EuroDNSConf),
    Body = build_eurodns_request(Domain),
    Request = {URL, [basic_auth_header(UserName, Password)], "application/x-www-form-urlencoded", Body},
    {ok, {{"HTTP/1.1",200,"OK"}, _, Response}} = httpc:request(post, Request, [], []),
    case ewhois_parser:get_eurodns_domain_status(Response) of
        {ok, true} -> {ok, true};
        {ok, false} -> {ok, false};
        {error, "210"} ->
            {error, bad_domain_name};
        {error, Other} ->
            lager:error(Other),
            {error, eurodns_bad_response}
    end;
is_available(Domain, _) ->
    RawData = query(Domain, [raw]),
    Patterns = get_config(free_patterns),
    case check_pattern(limit_patterns(), RawData) of
        true ->
            {error, limit_exceeded};
        false ->
            case check_pattern(error_patterns(), RawData) of
                true ->
                    {error, bad_request};
                false ->
                    case check_pattern(Patterns, RawData) of
                        true ->
                            {ok, true};
                        false ->
                            {ok, false}
                    end
            end
    end.

check_pattern([], _RawData) ->
    false;
check_pattern([Pattern|Tail], RawData) ->
    case re:run(RawData, Pattern, [{capture, none}]) of
        match ->
            true;
        nomatch ->
            check_pattern(Tail, RawData)
    end.

build_eurodns_request(FQDN) ->
    %TODO urlencoded xml instead raw string
    lists:flatten(["xml=%3C%3Fxml+version%3D%221.0%22+encoding%3D%22UTF-8%22%3F%3E++%09%09%09%3Crequest+
xmlns%3Adomain%3D%22http%3A%2F%2Fwww.eurodns.com%2Fdomain%22%3E++%09%09%09%09%3Cdomain%3Acheck%3E++
%09%09%09%09%09%3Cdomain%3Aname%3E", binary_to_list(FQDN), "%3C%2Fdomain%3Aname%3E++%3C%2Fdomain%3Acheck%3E%3C%2Frequest%3E"]).

basic_auth_header(Username, Password) ->
    Hash = base64:encode(<<Username/binary, $:, Password/binary>>),
    {"Authorization", ["Basic ", binary_to_list(Hash)]}.

response(RawData, [raw | _T]) ->
    RawData;
response(RawData, [bind | _T]) ->
    ewhois_parser:bind(RawData);
response(RawData, _Opts) ->
    ewhois_parser:parse_vals(RawData).


send_query(Domain, Nic, Opts) when is_list(Nic) ->
    Port = proplists:get_value(port, Opts, ?PORT),
    Timeout = proplists:get_value(timeout, Opts, ?TIMEOUT),
    case gen_tcp:connect(Nic, Port, [binary, {active, false}, {packet, 0}, {send_timeout, Timeout}], Timeout) of
        {ok, Sock} ->
            ok = gen_tcp:send(Sock, build_whois_request(Nic, Domain)),
            Reply = recv(Sock),
            ok = gen_tcp:close(Sock),
            {ok, Reply};
        {error, Reason} ->
            {error, Reason}
    end.

build_whois_request("whois.online.rs.corenic.net", Domain) ->
    iolist_to_binary(["-C UTF-8 ", Domain, <<"\r\n">>]);
build_whois_request(_, Domain) ->
    iolist_to_binary([Domain, <<"\r\n">>]).

recv(Sock) ->
    recv(Sock, []).

recv(Sock, Acc) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, Data} ->
            recv(Sock, [Data | Acc]);
        {error, closed} ->
            iolist_to_binary(lists:reverse(Acc))
    end.


get_nic(Domain) ->
    case get_nic(Domain, get_config(providers)) of
        undefined ->
            get_root_nics(Domain);
        {ok, Nic} ->
            Nic
    end.

get_nic(_Domain, []) ->
    undefined;
get_nic(Domain, [{Nic, Re} | Nics]) ->
    case re:run(Domain, Re) of
        {match, _} ->
            {ok, Nic};
        nomatch ->
            get_nic(Domain, Nics)
    end.


get_root_nics(Domain) ->
    case send_query(Domain, ?IANAHOST, ?OPTS) of
        {ok, Result} ->
            case re:run(Result, <<"refer:\s+(.*)\n">>, [{capture, [1], binary}]) of
                {match, [Refer]} ->
                    binary_to_list(Refer);
                nomatch ->
                    ?IANAHOST
            end;
        {error, Reason} ->
            {error, Reason}
    end.

get_config(Section) ->
    {ok, Config} = application:get_env(ewhois, Section),
    Config.

limit_patterns() ->
    [
        "Lookup quota exceeded"
    ].


error_patterns() ->
    [
        "Error: Invalid query",
        "This name is not available for registration"
    ].