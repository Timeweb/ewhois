-module(ewhois).

-export([query/1]).
-export([query/2]).
-export([is_available/1]).
-export([is_available/2]).

-define(IANAHOST, "whois.iana.org").
-define(TIMEOUT, 15000).
-define(PORT, 43).
-define(OPTS, [{port, ?PORT}, {timeout, ?TIMEOUT}]).

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
        {ok, true} -> true;
        {ok, false} -> false;
        {error, Other} ->
            lager:error(Other),
            {error, eurodns_bad_response}
    end;
is_available(Domain, _) ->
    RawData = query(Domain, [raw]),
    Patterns = free_patterns(),
    CheckFun = fun(Pattern) ->
        case re:run(RawData, Pattern, [{capture, none}]) of
            match ->
                true;
            nomatch ->
                false
        end
    end,
    LimitPatterns = limit_patterns(),
    LimitResult = lists:map(CheckFun, LimitPatterns),
    case lists:member(true, LimitResult) of
        true ->
            limit_exceeded;
        false ->
            Result = lists:map(CheckFun, Patterns),
            lists:member(true, Result)
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
            ok = gen_tcp:send(Sock, iolist_to_binary([Domain, <<"\r\n">>])),
            Reply = recv(Sock),
            ok = gen_tcp:close(Sock),
            {ok, Reply};
        {error, Reason} ->
            {error, Reason}
    end.

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
    case get_nic(Domain, defined_nics()) of
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


% TODO: move it to config file
defined_nics() ->
    [
        {"whois.r01.ru", <<"^(.*)+.(org|net|com|msk|spb|nov|sochi).ru$">>},
        {"whois.nic.fm", <<"^(.*)+fm">>},
        {"mn.whois-servers.net", <<"^(.*)+mn">>},
        {"whois.belizenic.bz", <<"^(.*)+bz">>}
    ].


free_patterns() ->
    [
        "No entries found for the selected",
        "No match for",
        "NOT FOUND",
        "Not found:",
        "No match",
        "not found in database",
        "Nothing found for this query",
        "Status: AVAILABLE",
        "Status:\tAVAILABLE",
        "Status: Not Registered",
        "NOT FOUND",
        "Whois Error: No Match for", %% .bz
        "Can't get information on non-local domain" %% tucows
    ].

limit_patterns() ->
    [
        "Lookup quota exceeded"
    ].