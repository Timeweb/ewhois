-module(ewhois).

-include_lib("ewhois/include/providers.hrl").

-export([query/1]).
-export([query/2]).
-export([is_available/1]).
-export([is_available/2]).

-define(IANAHOST, "whois.iana.org").
-define(TIMEOUT, 15000).
-define(PORT, 43).
-define(OPTS, [{port, ?PORT}, {timeout, ?TIMEOUT}]).

-define(LIMIT_PATTERNS, [
    "Lookup quota exceeded"
]).

-define(ERROR_PATTERNS,     [
    "Error: Invalid query",
    "This name is not available for registration"
]).

query(Domain) ->
    query(Domain, ?OPTS).

query(Domain, Opts) when is_binary(Domain), is_list(Opts) ->
    Nic = proplists:get_value(nic, Opts, get_nic(Domain)),
    case send_query(Domain, Nic, Opts) of
        {ok, Reply} ->
            case response(Reply, Opts) of
                [] -> case is_available(Domain) of
                          {ok, true} -> [{status, <<"Not Registered">>}];
                          _ -> [{status, <<"Registered">>}]
                      end;
                R -> R
            end;
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
    try
        check_pattern(?LIMIT_PATTERNS, RawData, limit_exceeded),
        check_pattern(?ERROR_PATTERNS, RawData, bad_request),
        check_pattern(?FREE_PATTERNS, RawData, resource_allowed)
    catch
        resource_allowed ->
            {ok, true};
        limit_exceeded ->
            {error, limit_exceeded};
        bad_request ->
            {error, bad_request};
        _ ->
            {ok, false}
    end.

-spec check_pattern(PatternList::list(), Data::binary(), MatchResult::atom()) -> boolean().
check_pattern([], _Data, _MatchResult) ->
    false;
check_pattern([Pattern | Tail], Data, MatchResult) when is_binary(Data) ->
    case re:run(Data, Pattern, [{capture, none}]) of
        match ->
            throw(MatchResult);
        nomatch ->
            check_pattern(Tail, Data, MatchResult)
    end;
check_pattern(_, {error, Reason}, _) ->
    throw(Reason).

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

build_whois_request(Nic, Domain) when Nic =:= "whois.online.rs.corenic.net"; Nic =:= "whois.site.rs.corenic.net" ->
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
    case get_nic(Domain, ?PROVIDERS) of
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