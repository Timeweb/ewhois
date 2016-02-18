-define(PRVIDERS, [
  {"whois.nic.ru", <<"^(.*)+\\.(org|net|com|msk|spb|nov|sochi).ru$">>},
  {"whois.r01.ru", <<"^[\w\d\-]+\.ru$">>},
  {"whois.nic.fm", <<"^(.*)+fm$">>},
  {"mn.whois-servers.net", <<"^(.*)+mn$">>},
  {"whois.belizenic.bz", <<"^(.*)+bz$">>},
  {"whois.online.rs.corenic.net", <<"^.*xn--80asehdb$">>}, %.онлайн
  {"whois.site.rs.corenic.net", <<"^.*.xn--80aswg$">>}, %.сайт
  {"whois.nic.menu", <<"^.*menu$">>},
  {"whois.nic.xyz", <<"^.*xyz$">>},
  {"whois.nic.bar", <<"^.*bar$">>},
  {"whois.nic.press", <<"^.*press$">>},
  {"whois.nic.website", <<"^.*website$">>},
  {"whois.nic.wiki", <<"^.*wiki$">>}
]).

-define(FREE_PATTERNS, [
  "no matching objects found",% CORE Accociation (.онлайн например)
  "No entries found for the selected",
  "No match for",
  "NOT FOUND",
  "Not found:",
  "No match",
  "No Data Found",% .menu
  "not found in database",
  "Nothing found for this query",
  "Status: AVAILABLE",
  "Status:\tAVAILABLE",
  "Status: Not Registered",
  "NOT FOUND",
  "Domain not found", %% .villas
  "Whois Error: No Match for", %% .bz
  "Can't get information on non-local domain", %% tucows
  "is available for\n>>> registration",
  "is available\n>>> for registration",
  "available for registration",
  "No entries found for"
]).