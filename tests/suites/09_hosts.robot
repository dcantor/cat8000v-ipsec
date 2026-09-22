*** Settings ***
Documentation     The LAN hosts: one small Alpine VM behind every router (its eth1 = .2 of the site LAN, the router's LAN port .1 as the
...               gateway), modelled in Nautobot and cabled to the router; every host reaches every other host — branch to branch through
...               a headend, branch to headend, headend to headend — over the IPsec tunnels (full ping mesh), and the path shows the tunnel.
Resource          ../resources/common.resource
Library           OperatingSystem
Library           ../../tools/host_cmd.py
Suite Teardown    Suite Teardown Close Connections

*** Test Cases ***
Every router has a LAN host, reachable over the OOB network, addressed on the site LAN with the router as its gateway
    FOR    ${r}    IN    @{ROUTER_NAMES}
        Dictionary Should Contain Key    ${HOST_OF}    ${r}    msg=${r} has no LAN host in the intent
    END
    # the acquired company's edge behind the DCI has one too (ACME's interconnect itself carries no host)
    FOR    ${r}    IN    @{EDGE_NAMES}
        IF    '${EDGE_ROUTERS}[${r}][role]' == 'partner'
            Dictionary Should Contain Key    ${HOST_OF}    ${r}    msg=${r} has no LAN host in the intent
        END
    END
    FOR    ${h}    IN    @{LAN_HOSTS}
        Host Ping    ${LAN_HOSTS}[${h}][host]
        Tcp Port Should Be Open    ${LAN_HOSTS}[${h}][host]    22
        ${rc}    ${out}=    Run    ${LAN_HOSTS}[${h}][host]    ip -4 -br addr show eth1; ip route show default; hostname
        Should Be Equal As Integers    ${rc}    0
        Should Match Regexp    ${out}    (?m)^eth1\\s+UP\\s+${LAN_HOSTS}[${h}][lan_ip]/24
        Should Contain    ${out}    default via ${LAN_HOSTS}[${h}][gateway]
        Should Contain    ${out}    ${h}
    END

The hosts are modelled in Nautobot: device at the router's site, eth1 addressed and cabled to the router's LAN port
    ${d}=    Nautobot Graphql    { devices(role: ["lan-host"], location: ["${NAUTOBOT_LOCATION}"]) { name platform { name } location { name } primary_ip4 { address } interfaces { name enabled ip_addresses { address parent { prefix role { name } } } connected_interface { name device { name } ip_addresses { address } } } } }
    Length Should Be    ${d}[devices]    ${{ len($LAN_HOSTS) }}
    FOR    ${dev}    IN    @{d}[devices]
        ${h}=    Set Variable    ${LAN_HOSTS}[${dev}[name]]
        Should Be Equal    ${dev}[platform][name]    alpine
        Should Be Equal    ${dev}[location][name]    ${ALL_ROUTERS}[${h}[router]][site]
        Should Be Equal    ${dev}[primary_ip4][address]    ${h}[host]/24
        ${e1}=    Evaluate    [i for i in $dev['interfaces'] if i['name'] == 'eth1'][0]
        Should Be Equal    ${e1}[ip_addresses][0][address]    ${h}[lan_ip]/24
        Should Be Equal    ${e1}[ip_addresses][0][parent][prefix]    ${h}[lan]
        Should Be Equal    ${e1}[ip_addresses][0][parent][role][name]    site-lan
        Should Be Equal    ${e1}[connected_interface][device][name]    ${h}[router]
        Should Be Equal    ${e1}[connected_interface][name]    ${ALL_ROUTERS}[${h}[router]][lan_if]
        Should Be Equal    ${e1}[connected_interface][ip_addresses][0][address]    ${h}[gateway]/24
    END

Every host reaches every other host, its own router and the internet: the full ping mesh over the tunnels
    [Documentation]    Every ordered pair (42 for 7 hosts): branch to its headends, branch to branch through a shared headend, headend
    ...    to headend through a spoke homed on both (headends do not peer with each other) — plus, per host, its own router (the LAN
    ...    gateway) and the internet (1.1.1.1 through its headend's breakout): 56 checks.
    ${m}=    Matrix
    Log    ${m}[results]
    Should Be True    ${m}[ok]    msg=${m}[failed] of ${m}[pairs] checks failed: ${m}[failed]
    Should Be Equal As Integers    ${m}[pairs]    ${{ len($LAN_HOSTS) * (len($LAN_HOSTS) + 1) }}
    FOR    ${h}    IN    @{LAN_HOSTS}
        Should Be True    ${m}[results][${h}][gateway][ok]    msg=${h} cannot ping its router ${LAN_HOSTS}[${h}][gateway]
        Should Be True    ${m}[results][${h}][internet][ok]    msg=${h} cannot ping the internet (${m}[targets][internet])
    END
    # every answered pair carries its round-trip time (the portal's mesh shows it, green; a failed pair is red)
    ${slow}=    Evaluate    [(s, d, v['ms']) for s, r in $m['results'].items() for d, v in r.items() if v['ms'] is None or v['ms'] > 500]
    Should Be Empty    ${slow}    msg=pairs without a round-trip time or slower than 500 ms: ${slow}
    ${live}=    Portal Get    /api/hosts    ping=true    live=true
    Should Be True    ${live}[matrix][live]
    Should Be Equal As Integers    ${live}[matrix][count]    1
    Should Be True    ${live}[matrix][ok]    msg=live mesh: ${live}[matrix][failed]

The path between two branch hosts goes through the branch routers and a headend's tunnels
    ${a}=    Set Variable    ${HOST_OF}[${SPOKES}[0]]
    ${b}=    Set Variable    ${HOST_OF}[${SPOKES}[1]]
    ${rc}    ${tr}=    Run    ${LAN_HOSTS}[${a}][host]    traceroute -n -w 2 -q 1 -m 8 ${LAN_HOSTS}[${b}][lan_ip]
    Log    ${tr}
    Should Contain    ${tr}    ${LAN_HOSTS}[${a}][gateway]    msg=first hop must be ${SPOKES}[0]'s LAN port
    ${hub_hops}=    Evaluate    [t['hub_ip'] for t in $TUNNEL_LIST if t['spoke'] == $SPOKES[0]]
    ${seen}=    Evaluate    [h for h in $hub_hops if h in """${tr}"""]
    Should Not Be Empty    ${seen}    msg=no headend tunnel address in the path: ${hub_hops}
    Should Contain    ${tr}    ${LAN_HOSTS}[${b}][lan_ip]
