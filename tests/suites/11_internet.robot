*** Settings ***
Documentation     Internet breakout: every firewall's uplink sits on the libvirt NAT network and masquerades the site LANs (LAN -> uplink
...               only, replies routed back to the headend), every headend holds a default via its firewall and originates one to its spokes,
...               every spoke prefers the nearest headend's default (local preference from the intent's regions), and every LAN host reaches
...               the internet through its preferred headend — the path shows it and the firewall logs it.
Resource          ../resources/common.resource
Library           OperatingSystem
Library           ../../tools/host_cmd.py
Suite Setup       Skip If    not $INTERNET['enabled']    internet breakout is disabled in the intent
Suite Teardown    Suite Teardown Close Connections

*** Variables ***
${NAT_NET}        192.168.122.

*** Test Cases ***
Every firewall has its uplink on the NAT network with an address, masquerades the site LANs and routes them back to its headend
    FOR    ${f}    IN    @{FIREWALLS}
        ${br}=    Vyos    ${f}    show interfaces ethernet ${INTERNET_UPLINK} brief
        Should Match Regexp    ${br}    (?m)^${INTERNET_UPLINK}\\s+${NAT_NET}\\d+/24\\s+u/u
        ${nat}=    Vyos    ${f}    show nat source rules
        Should Match Regexp    ${nat}    (?m)^100\\s+@N_SITE-LANS\\s+0\\.0\\.0\\.0/0\\s+any\\s+${INTERNET_UPLINK}\\s+masquerade
        ${cfg}=    Vyos    ${f}    show configuration commands | match "SITE-LANS network|static route|rule 50"
        ${hub}=    Evaluate    [h for h, fw in $FIREWALL_OF.items() if fw == $f][0]
        ${hub_wan}=    Evaluate    [t['hub_wan'] for t in $TUNNEL_LIST if t['hub'] == $hub][0]
        FOR    ${r}    IN    @{ROUTER_NAMES}
            Should Contain    ${cfg}    set firewall group network-group SITE-LANS network '${ROUTERS}[${r}][lan]'
            Should Contain    ${cfg}    set protocols static route ${ROUTERS}[${r}][lan] next-hop ${hub_wan}    msg=${f}: replies for ${ROUTERS}[${r}][lan] must go back to ${hub}
        END
        Should Match Regexp    ${cfg}    (?m)^set firewall ipv4 forward filter rule 50 inbound-interface name 'eth1'$
        Should Match Regexp    ${cfg}    (?m)^set firewall ipv4 forward filter rule 50 outbound-interface name '${INTERNET_UPLINK}'$
        Should Match Regexp    ${cfg}    (?m)^set firewall ipv4 forward filter rule 50 source group network-group 'SITE-LANS'$
        ${p}=    Vyos    ${f}    ping 1.1.1.1 count 2 interface ${INTERNET_UPLINK}
        Should Contain    ${p}    2 received    msg=${f}: no internet on the uplink (does the lab host have internet?)
    END

Every headend holds a static default via its firewall and originates a default route to each of its spokes
    FOR    ${h}    IN    @{HUBS}
        ${rt}=    Show    ${h}    show ip route 0.0.0.0
        Should Contain    ${rt}    Known via "static"
        ${gw}=    Evaluate    [t['hub_gw'] for t in $TUNNEL_LIST if t['hub'] == $h][0]
        Should Match Regexp    ${rt}    \\* ${gw}
        ${run}=    Show    ${h}    show running-config | section router bgp
        FOR    ${t}    IN    @{HUB_TUNNELS}[${h}]
            Should Contain    ${run}    neighbor ${t}[spoke_ip] default-originate
        END
    END

Every spoke prefers the nearest headend's default route (local preference by region) and keeps the others as backups
    FOR    ${s}    IN    @{SPOKES}
        ${pref}=    Set Variable    ${BREAKOUT_PREF}[${s}]
        ${bgp}=    Show    ${s}    show ip bgp 0.0.0.0/0
        Should Match Regexp    ${bgp}    Paths: \\(${{ len($pref) }} available
        ${best_hub_ip}=    Evaluate    [t['hub_ip'] for t in $TUNNEL_LIST if t['spoke'] == $s and t['hub'] == $pref[0]][0]
        Should Match Regexp    ${bgp}    (?s)${best_hub_ip} from ${best_hub_ip}.*?localpref 200, valid, external, best
        ${rt}=    Show    ${s}    show ip route 0.0.0.0
        Should Match Regexp    ${rt}    \\* ${best_hub_ip}
        ${run}=    Show    ${s}    show running-config | section router bgp|route-map|prefix-list
        FOR    ${h}    IN    @{pref}
            ${hub_ip}=    Evaluate    [t['hub_ip'] for t in $TUNNEL_LIST if t['spoke'] == $s and t['hub'] == $h][0]
            Should Contain    ${run}    neighbor ${hub_ip} route-map BREAKOUT-${h} in
            Should Match Regexp    ${run}    (?s)route-map BREAKOUT-${h} permit 10.*?set local-preference ${{ 200 - 50 * $pref.index($h) }}
            # the rank is carried by local-preference, never by the description: IOS-XE appends a route-map description over
            # RESTCONF instead of replacing it, so a description that changed with the rank left the old line behind after a
            # re-home (Golden Config then saw drift). One description per entry, and it must not name a preference rank.
            ${entry}=    Get Regexp Matches    ${run}    (?s)route-map BREAKOUT-${h} permit 10 *\n(.*?)(?=route-map |\Z)    1
            ${descs}=    Get Regexp Matches    ${entry}[0]    (?m)^ *description .*
            Length Should Be    ${descs}    1    msg=${s}: route-map BREAKOUT-${h} permit 10 has ${{ len($descs) }} description lines: ${descs}
            Should Not Contain    ${descs}[0]    preference #    msg=${s}: the route-map description must not carry the preference rank (it changes on a re-home; IOS-XE appends descriptions)
        END
    END

Every LAN host reaches the internet through its router's preferred headend, and the firewall there logs the flow
    [Documentation]    A branch host breaks out through its nearest headend. A host behind the DCI chain has no breakout preference of
    ...    its own (its default route comes from the headend over eBGP) — suite 12 checks that path.
    FOR    ${h}    IN    @{LAN_HOSTS}
        ${r}=    Set Variable    ${LAN_HOSTS}[${h}][router]
        ${rc}    ${out}=    Run    ${LAN_HOSTS}[${h}][host]    ping -c 3 -W 2 1.1.1.1; traceroute -n -w 2 -q 1 -m 6 1.1.1.1
        Should Match Regexp    ${out}    3 packets transmitted, [23] packets received    msg=${h}: no internet: ${out}
        Should Contain    ${out}    ${LAN_HOSTS}[${h}][gateway]    msg=${h}: first hop must be its router
        IF    $r in $BREAKOUT_PREF
            ${hub}=    Set Variable    ${BREAKOUT_PREF}[${r}][0]
            ${hub_ip}=    Evaluate    [t['hub_ip'] for t in $TUNNEL_LIST if t['spoke'] == $r and t['hub'] == $hub][0]
            Should Contain    ${out}    ${hub_ip}    msg=${h}: the path must go through ${hub} (its region's headend): ${out}
        ELSE IF    $r in $EDGE_ROUTERS
            # behind the DCI: the default route comes from the headend the chain hangs off, so it breaks out there
            ${hub}=    Evaluate    $DCI_UPLINK_HUB
            Should Contain    ${out}    ${{ [p['a_ip'] for p in $DIRECT_PEERINGS if p['b'] == $DCI_UPLINK][0] }}    msg=${h}: the path must cross the DCI: ${out}
        ELSE
            ${hub}=    Set Variable    ${r}
        END
        ${fw}=    Set Variable    ${FIREWALL_OF}[${hub}]
        Wait Until Keyword Succeeds    30s    5s    Firewall Logged Breakout    ${fw}    ${LAN_HOSTS}[${h}][lan_ip]
    END

*** Keywords ***
Vyos
    [Arguments]    ${f}    ${command}
    ${out}=    Run Vyos Command    ${FIREWALLS}[${f}][host]    ${command}
    RETURN    ${out}

Firewall Logged Breakout
    [Arguments]    ${f}    ${src}
    ${log}=    Vyos    ${f}    show log firewall | match "FWD-filter-50-A" | tail -n 40
    Should Match Regexp    ${log}    SRC=${src} DST=1\\.1\\.1\\.1    msg=${f}: no accepted breakout flow from ${src}
