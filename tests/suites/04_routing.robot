*** Settings ***
Documentation     eBGP over the VTIs: one AS per site, every hub peers with each of its spokes, spokes learn every other
...               site via a hub (AS path through the hub), end-to-end reachability between site LANs.
Resource          ../resources/common.resource
Suite Teardown    Suite Teardown Close Connections

*** Test Cases ***
Each hub has an Established eBGP session with each of its spokes over the tunnel
    FOR    ${h}    IN    @{HUBS}
        ${sum}=    Show    ${h}    show bgp ipv4 unicast summary
        Should Contain    ${sum}    local AS number ${ROUTERS}[${h}][asn]
        Should Contain    ${sum}    BGP router identifier ${ROUTERS}[${h}][router_id]
        FOR    ${t}    IN    @{HUB_TUNNELS}[${h}]
            Should Match Regexp    ${sum}    (?m)^${t}[spoke_ip]\\s+4\\s+${ROUTERS}[${t}[spoke]][asn]\\s+.*\\s\\d+\\s*$    msg=${h}: session to ${t}[spoke] not Established
            ${nbr}=    Show    ${h}    show bgp ipv4 unicast neighbors ${t}[spoke_ip] | include BGP state|external link
            Should Contain    ${nbr}    BGP state = Established
            Should Contain    ${nbr}    external link
        END
        ${count}=    Get Line Count    ${{ $sum.split('Neighbor', 1)[1].strip() }}
        ${core}=    Get Regexp Matches    ${sum}    (?m)^(172\\.19\\.\\d+\\.\\d+)\\s+4\\s+65000\\s    1    # the SRv6 core attachment (srv6-core lab), if that lab wired the headend
        Should Be True    len($core) <= 1    msg=${h}: more than one core attachment
        Should Be Equal As Integers    ${count}    ${{ len($HUB_TUNNELS[$h]) + 1 + len($core) }}    msg=${h} must peer with its spokes (and at most the SRv6 core) only
    END

Every spoke peers with its hub(s) only and learns every other site
    ${want}=    Evaluate    2 * (len($ROUTER_NAMES) - 1)    # LAN + loopback of every other router
    FOR    ${s}    IN    @{SPOKES}
        ${sum}=    Show    ${s}    show bgp ipv4 unicast summary | begin Neighbor
        FOR    ${t}    IN    @{SPOKE_TUNNELS}[${s}]
            Should Match Regexp    ${sum}    (?m)^${t}[hub_ip]\\s+4\\s+${ROUTERS}[${t}[hub]][asn]\\s+.*\\s\\d+\\s*$    msg=${s}: session to ${t}[hub] not Established
        END
        ${count}=    Get Line Count    ${sum}
        Should Be Equal As Integers    ${count}    ${{ len($SPOKE_TUNNELS[$s]) + 1 }}    msg=spokes must peer with their hubs only
        ${rt}=    Show    ${s}    show ip route bgp
        FOR    ${o}    IN    @{ROUTER_NAMES}
            Continue For Loop If    '${s}' == '${o}'
            Should Match Regexp    ${rt}    (?m)^B\\s+${ROUTERS}[${o}][lan] \\[20/0\\] via 172\\.17\\.
            Should Match Regexp    ${rt}    (?m)^B\\s+${ROUTERS}[${o}][router_id](/32)? \\[20/0\\] via 172\\.17\\.
        END
    END

Spoke routes to other spokes go through a hub
    ${hub_asns}=    Evaluate    '|'.join([$ROUTERS[h]['asn'] for h in $HUBS])
    FOR    ${s}    IN    @{SPOKES}
        FOR    ${o}    IN    @{SPOKES}
            Continue For Loop If    '${s}' == '${o}'
            ${path}=    Show    ${s}    show bgp ipv4 unicast ${ROUTERS}[${o}][lan]
            Should Match Regexp    ${path}    (?m)^\\s+(${hub_asns}) ${ROUTERS}[${o}][asn]\\s*$    msg=${s}: no hub-transit path to ${o} LAN
            Should Contain    ${path}    valid, external, best
        END
    END

Site LANs reach each other through the encrypted tunnels
    FOR    ${r}    IN    @{ROUTER_NAMES}
        FOR    ${o}    IN    @{ROUTER_NAMES}
            Continue For Loop If    '${r}' == '${o}'
            ${p}=    Show    ${r}    ping ${ROUTERS}[${o}][lan_ip] source ${ROUTERS}[${r}][lan_ip] repeat 5
            Should Match Regexp    ${p}    Success rate is (100|80|60) percent
        END
    END
    # spoke-to-spoke path goes through a hub's tunnel address (no direct spoke link)
    ${hub_ips}=    Evaluate    '|'.join([t['hub_ip'] for t in $SPOKE_TUNNELS[$SPOKES[0]]]).replace('.', '\\\\.')
    ${tr}=    Show    ${SPOKES}[0]    traceroute ${ROUTERS}[${SPOKES}[1]][lan_ip] source ${ROUTERS}[${SPOKES}[0]][lan_ip] numeric probe 1 timeout 2
    Should Match Regexp    ${tr}    (?m)^\\s*1\\s+(${hub_ips})\\s
