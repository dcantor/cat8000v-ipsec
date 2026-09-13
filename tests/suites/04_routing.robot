*** Settings ***
Documentation     eBGP over the VTIs: one AS per site, hub peers with both spokes, spokes learn each other's
...               LAN via the hub (AS path through 65200), end-to-end reachability between site LANs.
Resource          ../resources/common.resource
Suite Teardown    Suite Teardown Close Connections

*** Test Cases ***
Hub has an Established eBGP session with each spoke over its tunnel
    ${sum}=    Show    ${HUB}    show bgp ipv4 unicast summary
    Should Contain    ${sum}    local AS number ${ROUTERS}[${HUB}][asn]
    Should Contain    ${sum}    BGP router identifier ${ROUTERS}[${HUB}][router_id]
    FOR    ${s}    IN    @{SPOKES}
        ${t}=    Set Variable    ${TUNNELS}[${s}]
        Should Match Regexp    ${sum}    (?m)^${t}[spoke_ip]\\s+4\\s+${ROUTERS}[${s}][asn]\\s+.*\\s2\\s*$    msg=hub: session to ${s} not Established with 2 prefixes
        ${nbr}=    Show    ${HUB}    show bgp ipv4 unicast neighbors ${t}[spoke_ip] | include BGP state|external link
        Should Contain    ${nbr}    BGP state = Established
        Should Contain    ${nbr}    external link
    END

Every spoke peers with the hub only and receives every other site's LAN and loopback
    ${want}=    Evaluate    2 * (len($ROUTER_NAMES) - 1)    # hub's LAN+loopback plus 2 per other spoke
    FOR    ${s}    IN    @{SPOKES}
        ${t}=    Set Variable    ${TUNNELS}[${s}]
        ${sum}=    Show    ${s}    show bgp ipv4 unicast summary | begin Neighbor
        Should Match Regexp    ${sum}    (?m)^${t}[hub_ip]\\s+4\\s+${ROUTERS}[${HUB}][asn]\\s+.*\\s${want}\\s*$    msg=${s}: expected ${want} prefixes from the hub
        ${count}=    Get Line Count    ${sum}
        Should Be Equal As Integers    ${count}    2    msg=spokes must peer with the hub only
    END

Spokes see each other's LAN and loopback via the hub with the AS path hub-spoke
    FOR    ${s}    IN    @{SPOKES}
        ${t}=    Set Variable    ${TUNNELS}[${s}]
        ${rt}=    Show    ${s}    show ip route bgp
        Should Match Regexp    ${rt}    (?m)^B\\s+${ROUTERS}[${HUB}][lan] \\[20/0\\] via ${t}[hub_ip]
        Should Match Regexp    ${rt}    (?m)^B\\s+${ROUTERS}[${HUB}][router_id](/32)? \\[20/0\\] via ${t}[hub_ip]
        FOR    ${o}    IN    @{SPOKES}
            Continue For Loop If    '${s}' == '${o}'
            Should Match Regexp    ${rt}    (?m)^B\\s+${ROUTERS}[${o}][lan] \\[20/0\\] via ${t}[hub_ip]
            Should Match Regexp    ${rt}    (?m)^B\\s+${ROUTERS}[${o}][router_id](/32)? \\[20/0\\] via ${t}[hub_ip]
            ${path}=    Show    ${s}    show bgp ipv4 unicast ${ROUTERS}[${o}][lan]
            Should Match Regexp    ${path}    (?m)^\\s+${ROUTERS}[${HUB}][asn] ${ROUTERS}[${o}][asn]\\s*$    msg=${s}: AS path to ${o} LAN is not ${ROUTERS}[${HUB}][asn] ${ROUTERS}[${o}][asn]
            Should Contain    ${path}    valid, external, best
        END
    END

Hub learns each spoke's LAN directly from that spoke
    ${rt}=    Show    ${HUB}    show ip route bgp
    FOR    ${s}    IN    @{SPOKES}
        Should Match Regexp    ${rt}    (?m)^B\\s+${ROUTERS}[${s}][lan] \\[20/0\\] via ${TUNNELS}[${s}][spoke_ip]
        Should Match Regexp    ${rt}    (?m)^B\\s+${ROUTERS}[${s}][router_id](/32)? \\[20/0\\] via ${TUNNELS}[${s}][spoke_ip]
    END

Site LANs reach each other through the encrypted tunnels
    FOR    ${r}    IN    @{ROUTER_NAMES}
        FOR    ${o}    IN    @{ROUTER_NAMES}
            Continue For Loop If    '${r}' == '${o}'
            ${p}=    Show    ${r}    ping ${ROUTERS}[${o}][lan_ip] source ${ROUTERS}[${r}][lan_ip] repeat 5
            Should Match Regexp    ${p}    Success rate is (100|80|60) percent
        END
    END
    # spoke-to-spoke path goes through the hub's tunnel address (no direct spoke link)
    ${tr}=    Show    spoke1    traceroute ${ROUTERS}[spoke2][lan_ip] source ${ROUTERS}[spoke1][lan_ip] numeric probe 1 timeout 2
    Should Match Regexp    ${tr}    (?m)^\\s*1\\s+${TUNNELS}[spoke1][hub_ip]\\s
    Should Match Regexp    ${tr}    (?m)^\\s*2\\s+${TUNNELS}[spoke2][spoke_ip]\\s
