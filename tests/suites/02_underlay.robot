*** Settings ***
Documentation     WAN underlay: each spoke has a point-to-point /30 link to its headend's firewall, each headend one link to its
...               firewall; the headend WAN address is reached through the firewall (static routes); LLDP adjacency; loopbacks.
Resource          ../resources/common.resource
Suite Teardown    Suite Teardown Close Connections

*** Test Cases ***
WAN point-to-point interfaces are up with the modelled addresses
    FOR    ${t}    IN    @{TUNNEL_LIST}
        ${brief}=    Show    ${t}[hub]    show ip interface brief | include ${t}[hub_if]
        Should Match Regexp    ${brief}    ${t}[hub_if]\\s+${t}[hub_wan]\\s+YES\\s+\\S+\\s+up\\s+up
        ${brief}=    Show    ${t}[spoke]    show ip interface brief | include ${t}[spoke_if]
        Should Match Regexp    ${brief}    ${t}[spoke_if]\\s+${t}[spoke_wan]\\s+YES\\s+\\S+\\s+up\\s+up
    END

Each spoke reaches its headends' WAN addresses through the firewall, and nothing else
    FOR    ${t}    IN    @{TUNNEL_LIST}
        ${p}=    Show    ${t}[spoke]    ping ${t}[spoke_gw] source ${t}[spoke_if] repeat 3
        Should Match Regexp    ${p}    Success rate is (100|66) percent    msg=${t}[spoke]: firewall side of its link unreachable
        ${p}=    Show    ${t}[spoke]    ping ${t}[hub_wan] source ${t}[spoke_if] repeat 3
        Should Match Regexp    ${p}    Success rate is (100|66) percent    msg=${t}[spoke]: ${t}[hub] WAN ${t}[hub_wan] unreachable via ${t}[firewall]
        ${p}=    Show    ${t}[hub]    ping ${t}[spoke_wan] source ${t}[hub_if] repeat 3
        Should Match Regexp    ${p}    Success rate is (100|66) percent
        ${rt}=    Show    ${t}[spoke]    show ip route ${t}[hub_wan]
        Should Match Regexp    ${rt}    (?s)Known via "static".*${t}[spoke_gw]    msg=${t}[spoke]: no static route to ${t}[hub] via the firewall
    END
    # the WAN /30s stay out of the VPN: a headend routes only its own spokes' WAN links, so a branch cannot reach the WAN address of a
    # branch it shares no headend with (two branches on the same headend do reach each other there — that headend routes both /30s)
    Skip If    not $UNROUTED_WAN    every pair of branches shares a headend in this topology: no WAN address is unroutable from a branch
    ${p}=    Show    ${UNROUTED_WAN}[spoke]    ping ${UNROUTED_WAN}[target] source ${UNROUTED_WAN}[spoke_if] repeat 2
    Should Contain    ${p}    Success rate is 0 percent    msg=${UNROUTED_WAN}[spoke] reached ${UNROUTED_WAN}[target_spoke]'s WAN ${UNROUTED_WAN}[target] behind ${UNROUTED_WAN}[via_hub], which is not one of its headends

LLDP shows the firewall on each spoke's WAN port and on the headend's WAN port
    FOR    ${t}    IN    @{TUNNEL_LIST}
        Wait Until Keyword Succeeds    120s    10s    Lldp Shows Link    ${t}
    END

Loopback0 carries the router-id and the LAN port the site LAN
    [Documentation]    The site LAN /24 is the router's last port (.1 — the host's default gateway), no longer Loopback10.
    FOR    ${r}    IN    @{ROUTER_NAMES}
        ${brief}=    Show    ${r}    show ip interface brief | include Loopback|${ROUTERS}[${r}][lan_if]
        Should Match Regexp    ${brief}    (?m)^Loopback0\\s+${ROUTERS}[${r}][router_id]\\s+YES\\s+\\S+\\s+up\\s+up
        Should Match Regexp    ${brief}    (?m)^${ROUTERS}[${r}][lan_if]\\s+${ROUTERS}[${r}][lan_ip]\\s+YES\\s+\\S+\\s+up\\s+up
        Should Not Contain    ${brief}    Loopback10
    END

*** Keywords ***
Lldp Shows Link
    [Arguments]    ${t}
    ${spoke_port}=    Replace String    ${t}[spoke_if]    GigabitEthernet    Gi
    ${hub_port}=    Replace String    ${t}[hub_if]    GigabitEthernet    Gi
    ${l}=    Show    ${t}[spoke]    show lldp neighbors
    Should Match Regexp    ${l}    (?m)^${t}[firewall]\\S*\\s+${spoke_port}\\s.*${t}[fw_spoke_if]    msg=${t}[spoke] ${t}[spoke_if]: ${t}[firewall] ${t}[fw_spoke_if] not seen
    ${l}=    Show    ${t}[hub]    show lldp neighbors
    Should Match Regexp    ${l}    (?m)^${t}[firewall]\\S*\\s+${hub_port}\\s.*${t}[fw_hub_if]    msg=${t}[hub] ${t}[hub_if]: ${t}[firewall] ${t}[fw_hub_if] not seen
