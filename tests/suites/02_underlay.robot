*** Settings ***
Documentation     WAN underlay: a dedicated point-to-point /30 link from each hub to each of its spokes, CDP adjacency, loopbacks.
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

Each spoke reaches its hub(s) across its own links and nothing else
    FOR    ${t}    IN    @{TUNNEL_LIST}
        ${p}=    Show    ${t}[spoke]    ping ${t}[hub_wan] source ${t}[spoke_if] repeat 3
        Should Match Regexp    ${p}    Success rate is (100|66) percent
        ${p}=    Show    ${t}[hub]    ping ${t}[spoke_wan] source ${t}[hub_if] repeat 3
        Should Match Regexp    ${p}    Success rate is (100|66) percent
    END
    # the spokes' WAN addresses are not routed anywhere: a spoke must not reach another spoke's WAN directly
    ${a}=    Set Variable    ${SPOKE_TUNNELS}[${SPOKES}[0]][0]
    ${b}=    Set Variable    ${SPOKE_TUNNELS}[${SPOKES}[1]][0]
    ${p}=    Show    ${SPOKES}[0]    ping ${b}[spoke_wan] source ${a}[spoke_if] repeat 2
    Should Contain    ${p}    Success rate is 0 percent

CDP shows the hub on each spoke's WAN port and the spoke on the hub's port
    FOR    ${t}    IN    @{TUNNEL_LIST}
        Wait Until Keyword Succeeds    90s    10s    Cdp Shows Link    ${t}
    END

Loopbacks carry the router-id and the site LAN
    FOR    ${r}    IN    @{ROUTER_NAMES}
        ${brief}=    Show    ${r}    show ip interface brief | include Loopback
        Should Match Regexp    ${brief}    (?m)^Loopback0\\s+${ROUTERS}[${r}][router_id]\\s+YES\\s+\\S+\\s+up\\s+up
        Should Match Regexp    ${brief}    (?m)^Loopback10\\s+${ROUTERS}[${r}][lan_ip]\\s+YES\\s+\\S+\\s+up\\s+up
    END

*** Keywords ***
Cdp Shows Link
    [Arguments]    ${t}
    ${hub_port}=    Replace String    ${t}[hub_if]    GigabitEthernet    Gig${SPACE}
    ${spoke_port}=    Replace String    ${t}[spoke_if]    GigabitEthernet    Gig${SPACE}
    ${cdp}=    Show    ${t}[spoke]    show cdp neighbors
    Should Match Regexp    ${cdp}    ${t}[hub]\\.${DOMAIN_NAME}\\s+${spoke_port}\\s.*${hub_port}
    ${cdp}=    Show    ${t}[hub]    show cdp neighbors
    Should Match Regexp    ${cdp}    ${t}[spoke]\\.${DOMAIN_NAME}\\s+${hub_port}\\s.*${spoke_port}
