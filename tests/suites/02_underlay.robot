*** Settings ***
Documentation     WAN underlay: a dedicated point-to-point /30 link from the hub to each spoke, CDP adjacency, loopbacks.
Resource          ../resources/common.resource
Suite Teardown    Suite Teardown Close Connections

*** Test Cases ***
WAN point-to-point interfaces are up with the modelled addresses
    FOR    ${s}    IN    @{SPOKES}
        ${t}=    Set Variable    ${TUNNELS}[${s}]
        ${brief}=    Show    ${HUB}    show ip interface brief | include ${t}[hub_if]
        Should Match Regexp    ${brief}    ${t}[hub_if]\\s+${t}[hub_wan]\\s+YES\\s+\\S+\\s+up\\s+up
        ${brief}=    Show    ${s}    show ip interface brief | include ${t}[spoke_if]
        Should Match Regexp    ${brief}    ${t}[spoke_if]\\s+${t}[spoke_wan]\\s+YES\\s+\\S+\\s+up\\s+up
    END

Each spoke reaches the hub across its own link and nothing else
    FOR    ${s}    IN    @{SPOKES}
        ${t}=    Set Variable    ${TUNNELS}[${s}]
        ${p}=    Show    ${s}    ping ${t}[hub_wan] source ${t}[spoke_if] repeat 3
        Should Match Regexp    ${p}    Success rate is (100|66) percent
        ${p}=    Show    ${HUB}    ping ${t}[spoke_wan] source ${t}[hub_if] repeat 3
        Should Match Regexp    ${p}    Success rate is (100|66) percent
    END
    # the spokes' WAN addresses are not routed anywhere: spoke1 must not reach spoke2's WAN directly
    ${p}=    Show    spoke1    ping ${TUNNELS}[spoke2][spoke_wan] source ${TUNNELS}[spoke1][spoke_if] repeat 2
    Should Contain    ${p}    Success rate is 0 percent

CDP shows the hub on each spoke's WAN port and both spokes on the hub
    FOR    ${s}    IN    @{SPOKES}
        Wait Until Keyword Succeeds    90s    10s    Cdp Shows Link    ${s}
    END

Loopbacks carry the router-id and the site LAN
    FOR    ${r}    IN    @{ROUTER_NAMES}
        ${brief}=    Show    ${r}    show ip interface brief | include Loopback
        Should Match Regexp    ${brief}    (?m)^Loopback0\\s+${ROUTERS}[${r}][router_id]\\s+YES\\s+\\S+\\s+up\\s+up
        Should Match Regexp    ${brief}    (?m)^Loopback10\\s+${ROUTERS}[${r}][lan_ip]\\s+YES\\s+\\S+\\s+up\\s+up
    END

*** Keywords ***
Cdp Shows Link
    [Arguments]    ${s}
    ${t}=    Set Variable    ${TUNNELS}[${s}]
    ${hub_port}=    Replace String    ${t}[hub_if]    GigabitEthernet    Gig${SPACE}
    ${spoke_port}=    Replace String    ${t}[spoke_if]    GigabitEthernet    Gig${SPACE}
    ${cdp}=    Show    ${s}    show cdp neighbors
    Should Match Regexp    ${cdp}    ${HUB}\\.${DOMAIN_NAME}\\s+${spoke_port}\\s.*${hub_port}
    ${cdp}=    Show    ${HUB}    show cdp neighbors
    Should Match Regexp    ${cdp}    ${s}\\.${DOMAIN_NAME}\\s+${hub_port}\\s.*${spoke_port}
