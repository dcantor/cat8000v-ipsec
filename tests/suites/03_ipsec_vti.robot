*** Settings ***
Documentation     Point-to-point IPsec VTIs (tunnel mode ipsec ipv4) between each hub and each of its spokes, IKEv2 with
...               pre-shared keys, traffic actually encrypted, no encryption of the OOB management plane.
Resource          ../resources/common.resource
Suite Teardown    Suite Teardown Close Connections

*** Test Cases ***
Each tunnel is a static VTI sourced from the WAN link and protected by the IPsec profile
    FOR    ${t}    IN    @{TUNNEL_LIST}
        ${cfg}=    Show    ${t}[hub]    show run interface Tunnel${t}[id]
        Should Contain    ${cfg}    description IPsec VTI to ${t}[spoke]
        Should Contain    ${cfg}    ip address ${t}[hub_ip] 255.255.255.252
        Should Contain    ${cfg}    tunnel source ${t}[hub_if]
        Should Contain    ${cfg}    tunnel destination ${t}[spoke_wan]
        Should Contain    ${cfg}    tunnel mode ipsec ipv4
        Should Contain    ${cfg}    tunnel protection ipsec profile ${IPSEC_PROFILE}
        Should Not Contain    ${cfg}    nhrp
        ${cfg}=    Show    ${t}[spoke]    show run interface Tunnel${t}[id]
        Should Contain    ${cfg}    description IPsec VTI to ${t}[hub]
        Should Contain    ${cfg}    ip address ${t}[spoke_ip] 255.255.255.252
        Should Contain    ${cfg}    tunnel source ${t}[spoke_if]
        Should Contain    ${cfg}    tunnel destination ${t}[hub_wan]
        Should Contain    ${cfg}    tunnel mode ipsec ipv4
        Should Contain    ${cfg}    tunnel protection ipsec profile ${IPSEC_PROFILE}
    END

Tunnels are up/up at both ends and the tunnel subnet is reachable
    FOR    ${t}    IN    @{TUNNEL_LIST}
        ${brief}=    Show    ${t}[hub]    show ip interface brief | include Tunnel${t}[id]${SPACE}
        Should Match Regexp    ${brief}    Tunnel${t}[id]\\s+${t}[hub_ip]\\s+YES\\s+\\S+\\s+up\\s+up
        ${brief}=    Show    ${t}[spoke]    show ip interface brief | include Tunnel${t}[id]${SPACE}
        Should Match Regexp    ${brief}    Tunnel${t}[id]\\s+${t}[spoke_ip]\\s+YES\\s+\\S+\\s+up\\s+up
        ${p}=    Show    ${t}[spoke]    ping ${t}[hub_ip] source Tunnel${t}[id] repeat 5
        Should Match Regexp    ${p}    Success rate is (100|80) percent
    END

IKEv2 SAs are READY with the modelled proposal and the modelled authentication (PSK or certificates)
    [Documentation]    Auth sign / verify follow the intent's IKE authentication: PSK, or RSA when every router holds a certificate from the
    ...    lab CA (suite 08 checks the certificates themselves).
    FOR    ${t}    IN    @{TUNNEL_LIST}
        ${sa}=    Show    ${t}[hub]    show crypto ikev2 sa
        Should Match Regexp    ${sa}    (?m)^\\d+\\s+${t}[hub_wan]/500\\s+${t}[spoke_wan]/500\\s+none/none\\s+READY
        Should Contain    ${sa}    Encr: ${IKE_SA_ENCR}, PRF: ${IKE}[integrity], Hash: ${IKE}[integrity], DH Grp:${IKE}[dh_group], Auth sign: ${IKE_AUTH_SHOW}, Auth verify: ${IKE_AUTH_SHOW}
        ${ssa}=    Show    ${t}[spoke]    show crypto ikev2 sa
        Should Match Regexp    ${ssa}    (?m)^\\d+\\s+${t}[spoke_wan]/500\\s+${t}[hub_wan]/500\\s+none/none\\s+READY
    END
    FOR    ${r}    IN    @{ROUTER_NAMES}
        ${prof}=    Show    ${r}    show crypto ikev2 profile
        Should Contain    ${prof}    IKEv2 profile: ${IKEV2_PROFILE}
        Should Contain    ${prof}    Local authentication method: ${IKE_AUTH_METHOD}
        IF    ${DPD}[enabled]
            Should Contain    ${prof}    DPD: interval ${DPD}[interval], retry-interval ${DPD}[retries], on-demand
        END
    END

Traffic through the tunnels is encrypted with the modelled transform set
    FOR    ${t}    IN    @{TUNNEL_LIST}
        ${before}=    Ipsec Encaps    ${t}[spoke]    Tunnel${t}[id]
        ${p}=    Show    ${t}[spoke]    ping ${t}[hub_ip] source Tunnel${t}[id] repeat 10
        Should Match Regexp    ${p}    Success rate is (100|90|80) percent
        # IOS-XE refreshes the SA counters from the data plane (QFP) only every few seconds
        Wait Until Keyword Succeeds    90s    5s    Encaps Advanced    ${t}[spoke]    Tunnel${t}[id]    ${before}
        ${sa}=    Show    ${t}[spoke]    show crypto ipsec sa interface Tunnel${t}[id]
        Should Contain    ${sa}    transform: ${ESP_TRANSFORM}
        Should Contain    ${sa}    in use settings ={Tunnel, }
    END

Each hub holds exactly one IKEv2 session per spoke tunnel
    FOR    ${h}    IN    @{HUBS}
        ${sess}=    Show    ${h}    show crypto ikev2 session | include ^Session-id
        ${n}=    Get Line Count    ${sess}
        Should Be Equal As Integers    ${n}    ${{ len($HUB_TUNNELS[$h]) }}    msg=${h}: ${sess}
    END

*** Keywords ***
Encaps Advanced
    [Arguments]    ${r}    ${iface}    ${before}
    ${after}=    Ipsec Encaps    ${r}    ${iface}
    Should Be True    ${after} >= ${before} + 5    msg=${r}: ESP encaps counter did not advance (${before} -> ${after})

Ipsec Encaps
    [Arguments]    ${r}    ${iface}
    ${out}=    Show    ${r}    show crypto ipsec sa interface ${iface} | include pkts encaps
    ${m}=    Get Regexp Matches    ${out}    \#pkts encaps: (\\d+)    1
    RETURN    ${{ sum(int(x) for x in $m) }}    # several SAs are listed around a rekey; count all of them
