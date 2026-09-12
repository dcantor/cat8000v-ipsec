*** Settings ***
Documentation     Point-to-point IPsec VTIs (tunnel mode ipsec ipv4) between the hub and each spoke, IKEv2 with
...               pre-shared keys, traffic actually encrypted, no encryption of the OOB management plane.
Resource          ../resources/common.resource
Suite Teardown    Suite Teardown Close Connections

*** Test Cases ***
Each tunnel is a static VTI sourced from the WAN link and protected by the IPsec profile
    FOR    ${s}    IN    @{SPOKES}
        ${t}=    Set Variable    ${TUNNELS}[${s}]
        ${cfg}=    Show    ${HUB}    show run interface Tunnel${t}[id]
        Should Contain    ${cfg}    description IPsec VTI to ${s}
        Should Contain    ${cfg}    ip address ${t}[hub_ip] 255.255.255.252
        Should Contain    ${cfg}    tunnel source ${t}[hub_if]
        Should Contain    ${cfg}    tunnel destination ${t}[spoke_wan]
        Should Contain    ${cfg}    tunnel mode ipsec ipv4
        Should Contain    ${cfg}    tunnel protection ipsec profile ${IPSEC_PROFILE}
        Should Not Contain    ${cfg}    nhrp
        ${cfg}=    Show    ${s}    show run interface Tunnel${t}[id]
        Should Contain    ${cfg}    description IPsec VTI to ${HUB}
        Should Contain    ${cfg}    ip address ${t}[spoke_ip] 255.255.255.252
        Should Contain    ${cfg}    tunnel source ${t}[spoke_if]
        Should Contain    ${cfg}    tunnel destination ${t}[hub_wan]
        Should Contain    ${cfg}    tunnel mode ipsec ipv4
        Should Contain    ${cfg}    tunnel protection ipsec profile ${IPSEC_PROFILE}
    END

Tunnels are up/up at both ends and the tunnel subnet is reachable
    FOR    ${s}    IN    @{SPOKES}
        ${t}=    Set Variable    ${TUNNELS}[${s}]
        ${brief}=    Show    ${HUB}    show ip interface brief | include Tunnel${t}[id]
        Should Match Regexp    ${brief}    Tunnel${t}[id]\\s+${t}[hub_ip]\\s+YES\\s+\\S+\\s+up\\s+up
        ${brief}=    Show    ${s}    show ip interface brief | include Tunnel${t}[id]
        Should Match Regexp    ${brief}    Tunnel${t}[id]\\s+${t}[spoke_ip]\\s+YES\\s+\\S+\\s+up\\s+up
        ${p}=    Show    ${s}    ping ${t}[hub_ip] source Tunnel${t}[id] repeat 5
        Should Match Regexp    ${p}    Success rate is (100|80) percent
    END

IKEv2 SAs are READY with the modelled proposal and PSK authentication
    ${sa}=    Show    ${HUB}    show crypto ikev2 sa
    FOR    ${s}    IN    @{SPOKES}
        ${t}=    Set Variable    ${TUNNELS}[${s}]
        Should Match Regexp    ${sa}    (?m)^\\d+\\s+${t}[hub_wan]/500\\s+${t}[spoke_wan]/500\\s+none/none\\s+READY
        ${ssa}=    Show    ${s}    show crypto ikev2 sa
        Should Match Regexp    ${ssa}    (?m)^\\d+\\s+${t}[spoke_wan]/500\\s+${t}[hub_wan]/500\\s+none/none\\s+READY
    END
    Should Contain    ${sa}    Encr: AES-CBC, keysize: 256, PRF: SHA256, Hash: SHA256, DH Grp:14, Auth sign: PSK, Auth verify: PSK
    FOR    ${r}    IN    @{ROUTER_NAMES}
        ${prof}=    Show    ${r}    show crypto ikev2 profile
        Should Contain    ${prof}    IKEv2 profile: ${IKEV2_PROFILE}
        Should Contain    ${prof}    Local authentication method: pre-share
        Should Contain    ${prof}    DPD: interval 30, retry-interval 5, on-demand
    END

Traffic through the tunnels is encrypted with the modelled transform set
    FOR    ${s}    IN    @{SPOKES}
        ${t}=    Set Variable    ${TUNNELS}[${s}]
        ${before}=    Ipsec Encaps    ${s}    Tunnel${t}[id]
        ${p}=    Show    ${s}    ping ${t}[hub_ip] source Tunnel${t}[id] repeat 10
        Should Match Regexp    ${p}    Success rate is (100|90|80) percent
        ${after}=    Ipsec Encaps    ${s}    Tunnel${t}[id]
        Should Be True    ${after} >= ${before} + 8    msg=${s}: ESP encaps counter did not advance (${before} -> ${after})
        ${sa}=    Show    ${s}    show crypto ipsec sa interface Tunnel${t}[id]
        Should Contain    ${sa}    transform: esp-256-aes esp-sha256-hmac
        Should Contain    ${sa}    in use settings ={Tunnel, }
    END

The hub holds exactly one IKEv2 session per spoke
    ${sess}=    Show    ${HUB}    show crypto ikev2 session | include ^Session-id
    ${n}=    Get Line Count    ${sess}
    Should Be Equal As Integers    ${n}    2    msg=${sess}

*** Keywords ***
Ipsec Encaps
    [Arguments]    ${r}    ${iface}
    ${out}=    Show    ${r}    show crypto ipsec sa interface ${iface} | include pkts encaps
    ${m}=    Get Regexp Matches    ${out}    \#pkts encaps: (\\d+)    1
    RETURN    ${{ int($m[0]) }}
