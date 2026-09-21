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

IKEv2 SAs are READY with the modelled proposal and each spoke's chosen authentication (PSK or certificate)
    [Documentation]    Auth sign / verify follow the spoke's choice (device ike_authentication, else the lab default): PSK, or RSA when it
    ...    holds a certificate from the lab CA (suite 08 checks the certificates themselves). A headend runs one IKEv2 profile per method.
    FOR    ${t}    IN    @{TUNNEL_LIST}
        ${sa}=    Show    ${t}[hub]    show crypto ikev2 sa detail
        ${block}=    Sa Block    ${sa}    ${t}[spoke_wan]
        Should Match Regexp    ${block}    (?m)^\\d+\\s+${t}[hub_wan]/500\\s+${t}[spoke_wan]/500\\s+none/none\\s+READY
        Should Contain    ${block}    Encr: ${IKE_SA_ENCR}, PRF: ${IKE}[integrity], Hash: ${IKE}[integrity], DH Grp:${IKE}[dh_group], Auth sign: ${t}[auth_show], Auth verify: ${t}[auth_show]
        ${ssa}=    Show    ${t}[spoke]    show crypto ikev2 sa
        Should Match Regexp    ${ssa}    (?m)^\\d+\\s+${t}[spoke_wan]/500\\s+${t}[hub_wan]/500\\s+none/none\\s+READY
    END
    FOR    ${r}    IN    @{ROUTER_NAMES}
        FOR    ${a}    IN    @{ROUTER_AUTHS}[${r}]
            ${prof}=    Show    ${r}    show crypto ikev2 profile ${PROFILE_NAMES}[${a}][ikev2_profile]
            Should Contain    ${prof}    IKEv2 profile: ${PROFILE_NAMES}[${a}][ikev2_profile]
            Should Contain    ${prof}    Local authentication method: ${{ 'rsa-sig' if $a == 'certificate' else 'pre-share' }}
            IF    ${DPD}[enabled]
                Should Contain    ${prof}    DPD: interval ${DPD}[interval], retry-interval ${DPD}[retries], on-demand
            END
        END
        ${all}=    Show    ${r}    show crypto ikev2 profile | include IKEv2 profile:
        ${n}=    Get Line Count    ${all.strip()}
        Should Be Equal As Integers    ${n}    ${{ len($ROUTER_AUTHS[$r]) }}    msg=${r}: one IKEv2 profile per authentication method in use, got ${all}
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
Sa Block
    [Documentation]    The IKEv2 SA detail block whose remote address is the given one.
    [Arguments]    ${text}    ${remote}
    ${blocks}=    Evaluate    re.split(r'(?m)^(?=\\d+\\s+\\S+/500\\s+)', $text)    modules=re
    ${block}=    Evaluate    ([b for b in $blocks if re.match(r'\\d+\\s+\\S+/500\\s+' + re.escape("${remote}") + '/500', b)] or [''])[0]    modules=re
    Should Not Be Empty    ${block}    msg=no IKEv2 SA towards ${remote}
    RETURN    ${block}

Encaps Advanced
    [Arguments]    ${r}    ${iface}    ${before}
    ${after}=    Ipsec Encaps    ${r}    ${iface}
    Should Be True    ${after} >= ${before} + 5    msg=${r}: ESP encaps counter did not advance (${before} -> ${after})

Ipsec Encaps
    [Arguments]    ${r}    ${iface}
    ${out}=    Show    ${r}    show crypto ipsec sa interface ${iface} | include pkts encaps
    ${m}=    Get Regexp Matches    ${out}    \#pkts encaps: (\\d+)    1
    RETURN    ${{ sum(int(x) for x in $m) }}    # several SAs are listed around a rekey; count all of them
