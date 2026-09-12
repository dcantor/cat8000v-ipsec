*** Settings ***
Documentation     The IPsec lab as modelled in the shared Nautobot: devices match the routers, p2p links are cabled,
...               VTIs are objects with source/peer relationships, eBGP peerings match the live sessions, the rendered
...               NAC device model matches the committed file, Golden Config is compliant.
Resource          ../resources/common.resource
Suite Teardown    Suite Teardown Close Connections

*** Test Cases ***
Routers exist in Nautobot with role, serial, platform and management IP matching reality
    FOR    ${r}    IN    @{ROUTER_NAMES}
        ${d}=    Nautobot Get    dcim/devices/    name=${r}    depth=1
        Should Be Equal As Integers    ${d}[count]    1
        ${dev}=    Set Variable    ${d}[results][0]
        Should Be Equal    ${dev}[location][name]    ${NAUTOBOT_LOCATION}
        Should Be Equal    ${dev}[role][name]    vpn-${ROUTERS}[${r}][role]
        Should Be Equal    ${dev}[device_type][model]    C8000V
        Should Be Equal    ${dev}[platform][name]    cisco_xe
        Should Be Equal    ${dev}[primary_ip4][host]    ${ROUTERS}[${r}][host]
        ${ver}=    Show    ${r}    show version | include Processor board ID
        Should Contain    ${ver}    ${dev}[serial]
    END

WAN links are modelled as cables between the hub and spoke ports with /30 addresses
    FOR    ${s}    IN    @{SPOKES}
        ${t}=    Set Variable    ${TUNNELS}[${s}]
        ${d}=    Nautobot Graphql    { interfaces(device:["${s}"], name:"${t}[spoke_if]") { enabled description ip_addresses { address parent { prefix role { name } } } connected_interface { name device { name } ip_addresses { address } } } }
        ${i}=    Set Variable    ${d}[interfaces][0]
        Should Be True    ${i}[enabled]
        Should Be Equal    ${i}[description]    WAN to ${HUB} ${{ $t['hub_if'].replace('GigabitEthernet', 'Gi') }}
        Should Be Equal    ${i}[ip_addresses][0][address]    ${t}[spoke_wan]/30
        Should Be Equal    ${i}[ip_addresses][0][parent][prefix]    ${t}[wan_prefix]
        Should Be Equal    ${i}[ip_addresses][0][parent][role][name]    wan-p2p
        Should Be Equal    ${i}[connected_interface][device][name]    ${HUB}
        Should Be Equal    ${i}[connected_interface][name]    ${t}[hub_if]
        Should Be Equal    ${i}[connected_interface][ip_addresses][0][address]    ${t}[hub_wan]/30
    END
    ${d}=    Nautobot Graphql    { interfaces(device:["${HUB}","spoke1","spoke2"], description:"unwired") { device { name } name enabled } }
    FOR    ${i}    IN    @{d}[interfaces]
        Should Not Be True    ${i}[enabled]    msg=${i}[device][name]/${i}[name] is unwired but enabled
    END

The VTIs are modelled as objects: ipsec mode, IPsec profile, tunnel source and a symmetric tunnel peer
    ${d}=    Nautobot Graphql    { interfaces(device:["${HUB}","spoke1","spoke2"], name:["Tunnel1","Tunnel2"]) { device { name } name cf_tunnel_mode cf_tunnel_key cf_tunnel_ipsec_profile cf_nhrp_role ip_addresses { address parent { role { name } } } rel_tunnel_source_source { name ip_addresses { address } } rel_tunnel_peer { name device { name } ip_addresses { address } rel_tunnel_source_source { ip_addresses { address } } } } }
    Length Should Be    ${d}[interfaces]    4
    FOR    ${t}    IN    @{d}[interfaces]
        ${r}=    Set Variable    ${t}[device][name]
        ${s}=    Set Variable If    '${r}' == '${HUB}'    spoke${t}[name][-1]    ${r}
        ${x}=    Set Variable    ${TUNNELS}[${s}]
        Should Be Equal    ${t}[name]    Tunnel${x}[id]
        Should Be Equal    ${t}[cf_tunnel_mode]    ipsec-ipv4
        Should Be Equal    ${t}[cf_tunnel_key]    ${None}
        Should Be Equal    ${t}[cf_nhrp_role]    ${None}
        Should Be Equal    ${t}[cf_tunnel_ipsec_profile]    ${IPSEC_PROFILE}
        Should Be Equal    ${t}[ip_addresses][0][parent][role][name]    vpn-tunnel
        IF    '${r}' == '${HUB}'
            Should Be Equal    ${t}[ip_addresses][0][address]    ${x}[hub_ip]/30
            Should Be Equal    ${t}[rel_tunnel_source_source][name]    ${x}[hub_if]
            Should Be Equal    ${t}[rel_tunnel_peer][device][name]    ${s}
            Should Be Equal    ${t}[rel_tunnel_peer][ip_addresses][0][address]    ${x}[spoke_ip]/30
            Should Be Equal    ${t}[rel_tunnel_peer][rel_tunnel_source_source][ip_addresses][0][address]    ${x}[spoke_wan]/30
        ELSE
            Should Be Equal    ${t}[ip_addresses][0][address]    ${x}[spoke_ip]/30
            Should Be Equal    ${t}[rel_tunnel_source_source][name]    ${x}[spoke_if]
            Should Be Equal    ${t}[rel_tunnel_peer][device][name]    ${HUB}
            Should Be Equal    ${t}[rel_tunnel_peer][ip_addresses][0][address]    ${x}[hub_ip]/30
            Should Be Equal    ${t}[rel_tunnel_peer][rel_tunnel_source_source][ip_addresses][0][address]    ${x}[hub_wan]/30
        END
        # the router's tunnel destination is exactly the peer's tunnel-source address from the model
        ${dst}=    Fetch From Left    ${t}[rel_tunnel_peer][rel_tunnel_source_source][ip_addresses][0][address]    /
        ${cfg}=    Show    ${r}    show run interface ${t}[name] | include tunnel destination
        Should Contain    ${cfg}    tunnel destination ${dst}
    END

The IKEv2/IPsec suite comes from the crypto config context and matches the routers
    ${d}=    Nautobot Graphql    { devices(location:"${NAUTOBOT_LOCATION}") { name config_context } }
    Length Should Be    ${d}[devices]    3
    FOR    ${dev}    IN    @{d}[devices]
        ${cr}=    Set Variable    ${dev}[config_context][crypto]
        Should Be Equal    ${cr}[ikev2_profile][name]    ${IKEV2_PROFILE}
        Should Be Equal    ${cr}[ipsec_profile][name]    ${IPSEC_PROFILE}
        ${sa}=    Show    ${dev}[name]    show crypto ikev2 proposal ${cr}[ikev2_proposal][name]
        Should Contain    ${sa}    Encryption : AES-CBC-256
        Should Contain    ${sa}    Integrity  : SHA256
        Should Contain    ${sa}    DH Group   : DH_GROUP_2048_MODP/Group 14
        ${ts}=    Show    ${dev}[name]    show crypto ipsec transform-set ${cr}[ipsec_transform_set][name]
        Should Match Regexp    ${ts}    \\{ ${cr}[ipsec_transform_set][esp] ${cr}[ipsec_transform_set][esp_hmac]\\s*\\}
        Should Be Equal    ${dev}[config_context][oob][gateway]    ${OOB_GATEWAY}
    END

BGP model: one AS per site, eBGP peerings over the tunnel addresses matching the live sessions
    ${d}=    Nautobot Graphql    { bgp_routing_instances(device:["${HUB}","spoke1","spoke2"]) { device { name } autonomous_system { asn } router_id { address } endpoints { source_ip { address } autonomous_system { asn } peer { source_ip { address } autonomous_system { asn } routing_instance { device { name } } } } } }
    Length Should Be    ${d}[bgp_routing_instances]    3
    FOR    ${ri}    IN    @{d}[bgp_routing_instances]
        ${r}=    Set Variable    ${ri}[device][name]
        Should Be Equal As Integers    ${ri}[autonomous_system][asn]    ${ROUTERS}[${r}][asn]
        Should Be Equal    ${ri}[router_id][address]    ${ROUTERS}[${r}][router_id]/32
        ${expected}=    Set Variable If    '${r}' == '${HUB}'    2    1
        Length Should Be    ${ri}[endpoints]    ${expected}
        ${sum}=    Show    ${r}    show bgp ipv4 unicast summary | begin Neighbor
        FOR    ${ep}    IN    @{ri}[endpoints]
            Should Be Equal As Integers    ${ep}[autonomous_system][asn]    ${ROUTERS}[${r}][asn]
            ${peer}=    Set Variable    ${ep}[peer][routing_instance][device][name]
            Should Not Be Equal As Integers    ${ep}[peer][autonomous_system][asn]    ${ROUTERS}[${r}][asn]    msg=peering must be eBGP
            Should Be Equal As Integers    ${ep}[peer][autonomous_system][asn]    ${ROUTERS}[${peer}][asn]
            ${peer_ip}=    Fetch From Left    ${ep}[peer][source_ip][address]    /
            Should Match Regexp    ${sum}    (?m)^${peer_ip}\\s+4\\s+${ROUTERS}[${peer}][asn]\\s+.*\\s\\d+\\s*$    msg=${r}: session to ${peer_ip} not Established
        END
    END

NAC device model rendered from Nautobot matches the committed file
    [Tags]    nac
    ${rc}=    Render Nac Check
    Should Be Equal As Integers    ${rc}    0    msg=nac/data/devices.nac.yaml differs from Nautobot — run ./lab.sh nautobot render

Golden Config: router backups are in Gitea and every compliance row is compliant
    FOR    ${r}    IN    @{ROUTER_NAMES}
        ${raw}=    Evaluate    __import__('requests').get('http://10.0.0.10:3000/api/v1/repos/lab/config-backups/raw/${r}.cfg', timeout=30).text
        Should Contain    ${raw}    hostname ${r}
        Should Contain    ${raw}    tunnel mode ipsec ipv4
    END
    ${cc}=    Nautobot Get    plugins/golden-config/config-compliance/    location=${NAUTOBOT_LOCATION}    limit=200
    Should Be True    ${cc}[count] >= 45    msg=expected 15 features x 3 routers, got ${cc}[count]
    FOR    ${row}    IN    @{cc}[results]
        Should Be True    ${row}[compliance]    msg=non-compliant: ${row}[device] ${row}[rule] missing=${row}[missing] extra=${row}[extra]
    END
