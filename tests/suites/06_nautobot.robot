*** Settings ***
Documentation     The IPsec lab as modelled in the shared Nautobot: devices match the routers, p2p links are cabled,
...               the VPN lives in the core VPN app (VPN, tunnels, hub/spoke endpoints, profile with Phase 1/2 policies),
...               eBGP peerings match the live sessions, the rendered NAC device model matches the committed file,
...               Golden Config is compliant.
Resource          ../resources/common.resource
Suite Teardown    Suite Teardown Close Connections

*** Test Cases ***
Routers exist in Nautobot with role, serial, platform and management IP matching reality
    FOR    ${r}    IN    @{ROUTER_NAMES}
        ${d}=    Nautobot Get    dcim/devices/    name=${r}    depth=1
        Should Be Equal As Integers    ${d}[count]    1
        ${dev}=    Set Variable    ${d}[results][0]
        Should Be Equal    ${dev}[location][name]    ${ROUTERS}[${r}][site]    msg=${r} must live at its branch/HQ location
        Should Be Equal    ${dev}[role][name]    vpn-${ROUTERS}[${r}][role]
        Should Be Equal    ${dev}[device_type][model]    C8000V
        Should Be Equal    ${dev}[platform][name]    cisco_xe
        Should Be Equal    ${dev}[primary_ip4][host]    ${ROUTERS}[${r}][host]
        ${ver}=    Show    ${r}    show version | include Processor board ID
        Should Contain    ${ver}    ${dev}[serial]
    END

WAN links are modelled as cables: spoke port to the headend's firewall, firewall to the headend, /30 addresses
    FOR    ${t}    IN    @{TUNNEL_LIST}
        ${far}=    Set Variable If    $t['firewall']    ${t}[firewall]    ${t}[hub]
        ${far_if}=    Set Variable If    $t['firewall']    ${t}[fw_spoke_if]    ${t}[hub_if]
        ${d}=    Nautobot Graphql    { interfaces(device:["${t}[spoke]"], name:"${t}[spoke_if]") { enabled description ip_addresses { address parent { prefix role { name } } } connected_interface { name device { name } ip_addresses { address } } } }
        ${i}=    Set Variable    ${d}[interfaces][0]
        Should Be True    ${i}[enabled]
        Should Be Equal    ${i}[description]    WAN to ${far} ${far_if}
        Should Be Equal    ${i}[ip_addresses][0][address]    ${t}[spoke_wan]/30
        Should Be Equal    ${i}[ip_addresses][0][parent][prefix]    ${t}[wan_prefix]
        Should Be Equal    ${i}[ip_addresses][0][parent][role][name]    wan-p2p
        Should Be Equal    ${i}[connected_interface][device][name]    ${far}
        Should Be Equal    ${i}[connected_interface][name]    ${far_if}
        Should Be Equal    ${i}[connected_interface][ip_addresses][0][address]    ${t}[spoke_gw]/30
        IF    $t['firewall']
            ${d}=    Nautobot Graphql    { interfaces(device:["${t}[hub]"], name:"${t}[hub_if]") { enabled ip_addresses { address parent { prefix } } connected_interface { name device { name } ip_addresses { address } } } }
            ${h}=    Set Variable    ${d}[interfaces][0]
            Should Be Equal    ${h}[ip_addresses][0][address]    ${t}[hub_wan]/30
            Should Be Equal    ${h}[connected_interface][device][name]    ${t}[firewall]
            Should Be Equal    ${h}[connected_interface][name]    ${t}[fw_hub_if]
        END
    END
    ${d}=    Nautobot Graphql    { interfaces(device:[${ROUTER_GQL}], description:"unwired") { device { name } name enabled } }
    FOR    ${i}    IN    @{d}[interfaces]
        Should Not Be True    ${i}[enabled]    msg=${i}[device][name]/${i}[name] is unwired but enabled
    END

The VPN is modelled in Nautobot's core VPN app: one VPN, one tunnel per hub/spoke pair, hub/spoke endpoints
    ${d}=    Nautobot Graphql    { vpns(name:"${VPN_NAME}") { name service_type status { name } vpn_profile { name } vpn_tunnels { name tunnel_id encapsulation status { name } vpn_profile { name } endpoint_a { device { name } role { name } source_interface { name } source_ipaddress { address interfaces { name } } tunnel_interface { name type ip_addresses { address } } protected_prefixes { prefix } } endpoint_z { device { name } role { name } source_interface { name } source_ipaddress { address interfaces { name } } tunnel_interface { name type ip_addresses { address } } protected_prefixes { prefix } } } } }
    Length Should Be    ${d}[vpns]    1
    ${vpn}=    Set Variable    ${d}[vpns][0]
    Should Be Equal    ${vpn}[service_type]    IPSEC
    Should Be Equal    ${vpn}[status][name]    Active
    Should Be Equal    ${vpn}[vpn_profile][name]    ${IPSEC_PROFILE}
    Length Should Be    ${vpn}[vpn_tunnels]    ${{ len($TUNNEL_LIST) }}
    FOR    ${t}    IN    @{vpn}[vpn_tunnels]
        ${s}=    Set Variable    ${t}[endpoint_z][device][name]
        ${h}=    Set Variable    ${t}[endpoint_a][device][name]
        ${x}=    Evaluate    [x for x in $TUNNEL_LIST if x['hub'] == $h and x['spoke'] == $s][0]
        Should Be Equal    ${t}[name]    ${h}-${s}
        Should Be Equal    ${t}[tunnel_id]    ${x}[id]
        Should Be Equal    ${t}[encapsulation]    IPSEC_TUNNEL
        Should Be Equal    ${t}[status][name]    Active
        Should Be Equal    ${t}[vpn_profile][name]    ${VPN_PROFILE}
        # endpoint A = hub: source GiN with the WAN address, tunnel interface TunnelN, protects its LAN + loopback
        ${a}=    Set Variable    ${t}[endpoint_a]
        Should Be Equal    ${a}[role][name]    hub
        # a headend behind a firewall sources every tunnel from one WAN interface: the endpoint carries the address, the interface follows from it
        ${a_src}=    Set Variable If    $a['source_interface']    ${a}[source_interface][name]    ${a}[source_ipaddress][interfaces][0][name]
        Should Be Equal    ${a_src}    ${x}[hub_if]
        Should Be Equal    ${a}[source_ipaddress][address]    ${x}[hub_wan]/30
        Should Be Equal    ${a}[tunnel_interface][name]    Tunnel${x}[id]
        Should Be Equal    ${a}[tunnel_interface][type]    TUNNEL
        Should Be Equal    ${a}[tunnel_interface][ip_addresses][0][address]    ${x}[hub_ip]/30
        ${pfx}=    Evaluate    sorted(p['prefix'] for p in $a['protected_prefixes'])
        Should Be Equal    ${pfx}    ${{ sorted([$ROUTERS[$h]['router_id'] + '/32', $ROUTERS[$h]['lan']]) }}
        # endpoint Z = the spoke
        ${z}=    Set Variable    ${t}[endpoint_z]
        Should Be Equal    ${z}[role][name]    spoke
        Should Be Equal    ${z}[source_interface][name]    ${x}[spoke_if]
        Should Be Equal    ${z}[source_ipaddress][address]    ${x}[spoke_wan]/30
        Should Be Equal    ${z}[tunnel_interface][name]    Tunnel${x}[id]
        Should Be Equal    ${z}[tunnel_interface][ip_addresses][0][address]    ${x}[spoke_ip]/30
        ${pfx}=    Evaluate    sorted(p['prefix'] for p in $z['protected_prefixes'])
        Should Be Equal    ${pfx}    ${{ sorted([$ROUTERS[$s]['router_id'] + '/32', $ROUTERS[$s]['lan']]) }}
        # each router's tunnel destination is exactly the other endpoint's source address in the model
        ${cfg}=    Show    ${h}    show run interface Tunnel${x}[id] | include tunnel destination|tunnel source|tunnel mode
        Should Contain    ${cfg}    tunnel source ${a_src}
        Should Contain    ${cfg}    tunnel destination ${{ $z['source_ipaddress']['address'].split('/')[0] }}
        Should Contain    ${cfg}    tunnel mode ipsec ipv4
        ${cfg}=    Show    ${s}    show run interface Tunnel${x}[id] | include tunnel destination|tunnel source|tunnel mode
        Should Contain    ${cfg}    tunnel source ${z}[source_interface][name]
        Should Contain    ${cfg}    tunnel destination ${{ $a['source_ipaddress']['address'].split('/')[0] }}
        Should Contain    ${cfg}    tunnel mode ipsec ipv4
    END
    # the old interface-level modelling is gone from this lab
    ${d}=    Nautobot Graphql    { interfaces(device:[${ROUTER_GQL}], type:"tunnel") { cf_tunnel_mode cf_tunnel_ipsec_profile rel_tunnel_source_source { name } } }
    FOR    ${i}    IN    @{d}[interfaces]
        Should Be Equal    ${i}[cf_tunnel_mode]    ${None}
        Should Be Equal    ${i}[cf_tunnel_ipsec_profile]    ${None}
        Should Be Equal    ${i}[rel_tunnel_source_source]    ${None}
    END

Locations form the hierarchy lab site -> region -> branch, with site metadata on the branch
    ${d}=    Nautobot Graphql    { locations(location_type:"Branch") { name cf_site_code cf_contact parent { name location_type { name } parent { name } } devices { name } } }
    FOR    ${r}    IN    @{ROUTER_NAMES}
        ${br}=    Evaluate    [l for l in $d['locations'] if l['name'] == $ROUTERS[$r]['site']][0]
        Should Be Equal    ${br}[parent][name]    ${ROUTERS}[${r}][region]
        Should Be Equal    ${br}[parent][location_type][name]    Region
        Should Be Equal    ${br}[parent][parent][name]    ${NAUTOBOT_LOCATION}
        Should Be Equal    ${br}[cf_site_code]    ${ROUTERS}[${r}][site_code]
        Should Contain    ${{ [x['name'] for x in $br['devices']] }}    ${r}
    END
    ${rg}=    Nautobot Graphql    { locations(location_type:"Region") { name } }
    Should Be Equal    ${{ sorted([l["name"] for l in $rg["locations"]]) }}    ${{ sorted($REGIONS) }}

Every spoke uses its own pre-shared key on all of its tunnels and each headend keys per spoke
    [Documentation]    PSK mode only: with certificates (suite 08) no keyring exists on any router.
    Skip If    '${IKE_AUTH}' == 'certificate'    IKE authenticates with certificates: no pre-shared keys on the routers (suite 08 proves the keyrings are gone)
    FOR    ${s}    IN    @{SPOKES}
        ${kr}=    Show    ${s}    show run | section crypto ikev2 keyring
        FOR    ${t}    IN    @{SPOKE_TUNNELS}[${s}]
            Should Match Regexp    ${kr}    (?s)peer ${t}[hub]\\s+address ${t}[hub_wan]\\s+pre-shared-key ${ROUTERS}[${s}][psk]
        END
        FOR    ${o}    IN    @{SPOKES}
            Continue For Loop If    '${s}' == '${o}'
            Should Not Contain    ${kr}    ${ROUTERS}[${o}][psk]    msg=${s} must not know ${o}'s key
        END
    END
    FOR    ${h}    IN    @{HUBS}
        ${kr}=    Show    ${h}    show run | section crypto ikev2 keyring
        FOR    ${t}    IN    @{HUB_TUNNELS}[${h}]
            Should Match Regexp    ${kr}    (?s)peer ${t}[spoke]\\s+address ${t}[spoke_wan]\\s+pre-shared-key ${ROUTERS}[${t}[spoke]][psk]
        END
        Should Not Contain    ${kr}    address 0.0.0.0    msg=${h} still has the wildcard peer
    END

The IKEv2/IPsec suite comes from the VPN profile's Phase 1 / Phase 2 policies and matches the routers
    ${d}=    Nautobot Graphql    { vpn_profiles(name:"${VPN_PROFILE}") { name keepalive_enabled keepalive_interval keepalive_retries extra_options vpn_phase1_policies { name ike_version encryption_algorithm integrity_algorithm dh_group lifetime_seconds authentication_method } vpn_phase2_policies { name encryption_algorithm integrity_algorithm lifetime } } }
    Length Should Be    ${d}[vpn_profiles]    1
    ${prof}=    Set Variable    ${d}[vpn_profiles][0]
    ${ios}=    Set Variable    ${prof}[extra_options][ios]
    Should Be Equal    ${ios}[ikev2_profile]    ${IKEV2_PROFILE}
    Should Be Equal    ${ios}[ipsec_profile]    ${IPSEC_PROFILE}
    ${p1}=    Set Variable    ${prof}[vpn_phase1_policies][0]
    ${p2}=    Set Variable    ${prof}[vpn_phase2_policies][0]
    Should Be Equal    ${p1}[ike_version]    IKEV2
    Should Be Equal    ${p1}[authentication_method]    ${{ 'RSA' if $IKE_AUTH == 'certificate' else 'PSK' }}
    Should Be Equal    ${p1}[encryption_algorithm]    ${{ [$IKE['encryption']] }}
    Should Be Equal    ${p1}[integrity_algorithm]    ${{ [$IKE['integrity']] }}
    Should Be Equal    ${p1}[dh_group]    ${{ [str($IKE['dh_group'])] }}
    Should Be Equal    ${p2}[encryption_algorithm]    ${{ [$IPSEC['encryption']] }}
    Should Be Equal    ${p2}[integrity_algorithm]    ${{ [$IPSEC['integrity']] }}
    Should Be Equal    ${prof}[keepalive_enabled]    ${DPD}[enabled]
    FOR    ${r}    IN    @{ROUTER_NAMES}
        ${sa}=    Show    ${r}    show crypto ikev2 proposal ${ios}[ikev2_proposal]
        Should Contain    ${sa}    Encryption : ${IKE_PROPOSAL_ENCR}
        Should Contain    ${sa}    Integrity  : ${IKE}[integrity]
        Should Match Regexp    ${sa}    DH Group   : \\S+/Group ${IKE}[dh_group]\\b
        ${ts}=    Show    ${r}    show crypto ipsec transform-set ${ios}[transform_set]
        Should Match Regexp    ${ts}    \\{ ${ESP_TRANSFORM}\\s*\\}
        ${prof_out}=    Show    ${r}    show crypto ikev2 profile ${ios}[ikev2_profile]
        Should Contain    ${prof_out}    ${{ 'Keyring: none' if $IKE_AUTH == 'certificate' else 'Keyring: ' + $ios['ikev2_keyring'] }}
        IF    ${prof}[keepalive_enabled]
            Should Contain    ${prof_out}    DPD: interval ${prof}[keepalive_interval], retry-interval ${prof}[keepalive_retries], on-demand
        END
        ${sa}=    Show    ${r}    show crypto ikev2 sa | include READY
        Should Match Regexp    ${sa}    READY
    END
    ${d}=    Nautobot Graphql    { devices(location:"${NAUTOBOT_LOCATION}") { name config_context } }
    FOR    ${dev}    IN    @{d}[devices]
        Should Be Equal    ${dev}[config_context][oob][gateway]    ${OOB_GATEWAY}
    END

BGP model: one AS per site, eBGP peerings over the tunnel addresses matching the live sessions
    ${d}=    Nautobot Graphql    { bgp_routing_instances(device:[${ROUTER_GQL}]) { device { name } autonomous_system { asn } router_id { address } endpoints { source_ip { address } autonomous_system { asn } peer { source_ip { address } autonomous_system { asn } routing_instance { device { name } } } } } }
    Length Should Be    ${d}[bgp_routing_instances]    ${{ len($ROUTER_NAMES) }}
    FOR    ${ri}    IN    @{d}[bgp_routing_instances]
        ${r}=    Set Variable    ${ri}[device][name]
        Should Be Equal As Integers    ${ri}[autonomous_system][asn]    ${ROUTERS}[${r}][asn]
        Should Be Equal    ${ri}[router_id][address]    ${ROUTERS}[${r}][router_id]/32
        ${expected}=    Evaluate    len($HUB_TUNNELS.get($r, [])) or len($SPOKE_TUNNELS.get($r, []))
        ${foreign}=    Evaluate    [e for e in $ri["endpoints"] if e["peer"] and e["peer"]["routing_instance"]["device"]["name"] not in $ROUTERS]    # another lab's attachment (the SRv6 core on a headend)
        Should Be True    len($foreign) <= 1    msg=${r}: more than one foreign peering
        Length Should Be    ${ri}[endpoints]    ${{ $expected + len($foreign) }}
        ${sum}=    Show    ${r}    show bgp ipv4 unicast summary | begin Neighbor
        FOR    ${ep}    IN    @{ri}[endpoints]
            Should Be Equal As Integers    ${ep}[autonomous_system][asn]    ${ROUTERS}[${r}][asn]
            ${peer}=    Set Variable    ${ep}[peer][routing_instance][device][name]
            Should Not Be Equal As Integers    ${ep}[peer][autonomous_system][asn]    ${ROUTERS}[${r}][asn]    msg=peering must be eBGP
            ${peer_asn}=    Evaluate    $ROUTERS[$peer]["asn"] if $peer in $ROUTERS else $ep["peer"]["autonomous_system"]["asn"]
            Should Be Equal As Integers    ${ep}[peer][autonomous_system][asn]    ${peer_asn}
            ${peer_ip}=    Fetch From Left    ${ep}[peer][source_ip][address]    /
            Should Match Regexp    ${sum}    (?m)^${peer_ip}\\s+4\\s+${peer_asn}\\s+.*\\s\\d+\\s*$    msg=${r}: session to ${peer_ip} (${peer}) not Established
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
