*** Settings ***
Documentation     The DCI chain off west-headend: ACME's data-centre interconnect (DCI) and the acquired company's edge router
...               (ACME-acquisition) behind it. They carry no IPsec — west-headend <-> DCI <-> ACME-acquisition are direct /30 links
...               with plain eBGP — and the acquisition originates its own prefixes (its site LAN and a service prefix on a loopback),
...               which must be routable from every branch over the VPN. Modelled in Nautobot like everything else (devices, cables,
...               prefixes, BGP peerings, tenants) and rendered by the same NaC pipeline and Golden Config template.
Resource          ../resources/common.resource
Library           OperatingSystem
Library           ../../tools/host_cmd.py
Suite Setup       Skip If    not $EDGE_ROUTERS    no DCI chain in this lab
Suite Teardown    Suite Teardown Close Connections

*** Test Cases ***
The DCI chain is modelled in Nautobot: roles, tenants, cabled links, prefixes and the acquisition's own service prefix
    [Documentation]    ACME owns the DCI (tenant ACME Networks, role vpn-dci); the acquired company is a customer tenant of its own on a
    ...    partner-edge router. The two links are cables between router ports (no firewall in between) and their /30s are modelled.
    ${q}=    Catenate    { devices(location: ["${NAUTOBOT_LOCATION}"]) { name role { name } tenant { name tenant_group { name } } _custom_field_data
    ...    interfaces { name enabled description ip_addresses { address parent { prefix tags { name } } } connected_interface { name device { name } } } } }
    ${d}=    Nautobot Graphql    ${q}
    ${by}=    Evaluate    {x['name']: x for x in $d['devices']}
    FOR    ${r}    IN    @{EDGE_NAMES}
        Dictionary Should Contain Key    ${by}    ${r}    msg=${r} is not in Nautobot
        ${want}=    Set Variable If    '${EDGE_ROUTERS}[${r}][role]' == 'dci'    vpn-dci    partner-edge
        Should Be Equal    ${by}[${r}][role][name]    ${want}
        ${tenant}=    Set Variable If    '${EDGE_ROUTERS}[${r}][role]' == 'dci'    ${PROVIDER}[name]    ${CUSTOMERS_ALL}[${r}][company]
        Should Be Equal    ${by}[${r}][tenant][name]    ${tenant}    msg=${r}: wrong tenant
        ${group}=    Set Variable If    '${EDGE_ROUTERS}[${r}][role]' == 'dci'    ${PROVIDER}[group]    Customers
        Should Be Equal    ${by}[${r}][tenant][tenant_group][name]    ${group}
        Should Be Equal    ${by}[${r}][_custom_field_data][acme_design_pattern]    ${PATTERNS}[${r}][name]
    END
    # the two direct links: both ends are routers, addressed from the /30 and cabled to each other
    FOR    ${p}    IN    @{DIRECT_PEERINGS}
        ${ia}=    Evaluate    [i for i in $by[$p['a']]['interfaces'] if i['name'] == 'GigabitEthernet' + str($p['a_port'])][0]
        ${ib}=    Evaluate    [i for i in $by[$p['b']]['interfaces'] if i['name'] == 'GigabitEthernet' + str($p['b_port'])][0]
        Should Be Equal    ${ia}[ip_addresses][0][address]    ${p}[a_ip]/30
        Should Be Equal    ${ib}[ip_addresses][0][address]    ${p}[b_ip]/30
        Should Be Equal    ${ia}[connected_interface][device][name]    ${p}[b]    msg=${p}[a] Gi${p}[a_port] is not cabled to ${p}[b]
        Should Be Equal    ${ib}[connected_interface][device][name]    ${p}[a]
        Should Be Equal    ${ia}[ip_addresses][0][parent][prefix]    ${p}[prefix]
    END
    # the acquisition's service prefix: an extra loopback, tagged for advertisement like every other originated prefix
    FOR    ${r}    IN    @{EDGE_NAMES}
        FOR    ${lo}    IN    @{EXTRA_LOOPBACKS}[${r}]
            ${i}=    Evaluate    [i for i in $by[$r]['interfaces'] if i['name'] == $lo['name']][0]
            Should Be Equal    ${i}[ip_addresses][0][address]    ${lo}[address]
            Should Contain    ${{ [t['name'] for t in $i['ip_addresses'][0]['parent']['tags']] }}    bgp:advertise
            ...    msg=${r}/${lo}[name]: the prefix is not tagged for advertisement
        END
    END

The interconnect links are up with the modelled addresses, no IPsec anywhere on them, and the neighbour answers
    [Documentation]    Plain routed links: the addresses come from the model, the far end pings, and neither router holds a tunnel,
    ...    a crypto profile or a keyring — the encryption stops at the headends.
    FOR    ${p}    IN    @{DIRECT_PEERINGS}
        ${brief}=    Show    ${p}[a]    show ip interface brief | include GigabitEthernet${p}[a_port]
        Should Match Regexp    ${brief}    GigabitEthernet${p}[a_port]\\s+${p}[a_ip]\\s+YES\\s+\\S+\\s+up\\s+up
        ${brief}=    Show    ${p}[b]    show ip interface brief | include GigabitEthernet${p}[b_port]
        Should Match Regexp    ${brief}    GigabitEthernet${p}[b_port]\\s+${p}[b_ip]\\s+YES\\s+\\S+\\s+up\\s+up
        ${ping}=    Show    ${p}[a]    ping ${p}[b_ip] source GigabitEthernet${p}[a_port] repeat 3
        Should Match Regexp    ${ping}    Success rate is (100|66) percent    msg=${p}[a] cannot reach ${p}[b] over ${p}[prefix]
    END
    FOR    ${r}    IN    @{EDGE_NAMES}
        ${run}=    Show    ${r}    show running-config | include ^interface Tunnel|^crypto ike|^crypto ipsec|tunnel protection|^crypto pki trustpoint ${PKI}[trustpoint]
        Should Be Empty    ${run.strip()}    msg=${r} carries VPN crypto or a tunnel — the DCI chain is plain eBGP: ${run}
    END

eBGP is Established on every hop of the chain with the modelled AS numbers
    [Documentation]    west-headend <-> DCI <-> ACME-acquisition: one session per link, over the link addresses (not loopbacks),
    ...    each with the AS from the model — the same nautobot-bgp-models peerings the tunnels use, just over a direct link.
    FOR    ${p}    IN    @{DIRECT_PEERINGS}
        ${sum}=    Show    ${p}[a]    show ip bgp summary
        Should Match Regexp    ${sum}    (?m)^${p}[b_ip]\\s+4\\s+${ALL_ROUTERS}[${p}[b]][asn]\\s+\\d+\\s+\\d+\\s+\\d+\\s+\\d+\\s+\\d+\\s+\\S+\\s+\\d+
        ...    msg=${p}[a]: the session to ${p}[b] (${p}[b_ip], AS ${ALL_ROUTERS}[${p}[b]][asn]) is not Established
        ${sum}=    Show    ${p}[b]    show ip bgp summary
        Should Match Regexp    ${sum}    (?m)^${p}[a_ip]\\s+4\\s+${ALL_ROUTERS}[${p}[a]][asn]\\s+\\d+\\s+\\d+\\s+\\d+\\s+\\d+\\s+\\d+\\s+\\S+\\s+\\d+
        ...    msg=${p}[b]: the session to ${p}[a] (${p}[a_ip], AS ${ALL_ROUTERS}[${p}[a]][asn]) is not Established
        ${run}=    Show    ${p}[a]    show running-config | section router bgp
        Should Contain    ${run}    neighbor ${p}[b_ip] remote-as ${ALL_ROUTERS}[${p}[b]][asn]
    END

The acquisition originates its prefixes and every branch learns them through its headend
    [Documentation]    The site LAN and the service prefix on the loopback are `network`ed by ACME-acquisition, cross the DCI into
    ...    west-headend's AS and are re-advertised over the tunnels: every branch has them via one of its headends and can reach them.
    ${acq}=    Evaluate    [n for n, r in $EDGE_ROUTERS.items() if r['role'] == 'partner'][0]
    ${run}=    Show    ${acq}    show running-config | section address-family ipv4
    FOR    ${p}    IN    @{ACQUISITION_PREFIXES}
        ${net}=    Evaluate    $p.split('/')[0]
        Should Contain    ${run}    network ${net}    msg=${acq} does not originate ${p}
    END
    FOR    ${s}    IN    @{SPOKES}
        ${rt}=    Show    ${s}    show ip route bgp
        FOR    ${p}    IN    @{ACQUISITION_PREFIXES}
            ${net}=    Evaluate    $p.split('/')[0]
            Should Contain    ${rt}    ${net}    msg=${s} has no route to the acquisition prefix ${p}
        END
        ${line}=    Get Lines Containing String    ${rt}    ${{ $ACQUISITION_PREFIXES[0].split('/')[0] }}
        ${ok}=    Evaluate    any(t['hub_ip'] in """${line}""" for t in $TUNNEL_LIST if t['spoke'] == """${s}""")
        Should Be True    ${ok}    msg=${s}: the acquisition prefix must come from one of its headends: ${line}
    END

A branch reaches the acquisition's LAN and its service prefix, and the acquisition reaches every branch
    [Documentation]    End to end over IPsec + the DCI: a branch pings both acquisition prefixes from its own LAN address, and the
    ...    acquisition's host reaches every branch host (the ping mesh of suite 09 covers the reverse direction as well).
    ${acq}=    Evaluate    [n for n, r in $EDGE_ROUTERS.items() if r['role'] == 'partner'][0]
    ${targets}=    Set Variable    ${ACQUISITION_IPS}
    FOR    ${s}    IN    @{SPOKES}
        FOR    ${t}    IN    @{targets}
            ${ping}=    Show    ${s}    ping ${t} source ${ROUTERS}[${s}][lan_if] repeat 3
            Should Match Regexp    ${ping}    Success rate is (100|66) percent    msg=${s} cannot reach ${t} (the acquisition, over the DCI)
        END
    END
    FOR    ${s}    IN    @{SPOKES}
        # a branch whose LAN the acquired company also uses is reached through the NAT instead (the next test) — its real
        # address is not routable from here, and that is the point of the translation
        Continue For Loop If    '${ROUTERS}[${s}][lan]' in ${{ [o['prefix'] for o in $OVERLAPS] }}
        ${ping}=    Show    ${acq}    ping ${ROUTERS}[${s}][lan_ip] source ${EDGE_ROUTERS}[${acq}][lan_if] repeat 3
        Should Match Regexp    ${ping}    Success rate is (100|66) percent    msg=${acq} cannot reach ${s}'s LAN
    END

The host behind the acquisition is in the mesh and breaks out to the internet through west-headend
    [Documentation]    Its default route comes from the headend over eBGP (it has no breakout preference of its own), so the path runs
    ...    acquisition -> DCI -> west-headend -> the firewall that NATs.
    ${acq}=    Evaluate    [n for n, r in $EDGE_ROUTERS.items() if r['role'] == 'partner'][0]
    ${host}=    Set Variable    ${HOST_OF}[${acq}]
    ${rc}    ${out}=    Run    ${LAN_HOSTS}[${host}][host]    ping -c 3 -W 2 1.1.1.1; traceroute -n -w 2 -q 1 -m 6 1.1.1.1
    Should Match Regexp    ${out}    3 packets transmitted, [23] packets received    msg=${host}: no internet: ${out}
    ${dci_ip}=    Evaluate    [p['a_ip'] for p in $DIRECT_PEERINGS if p['b'] == $acq][0]
    Should Contain    ${out}    ${dci_ip}    msg=${host}: the path must cross the DCI: ${out}
    ${hub_ip}=    Evaluate    [p['a_ip'] for p in $DIRECT_PEERINGS if p['b'] == 'DCI'][0]
    Should Contain    ${out}    ${hub_ip}    msg=${host}: the path must reach the headend that breaks out: ${out}
    FOR    ${h}    IN    @{LAN_HOSTS}
        Continue For Loop If    '${h}' == '${host}'
        ${rc}    ${out}=    Run    ${LAN_HOSTS}[${host}][host]    ping -c 2 -W 2 ${LAN_HOSTS}[${h}][lan_ip]
        Should Contain    ${out}    2 packets received    msg=${host} cannot reach ${h} (${LAN_HOSTS}[${h}][lan_ip])
    END

Golden Config renders the DCI chain from the same template and reports it compliant
    [Documentation]    The two routers are in the Golden Config scope like every other Catalyst 8000v: the template renders them without
    ...    a crypto section (they have no VPN profile) and every compliance feature matches.
    ${c}=    Portal Get    /api/compliance
    FOR    ${r}    IN    @{EDGE_NAMES}
        ${d}=    Evaluate    [x for x in $c['devices'] if x['name'] == $r][0]
        Should Be True    ${d}[total] > 0    msg=${r} has no compliance rows — the intended configuration was not rendered
        Should Be True    ${d}[ok]    msg=${r} is not compliant: ${{ [f for f, v in $d['features'].items() if not v['compliant']] }}
        Should Be Equal As Integers    ${d}[compliant]    ${d}[total]
    END

The overlapping prefix exists on both sides of the DCI and neither side learns the other's copy
    [Documentation]    The acquired company runs a server on a prefix ACME already uses (a branch LAN). The DCI filters that prefix in
    ...    both directions — each side keeps exactly one path for it, its own — and advertises the translated range instead.
    Skip If    not $OVERLAPS    no overlapping prefix is modelled
    ${ov}=    Set Variable    ${OVERLAPS}[0]
    ${acq}=    Evaluate    [n for n, r in $EDGE_ROUTERS.items() if r['role'] == 'partner'][0]
    # both sides really do use the same prefix
    ${run}=    Show    ${acq}    show running-config | section interface Loopback2
    Should Contain    ${run}    ip address ${{ str(__import__('ipaddress').ip_network($ov['prefix'])[2]) }}    msg=the acquisition has no server on the overlapping prefix
    ${own}=    Evaluate    [n for n, r in $ROUTERS.items() if r['lan'] == $ov['prefix']][0]
    Should Be Equal    ${ROUTERS}[${own}][lan]    ${ov}[prefix]    msg=${ov}[prefix] must be an ACME branch LAN as well
    # the DCI keeps one path for it: the acquisition's, because ACME's copy is filtered inbound
    ${rt}=    Show    ${NAT_ROUTER}    show ip route ${{ $ov['prefix'].split('/')[0] }} ${{ str(__import__('ipaddress').ip_network($ov['prefix']).netmask) }}
    ${inside_peer}=    Evaluate    [p['b_ip'] for p in $DIRECT_PEERINGS if p['a'] == $NAT_ROUTER][0]
    Should Contain    ${rt}    ${inside_peer}    msg=the DCI must reach ${ov}[prefix] through the acquisition, not through ACME: ${rt}
    ${run}=    Show    ${NAT_ROUTER}    show running-config | include ^ip prefix-list OVERLAP|route-map NO-OVERLAP
    Should Contain    ${run}    ip prefix-list OVERLAP seq 5 permit ${ov}[prefix]
    # ACME never hears the acquisition's copy, and the acquisition never hears ACME's
    FOR    ${s}    IN    @{SPOKES}
        ${b}=    Show    ${s}    show ip bgp ${ov}[prefix]
        Should Not Contain    ${b}    ${{ [p['b_ip'] for p in $DIRECT_PEERINGS if p['a'] == 'DCI'][0] }}    msg=${s} learned the acquisition's copy of ${ov}[prefix]
    END
    ${b}=    Show    ${acq}    show ip route ${{ $ov['prefix'].split('/')[0] }} ${{ str(__import__('ipaddress').ip_network($ov['prefix']).netmask) }}
    Should Contain    ${b}    directly connected    msg=${acq} must only know its own ${ov}[prefix]: ${b}

The DCI translates in both directions: each side reaches the other through the range it was given
    [Documentation]    ACME reaches the acquisition's server at the inside-global address and the acquisition reaches ACME's host at the
    ...    outside-local one; the translations show up in the NAT table with both halves.
    Skip If    not $OVERLAPS    no overlapping prefix is modelled
    ${ov}=    Set Variable    ${OVERLAPS}[0]
    ${acq}=    Evaluate    [n for n, r in $EDGE_ROUTERS.items() if r['role'] == 'partner'][0]
    ${own}=    Evaluate    [n for n, r in $ROUTERS.items() if r['lan'] == $ov['prefix']][0]
    ${acq_as_acme_sees_it}=    Evaluate    str(__import__('ipaddress').ip_network($ov['inside_global'])[2])
    ${acme_as_acq_sees_it}=    Evaluate    str(__import__('ipaddress').ip_network($ov['outside_local'])[2])
    # ACME -> the acquisition (the branch router and the host behind it)
    ${p}=    Show    ${own}    ping ${acq_as_acme_sees_it} source ${ROUTERS}[${own}][lan_if] repeat 3
    Should Match Regexp    ${p}    Success rate is (100|66) percent    msg=${own} cannot reach the acquisition at ${acq_as_acme_sees_it}
    ${rc}    ${out}=    Run    ${LAN_HOSTS}[${HOST_OF}[${own}]][host]    ping -c 3 -W 2 ${acq_as_acme_sees_it}
    Should Contain    ${out}    3 packets received    msg=${HOST_OF}[${own}] cannot reach the acquisition at ${acq_as_acme_sees_it}: ${out}
    # the acquisition -> ACME
    ${p}=    Show    ${acq}    ping ${acme_as_acq_sees_it} source Loopback2 repeat 3
    Should Match Regexp    ${p}    Success rate is (100|66) percent    msg=${acq} cannot reach ACME's ${own} host at ${acme_as_acq_sees_it}
    # and the NAT table holds both halves of the translation
    ${t}=    Show    ${NAT_ROUTER}    show ip nat translations
    Should Contain    ${t}    ${acq_as_acme_sees_it}    msg=no inside-global entry for the acquisition's server
    Should Contain    ${t}    ${acme_as_acq_sees_it}    msg=no outside-local entry for ACME's host
    ${run}=    Show    ${NAT_ROUTER}    show running-config | include ^ip nat (inside|outside) source
    Should Contain    ${run}    ip nat inside source static network ${{ $ov['prefix'].split('/')[0] }} ${{ $ov['inside_global'].split('/')[0] }}
    Should Contain    ${run}    ip nat outside source static network ${{ $ov['prefix'].split('/')[0] }} ${{ $ov['outside_local'].split('/')[0] }}

DNS is fixed up on the way through the NAT: a name that resolves to an overlapping address comes back translated
    [Documentation]    ACME's headend answers for its own zone; the acquisition resolves a name whose A record is an address that exists
    ...    on both sides, and the DCI's NAT rewrites the answer to the range the acquisition can actually reach.
    Skip If    not $DNS_SERVER or not $DNS_CLIENT    no DNS zone or resolver is modelled
    ${acq}=    Evaluate    [n for n in $DNS_CLIENT][0]
    ${ov}=    Set Variable    ${OVERLAPS}[0]
    # the server answers for the zone, and holds a record that points into the overlapping prefix
    ${run}=    Show    ${DNS_SERVER}    show running-config | include ^ip dns server|^ip host
    Should Contain    ${run}    ip dns server
    ${name}=    Evaluate    [h for h, a in $DNS_ZONE['hosts'].items() if __import__('ipaddress').ip_address(a) in __import__('ipaddress').ip_network($ov['prefix'])][0]
    ${real}=    Set Variable    ${DNS_ZONE}[hosts][${name}]
    Should Contain    ${run}    ip host ${name}.${DNS_ZONE}[domain] ${real}
    # the client asks through the NAT and gets the translated address back
    ${cfg}=    Show    ${acq}    show running-config | include ^ip name-server|^ip domain lookup source
    Should Contain    ${cfg}    ip name-server ${DNS_CLIENT}[${acq}][server]
    ${translated}=    Evaluate    str(__import__('ipaddress').ip_network($ov['outside_local'])[int($real.split('.')[-1])])
    ${p}=    Show    ${acq}    ping ${name}.${DNS_ZONE}[domain] source ${DNS_CLIENT}[${acq}][source_interface] repeat 3
    Should Contain    ${p}    ${translated}    msg=the DNS answer was not fixed up: the name should resolve to ${translated}, not ${real} — ${p}
    Should Match Regexp    ${p}    Success rate is (100|66) percent    msg=${acq} resolved the name but could not reach it: ${p}
