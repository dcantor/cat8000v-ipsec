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
