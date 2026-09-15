*** Settings ***
Documentation     The VyOS firewall in front of each headend: modelled in Nautobot, configured from it, and actually
...               filtering: only IKEv2, ESP and ICMP cross between the spokes and the headend; anything else is dropped.
Resource          ../resources/common.resource
Library           OperatingSystem
Suite Teardown    Suite Teardown Close Connections

*** Test Cases ***
Each headend has exactly one firewall, reachable over the OOB network with SSH
    ${hubs}=    Evaluate    sorted($FIREWALL_OF)
    Should Be Equal    ${hubs}    ${HUBS}    msg=every headend must have a firewall
    FOR    ${f}    IN    @{FIREWALLS}
        Host Ping    ${FIREWALLS}[${f}][host]
        Tcp Port Should Be Open    ${FIREWALLS}[${f}][host]    22
        ${v}=    Vyos    ${f}    show version | match Version
        Should Contain    ${v}    VyOS
        ${h}=    Vyos    ${f}    show configuration commands | match host-name
        Should Contain    ${h}    host-name '${f}'
    END

Firewall interfaces carry the modelled addresses and face the right neighbours
    FOR    ${t}    IN    @{TUNNEL_LIST}
        ${ifs}=    Vyos    ${t}[firewall]    show interfaces
        Should Match Regexp    ${ifs}    (?m)^${t}[fw_spoke_if]\\s+${t}[spoke_gw]/30\\s.*u/u\\s+to ${t}[spoke] ${t}[spoke_if]
        Should Match Regexp    ${ifs}    (?m)^${t}[fw_hub_if]\\s+${t}[hub_gw]/30\\s.*u/u\\s+to ${t}[hub] ${t}[hub_if]
    END
    ${d}=    Nautobot Graphql    { devices(role:["vpn-firewall"], location:["${NAUTOBOT_LOCATION}"]) { name platform { name } location { name } interfaces { name enabled ip_addresses { address } connected_interface { name device { name } } } } }
    Length Should Be    ${d}[devices]    ${{ len($FIREWALLS) }}
    FOR    ${dev}    IN    @{d}[devices]
        Should Be Equal    ${dev}[platform][name]    vyos
        Should Be Equal    ${dev}[location][name]    ${FIREWALLS}[${dev}[name]][site]
        ${wired}=    Evaluate    [i for i in $dev['interfaces'] if i['enabled'] and i['name'] != 'eth0']
        FOR    ${i}    IN    @{wired}
            Should Not Be Equal    ${i}[connected_interface]    ${None}    msg=${dev}[name]/${i}[name] enabled but not cabled
            Length Should Be    ${i}[ip_addresses]    1
        END
    END

The rendered firewall configuration matches what runs on the firewalls
    [Tags]    nac
    ${rc}=    Vyos Check
    Should Be Equal As Integers    ${rc}    0    msg=a firewall drifted from Nautobot — run ./lab.sh nautobot vyos

Only IKEv2, ESP and ICMP cross the firewall; the tunnels actually carry ESP through it
    FOR    ${f}    IN    @{FIREWALLS}
        ${rules}=    Vyos    ${f}    show firewall ipv4 forward filter
        Should Match Regexp    ${rules}    (?m)^10\\s+accept\\s+udp\\s+\\d+\\s+\\S+\\s+udp dport \\{ 500, 4500 \\}
        Should Match Regexp    ${rules}    (?m)^20\\s+accept\\s+esp\\s+[1-9]\\d*\\s    msg=${f}: no ESP packets have crossed
        Should Match Regexp    ${rules}    (?m)^30\\s+accept\\s+icmp
        Should Match Regexp    ${rules}    (?m)^900\\s+drop\\s+all
        Should Match Regexp    ${rules}    (?m)^default\\s+drop
    END

Firewall bandwidth is modelled in Nautobot and bounds the headend capacity together with the tunnel count
    [Documentation]    Every firewall carries custom field firewall_bandwidth_mbps (from the intent); the VPN records the per-tunnel
    ...    commitment; the portal's inventory reports both constraints per headend and the aggregate is the tighter of the two.
    ${vpn}=    Nautobot Get    vpn/vpns/    name=${VPN_NAME}
    ${per}=    Set Variable    ${vpn}[results][0][extra_attributes][bandwidth_per_tunnel_mbps]
    Should Be True    ${per} > 0    msg=the VPN must record what each tunnel commits of the firewall bandwidth
    FOR    ${f}    IN    @{FIREWALLS}
        ${d}=    Nautobot Get    dcim/devices/    name=${f}
        Should Be Equal As Integers    ${d}[results][0][custom_fields][firewall_bandwidth_mbps]    ${FIREWALLS}[${f}][bandwidth_mbps]    msg=${f} bandwidth in Nautobot differs from the intent
    END
    ${inv}=    Portal Inventory
    FOR    ${h}    IN    @{HUBS}
        ${hc}=    Set Variable    ${HEADEND_CAPACITY}[${h}]
        ${row}=    Evaluate    [x for x in $inv["headends"] if x["name"] == $h][0]
        Should Be Equal As Integers    ${row}[tunnels]    ${hc}[tunnels]
        Should Be Equal As Integers    ${row}[bandwidth_mbps]    ${hc}[bandwidth_mbps]
        Should Be Equal As Integers    ${row}[bandwidth_used_mbps]    ${hc}[bandwidth_used_mbps]
        Should Be Equal    ${row}[binding]    ${hc}[binding]
        Should Be Equal As Integers    ${row}[effective_free]    ${hc}[effective_free]
        ${agg}=    Evaluate    max($row["utilisation"], $row["bandwidth_utilisation"])
        Should Be Equal As Numbers    ${row}[aggregate_utilisation]    ${agg}    msg=${h}: aggregate must be the tighter of the two constraints
        Should Be True    ${row}[bandwidth_used_mbps] <= ${row}[bandwidth_mbps]    msg=${h}: tunnels commit more than the firewall carries
    END

Non-VPN traffic from a spoke to a headend is dropped by the firewall
    ${t}=    Set Variable    ${TUNNEL_LIST}[0]
    ${before}=    Drop Counter    ${t}[firewall]
    # SSH from the spoke's WAN address to the headend's WAN address must not get through (only IKE/ESP/ICMP may)
    ${out}=    Show    ${t}[spoke]    telnet ${t}[hub_wan] 22 /source-interface ${t}[spoke_if]    120
    Should Not Contain    ${out}    SSH-2.0    msg=SSH from ${t}[spoke] reached ${t}[hub] through ${t}[firewall]
    Should Match Regexp    ${out}    Connection timed out|Destination unreachable|Connection refused
    Wait Until Keyword Succeeds    30s    5s    Drops Increased    ${t}[firewall]    ${before}

*** Keywords ***
Vyos
    [Arguments]    ${f}    ${command}
    ${out}=    Run Vyos Command    ${FIREWALLS}[${f}][host]    ${command}
    RETURN    ${out}

Drop Counter
    [Arguments]    ${f}
    ${rules}=    Vyos    ${f}    show firewall ipv4 forward filter
    ${m}=    Get Regexp Matches    ${rules}    (?m)^900\\s+drop\\s+all\\s+(\\d+)    1
    RETURN    ${{ int($m[0]) }}

Drops Increased
    [Arguments]    ${f}    ${before}
    ${after}=    Drop Counter    ${f}
    Should Be True    ${after} > ${before}    msg=${f}: drop counter did not increase (${before} -> ${after})
