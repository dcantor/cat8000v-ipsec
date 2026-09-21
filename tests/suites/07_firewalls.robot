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

Only IKEv2, ESP and ICMP cross the firewall, IKEv2 and ESP only between the modelled WAN addresses; the tunnels actually carry ESP through it
    [Documentation]    The address groups HEADEND-WAN / SPOKE-WAN hold exactly the WAN addresses Nautobot models on the far ends of the
    ...    firewall's cables; the IKE / ESP rules reference them in both directions.
    FOR    ${f}    IN    @{FIREWALLS}
        ${rules}=    Vyos    ${f}    show firewall ipv4 forward filter
        Should Match Regexp    ${rules}    (?m)^10\\s+accept\\s+udp\\s+\\d+\\s+\\S+\\s+udp dport \\{ 500, 4500 \\} ip daddr @A_HEADEND-WAN ip saddr @A_SPOKE-WAN
        Should Match Regexp    ${rules}    (?m)^11\\s+accept\\s+udp\\s+\\d+\\s+\\S+\\s+udp dport \\{ 500, 4500 \\} ip daddr @A_SPOKE-WAN ip saddr @A_HEADEND-WAN
        Should Match Regexp    ${rules}    (?m)^20\\s+accept\\s+esp\\s+\\d+\\s+\\S+\\s+meta l4proto esp ip daddr @A_HEADEND-WAN ip saddr @A_SPOKE-WAN
        Should Match Regexp    ${rules}    (?m)^21\\s+accept\\s+esp\\s+\\d+\\s+\\S+\\s+meta l4proto esp ip daddr @A_SPOKE-WAN ip saddr @A_HEADEND-WAN
        # ESP actually crossing: conntrack tracks ESP with the generic tracker ("unknown" protocol) and, once a flow is known, every further
        # packet is counted by the established rule, so the ESP rules' own counters only see the first packet of each flow (0 right after a
        # policy reload while the flows persist) — the flow entries between the WAN addresses are the proof
        ${ct}=    Vyos    ${f}    show conntrack table ipv4
        Should Match Regexp    ${ct}    (?m)^100\\.6[45]\\.\\d+\\.\\d+\\s+100\\.6[45]\\.\\d+\\.\\d+\\s+.*\\sunknown\\s    msg=${f}: no ESP flow between the WAN addresses in the conntrack table
        Should Match Regexp    ${rules}    (?m)^30\\s+accept\\s+icmp
        Should Match Regexp    ${rules}    (?m)^900\\s+drop\\s+all
        Should Match Regexp    ${rules}    (?m)^default\\s+drop
        ${groups}=    Vyos    ${f}    show configuration commands | match "firewall group address-group"
        ${hub}=    Set Variable    ${FIREWALLS}[${f}][hub]
        ${hub_wan}=    Evaluate    [str(__import__("ipaddress").IPv4Network(l["prefix"])[2]) for l in $LINKS if "${hub}" in (l["a"], l["b"]) and "${f}" in (l["a"], l["b"])]
        ${spoke_wans}=    Evaluate    sorted(str(__import__("ipaddress").IPv4Network(l["prefix"])[2]) for l in $LINKS if "${f}" in (l["a"], l["b"]) and "${hub}" not in (l["a"], l["b"]))
        ${have_hub}=    Get Regexp Matches    ${groups}    address-group HEADEND-WAN address '([\\d.]+)'    1
        ${have_spokes}=    Get Regexp Matches    ${groups}    address-group SPOKE-WAN address '([\\d.]+)'    1
        Lists Should Be Equal    ${{ sorted($have_hub) }}    ${{ sorted($hub_wan) }}    msg=${f}: HEADEND-WAN differs from the modelled headend WAN address
        Lists Should Be Equal    ${{ sorted($have_spokes) }}    ${spoke_wans}    msg=${f}: SPOKE-WAN differs from the modelled spoke WAN addresses
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
        IF    '${row}[binding]' == 'cpu'
            # live: the headend's control-plane CPU can be the tightest constraint while the suites (or a Terraform apply) load it
            Should Be True    ${row}[cpu_utilisation] >= max(${row}[utilisation], ${row}[bandwidth_utilisation])    msg=${h}: cpu-bound but the CPU utilisation is not the highest
        ELSE
            Should Be Equal    ${row}[binding]    ${hc}[binding]
            Should Be Equal As Integers    ${row}[effective_free]    ${hc}[effective_free]
        END
        ${agg}=    Evaluate    max($row["utilisation"], $row["bandwidth_utilisation"], $row.get("cpu_utilisation") or 0)
        Should Be Equal As Numbers    ${row}[aggregate_utilisation]    ${agg}    msg=${h}: aggregate must be the tightest of the constraints
        Should Be True    ${row}[bandwidth_used_mbps] <= ${row}[bandwidth_mbps]    msg=${h}: tunnels commit more than the firewall carries
    END

Headend CPU is collected live and joins the aggregate capacity
    [Documentation]    The portal reads `show platform resources` on every headend: control-plane CPU against the platform's
    ...    warning threshold, data-plane (QFP) CPU and DRAM. Aggregate utilisation is the tightest of tunnels, bandwidth and CPU.
    ${inv}=    Portal Inventory    live=${True}
    FOR    ${h}    IN    @{HUBS}
        ${row}=    Evaluate    [x for x in $inv["headends"] if x["name"] == $h][0]
        Should Not Be Equal    ${row}[cpu_pct]    ${None}    msg=${h}: no CPU reading (${row}[live])
        Should Be True    0 <= ${row}[cpu_pct] <= 100
        Should Be True    0 < ${row}[cpu_warning_pct] <= 100
        Should Be True    0 <= ${row}[qfp_cpu_pct] <= 100
        Should Be True    0 <= ${row}[dram_pct] <= 100
        ${agg}=    Evaluate    max($row["utilisation"], $row["bandwidth_utilisation"], $row["cpu_utilisation"])
        Should Be Equal As Numbers    ${row}[aggregate_utilisation]    ${agg}    msg=${h}: aggregate must include the CPU utilisation
        Run Keyword If    ${row}[cpu_pct] >= ${row}[cpu_warning_pct]    Should Be Equal As Integers    ${row}[effective_free]    0    msg=${h} is above its CPU threshold and must have no free slots
    END

Non-VPN traffic from a spoke to a headend is dropped by the firewall
    ${t}=    Set Variable    ${TUNNEL_LIST}[0]
    ${before}=    Drop Counter    ${t}[firewall]
    # SSH from the spoke's WAN address to the headend's WAN address must not get through (only IKE/ESP/ICMP may)
    ${out}=    Show    ${t}[spoke]    telnet ${t}[hub_wan] 22 /source-interface ${t}[spoke_if]    120
    Should Not Contain    ${out}    SSH-2.0    msg=SSH from ${t}[spoke] reached ${t}[hub] through ${t}[firewall]
    Should Match Regexp    ${out}    Connection timed out|Destination unreachable|Connection refused
    Wait Until Keyword Succeeds    30s    5s    Drops Increased    ${t}[firewall]    ${before}

The firewalls ship their firewall log to VictoriaLogs, and the portal reads the history from there
    [Documentation]    The config context sets the remote syslog target (VictoriaLogs on the NMS, UDP 5514); render_vyos pushes it. The kernel's
    ...    forward-filter lines arrive tagged with the firewall's hostname, the same lines `show log firewall` prints, so the portal's Firewalls
    ...    tab (source=logs) and the Grafana drops panel / FirewallDropBurst alert see every firewall.
    FOR    ${f}    IN    @{FIREWALLS}
        ${cfg}=    Vyos    ${f}    show configuration commands | match "syslog remote"
        Should Match Regexp    ${cfg}    (?m)^set system syslog remote 10\.2\.0\.10 port '5514'$
        Should Match Regexp    ${cfg}    (?m)^set system syslog remote 10\.2\.0\.10 facility all level 'info'$
    END
    # the previous test made ${TUNNEL_LIST}[0]'s firewall drop something; the accept rules log every new IKE flow on every firewall anyway
    ${t}=    Set Variable    ${TUNNEL_LIST}[0]
    Wait Until Keyword Succeeds    60s    5s    Victorialogs Has Firewall Lines    ${t}[firewall]    "FWD-filter-900-D"
    FOR    ${f}    IN    @{FIREWALLS}
        Wait Until Keyword Succeeds    60s    5s    Victorialogs Has Firewall Lines    ${f}    "FWD-filter"
    END
    ${d}=    Portal Get    /api/firewalls    hours=24    source=logs
    Should Be Equal    ${d}[source]    logs
    FOR    ${fw}    IN    @{d}[firewalls]
        Should Not Contain    ${fw}    error    msg=${fw}[name]: ${fw}
        Should Not Contain    ${fw}    log_error    msg=${fw}[name]: ${fw}
        Should Be Equal    ${fw}[log_source]    logs
        Should Be True    ${fw}[log_total] > 0    msg=${fw}[name]: nothing in VictoriaLogs for the last 24 h
        Should Be True    len($fw['flows']) > 0
    END
    # the same window over SSH is the firewall's own journal (read after VictoriaLogs): the newest line VictoriaLogs holds is in it, same fields
    ${s}=    Portal Get    /api/firewalls    hours=24    source=ssh    refresh=true
    FOR    ${fw}    ${sf}    IN ZIP    ${d}[firewalls]    ${s}[firewalls]
        Should Be Equal    ${fw}[name]    ${sf}[name]
        ${key}=    Evaluate    lambda e: (e['time'], e['tag'], e['in'], e['out'], e['src'], e['dst'], e['proto'], e['sport'], e['dport'])
        ${newest}=    Evaluate    $key($fw['log'][0])
        ${journal}=    Evaluate    [$key(e) for e in $sf['log']]
        Should Contain    ${journal}    ${newest}    msg=${fw}[name]: VictoriaLogs' newest line ${newest} is not in the firewall's own journal
    END

*** Keywords ***
Victorialogs Has Firewall Lines
    [Arguments]    ${f}    ${match}
    ${rows}=    Victorialogs Query    hostname:${f} app_name:kernel ${match} _time:1h | stats count() as n
    Should Be True    int($rows[0]['n']) > 0    msg=${f}: no ${match} line in VictoriaLogs in the last hour

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
