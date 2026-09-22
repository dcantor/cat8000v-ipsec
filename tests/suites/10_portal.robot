*** Settings ***
Documentation     The portal itself: runs queue instead of colliding (one executes at a time, a queued one can be cancelled), every
...               router has a page that gathers its tunnels, authentication, firewall rules, host and runs, and single sign-on (OpenID
...               Connect against the lab's Gitea) is offered and starts a proper authorization-code + PKCE flow.
Resource          ../resources/common.resource
Library           OperatingSystem
Suite Teardown    Suite Teardown Close Connections

*** Test Cases ***
Runs queue behind the one executing and a queued run can be cancelled; the executing one finishes
    Skip If Started From A Portal Run    this test fills the run queue
    ${intent}=    Portal Get    /api/intent
    ${a}=    Portal Request    POST    /api/runs    ${{ {"mode": "plan", "intent": $intent["intent"]} }}
    Should Be Equal As Integers    ${a}[status]    200
    ${b}=    Portal Request    POST    /api/runs    ${{ {"mode": "plan", "intent": $intent["intent"]} }}
    Should Be Equal As Integers    ${b}[status]    200    msg=a second run must queue, not be refused: ${b}[text]
    Should Be Equal    ${b}[json][status]    queued
    Should Be Equal As Integers    ${b}[json][queue_position]    1
    Should Be Equal    ${b}[json][waiting_for]    ${a}[json][id]
    Should Be Equal    ${b}[json][user]    operator
    ${c}=    Portal Request    DELETE    /api/runs/${b}[json][id]
    Should Be Equal As Integers    ${c}[status]    200
    Should Be Equal    ${c}[json][status]    cancelled
    ${again}=    Portal Request    DELETE    /api/runs/${b}[json][id]
    Should Be Equal As Integers    ${again}[status]    409    msg=cancelling twice must be refused
    ${running}=    Portal Get    /api/runs/${a}[json][id]
    Should Be True    $running['status'] in ('running', 'queued', 'success')
    ${res}=    Wait Until Keyword Succeeds    8 min    10s    Run Finished    ${a}[json][id]
    Should Be Equal    ${res}[status]    success    msg=the plan run ended ${res}[status]: ${res}[error]
    ${audit}=    Portal Get    /api/audit    action=run.cancel    limit=5
    Should Be Equal    ${audit}[0][user]    operator

Every router has a page: identity, authentication, its tunnels with live state, firewall rules touching it, its host and its runs
    FOR    ${r}    IN    @{ROUTER_NAMES}
        ${p}=    Portal Get    /api/branch/${r}
        Should Be Equal    ${p}[name]    ${r}
        Should Be Equal    ${p}[role]    ${ROUTERS}[${r}][role]
        Should Be Equal    ${p}[device][lan]    ${ROUTERS}[${r}][lan]
        Should Not Contain    ${p}[device]    psk    msg=the page must not carry the pre-shared key
        ${n}=    Evaluate    len([t for t in $TUNNEL_LIST if $r in (t['hub'], t['spoke'])])
        Length Should Be    ${p}[tunnels]    ${n}
        FOR    ${t}    IN    @{p}[tunnels]
            Should Be Equal    ${t}[live][health]    up    msg=${r}: ${t}[name] is ${t}[live]
            Should Be Equal    ${t}[auth]    ${SPOKE_AUTH}[${t}[spoke]]
        END
        IF    '${ROUTERS}[${r}][role]' == 'spoke'
            Should Be Equal    ${p}[authentication]    ${SPOKE_AUTH}[${r}]
            ${in_path}=    Evaluate    [f for f in $p['firewalls'] if f['in_path']]
            Should Be True    len($in_path) >= 1    msg=${r}: no firewall in its path
            FOR    ${f}    IN    @{in_path}
                Should Be True    len($f['rules']) >= 2    msg=${r}: ${f}[name] (in front of ${f}[hub]) should admit its IKE and ESP
            END
        ELSE
            Should Be Equal    ${p}[methods]    ${ROUTER_AUTHS}[${r}]
            Should Not Be Equal    ${p}[headend]    ${None}
        END
        Should Be Equal    ${p}[host][name]    ${HOST_OF}[${r}]
        Should Be Equal    ${p}[host][state]    running
        Run Keyword If    $r in $CERT_ROUTERS    Should Not Be Equal    ${p}[certificate]    ${None}    msg=${r} holds a certificate but the page shows none
        Run Keyword If    $r not in $CERT_ROUTERS    Should Be Equal    ${p}[certificate]    ${None}
    END
    ${missing}=    Portal Request    GET    /api/branch/fw-east    user=viewer    password=viewer
    Should Be Equal As Integers    ${missing}[status]    404    msg=a firewall has no branch page

The Branches list names every router with its health, method, certificate and host, and each row opens the router's page
    ${l}=    Portal Get    /api/branches
    Length Should Be    ${l}[routers]    ${{ len($ALL_ROUTERS) }}    msg=the list holds every Catalyst 8000v: the headends, the branches and the DCI chain
    FOR    ${b}    IN    @{l}[routers]
        Should Contain    ${{ list($ALL_ROUTERS) }}    ${b}[name]
        # the DCI chain has no tunnels: its health is reported as "none" and it holds no certificate
        ${expect}=    Set Variable If    '${b}[role]' in ['dci', 'partner']    none    up
        Should Be Equal    ${b}[health]    ${expect}
        Should Be Equal As Integers    ${b}[tunnels_up]    ${b}[tunnels]
        Should Be Equal    ${b}[host]    ${{ $HOST_OF.get($b['name']) }}
        IF    $b['host']    Should Be Equal    ${b}[host_state]    running
        IF    '${b}[role]' == 'spoke'    Should Be Equal    ${b}[authentication]    ${SPOKE_AUTH}[${b}[name]]
        Run Keyword If    $b['name'] in $CERT_ROUTERS    Should Be True    ${b}[cert_days] > 30
        Run Keyword If    $b['name'] not in $CERT_ROUTERS    Should Be Equal    ${b}[cert_days]    ${None}
        ${p}=    Portal Get    /api/branch/${b}[name]
        Should Be Equal    ${p}[name]    ${b}[name]
    END

Every router's page shows its configuration: the live running config (keys redacted for viewers), Nautobot's intended config and compliance
    FOR    ${r}    IN    @{ROUTER_NAMES}
        ${v}=    Portal Request    GET    /api/branch/${r}/config    user=viewer    password=viewer
        Should Be Equal As Integers    ${v}[status]    200
        Should Be Equal    ${v}[json][error]    ${None}    msg=${r}: ${v}[json][error]
        Should Contain    ${v}[json][running]    hostname ${r}
        Should Be True    ${v}[json][lines] > 100
        Should Not Match Regexp    ${v}[json][running]    pre-shared-key (?!<redacted>)\\S+    msg=${r}: a viewer must not see pre-shared keys
        Should Be Equal    ${v}[json][keys_shown]    ${False}
        Should Contain    ${v}[json][golden][intended]    hostname ${r}
        ${bad}=    Evaluate    [c['feature'] for c in $v['json']['golden']['compliance'] if not c['compliant']]
        Should Be Empty    ${bad}    msg=${r}: non-compliant features in Nautobot: ${bad}
        IF    $SPOKE_AUTH.get($r) == 'psk'
            ${o}=    Portal Request    GET    /api/branch/${r}/config    user=operator    password=operator
            Should Match Regexp    ${o}[json][running]    pre-shared-key ${ROUTERS}[${r}][psk]    msg=${r}: an operator sees the key as configured
        END
    END

A router's page shows its configuration history from Gitea, the diff of a backup commit, and live show snippets
    ${r}=    Set Variable    ${SPOKES}[0]
    ${h}=    Portal Get    /api/branch/${r}/history
    Should Be Equal    ${h}[file]    ${r}.cfg
    Should Be True    len($h['commits']) >= 1    msg=no Golden Config backup commits for ${r}
    Should Be Equal    ${h}[commits][0][author]    nautobot
    ${d}=    Portal Get    /api/branch/${r}/history    sha=${h}[commits][-1][sha]
    Should Contain    ${d}[diff]    ${r}.cfg
    ${s}=    Portal Get    /api/branch/${r}/show/bgp
    Should Be Equal    ${s}[error]    ${None}
    Should Contain    ${s}[output]    BGP router identifier ${ROUTERS}[${r}][router_id]
    ${s}=    Portal Get    /api/branch/${r}/show/ike
    Should Contain    ${s}[output]    READY
    ${bad}=    Portal Request    GET    /api/branch/${r}/show/reload    user=viewer    password=viewer
    Should Be Equal As Integers    ${bad}[status]    404    msg=only allow-listed show commands may run

The Compliance page reports Nautobot's Golden Config verdict for every router and feature, and a golden run refreshes it
    Skip If Started From A Portal Run    this test starts a golden run
    ${c}=    Portal Get    /api/compliance
    Length Should Be    ${c}[devices]    ${{ len($ALL_ROUTERS) }}    msg=every Catalyst 8000v is in the Golden Config scope, the DCI chain included
    Should Be True    len($c['features']) >= 10
    Should Be Equal As Integers    ${c}[summary][devices_ok]    ${c}[summary][devices]    msg=non-compliant routers: ${{ [d['name'] for d in $c['devices'] if not d['ok']] }}
    Should Be Equal As Integers    ${c}[summary][rows_ok]    ${c}[summary][rows]
    FOR    ${d}    IN    @{c}[devices]
        Should Contain    ${{ list($ALL_ROUTERS) }}    ${d}[name]
        Should Be Equal As Integers    ${d}[total]    ${{ len($c['features']) }}    msg=${d}[name]: a feature has no compliance row
        Should Not Be Empty    ${d}[compliance_at]
        Dictionary Should Contain Key    ${d}[features]    IKEv2/IPsec
        Should Be True    ${d}[features][IKEv2/IPsec][compliant]
    END
    ${run}=    Portal Post    /api/runs    {"mode": "golden", "options": {}}
    ${res}=    Wait Until Keyword Succeeds    8 min    10s    Run Finished    ${run}[id]
    Should Be Equal    ${res}[status]    success    msg=golden run ${run}[id] ended ${res}[status]: ${res}[error]
    ${after}=    Portal Get    /api/compliance    refresh=true
    Should Be True    $after['summary']['last_compliance'] > $c['summary']['last_compliance']    msg=the compliance run did not refresh the report
    # the portal schedules the same run on its own (GOLDEN_INTERVAL_HOURS) and records one drift-history line per compliance run
    Should Be True    $after['schedule']['enabled'] and $after['schedule']['interval_hours'] > 0    msg=no scheduled Golden Config run: ${after}[schedule]
    Should Be True    $after['schedule']['next_run'] > time.time()    msg=the next scheduled run is in the past: ${after}[schedule]
    Should Be Equal    ${after}[history][-1][at]    ${after}[summary][last_compliance]    msg=the run was not recorded in the drift history
    Should Be Equal As Integers    ${after}[history][-1][devices_ok]    ${after}[history][-1][devices]

Provisioning a new router can register it in lab.conf: every array the pipeline rewrites is found and reads back
    [Documentation]    The first step of a spoke / headend run writes the new router into lab.conf's arrays. They are wrapped over
    ...    several lines (every router has a LAN host), so the rewriter has to span lines — this is a dry run of that rewrite on
    ...    the real lab.conf, read back with bash; lab.conf itself is untouched.
    ${v}=    Lab Conf Registration    robot-probe
    Should Be Equal    ${v}[ROLE]    spoke
    Should Be Equal    ${v}[MGMT_IP]    10.2.0.99
    Should Be Equal    ${v}[BGP_AS]    65299
    Should Be Equal    ${v}[LAN]    192.168.99.0/24
    Should Be Equal    ${v}[CONSOLE_PORT]    5299
    Should Be Equal    ${v}[NODE_IDX]    99
    Should Be Equal    ${v}[ROUTERS]    robot-probe    msg=the new router must be the last entry of ROUTERS
    Should Be Equal    ${v}[ALL_NODES]    robot-probe

Drift on a router is detected by the Golden Config run, remediated from the portal with Nautobot's remediation lines, and recorded in the drift history
    [Documentation]    An extra static route is configured on a spoke by hand. The golden run marks its Static routes feature non-compliant
    ...    with the `no ...` remediation line; a `remediate` run pushes that line and saves, the next verdict is compliant again, the drift
    ...    history shows the drift and its repair, and Prometheus (via /metrics) saw the router non-compliant in between.
    [Tags]    remediation
    Skip If Started From A Portal Run    this test starts golden and remediate runs
    ${spoke}=    Set Variable    ${{ [n for n, r in $ROUTERS.items() if r['role'] == 'spoke'][-1] }}
    ${host}=    Set Variable    ${ROUTERS}[${spoke}][host]
    Configure Router    ${host}    ip route 10.99.99.0 255.255.255.0 Null0 name robot-drift
    ${run}=    Portal Post    /api/runs    {"mode": "golden", "options": {}}
    ${res}=    Wait Until Keyword Succeeds    8 min    10s    Run Finished    ${run}[id]
    Should Be Equal    ${res}[status]    failed    msg=the golden run should fail on the drifted router (${res}[status])
    Should Contain    ${res}[error]    ${spoke}
    ${c}=    Portal Get    /api/compliance    refresh=true
    ${d}=    Set Variable    ${{ [d for d in $c['devices'] if d['name'] == $spoke][0] }}
    Should Not Be True    ${d}[ok]    msg=${spoke} still compliant after the drift
    Should Not Be True    ${d}[features][Static routes][compliant]
    Should Contain    ${d}[features][Static routes][extra]    10.99.99.0
    Should Contain    ${d}[features][Static routes][remediation]    no ip route 10.99.99.0 255.255.255.0 Null0
    Should Contain    ${c}[history][-1][drifted]    ${spoke}    msg=the drift is not in the history: ${c}[history][-1]
    Should Be Equal As Integers    ${c}[summary][devices_ok]    ${{ len($ALL_ROUTERS) - 1 }}
    ${m}=    Portal Get Text    /metrics
    Should Match Regexp    ${m}    lab_config_compliance_ok\\{[^}]*device="${spoke}"[^}]*\\} 0
    Should Match Regexp    ${m}    lab_config_noncompliant_features\\{[^}]*device="${spoke}"[^}]*\\} 1
    # remediate that one feature from the portal
    ${run}=    Portal Post    /api/runs    {"mode": "remediate", "spoke": {"name": "${spoke}", "features": ["Static routes"]}, "options": {}}
    Should Be Equal    ${run}[mode]    remediate
    Should Be Equal    ${{ [s['name'] for s in $run['steps']] }}    ${{ ['rem_validate', 'rem_push', 'golden'] }}
    ${res}=    Wait Until Keyword Succeeds    8 min    10s    Run Finished    ${run}[id]
    Should Be Equal    ${res}[status]    success    msg=remediate run ${run}[id] ended ${res}[status]: ${res}[error]
    Should Contain    ${res}[steps][1][summary]    1 line(s) pushed
    ${out}=    Run Command    ${host}    show running-config | include 10.99.99.0
    Should Not Contain    ${out}    10.99.99.0    msg=the remediation did not remove the route
    ${out}=    Run Command    ${host}    show startup-config | include 10.99.99.0
    Should Not Contain    ${out}    10.99.99.0    msg=the remediation was not saved
    ${c}=    Portal Get    /api/compliance    refresh=true
    Should Be True    ${{ [d for d in $c['devices'] if d['name'] == $spoke][0]['ok'] }}    msg=${spoke} still non-compliant after the remediation
    Should Be Equal As Integers    ${c}[summary][devices_ok]    ${c}[summary][devices]
    ${h}=    Portal Get    /api/compliance/history    device=${spoke}
    Should Not Be True    ${h}[runs][-2][ok]
    Should Contain    ${h}[runs][-2][drifted]    Static routes
    Should Be True    ${h}[runs][-1][ok]
    ${m}=    Portal Get Text    /metrics
    Should Match Regexp    ${m}    lab_config_compliance_ok\\{[^}]*device="${spoke}"[^}]*\\} 1
    # a second remediation has nothing to do
    ${r}=    Portal Request    POST    /api/runs    {"mode": "remediate", "spoke": {"name": "${spoke}"}}
    Should Be Equal As Integers    ${r}[status]    422    msg=remediating a compliant router should be refused: ${r}[json]
    [Teardown]    Run Keyword And Ignore Error    Configure Router    ${host}    no ip route 10.99.99.0 255.255.255.0 Null0 name robot-drift

Re-apply from the model restores a modelled attribute that was changed by hand, through a Terraform apply targeted at that router
    [Documentation]    Loopback0's description on a spoke is changed by hand (Terraform manages it). A `reapply` run renders the NaC data,
    ...    plans and applies only that router's resources, and ends with Golden Config compliant; the description is back.
    [Tags]    remediation
    Skip If Started From A Portal Run    this test starts a reapply run
    ${spoke}=    Set Variable    ${{ [n for n, r in $ROUTERS.items() if r['role'] == 'spoke'][0] }}
    ${host}=    Set Variable    ${ROUTERS}[${spoke}][host]
    ${before}=    Run Command    ${host}    show running-config interface Loopback0
    ${desc}=    Set Variable    ${{ re.search(r'description (.*)', $before).group(1).strip() }}
    Configure Router    ${host}    interface Loopback0    description robot-drift
    ${run}=    Portal Post    /api/runs    {"mode": "reapply", "spoke": {"name": "${spoke}"}, "options": {}}
    Should Be Equal    ${{ [s['name'] for s in $run['steps']] }}    ${{ ['render', 'reapply_plan', 'reapply_apply', 'golden'] }}
    ${res}=    Wait Until Keyword Succeeds    10 min    10s    Run Finished    ${run}[id]
    Should Be Equal    ${res}[status]    success    msg=reapply run ${run}[id] ended ${res}[status]: ${res}[error]
    Should Contain    ${res}[steps][1][summary]    1 to update in place    msg=the targeted plan should see exactly the loopback: ${res}[steps][1][summary]
    Should Contain    ${res}[steps][2][summary]    1 changed
    ${after}=    Run Command    ${host}    show running-config interface Loopback0
    Should Contain    ${after}    description ${desc}
    Should Not Contain    ${after}    robot-drift
    [Teardown]    Run Keyword And Ignore Error    Configure Router    ${host}    interface Loopback0    description ${desc}

Single sign-on is offered and starts an authorization-code flow with PKCE at the provider
    ${o}=    Portal Get    /api/oidc
    Skip If    not $o['enabled']    OIDC is not configured on this portal (webapp/oidc.json)
    Should Not Be Empty    ${o}[provider]
    ${r}=    Portal Request    GET    /api/oidc/login    user=${EMPTY}    allow_redirects=${False}
    Should Be Equal As Integers    ${r}[status]    302
    ${loc}=    Set Variable    ${r}[headers][location]
    Should Contain    ${loc}    /login/oauth/authorize?
    Should Contain    ${loc}    response_type=code
    Should Contain    ${loc}    code_challenge_method=S256
    Should Match Regexp    ${loc}    state=[A-Za-z0-9_-]{20,}
    Should Match Regexp    ${loc}    nonce=[A-Za-z0-9_-]{20,}
    Should Contain    ${loc}    scope=openid
    Should Contain    ${r}[headers][set-cookie]    portal_oidc=
    ${bad}=    Portal Request    GET    /api/oidc/callback?code=x&state=y    user=${EMPTY}    allow_redirects=${False}
    Should Be Equal As Integers    ${bad}[status]    302
    Should Contain    ${bad}[headers][location]    login_error    msg=a callback without the flow cookie must be rejected

*** Keywords ***
Run Finished
    [Arguments]    ${id}
    ${r}=    Portal Get    /api/runs/${id}
    Should Be True    $r['status'] in ('success', 'failed', 'cancelled')    msg=run ${id} still ${r}[status]
    RETURN    ${r}
