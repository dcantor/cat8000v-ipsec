*** Settings ***
Documentation     The portal itself: runs queue instead of colliding (one executes at a time, a queued one can be cancelled), every
...               router has a page that gathers its tunnels, authentication, firewall rules, host and runs, and single sign-on (OpenID
...               Connect against the lab's Gitea) is offered and starts a proper authorization-code + PKCE flow.
Resource          ../resources/common.resource
Library           OperatingSystem
Suite Teardown    Suite Teardown Close Connections

*** Test Cases ***
Runs queue behind the one executing and a queued run can be cancelled; the executing one finishes
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
            Should Be True    len($p['firewalls']) >= 1    msg=${r}: no firewall rule names its WAN addresses
            FOR    ${f}    IN    @{p}[firewalls]
                Should Be True    len($f['rules']) >= 2    msg=${r}: ${f}[name] should admit its IKE and ESP
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
