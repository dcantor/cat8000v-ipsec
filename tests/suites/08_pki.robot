*** Settings ***
Documentation     Certificate authentication, chosen per spoke (device ike_authentication, else the lab default): every router with a
...               certificate-authenticated tunnel holds a certificate from the lab CA (pki/ca.py) in the modelled trustpoint, the CA is pinned
...               by fingerprint, those tunnels authenticate with rsa-sig, and a router whose tunnels all use keys holds no trustpoint;
...               Nautobot records what each router presents; the portal renews a certificate and switches a spoke between the two methods.
Resource          ../resources/common.resource
Library           OperatingSystem
Suite Setup       Skip Unless Certificate Mode
Suite Teardown    Suite Teardown Close Connections

*** Variables ***
${CA_CRT}         ${CURDIR}/../../pki/ca/ca.crt
${INDEX}          ${CURDIR}/../../pki/index.json

*** Test Cases ***
The lab CA exists and the routers with certificate tunnels trust exactly it, pinned by fingerprint
    File Should Exist    ${CA_CRT}
    ${fp}=    Ca Fingerprint    ${CA_CRT}
    ${ca}=    Cert Info    ${CA_CRT}
    FOR    ${r}    IN    @{CERT_ROUTERS}
        ${tp}=    Show    ${r}    show running-config | section crypto pki trustpoint ${PKI}[trustpoint]
        Should Match Regexp    ${tp}    (?m)^ enrollment terminal pem$
        Should Match Regexp    ${tp}    (?m)^ fingerprint ${fp}$
        Should Match Regexp    ${tp}    (?m)^ fqdn ${r}\\.${DOMAIN_NAME}$
        Should Match Regexp    ${tp}    (?m)^ subject-name CN=${r}\\.${DOMAIN_NAME},O=cat8000v-ipsec$
        Should Match Regexp    ${tp}    (?m)^ rsakeypair ${PKI}[keypair]$
        Should Match Regexp    ${tp}    (?m)^ revocation-check none$
        ${certs}=    Show    ${r}    show crypto pki certificates ${PKI}[trustpoint]
        ${cac}=    Cert Block    ${certs}    CA Certificate
        Should Be Equal    ${cac}[serial]    ${ca}[serial]    msg=${r}: the installed CA certificate is not pki/ca/ca.crt
        Should Contain    ${cac}[text]    Status: Available
    END

Every router with a certificate tunnel holds a certificate issued by the lab CA to its own name, valid and not close to expiry; key-only routers hold none
    ${idx}=    Evaluate    json.load(open($INDEX))    modules=json
    FOR    ${r}    IN    @{ROUTER_NAMES}
        IF    $r in $CERT_ROUTERS    CONTINUE
        Should Not Contain    ${idx}    ${r}    msg=${r} authenticates with keys only but the CA index still lists a live certificate for it
        ${tp}=    Show    ${r}    show running-config | section crypto pki (trustpoint ${PKI}[trustpoint]|certificate map)
        Should Be Empty    ${tp.strip()}    msg=${r} authenticates with keys only but still holds the trustpoint / certificate map
    END
    FOR    ${r}    IN    @{CERT_ROUTERS}
        Dictionary Should Contain Key    ${idx}    ${r}    msg=${r}: no certificate in pki/index.json
        ${certs}=    Show    ${r}    show crypto pki certificates ${PKI}[trustpoint]
        ${rc}=    Cert Block    ${certs}    Certificate
        Should Contain    ${rc}[text]    Status: Available
        Should Be Equal    ${rc}[serial]    ${idx}[${r}][serial]    msg=${r}: the router certificate is not the one the CA issued last
        Should Contain    ${rc}[text]    cn=${r}.${DOMAIN_NAME}
        Should Contain    ${rc}[text]    cn=cat8000v-ipsec lab CA
        ${days}=    Days Until    ${rc}[end]
        Should Be True    ${days} > ${PKI}[renew_before_days]    msg=${r}: certificate expires in ${days} days (renewal threshold ${PKI}[renew_before_days])
        ${on_disk}=    Cert Info    ${CURDIR}/../../pki/certs/${r}.crt
        Should Be Equal    ${on_disk}[serial]    ${rc}[serial]
        ${ok}=    Run    openssl verify -CAfile ${CA_CRT} ${CURDIR}/../../pki/certs/${r}.crt
        Should Contain    ${ok}    : OK
    END

Certificate tunnels authenticate with rsa-sig against the trustpoint; a key stays only where a spoke chose one
    FOR    ${r}    IN    @{CERT_ROUTERS}
        ${prof}=    Show    ${r}    show crypto ikev2 profile ${PROFILE_NAMES}[certificate][ikev2_profile]
        Should Contain    ${prof}    Local authentication method: rsa-sig
        Should Contain    ${prof}    Remote authentication method(s): rsa-sig
        Should Contain    ${prof}    Keyring: none
        ${run}=    Show    ${r}    show running-config | section crypto ikev2 profile ${PROFILE_NAMES}[certificate][ikev2_profile]$
        Should Contain    ${run}    pki trustpoint ${PKI}[trustpoint]
        Should Contain    ${run}    match certificate ${PKI}[certificate_map]
        Should Not Contain    ${run}    pre-share
        IF    $r not in $PSK_ROUTERS
            ${kr}=    Show    ${r}    show running-config | section crypto ikev2 keyring
            Should Be Empty    ${kr.strip()}    msg=${r}: no tunnel of this router uses a key, yet a keyring is configured
        END
    END
    FOR    ${t}    IN    @{TUNNEL_LIST}
        ${sa}=    Show    ${t}[hub]    show crypto ikev2 sa detail
        ${block}=    Sa Block    ${sa}    ${t}[spoke_wan]
        IF    '${t}[auth]' == 'certificate'
            Should Contain    ${block}    Auth sign: RSA, Auth verify: RSA
            Should Contain    ${block}    Remote id: hostname=${t}[spoke].${DOMAIN_NAME},cn=${t}[spoke].${DOMAIN_NAME},o=cat8000v-ipsec
        ELSE
            Should Contain    ${block}    Auth sign: PSK, Auth verify: PSK
            Should Contain    ${block}    Remote id: ${t}[spoke_wan]
        END
    END

The NaC data carries a key only for the spokes that chose one, and the rendered model matches Nautobot
    ${nac}=    Get File    ${CURDIR}/../../nac/data/devices.nac.yaml
    Should Contain    ${nac}    authentication local rsa-sig
    ${groups}=    Get File    ${CURDIR}/../../nac/data/device_groups.nac.yaml
    FOR    ${s}    IN    @{SPOKES}
        IF    '${SPOKE_AUTH}[${s}]' == 'certificate'
            Should Not Contain    ${groups}    psk_${s}:    msg=${s} authenticates with a certificate but a key is rendered for it
            Should Not Contain    ${nac}    \${psk_${s}}
        ELSE
            Should Contain    ${groups}    psk_${s}:
        END
    END
    ${d}=    Nautobot Graphql    { vpn_profiles(name: ["${PROFILE_NAMES}[certificate][profile]"]) { extra_options vpn_phase1_policies { authentication_method } } }
    Should Be Equal    ${d}[vpn_profiles][0][vpn_phase1_policies][0][authentication_method]    RSA
    Should Be Equal    ${d}[vpn_profiles][0][extra_options][ios][trustpoint]    ${PKI}[trustpoint]
    ${fp}=    Ca Fingerprint    ${CA_CRT}
    Should Be Equal    ${d}[vpn_profiles][0][extra_options][ios][ca_fingerprint]    ${fp}

Nautobot records the certificate every router presents
    ${idx}=    Evaluate    json.load(open($INDEX))    modules=json
    FOR    ${r}    IN    @{ROUTER_NAMES}
        IF    $r not in $CERT_ROUTERS
            ${dev}=    Nautobot Get    dcim/devices/    name=${r}
            Should Be Equal    ${dev}[results][0][custom_fields][cert_serial]    ${None}    msg=${r} authenticates with keys only but Nautobot still records a certificate
            CONTINUE
        END
        ${dev}=    Nautobot Get    dcim/devices/    name=${r}
        ${cf}=    Set Variable    ${dev}[results][0][custom_fields]
        Should Be Equal    ${cf}[cert_serial]    ${idx}[${r}][serial]    msg=${r}: Nautobot's cert_serial differs from the CA index
        Should Be Equal    ${cf}[cert_subject]    ${r}.${DOMAIN_NAME}
        Should Be Equal    ${cf}[cert_expires]    ${{ $idx[$r]['not_after'][:10] }}
    END
    ${p}=    Portal Get    /api/pki
    Should Be Equal    ${p}[authentication]    ${IKE_AUTH}
    Should Be Equal    ${p}[cert_routers]    ${CERT_ROUTERS}
    Should Be Equal    ${p}[spokes]    ${SPOKE_AUTH}
    FOR    ${r}    IN    @{CERT_ROUTERS}
        Should Be Equal    ${p}[devices][${r}][serial]    ${idx}[${r}][serial]
    END

The portal renews a spoke's certificate: new serial on the router, in the CA index and in Nautobot; every tunnel back with RSA
    [Documentation]    A real renewal of the first spoke through the portal's renew run (operator): the router's tunnels re-authenticate with
    ...    the new certificate, the old serial is retired into the index's history.
    [Tags]    slow
    ${spoke}=    Evaluate    [s for s in $SPOKES if $SPOKE_AUTH[s] == 'certificate'][0]
    ${before}=    Evaluate    json.load(open($INDEX))[$spoke]['serial']    modules=json
    ${run}=    Portal Post    /api/runs    {"mode": "renew", "spoke": {"name": "${spoke}"}, "options": {"test": false}}
    ${res}=    Wait Until Keyword Succeeds    6 min    10s    Run Finished    ${run}[id]
    Should Be Equal    ${res}[status]    success    msg=renew run ${run}[id] ended ${res}[status]: ${res}[steps]
    ${idx}=    Evaluate    json.load(open($INDEX))    modules=json
    Should Not Be Equal    ${idx}[${spoke}][serial]    ${before}    msg=the CA index still shows the old serial
    Should Contain    ${idx}[${spoke}][previous]    ${before}
    ${certs}=    Show    ${spoke}    show crypto pki certificates ${PKI}[trustpoint]
    ${rc}=    Cert Block    ${certs}    Certificate
    Should Be Equal    ${rc}[serial]    ${idx}[${spoke}][serial]
    ${dev}=    Nautobot Get    dcim/devices/    name=${spoke}
    Should Be Equal    ${dev}[results][0][custom_fields][cert_serial]    ${idx}[${spoke}][serial]
    Should Be Equal    ${dev}[results][0][custom_fields][cert_renewed]    ${{ __import__('datetime').date.today().isoformat() }}
    FOR    ${t}    IN    @{TUNNEL_LIST}
        IF    '${t}[spoke]' != '${spoke}'    CONTINUE
        ${sa}=    Show    ${t}[hub]    show crypto ikev2 sa detail
        ${block}=    Sa Block    ${sa}    ${t}[spoke_wan]
        Should Contain    ${block}    READY
        Should Contain    ${block}    Auth sign: RSA, Auth verify: RSA
    END

The portal switches a spoke between certificate and pre-shared key and back: profiles, keyring, trustpoint, SAs and Nautobot follow
    [Documentation]    A certificate spoke goes to its pre-shared key through the portal's auth run (its trustpoint retired, its headends
    ...    keying for it on their PSK profile, SAs on PSK) and back again (enrolled anew, keyring gone, SAs on RSA) — two runs, about
    ...    ten minutes.
    [Tags]    slow
    ${spoke}=    Evaluate    [s for s in $SPOKES if $SPOKE_AUTH[s] == 'certificate'][0]
    ${hubs}=    Evaluate    sorted({t['hub'] for t in $TUNNEL_LIST if t['spoke'] == $spoke})
    Switch And Verify    ${spoke}    psk    ${hubs}
    Switch And Verify    ${spoke}    certificate    ${hubs}

*** Keywords ***
Switch And Verify
    [Arguments]    ${spoke}    ${method}    ${hubs}
    ${run}=    Portal Post    /api/runs    {"mode": "auth", "spoke": {"name": "${spoke}", "ike_authentication": "${method}"}, "options": {"golden": false, "test": false}}
    ${res}=    Wait Until Keyword Succeeds    10 min    15s    Run Finished    ${run}[id]
    Should Be Equal    ${res}[status]    success    msg=auth run ${run}[id] (${spoke} -> ${method}) ended ${res}[status]: ${res}[steps]
    ${p}=    Portal Get    /api/pki
    Should Be Equal    ${p}[spokes][${spoke}]    ${method}
    ${prof}=    Set Variable    ${PROFILE_NAMES}[${method}][ikev2_profile]
    ${run_cfg}=    Show    ${spoke}    show running-config | section crypto ikev2 (profile|keyring)|crypto pki trustpoint ${PKI}[trustpoint]
    Should Contain    ${run_cfg}    crypto ikev2 profile ${prof}
    IF    '${method}' == 'psk'
        Should Contain    ${run_cfg}    pre-shared-key ${ROUTERS}[${spoke}][psk]
        Should Not Contain    ${run_cfg}    crypto pki trustpoint    msg=${spoke} switched to its key but keeps the trustpoint
        Should Not Contain    ${p}[devices]    ${spoke}
    ELSE
        Should Not Contain    ${run_cfg}    pre-shared-key    msg=${spoke} switched to a certificate but keeps a key
        Should Contain    ${run_cfg}    pki trustpoint ${PKI}[trustpoint]
        Dictionary Should Contain Key    ${p}[devices]    ${spoke}
    END
    ${want}=    Set Variable    ${{ 'PSK' if $method == 'psk' else 'RSA' }}
    FOR    ${h}    IN    @{hubs}
        ${t}=    Evaluate    [t for t in $TUNNEL_LIST if t['hub'] == $h and t['spoke'] == $spoke][0]
        ${sa}=    Show    ${h}    show crypto ikev2 sa detail
        ${block}=    Sa Block    ${sa}    ${t}[spoke_wan]
        Should Contain    ${block}    READY
        Should Contain    ${block}    Auth sign: ${want}, Auth verify: ${want}
        ${kr}=    Show    ${h}    show running-config | section crypto ikev2 keyring
        IF    '${method}' == 'psk'    Should Contain    ${kr}    peer ${spoke}    ELSE    Should Not Contain    ${kr}    peer ${spoke}
    END
    ${tun}=    Nautobot Graphql    { vpn_tunnels(name__ic: "${spoke}") { name vpn_profile { name } endpoint_z { device { name } } } }
    FOR    ${x}    IN    @{tun}[vpn_tunnels]
        IF    '${x}[endpoint_z][device][name]' != '${spoke}'    CONTINUE
        Should Be Equal    ${x}[vpn_profile][name]    ${PROFILE_NAMES}[${method}][profile]    msg=${x}[name] references the wrong VPN profile after the switch
    END

Skip Unless Certificate Mode
    Skip If    not $CERT_ROUTERS    no spoke authenticates with a certificate (per-spoke ike_authentication / the lab default); certificate checks do not apply

Ca Fingerprint
    [Arguments]    ${file}
    ${out}=    Run    openssl x509 -in ${file} -noout -fingerprint -sha1
    ${fp}=    Evaluate    $out.split('=', 1)[1].replace(':', '').strip().upper()
    RETURN    ${fp}

Cert Info
    [Arguments]    ${file}
    ${out}=    Run    openssl x509 -in ${file} -noout -serial -enddate
    ${info}=    Evaluate    {'serial': $out.split('serial=')[1].split()[0].upper().lstrip('0'), 'end': $out.split('notAfter=')[1].strip()}
    RETURN    ${info}

Cert Block
    [Documentation]    The "Certificate" (router) or "CA Certificate" block of `show crypto pki certificates`, with its serial and end date.
    [Arguments]    ${text}    ${kind}
    ${blocks}=    Evaluate    re.split(r'(?m)^(?=(?:CA )?Certificate\\s*$)', $text)    modules=re
    ${block}=    Evaluate    [b for b in $blocks if b.startswith("${kind}" + chr(10)) or b.startswith("${kind}" + chr(13))][0]
    ${serial}=    Evaluate    re.search(r'Serial Number \\(hex\\): (\\w+)', $block)[1].upper().lstrip('0')    modules=re
    ${end}=    Evaluate    re.search(r'end\\s+date: (.+)', $block)[1].strip()    modules=re
    RETURN    ${{ {'text': $block, 'serial': $serial, 'end': $end} }}

Days Until
    [Arguments]    ${ios_date}
    ${days}=    Evaluate    (datetime.datetime.strptime($ios_date, '%H:%M:%S %Z %b %d %Y') - datetime.datetime.utcnow()).days    modules=datetime
    RETURN    ${days}

Sa Block
    [Documentation]    The IKEv2 SA detail block whose remote address is the given one.
    [Arguments]    ${text}    ${remote}
    ${blocks}=    Evaluate    re.split(r'(?m)^(?=\\d+\\s+\\S+/500\\s+)', $text)    modules=re
    ${block}=    Evaluate    ([b for b in $blocks if re.match(r'\\d+\\s+\\S+/500\\s+' + re.escape("${remote}") + '/500', b)] or [''])[0]    modules=re
    Should Not Be Empty    ${block}    msg=no IKEv2 SA towards ${remote}
    RETURN    ${block}

Run Finished
    [Arguments]    ${id}
    ${r}=    Portal Get    /api/runs/${id}
    Should Be True    $r['status'] in ('success', 'failed')    msg=run ${id} still ${r}[status]
    RETURN    ${r}
