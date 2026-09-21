*** Settings ***
Documentation     Certificate authentication (intent profile.ike.authentication = certificate): every router holds a certificate from the
...               lab CA (pki/ca.py) in the modelled trustpoint, the CA is pinned by fingerprint, IKEv2 authenticates with rsa-sig and no
...               pre-shared key is left on any router; Nautobot records what each router presents; the portal can renew a certificate.
Resource          ../resources/common.resource
Library           OperatingSystem
Suite Setup       Skip Unless Certificate Mode
Suite Teardown    Suite Teardown Close Connections

*** Variables ***
${CA_CRT}         ${CURDIR}/../../pki/ca/ca.crt
${INDEX}          ${CURDIR}/../../pki/index.json

*** Test Cases ***
The lab CA exists and the routers trust exactly it, pinned by fingerprint
    File Should Exist    ${CA_CRT}
    ${fp}=    Ca Fingerprint    ${CA_CRT}
    ${ca}=    Cert Info    ${CA_CRT}
    FOR    ${r}    IN    @{ROUTER_NAMES}
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

Every router holds a certificate issued by the lab CA to its own name, valid and not close to expiry
    ${idx}=    Evaluate    json.load(open($INDEX))    modules=json
    FOR    ${r}    IN    @{ROUTER_NAMES}
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

IKEv2 authenticates with rsa-sig against the trustpoint and no pre-shared key is left on any router
    FOR    ${r}    IN    @{ROUTER_NAMES}
        ${prof}=    Show    ${r}    show crypto ikev2 profile
        Should Contain    ${prof}    Local authentication method: rsa-sig
        Should Contain    ${prof}    Remote authentication method(s): rsa-sig
        Should Contain    ${prof}    Keyring: none
        ${run}=    Show    ${r}    show running-config | section crypto ikev2 (profile|keyring)
        Should Contain    ${run}    pki trustpoint ${PKI}[trustpoint]
        Should Contain    ${run}    match certificate ${PKI}[certificate_map]
        Should Not Contain    ${run}    pre-shared-key    msg=${r}: a pre-shared key is still configured
        Should Not Contain    ${run}    crypto ikev2 keyring    msg=${r}: a keyring is still configured
        Should Not Contain    ${run}    authentication local pre-share
    END
    FOR    ${t}    IN    @{TUNNEL_LIST}
        ${sa}=    Show    ${t}[hub]    show crypto ikev2 sa detail
        ${block}=    Sa Block    ${sa}    ${t}[spoke_wan]
        Should Contain    ${block}    Auth sign: RSA, Auth verify: RSA
        Should Contain    ${block}    Remote id: hostname=${t}[spoke].${DOMAIN_NAME},cn=${t}[spoke].${DOMAIN_NAME},o=cat8000v-ipsec
    END

The NaC data carries no key and the rendered model matches Nautobot
    ${nac}=    Get File    ${CURDIR}/../../nac/data/devices.nac.yaml
    Should Not Contain    ${nac}    pre_shared_key
    Should Not Contain    ${nac}    keyrings:
    Should Contain    ${nac}    authentication local rsa-sig
    ${groups}=    Get File    ${CURDIR}/../../nac/data/device_groups.nac.yaml
    Should Not Contain    ${groups}    psk_
    ${d}=    Nautobot Graphql    { vpn_profiles(name: ["${PROFILE_NAME}"]) { extra_options vpn_phase1_policies { authentication_method } } }
    Should Be Equal    ${d}[vpn_profiles][0][vpn_phase1_policies][0][authentication_method]    RSA
    Should Be Equal    ${d}[vpn_profiles][0][extra_options][ios][trustpoint]    ${PKI}[trustpoint]
    ${fp}=    Ca Fingerprint    ${CA_CRT}
    Should Be Equal    ${d}[vpn_profiles][0][extra_options][ios][ca_fingerprint]    ${fp}

Nautobot records the certificate every router presents
    ${idx}=    Evaluate    json.load(open($INDEX))    modules=json
    FOR    ${r}    IN    @{ROUTER_NAMES}
        ${dev}=    Nautobot Get    dcim/devices/    name=${r}
        ${cf}=    Set Variable    ${dev}[results][0][custom_fields]
        Should Be Equal    ${cf}[cert_serial]    ${idx}[${r}][serial]    msg=${r}: Nautobot's cert_serial differs from the CA index
        Should Be Equal    ${cf}[cert_subject]    ${r}.${DOMAIN_NAME}
        Should Be Equal    ${cf}[cert_expires]    ${{ $idx[$r]['not_after'][:10] }}
    END
    ${p}=    Portal Get    /api/pki
    Should Be Equal    ${p}[authentication]    certificate
    FOR    ${r}    IN    @{ROUTER_NAMES}
        Should Be Equal    ${p}[devices][${r}][serial]    ${idx}[${r}][serial]
    END

The portal renews a spoke's certificate: new serial on the router, in the CA index and in Nautobot; every tunnel back with RSA
    [Documentation]    A real renewal of the first spoke through the portal's renew run (operator): the router's tunnels re-authenticate with
    ...    the new certificate, the old serial is retired into the index's history.
    [Tags]    slow
    ${spoke}=    Set Variable    ${SPOKES}[0]
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

*** Keywords ***
Skip Unless Certificate Mode
    Skip If    '${IKE_AUTH}' != 'certificate'    IKE authenticates with pre-shared keys in the intent (profile.ike.authentication); certificate checks do not apply

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
