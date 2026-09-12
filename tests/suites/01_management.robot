*** Settings ***
Documentation     Out-of-band management plane of the C8000v routers: reachability, SSH, RESTCONF, Mgmt-vrf, hardening.
Resource          ../resources/common.resource
Suite Teardown    Suite Teardown Close Connections

*** Test Cases ***
Routers are reachable over the OOB network with SSH and RESTCONF
    FOR    ${r}    IN    @{ROUTER_NAMES}
        ${host}=    Router Host    ${r}
        Host Ping    ${host}
        Tcp Port Should Be Open    ${host}    22
        Tcp Port Should Be Open    ${host}    443
        ${json}=    Restconf Get    ${host}    Cisco-IOS-XE-native:native/hostname
        Should Be Equal    ${json}[Cisco-IOS-XE-native:hostname]    ${r}
        ${ver}=    Show    ${r}    show version | include uptime|Version 17
        Should Contain    ${ver}    ${r} uptime
        Should Contain    ${ver}    Version 17.15
    END

Management interface lives in Mgmt-vrf with a default route to the host
    FOR    ${r}    IN    @{ROUTER_NAMES}
        ${cfg}=    Show    ${r}    show run interface GigabitEthernet1
        Should Contain    ${cfg}    vrf forwarding Mgmt-vrf
        Should Contain    ${cfg}    ip address ${ROUTERS}[${r}][host] 255.255.255.0
        ${rt}=    Show    ${r}    show ip route vrf Mgmt-vrf 0.0.0.0
        Should Contain    ${rt}    Routing entry for 0.0.0.0/0
        Should Match Regexp    ${rt}    (?m)^\\s*\\*?\\s*${OOB_GATEWAY}\\b
    END

License boot level provides the security feature set
    FOR    ${r}    IN    @{ROUTER_NAMES}
        ${lic}=    Show    ${r}    show version | include License Level
        Should Match Regexp    ${lic}    (?m)^License Level:\\s*network-advantage
        Should Match Regexp    ${lic}    (?m)^Addon License Level:\\s*dna-advantage
    END

AAA, SSH and VTY hardening from the NAC baseline
    FOR    ${r}    IN    @{ROUTER_NAMES}
        ${aaa}=    Show    ${r}    show run | include ^aaa
        Should Match Regexp    ${aaa}    (?m)^aaa new-model$
        Should Match Regexp    ${aaa}    (?m)^aaa authentication login default local$
        Should Match Regexp    ${aaa}    (?m)^aaa authorization exec default local\\s*$
        ${ssh}=    Show    ${r}    show ip ssh
        Should Contain    ${ssh}    SSH Enabled - version 2.0
        Should Contain    ${ssh}    Authentication timeout: 60 secs; Authentication retries: 3
        ${vty}=    Show    ${r}    show run | section ^line vty
        Should Contain    ${vty}    transport input ssh
        Should Contain    ${vty}    access-class ${MGMT_ACL} in vrf-also
        ${acl}=    Show    ${r}    show ip access-lists ${MGMT_ACL}
        Should Match Regexp    ${acl}    20 permit 10\\.2\\.0\\.0, wildcard bits 0\\.0\\.0\\.255
        ${banner}=    Show    ${r}    show run | section ^banner motd
        Should Contain    ${banner}    ${BANNER_TEXT}
    END
