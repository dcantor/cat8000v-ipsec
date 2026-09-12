*** Settings ***
Documentation     Shared settings for the C8000v IPsec VTI lab suites.
Library           LabLib.py
Variables         lab_vars.py
Library           Collections
Library           String

*** Keywords ***
Suite Teardown Close Connections
    Close All Connections

Router Host
    [Arguments]    ${r}
    RETURN    ${ROUTERS}[${r}][host]

Show
    [Documentation]    Run a show command on a router by name.
    [Arguments]    ${r}    ${command}    ${timeout}=60
    ${host}=    Router Host    ${r}
    ${out}=    Run Command    ${host}    ${command}    ${timeout}
    RETURN    ${out}
