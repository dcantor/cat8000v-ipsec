*** Settings ***
Documentation     Shared settings for the C8000v IPsec VTI lab suites.
Library           LabLib.py
Variables         lab_vars.py
Library           Collections
Library           OperatingSystem
Library           String

*** Keywords ***
Suite Teardown Close Connections
    Close All Connections

Router Host
    [Documentation]    The management address of any Catalyst 8000v: a headend, a branch, or the DCI chain off west-headend.
    [Arguments]    ${r}
    RETURN    ${ALL_ROUTERS}[${r}][host]

Show
    [Documentation]    Run a show command on a router by name.
    [Arguments]    ${r}    ${command}    ${timeout}=60
    ${host}=    Router Host    ${r}
    ${out}=    Run Command    ${host}    ${command}    ${timeout}
    RETURN    ${out}

Skip If Started From A Portal Run
    [Documentation]    The portal runs one pipeline at a time. When the suites are the `test` step of a run, a portal run this test
    ...    would start queues behind that very run and never executes — so the test is skipped here and runs when the suite is
    ...    started from a shell (./lab.sh test) or from a `test`-only run.
    [Arguments]    ${what}=this test starts a portal run
    ${inside}=    Get Environment Variable    PORTAL_RUN_ID    ${EMPTY}
    Skip If    $inside    ${what}: the run queue is busy with run ${inside}, which is running this suite — start the suites from a shell to exercise it
