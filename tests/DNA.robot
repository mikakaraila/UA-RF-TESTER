*** Settings ***
Documentation     CTAC OPC UA server test endpoint security.
Suite Teardown    Ua Cleanup
#Force Tags        Endpoint
Test Timeout      1 minutes
Library           ..${/}libs${/}UaTestLibrary.py          # OPC UA Python library
Resource          ..${/}resources${/}resource_ua.robot    # OPC UA specific keywords

*** Variables ***
${OPCUaHostName}=   opc.tcp://localhost       # The location of the server to be tested
${OPCUaPort}=       62544                     # The port to OPCUA Server
${username}=        ctac                            # Added to server for the testing
${password}=        ctac                            # Added to server for the testing

*** Test Cases ***
Test Current Time
    [Documentation]    Test current time
    [Tags]    CurrentTime
    ${rc}=    Opcua Current Time    ${OPCUaHostName}    ${OPCUaPort}    ctac    ctac
    Should Be Equal As Integers	${rc}	0
    [Timeout]   10 seconds

Test Permissions
    [Documentation]     Test permissions from given root variable
    [Tags]    Permissions
    Test Permissions  ${username}  ${password}  ns=1;s=DNA
#   Test Permissions  ${username}  ${password}  ns=1;s=M3-TANK5-MTR1/curh