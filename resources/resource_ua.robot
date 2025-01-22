*** settings ***
Documentation     This uses def functions that will wait until async opcua function is executed
Library           ..${/}libs${/}UaTestLibrary.py    # Access to read/write variables into the system

*** Variables ***
${Timeout}          60s

*** keywords ***
Test Anonymous
    [Documentation]    Test Anonymous access
    ${rc}=    Ua No Anonymous    ${OPCUaHostName}    ${OPCUaPort}
    Should Be Equal As Integers	${rc}	0
    [Timeout]    ${Timeout}

Test Client Certificate
    [Arguments]        ${username}  ${password}  ${PKI}  ${server_certificate}  ${variable}
    [Documentation]    Test client certificate based access to server PKI = 0 (no PKI)
    ${rc}=    Ua Use Client Certificate    ${OPCUaHostName}    ${OPCUaPort}    ${username}    ${password}    ${PKI}    ${server_certificate}    ${variable}
    Should Be Equal As Integers	${rc}	0
    [Timeout]    ${Timeout}

Test Invalid UserName PassWord
    [Arguments]       ${username}    ${password}=WrongPassWord
    [Documentation]   Test access with invalid username and password
    ${rc}=    Ua Invalid User    ${OPCUaHostName}    ${OPCUaPort}    ${username}    ${password}
    Should Be Equal As Integers	${rc}	0
    [Timeout]    ${Timeout}

Test Valid UserName PassWord
    [Arguments]        ${username}    ${password}
    [Documentation]    Test access with valid username and password
    ${rc}=    Ua User    ${OPCUaHostName}    ${OPCUaPort}    ${username}    ${password}
    Should Be Equal As Integers	${rc}	0
    [Timeout]    ${Timeout}

Test Endpoints
    [Arguments]        ${username}  ${password}
    [Documentation]    Validate endpoints
    ${rc}=    Ua Validate Endpoints    ${OPCUaHostName}    ${OPCUaPort}    ${username}    ${password}
    Should Be Equal As Integers	${rc}	0
    [Timeout]    ${Timeout}

Test Current Time
    [Documentation]    Test current time
    ${rc}=    Ua Current Time    ${OPCUaHostName}    ${OPCUaPort}    ${username}  ${password}
    Should Be Equal As Integers	${rc}	0
    [Timeout]   ${Timeout}

Test Diagnostics
    [Arguments]        ${username}  ${password}
    [Documentation]    Test diagnostics (read counters)
    ${rc}=    Ua Test Diagnostics    ${OPCUaHostName}    ${OPCUaPort}    ${username}    ${password}
    Should Be Equal As Integers	${rc}	0
    [Timeout]   ${Timeout}

Test Method
    [Arguments]        ${username}  ${password}  ${parentNodeId}  ${methodNodeId}  ${params}   ${types}
    [Documentation]    Test method call with given parameter values and types (list)
    ${rc}=    Ua Method Call    ${OPCUaHostName}    ${OPCUaPort}    ${username}  ${password}  ${parentNodeId}  ${methodNodeId}  ${params}  ${types}
    Should Be Equal As Integers	${rc}	0
    [Timeout]   ${Timeout}

Test Write
    [Arguments]        ${username}  ${password}  ${variable}  ${type}  ${value}
    [Documentation]    Test write variable
    ${rc}=    Ua Write Variable    ${OPCUaHostName}    ${OPCUaPort}    ${username}  ${password}  ${variable}  ${type}  ${value}
    Should Be Equal As Integers	${rc}	0
    [Timeout]   ${Timeout}

Test Read
    [Arguments]        ${username}  ${password}  ${variable}  ${type}  ${value}
    [Documentation]    Test read variable
    ${rc}=    Ua Read Variable    ${OPCUaHostName}    ${OPCUaPort}    ${username}  ${password}  ${variable}  ${type}  ${value}
    Should Be Equal As Integers	${rc}	0
    [Timeout]   ${Timeout}

Test Read History
    [Arguments]        ${username}  ${password}  ${variable}
    [Documentation]    Test read history from variable
    ${rc}=    Ua Read History    ${OPCUaHostName}    ${OPCUaPort}    ${username}  ${password}  ${variable}
    Should Be Equal As Integers	${rc}	0
    [Timeout]   ${Timeout}

Test StatusCode
    [Arguments]        ${username}  ${password}  ${variable}  ${statuscode}
    [Documentation]    Test set statuscode
    ${rc}=    Ua set variable statuscode    ${OPCUaHostName}    ${OPCUaPort}    ${username}  ${password}  ${variable}  ${statuscode}
    Should Be Equal As Integers	${rc}	0
    [Timeout]   ${Timeout}

Test SourceTimestamp
    [Arguments]        ${username}  ${password}  ${variable}
    [Documentation]    Test set source timestamp
    ${rc}=    Ua set variable source timestamp    ${OPCUaHostName}    ${OPCUaPort}    ${username}  ${password}  ${variable}
    Should Be Equal As Integers	${rc}	0
    [Timeout]   ${Timeout}

Test Access Level
    [Arguments]        ${username}  ${password}  ${variable}
    [Documentation]    Test variable access level
    ${rc}=    Ua Read Access Level    ${OPCUaHostName}    ${OPCUaPort}    ${username}  ${password}  ${variable}
    Should Be Equal As Integers	${rc}	0
    [Timeout]   ${Timeout}

Test Subscription
    [Arguments]        ${username}  ${password}  ${variable}
    [Documentation]    Test subscription
    ${rc}=    Ua Test Subscription    ${OPCUaHostName}    ${OPCUaPort}    ${username}  ${password}  ${variable}
    Should Be Equal As Integers	${rc}	0
    [Timeout]   ${Timeout}

Test Permissions
    [Arguments]        ${username}  ${password}  ${variable}
    [Documentation]    Test permissions, browse all nodes under root variable
    ${rc}=    Ua Read Permissions    ${OPCUaHostName}    ${OPCUaPort}    ${username}  ${password}  ${variable}
    Should Be Equal As Integers	${rc}	0
    [Timeout]   ${Timeout}

Test Events
    [Arguments]        ${username}  ${password}
    [Documentation]    Test events
    ${rc}=    Ua Test Events    ${OPCUaHostName}    ${OPCUaPort}    ${username}  ${password}
    Should Be Equal As Integers	${rc}	0
    [Timeout]   ${Timeout}

Test DDOS
    [Arguments]        ${username}  ${password}
    [Documentation]    Test DDOS
    ${rc}=    Ua Test DDOS    ${OPCUaHostName}    ${OPCUaPort}    ${username}  ${password}
    Should Be Equal As Integers	${rc}	0
    [Timeout]   ${Timeout}
