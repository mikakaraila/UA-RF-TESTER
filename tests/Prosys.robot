*** Settings ***
Documentation     CTAC Prosys OPC UA Simulation server security tests.
Suite Teardown    Ua Cleanup
#Force Tags        Endpoint
Test Timeout      1 minutes
Library           ..${/}libs${/}UaTestLibrary.py          # OPC UA Python library
Resource          ..${/}resources${/}resource_ua.robot    # OPC UA specific keywords

# Local this environment specific variables other common ones are defined in the resource_opcua
*** Variables ***
${OPCUaHostName}=   opc.tcp://localhost             # The location of the server to be tested
${OPCUaPort}=       53530/OPCUA/SimulationServer    # The port to OPCUA Server with the resource path
${username}=        ctac                            # Added to server for the testing
${password}=        ctac                            # Added to server for the testing
@{params}=          sin    ${5}                     # List of parameters for the method call
@{types}=           String    Double                # List of types for each parameter in the method call

*** Test Cases ***
Test Anonymous Access
    [Documentation]    Anonymous must be forbidden
    [Tags]    Endpoint  Anonymous
    Test Anonymous

Test Client Certificate no PKI
    [Documentation]    Test certificate without PKI use
    [Tags]    Endpoint  Certificate
    Test Client Certificate  ${username}  ${password}  0  C:/users/karaimi/.prosysopc/prosys-opc-ua-simulation-server/PKI/CA/private/SimulationServer@H7Q8Q13_2048.der  ns=6;s=MyLevel

Test Client Certificate with PKI
    [Documentation]    Test certificate with PKI use
    [Tags]    Endpoint  Certificate
    Test Client Certificate  ${username}  ${password}  1  SimulationServer@H7Q8Q13_2048.der  ns=6;s=MyLevel

Test Invalid User No Access
    [Documentation]    Valid username, invalid password
    [Tags]    Endpoint  PassWord
    Test Invalid UserName PassWord  ${username}

Test Valid User Access OK
    [Documentation]    Valid username, valid password
    [Tags]    Endpoint  PassWord
    Test Valid UserName PassWord  ${username}  ${password}

Test Endpoints are secure
    [Documentation]     Check all endpoints
    [Tags]    Endpoint  Validate  Certificate  Security
    Test Endpoints  ${username}  ${password}

Test Current Time
    [Documentation]     Compare server time with client time (NTP)
    [Tags]    CurrentTime
    Test Current Time

Test Server Diagnostics
    [Documentation]     Test will not fail to warn/error messages
    [Tags]    Diagnostics
    Test Diagnostics  ${username}  ${password}

Test Method
    [Documentation]     Test method call Prosys MyMethod sin(5)
    [Tags]    MethodCall
    Test Method  ${username}  ${password}  ns=6;s=MyDevice  ns=6;s=MyMethod  ${params}  ${types}

Test Write Variable
    [Documentation]     Test write variables
    [Tags]    Write
    Test Write  ${username}  ${password}  ns=5;s=Float  Float  0.5
    Test Write  ${username}  ${password}  ns=5;s=Double  Double  0.5
    Test Write  ${username}  ${password}  ns=5;s=Int32  Int32  -32
    Test Write  ${username}  ${password}  ns=5;s=Int16  Int16  -16
    Test Write  ${username}  ${password}  ns=5;s=SByte  SByte  -8
    Test Write  ${username}  ${password}  ns=5;s=UInt32  UInt32  32
    Test Write  ${username}  ${password}  ns=5;s=UInt16  UInt16  16
    Test Write  ${username}  ${password}  ns=5;s=Byte  Byte  8
    Test Write  ${username}  ${password}  ns=5;s=String  String  Test
    Test Write  ${username}  ${password}  ns=5;s=Boolean  Boolean  True
    Test Write  ${username}  ${password}  ns=5;s=Boolean  Boolean  False
    Test Write  ${username}  ${password}  ns=5;s=DateTime  DateTime  2024-01-16 10:01:20

Test Read Variable
    [Documentation]     Test read variables, value is written is used here for validation
    [Tags]    Read
    Test Read  ${username}  ${password}  ns=5;s=Float  Float  0.5
    Test Read  ${username}  ${password}  ns=5;s=Double  Double  0.5
    Test Read  ${username}  ${password}  ns=5;s=Int32  Int32  -32
    Test Read  ${username}  ${password}  ns=5;s=Int16  Int16  -16
    Test Read  ${username}  ${password}  ns=5;s=SByte  SByte  -8
    Test Read  ${username}  ${password}  ns=5;s=UInt32  UInt32  32
    Test Read  ${username}  ${password}  ns=5;s=UInt16  UInt16  16
    Test Read  ${username}  ${password}  ns=5;s=Byte  Byte  8
    Test Read  ${username}  ${password}  ns=5;s=String  String  Test
    Test Read  ${username}  ${password}  ns=5;s=Boolean  Boolean  False
    Test Read  ${username}  ${password}  ns=5;s=DateTime  DateTime  2024-01-16 10:01:20

Test Read History
    [Documentation]     Test read history
    [Tags]    History
    Test Read History  ${username}  ${password}  ns=6;s=MyLevel

Test StatusCodes
    [Documentation]     Test set statuscode
    [Tags]    StatusCode
    Test StatusCode  ${username}  ${password}  ns=5;s=Float  BadDeviceFailure
    Test StatusCode  ${username}  ${password}  ns=5;s=Float  UncertainEngineeringUnitsExceeded
    Test StatusCode  ${username}  ${password}  ns=5;s=Float  UncertainSubstituteValue
    Test StatusCode  ${username}  ${password}  ns=5;s=Float  UncertainInitialValue
    Test StatusCode  ${username}  ${password}  ns=5;s=Float  BadNoCommunication
    Test StatusCode  ${username}  ${password}  ns=5;s=Float  UncertainSubNormal
    Test StatusCode  ${username}  ${password}  ns=5;s=Float  GoodLocalOverride
    Test StatusCode  ${username}  ${password}  ns=5;s=Float  Good

Test SourceTimestamp
    [Documentation]     Test set source timestamp
    [Tags]    SourceTimestamp
    Test SourceTimestamp  ${username}  ${password}  ns=5;s=Float

Test Access Levels
    [Documentation]     Test access levels
    [Tags]    AccessLevels
    Test Access Level  ${username}  ${password}  ns=5;s=AccessLevelCurrentRead
    Test Access Level  ${username}  ${password}  ns=5;s=AccessLevelCurrentReadNotUser
    Test Access Level  ${username}  ${password}  ns=5;s=AccessLevelCurrentReadWrite
    Test Access Level  ${username}  ${password}  ns=5;s=AccessLevelCurrentWrite
    Test Access Level  ${username}  ${password}  ns=5;s=AccessLevelCurrentWriteNotUser
    Test Access Level  ${username}  ${password}  ns=6;s=MyLevel

# PERMISSIONS ARE NOT IMPLEMENTED ON Prosys UA Simulation server
Test Permissions
    [Documentation]     Test permissions from given root variable
    [Tags]    Permissions
    Test Permissions  ${username}  ${password}  ns=5;s=StaticVariables

Test Subscription
    [Documentation]     Test subscription for Simulation Counter (5s)
    [Tags]    Subscription
    Test Subscription  ${username}  ${password}  ns=3;i=1001

Test Events
    [Documentation]     Test server events (60s)
    [Tags]    Events
    Test Events  ${username}  ${password}

Test DDOS
    [Documentation]     Test server denial of service 
    [Tags]    DDOS
    Test DDOS  ${username}  ${password}
