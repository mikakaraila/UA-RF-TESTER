'''
MIT License

Copyright (c) 2023  Valmet Automation - Finland (https://www.valmet.com)

Copyright (c) 2024 Mika Karaila, mika.karaila@valmet.com

OPC UA Test Library is part of CTAC project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''
#
# This test library is part of CTAC project.
# Purpose: CI/CD Robot Framework test library to be used with resource and SUT robot files.
# Example: Files are UaTestLibrary.py, resource_ua.robot and Prosys.robot (to test Prosys UA Simulation server.
#          Note: add user ctac password ctac to server).
# Execute: robot tests\prosys.robot
#
from asyncua import Client, ua
from robot.api.deco import keyword, not_keyword
import logging as logger
import asyncio
import datetime
import socket
import os
from pathlib import Path
import shutil
# Needed for certificates
from cryptography.x509.oid import ExtendedKeyUsageOID
from asyncua import Client
from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256
from asyncua.crypto.cert_gen import setup_self_signed_certificate
from asyncua.crypto.validator import CertificateValidator, CertificateValidatorOptions
from asyncua.crypto.truststore import TrustStore

@keyword
def ua_use_client_certificate(server, port, username, password, PKI, cert, variable):
	"""
    Test:   Server access with certificate.

		*Server*: _opc.tcp://hostname_

		*Port*:   _26555/resource_path_

		*Username*:   _username_

		*Password*:   _password_

		*PKI*:    _use PKI Store folder structure_ (0 == NO PKI, 1 = PKI)
		*cert*:   _server certificate_ NOTE: NO PKI use absolute paths, PKI only certificate filename.
		*variable*: _nodeId of test variable_
  """
	loop = asyncio.get_event_loop()
	#loop.set_debug(True)
	rc = loop.run_until_complete(opcua_use_client_certificate(server, port, username, password, PKI, cert, variable))
	return rc

@not_keyword
async def opcua_use_client_certificate(server, port, username, password, PKI, scert, variable):
	logger.getLogger('asyncua').setLevel(logger.ERROR)
	logger.basicConfig(level=logger.ERROR)
	rc = -1
	if (int(PKI) == 0):
		logger.info("Not using PKI folder structure, absolute file paths used")
		USE_TRUST_STORE = False
	else:
		logger.info("Using PKI folder structure, certificate file basename must be used!")
		USE_TRUST_STORE = True

	if USE_TRUST_STORE:
		# Create folders needed
		# PKI TRUSTED FOLDER
		path = os.path.join(os.getcwd(), "certificates/PKI/trusted/certs")
		# Create PKI folder structure for trusted certificates
		try:
			os.makedirs(path, exist_ok=True)
			logger.info("PKI trusted certificates folder: " + path + " created successfully")
			logger.warn("Remember to copy server public certificate to PKI trusted certificates folder: " + path)
		except OSError as error:
			logger.error("PKI trusted certificates folder '%s' can not be created! Error: '%s'" % path, str(error))
		# PKI OWN CERTIFICATE
		path = os.path.join(os.getcwd(), "certificates/PKI/own/certs")
		# Create PKI folder structure for trusted certificates
		try:
			os.makedirs(path, exist_ok=True)
			logger.info("PKI own certificates folder: " + path + " created successfully")
		except OSError as error:
			logger.error("PKI own certificates folder '%s' can not be created! Error: '%s'" % path, str(error))
		# PKI PRIVATE KEY FOLDER
		path = os.path.join(os.getcwd(), "certificates/PKI/own/private")
		# Create PKI folder structure for trusted certificates
		try:
			os.makedirs(path, exist_ok=True)
			logger.info("PKI own private key folder: " + path+ " created successfully")
		except OSError as error:
			logger.error("PKI own private key folder '%s' can not be created! Error: '%s'" % path, str(error))

	cert_base = Path(__file__).parent
	cert = Path(cert_base / f"CTAC_cert.der")
	private_key = Path(cert_base / f"CTAC_key.pem")
	# Example value:
	# C:/users/karaimi/.prosysopc/prosys-opc-ua-simulation-server/PKI/CA/private/SimulationServer@H7Q8Q13_2048.der
	# or with PKI
	# SimulationServer@H7Q8Q13_2048.der
	server_cert = scert
	if USE_TRUST_STORE:
		cwd = Path(os.getcwd())
		cert_trust_store = os.path.join(cwd, f"certificates/PKI/own/certs/CTAC_cert.der")
		private_key_trust_store = os.path.join(cwd, f"certificates/PKI/own/private/CTAC_key.pem")
		server_cert = os.path.join(os.getcwd(), f"certificates/PKI/trusted/certs/" + scert) # SimulationServer@H7Q8Q13_2048.der")

	logger.info("Using self signed certificate:   " + str(cert))
	logger.info("Using private key:               " + str(private_key))
	logger.info("Using server public certificate: " + server_cert)

	host_name = socket.gethostname()
	client_app_uri = f"urn:{host_name}:CTAC:RobotFramework" # Certificate name that will be on server side
	if (os.path.exists(cert) and os.path.exists(private_key)):
		logger.info("Own self-signed certificates already created")
	else:
		logger.info("Creating self-signed certificates for the client: " + client_app_uri)
		logger.warn("You must trust client certificate on server and re-run this test!")
	# Create self-signed certificate for this client
	await setup_self_signed_certificate(private_key,
                                      cert,
                                      client_app_uri,
                                      host_name,
                                      [ExtendedKeyUsageOID.CLIENT_AUTH],
                                      {
                                        'countryName': 'FI',
                                        'stateOrProvinceName': 'CTAC Consortium',
                                        'localityName': 'CTAC',
                                        'organizationName': "CTAC",
                                      })

	client = Client(url=server + ":" + port, timeout=5.0)
	client.application_uri = client_app_uri
	if (not(os.path.exists(server_cert))):
		logger.error("Server public certificate file not found, check file path: "  + server_cert)
		rc = -1
	else:
		logger.info("Server public certificate found, file path: " + server_cert)

	client.session_timeout = 600000
	client.set_user(username)
	client.set_password(password)
	logger.info("Server=" + server + " port=" + port + "username= " + username)

	try:
		await client.set_security(
           SecurityPolicyBasic256Sha256, # TODO Check others
           certificate=str(cert),
           private_key=str(private_key),
           server_certificate=server_cert
       )
	except Exception as e:
		rc = -1
		logger.error("Set security: " + str(e))

	if USE_TRUST_STORE:
		# Copy own certificate & private key to trust store, not mandatory but better to place them into correct places
		shutil.copy(cert, cert_trust_store)
		shutil.copy(private_key, private_key_trust_store)
		trust_store = TrustStore([Path('certificates') / 'PKI' / 'trusted' / 'certs'], [])
		await trust_store.load()
		# Check if more options should be used
		validator =CertificateValidator(CertificateValidatorOptions.TRUSTED_VALIDATION|CertificateValidatorOptions.PEER_SERVER, trust_store)
	else:
		# Check if more options should be used
		validator =CertificateValidator(CertificateValidatorOptions.BASIC_VALIDATION|
                                    CertificateValidatorOptions.EXT_VALIDATION|
                                    CertificateValidatorOptions.TIME_RANGE|
                                    CertificateValidatorOptions.KEY_USAGE|
                                    CertificateValidatorOptions.EXT_KEY_USAGE|
                                    CertificateValidatorOptions.EXT_VALIDATION)
	client.certificate_validator = validator
	logger.warn("Check after first time connect that you have trusted client certificate on server side: " + client_app_uri)

	try:
		async with client:
			var = client.get_node(variable)
			logger.info("Variable value: " + str(await var.get_value()))
			rc = 0
	except ua.UaError as exp:
		logger.error("Cannot read variable: " + variable + " error: " + str(exp))
		rc = -1
		
	return rc

@keyword
def ua_no_anonymous(server, port):
	"""
	Test:   Server shall not have Anonymous access.

    *Server*: _opc.tcp://hostname_

    *Port*:   _26555/resource_path_
	"""
	loop = asyncio.get_event_loop()
	rc = loop.run_until_complete(opcua_no_anonymous(server, port))
	return rc
 
@not_keyword
async def opcua_no_anonymous(server, port):
	logger.getLogger('asyncua').setLevel(logger.ERROR)
	logger.basicConfig(level=logger.ERROR)
	rc = -1 # FAILED
	client = Client(server+":"+port + "/", timeout=5) # Server cannot response in normal 4s timeout
	client.session_timeout = 600000
	logger.info("Server=" + server +" port=" + port)
	if client:
		client.name = "CTAC"
		client.application_uri = "urn:CTAC:RobotFramework"
		try:
			await client.connect()
			logger.info("Client connected!")
			await client.disconnect()
			logger.error("Failed: Anonymous can access server!")
			return rc
		except:
			logger.info("Passed: Anonymous cannot access server!")
			rc = 0
	else:
		logger.error("Failed: Cannot connect server!")
	return rc

# Test valid username & password
@keyword
def ua_user(server, port, username, password):
	"""
	Test:   Sign in to server with valid username and password.

    *Server*: _opc.tcp://hostname_

    *Port*:   _26555/resource_path_

		*Username*:   _username_

		*Password*:   _password_
	"""
	loop = asyncio.get_event_loop()
	return loop.run_until_complete(opcua_user(server, port, username, password))

@keyword
async def opcua_user(server, port, username, password):
	logger.getLogger('asyncua').setLevel(logger.ERROR)
	logger.basicConfig(level=logger.ERROR)
	rc = -1 # FAILED
	client = Client(server+":"+port,timeout=5) # Server cannot response in normal 4s timeout
	client.session_timeout = 600000
	logger.info("Server="+server+" port="+port)
	client.set_user(username)
	client.set_password(password)
	if client:
		client.name = "CTAC"
		client.application_uri = "urn:CTAC:RobotFramework"
		try:
			await client.connect()
			logger.info("Client connected!")
			await client.disconnect()
			logger.info("Valid user can access server!")
			rc = 0
		except:
			logger.error("Wrong username / password")
	else:
		logger.error("Client cannot connect!")
	return rc

@keyword
def ua_invalid_user(server, port, username, password):
	"""
	Test:   Sign in to server shall not succeed with *invalid* username / password.

    *Server*: _opc.tcp://hostname_

    *Port*:   _26555/resource_path_

		*Username*:   _username_

		*Password*:   _password_
	"""
	loop = asyncio.get_event_loop()
	return loop.run_until_complete(opcua_invalid_user(server, port, username, password))

@not_keyword
async def opcua_invalid_user(server, port, username, password):
	logger.getLogger('opcua').setLevel(logger.ERROR)
	logger.basicConfig(level=logger.ERROR)
	rc = -1 # FAILED
	client = Client(server+":"+port,timeout=5) # Server cannot response in normal 4s timeout
	client.session_timeout = 600000
	logger.info("Server="+server+" port="+port)
	client.set_user(username)
	client.set_password(password)
	if client:
		client.name = "CTAC"
		client.application_uri = "urn:CTAC:RobotFramework"
		try:
			await client.connect()
			logger.info("Client connected!")
			await client.disconnect()
			logger.error("Invalid username / password can access server!")
		except:
			logger.info("Wrong password OK")
			rc = 0
	else:
		logger.error("Client cannot connect!")
	return rc

def ua_current_time(server, port, username, password, timedelta=30):
	"""
	Test:   Validate that server current time and client current time is almost same.
	 
		      NTP sync should be used in all computers.

    *Server*: _opc.tcp://hostname_

    *Port*:   _26555/resource_path_

		*Username*:   _username_

		*Password*:   _password_

		*Timedelta*:   _timedelta_ (default 30)
	"""
	loop = asyncio.get_event_loop()
	return loop.run_until_complete(opcua_current_time(server, port, username, password, timedelta))

async def opcua_current_time(server, port, username, password, timedelta=30):
	logger.getLogger('asyncua').setLevel(logger.ERROR)
	logger.basicConfig(level=logger.ERROR)
	rc = -1 # FAILED
	client = Client(server+":"+port,timeout=5) # Server cannot response in normal 4s timeout
	client.session_timeout = 600000
	logger.info("Server=" + server + " port=" + port + " username= "+ username + " timedelta= " + str(timedelta))
	client.set_user(username)
	client.set_password(password)
	client.name = "CTAC"
	client.application_uri = "urn:CTAC:RobotFramework"
	async with client:
		ct = client.get_node("ns=0;i=2258") # Current time from the server
		value = await ct.read_data_value()
		stime = value.Value.Value
		ctime = datetime.datetime.utcnow()
		d1 = stime - ctime # time difference, should be less than 30s
		d2 = ctime - stime # time difference, should be less than 30s
		d = d1
		if (d1 > d2):
			d = d1
		if (d2 > d1):
			d = d2
		logger.info("Server time: " + str(stime))
		logger.info("Client time: " + str(ctime))
		# Check that server and client are running same time (NTP should be used)
		if (d > datetime.timedelta(seconds=timedelta)):
			logger.error("Clock difference is too much between server and client! Delta time: " + str(d) + " limit: " + str(timedelta))
			rc = -1
		else:
			logger.info("Time difference (max " + str(timedelta) + " difference allowed): " + str(d))
			rc = 0
	return rc

def ua_validate_endpoints(server, port, username, password):
	"""
	Test:   Validate server endpoints does not contain None / None security mode/policy and certificates are not deprecated.

    *Server*: _opc.tcp://hostname_

    *Port*:   _26555/resource_path_

		*Username*:   _username_

		*Password*:   _password_
	"""
	loop = asyncio.get_event_loop()
	return loop.run_until_complete(opcua_validate_endpoints(server, port, username, password))

async def opcua_validate_endpoints(server, port, username, password):
	logger.getLogger('asyncua').setLevel(logger.ERROR)
	logger.basicConfig(level=logger.ERROR)
	rc = -1 # FAILED
	client = Client(server+":"+port + "/", timeout=5) # Server cannot response in normal 4s timeout
	client.session_timeout = 600000
	logger.info("Server=" + server +" port=" + port)
	client.set_user(username)
	client.set_password(password)
	endpoints = None
	if client:
		client.name = "CTAC"
		client.application_uri = "urn:CTAC:RobotFramework"
		await client.connect()
		logger.info("Client connected!")
		endpoints = await client.get_endpoints()
		# logger.info(endpoints)
		# Check all endpoints: 
		# No None security policy
		# No None security mode
		# No unsecure/deprecated certificates:
		#  Security Policy Basic256 deprecated
		#  Security Policy Basic128Rsa15 deprecated
		for e in endpoints:
			#logger.info("Endpoint: "+ str(e.SecurityPolicyUri))
			if ("None" in str(e.SecurityMode) and "None" in str(e.SecurityPolicyUri)):
				logger.error("Server endpoint is not secure: " + str(e.SecurityMode) + " / " + str(e.SecurityPolicyUri))
			if ("Basic256" in str(e.SecurityPolicyUri) and not "Basic256Sha256" in str(e.SecurityPolicyUri)):
				logger.warning("Server endpoint deprecated: " + e.SecurityPolicyUri)
			if ("Basic128Rsa15" in str(e.SecurityPolicyUri)):
				logger.warning("Server endpoint deprecated: " + e.SecurityPolicyUri)
		await client.disconnect()
		rc = 0
	else:
		logger.error("Client cannot connect!")
	return rc

@not_keyword
async def infoVariable(client, varname, nodeId):
	tmp = client.get_node(nodeId)
	tmpValue = await tmp.get_value()
	logger.info(varname + " = " + str(tmpValue))

@not_keyword
async def warnVariableNotZero(client, varname, nodeId):
	tmp = client.get_node(nodeId)
	tmpValue = await tmp.get_value()
	if (tmpValue > 0):
		logger.warn(varname + " > 0 value=" + str(tmpValue))

@not_keyword
async def errorVariableNotZero(client, varname, nodeId):
	tmp = client.get_node(nodeId)
	tmpValue = await tmp.get_value()
	if (tmpValue > 0):
		logger.error(varname + " > 0 value=" + str(tmpValue))

@keyword
def ua_test_diagnostics(server, port, username, password):
	"""
	Test:   Check server diagnostic counters.
	 
	        Info level log diagnostic data variables.

          Warning level log if error counter != 0.

          Error level if security related counter != 0.

    *Server*: _opc.tcp://hostname_

    *Port*:   _26555/resource_path_

		*Username*:   _username_

		*Password*:   _password_
	"""
	loop = asyncio.get_event_loop()
	return loop.run_until_complete(opcua_test_diagnostics(server, port, username, password))

@not_keyword
async def opcua_test_diagnostics(server, port, username, password):
	logger.getLogger('asyncua').setLevel(logger.ERROR)
	logger.basicConfig(level=logger.ERROR)
	rc = -1 # FAILED
	client = Client(server+":"+port + "/", timeout=5) # Server cannot response in normal 4s timeout
	client.session_timeout = 600000
	logger.info("Server=" + server +" port=" + port)
	client.set_user(username)
	client.set_password(password)
	endpoints = None
	if client:
		client.name = "CTAC"
		client.application_uri = "urn:CTAC:RobotFramework"
		await client.connect()
		logger.info("Client connected!")
		# TODO Read meaningful / practical diagnostics
		# ServerStatus print to log
		await infoVariable(client, "ProductName", "ns=0;i=2261")
		await infoVariable(client, "ProductUri", "ns=0;i=2262")
		await infoVariable(client, "ManufacturerName", "ns=0;i=2263")
		await infoVariable(client, "SoftwareVersion", "ns=0;i=2264")
		await infoVariable(client, "BuildDate", "ns=0;i=2266")
		await infoVariable(client, "BuildNumber", "ns=0;i=2265")

		await infoVariable(client, "CurrentSessionCount", "ns=0;i=2277")
		await infoVariable(client, "CumulatedSessionCount", "ns=0;i=2278")
		await infoVariable(client, "CurrentSubscriptionCount", "ns=0;i=2285")
		# Read again after some time variables above to check if increased
		# NOTE ActualSessionTimeout will limit this, think if we should use keepalive or session subscription with current time
		
		# Read rejected counters that will make warning
		await warnVariableNotZero(client, "RejectedRequestCount", "ns=0;i=2288")
		await warnVariableNotZero(client, "RejectedSessionCount", "ns=0;i=3705")
		await warnVariableNotZero(client, "SessionAbortCount", "ns=0;i=2282")
		await warnVariableNotZero(client, "SessionTimeoutCount", "ns=0;i=2281")

		# Read rejected counters that will make error
		await errorVariableNotZero(client, "SecurityRejectedRequestCount", "ns=0;i=2287")
		await errorVariableNotZero(client, "SecurityRejectedSessionCount", "ns=0;i=2279")

		await client.disconnect()
		rc = 0
	else:
		logger.error("Client cannot connect!")
	return rc

@keyword
def ua_method_call(server, port, username, password, parentNodeId, methodNodeId, params, types):
	#def ua_method_call(server, port, username, password, parentNodeId, methodNodeId, value1, type1, value2, type2):
	"""
	Test:   Call server method with given value(s) & type(s).
	 
    *Server*:       _opc.tcp://hostname_

    *Port*:         _26555/resource_path_

		*Username*:     _username_

		*Password*:     _password_

		*ParentNodeId:* _ns=6;s=MyDevice_
		*MethodNodeId:* _ns=6;s=MyMethod_
		*value1:*       _sin_
		*type1:*        _String_
		*value2:*       _5.0_
		*type2:*        _Double_
	"""
	loop = asyncio.get_event_loop()
	return loop.run_until_complete(opcua_method_call(server, port, username, password, parentNodeId, methodNodeId, params, types))

@not_keyword
def type_to_uatype(typeAsString):
	if (typeAsString == "String"):
		uaType = ua.VariantType.String
	if (typeAsString == "Float"):
		uaType = ua.VariantType.Float
	if (typeAsString == "Double"):
		uaType = ua.VariantType.Double
	if (typeAsString == "Int32"):
		uaType = ua.VariantType.Int32
	if (typeAsString == "Int16"):
		uaType = ua.VariantType.Int16
	if (typeAsString == "UInt32"):
		uaType = ua.VariantType.UInt32
	if (typeAsString == "UInt16"):
		uaType = ua.VariantType.UInt16
	if (typeAsString == "Byte"):
		uaType = ua.VariantType.Byte
	if (typeAsString == "SByte"):
		uaType = ua.VariantType.SByte	
	return uaType

# NOTE Default parameters are for Prosys
# TODO Extend from 2 value & type to dynamic amount of parameters [1..n]
@not_keyword
async def opcua_method_call(server, port, username, password, parentNodeId, methodNodeId, params, types):
	# async def opcua_method_call(server, port, username, password, parentNodeId="ns=6;s=MyDevice", methodNodeId="ns=6;s=MyMethod", value1="sin", type1="String", value2=5.0, type2="Double"):
	logger.getLogger('asyncua').setLevel(logger.ERROR)
	logger.basicConfig(level=logger.ERROR)
	rc = -1 # FAILED
	client = Client(server+":"+port + "/", timeout=5) # Server cannot response in normal 4s timeout
	client.session_timeout = 600000
	logger.info("Server=" + server +" port=" + port, " method parentNodeId=" + parentNodeId + " methodNodeId=" + methodNodeId + " parameters=" + str(params) + " types=" + str(types))
	client.set_user(username)
	client.set_password(password)
	if client:
		client.name = "CTAC"
		client.application_uri = "urn:CTAC:RobotFramework"
		await client.connect()
		logger.info("Client connected!")
		parentId = client.get_node(parentNodeId)
		methodId = client.get_node(methodNodeId)
		# TODO Make function to return string type to ua type
		#pType1 = type_to_uatype(type1)
		#pType2 = type_to_uatype(type2)
		pType = []
		for t in types:
			pType.append(type_to_uatype(t))
		if (len(params) == 0):
			res = await parentId.call_method(methodId, None, None)
		if (len(params) == 1):
			res = await parentId.call_method(methodId, ua.Variant(params[0], pType[0]))
		if (len(params) == 2):
			res = await parentId.call_method(methodId, ua.Variant(params[0], pType[0]), ua.Variant(params[1], pType[1]))
		if (len(params) == 3):
			res = await parentId.call_method(methodId, ua.Variant(params[0], pType[0]), ua.Variant(params[1], pType[1]), ua.Variant(params[2], pType[2]))
		if (len(params) > 3):
			logger.error("Max 3 method call parameters are supported")

		logger.info("Method call result is: %r", res)
		await client.disconnect()
		rc = 0
		# Removed this and make generic or no validation
		'''
		if (round(res,4) == round(0.0871557427477, 4)):
			rc = 0
		else:
			logger.error("Method sin(5) result is not 0.0871557427477 <> %r", res)
			rc = -1
		'''
	else:
		logger.error("Client cannot connect!")
	return rc

def ua_write_variable(server, port, username, password, variable, variableType, value):
	"""
	Test:   Write value to variable based on given type (*NO default values*).

	        NOTE: Value is read back and check that it is same as written value.

    *Server*:       _opc.tcp://hostname_

    *Port*:         _26555/resource_path_

		*Username*:     _username_

		*Password*:     _password_

		*Variable:*     _ns=5;s=Float_
		*VariableType:* _Float_
		*Value:*       _5.0_
	"""
	loop = asyncio.get_event_loop()
	return loop.run_until_complete(opcua_write_variable(server, port, username, password, variable, variableType, value))

@keyword
async def opcua_write_variable(server, port, username, password, variable, variable_type, value):
	logger.getLogger('asyncua').setLevel(logger.ERROR)
	logger.basicConfig(level=logger.ERROR)
	rc = -1 # FAILED
	client = Client(server+":"+port + "/", timeout=5) # Server cannot response in normal 4s timeout
	client.session_timeout = 600000
	logger.info("Server=" + server +" port=" + port)
	client.set_user(username)
	client.set_password(password)
	if client:
		client.name = "CTAC"
		client.application_uri = "urn:CTAC:RobotFramework"
		await client.connect()
		logger.info("Client connected!")
		logger.info("NodeID: " + variable)
		try:
			var = client.get_node(variable)
			if (variable_type == "Double"):
				await var.set_value(ua.Variant(float(value), ua.VariantType.Double))
			if (variable_type == "Float"):
				await var.set_value(ua.Variant(float(value), ua.VariantType.Float))
			if (variable_type == "Int32"):
				await var.set_value(ua.Variant(int(value), ua.VariantType.Int32))
			if (variable_type == "Int16"):
				await var.set_value(ua.Variant(int(value), ua.VariantType.Int16))
			if (variable_type == "Int8" or variable_type == "SByte"):
				await var.set_value(ua.Variant(int(value), ua.VariantType.SByte))
			if (variable_type == "UInt32"):
				await var.set_value(ua.Variant(int(value), ua.VariantType.UInt32))
			if (variable_type == "UInt16"):
				await var.set_value(ua.Variant(int(value), ua.VariantType.UInt16))
			if (variable_type == "UInt8" or variable_type == "Byte"):
				await var.set_value(ua.Variant(int(value), ua.VariantType.Byte))
			if (variable_type == "Boolean"):
				if (value == "True"):
					await var.set_value(ua.Variant(True, ua.VariantType.Boolean))
				if (value == "False"):
					await var.set_value(ua.Variant(False, ua.VariantType.Boolean))
			if (variable_type == "String"):
				await var.set_value(ua.Variant(value, ua.VariantType.String))
			if (variable_type == "DateTime"):
				await var.set_value(ua.Variant(datetime.datetime.strptime(value, "%Y-%m-%d %H:%M:%S"), ua.VariantType.DateTime))
			# TODO ByteString, GUID, Int64, UInt64, XML
			tmp = await var.get_value()
			logger.info("Write value: " + str(value) + " read: " + str(tmp))
			if (str(value) != str(tmp)):
				rc = -1
				logger.error("Validate failed values: " + str(value) + "<>" + str(tmp))
			else:
				rc = 0
		except Exception as e:
			rc = -1
			logger.error("Write failed: " + str(e) + " for variable: " + variable + " " + variable_type + " " + str(value))
		await client.disconnect()
	else:
		logger.error("Client cannot connect!")
	return rc

@keyword
def ua_read_variable(server, port, username, password, variable, variableType, value):
	"""
	Test:   Read value to variable based on given type (*NO default values*).

	        NOTE: Value read is compared to given value.

    *Server*:       _opc.tcp://hostname_

    *Port*:         _26555/resource_path_

		*Username*:     _username_

		*Password*:     _password_

		*Variable:*     _ns=5;s=Float_
		*VariableType:* _Float_
		*Value:*       _5.0_
	"""
	loop = asyncio.get_event_loop()
	return loop.run_until_complete(opcua_read_variable(server, port, username, password, variable, variableType, value))

@not_keyword
async def opcua_read_variable(server, port, username, password, variable, variable_type, value):
	logger.getLogger('asyncua').setLevel(logger.ERROR)
	logger.basicConfig(level=logger.ERROR)
	rc = -1 # FAILED
	client = Client(server+":"+port + "/", timeout=5) # Server cannot response in normal 4s timeout
	client.session_timeout = 600000
	logger.info("Server=" + server +" port=" + port)
	client.set_user(username)
	client.set_password(password)
	if client:
		client.name = "CTAC"
		client.application_uri = "urn:CTAC:RobotFramework"
		await client.connect()
		logger.info("Client connected!")
		logger.info("NodeID: " + variable)
		try:
			var = client.get_node(variable)
			tmp = await var.get_value()
			logger.info("Read value: " + str(tmp) + " validate to " + str(value))
			# TODO Check ByteString, GUID, Int64, UInt64, XML
			if (str(value) != str(tmp)):
				rc = -1
				logger.error("Validate failed values: " + str(tmp) + "<>" + str(value))
			else:
				rc = 0
		except Exception as e:
			rc = -1
			logger.error("Read failed: " + str(e) + " for variable: " + variable + " " + variable_type + " " + str(value))
		await client.disconnect()
	else:
		logger.error("Client cannot connect!")
	return rc

def ua_read_history(server, port, username, password, variable):
	"""
	Test:   Read history (trend data, *last one day*) from the given variable (Log to info values).

    *Server*:       _opc.tcp://hostname_

    *Port*:         _26555/resource_path_

		*Username*:     _username_

		*Password*:     _password_

		*Variable:*     _ns=6;s=MyLevel_
	"""
	loop = asyncio.get_event_loop()
	return loop.run_until_complete(opcua_read_history(server, port, username, password, variable))

@not_keyword
async def opcua_read_history(server, port, username, password, variable):
	logger.getLogger('asyncua').setLevel(logger.ERROR)
	logger.basicConfig(level=logger.ERROR)
	rc = -1 # FAILED
	client = Client(server+":"+port + "/", timeout=5) # Server cannot response in normal 4s timeout
	client.session_timeout = 600000
	logger.info("Server=" + server +" port=" + port)
	client.set_user(username)
	client.set_password(password)
	if client:
		client.name = "CTAC"
		client.application_uri = "urn:CTAC:RobotFramework"
		await client.connect()
		logger.info("Client connected!")
		try:
			var = client.get_node(variable)
			endtime = datetime.datetime.now()
			starttime = endtime - datetime.timedelta(days=1) # TODO one day enough or more/less
			logger.info("NodeID: " + variable + " start time: " + str(starttime) + " end time: " + str(endtime))
			values = await var.read_raw_history(starttime, endtime, numvalues=1000)
			# Shorter values
			i=0
			val=[]
			while(i<len(values)):
				e=values[i]
				v=e.Value
				val.append(v.Value)
				i=i+1
			logger.info("Variable: " + variable + " history values[" + str(i) + "]: " + str(val))
			rc = 0
		except Exception as e:
			rc = -1
			logger.error("Read history failed: " + str(e) + " for variable: " + variable)
		await client.disconnect()
	else:
		logger.error("Client cannot connect!")
	return rc

@keyword
def ua_set_variable_statuscode(server, port, username, password, variable, statuscode):
	"""
	Test:   Write statuscode to variable. After test write back to Good.

	        NOTE: Valid values at the moment: 
					BadDeviceFailure
					UncertainEngineeringUnitsExceeded
					UncertainSubstituteValue
					BadNoCommunication
					UncertainSubNormal
					GoodLocalOverride
					Good

    *Server*:       _opc.tcp://hostname_

    *Port*:         _26555/resource_path_

		*Username*:     _username_

		*Password*:     _password_

		*Variable:*     _ns=5;s=Float_
		*Statuscode:*     _BadDeviceFailure_
	"""
	loop = asyncio.get_event_loop()
	return loop.run_until_complete(opcua_set_variable_statuscode(server, port, username, password, variable, statuscode))

@not_keyword
async def opcua_set_variable_statuscode(server, port, username, password, variable, statuscode):
	logger.getLogger('asyncua').setLevel(logger.ERROR)
	logger.basicConfig(level=logger.ERROR)
	rc = -1 # FAILED
	client = Client(server+":"+port + "/", timeout=5) # Server cannot response in normal 4s timeout
	client.session_timeout = 600000
	logger.info("Server=" + server +" port=" + port)
	client.set_user(username)
	client.set_password(password)
	status = ua.StatusCode(ua.StatusCodes.BadNotImplemented)
	if client:
		client.name = "CTAC"
		client.application_uri = "urn:CTAC:RobotFramework"
		await client.connect()
		logger.info("Client connected!")
		logger.info("NodeID: " + variable)
		try:
			var = client.get_node(variable)
			dv = await var.read_data_value() # Read current value
			logger.info("Variable StatusCode: " + str(dv.StatusCode_))
			if (statuscode == "BadDeviceFailure"):
				status = ua.StatusCode(ua.StatusCodes.BadDeviceFailure)
			if (statuscode == "UncertainEngineeringUnitsExceeded"):
				status = ua.StatusCode(ua.StatusCodes.UncertainEngineeringUnitsExceeded)
			if (statuscode == "UncertainSubstituteValue"):
				status = ua.StatusCode(ua.StatusCodes.UncertainSubstituteValue)
			if (statuscode == "UncertainInitialValue"):
				status = ua.StatusCode(ua.StatusCodes.UncertainInitialValue)
			if (statuscode == "BadNoCommunication"):
				status = ua.StatusCode(ua.StatusCodes.BadNoCommunication)
			if (statuscode == "UncertainSubNormal"):
				status = ua.StatusCode(ua.StatusCodes.UncertainSubNormal)
			if (statuscode == "GoodLocalOverride"):
				status = ua.StatusCode(ua.StatusCodes.GoodLocalOverride)
			if (statuscode == "Good"):
				status = ua.StatusCode(ua.StatusCodes.Good)
			await var.write_attribute(ua.AttributeIds.Value, ua.DataValue(StatusCode_=status)) # Write status
			rc = 0
		except Exception as e:
			rc = 0
			logger.info("Set statuscode: " + str(e) + " for variable: " + variable + " StatusCode: " + str(status))
			#tmp = await var.read_data_value()
			#logger.info("Get statuscode: " + str(tmp.StatusCode_) + " == " + str(status))
		# Set back to Good
		await var.write_attribute(ua.AttributeIds.Value, ua.DataValue(StatusCode_=ua.StatusCode(ua.StatusCodes.Good)))
		await client.disconnect()
	else:
		logger.error("Client cannot connect!")
	return rc

@keyword
def ua_set_variable_source_timestamp(server, port, username, password, variable):
	"""
	Test:   Write current time to variable source timestamp.

    *Server*:       _opc.tcp://hostname_

    *Port*:         _26555/resource_path_

		*Username*:     _username_

		*Password*:     _password_

		*Variable:*     _ns=5;s=Float_
	"""
	loop = asyncio.get_event_loop()
	return loop.run_until_complete(opcua_set_variable_source_timestamp(server, port, username, password, variable))

@not_keyword
async def opcua_set_variable_source_timestamp(server, port, username, password, variable):
	logger.getLogger('asyncua').setLevel(logger.ERROR)
	logger.basicConfig(level=logger.ERROR)
	rc = -1 # FAILED
	client = Client(server+":"+port + "/", timeout=5) # Server cannot response in normal 4s timeout
	client.session_timeout = 600000
	logger.info("Server=" + server +" port=" + port)
	client.set_user(username)
	client.set_password(password)
	if client:
		client.name = "CTAC"
		client.application_uri = "urn:CTAC:RobotFramework"
		await client.connect()
		logger.info("Client connected!")
		logger.info("NodeID: " + variable)
		try:
			var = client.get_node(variable)
			now = datetime.datetime.now()
			await var.write_attribute(ua.AttributeIds.Value, ua.DataValue(SourceTimestamp=now)) # Write SourceTimestamp
			logger.info("Variable: " + variable + " SourceTimestamp: " + str(now))
			rc = 0
		except Exception as e:
			rc = -1
			logger.error("Set source timestamp failed: " + str(e) + " for variable: " + variable)
		await client.disconnect()
	else:
		logger.error("Client cannot connect!")
	return rc

@not_keyword
async def getAccessLevel(node):
  result="" # Empty string
  access = (await node.read_attribute(ua.AttributeIds.AccessLevel)).Value.Value
  r = access & 1<<0 # "CurrentRead"
  w = access & 1<<1 # "CurrentWrite"
  hr = access & 1<<2 # "HistoryRead"
  hw = access & 1<<3 # "HistoryWrite"
  sc = access & 1<<4 # "SemanticChange"
  sw = access & 1<<5 # "StatusWrite"
  tw = access & 1<<6 # "TimestampWrite"
  # If no access "--"
  if (r != 0):
    result = " CurrentRead   " # "CR"
  else:
    result = " ------------- "
  if (w != 0):
    result += " CurrentWrite "
  else:
    result += " ------------ "
  if (hr != 0):
    result += " HistoryRead  "
  else:
    result += " ------------ "
  if (hw != 0):
    result += " HistoryWrite "
  else:
    result += " ------------ "
  if (sc != 0):
    result += "SemanticChange"
  else:
    result += " ------------ "
  if (sw != 0):
    result += " StatusWrite  "
  else:
    result += " ------------ "
  if (tw != 0):
    result += " TimestampWrite"
  else:
    result += " --------------"
  return result

@keyword
def ua_read_access_level(server, port, username, password, variable):
	"""
	Test:   Read variable access level, write to Log info level values.

    *Server*:       _opc.tcp://hostname_

    *Port*:         _26555/resource_path_

		*Username*:     _username_

		*Password*:     _password_

		*Variable:*     _ns=5;s=Float_
	"""
	loop = asyncio.get_event_loop()
	return loop.run_until_complete(opcua_read_access_level(server, port, username, password, variable))

@not_keyword
async def opcua_read_access_level(server, port, username, password, variable):
	logger.getLogger('asyncua').setLevel(logger.ERROR)
	logger.basicConfig(level=logger.ERROR)
	rc = -1 # FAILED
	client = Client(server+":"+port + "/", timeout=5) # Server cannot response in normal 4s timeout
	client.session_timeout = 600000
	logger.info("Server=" + server +" port=" + port)
	client.set_user(username)
	client.set_password(password)
	if client:
		client.name = "CTAC"
		client.application_uri = "urn:CTAC:RobotFramework"
		await client.connect()
		logger.info("Client connected!")
		logger.info("NodeID: " + variable)
		try:
			var = client.get_node(variable)
			level = await getAccessLevel(var)
			logger.info("Variable: " + str(variable) + " access level: " + str(level))
			rc = 0
		except Exception as e:
			rc = -1
			logger.error("Read access level failed: " + str(e) + " for variable: " + variable + " " + variable)
		await client.disconnect()
	else:
		logger.error("Client cannot connect!")
	return rc

# WellKnownRoles: OPC UA specification https://reference.opcfoundation.org/Core/Part3/4.8.2/
@not_keyword
def getRole(id):
  if (id == 15644): return "Anonymous"
  if (id == 15656): return "Authenticated"
  if (id == 15668): return "Observer"
  if (id == 16036): return "Engineer"
  if (id == 15680): return "Operator"
  if (id == 15716): return "ConfigureAdmin"
  if (id == 15704): return "SecurityAdmin"
  if (id == 15692): return "Supervisor"
  return "UnknownRole"

@not_keyword
async def getPermissions(node):
  result="" # Empty string
  permissions = (await node.read_attribute(ua.AttributeIds.RolePermissions)).Value.Value
  i=0
  for p in permissions:
    item = permissions[i]
    i = i + 1
    #print("PERM 1, role: ", item.RoleId.Identifier, " permissions: ", item.Permissions)
    #print("Role: ", getRole(item.RoleId.Identifier))
    perm = item.Permissions
    Browse = perm & 1<<0
    ReadRolePermissions = perm & 1<<1
    WriteAttribute = perm & 1<<2
    WriteRolePermissions = perm & 1<<3
    WriteHistorizing = perm & 1<<4
    Read = perm & 1<<5
    Write = perm & 1<<6
    ReadHistory = perm & 1<<7
    InsertHistory = perm & 1<<8
    ModifyHistory = perm & 1<<9
    DeleteHistory = perm & 1<<10
    ReceiveEvents = perm & 1<<11
    Call = perm & 1<<12
    AddReference = perm & 1<<13
    RemoveReference = perm & 1<<14
    DeleteNode = perm & 1<<15
    AddNode = perm & 1<<16
    # TODO table and show smarter way than one character
    result += "\nUser role: " + getRole(item.RoleId.Identifier).ljust(15) + " "
    if Browse:
      result += "Browse " # "B"
    else:
      result =  " ----- "
    if Read:
      result += "Read " # R
    else:
      result += " --- "
    if Write:
      result += "Write " # W
    else:
      result += " ---- "
    if ReadRolePermissions:
      result += "ReadRole " # p"
    else:
      result += " ------- "
    if WriteAttribute:
      result += "WriteAttrib "
    else:
      result += " ---------- "
    if WriteHistorizing:
      result += "WriteHistory "
    else:
      result += " ----------- "
    if ReadHistory:
      result += "ReadHistory " # "h"
    else:
      result += " ---------- "
    if WriteRolePermissions:
      result += "WriteRole " # "P"
    else:
      result += " -------- "
    if InsertHistory:
      result += "InsertHistory "
    else:
      result += " ------------ "
    if ModifyHistory:
      result += "ModifyHistory "
    else:
      result += " ------------ "
    if DeleteHistory:
      result += "DeleteHistory "
    else:
      result += " ------------ "
    if ReceiveEvents:
      result += "ReceiveEvents " # E"
    else:
      result += " ------------ "
    if AddReference:
      result += "AddRefefence " # "a"
    else:
      result += " ----------- "
    if RemoveReference:
      result += "RemoveReference "
    else:
      result += " -------------- "
    if AddNode:
      result += "AddNode "
    else:
      result += " ------ "
    if DeleteNode:
      result += "DeleteNode " # "d"
    else:
      result += " --------- "
    if Call:
      result += "Call "
    else:
      result += " --- "
  return result

@keyword
def ua_read_permissions(server, port, username, password, variable):
	"""
	Test:   Read variable permissions, write to Log info level values.

    *Server*:       _opc.tcp://hostname_

    *Port*:         _26555/resource_path_

		*Username*:     _username_

		*Password*:     _password_

		*Variable:*     _ns=5;s=Float_
	"""
	loop = asyncio.get_event_loop()
	return loop.run_until_complete(opcua_read_permissions(server, port, username, password, variable))

@not_keyword
async def collect_all_under(node, collect_maximum=500000):
    all_nodes = []
    unsearched = [node]

    while unsearched and len(all_nodes) < collect_maximum:
        child = unsearched.pop()
        all_nodes.append(child)
        children = await child.get_children()
        unsearched.extend(children)

    return all_nodes

@not_keyword
async def opcua_read_permissions(server, port, username, password, variable):
	logger.getLogger('asyncua').setLevel(logger.ERROR)
	logger.basicConfig(level=logger.ERROR)
	rc = -1 # FAILED
	client = Client(server+":"+port + "/", timeout=5) # Server cannot response in normal 4s timeout
	client.session_timeout = 600000
	logger.info("Server=" + server +" port=" + port)
	client.set_user(username)
	client.set_password(password)
	if client:
		client.name = "CTAC"
		client.application_uri = "urn:CTAC:RobotFramework"
		await client.connect()
		logger.info("Client connected!")
		logger.info("Root nodeID: " + variable)
		try:
			root = client.get_node(variable)
			all_nodes = await collect_all_under(root)
			for n in all_nodes:
				var = client.get_node(n)
				try:
					perm = await getPermissions(var)
					logger.info("Variable: " + str(var) + " permissions: " + str(perm))
				except:
					logger.info("Variable: " + str(var) + " no permissions defined")
					continue
			rc = 0
		except Exception as e:
			rc = -1
			logger.error("Read permissions failed: " + str(e) + " for variable: " + variable)
		await client.disconnect()
	else:
		logger.error("Client cannot connect!")
	return rc

class SubscriptionHandler:
    """
    The SubscriptionHandler is used to handle the data that is received for the subscription.
    """
    def datachange_notification(self, node, val, data):
        """
        Callback for asyncua Subscription.
        This method will be called when the Client received a data change message from the Server.
        """
        logger.info('subscription change on nodeId: %s value: %s', node, val)

@keyword
def ua_test_subscription(server, port, username, password, variable):
	"""
	Test:   Subscribe variable for *5s*, write changed values to Log info level.

    *Server*:       _opc.tcp://hostname_

    *Port*:         _26555/resource_path_

		*Username*:     _username_

		*Password*:     _password_

		*Variable:*     _ns=5;s=Float_
	"""
	loop = asyncio.get_event_loop()
	return loop.run_until_complete(opcua_test_subscription(server, port, username, password, variable))

@not_keyword
async def opcua_test_subscription(server, port, username, password, variable):
	logger.getLogger('asyncua').setLevel(logger.ERROR)
	logger.basicConfig(level=logger.ERROR)
	rc = -1 # FAILED
	client = Client(server+":"+port + "/", timeout=5) # Server cannot response in normal 4s timeout
	client.session_timeout = 600000
	logger.info("Server=" + server +" port=" + port)
	client.set_user(username)
	client.set_password(password)
	if client:
		client.name = "CTAC"
		client.application_uri = "urn:CTAC:RobotFramework"
		await client.connect()
		logger.info("Client connected!")
		logger.info("NodeID: " + variable)
		var = client.get_node(variable)
		handler = SubscriptionHandler()
    # We create a Client Subscription.
		subscription = await client.create_subscription(500, handler)
		# NOTE: Current time changes always
		nodes = [ var, client.get_node(ua.ObjectIds.Server_ServerStatus_CurrentTime)]
    # We subscribe to data changes for two nodes (variables).
		await subscription.subscribe_data_change(nodes)
    # We let the subscription run for 5 seconds
		await asyncio.sleep(5) # TODO needed as parameter?
		await client.disconnect()
		rc = 0
	else:
		logger.error("Client cannot connect!")
	return rc

class SubHandler:
    """
    Subscription Handler. To receive events from server for a subscription
    data_change and event methods are called directly from receiving thread.
    Do not do expensive, slow or network operation there. Create another
    thread if you need to do such a thing
    """
    def event_notification(self, event):
      # logger.info("New event received: %r", event)
      logger.info("Time: " + str(event.Time) +
									" Severity: " + str(event.Severity) + 
									" SourceName: " + str(event.SourceName) +
									" Message: " + str(event.Message.Text))

@keyword
def ua_test_events(server, port, username, password):
	"""
	Test:   Subscribe events from server for *59s*, write events to Log info level values.

    *Server*:       _opc.tcp://hostname_

    *Port*:         _26555/resource_path_

		*Username*:     _username_

		*Password*:     _password_
	"""
	loop = asyncio.get_event_loop()
	return loop.run_until_complete(opcua_test_events(server, port, username, password))

@not_keyword
async def opcua_test_events(server, port, username, password):
	logger.getLogger('asyncua').setLevel(logger.ERROR)
	logger.basicConfig(level=logger.ERROR)
	rc = -1 # FAILED
	client = Client(server+":"+port + "/", timeout=5) # Server cannot response in normal 4s timeout
	client.session_timeout = 600000
	logger.info("Server=" + server +" port=" + port)
	client.set_user(username)
	client.set_password(password)
	if client:
		client.name = "CTAC"
		client.application_uri = "urn:CTAC:RobotFramework"
		await client.connect()
		logger.info("Client connected!")
		var = client.get_node("ns=0;i=2253") # Server
		# Events
		myevent = await client.nodes.root.get_child(["0:Types", "0:EventTypes", "0:BaseEventType"])
		evt = SubHandler()
		sub = await client.create_subscription(100, evt)
		handle = await sub.subscribe_events(var, myevent)
		await asyncio.sleep(59) # Should be less than timeout to get MyLevel alarms (example in case server is Prosys UA Simulation server)
		await sub.unsubscribe(handle)
		await sub.delete()
		await client.disconnect()
		rc = 0
	else:
		logger.error("Client cannot connect!")
	return rc

@keyword
def ua_test_DDOS(server, port, username, password):
	"""
	Test:   Test server for denial of service attack. Create multiple session until server does not accept more.

	        NOTE: *maxSessions* is different on servers.

    *Server*:       _opc.tcp://hostname_

    *Port*:         _26555/resource_path_

		*Username*:     _username_

		*Password*:     _password_
	"""
	loop = asyncio.get_event_loop()
	return loop.run_until_complete(opcua_test_DDOS(server, port, username, password))

@not_keyword
async def opcua_test_DDOS(server, port, username, password):
	logger.getLogger('asyncua').setLevel(logger.ERROR)
	logger.basicConfig(level=logger.ERROR)
	rc = -1 # FAILED
	s = 0
	client = []
	try:
		# PErhaps maxSession like 100 as parameter/argument
		while (s < 100):
			client.append(Client(server+":"+port + "/", timeout=5)) # Server cannot response in normal 4s timeout
			client[s].session_timeout = 600000
			logger.info("Server=" + server +" port=" + port)
			client[s].set_user(username)
			client[s].set_password(password)
			client[s].name = "CTAC" + str(s)
			client[s].application_uri = "urn:CTAC:RobotFramework"
			await client[s].connect()
			logger.info("Client #" + str(s+1) + " connected!")
			rc = 0
			s = s + 1
	except Exception as e:
			rc = 0 # just test that server can/will limit sessions
			logger.warn(" Server limits sessions: " + str(e) + " max sessions: " + str(s))
	i = 0
	# Cleanup or wait session timeout and check that sessions are removed (server can retrieve itself)
	while (i < s):
		await client[i].disconnect()
		i = i + 1
	return rc

@keyword
def ua_cleanup():
	"""
	Test:   Cleanup test suite.
	"""
	logger.getLogger('asyncua').setLevel(logger.ERROR)
	logger.basicConfig(level=logger.ERROR)
	logger.info("Testing done.")
	try:
		exit(0)
	except:
		pass

@not_keyword
async def opcua_cleanup():
	logger.getLogger('asyncua').setLevel(logger.ERROR)
	logger.basicConfig(level=logger.ERROR)
	await asyncio.sleep(1)
	logger.info("Testing done.")
	try:
		exit(0)
	except:
		pass
