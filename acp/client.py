import logging
import os
import struct
from collections import OrderedDict

from .cflbinary import CFLBinaryPListComposer, CFLBinaryPListParser
from .exception import ACPClientError
from .message import ACPMessage
from .property import ACPProperty
from .session import ACPClientSession
from .srp import AppleSRPClient, SRP6aClient


class ACPClient(object):
	def __init__(self, target, password=""):
		self.target = target
		self.password = password
		
		self.session = ACPClientSession(target, password)
	
	
	def connect(self):
		self.session.connect()
	
	
	def close(self):
		self.session.close()
	
	
	def send(self, data):
		self.session.send(data)
	
	
	def recv(self, size):
		return self.session.recv(size)
	
	
	def recv_message_header(self):
		return self.recv(ACPMessage.header_size)
	
	
	def recv_property_element_header(self):
		return self.recv(ACPProperty.element_header_size)
	
	
	def _raise_for_reply_error(self, operation, reply_header):
		if reply_header.error_code != 0:
			raise ACPClientError(
				"{0} failed with error code: {1:#x}".format(
					operation,
					reply_header.error_code,
				)
			)


	def _unpack_property_error(self, operation, name, prop_data):
		try:
			(error_code, ) = struct.unpack(">I", prop_data)
		except struct.error as e:
			raise ACPClientError(
				"{0} returned a malformed property error for \"{1}\"".format(
					operation,
					name,
				)
			) from e
		raise ACPClientError(
			"error {0} for property \"{1}\": {2:#x}".format(
				operation,
				name,
				error_code,
			)
		)


	def get_properties(self, prop_names=None):
		if prop_names is None:
			prop_names = []
		# request property by sending name and "null" value
		payload = b""
		for name in prop_names:
			payload += ACPProperty.compose_raw_element(0, ACPProperty(name))
		
		request = ACPMessage.compose_getprop_command(4, self.password, payload)
		self.send(request)
		
		raw_reply = self.recv_message_header()
		reply_header = ACPMessage.parse_raw(raw_reply)
		
		self._raise_for_reply_error("get_properties", reply_header)
		
		props = []
		while True:
			prop_header = self.recv_property_element_header()
			name, flags, size = ACPProperty.parse_raw_element_header(prop_header)
			logging.debug("name  ".format(name))
			logging.debug("flags ".format(flags))
			logging.debug("size  ".format(size))
			
			prop_data = self.recv(size)
			logging.debug("prop_data {0!r}".format(prop_data))
			
			if flags & 1:
				try:
					self._unpack_property_error("requesting value", name, prop_data)
				except ACPClientError as e:
					logging.warning(str(e))
					continue
			
			prop = ACPProperty(name, prop_data)
			logging.debug("prop {0!r}".format(prop))
			
			#XXX: this is still a bit ugly
			if prop.name is None and prop.value is None:
				logging.debug("found empty prop end marker")
				break
			
			#XXX: should we should return dict(name=name, prop=ACPProperty(name, value)) instead?
			props.append(prop)
			
		return props
	
	
	def set_properties(self, props_dict=None):
		if props_dict is None:
			props_dict = {}
		payload = b""
		for name, prop in props_dict.items():
			logging.debug("prop: {0!r}".format(prop))
			payload += ACPProperty.compose_raw_element(0, prop)
		request = ACPMessage.compose_setprop_command(0, self.password, payload)
		self.send(request)
		
		raw_reply = self.recv_message_header()
		reply_header = ACPMessage.parse_raw(raw_reply)
		
		self._raise_for_reply_error("set_properties", reply_header)
		
		prop_header = self.recv_property_element_header()
		name, flags, size = ACPProperty.parse_raw_element_header(prop_header)
		logging.debug("name  {0!r}".format(name))
		logging.debug("flags {0!r}".format(flags))
		logging.debug("size  {0!r}".format(size))
		
		prop_data = self.recv(size)
		logging.debug("prop_data {0!r}".format(prop_data))
		
		if flags & 1:
			self._unpack_property_error("setting value", name, prop_data)
			
		prop = ACPProperty(name, prop_data)
		logging.debug("prop {0!r}".format(prop))
		
		#XXX: this is still a bit ugly
		if prop.name is None and prop.value is None:
			logging.debug("found empty prop end marker")
	
	
	def get_features(self):
		self.send(ACPMessage.compose_feat_command(0))
		
		reply_header = ACPMessage.parse_raw(self.recv_message_header())
		self._raise_for_reply_error("get_features", reply_header)
		
		reply = self.recv(reply_header.body_size)
		
		return CFLBinaryPListParser.parse(reply)
	
	
	def flash_primary(self, payload):
		self.send(ACPMessage.compose_flash_primary_command(0, self.password, payload))
		
		reply_header = ACPMessage.parse_raw(self.recv_message_header())
		self._raise_for_reply_error("flash_primary", reply_header)
		
		return self.recv(reply_header.body_size)
	
	
	def _authenticate_srp_client(self, username, srp_client, operation):
		dic = OrderedDict([(u"state", 1), (u"username", username)])
		payload = CFLBinaryPListComposer.compose(dic)
		raw_message = ACPMessage.compose_auth_command(4, payload)
		self.send(raw_message)
		
		raw_reply_header = self.recv_message_header()
		reply_header = ACPMessage.parse_raw(raw_reply_header)
		
		self._raise_for_reply_error(operation, reply_header)
		
		logging.debug("recv_size: {0}".format(reply_header.body_size))
		raw_message = self.recv(reply_header.body_size)
		logging.debug("raw_message: {0!r}".format(raw_message))
		params1 = CFLBinaryPListParser.parse(raw_message)
		logging.debug(params1)
		
		n = self._require_auth_field(operation, params1, u"modulus")
		g = self._require_auth_field(operation, params1, u"generator")
		salt = self._require_auth_field(operation, params1, u"salt")
		server_pkey = self._require_auth_field(operation, params1, u"publicKey")
		
		logging.debug("nhex: {0}".format(n.hex()))
		logging.debug("ghex: {0}".format(g.hex()))
		logging.debug("salt: {0}".format(salt.hex()))
		logging.debug("server_pkey: {0}".format(server_pkey.hex()))
		
		client_iv = os.urandom(0x10)
		client_pkey, client_proof, client_computed_key_buf = srp_client.process_challenge(
			n,
			g,
			salt,
			server_pkey,
		)
		
		dic = OrderedDict([
			(u"iv", client_iv),
			(u"publicKey", client_pkey),
			(u"state", 3),
			(u"response", client_proof),
		])
		payload = CFLBinaryPListComposer.compose(dic)
		raw_message = ACPMessage.compose_auth_command(4, payload)
		self.send(raw_message)
		
		raw_reply_header = self.recv_message_header()
		reply_header = ACPMessage.parse_raw(raw_reply_header)
		
		self._raise_for_reply_error(operation, reply_header)
		
		logging.debug("recv_size: {0}".format(reply_header.body_size))
		raw_message = self.recv(reply_header.body_size)
		logging.debug("raw_message: {0!r}".format(raw_message))
		params2 = CFLBinaryPListParser.parse(raw_message)
		logging.debug(params2)
	
		server_proof = self._require_auth_field(operation, params2, u"response")
		server_iv = self._require_auth_field(operation, params2, u"iv")
		
		# verify server response
		srp_client.verify_server_proof(server_proof)
		return client_computed_key_buf, client_iv, server_iv


	def _require_auth_field(self, operation, params, field):
		try:
			return params[field]
		except KeyError as e:
			raise ACPClientError(
				"{0} reply missing required field \"{1}\"".format(operation, field)
			) from e


	def authenticate_srp(self, username="admin", srp_client_factory=SRP6aClient):
		srp_client = srp_client_factory(username, self.password)
		try:
			session_key, client_iv, server_iv = self._authenticate_srp_client(
				username,
				srp_client,
				"authenticate_srp",
			)
			self.session.enable_encryption(session_key, client_iv, server_iv)
			return session_key, client_iv, server_iv
		finally:
			srp_client.close()


	def authenticate_AppleSRP(self, srp_client_factory=AppleSRPClient):
		#XXX: STILL TESTING SHIT
		username = "admin"
		srp_client = srp_client_factory(username, self.password)
		try:
			return self._authenticate_srp_client(
				username,
				srp_client,
				"authenticate_AppleSRP",
			)
		finally:
			srp_client.close()
