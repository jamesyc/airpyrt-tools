import logging
import os
import struct
from collections import OrderedDict

from .cflbinary import CFLBinaryPListComposer, CFLBinaryPListParser
from .exception import ACPClientError
from .message import ACPMessage
from .property import ACPProperty
from .session import ACPClientSession
from .srp import SRP6aClient


class ACPClient:
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
				f"{operation} failed with error code: {reply_header.error_code:#x}"
			)


	def _unpack_property_error(self, operation, name, prop_data):
		try:
			(error_code, ) = struct.unpack(">I", prop_data)
		except struct.error as e:
			raise ACPClientError(
				f"{operation} returned a malformed property error for {name!r}"
			) from e
		raise ACPClientError(
			f"error {operation} for property {name!r}: {error_code:#x}"
		)


	def _warn_for_unknown_property_flags(self, operation, name, flags):
		unknown_flags = ACPProperty.unsupported_element_flags(flags)
		if unknown_flags:
			logging.warning(
				f"{operation} returned unsupported property element flags for "
				f"{name!r}: {flags:#x} (unknown bits {unknown_flags:#x})"
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
			logging.debug(f"name  {name!r}")
			logging.debug(f"flags {flags!r}")
			logging.debug(f"size  {size!r}")
			
			prop_data = self.recv(size)
			logging.debug(f"prop_data {prop_data!r}")

			self._warn_for_unknown_property_flags("get_properties", name, flags)
			if ACPProperty.element_has_error(flags):
				try:
					self._unpack_property_error("requesting value", name, prop_data)
				except ACPClientError as e:
					logging.warning(str(e))
					continue
			
			prop = ACPProperty(name, prop_data)
			logging.debug(f"prop {prop!r}")
			
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
		for prop in props_dict.values():
			logging.debug(f"prop: {prop!r}")
			payload += ACPProperty.compose_raw_element(0, prop)
		request = ACPMessage.compose_setprop_command(0, self.password, payload)
		self.send(request)
		
		raw_reply = self.recv_message_header()
		reply_header = ACPMessage.parse_raw(raw_reply)
		
		self._raise_for_reply_error("set_properties", reply_header)
		
		prop_header = self.recv_property_element_header()
		name, flags, size = ACPProperty.parse_raw_element_header(prop_header)
		logging.debug(f"name  {name!r}")
		logging.debug(f"flags {flags!r}")
		logging.debug(f"size  {size!r}")
		
		prop_data = self.recv(size)
		logging.debug(f"prop_data {prop_data!r}")

		self._warn_for_unknown_property_flags("set_properties", name, flags)
		if ACPProperty.element_has_error(flags):
			self._unpack_property_error("setting value", name, prop_data)
			
		prop = ACPProperty(name, prop_data)
		logging.debug(f"prop {prop!r}")
		
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
		dic = OrderedDict([("state", 1), ("username", username)])
		payload = CFLBinaryPListComposer.compose(dic)
		raw_message = ACPMessage.compose_auth_command(4, payload)
		self.send(raw_message)
		
		raw_reply_header = self.recv_message_header()
		reply_header = ACPMessage.parse_raw(raw_reply_header)
		
		self._raise_for_reply_error(operation, reply_header)
		
		logging.debug(f"recv_size: {reply_header.body_size}")
		raw_message = self.recv(reply_header.body_size)
		logging.debug(f"raw_message: {raw_message!r}")
		params1 = CFLBinaryPListParser.parse(raw_message)
		logging.debug(params1)
		
		n = self._require_auth_field(operation, params1, "modulus")
		g = self._require_auth_field(operation, params1, "generator")
		salt = self._require_auth_field(operation, params1, "salt")
		server_pkey = self._require_auth_field(operation, params1, "publicKey")
		
		logging.debug(f"nhex: {n.hex()}")
		logging.debug(f"ghex: {g.hex()}")
		logging.debug(f"salt: {salt.hex()}")
		logging.debug(f"server_pkey: {server_pkey.hex()}")
		
		client_iv = os.urandom(0x10)
		client_pkey, client_proof, client_computed_key_buf = srp_client.process_challenge(
			n,
			g,
			salt,
			server_pkey,
		)
		
		dic = OrderedDict([
			("iv", client_iv),
			("publicKey", client_pkey),
			("state", 3),
			("response", client_proof),
		])
		payload = CFLBinaryPListComposer.compose(dic)
		raw_message = ACPMessage.compose_auth_command(4, payload)
		self.send(raw_message)
		
		raw_reply_header = self.recv_message_header()
		reply_header = ACPMessage.parse_raw(raw_reply_header)
		
		self._raise_for_reply_error(operation, reply_header)
		
		logging.debug(f"recv_size: {reply_header.body_size}")
		raw_message = self.recv(reply_header.body_size)
		logging.debug(f"raw_message: {raw_message!r}")
		params2 = CFLBinaryPListParser.parse(raw_message)
		logging.debug(params2)
	
		server_proof = self._require_auth_field(operation, params2, "response")
		server_iv = self._require_auth_field(operation, params2, "iv")
		
		# verify server response
		srp_client.verify_server_proof(server_proof)
		return client_computed_key_buf, client_iv, server_iv


	def _require_auth_field(self, operation, params, field):
		try:
			return params[field]
		except KeyError as e:
			raise ACPClientError(
				f"{operation} reply missing required field \"{field}\""
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
