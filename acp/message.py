import logging
import struct
import zlib

from .exception import ACPMessageError
from .keystream import generate_acp_keystream


def _as_bytes(value):
	if value is None:
		return None
	if isinstance(value, bytes):
		return value
	if isinstance(value, str):
		return value.encode("utf-8")
	raise TypeError("expected str or bytes")


def _signed_i32(value):
	value &= 0xFFFFFFFF
	if value > 0x7FFFFFFF:
		return value - 0x100000000
	return value


def _adler32_i32(data):
	return _signed_i32(zlib.adler32(data))


def _generate_acp_header_key(password):
	"""
	Encrypt password for ACP message header key field
	
	Note:
		Truncates the password at 0x20 bytes. It is unclear whether this is
		right for all cases.
	
	Args:
		password (str): system password of the router (syAP)
	
	Returns:
		Bytes containing encrypted password of proper length for the header field
	
	"""
	pw_len = 0x20
	pw_key = generate_acp_keystream(pw_len)
	
	# pad with NULLs
	pw_buf = _as_bytes(password)[:pw_len].ljust(pw_len, b"\x00")
	enc_pw_buf = bytearray()
	for i in range(pw_len):
		enc_pw_buf.append(pw_key[i] ^ pw_buf[i])
	
	return bytes(enc_pw_buf)


class ACPMessage:
	"""ACP message composition and parsing"""
	
	#XXX: struct is stupid about unpacking unsigned ints > 0x7fffffff,
	#     so treat everything as signed and "cast" where necessary.
	#     Should we switch to using ctypes?
	_header_format = struct.Struct("!4s8i12x32s48x")
	_header_magic  = b"acpp"
	
	header_size = _header_format.size
	
	
	def __init__(self, version, flags, unused, command, error_code, key, body=None, body_size=None):
		self.version = version
		self.flags = flags
		self.unused = unused
		self.command = command
		self.error_code = error_code
		
		# body is not specified, this is a stream header
		if body is None:
			# the body size is already specified, don't override it
			self.body_size = body_size if body_size is not None else -1
			self.body_checksum = 1 # equivalent to zlib.adler32(b"")
		else:
			body = _as_bytes(body)
			# the body size is already specified, don't override it
			self.body_size = body_size if body_size is not None else len(body)
			self.body_checksum = _adler32_i32(body)
		
		self.key = key
		self.body = body
	
	
	def __str__(self):
		s =  f"ACPMessage:    {self!r}\n"
		s += f"body_checksum: {self.body_checksum:#x}\n"
		s += f"body_size:     {self.body_size:#x}\n"
		s += f"flags:         {self.flags:#x}\n"
		s += f"unused:        {self.unused:#x}\n"
		s += f"command:       {self.command:#x}\n"
		s += f"error_code:    {self.error_code:#x}\n"
		s += f"key:           {self.key!r}"
		return s
	
	
	@classmethod
	def parse_raw(cls, data):
		try:
			data = _as_bytes(data)
		except TypeError as e:
			raise ACPMessageError("expected str or bytes") from e
		if data is None:
			raise ACPMessageError("expected str or bytes")
		# bail early if there is not enough data
		if len(data) < cls.header_size:
			raise ACPMessageError(f"need to pass at least {cls.header_size} bytes")
		header_data = data[:cls.header_size]
		# make sure there's data beyond the header before we try to access it
		body_data = data[cls.header_size:] if len(data) > cls.header_size else None
		
		(
			magic,
			version,
			header_checksum,
			body_checksum,
			body_size,
			flags,
			unused,
			command,
			error_code,
			key,
		) = cls._header_format.unpack(header_data)
		logging.debug("ACP message header fields, parsed not validated")
		logging.debug(f"magic           {magic!r}")
		logging.debug(f"header_checksum {header_checksum:#x}")
		logging.debug(f"body_checksum   {body_checksum:#x}")
		logging.debug(f"body_size       {body_size:#x}")
		logging.debug(f"flags           {flags:#x}")
		logging.debug(f"unused          {unused:#x}")
		logging.debug(f"command         {command:#x}")
		logging.debug(f"error_code      {error_code:#x}")
		logging.debug(f"key             {key!r}")
		
		if magic != cls._header_magic:
			raise ACPMessageError("bad header magic")
		
		if version not in [0x00000001, 0x00030001]:
			raise ACPMessageError("invalid version")
		
		#TODO: can we zero the header_checksum field without recreating the struct (how?)
		tmphdr = cls._header_format.pack(
			magic,
			version,
			0,
			body_checksum,
			body_size,
			flags,
			unused,
			command,
			error_code,
			key,
		)
		if header_checksum != _adler32_i32(tmphdr):
			raise ACPMessageError("header checksum does not match")

		if body_size < -1:
			raise ACPMessageError("invalid body size")
		
		if body_data is not None and body_size == -1:
			raise ACPMessageError("cannot handle stream header with data attached")
		
		if body_data is not None and body_size != len(body_data):
			raise ACPMessageError("message body size does not match available data")
		
		if body_data is not None and body_checksum != _adler32_i32(body_data):
			raise ACPMessageError("body checksum does not match")
		
		#TODO: check flags
		
		#TODO: check status
		
		if command not in [1, 3, 4, 5, 6, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b]:
			raise ACPMessageError("unknown command")
		
		#TODO: check error code
		
		return cls(version, flags, unused, command, error_code, key, body_data, body_size)
	
	
	@classmethod
	def compose_echo_command(cls, flags, password, payload):
		return cls(
			0x00030001, flags, 0, 1, 0, _generate_acp_header_key(password), payload
		)._compose_raw_packet()
	
	
	@classmethod
	def compose_flash_primary_command(cls, flags, password, payload):
		return cls(
			0x00030001, flags, 0, 3, 0, _generate_acp_header_key(password), payload
		)._compose_raw_packet()
	
	
	@classmethod
	def compose_flash_secondary_command(cls, flags, password, payload):
		return cls(
			0x00030001, flags, 0, 5, 0, _generate_acp_header_key(password), payload
		)._compose_raw_packet()
	
	
	@classmethod
	def compose_flash_bootloader_command(cls, flags, password, payload):
		return cls(
			0x00030001, flags, 0, 6, 0, _generate_acp_header_key(password), payload
		)._compose_raw_packet()
	
	
	@classmethod
	def compose_getprop_command(cls, flags, password, payload):
		return cls(
			0x00030001, flags, 0, 0x14, 0, _generate_acp_header_key(password), payload
		)._compose_raw_packet()
	
	
	@classmethod
	def compose_setprop_command(cls, flags, password, payload):
		return cls(
			0x00030001, flags, 0, 0x15, 0, _generate_acp_header_key(password), payload
		)._compose_raw_packet()
	
	
	@classmethod
	def compose_perform_command(cls, flags, password, payload):
		return cls(
			0x00030001, flags, 0, 0x16, 0, _generate_acp_header_key(password), payload
		)._compose_raw_packet()
	
	
	@classmethod
	def compose_monitor_command(cls, flags, password, payload):
		return cls(
			0x00030001, flags, 0, 0x18, 0, _generate_acp_header_key(password), payload
		)._compose_raw_packet()
	
	
	@classmethod
	def compose_rpc_command(cls, flags, password, payload):
		return cls(
			0x00030001, flags, 0, 0x19, 0, _generate_acp_header_key(password), payload
		)._compose_raw_packet()
	
	
	@classmethod
	def compose_auth_command(cls, flags, payload):
		return cls(
			0x00030001, flags, 0, 0x1a, 0, _generate_acp_header_key(""), payload
		)._compose_raw_packet()
	
	
	@classmethod
	def compose_feat_command(cls, flags):
		return cls(
			0x00030001, flags, 0, 0x1b, 0, _generate_acp_header_key("")
		)._compose_raw_packet()
	
	
	@classmethod
	def compose_message_ex(
		cls, version, flags, unused, command, error_code, password, payload, payload_size
	):
		return cls(
			version,
			flags,
			unused,
			command,
			error_code,
			_generate_acp_header_key(password),
			payload,
			payload_size,
		)._compose_raw_packet()
	
	
	def _compose_raw_packet(self):
		"""Compose a request from the client to ACP daemon
		
		Returns:
			Bytes containing message to send
		
		"""
		reply = self._compose_header()
		if self.body:
			reply += self.body
		
		return reply
	
	
	def _compose_header(self):
		"""Compose the message header
		
		Returns:
			Bytes containing header data
		
		"""
		tmphdr = self._header_format.pack(
			self._header_magic,
			self.version,
			0,
			self.body_checksum,
			self.body_size,
			self.flags,
			self.unused,
			self.command,
			self.error_code,
			self.key,
		)
		
		header = self._header_format.pack(
			self._header_magic,
			self.version,
			_adler32_i32(tmphdr),
			self.body_checksum,
			self.body_size,
			self.flags,
			self.unused,
			self.command,
			self.error_code,
			self.key,
		)
		
		return header
