import logging
import struct
import zlib

from Cryptodome.Cipher import AES

#XXX: ugh...
from .misc import cast_u32

# Hardcoded 128-bit values. The model IDs and additional keys below are from
# TimeCapsuleSMB's supported AirPort device and basebinary key registries:
# https://github.com/jamesyc/TimeCapsuleSMB
_basebinary_keys = {
	104: "ec7abae211819b1349880d2035a24d78",
	105: "87f52f57c573e87499b6d69c8e4bcb8b",
	106: "513c1ca5bf035127335f7c2596aa20aa",
	107: "5249c351028bf1fd2bd1849e28b23f24",
	108: "bb7deb0970d8ee2e00fa46cb1c3c098e",
	109: "cfb15a151a3998b983a5a48aaa859e80",
	113: "c025fefa2320b0e985dfac106694db4a",
	114: "a66e263e7b751242ac7fa0c90951ed08",
	115: "1075e806f4770cd4763bd285a64e9174",
	116: "9d1259ee89f28a2ccfa64697adbb4193",
	117: "74119d5182c7a317db0026e49efde79a",
	119: "b19937ddcb78b3f151e4e0b48198e6a7",
	120: "688cdd3b1b6bdda207b6cec2735292d2",
}

def _derive_key(model):
	if model not in _basebinary_keys:
		return None
	key = bytes.fromhex(_basebinary_keys[model])
	derived_key = bytes(key[i] ^ (i + 0x19) for i in range(len(key)))
	logging.debug(f"derived key {derived_key.hex()}")
	return derived_key


class BasebinaryError(Exception):
	pass

class Basebinary:
	_header_magic = b"APPLE-FIRMWARE\x00"
	#XXX: do we need to fix shitty Python struct member signdness things here too?
	_header_format = struct.Struct(">15sB2I4BI")
	
	header_size = _header_format.size
	
	
	@classmethod
	def parse(cls, data):
		if len(data) < (cls.header_size + 4):
			raise BasebinaryError("not enough data to parse")
		
		header_data = data[:cls.header_size]
		inner_data = data[cls.header_size:-4]
		
		#XXX: and here??
		stored_checksum, = struct.unpack(">I", data[-4:])
		
		(
			byte_0x0F,
			model,
			version,
			byte_0x18,
			byte_0x19,
			byte_0x1A,
			flags,
			unk_0x1C,
		) = cls.parse_header(header_data)
		
		if flags & 2:
			inner_data = cls.decrypt(inner_data, model, byte_0x0F)
		
		#XXX: why is Python so shitty about this comparison <.<
		checksum = cast_u32(zlib.adler32(header_data+inner_data))
		logging.debug(f"stored checksum     {stored_checksum:#x}")
		logging.debug(f"calculated checksum {checksum:#x}")
		logging.debug(f"data length         {len(header_data+inner_data):#x}")
		if stored_checksum != checksum:
			raise BasebinaryError("bad checksum")
			
		return inner_data
	
	
	@classmethod
	def compose(cls, data):
		#TODO
		pass
	
	
	@classmethod
	def parse_header(cls, data):
		try:
			(
				magic,
				byte_0x0F,
				model,
				version,
				byte_0x18,
				byte_0x19,
				byte_0x1A,
				flags,
				unk_0x1C,
			) = cls._header_format.unpack(data)
		except struct.error as e:
			raise BasebinaryError("failed to parse firmware header") from e
		
		if magic != cls._header_magic:
			raise BasebinaryError("bad header magic")
		
		return (byte_0x0F, model, version, byte_0x18, byte_0x19, byte_0x1A, flags, unk_0x1C)
	
	
	@classmethod
	def compose_header(
		cls,
		byte_0x0F,
		model,
		version,
		byte_0x18,
		byte_0x19,
		byte_0x1A,
		flags,
		unk_0x1C,
	):
		#TODO
		pass
	
	
	@classmethod
	def decrypt(cls, data, model, byte_0x0F):
		iv = cls._header_magic + bytes([byte_0x0F])
		key = _derive_key(model)
		if key is None:
			raise BasebinaryError(f"key missing for model {model}")
		
		decrypted_chunks = []
		remaining_length = len(data)
		chunk_length = 0x8000
		while remaining_length:
			if remaining_length > chunk_length:
				start = -remaining_length
				end = -(remaining_length - chunk_length)
				decrypted_chunks.append(cls.decrypt_chunk(data[start:end], key, iv))
				remaining_length -= chunk_length
			else:
				decrypted_chunks.append(cls.decrypt_chunk(data[-remaining_length:], key, iv))
				remaining_length = 0
		
		return b"".join(decrypted_chunks)
	
	
	@classmethod
	def decrypt_chunk(cls, encrypted_data, key, iv):
		cipher = AES.new(key, AES.MODE_CBC, iv)
		decrypted_chunks = []
		bytes_left = len(encrypted_data)
		while bytes_left:
			#logging.debug("bytes left: {0:#x}".format(bytes_left))
			if bytes_left > 0x10:
				decrypted_chunks.append(cipher.decrypt(encrypted_data[-bytes_left:-(bytes_left-0x10)]))
				bytes_left -= 0x10
			elif bytes_left == 0x10:
				decrypted_chunks.append(cipher.decrypt(encrypted_data[-bytes_left:]))
				bytes_left = 0
			else: # bytes_left < 0x10
				#LOL: odd-sized chunk at the end is left unencrypted
				decrypted_chunks.append(encrypted_data[-bytes_left:])
				bytes_left = 0
		
		return b"".join(decrypted_chunks)
	
	
	@classmethod
	def encrypt(cls, data):
		#TODO: not really necessary; router doesn't require an encrypted firmware if flag is unset
		pass
	
	
	@classmethod
	def extract(cls, data):
		#TODO: proper gzip header validation?
		try:
			gzip_offset = data.index(b"\x1f\x8b\x08")
		except ValueError as e:
			raise BasebinaryError("gzip payload not found") from e
		gzdata = data[gzip_offset:]
		
		try:
			return zlib.decompress(gzdata, 16+zlib.MAX_WBITS)
		except zlib.error as e:
			raise BasebinaryError("failed to decompress gzip payload") from e
