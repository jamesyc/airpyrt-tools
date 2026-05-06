"""Static key/seed for keystream generation"""
ACP_STATIC_KEY = bytes.fromhex("5b6faf5d9d5b0e1351f2da1de7e8d673")

def generate_acp_keystream(length):
	"""Get key used to encrypt the header key (and some message data?)
	
	Args:
		length (int): length of keystream to generate
	
	Returns:
		String of requested length
	
	Note:
		Keystream repeats every 256 bytes
	
	"""
	key = bytearray()
	
	for key_idx in range(length):
		key.append(((key_idx + 0x55) & 0xFF) ^ ACP_STATIC_KEY[key_idx % len(ACP_STATIC_KEY)])
	
	return bytes(key)
