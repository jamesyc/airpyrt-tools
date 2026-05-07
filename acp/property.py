import logging
import pprint
import struct

from .cflbinary import CFLBinaryPListParser
from .exception import ACPPropertyError

_acp_properties = [
	# Uncomment and fill out relevant fields to add support for a property
	# Properties must be in the following format:
	# (name, type, description, validation), where
	# name (required) is a 4 character string,
	# type (required) is a valid property type (str, dec, hex, log, mac, cfb, bin)
	# description (required) is a short, one-line description of the property
	# validation (optional) names a structured rule used to verify property values
	("buil","str","Build string?",""),
	("DynS","cfb","DNS",""),
	#("cfpf","","",""),
	#("cloC","","",""),
	#("cloD","","",""),
	#("conf","","",""),
	("fire","cfb","Firewall???",""),
	#("prob","","",""),
	("srcv","str","Source Version",""),
	("syNm","str","Device name",""),
	#("syDN","","",""),
	#("syPI","","",""),
	("syPW","str","Router administration password",""),
	("syPR","str","syPR string???",""),
	("syGP","str","Router guest password???",""),
	#("syCt","","",""),
	#("syLo","","",""),
	("syDs","str","System description",""),
	("syVs","str","System version",""),
	("syVr","str","System version???",""),
	("syIn","str","System information???",""),
	("syFl","hex","????",""),
	("syAM","str","Model Identifier",""),
	("syAP","dec","Product ID",""),
	("sySN","str","Apple Serial Number",""),
	#("ssSN","","",""),
	#("sySK","","",""),
	("ssSK","str","Apple SKU",""),
	#("syRe","","",""),
	("syLR","cfb","syLR Blob",""),
	("syAR","cfb","syAR Blob",""),
	("syUT","dec","System Uptime",""),
	#("minV","","",""),
	("minS","str","apple-minver",""),
	("chip","str","SoC Description",""),
	#("card","","",""),
	#("memF","","",""),
	#("pool","","",""),
	#("tmpC","","",""),
	#("RPMs","","",""),
	("sySI","cfb","System Info Blob?",""),
	#("fDCY","","",""),
	("TMEn","hex","TMEn???",""),
	("CLTM","cfb","CLTM???",""),
	#("sPLL","","",""),
	#("syTL","","",""),
	#("syST","","",""),
	("sySt","cfb","System Status",""),
	#("syIg","","",""),
	("syBL","str","Bootloader vesrsion string",""),
	("time","dec","System time",""),
	("timz","cfb","Timezone Config Blob",""),
	("usrd","cfb","usrd???",""),
	#("uuid","","",""),
	#("drTY","","",""),
	#("sttE","","",""),
	#("sttF","","",""),
	#("stat","","",""),
	#("sRnd","","",""),
	#("Accl","","",""),
	("dSpn","cfb","Disk spin status?",""),
	("syMS","str","MLB Serial Number",""),
	#("IGMP","","",""),
	("diag","bin","diag???",""),
	#("paFR","","",""),
	("raNm","str","Radio Name",""),
	#("raCl","","",""),
	#("raSk","","",""),
	#("raWM","","",""),
	#("raEA","","",""),
	#("raWE","","",""),
	#("raCr","","",""),
	#("raKT","","",""),
	#("raNN","","",""),
	#("raGK","","",""),
	#("raHW","","",""),
	#("raCM","","",""),
	#("raRo","","",""),
	#("raCA","","",""),
	#("raCh","","",""),
	#("rCh2","","",""),
	#("raWC","","",""),
	#("raDe","","",""),
	#("raMu","","",""),
	#("raLC","","",""),
	#("raLF","","",""),
	#("ra1C","","",""),
	#("raVs","","",""),
	("raMA","mac","Radio MAC Address",""),
	#("raM2","","",""),
	#("raMO","","",""),
	#("raLO","","",""),
	#("raDS","","",""),
	#("raNA","","",""),
	#("raWB","","",""),
	#("raIS","","",""),
	#("raMd","","",""),
	#("raPo","","",""),
	#("raPx","","",""),
	#("raTr","","",""),
	#("raDt","","",""),
	#("raFC","","",""),
	#("raEC","","",""),
	#("raMX","","",""),
	#("raIE","","",""),
	#("raII","","",""),
	#("raB0","","",""),
	#("raB1","","",""),
	#("raB2","","",""),
	#("raSt","","",""),
	#("APSR","","",""),
	#("raTX","","",""),
	#("raRX","","",""),
	#("raAC","","",""),
	("raSL","cfb","Radios list?",""),
	#("raMI","","",""),
	#("raST","","",""),
	#("raDy","","",""),
	#("raEV","","",""),
	#("rTSN","","",""),
	("raSR","cfb","Radio scan results?",""),
	#("eaRA","","",""),
	("WiFi","cfb","Wifi configuration?",""),
	("rCAL","cfb","Radio calibration data?",""),
	#("moPN","","",""),
	#("moAP","","",""),
	#("moUN","","",""),
	#("moPW","","",""),
	#("moIS","","",""),
	#("moLS","","",""),
	#("moLI","","",""),
	#("moID","","",""),
	#("moDT","","",""),
	#("moPD","","",""),
	#("moAD","","",""),
	#("moCC","","",""),
	#("moCR","","",""),
	#("moCI","","",""),
	#("^moM","","",""),
	#("moVs","","",""),
	#("moMP","","",""),
	#("moMF","","",""),
	#("moFV","","",""),
	#("pdFl","","",""),
	#("pdUN","","",""),
	#("pdPW","","",""),
	#("pdAR","","",""),
	#("pdID","","",""),
	#("pdMC","","",""),
	#("peSN","","",""),
	#("peUN","","",""),
	#("pePW","","",""),
	#("peSC","","",""),
	#("peAC","","",""),
	#("peID","","",""),
	#("peAO","","",""),
	("waCV","bin","WAN Config Mode?",""),
	("waIn","bin","WAN Interface Mode?",""),
	#("waD1","","",""),
	#("waD2","","",""),
	#("waD3","","",""),
	#("waC1","","",""),
	#("waC2","","",""),
	#("waC3","","",""),
	("waIP","bin","WAN IP",""),
	#("waSM","","",""),
	("waRA","bin","WAN Upstream Gateway IP",""),
	#("waDC","","",""),
	#("waDS","","",""),
	("waMA","mac","WAN MAC Address",""),
	#("waMO","","",""),
	#("waDN","","",""),
	#("waCD","","",""),
	#("waIS","","",""),
	#("waNM","","",""),
	#("waSD","","",""),
	#("waFF","","",""),
	#("waRO","","",""),
	#("waW1","","",""),
	#("waW2","","",""),
	#("waW3","","",""),
	#("waLL","","",""),
	#("waUB","","",""),
	("waDI","cfb","WAN DHCP Info?",""),
	#("laCV","","",""),
	#("laIP","","",""),
	#("laSM","","",""),
	#("laRA","","",""),
	#("laDC","","",""),
	#("laDS","","",""),
	#("laNA","","",""),
	("laMA","mac","LAN MAC Address",""),
	#("laIS","","",""),
	#("laSD","","",""),
	#("laIA","","",""),
	#("gn6?","","",""),
	#("gn6A","","",""),
	#("gn6P","","",""),
	#("dhFl","","",""),
	#("dhBg","","",""),
	#("dhEn","","",""),
	#("dhSN","","",""),
	#("dhRo","","",""),
	#("dhLe","","",""),
	#("dhMg","","",""),
	#("dh95","","",""),
	("DRes","cfb","DHCP Reservations",""),
	#("dhWA","","",""),
	#("dhDS","","",""),
	#("dhDB","","",""),
	#("dhDE","","",""),
	#("dhDL","","",""),
	("dhSL","cfb","DHCP Server leases?",""),
	#("gnFl","","",""),
	#("gnBg","","",""),
	#("gnEn","","",""),
	#("gnSN","","",""),
	#("gnRo","","",""),
	#("gnLe","","",""),
	#("gnMg","","",""),
	#("gn95","","",""),
	#("gnDi","","",""),
	#("naFl","","",""),
	#("naBg","","",""),
	#("naEn","","",""),
	#("naSN","","",""),
	#("naRo","","",""),
	#("naAF","","",""),
	#("nDMZ","","",""),
	#("pmPI","","",""),
	#("pmPS","","",""),
	#("pmPR","","",""),
	#("pmTa","","",""),
	#("acEn","","",""),
	#("acTa","","",""),
	("tACL","cfb","Timed Access Control",""),
	#("wdFl","","",""),
	#("wdLs","","",""),
	#("dWDS","","",""),
	#("cWDS","","",""),
	#("dwFl","","",""),
	#("raFl","","",""),
	#("raI1","","",""),
	#("raTm","","",""),
	#("raAu","","",""),
	#("raAc","","",""),
	#("raSe","","",""),
	#("raRe","","",""),
	#("raF2","","",""),
	#("raI2","","",""),
	#("raT2","","",""),
	#("raU2","","",""),
	#("raC2","","",""),
	#("raS2","","",""),
	#("raR2","","",""),
	#("raCi","","",""),
	("ntSV","str","NTP Server Hostname",""),
	#("ntpC","","",""),
	#("smtp","","",""),
	#("slog","","",""),
	#("slgC","","",""),
	#("slCl","","",""),
	("slvl","dec","System log severity level?",""),
	#("slfl","","",""),
	("logm","log","System log data",""),
	#("snAF","","",""),
	#("snLW","","",""),
	#("snLL","","",""),
	#("snRW","","",""),
	#("snWW","","",""),
	#("snRL","","",""),
	#("snWL","","",""),
	#("snCS","","",""),
	#("srtA","","",""),
	#("srtF","","",""),
	#("upsF","","",""),
	#("usbF","","",""),
	("USBi","cfb","USB Info",""),
	#("USBL","","",""),
	#("USBR","","",""),
	#("USBO","","",""),
	#("USBs","","",""),
	#("USBo","","",""),
	#("USBh","","",""),
	#("USBb","","",""),
	#("USBn","","",""),
	("prni","cfb","Printer Info?",""),
	#("prnM","","",""),
	#("prnI","","",""),
	#("prnR","","",""),
	#("RUdv","","",""),
	#("RUfl","","",""),
	("MaSt","cfb","USB Mass Storage Info",""),
	#("SMBw","","",""),
	#("SMBs","","",""),
	#("fssp","","",""),
	#("diSD","","",""),
	#("diCS","","",""),
	#("deSt","","",""),
	#("daSt","","",""),
	#("dmSt","","",""),
	#("adNm","","",""),
	#("adBD","","",""),
	#("adAD","","",""),
	#("adHU","","",""),
	#("IDNm","","",""),
	("seFl","bin","????",""), #????
	#("nvVs","","",""),
	#("dbRC","","",""),
	("dbug","hex","Debug flags","0 <= value <= 0xFFFFFFFF"),
	#("dlvl","","",""),
	#("dcmd","","",""),
	#("dsps","","",""),
	#("logC","","",""),
	#("cver","","",""),
	("ctim","hex","ctim???",""),
	#("svMd","","",""),
	#("serM","","",""),
	#("serT","","",""),
	#("emNo","","",""),
	#("effF","","",""),
	#("LLnk","","",""),
	#("WLnk","","",""),
	#("PHYS","","",""),
	#("PHYN","","",""),
	#("Rnfo","","",""),
	#("evtL","","",""),
	#("isAC","","",""),
	#("Adet","","",""),
	("Prof","cfb","Restore Profile Blob",""),
	#("maAl","","",""),
	#("maPr","","",""),
	#("leAc","","",""),
	#("APID","","",""),
	#("AAU ","","",""),
	("lcVs","str","lcVs Version String?",""),
	#("lcVr","","",""),
	#("lcmV","","",""),
	#("lcMV","","",""),
	#("iMTU","","",""),
	("wsci","cfb","wsci Blob",""),
	#("FlSu","","",""),
	("OTPR","hex","machdep.otpval",""),
	("acRB","dec","Reboot device flag","value == 0"),
	("acRI","dec","Reload services??","value == 0"),
	#("acPC","","",""),
	#("acDD","","",""),
	#("acPD","","",""),
	#("acPG","","",""),
	#("acDS","","",""),
	#("acFN","","",""),
	#("acRP","","",""),
	("acRN","dec","Resets something... (?)","value == 0"),
	("acRF","dec","Reset to factory defaults","value == 0"),
	#("MdmH","","",""),
	#("dirf","","",""),
	#("Afrc","","",""),
	#("lebl","","",""),
	#("lebs","","",""),
	("LEDc","dec","LED color/pattern","0 <= value <= 3"),
	#("acEf","","",""),
	#("invr","","",""),
	#("FLSH","","",""),
	#("acPL","","",""),
	#("rReg","","",""),
	#("dReg","","",""),
	("GPIs","bin","GPIOs values","len(value) == 8"),
	#("play","","",""),
	#("paus","","",""),
	#("ffwd","","",""),
	#("rwnd","","",""),
	#("itun","","",""),
	#("plls","","",""),
	#("User","","",""),
	#("Pass","","",""),
	#("itIP","","",""),
	#("itpt","","",""),
	#("daap","","",""),
	#("song","","",""),
	#("arti","","",""),
	#("albm","","",""),
	#("volm","","",""),
	#("rvol","","",""),
	#("Tcnt","","",""),
	#("Bcnt","","",""),
	#("shfl","","",""),
	#("rept","","",""),
	#("auPr","","",""),
	#("auJD","","",""),
	#("auNN","","",""),
	#("auNP","","",""),
	#("aFrq","","",""),
	#("aChn","","",""),
	#("aLvl","","",""),
	#("aPat","","",""),
	#("aSta","","",""),
	#("aStp","","",""),
	#("auCC","","",""),
	#("acmp","","",""),
	#("aenc","","",""),
	#("anBf","","",""),
	#("aWan","","",""),
	#("auRR","","",""),
	#("auMt","","",""),
	#("aDCP","","",""),
	#("DCPc","","",""),
	#("DACP","","",""),
	#("DCPi","","",""),
	#("auSl","","",""),
	#("auFl","","",""),
	("fe01","hex","????",""),
	("feat","str","Supported features?",""),
	("prop","str","Valid acp properties",""),
	("hw01","hex","????",""),
	#("fltr","","",""),
	#("wdel","","",""),
	#("plEB","","",""),
	#("rWSC","","",""),
	#("uDFS","","",""),
	#("dWPA","","",""),
	#("dpFF","","",""),
	#("duLF","","",""),
	#("ieHT","","",""),
	#("dwlX","","",""),
	#("dd11","","",""),
	#("dRdr","","",""),
	#("dotD","","",""),
	#("dotH","","",""),
	#("dPwr","","",""),
	#("wlBR","","",""),
	#("iTIM","","",""),
	#("idAG","","",""),
	#("mvFL","","",""),
	#("mvFM","","",""),
	#("dPPP","","",""),
	#("!mta","","",""),
	#("minR","","",""),
	#("SpTr","","",""),
	#("dRBT","","",""),
	#("dRIR","","",""),
	("pECC","cfb","PCIe ECC Blob?",""),
	#("fxEB","","",""),
	#("fxID","","",""),
	#("fuup","","",""),
	#("fust","","",""),
	#("fuca","","",""),
	("fugp","str","Firmware upgrade progress",""),
	("cks0","hex","Bootloader Flash Checksum",""),
	("cks1","hex","Primary Flash Checksum",""),
	("cks2","hex","Secondary Flash Checksum",""),
	#("ddBg","","",""),
	#("ddEn","","",""),
	#("ddIn","","",""),
	#("ddSm","","",""),
	#("ddEC","","",""),
	#("ddFE","","",""),
	#("ddSR","","",""),
	#("6cfg","","",""),
	#("6aut","","",""),
	#("6Qpd","","",""),
	#("6Wad","","",""),
	#("6Wfx","","",""),
	#("6Wgw","","",""),
	#("6Wte","","",""),
	#("6Lfw","","",""),
	#("6Lad","","",""),
	#("6Lfx","","",""),
	#("6sfw","","",""),
	#("6pmp","","",""),
	#("6trd","","",""),
	#("6sec","","",""),
	#("6fwl","","",""),
	#("6NS1","","",""),
	#("6NS2","","",""),
	#("6NS3","","",""),
	#("6ahr","","",""),
	#("6dhs","","",""),
	#("6dso","","",""),
	#("6PDa","","",""),
	#("6PDl","","",""),
	#("6vlt","","",""),
	#("6plt","","",""),
	#("6CWa","","",""),
	#("6CWp","","",""),
	#("6CWg","","",""),
	#("6CLa","","",""),
	#("6NSa","","",""),
	#("6NSb","","",""),
	#("6NSc","","",""),
	#("6CPa","","",""),
	#("6CPl","","",""),
	#("6!at","","",""),
	("rteI","cfb","rteI Blob",""),
	#("PCLI","","",""),
	#("dxEM","","",""),
	#("dxID","","",""),
	#("dxAI","","",""),
	#("dxIP","","",""),
	#("dxOA","","",""),
	#("dxIA","","",""),
	#("dxC1","","",""),
	#("dxP1","","",""),
	#("dxC2","","",""),
	#("dxP2","","",""),
	#("bjFl","","",""),
	#("bjSd","","",""),
	#("bjSM","","",""),
	#("wbEn","","",""),
	#("wbHN","","",""),
	#("wbHU","","",""),
	#("wbHP","","",""),
	#("wbRD","","",""),
	#("wbRU","","",""),
	#("wbRP","","",""),
	#("wbAC","","",""),
	#("dMac","","",""),
	#("iCld","","",""),
	#("iCLH","","",""),
	#("iCLB","","",""),
	#("SUEn","","",""),
	#("SUAI","","",""),
	#("SUFq","","",""),
	#("SUSv","","",""),
	#("suPR","","",""),
	#("msEn","","",""),
	#("trCo","","",""),
	#("EZCF","","",""),
	#("ezcf","","",""),
	#("gVID","","",""),
	#("wcfg","","",""),
	#("awce","","",""),
	#("wcgu","","",""),
	#("wcgs","","",""),
	#("awcc","","",""),
	]

def _validation_range(min_value, max_value):
	def _validate(value):
		return isinstance(value, int) and min_value <= value <= max_value
	return _validate


def _validation_equals(expected):
	def _validate(value):
		return value == expected
	return _validate


def _validation_len(expected):
	def _validate(value):
		return len(value) == expected
	return _validate


_validation_rules = {
	"0 <= value <= 0xFFFFFFFF": _validation_range(0, 0xFFFFFFFF),
	"value == 0": _validation_equals(0),
	"0 <= value <= 3": _validation_range(0, 3),
	"len(value) == 8": _validation_len(8),
}


def _get_validation_rule(validation):
	if not validation:
		return None
	if validation not in _validation_rules:
		raise AssertionError(f"unsupported property validation rule: {validation}")
	return _validation_rules[validation]


def _generate_acp_property_dict():	
	props = {}
	for (name, type, description, validation) in _acp_properties:
		# basic validation of tuples
		assert len(name) == 4, f"bad name in _acp_properties list: {name}"
		assert type in ["str", "dec", "hex", "log", "mac", "cfb", "bin"], f"bad type in _acp_properties list for name: {name}"
		assert description, f"missing description in _acp_properties list for name: {name}"
		props[name] = dict(
			type=type,
			description=description,
			validation=validation,
			validator=_get_validation_rule(validation),
		)
	return props


class ACPPropertyInitValueError(ACPPropertyError):
	pass


class ACPProperty:
	_acpprop = _generate_acp_property_dict()
	
	_element_header_format = struct.Struct("!4s2I")
	element_header_size = _element_header_format.size
	_null_raw_value = b"\x00\x00\x00\x00"

	@staticmethod
	def _name_to_wire(name):
		if name is None:
			return ACPProperty._null_raw_value
		if isinstance(name, bytes):
			raw_name = name
		elif isinstance(name, str):
			raw_name = name.encode("ascii")
		else:
			raise ACPPropertyError("property name must be str or bytes")
		if len(raw_name) != 4:
			raise ACPPropertyError("property name must be 4 bytes")
		return raw_name

	@staticmethod
	def _name_from_wire(name):
		if isinstance(name, bytes):
			return name.decode("ascii")
		return name
	
	
	def __init__(self, name=None, value=None):
		# handle "null" property packed name and value first
		if name in ["\x00\x00\x00\x00", self._null_raw_value] and value == self._null_raw_value:
			name = None
			value = None
		else:
			name = self._name_from_wire(name)
		
		if name and name not in self.get_supported_property_names():
			raise ACPPropertyError(f"invalid property name passed to initializer: {name}")
		
		if value is not None:
			# accept value as packed binary string or Python type
			prop_type = self.get_property_info_string(name, "type")
			_init_handler_name = f"_init_{prop_type}"
			assert hasattr(self, _init_handler_name), f"missing init handler for \"{prop_type}\" property type"
			_init_handler = getattr(self, _init_handler_name)
			
			logging.debug(f"old value: {value!r} type: {type(value)}")
			try:
				value = _init_handler(value)
			except ACPPropertyInitValueError as e:
				raise ACPPropertyError(f"{e!s} provided for \"{prop_type}\" property type: {value!r}") from e
			logging.debug(f"new value: {value!r} type: {type(value)}")
			
			validator = self.get_property_validator(name)
			if validator and not validator(value):
				raise ACPPropertyError(f"invalid value passed to initializer for property \"{name}\": {repr(value)}")
		
		self.name = name
		self.value = value
	
	def _init_dec(self, value):
		if isinstance(value, int):
			return value
		elif isinstance(value, bytes):
			try:
				return struct.unpack("!I", value)[0]
			except struct.error as e:
				raise ACPPropertyInitValueError("invalid packed binary string") from e
		else:
			raise ACPPropertyInitValueError("invalid built-in type")
	
	def _init_hex(self, value):
		if isinstance(value, int):
			return value
		elif isinstance(value, bytes):
			try:
				return struct.unpack("!I", value)[0]
			except struct.error as e:
				raise ACPPropertyInitValueError("invalid packed binary string") from e
		else:
			raise ACPPropertyInitValueError("invalid built-in type")
	
	def _init_mac(self, value):
		if isinstance(value, bytes):
			# first, try as packed binary value
			if len(value) == 6:
				return value
			raise ACPPropertyInitValueError("invalid value")
		elif isinstance(value, str):
			# second, attempt to unpack colon delimited value
			mac_bytes = value.split(":")
			if len(mac_bytes) == 6:
				try:
					return bytes.fromhex("".join(mac_bytes))
				except ValueError as e:
					raise ACPPropertyInitValueError("non-hex digit in value") from e
			# fallthrough
			raise ACPPropertyInitValueError("invalid value")
		else:
			raise ACPPropertyInitValueError("invalid built-in type")
	
	def _init_bin(self, value):
		if isinstance(value, bytes):
			return value
		else:
			raise ACPPropertyInitValueError("invalid built-in type")
	
	def _init_cfb(self, value):
		if isinstance(value, bytes):
			return value
		else:
			raise ACPPropertyInitValueError("invalid built-in type")
	
	def _init_log(self, value):
		if isinstance(value, bytes):
			return value
		else:
			raise ACPPropertyInitValueError("invalid built-in type")
	
	def _init_str(self, value):
		if isinstance(value, str):
			return value
		elif isinstance(value, bytes):
			try:
				return value.decode("utf-8")
			except UnicodeDecodeError as e:
				raise ACPPropertyInitValueError("invalid UTF-8 string") from e
		else:
			raise ACPPropertyInitValueError("invalid built-in type")
	
	
	def __repr__(self):
		#XXX: return tuple or dict?
		return repr((self.name, self.value))
	
	
	#TODO: make this function return something other than the formatted value of the property...I keep getting confused by its current shittiness
	def __str__(self):
		#XXX: is this the correct thing to do?
		if self.name is None or self.value is None:
			return ""
		
		prop_type = self.get_property_info_string(self.name, "type")
		_format_handler_name = f"_format_{prop_type}"
		assert hasattr(self, _format_handler_name), f"missing format handler for \"{prop_type}\" property type"
		return getattr(self, _format_handler_name)(self.value)
	
	def _format_dec(self, value):
		return str(value)
	
	def _format_hex(self, value):
		return hex(value)
	
	def _format_mac(self, value):
		mac_bytes = []
		for i in range(6):
			mac_bytes.append(f"{value[i]:02x}")
		return "{0}:{1}:{2}:{3}:{4}:{5}".format(*mac_bytes)
	
	def _format_bin(self, value):
		return value.hex()
	
	def _format_cfb(self, value):
		return pprint.pformat(CFLBinaryPListParser.parse(value))
	
	def _format_log(self, value):
		s = ""
		for line in value.strip(b"\x00").split(b"\x00"):
			s += "{0}\n".format(line.decode("utf-8", errors="replace"))
		return s
	
	def _format_str(self, value):
		return value


	@classmethod
	def get_supported_property_names(cls):
		props = []
		for name in cls._acpprop:
			props.append(name)
		return props
	
	
	@classmethod
	def get_property_info_string(cls, prop_name, key):
		#XXX: should we do this differently?
		if prop_name is None:
			return None
		if prop_name not in cls._acpprop:
			logging.error(f"property \"{prop_name}\" not supported")
			return None
		prop_info = cls._acpprop[prop_name]
		if key not in prop_info:
			logging.error(f"invalid property info key \"{key}\"")
			return None
		return prop_info[key]


	@classmethod
	def get_property_validator(cls, prop_name):
		return cls.get_property_info_string(prop_name, "validator")


	@classmethod
	def parse_raw_element(cls, data):
		name, flags, size = cls.parse_raw_element_header(data[:cls.element_header_size])
		#TODO: handle flags!???
		value_data = data[cls.element_header_size:]
		if len(value_data) < size:
			raise ACPPropertyError("property element data shorter than declared size")
		if len(value_data) > size:
			raise ACPPropertyError("extra data found after property element")
		return cls(name, value_data)
	
	
	@classmethod
	def parse_raw_element_header(cls, data):
		try:
			name, flags, size = cls._element_header_format.unpack(data)
		except struct.error as e:
			raise ACPPropertyError("failed to parse property element header") from e
		return cls._name_from_wire(name), flags, size
	
	
	@classmethod
	def compose_raw_element(cls, flags, property):
		#TODO: handle flags!???
		#XXX: handles "null" name or value first, but this is currently garbage
		name = cls._name_to_wire(property.name)
		value = property.value if property.value is not None else cls._null_raw_value
		if isinstance(value, int):
			st = struct.Struct(">I")
			if value < 0 or value > 0xFFFFFFFF:
				raise ACPPropertyError("integer property value must fit unsigned 32-bit")
			return cls.compose_raw_element_header(name, flags, st.size) + st.pack(value)
		elif isinstance(value, bytes):
			return cls.compose_raw_element_header(name, flags, len(value)) + value
		elif isinstance(value, str):
			raw_value = value.encode("utf-8")
			return cls.compose_raw_element_header(name, flags, len(raw_value)) + raw_value
		else:
			raise ACPPropertyError("unhandled property type for raw element composition")
	
	
	@classmethod
	def compose_raw_element_header(cls, name, flags, size):
		try:
			return cls._element_header_format.pack(cls._name_to_wire(name), flags, size)
		except struct.error as e:
			raise ACPPropertyError("failed to compose property header") from e
