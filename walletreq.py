from w3crack import WalletType

class WalletReq:
	def __init__(self, wdata: bytes | str, wtype: WalletType, wsource: str = "Unknown", wname: str = "Unknown"):
		self.wtype = wtype
		self.wdata = wdata
		self.name = wname
		self.source = wsource

	def __eq__(self, other):
		return other and self.wtype == other.wtype and self.wdata == other.wdata

	def __ne__(self, other):
		return not self.__eq__(other)

	def __hash__(self):
		return hash(self.wdata)
	
	def set_name(self, name: str):
		self.name = name

	def set_source(self, source: str):
		self.source = source