#!/usr/bin/env python3

from w3crack import WalletType, WalletCrackContext, try_shutdown as wcrack_shutdown, WalletCrackConfig as wccfg
import os
import sys
import hashlib
import argparse
import asyncio
import aiofiles
import aiosqlite
import sqlite3
import json
from walletreq import WalletReq
from utils import collect_browsers
from chromium import ChromiumBrowser

class Cracker(object):
	@classmethod
	async def create(cls, outfile):
		self = cls()
		self.passwords = set()
		self.lock = asyncio.Lock()
		self.wallets = set()
		self.outfile = await aiofiles.open(outfile, "w+")
		self.wcctx = WalletCrackContext()
		self.total_cracked = int(0)
		self.cracked_cached_wallets = int(0)
		
		# this local database used for caching our results so we don't bruteforce cracked wallets and don't use already checked passwords twice
		self.db = await aiosqlite.connect("./cache.db")

		# here we also create our tables
		# this table stores wallets hashes which are used to get wallet id in the database
		await self.db.execute("CREATE TABLE IF NOT EXISTS wallets_hashes (id INTEGER NOT NULL PRIMARY KEY, hash BLOB NOT NULL UNIQUE)")
		await self.db.commit()

		# this table stores already cracked wallets so we don't crack them twice
		await self.db.execute("CREATE TABLE IF NOT EXISTS wallets_cracked (id INTEGER NOT NULL UNIQUE, data BLOB NOT NULL, password TEXT NOT NULL)")
		await self.db.commit()

		# this table stores tested passwords so we don't test them twice
		await self.db.execute("CREATE TABLE IF NOT EXISTS tested_passwords (id INTEGER NOT NULL PRIMARY KEY, wid INTEGER NOT NULL, password TEXT NOT NULL, UNIQUE(wid, password))")
		await self.db.commit()

		return self
	
	async def destroy(self):
		await self.db.close()
		self.wcctx = None

	async def crack(self, wallet: WalletReq):
		try:
			# first we want to remove already checked passwords for this wallet
			# because we don't wanna check them twice (they don't match and we checked that already)
			# we store these passwords in the local sqlite database
			match wallet.wdata:
				case str(s): wallet_blob = s.encode()
				case bytes(b): wallet_blob = b
				case _: return
			
			wallet_type = wallet.wtype
			wallet_name = wallet.name
			wallet_source = wallet.source
			sha3 = hashlib.sha3_256()
			sha3.update(wallet_blob)
			wallet_digest = sha3.digest()
			wallet_hash = sqlite3.Binary(wallet_digest)

			# check if this wallet was cracked before, if so we won't perform any bruteforce on this wallet since we already know its content
			cursor = await self.db.execute("SELECT wallets_cracked.data AS data, wallets_cracked.password AS pass FROM wallets_cracked LEFT JOIN wallets_hashes ON (wallets_cracked.id = wallets_hashes.id) WHERE wallets_hashes.hash = ?", (wallet_hash, ))
			row = await cursor.fetchone()
			await cursor.close()

			if row != None:
				await self.__store_wallet_result(wallet_name, wallet_source, row[0], row[1], True)
				return

			# select already tested passwords
			cursor = await self.db.execute("SELECT tested_passwords.password AS pass FROM tested_passwords LEFT JOIN wallets_hashes ON (tested_passwords.wid = wallets_hashes.id) WHERE wallets_hashes.hash = ?", (wallet_hash, ))
			rows = await cursor.fetchall()
			await cursor.close()

			# insert current wallet hash if it wasn't inserted before
			# select the id after that, we do that cuz we don't wana select last_insert_rowid() function
			# (this is what aiosqlite does under the hood in execute_insert)
			# cuz we want to avoid potential race conditions so do that explicitly, here
			try:
				await self.db.execute("INSERT INTO wallets_hashes (hash) VALUES (?)", (wallet_hash, ))
				await self.db.commit()
			except:
				pass
			cursor = await self.db.execute("SELECT id FROM wallets_hashes WHERE hash = ?", (wallet_hash, ))
			row = await cursor.fetchone()
			await cursor.close()
			if row == None:
				return

			wallet_id = row[0]
			passwords: set[str] = set()
			for row in rows:
				pwd = row[0]
				passwords.add(pwd)

			# notify we are into wallet
			print(f"Cracking \"{wallet_name}\" wallet from \"{wallet_source}\"")

			# remove already tested passwords and make our request
			# since self.passwords are not being modified, we don't need to lock here
			passwords = self.passwords.difference(passwords)
			if len(passwords) == 0:
				print(f"No matches found for a wallet \"{wallet_name}\" from \"{wallet_source}\"")
				return
			
			# possible cfg values are:
			# preparse (bool) -- described below
			# cpu_only (bool) -- perform CPU only bruteforce, this can be used in case if correct password is already known or there no many passwods to test
			#                    in this case CPU bruteforce may be faster cos we don't need to setup GPU device, build kernels, alloc memory, wait for GPU events, etc. in this case
			# gpu_only (bool) -- try to perform GPU only bruteforce, in case if we can't perform GPU bruteforce for any reason, we will simply get out with error instead of falling back to CPU
			#                    this can be useful if you want to guarantee that only GPU bruteforce will be done if possible and so no CPU bruteforce in error case
			# NOTE: gpu_only and cpu_only flags are mutually exclusive, if you pass both then no bruteforce will be performed
			wcrack_cfg = wccfg(preparse = True)

			# this function will also try to parse the wallet data in case if decrypted and return only useful data
			# if parse fails, then the original data is returned.
			# the parsing can be suppressed by passing False instead of True to the preparse param of cfg
			# arguments of this function are: wallet_type, wallet_data, passwords_to_test, cfg
			# this can be useful to decrypt any metamask-like wallets and then parse the result here in python
			# (so we can avoid extra recompilations)
			result = await self.wcctx.try_crack_wallet(wallet_type, wallet_blob, passwords, wcrack_cfg)
			if result == None:
				print(f"No matches found for a wallet \"{wallet_name}\" from \"{wallet_source}\"")
			elif isinstance(result, str):
				print(f"Error while cracking a wallet \"{wallet_name}\" from \"{wallet_source}\": {result}")
			else:
				# wallet was successfuly cracked, store its passwords and data to the local database so we don't bruteforce twice
				# the result data is list[bytes] here, we have to dump that stuff to some readable format first
				# the format will depend on wallet type being cracked
				result_data, result_password = result
				result_data = self.__wallet_result_to_string(wallet_type, result_data)
				await self.db.execute("INSERT OR IGNORE INTO wallets_cracked (id, data, password) VALUES (?, ?, ?)", (wallet_id, result_data, result_password))
				await self.db.commit()
				await self.__store_wallet_result(wallet_name, wallet_source, result_data, result_password, False)
				print(f"Successfuly cracked wallet \"{wallet_name}\" from \"{wallet_source}\"")
				return
			
			# cache used passwords
			pwds = list(passwords)
			await self.db.executemany("INSERT OR IGNORE INTO tested_passwords (wid, password) VALUES (?, ?)", ((wallet_id, pwd) for pwd in pwds))
			await self.db.commit()
		except:
			pass

	@staticmethod
	def __wallet_result_to_string(wallet_type: WalletType, result_data: list[bytes]) -> str:
		match wallet_type:
			case WalletType.MetaMask | WalletType.Brave | WalletType.Ronin | WalletType.TrustWallet:
				return b"; ".join(result_data).decode("utf-8")
			case WalletType.Binance:
				result = "\n"
				for data in result_data:
					data = json.loads(data.decode("utf-8"))
					mnemonic = data["mnemonic"]
					addresses = []
					for address in data["addresses"]:
						address_type = address["type"]
						address_privkey = address["privateKey"]
						address_address = address["address"]
						addresses.append(f"{address_address} (Network: {address_type}; Private key: {address_privkey})")

					addresses = "\n\t\t\t".join(addresses)
					result += f"\t\tMnemonic: {mnemonic}\n\t\tAddresses:\n\t\t\t{addresses}"
				if len(result) != 1:
					return result
				return ""
			case _:
				return ""
	
	async def __store_wallet_result(self, wallet_name: str, wallet_source: str, wallet_data, correct_password, was_cached):
		async with self.lock:
			self.total_cracked += int(1)
			if was_cached: self.cracked_cached_wallets += int(1)
			await self.outfile.write(f"Wallet \"{wallet_name}\" from \"{wallet_source}\":\n\tData: {wallet_data}\n\tPassword: {correct_password}\n\n")

	async def collect_passwords_from_browser(self, browser: ChromiumBrowser):
		passwords = await browser.collect_passwords()
		if len(passwords) != 0:
			async with self.lock:
				self.passwords.update(passwords)

	async def collect_wallets_from_browser(self, browser: ChromiumBrowser):
		wallets = await browser.collect_wallets()
		if len(wallets) != 0:
			async with self.lock:
				self.wallets.update(wallets)
	
	async def collect_passwords_platform_specific(self):
		if sys.platform.startswith("win"):
			from winvault import WinVault
			vault = WinVault()
			accounts = vault.extract_accounts()
			async with self.lock:
				for (resource, identity, password) in accounts:
					if len(password) != 0:
						self.passwords.add(password)

async def async_main(args):
	# the algorithm is the following:
	# 1 Collect browsers directories. We gonna extract wallets and passwords from there
	# 2 Try to collect passwords from browsers and additional sources
	# 3 Then we also take passwords from passwords file if specified
	# 4 If there's no passwords, then get out, otherwise continue
	# 5 If there's no wallets in total, then get out, otherwise continue
	# 6 Wallet cracking algorithm looks like following (it will be parallelized since we do it in async maner, but here it is ordered):
	# 6 1 We select already checked passwords and info for specific wallet from SQLite database and remove these passwords from the list
	# 6 2 If there's no passwords, then get to the next wallet if any, otherwise continue
	# 6 3 If this wallet was already cracked (hash matches), then simply select the already cracked data and correct password (we don't wana waste CPU or GPU time bruteforcing it again), otherwise continue
	# 6 4 Pass the wallet data and passwords to the crack driver. It will use GPU if possible to crack the wallet so it should be fast enough
	# 6 5 Cache the result and passed data so we don't do job twice next time
	# 6 6 If crack was successful, then store the cracked data to the output file and go to the next wallet
	cracker = await Cracker.create(args.outfile)

	async def collect_passwords_from_browsers():
		tasks = []
		for browser in browsers:
			tasks.append(asyncio.create_task(cracker.collect_passwords_from_browser(browser)))
		await asyncio.wait(tasks, return_when = asyncio.ALL_COMPLETED)

	# predefine some here
	async def collect_wallets():
		tasks = []
		for browser in browsers:
			tasks.append(asyncio.create_task(cracker.collect_wallets_from_browser(browser)))
		await asyncio.wait(tasks, return_when = asyncio.ALL_COMPLETED)

	# collect the browsers first, then we gonna collect data from them in parallel maner
	browsers = collect_browsers()
	if len(browsers) == 0:
		print("No supported browsers found. Consider adding it to the list in utils.py")
		await cracker.destroy()
		return

	await collect_passwords_from_browsers()
	
	# parse passfile if it was specified
	# we don't need to lock since we are the only one who is accessing cracker object at the moment
	if args.passfile != None:
		try:
			async with aiofiles.open(args.passfile, mode="r") as f:
				passwords = await f.read()
				passwords = passwords.splitlines()
				if len(passwords) != 0:
					cracker.passwords.update(passwords)
		except:
			print(f"Unable to load passwords from \"{args.passfile}\". Check if the file name is correct")
			await cracker.destroy()
			return
		
	# collect some additional from platform specific collectors
	await cracker.collect_passwords_platform_specific()
	
	# if still no passwords, then get out
	if len(cracker.passwords) == 0:
		print("Got no passwords to use. Consider using --help")
		await cracker.destroy()
		return
	
	# collect wallets from the browsers
	await collect_wallets()
	print("Wallets and passwords were collected. We cracking them now. It may take some time, so please wait")

	# try to crack the wallets
	if len(cracker.wallets) != 0:
		tasks = []
		for wallet in cracker.wallets:
			tasks.append(asyncio.create_task(cracker.crack(wallet)))
		await asyncio.wait(tasks, return_when = asyncio.ALL_COMPLETED)

	print(f"Job is done. Total cracked wallets: {cracker.total_cracked} ({cracker.cracked_cached_wallets} taken from cache). Cracked wallets should now appear in output file")
	await cracker.destroy()

def main(args):
	try:
		asyncio.run(async_main(args))
	except Exception as e:
		print(f"An error happened: {e}")
	finally:
		# explicitly shutdown the wcrack module
		# this is needed to stop the inner event loop
		try:
			wcrack_shutdown(False)
		except:
			# this one must never happen
			pass

if __name__ == "__main__":
	scriptname = os.path.basename(__file__)
	parser = argparse.ArgumentParser(
		prog = "Wallet Recovery Tool",
		description = "Attempts to recover your crypto wallets from web browsers.\n" \
					f"Example usage: {scriptname} -p ./passwords.txt -o ./output.txt",
		epilog = "NOTE: Since this script walks thru browsers directories and tries to extract passwords and crack crypto wallets some antiviruses may falsely detect it as a virus.\n"
				"If this happens you may try to add this script and|or python process to the antivirus exceptions\n")

	parser.add_argument("-o", "--output", dest = "outfile", action = "store", default = "./output.txt", help = "Output file name. output.txt is default file name")

	parser.add_argument("-p", "--passfile", action = "store", dest = "passfile", help = "File which contains passwords.\n" \
					 						"Each password must be separated line by line.\n" \
											"Max len of each password is 128 bytes, otherwise the password is ignored.\n" \
											"This argument is optional, however if there's no password collected no crack attempts will be performed.")

	args = parser.parse_args()
	main(args)
