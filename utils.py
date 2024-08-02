import sys
import os
from pathlib import PosixPath
from chromium import ChromiumBrowser, ChromiumFlags

# this one simply creates list of hardcoded browsers
# if your browser is not in the list, feel free to add it
# note that only chromium browsers are supported at the moment
def collect_browsers() -> list[ChromiumBrowser]:
	browsers: list[ChromiumBrowser] = list()
	if sys.platform.startswith("win"):
		appdata_roaming = os.getenv('APPDATA')
		appdata_local = os.getenv('LOCALAPPDATA')
		browsers.append(ChromiumBrowser("Opera", f"{appdata_roaming}\\Opera Software\\Opera Stable\\", "", ChromiumFlags(0)))
		browsers.append(ChromiumBrowser("Opera GX", f"{appdata_roaming}\\Opera Software\\Opera GX Stable\\", "", ChromiumFlags(0)))
		browsers.append(ChromiumBrowser("Opera Neon", f"{appdata_roaming}\\Opera Software\\Opera Neon\\", "User Data\\Default\\", ChromiumFlags(0)))
		browsers.append(ChromiumBrowser("Google Chrome", f"{appdata_local}\\Google\\Chrome\\", "User Data\\Default\\", ChromiumFlags(0)))
		browsers.append(ChromiumBrowser("Google Chrome Beta", f"{appdata_local}\\Google\\Chrome Beta\\", "User Data\\Default\\", ChromiumFlags(0)))
		browsers.append(ChromiumBrowser("Google Chrome SxS", f"{appdata_local}\\Google\\Chrome SxS\\", "User Data\\Default\\", ChromiumFlags(0)))
		browsers.append(ChromiumBrowser("360 Browser", f"{appdata_local}\\360chrome\\Chrome\\", "User Data\\Default\\", ChromiumFlags(0)))
		browsers.append(ChromiumBrowser("Chrome Plus", f"{appdata_local}\\ChromePlus\\MappleStudio\\", "User Data\\Default\\", ChromiumFlags(0)))
		browsers.append(ChromiumBrowser("Brave Browser", f"{appdata_local}\\BraveSoftware\\Brave-Browser\\", "User Data\\Default\\", ChromiumFlags.Brave))
		browsers.append(ChromiumBrowser("Microsoft Edge", f"{appdata_local}\\Microsoft\\Edge\\", "User Data\\Default\\", ChromiumFlags(0)))
		browsers.append(ChromiumBrowser("Chromium", f"{appdata_local}\\Chromium\\", "User Data\\Default\\", ChromiumFlags(0)))
		browsers.append(ChromiumBrowser("Vivaldi", f"{appdata_local}\\Vivaldi\\", "User Data\\Default\\", ChromiumFlags(0)))
		browsers.append(ChromiumBrowser("Amigo", f"{appdata_local}\\Amigo\\", "User Data\\Default\\", ChromiumFlags(0)))
		browsers.append(ChromiumBrowser("Kometa", f"{appdata_local}\\Kometa\\", "User Data\\Default\\", ChromiumFlags(0)))
		browsers.append(ChromiumBrowser("Orbitum", f"{appdata_local}\\Orbitum\\", "User Data\\Default\\", ChromiumFlags(0)))
		browsers.append(ChromiumBrowser("Sputnik", f"{appdata_local}\\Sputnik\\Sputnik\\", "User Data\\Default\\", ChromiumFlags(0)))
		browsers.append(ChromiumBrowser("Torch", f"{appdata_local}\\Torch\\", "User Data\\Default\\", ChromiumFlags(0)))
		browsers.append(ChromiumBrowser("Mail.RU Atom", f"{appdata_local}\\Mail.Ru\\Atom\\", "User Data\\Default\\", ChromiumFlags(0)))
		browsers.append(ChromiumBrowser("Yandex Browser", f"{appdata_local}\\Yandex\\YandexBrowser\\", "User Data\\Default\\", ChromiumFlags.Yandex))
	elif sys.platform.startswith("linux"):
		browsers.append(ChromiumBrowser("Opera", PosixPath("~/.config/opera/").expanduser().as_posix()+"/", "Default/", ChromiumFlags(0)))
		browsers.append(ChromiumBrowser("Google Chrome", PosixPath("~/.config/google-chrome/").expanduser().as_posix()+"/", "Default/", ChromiumFlags(0)))
		browsers.append(ChromiumBrowser("Chromium", PosixPath("~/.config/chromium/").expanduser().as_posix()+"/", "Default/", ChromiumFlags(0)))
		browsers.append(ChromiumBrowser("Brave Browser", PosixPath("~/.config/BraveSoftware/").expanduser().as_posix()+"/", "Default/", ChromiumFlags.Brave))
		browsers.append(ChromiumBrowser("Vivaldi", PosixPath("~/.config/vivaldi/").expanduser().as_posix()+"/", "Default/", ChromiumFlags(0)))
		browsers.append(ChromiumBrowser("Vivaldi", PosixPath("~/.config/vivaldi-snapshot/").expanduser().as_posix()+"/", "Default/", ChromiumFlags(0)))
		browsers.append(ChromiumBrowser("Yandex Browser", PosixPath("~/.config/yandex-browser/").expanduser().as_posix()+"/", "Default/", ChromiumFlags.Yandex))
	else:
		raise "not implemented"
	
	return browsers
