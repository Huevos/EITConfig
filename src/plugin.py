from os import path as ospath
from re import match

from enigma import eEPGCache

from ServiceReference import ServiceReference

from Components.ActionMap import HelpableActionMap
from Components.config import ConfigNothing, NoSave
from Components.Sources.StaticText import StaticText

from Plugins.Plugin import PluginDescriptor

from Screens.MessageBox import MessageBox
from Screens.Setup import Setup

from . import _

BLACKLIST = eEPGCache.BLACKLIST
WHITELIST = eEPGCache.WHITELIST

BLACKLISTPATH = "/etc/enigma2/blacklist.eit"
WHITELISTPATH = "/etc/enigma2/whitelist.eit"


def make_sref(service):
	return "1:0:%X:%X:%X:%X:%X:0:0:0:" % (
		service["service_type"],
		service["service_id"],
		service["transport_stream_id"],
		service["original_network_id"],
		service["namespace"])


class LamedbReader():
	def readLamedb(self, path):
		# print("[%s-LamedbReader] Reading lamedb..." % (debug_name))

		transponders = {}

		try:
			lamedb = open(path + "/lamedb", "r")
		except Exception:
			return transponders

		content = lamedb.read()
		lamedb.close()

		lamedb_ver = 4
		result = match('eDVB services /([45])/', content)
		if result:
			lamedb_ver = int(result.group(1))
			# print("[%s-LamedbReader] lamedb ver" % (debug_name), lamedb_ver)
		if lamedb_ver == 4:
			transponders = self.parseLamedbV4Content(content)
		elif lamedb_ver == 5:
			transponders = self.parseLamedbV5Content(content)
		return transponders

	def parseLamedbV4Content(self, content):
		transponders = {}
		transponders_count = 0
		services_count = 0

		tp_start = content.find("transponders\n")
		tp_stop = content.find("end\n")

		tp_blocks = content[tp_start + 13:tp_stop].strip().split("/")
		content = content[tp_stop + 4:]

		for block in tp_blocks:
			rows = block.strip().split("\n")
			if len(rows) != 2:
				continue

			first_row = rows[0].strip().split(":")
			if len(first_row) != 3:
				continue

			transponder = {}
			transponder["services"] = {}
			transponder["namespace"] = int(first_row[0], 16)
			transponder["transport_stream_id"] = int(first_row[1], 16)
			transponder["original_network_id"] = int(first_row[2], 16)

			# print("%x:%x:%x" % (namespace, transport_stream_id, original_network_id))
			second_row = rows[1].strip()
			transponder["dvb_type"] = 'dvb' + second_row[0]
			if transponder["dvb_type"] not in ["dvbs", "dvbt", "dvbc"]:
				continue

			second_row = second_row[2:].split(":")

			if transponder["dvb_type"] == "dvbs" and len(second_row) not in (7, 11, 14, 16):
				continue
			if transponder["dvb_type"] == "dvbt" and len(second_row) != 12:
				continue
			if transponder["dvb_type"] == "dvbc" and len(second_row) != 7:
				continue

			if transponder["dvb_type"] == "dvbs":
				transponder["frequency"] = int(second_row[0])
				transponder["symbol_rate"] = int(second_row[1])
				transponder["polarization"] = int(second_row[2])
				transponder["fec_inner"] = int(second_row[3])
				orbital_position = int(second_row[4])
				if orbital_position < 0:
					transponder["orbital_position"] = orbital_position + 3600
				else:
					transponder["orbital_position"] = orbital_position

				transponder["inversion"] = int(second_row[5])
				transponder["flags"] = int(second_row[6])
				if len(second_row) == 7:  # DVB-S
					transponder["system"] = 0
				else:  # DVB-S2
					transponder["system"] = int(second_row[7])
					transponder["modulation"] = int(second_row[8])
					transponder["roll_off"] = int(second_row[9])
					transponder["pilot"] = int(second_row[10])
					if len(second_row) > 13:  # Multistream
						transponder["is_id"] = int(second_row[11])
						transponder["pls_code"] = int(second_row[12])
						transponder["pls_mode"] = int(second_row[13])
						if len(second_row) > 15:  # T2MI
							transponder["t2mi_plp_id"] = int(second_row[14])
							transponder["t2mi_pid"] = int(second_row[15])
			elif transponder["dvb_type"] == "dvbt":
				transponder["frequency"] = int(second_row[0])
				transponder["bandwidth"] = int(second_row[1])
				transponder["code_rate_hp"] = int(second_row[2])
				transponder["code_rate_lp"] = int(second_row[3])
				transponder["modulation"] = int(second_row[4])
				transponder["transmission_mode"] = int(second_row[5])
				transponder["guard_interval"] = int(second_row[6])
				transponder["hierarchy"] = int(second_row[7])
				transponder["inversion"] = int(second_row[8])
				transponder["flags"] = int(second_row[9])
				transponder["system"] = int(second_row[10])
				transponder["plpid"] = int(second_row[11])
			elif transponder["dvb_type"] == "dvbc":
				transponder["frequency"] = int(second_row[0])
				transponder["symbol_rate"] = int(second_row[1])
				transponder["inversion"] = int(second_row[2])
				transponder["modulation"] = int(second_row[3])
				transponder["fec_inner"] = int(second_row[4])
				transponder["flags"] = int(second_row[5])
				transponder["system"] = int(second_row[6])

			key = "%x:%x:%x" % (transponder["namespace"], transponder["transport_stream_id"], transponder["original_network_id"])
			transponders[key] = transponder
			transponders_count += 1

		srv_start = content.find("services\n")
		srv_stop = content.rfind("end\n")

		srv_blocks = content[srv_start + 9:srv_stop].strip().split("\n")

		for i in range(0, len(srv_blocks) // 3):
			service_reference = srv_blocks[i * 3].strip()
			service_name = srv_blocks[(i * 3) + 1].strip()
			service_provider = srv_blocks[(i * 3) + 2].strip()
			service_reference = service_reference.split(":")

			if len(service_reference) not in (6, 7):
				continue

			service = {}
			service["service_name"] = service_name
			service["service_line"] = service_provider
			service["service_provider"] = service_provider.replace("p:", "").split(",", 1)[0].strip()
			service["service_id"] = int(service_reference[0], 16)
			service["namespace"] = int(service_reference[1], 16)
			service["transport_stream_id"] = int(service_reference[2], 16)
			service["original_network_id"] = int(service_reference[3], 16)
			service["service_type"] = int(service_reference[4])
			service["flags"] = int(service_reference[5])
			if len(service_reference) == 7 and int(service_reference[6], 16) != 0:
				service["ATSC_source_id"] = int(service_reference[6], 16)

			key = "%x:%x:%x" % (service["namespace"], service["transport_stream_id"], service["original_network_id"])
			if key not in transponders:
				continue

			# The original (correct) code
			# transponders[key]["services"][service["service_id"]] = service

			# Dirty hack to work around the (well known) service type bug in lamedb/enigma2
			transponders[key]["services"]["%x:%x" % (service["service_type"], service["service_id"])] = service

			services_count += 1

		# print("[%s-LamedbReader] Read %d transponders and %d services" % (debug_name, transponders_count, services_count))
		return transponders

	def parseLamedbV5Content(self, content):
		transponders = {}
		transponders_count = 0
		services_count = 0

		lines = content.splitlines()
		for line in lines:
			if line.startswith("t:"):
				first_part = line.strip().split(",")[0][2:].split(":")
				if len(first_part) != 3:
					continue

				transponder = {}
				transponder["services"] = {}
				transponder["namespace"] = int(first_part[0], 16)
				transponder["transport_stream_id"] = int(first_part[1], 16)
				transponder["original_network_id"] = int(first_part[2], 16)

				second_part = line.strip().split(",")[1]
				transponder["dvb_type"] = 'dvb' + second_part[0]
				if transponder["dvb_type"] not in ["dvbs", "dvbt", "dvbc"]:
					continue

				second_part = second_part[2:].split(":")

				if transponder["dvb_type"] == "dvbs" and len(second_part) not in (7, 11):
					continue
				if transponder["dvb_type"] == "dvbt" and len(second_part) != 12:
					continue
				if transponder["dvb_type"] == "dvbc" and len(second_part) != 7:
					continue

				if transponder["dvb_type"] == "dvbs":
					transponder["frequency"] = int(second_part[0])
					transponder["symbol_rate"] = int(second_part[1])
					transponder["polarization"] = int(second_part[2])
					transponder["fec_inner"] = int(second_part[3])
					orbital_position = int(second_part[4])
					if orbital_position < 0:
						transponder["orbital_position"] = orbital_position + 3600
					else:
						transponder["orbital_position"] = orbital_position

					transponder["inversion"] = int(second_part[5])
					transponder["flags"] = int(second_part[6])
					if len(second_part) == 7:  # DVB-S
						transponder["system"] = 0
					else:  # DVB-S2
						transponder["system"] = int(second_part[7])
						transponder["modulation"] = int(second_part[8])
						transponder["roll_off"] = int(second_part[9])
						transponder["pilot"] = int(second_part[10])
						for part in line.strip().split(",")[2:]:  # Multistream/T2MI
							if part.startswith("MIS/PLS:") and len(part[8:].split(":")) == 3:
								transponder["is_id"] = int(part[8:].split(":")[0])
								transponder["pls_code"] = int(part[8:].split(":")[1])
								transponder["pls_mode"] = int(part[8:].split(":")[2])
							elif part.startswith("T2MI:") and len(part[5:].split(":")) == 2:
								transponder["t2mi_plp_id"] = int(part[5:].split(":")[0])
								transponder["t2mi_pid"] = int(part[5:].split(":")[1])
				elif transponder["dvb_type"] == "dvbt":
					transponder["frequency"] = int(second_part[0])
					transponder["bandwidth"] = int(second_part[1])
					transponder["code_rate_hp"] = int(second_part[2])
					transponder["code_rate_lp"] = int(second_part[3])
					transponder["modulation"] = int(second_part[4])
					transponder["transmission_mode"] = int(second_part[5])
					transponder["guard_interval"] = int(second_part[6])
					transponder["hierarchy"] = int(second_part[7])
					transponder["inversion"] = int(second_part[8])
					transponder["flags"] = int(second_part[9])
					transponder["system"] = int(second_part[10])
					transponder["plpid"] = int(second_part[11])
				elif transponder["dvb_type"] == "dvbc":
					transponder["frequency"] = int(second_part[0])
					transponder["symbol_rate"] = int(second_part[1])
					transponder["inversion"] = int(second_part[2])
					transponder["modulation"] = int(second_part[3])
					transponder["fec_inner"] = int(second_part[4])
					transponder["flags"] = int(second_part[5])
					transponder["system"] = int(second_part[6])

				key = "%x:%x:%x" % (transponder["namespace"], transponder["transport_stream_id"], transponder["original_network_id"])
				transponders[key] = transponder
				transponders_count += 1
			elif line.startswith("s:"):
				service_reference = line.strip().split(",")[0][2:]
				service_name = line.strip().split('"', 1)[1].split('"')[0]
				third_part = line.strip().split('"', 2)[2]
				service_provider = ""
				if len(third_part):
					service_provider = third_part[1:]
				service_reference = service_reference.split(":")
				if len(service_reference) != 6 and len(service_reference) != 7:
					continue

				service = {}
				service["service_name"] = service_name
				service["service_line"] = service_provider
				service["service_provider"] = service_provider.replace("p:", "").split(",", 1)[0].strip()
				service["service_id"] = int(service_reference[0], 16)
				service["namespace"] = int(service_reference[1], 16)
				service["transport_stream_id"] = int(service_reference[2], 16)
				service["original_network_id"] = int(service_reference[3], 16)
				service["service_type"] = int(service_reference[4])
				service["flags"] = int(service_reference[5])
				if len(service_reference) == 7 and int(service_reference[6], 16) != 0:
					service["ATSC_source_id"] = int(service_reference[6], 16)

				key = "%x:%x:%x" % (service["namespace"], service["transport_stream_id"], service["original_network_id"])
				if key not in transponders:
					continue

				# The original (correct) code
				# transponders[key]["services"][service["service_id"]] = service

				# Dirty hack to work around the (well known) service type bug in lamedb/enigma2
				transponders[key]["services"]["%x:%x" % (service["service_type"], service["service_id"])] = service

				services_count += 1

		# print("[%s-LamedbReader] Read %d transponders and %d services" % (debug_name, transponders_count, services_count))
		return transponders


class Database:
	def __init__(self, filename):
		self.filename = filename
		self.__srefs = self.__sanitizeData(open(self.filename, 'r').readlines()) if ospath.isfile(self.filename) else []

	def __sanitizeData(self, data):
		return list(set([line.strip() for line in data if line and isinstance(line, str) and match("^(?:[0-9A-F]+[:]){10}$", line.strip())])) if isinstance(data, list) else []

	def __saveToFile(self):
		self.__srefs.sort(key=lambda ref: (int((x := ref.split(":"))[6], 16), int(x[5], 16), int(x[4], 16), int(x[3], 16)))
		open(self.filename, 'w').write('\n'.join(self.__srefs))

	def getData(self):
		return self.__srefs

	def setData(self, data):
		self.__srefs = self.__sanitizeData(data)
		self.__saveToFile()

	data = property(getData, setData)


class Editor(Setup):
	def __init__(self, session, what):
		self.processLamedb()
		self.askAboutProviderAdditions = True
		self.askAboutProviderRemovals = True
		self.isBlacklist = what == BLACKLIST
		self.serviceitems = []
		self.db1 = Database(BLACKLISTPATH if self.isBlacklist else WHITELISTPATH)
		self.db2 = Database(WHITELISTPATH if self.isBlacklist else BLACKLISTPATH)
		self.services = self.db1.data[:]  # work on a copy
		self.services_other = self.db2.data[:]  # work on a copy
		Setup.__init__(self, session=session, setup=None)
		self.title = _("Edit Now/Next EIT Blacklist") if self.isBlacklist else _("Edit Now/Next EIT Whitelist")
		self["key_yellow"] = StaticText()
		self["key_blue"] = StaticText()
		self["addActions"] = HelpableActionMap(self, ["ColorActions"], {
			"yellow": (self.keyAddService, _("Add a service"))
		}, prio=0, description=_("EIT Setup Actions"))
		self["removeActions"] = HelpableActionMap(self, ["ColorActions"], {
			"blue": (self.keyRemoveService, _("Remove a service"))
		}, prio=0, description=_("Eit Setup Actions"))
		self["removeActions"].setEnabled(False)
		self.updateButtons()

	def processLamedb(self):
		self.sref_to_provider = {}
		self.provider_to_srefs = {}
		transponders = LamedbReader().readLamedb("/etc/enigma2")
		for key in transponders:
			for key2 in transponders[key]["services"]:
				service = transponders[key]["services"][key2]
				sref = make_sref(service)
				provider = service["service_provider"]
				self.sref_to_provider[sref] = provider
				if provider:
					if provider not in self.provider_to_srefs:
						self.provider_to_srefs[provider] = []
					self.provider_to_srefs[provider].append(sref)

	def createSetup(self):
		self.serviceitems = []
		if self.services:
			for serviceref in self.services:
				self.serviceitems.append((self.getServiceName(serviceref) + self.getProvider(serviceref) + " " + self.formatOrbPos(serviceref), NoSave(ConfigNothing()), serviceref, self.getOrbPos(serviceref)))
			self.serviceitems.sort(key=self.sort)
		self["config"].list = self.serviceitems

	def selectionChanged(self):
		self.updateButtons()
		Setup.selectionChanged(self)

	def updateButtons(self):
		if self.services and isinstance(self.getCurrentItem(), ConfigNothing):
			self["removeActions"].setEnabled(True)
			self["key_blue"].setText(_("Remove"))
		else:
			self["removeActions"].setEnabled(False)
			self["key_blue"].setText("")
		self["key_yellow"].setText(_("Add service"))

	def keySelect(self):
		if not isinstance(self.getCurrentItem(), ConfigNothing):
			Setup.keySelect(self)

	def keyMenu(self):
		if not isinstance(self.getCurrentItem(), ConfigNothing):
			Setup.keyMenu(self)

	def keyRemoveService(self):
		currentItem = self.getCurrentItem()
		if currentItem:
			serviceref = self["config"].getCurrent()[2]
			self.services.remove(serviceref)
			index = self["config"].getCurrentIndex()
			self.createSetup()
			self["config"].setCurrentIndex(index)
			if self.askAboutProviderRemovals and serviceref in self.sref_to_provider and self.sref_to_provider[serviceref]:
				self.currentProvider = self.sref_to_provider[serviceref]
				choices = [(_("No"), False), (_("No, and don't ask again"), "dont ask again"), (_("Yes"), True)]
				message = _("Would you like to remove all services from provider '%s'?") % self.currentProvider
				mb = self.session.openWithCallback(self.removeCurrentProviderCallback, MessageBox, message, list=choices, default=1)
				mb.title = _("Removed service %s") % self.getServiceName(serviceref)

	def removeCurrentProviderCallback(self, retval):
		if retval:
			if retval == "dont ask again":
				self.askAboutProviderRemovals = False
			elif self.currentProvider in self.provider_to_srefs:
				for serviceref in self.provider_to_srefs[self.currentProvider]:
					if serviceref in self.services:
						self.services.remove(serviceref)
				index = self["config"].getCurrentIndex()
				self.createSetup()
				self["config"].setCurrentIndex(index)
				self["description"].text = self.getCurrentDescription()
				self.updateButtons()

	def keyAddService(self):
		def keyAddServiceCallback(*result):
			if result:
				service = ServiceReference(result[0])
				serviceref = str(service)
				if serviceref not in self.sref_to_provider:  # abort if service not in lamedb
					self.session.open(MessageBox, _("It is only possible to add services that exist in lamedb."), MessageBox.TYPE_INFO, timeout=10)
					return  # this needs to be a MessageBox
				if serviceref not in self.services:
					self.services.append(serviceref)
					index = self["config"].getCurrentIndex()
					self.createSetup()
					self["config"].setCurrentIndex(index)
				self.currentProvider = self.sref_to_provider[serviceref]
				if self.currentProvider and self.askAboutProviderAdditions:  # avoid providers that are empty strings
					choices = [(_("No"), False), (_("No, and don't ask again"), "dont ask again"), (_("Yes"), True)]
					message = _("Would you like to add all services from provider '%s'?") % self.currentProvider
					mb = self.session.openWithCallback(self.addCurrentProviderCallback, MessageBox, message, list=choices, default=1)
					mb.title = _("Added service %s") % self.getServiceName(serviceref)

		from Screens.ChannelSelection import SimpleChannelSelection  # deferred to avoid circular import
		self.session.openWithCallback(keyAddServiceCallback, SimpleChannelSelection, _("Select"), currentBouquet=False)

	def addCurrentProviderCallback(self, retval):
		if retval:
			if retval == "dont ask again":
				self.askAboutProviderAdditions = False
			elif self.currentProvider in self.provider_to_srefs:
				for serviceref in self.provider_to_srefs[self.currentProvider]:
					if serviceref not in self.services:
						self.services.append(serviceref)
				index = self["config"].getCurrentIndex()
				self.createSetup()
				self["config"].setCurrentIndex(index)

	def keySave(self):
		if self.db1.data != self.services:
			self.db1.data = self.services
			eEPGCache.getInstance().reloadEITConfig(BLACKLIST if self.isBlacklist else WHITELIST)
		self.services_other = list(set(self.services_other).difference(self.services))  # test that no added services exist in the other list and if so remove them
		if self.db2.data != self.services_other:
			self.db2.data = self.services_other
			eEPGCache.getInstance().reloadEITConfig(WHITELIST if self.isBlacklist else BLACKLIST)
#		Setup.keySave(self)
		self.close()

	def getOrbPos(self, sref):
		orbpos = 0
		try:
			orbpos = int(sref.split(":")[6], 16) >> 16
		except:
			pass
		return orbpos

	def formatOrbPos(self, sref):
		orbpos = self.getOrbPos(sref)
		if isinstance(orbpos, int):
			if 1 <= orbpos <= 3600:  # sanity
				if orbpos > 1800:
					return str((float(3600 - orbpos)) / 10.0) + "\xb0" + "W"
				else:
					return str((float(orbpos)) / 10.0) + "\xb0" + "E"
			elif orbpos == 0xEEEE:
				return _("terrestrial")
			elif orbpos == 0xFFFF:
				return _("cable")
		return ""

	def getProvider(self, ref):
		provider = ref in self.sref_to_provider and self.sref_to_provider[ref]
		return ", " + provider + "," if provider else ""

	def getServiceName(self, serviceref):
		return (service := ServiceReference(serviceref)) and service.getServiceName() or serviceref

	def sort(self, item):
		return (item[3], item[0].lower() if item and item[0] and ord(item[0].lower()[0]) in range(97, 123) else f"zzzzz{item[0].lower()}")

	def keyRight(self):  # use key as page down for service items
		if isinstance(self.getCurrentItem(), ConfigNothing):
			self.keyPageDown()
		else:
			Setup.keyRight(self)
	
	def keyLeft(self):  # use key as page up for service items
		if isinstance(self.getCurrentItem(), ConfigNothing):
			self.keyPageUp()
		else:
			Setup.keyLeft(self)



def BlacklistStart(menuid, **kwargs):  # Menu position of plugin setup screen
	if menuid == "epg":
		return [(_("Now/Next Blacklist"), BlacklistMain, "NowNext_blacklist", 10002)]
	return []


def BlacklistMain(session, **kwargs):
	session.open(Editor, BLACKLIST)


def WhitelistStart(menuid, **kwargs):  # Menu position of plugin setup screen
	if menuid == "epg":
		return [(_("Now/Next Whitelist"), WhitelistMain, "NowNext_whitelist", 10001)]
	return []


def WhitelistMain(session, **kwargs):
	session.open(Editor, WHITELIST)


def Plugins(**kwargs):
	plist = []
	plist.append(PluginDescriptor(name=_("Now/Next Whitelist"), description="", where=PluginDescriptor.WHERE_MENU, fnc=WhitelistStart))
	plist.append(PluginDescriptor(name=_("Now/Next Blacklist"), description="", where=PluginDescriptor.WHERE_MENU, fnc=BlacklistStart))
	return plist
