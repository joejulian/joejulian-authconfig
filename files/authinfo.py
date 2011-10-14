# -*- coding: UTF-8 -*-
#
# Authconfig - client authentication configuration program
# Copyright (c) 1999-2008 Red Hat, Inc.
#
# Authors: Preston Brown <pbrown@redhat.com>
#          Nalin Dahyabhai <nalin@redhat.com>
#          Matt Wilson <msw@redhat.com>
#          Tomas Mraz <tmraz@redhat.com>
#
# This is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

import sys
sys.path.insert(0, "/usr/share/authconfig")

import string
import os
import copy
import fcntl
import socket
import select
import signal
import stat
import shvfile
import dnsclient
import sys
import errno
import urllib2
import time
import simplejson
from subprocess import *
import acutil
import gettext
_ = gettext.lgettext

SYSCONFDIR = "/etc"
AUTH_PAM_SERVICE = "system-auth"
AUTH_PAM_SERVICE_AC = "system-auth-ac"

if "lib64" in str(globals()["acutil"]):
	LIBDIR = "/lib64"
else:
	LIBDIR = "/lib"	

AUTH_MODULE_DIR = LIBDIR + "/security"

PATH_PORTMAP = "/sbin/portmap"
PATH_PWCONV = "/usr/sbin/pwconv"
PATH_NSCD = "/usr/sbin/nscd"
PATH_NSCD_PID = "/var/run/nscd/nscd.pid"
PATH_DBBIND = "/usr/sbin/dbbind"
PATH_DBBIND_PID = "/var/run/dbbind.pid"
PATH_DBIBIND = "/usr/sbin/dbibind"
PATH_DBIBIND_PID = "/var/run/dbibind.pid"
PATH_HESIODBIND = "/usr/sbin/hesiodbind"
PATH_HESIODBIND_PID = "/var/run/hesiodbind.pid"
PATH_LDAPBIND = "/usr/sbin/ldapbind"
PATH_LDAPBIND_PID = "/var/run/ldapbind.pid"
PATH_ODBCBIND = "/usr/sbin/odbcbind"
PATH_ODBCBIND_PID = "/var/run/odbcbind.pid"
PATH_WINBIND = "/usr/sbin/winbindd"
PATH_WINBIND_PID = "/var/run/winbindd.pid"
PATH_YPBIND = "/sbin/ypbind"
PATH_YPBIND_PID = "/var/run/ypbind.pid"
PATH_SEBOOL = "/usr/sbin/setsebool"
PATH_SCEVENTD = "/usr/bin/pkcs11_eventmgr"
PATH_SCEVENTD_PID = "/var/run/sceventd.pid"
PATH_SCSETUP = "/usr/bin/pkcs11_setup"

PATH_LIBNSS_DB = LIBDIR + "/libnss_db.so.2"
PATH_LIBNSS_LDAP = LIBDIR + "/libnss_ldap.so.2"
PATH_LIBNSS_NIS = LIBDIR + "/libnss_nis.so.2"
PATH_LIBNSS_HESIOD = LIBDIR + "/libnss_hesiod.so.2"
PATH_LIBNSS_ODBCBIND = LIBDIR + "/libnss_odbcbind.so.2"
PATH_LIBNSS_WINBIND = LIBDIR + "/libnss_winbind.so.2"
PATH_LIBNSS_WINS = LIBDIR + "/libnss_wins.so.2"

PATH_PAM_KRB5 = AUTH_MODULE_DIR + "/pam_krb5.so"
PATH_PAM_LDAP = AUTH_MODULE_DIR + "/pam_ldap.so"
PATH_PAM_SMB = AUTH_MODULE_DIR + "/pam_smb_auth.so"
PATH_PAM_WINBIND = AUTH_MODULE_DIR + "/pam_winbind.so"
PATH_PAM_PKCS11 = AUTH_MODULE_DIR + "/pam_pkcs11.so"

PATH_WINBIND_NET = "/usr/bin/net"

PATH_LDAP_CACERTS = "/etc/openldap/cacerts"
LDAP_CACERT_DOWNLOADED = "authconfig_downloaded.pem"

LOGIC_REQUIRED = "required"
LOGIC_REQUISITE	= "requisite"
LOGIC_SUFFICIENT = "sufficient"
LOGIC_OPTIONAL = "optional"
LOGIC_IGNORE_UNKNOWN = "[default=bad success=ok user_unknown=ignore]"
LOGIC_IGNORE_AUTH_ERR = "[default=bad success=ok auth_err=ignore user_unknown=ignore ignore=ignore]"
LOGIC_PKCS11 = "[success=done authinfo_unavail=ignore ignore=ignore default=die]"
LOGIC_FORCE_PKCS11 = "[success=done ignore=ignore default=die]"
LOGIC_PKCS11_KRB5 = "[success=ok authinfo_unavail=2 ignore=2 default=die]"
LOGIC_FORCE_PKCS11_KRB5 = "[success=ok ignore=2 default=die]"
LOGIC_SKIPNEXT = "[success=1 default=ignore]"
LOGIC_SKIPNEXT3 = "[success=3 default=ignore]"

# Snip off line terminators and final whitespace from a passed-in string.
def snipString(s):
	return s.split("\n",1)[0].rstrip()

# Make a list presentable.
def cleanList(lst):
	s = lst.replace("\t"," ")
	return ",".join(filter(None, s.split(" ")))

def matchKey(line, key):
	if line.startswith(key):
		# Skip intervening whitespace.
		return line[len(key):].lstrip()
	else:
		return False

def matchKeyEquals(line, key):
	if line.startswith(key):
		# Skip intervening whitespace.
		return line[len(key):].lstrip(string.whitespace+"=")
	else:
		return False

def matchLine(line, key):
	return line.startswith(key)

def matchLineI(line, key):
	return line.lower().startswith(key.lower())
				
def commaAppend(lst, value):
	if lst:
		return lst + "," + value
	else:
		return value
def stringsDiffer(a, b, case_sensitive):
	if not a and not b:
		return False
	if not a or not b:
		return True
	if case_sensitive:
		return a != b
	else:
		return a.lower() != b.lower()

# Check for a string in an nss configuration line.
def checkNSS(configuration, candidate):
	lst = configuration.split(":",1)
	if len(lst) > 1:
		configuration = lst[1]
	start = 0
	clen = len(candidate)
	while True:
		start = configuration.find(candidate, start)
		if start < 0:
			return None
		if start > 0 and configuration[start-1].isalnum():
			start += clen
			continue
		if start+clen < len(configuration) and configuration[start+clen].isalnum():
			start += clen
			continue
		return start
	return None

def openLocked(filename, perms):
	fd = -1
	try:
		fd = os.open(filename, os.O_RDWR | os.O_CREAT, perms)
		
		fcntl.lockf(fd, fcntl.LOCK_EX)
	except OSError, (errno, strerr):
		if fd != -1:
			try:
				os.close(fd)
			except OSError:
				pass
		raise IOError(errno, strerr)
	return os.fdopen(fd, "r+")

def krbKdc(kdclist):
	output = ""
	kdclist = kdclist.split(",")
	for kdc in kdclist:
		if kdc:
			output += "  kdc = " + kdc + "\n"
	return output

def krbAdminServer(adminservers):
	output = ""
	adminservers = adminservers.split(",")
	for adminserver in adminservers:
		if adminserver:
			output += "  admin_server = "
			output += adminserver + "\n"
	return output

def krbRealm(realm, kdclist, adminservers):
	output = ""
	if realm:
		output += " " + realm + " = {\n"
		output += krbKdc(kdclist)
		output += krbAdminServer(adminservers)
		output += " }\n\n"
	return output

# Compare two strings, one a possible data line, the other a Samba-style key
# name.  Returns False on non-match, value of the key if matched.
def matchLineSMB(line, key):
	linelst = line.split("=", 1)
	if len(linelst) < 2:
		param = ""
	else:
		param = linelst[1]

	linelst = linelst[0].lower().split(None)	
	keylst = key.lower().split(None)
	# Compare the lists
	if keylst == linelst:
		return param.lstrip(string.whitespace+"=")
	return False

# Mandatory arguments for the various modules.
argv_unix_auth = [
	"try_first_pass"
]

argv_unix_password = [
	"try_first_pass",
	"use_authtok"
]

argv_afs_auth = [
	"use_first_pass"
]

argv_afs_password = [
	# It looks like current pam_afs (from OpenAFS 1.1.1) doesn't support
	# "use_authtok", so it'll probably interact badly with pam_cracklib,
	# but thanks to stack-traversal changes in Linux-PAM 0.75 and higher,
	# the password-changing should work anyway.
	"use_first_pass"
]

argv_cracklib_password = [
	"try_first_pass",
	"retry=3",
	"type="
]

argv_passwdqc_password = [
	"enforce=users"
]

argv_eps_auth = [
	"use_first_pass"
]

argv_eps_password = [
	"use_authtok"
]

argv_pkcs11_auth = [
]

argv_force_pkcs11_auth = [
	"wait_for_card"
]

argv_krb5_auth = [
	"use_first_pass"
]

argv_krb5_sc_auth = [
	"use_first_pass",
	"no_subsequent_prompt"
]

argv_krb5_password = [
	"use_authtok"
]

argv_ldap_auth = [
	"use_first_pass"
]

argv_ldap_password = [
	"use_authtok"
]

# This probably won't work straight-off because pam_unix won't give the right
# challenge, but what the heck.
argv_otp_auth = [
	"use_first_pass"
]

argv_smb_auth = [
	"use_first_pass",	
	"nolocal"
]

argv_succeed_if_auth = [
	"uid >= 500",
	"quiet"
]

argv_succeed_if_account = [
	"uid < 500",
	"quiet"
]

argv_succeed_if_session = [
	"service in crond",
	"quiet",
	"use_uid"
]

argv_succeed_if_nonlogin = [
	"service notin login:gdm:xdm:kdm:xscreensaver:gnome-screensaver:kscreensaver",
	"quiet",
	"use_uid"
]

argv_winbind_auth = [
	"use_first_pass"
]

argv_winbind_password = [
	"use_authtok"
]

argv_keyinit_session = [
	"revoke"
]

# Password hashing algorithms.
password_algorithms = ["descrypt", "bigcrypt", "md5", "sha256", "sha512"]

# Enumerations for PAM control flags and stack names.
AUTH = 0
ACCOUNT = 1
SESSION = 2
PASSWORD = 3

pam_stacks = ["auth", "account", "session", "password"]

MANDATORY = 0
STACK = 1
LOGIC = 2
NAME = 3
ARGV = 4

# The list of stacks, module flags, and arguments, if there are any.
# [ MANDATORY, STACK, LOGIC, NAME, ARGV ]
standard_pam_modules = [
	[True,  AUTH,		LOGIC_REQUIRED,
	 "env",			[]],
	[False,  AUTH,          LOGIC_SKIPNEXT,
	 "succeed_if",		argv_succeed_if_nonlogin],
	[False,  AUTH,          LOGIC_PKCS11,
	 "pkcs11",		argv_pkcs11_auth],
	[False, AUTH,		LOGIC_OPTIONAL,
	 "krb5",		argv_krb5_sc_auth],
	[False, AUTH,		LOGIC_SUFFICIENT,
	 "permit",		[]],
	[True,  AUTH,		LOGIC_SUFFICIENT,
	 "unix",		argv_unix_auth],
	[False, AUTH,		LOGIC_REQUISITE,
	 "succeed_if",		argv_succeed_if_auth],
	[False, AUTH,		LOGIC_SUFFICIENT,
	 "afs",			argv_afs_auth],
	[False, AUTH,		LOGIC_SUFFICIENT,
	 "afs.krb",		argv_afs_auth],
	[False, AUTH,		LOGIC_SUFFICIENT,
	 "eps_auth",		argv_eps_auth],
	[False, AUTH,		LOGIC_SUFFICIENT,
	 "krb5",		argv_krb5_auth],
	[False, AUTH,		LOGIC_SUFFICIENT,
	 "ldap",		argv_ldap_auth],
	[False, AUTH,		LOGIC_SUFFICIENT,
	 "otp",			argv_otp_auth],
	[False, AUTH,		LOGIC_SUFFICIENT,
	 "smb_auth",		argv_smb_auth],
	[False, AUTH,		LOGIC_SUFFICIENT,
	 "winbind",		argv_winbind_auth],
	[True,  AUTH,		LOGIC_REQUIRED,
	 "deny",		[]],

# Account management is tricky.  Because we've implicitly committed to
# getting it "right" for any combination of nss and pam, we have to be
# careful about how we handle cases where networked sources of information
# are unavailable.
# At the very least, proper handling of password expiration depends on
# this, and in the case of pam_ldap, we also may be depending on the
# directory server for actual "is allowed to log in on this host" data.
# The frequently-suggested method of using pam_localuser to short-circuit
# pam_ldap may be only optional, but we can use pam_succeed_if 
# to short-circuit any network checks for *system* accounts
# without allowing actual users in who should be legitimately denied by
# LDAP (if not overriden by enabling the optional pam_localuser).
# Because we'd now be ending the stack with sufficient modules, and PAM's
# behavior isn't defined if none of them return success, we add a
# successful call to pam_permit at the end as a requirement.
	[False, ACCOUNT,	LOGIC_REQUIRED,
	 "access",		[]],
	[True,  ACCOUNT,	LOGIC_REQUIRED,
	 "unix",		[]],
	[False,  ACCOUNT,	LOGIC_SUFFICIENT,
	 "localuser",		[]],
	[True,  ACCOUNT,	LOGIC_SUFFICIENT,
	 "succeed_if",		argv_succeed_if_account],
	[False, ACCOUNT,	LOGIC_IGNORE_UNKNOWN,
	 "ldap",		[]],
	[False, ACCOUNT,	LOGIC_IGNORE_UNKNOWN,
	 "krb5",		[]],
	[False, ACCOUNT,	LOGIC_IGNORE_UNKNOWN,
	 "winbind",		[]],
	[True,  ACCOUNT,	LOGIC_REQUIRED,
	 "permit",		[]],

	[False,  PASSWORD,	LOGIC_OPTIONAL,
	 "pkcs11",		[]],
	[False,  PASSWORD,	LOGIC_REQUISITE,
	 "cracklib",		argv_cracklib_password],
	[False,  PASSWORD,	LOGIC_REQUISITE,
	 "passwdqc",		argv_passwdqc_password],
	[True,  PASSWORD,	LOGIC_SUFFICIENT,
	 "unix",		argv_unix_password],
	[False, PASSWORD,	LOGIC_SUFFICIENT,
	 "afs",			argv_afs_password],
	[False, PASSWORD,	LOGIC_SUFFICIENT,
	 "afs.krb",		argv_afs_password],
	[False, PASSWORD,	LOGIC_SUFFICIENT,
	 "eps_passwd",		argv_eps_password],
	[False, PASSWORD,	LOGIC_SUFFICIENT,
	 "krb5",		argv_krb5_password],
	[False, PASSWORD,	LOGIC_SUFFICIENT,
	 "ldap",		argv_ldap_password],
	[False, PASSWORD,	LOGIC_SUFFICIENT,
	 "winbind",		argv_winbind_password],
	[True,  PASSWORD,	LOGIC_REQUIRED,
	 "deny",		[]],

	[True,  SESSION,	LOGIC_OPTIONAL,
	 "keyinit",		argv_keyinit_session],
	[True,  SESSION,	LOGIC_REQUIRED,
	 "limits",		[]],
	[False, SESSION,	LOGIC_OPTIONAL,
	 "mkhomedir",		[]],
	[True,  SESSION,	LOGIC_SKIPNEXT,
	 "succeed_if",		argv_succeed_if_session],
	[True,  SESSION,	LOGIC_REQUIRED,
	 "unix",		[]],
	[False, SESSION,	LOGIC_OPTIONAL,
	 "afs",			[]],
	[False, SESSION,	LOGIC_OPTIONAL,
	 "afs.krb",		[]],
	[False, SESSION,	LOGIC_OPTIONAL,
	 "krb5",		[]],
	[False, SESSION,	LOGIC_OPTIONAL,
	 "ldap",		[]],
]

def domain2dn(domain):
	output = "DC="
	domain = domain.rstrip(".")
	output += domain.replace(".", ",DC=")
	return output

DEFAULT_DNS_QUERY_SIZE = 1024

def toggleCachingService(enableCaching, nostart):
	if not nostart:
		if enableCaching:
			os.system("/sbin/service nscd restart")
		else:
			try:
				os.stat(PATH_NSCD_PID)
				os.system("/sbin/service nscd stop")
			except OSError:
				pass
	return True

def toggleNisService(enableNis, nisDomain, nostart):
	if enableNis and nisDomain:
		os.system("/bin/domainname " + nisDomain)
		try:
			os.stat(PATH_PORTMAP)
			os.system("/sbin/chkconfig --add portmap")
			os.system("/sbin/chkconfig --level 345 portmap on")
			if not nostart:
				os.system("/sbin/service portmap restart")
		except OSError:
			pass
		try:
			os.stat(PATH_YPBIND)
			os.system("/sbin/chkconfig --add ypbind")
			os.system("/sbin/chkconfig --level 345 ypbind on")
			if not nostart:
				try:
					os.stat(PATH_YPBIND_PID)
					os.system("/sbin/service ypbind restart")
				except OSError:
					os.system("/sbin/service ypbind start")
		except OSError:
			pass
	else:
		os.system("/bin/domainname \"(none)\"")
		try:
			os.stat(PATH_YPBIND)
			if not nostart:
				try:
					os.stat(PATH_YPBIND_PID)
					os.system("/sbin/service ypbind stop")
				except OSError:
					pass
			os.system("/sbin/chkconfig --level 345 ypbind off")
		except OSError:
			pass
	return True

def toggleSplatbindService(enable, path, pidfile, name, nostart):
	if enable:
		try:
			os.stat(path)
			os.system("/sbin/chkconfig --add " + name)
			os.system("/sbin/chkconfig --level 345 " + name + " on")
			if not nostart:
				os.system("/sbin/service " + name +" restart")
		except OSError:
			pass
	else:
		try:
			os.stat(path)
			if not nostart:
				try:
					os.stat(pidfile)
					os.system("/sbin/service " + name +" stop")
				except OSError:
					pass
			
			os.system("/sbin/chkconfig --level 345 " + name + " off")
		except OSError:
			pass
	return True

def formatBool(val):
	if val:
		return "enabled"
	else:
		return "disabled"

def feedFork(command, echo, query, response):
	try:
		(pid, master) = os.forkpty()
	except OSError:
		return
	if not pid:
		# child
		os.system(command)
		os._exit(0)
	output = ""
	try:
		i = fcntl.fcntl(master, fcntl.F_GETFL)
		fcntl.fcntl(master, fcntl.F_SETFL, i & ~os.O_NONBLOCK)
	except IOError:
		pass
		
	eof = False
	while not eof:
		try:
			ifds = []
			efds = []
			(ifds,ofds,efds) = select.select([master],[],[master], 60)
		except select.error, (err, text):
			sys.stderr.write("select: " + text + "\n")
		if not ifds and not efds:
			# timeout or error
			os.close(master)
			eof = True
			continue
		c = ""
		try:
			c = os.read(master, 1)
		except OSError, (err, text):
			if err == errno.EINTR or err == errno.EAGAIN:
				pass
			elif err == errno.EIO:
				os.close(master)
				eof = True
			else:
				sys.stderr.write("read: " + text + "\n")
				os.close(master)
				eof = True
			continue
		if c:
			try:
				output += c
				if echo:
					sys.stderr.write(c)
				if query in output:
					os.write(master, response)
					os.write(master, "\r\n")
					output = ""
					sys.stderr.write("<...>\n")
			except OSError, (err, text):
				sys.stderr.write("write: " + text + "\n")				
				os.close(master)
				eof = True
		else:
			os.close(master)
			eof = True			
	try:
		os.kill(pid, signal.SIGTERM)
	except OSError:
		pass
	try:
		(child, status) = os.waitpid(pid, 0)
	except OSError, (err, text):
		sys.stderr.write("waitpid: " + text + "\n")

def isEmptyDir(path):
	try:
		lst = os.listdir(path)
	except OSError:
		# we don't know but return True anyway
		return True
	
	for filename in lst:
		try:
			st = os.stat(path + "/" + filename)
			if stat.S_ISREG(st.st_mode):
				return False
		except OSError:
			pass
	return True

def callPKCS11Setup(options):
	try:
		child = Popen([PATH_SCSETUP] + options, stdout=PIPE)
		lst = child.communicate()[0].split("\n")
		if child.returncode != 0:
			return None
		if lst[-1] == '':
			del lst[-1:]
	except OSError:
		return None
	return lst		

def getSmartcardModules():
	mods = callPKCS11Setup(["list_modules"])
	if mods == None:
		return []
	return mods

def getSmartcardActions():
	return [_("Lock"), _("Ignore")]
		
def read(msgcb):
	info = AuthInfo(msgcb)
	info.read()
	return info

class SaveGroup:
	def __init__(self, savefunc, attrlist):
		self.saveFunction = savefunc
		self.attrlist = attrlist

	def attrsDiffer(self, a, b):
		ret = False
		for (aname, atype) in self.attrlist:
			if atype == "b":
				ret = ret or getattr(a, aname) != getattr(b, aname)
			elif atype == "c":
				ret = ret or stringsDiffer(getattr(a, aname), getattr(b, aname), True)
			elif atype == "i":
				ret = ret or stringsDiffer(getattr(a, aname), getattr(b, aname), False)
		return ret

class AuthInfo:
	def __init__(self, msgcb):
		self.messageCB = msgcb

		# Service-specific settings.
		self.hesiodLHS = ""
		self.hesiodRHS = ""
  
		self.ldapServer = ""
		self.ldapBaseDN = ""

		self.kerberosRealm = ""
		self.kerberosRealmviaDNS = None
		self.kerberosKDC = ""
		self.kerberosKDCviaDNS = None
		self.kerberosAdminServer = ""

		self.nisServer = ""
		self.nisDomain = ""
		self.nisLocalDomain = ""

		self.smbWorkgroup = ""
		self.smbRealm = ""
		self.smbServers = ""
		self.smbSecurity = ""
		self.smbIdmapUid = ""
		self.smbIdmapGid = ""

		self.winbindSeparator = ""
		self.winbindTemplateHomedir = ""
		self.winbindTemplatePrimaryGroup = ""
		self.winbindTemplateShell = ""
		self.winbindUseDefaultDomain = None
		self.winbindOffline = None
		
		self.smartcardModule = ""
		self.smartcardAction = ""

		# NSSwitch setup.  Files is always in there.
		self.enableCache = None
		self.enableCompat = None
		self.enableDB = None
		self.enableDirectories = None
		self.enableHesiod = None
		self.enableLDAP = None
		self.enableLDAPS = None
		self.enableNIS = None
		self.enableNIS3 = None
		self.enableDBbind = None
		self.enableDBIbind = None
		self.enableHesiodbind = None
		self.enableLDAPbind = None
		self.enableOdbcbind = None
		self.enableWinbind = None
		self.enableWINS = None
		self.preferDNSinHosts = None

		# Authentication setup.
		self.enableAFS = None
		self.enableAFSKerberos = None
		self.enableNullOk = True
		self.enableCracklib = None
		self.enableEPS = None
		self.enableKerberos = None
		self.enableLDAPAuth = None
		self.passwordAlgorithm = ""
		self.algoRounds = ""
		self.enableOTP = None
		self.enablePasswdQC = None
		self.enableShadow = None
		self.enableSMB = None
		self.enableWinbindAuth = None
		self.enableLocAuthorize = None
		self.enablePAMAccess = None
		self.enableSysNetAuth = None
		self.enableMkHomeDir = None
		self.enableSmartcard = None

		self.brokenShadow = None
		self.forceBrokenShadow = None
		self.forceSmartcard = None

		# Not really options.
		self.joinUser = ""
		self.joinPassword = ""
		self.cracklibArgs = ""
		self.passwdqcArgs = ""
		self.localuserArgs = ""
		self.pamAccessArgs = ""
		self.mkhomedirArgs = ""
		self.ldapCacertDir = ""
		self.ldapCacertURL = ""
		
	# Read hesiod setup.  Luckily, /etc/hesiod.conf is simple enough that shvfile
	# can read it just fine.
	def readHesiod(self):
		# Open the file.  Bail if it's not there.
		try:
			shv = shvfile.read(SYSCONFDIR+"/hesiod.conf")
		except IOError:
			return False
	
		# Read the LHS.
		self.hesiodLHS = snipString(shv.getValue("lhs"))

		# Read the RHS.
		self.hesiodRHS = snipString(shv.getValue("rhs"))
		
		shv.close()
		return True

	# Read SMB setup from /etc/pam_smb.conf.
	def readSMB(self):
		# Open the file.  Bail if it's not there or there's some problem
	 	# reading it.
		try:
			f = open(SYSCONFDIR+"/pam_smb.conf", "r")
		except IOError:
			return False

		# Read three lines.  The first is the workgroup, and subsequent
	 	# lines are the PDC and BDC, respectively.
		self.smbWorkgroup = snipString(f.readline())
		servers = f.readlines()
		servers = map(snipString, servers)
		self.smbServers = ",".join(filter(None, servers))

		f.close()
		return True

	# Read NIS setup from /etc/yp.conf.
	def readNIS(self):
		# Open the file.  Bail if it's not there or there's some problem
	 	# reading it.
		try:
			f = open(SYSCONFDIR+"/yp.conf", "r")
		except IOError:
			return False
		
		for line in f:
			line = line.strip()

			# Is it a "ypserver" statement?  If so, extract the server.
			value = matchKey(line, "ypserver")
			if value and self.nisLocalDomain:
				# Save the server's name.
				self.nisServer = commaAppend(self.nisServer, value)
				continue

			# It had better be a "domain" statement, because the man page
		 	# for this file states that this is all there is.
			value = matchKey(line, "domain")
			if value:
				# Save the domain's name.  To do that, find its end.
				value = value.split(None, 1)
				if len(value) < 1:
					continue
				if value[0] != self.nisLocalDomain:
					continue
				if len(value) < 2:
					continue
				value = value[1]

				# Is it "server"?  If not, assume "broadcast".
				value = matchKey(value, "server")
				if value:
					self.nisServer = commaAppend(self.nisServer, value)

		f.close()
		return True

	def ldapHostsToURIs(self, s):
		l = s.split(",")
		ret = ""
		for item in l:
			if item:
				if ret:
					ret += ","
				if "://" in item:
					ret += item
				else:
					ret += "ldap://" + item + "/"
		return ret

	# Read LDAP setup from /etc/ldap.conf.
	def readLDAP(self):
		self.ldapCacertDir = PATH_LDAP_CACERTS
		self.ldapServer = ""
		# Open the file.  Bail if it's not there or there's some problem
	 	# reading it.
		try:
			f = open(SYSCONFDIR+"/ldap.conf", "r")
		except IOError:
			return False
	
		for line in f:
			line = line.strip()

			# Is it a "base" statement?
			value = matchKey(line, "base")
			if value:
				# Save the base DN.
				self.ldapBaseDN = value
				continue
			# Is it a "host" statement?
			value = matchKey(line, "host")
			if value:
				# Save the host name or IP.
				self.ldapServer += value
				continue
			# Is it a "uri" statement?
			value = matchKey(line, "uri")
			if value:
				# Save the host name or IP.
				self.ldapServer += value
				continue
			# Is it a "ssl" statement?
			value = matchKey(line, "ssl")
			if value:
				self.enableLDAPS = matchLine(value, "start_tls")
				continue
			# We'll pull MD5/DES crypt ("pam_password") from the config
		 	# file, or from the pam_unix PAM config lines.

		self.ldapServer = self.ldapHostsToURIs(cleanList(self.ldapServer))
		f.close()
		return True

	# Read Kerberos setup from /etc/krb5.conf.
	def getKerberosKDC(self, realm):
		try:
			return self.allKerberosKDCs[realm]
		except KeyError:
			return ""

	def getKerberosAdminServer(self, realm):
		try:
			return self.allKerberosAdminServers[realm]
		except KeyError:
			return ""

	def readKerberos(self):
		section = ""
		self.allKerberosKDCs = {}
		self.allKerberosAdminServers = {}		
		# Open the file.  Bail if it's not there or there's some problem
	 	# reading it.
		try:
			f = open(SYSCONFDIR+"/krb5.conf", "r")
		except IOError:
			return False
	
		for line in f:
			line = line.strip()

			# If it's a new section, note which one we're "in".
			if line[0:1] == "[":
				section = line[1:-1]
				subsection = ""
				continue;

			if section == "libdefaults":
				# Check for the default realm setting.
				value = matchKeyEquals(line, "default_realm")
				if value:
					self.kerberosRealm = value
					continue;
				# Check for the DNS settings.
				value = matchKeyEquals(line, "dns_lookup_kdc")
				if value:
					self.kerberosKDCviaDNS = matchKey(value, "true") == ""
					continue
				value = matchKeyEquals(line, "dns_lookup_realm")
				if value:
					self.kerberosRealmviaDNS = matchKey(value, "true") == ""
					continue;

			elif section == "realms":
				if not subsection:
					# Read the name of the realm.
					value = line.split(None,1)
					if len(value) < 1:
						continue
					subsection = value[0]
				# Check for the end of a realm section.
				else:
					if line[0:1] == "}":
						subsection = ""
						continue
					if not self.kerberosRealm:
						self.kerberosRealm = subsection
					# See if this is a key we care about.
					value = matchKeyEquals(line, "kdc")
					if value:
						self.allKerberosKDCs[subsection] = commaAppend(self.getKerberosKDC(subsection), value)
						continue					
					value = matchKeyEquals(line, "admin_server")
					if value:
						self.allKerberosAdminServers[subsection] = commaAppend(self.getKerberosAdminServer(subsection), value)
		if self.kerberosRealm:
			self.kerberosKDC = self.getKerberosKDC(self.kerberosRealm)
			self.kerberosAdminServer = self.getKerberosAdminServer(self.kerberosRealm)
		f.close()
		return True

	def readSmartcard(self):
		lock = False
		self.smartcardModule = callPKCS11Setup(["use_module"])
		if self.smartcardModule == None:
			return False
		self.smartcardModule = self.smartcardModule[0]
   		rmactions = callPKCS11Setup(["rm_action"])
   		if rmactions == None:
   			return False
   		for action in rmactions:
   			if "lockhelper.sh" in action:
   				lock = True
   		if lock:
   			self.smartcardAction = _("Lock")
   		else:
   			self.smartcardAction = _("Ignore")
   		return True
   		
	# Read Samba setup from /etc/samba/smb.conf.
	def readWinbindGlobal(self, key):
		result = ""
		section = ""
		# Open the file.  Bail if it's not there or there's some problem
	 	# reading it.
		try:
			f = open(SYSCONFDIR+"/samba/smb.conf", "r")
		except IOError:
			return result

		for line in f:
			line = line.strip()
			# Skip comments.
			if matchLine(line, "#"):
				continue
			if matchLine(line, ";"):
				continue
			# If it's a new section, note which one we're "in".
			value = matchKey(line, "[")
			if value:
				section = value.split("]")[0].lower()
				continue
			# Check for global settings.  Anything else we can skip.
			if not section or section != "global":
				continue
			# Check for a match with the requested setting name.
			res = matchLineSMB(line, key)
			if res:
				result = res
		f.close()
		return result
	
	def readWinbindGlobalBool(self, key):
		tmp = self.readWinbindGlobal(key)
		if tmp:
			if tmp.lower() == "yes" or tmp.lower() == "true" or tmp == "1":
				return True
			else:
				return False
		return None

	# Read winbind settings from /etc/smb/samba.conf.
	def readWinbind(self):
		tmp = self.readWinbindGlobal("workgroup")
		if tmp:
			self.smbWorkgroup = tmp

		tmp = self.readWinbindGlobal("password server")
		if tmp:
			self.smbServers = tmp
		tmp = self.readWinbindGlobal("realm")
		if tmp:
			self.smbRealm = tmp
		tmp = self.readWinbindGlobal("security")
		if tmp:
			self.smbSecurity = tmp
		if not self.smbSecurity:
			self.smbSecurity = "user"
		tmp = self.readWinbindGlobal("idmap uid")
		if tmp:
			self.smbIdmapUid = tmp
		if not self.smbIdmapUid:
			# 2^24 to 2^25 - 1 should be safe
			self.smbIdmapUid = "16777216-33554431"
		tmp = self.readWinbindGlobal("idmap gid")
		if tmp:
			self.smbIdmapGid = tmp

		if not self.smbIdmapGid:
			# 2^24 to 2^25 - 1 should be safe
			self.smbIdmapGid = "16777216-33554431"
		tmp = self.readWinbindGlobal("winbind separator")
		if tmp:
			self.winbindSeparator = tmp
		tmp = self.readWinbindGlobal("template homedir")
		if tmp:
			self.winbindTemplateHomedir = tmp
		tmp = self.readWinbindGlobal("template primary group")
		if tmp:
			self.winbindTemplatePrimaryGroup = tmp
		tmp = self.readWinbindGlobal("template shell")
		if tmp:
			self.winbindTemplateShell = tmp
		if not self.winbindTemplateShell:
			self.winbindTemplateShell = "/bin/false"
		tmp = self.readWinbindGlobalBool("winbind use default domain")
		if tmp != None:
			self.winbindUseDefaultDomain = tmp
		tmp = self.readWinbindGlobalBool("winbind offline logon")
		if tmp != None:
			self.winbindOffline = tmp

		return True

	# Read NSS setup from /etc/nsswitch.conf.
	def readNSS(self):
		# Open the file.  Bail if it's not there or there's some problem
	 	# reading it.
		nssconfig = ""
		try:
			f = open(SYSCONFDIR+"/nsswitch.conf", "r")
		except IOError:
			return False

		for line in f:
			line = line.strip()
			
			value = matchKey(line, "passwd:")
			if value:
				nssconfig = value
			else:
				# wins can be found in hosts only
				value = matchKey(line, "hosts:")
				if value:
					self.enableWINS = bool(checkNSS(value, "wins"))

					nispos = checkNSS(value, "nis")
					if nispos == None:
						nispos = checkNSS(value, "wins")
					dnspos = checkNSS(value, "dns")
					if nispos != None and dnspos != None:
						self.preferDNSinHosts = dnspos < nispos

		if nssconfig:
			self.enableCompat = bool(checkNSS(nssconfig, "compat"))
			self.enableDB = bool(checkNSS(nssconfig, "db"))
			self.enableDirectories = bool(checkNSS(nssconfig,
							   "directories"))
			self.enableHesiod = bool(checkNSS(nssconfig, "hesiod"))
			self.enableLDAP = bool(checkNSS(nssconfig, "ldap"))
			self.enableNIS = bool(checkNSS(nssconfig, "nis"))
			self.enableNIS3 = bool(checkNSS(nssconfig, "nisplus"))
			self.enableWinbind = bool(checkNSS(nssconfig, "winbind"))
		f.close()
		return True

	# Read whether or not caching is enabled.
	def readCache(self):
		rv = os.system("/sbin/chkconfig nscd >/dev/null 2>&1")
		self.enableCache = os.WIFEXITED(rv) and os.WEXITSTATUS(rv) == 0
		return True

	# Read hints from the PAM control file.
	def readPAM(self):
		# Open the file.  Bail if it's not there or there's some problem
	 	# reading it.
		try:
			f = open(SYSCONFDIR+"/pam.d/"+AUTH_PAM_SERVICE_AC, "r")
		except IOError:
			try:
				f = open(SYSCONFDIR+"/pam.d/"+AUTH_PAM_SERVICE, "r")
			except IOError:
				return False

		prevline = ""
		for line in f:
			lst = line.split("#", 1)
			if len(lst) > 1:
				line = lst[0]
				
			line = line.rstrip()
			# Join lines ending with "\\"
			if line[-1:] == "\\":
				prevline += line[:-1] + " "
				continue
			line = prevline + line
			prevline = ""
			line = line.lstrip()
			
			args = ""

			lst = line.split(None, 1)
			if len(lst) < 2:
				continue
			(stack, line) = lst

			if (stack != "auth" and stack != "account"
				and stack != "password" and stack != "session"):
				continue

			if line.startswith("["):
				lst = line.split("]", 1)
			else:
				lst = line.split(None, 1)

			if len(lst) < 2:
				continue
			
			if lst[0] == "include":
				continue
				
			control = lst[0]
			if control.startswith("["):
				control += "]"

			line = lst[1]

			lst = line.split(None, 1)
			
			if len(lst) < 1:
				continue
			(module,) = lst[0].split("/")[-1:]

			if len(lst) == 2:
				args = lst[1]
			
			if module.startswith("pam_cracklib"):
				self.enableCracklib = True
				if args:
					self.cracklibArgs = args
				continue
			if module.startswith("pam_krb5"):
				self.enableKerberos = True
				continue
			if module.startswith("pam_ldap"):
				self.enableLDAPAuth = True
				continue
			if module.startswith("pam_pkcs11"):
				self.enableSmartcard = True
				if control == LOGIC_FORCE_PKCS11:
					self.forceSmartcard = True
				else:
					self.forceSmartcard = False
				continue
			if module.startswith("pam_passwdqc"):
				self.enablePasswdQC = True
				if args:
					self.passwdqcArgs = args
				continue
			if module.startswith("pam_smb"):
				self.enableSMB = True
				continue
			if module.startswith("pam_winbind"):
				self.enableWinbindAuth = True
				continue
			if module.startswith("pam_access"):
				self.enablePAMAccess = True
				if args:
					self.pamAccessArgs = args
				continue
			if module.startswith("pam_mkhomedir"):
				self.enableMkHomeDir = True
				if args:
					self.mkhomedirArgs = args
				continue
			if module.startswith("pam_localuser"):
				self.enableLocAuthorize = True
				if args:
					self.localuserArgs = args
				continue
			if stack == "password":
				if module.startswith("pam_unix"):
					for algo in password_algorithms:
						if args.find(algo) >= 0:
							self.passwordAlgorithm = algo
					try:
						ridx = args.index("rounds=")
						rounds = args[ridx+7:].split(None,1)
						self.algoRounds = str(int(rounds[0]))
					except (ValueError, IndexError):
						pass
					try:
						os.stat("/etc/shadow")
						self.enableShadow = True
					except OSError:
						self.enableShadow = False
			if stack == "auth":
				if module.startswith("pam_unix"):
					self.enableNullOk = args.find("nullok") >= 0
			if stack == "account":
				if module.startswith("pam_unix"):
					self.brokenShadow = args.find("broken_shadow") >= 0

		f.close()

		# Read settings from our config file, which override anything we
		# figure out by examination.
		# Open the file.  Bail if it's not there.
		try:
			shv = shvfile.read(SYSCONFDIR+"/sysconfig/authconfig")

			try:
				self.enableAFS = shv.getBoolValue("USEAFS")
			except ValueError:
				pass
			try:
				self.enableAFSKerberos = shv.getBoolValue("USEAFSKERBEROS")
			except ValueError:
				pass
			try:
				self.enableDB = shv.getBoolValue("USEDB")
			except ValueError:
				pass
			try:
				self.enableCracklib = shv.getBoolValue("USECRACKLIB")
			except ValueError:
				pass
			try:
				self.enableDBbind = shv.getBoolValue("USEDBBIND")
			except ValueError:
				pass
			try:
				self.enableDBIbind = shv.getBoolValue("USEDBIBIND")
			except ValueError:
				pass
			try:
				self.enableDirectories = shv.getBoolValue("USEDIRECTORIES")
			except ValueError:
				pass
			try:
				self.enableEPS = shv.getBoolValue("USEEPS")
			except ValueError:
				pass
			try:
				self.enableHesiod = shv.getBoolValue("USEHESIOD")
			except ValueError:
				pass
			try:
				self.enableHesiodbind = shv.getBoolValue("USEHESIODBIND")
			except ValueError:
				pass
			try:
				self.enableKerberos = shv.getBoolValue("USEKERBEROS")
			except ValueError:
				pass
			try:
				self.enableLDAP = shv.getBoolValue("USELDAP")
			except ValueError:
				pass
			try:
				self.enableLDAPAuth = shv.getBoolValue("USELDAPAUTH")
			except ValueError:
				pass
			try:
				self.enableSmartcard = shv.getBoolValue("USESMARTCARD")
			except ValueError:
				pass
			try:
				self.forceSmartcard = shv.getBoolValue("FORCESMARTCARD")
			except ValueError:
				pass
			try:
				self.enableLDAPbind = shv.getBoolValue("USELDAPBIND")
			except ValueError:
				pass
			try:
				enableMD5 = shv.getBoolValue("USEMD5")
				if enableMD5:
					self.passwordAlgorithm = 'md5'
				else:
					self.passwordAlgorithm = 'descrypt'
			except ValueError:
				pass
			try:
				self.enableNIS = shv.getBoolValue("USENIS")
			except ValueError:
				pass
			try:
				self.enableNISP3 = shv.getBoolValue("USENISPLUS")
			except ValueError:
				pass
			try:
				self.enableOdbcbind = shv.getBoolValue("USEODBCBIND")
			except ValueError:
				pass
			try:
				self.enableOTP = shv.getBoolValue("USEOTP")
			except ValueError:
				pass
			try:
				self.enablePasswdQC = shv.getBoolValue("USEPASSWDQC")
			except ValueError:
				pass
			try:
				self.enableShadow = shv.getBoolValue("USESHADOW")
			except ValueError:
				pass
			try:
				self.enableSMB = shv.getBoolValue("USESMBAUTH")
			except ValueError:
				pass
			try:
				self.enableWinbind = shv.getBoolValue("USEWINBIND")
			except ValueError:
				pass
			try:
				self.enableWinbindAuth = shv.getBoolValue("USEWINBINDAUTH")
			except ValueError:
				pass
			try:
				self.enableLocAuthorize = shv.getBoolValue("USELOCAUTHORIZE")
			except ValueError:
				pass
			try:
				self.enablePAMAccess = shv.getBoolValue("USEPAMACCESS")
			except ValueError:
				pass
			try:
				self.enableMkHomeDir = shv.getBoolValue("USEMKHOMEDIR")
			except ValueError:
				pass
			try:
				self.enableSysNetAuth = shv.getBoolValue("USESYSNETAUTH")
			except ValueError:
				pass
			algo = shv.getValue("PASSWDALGORITHM")
			if algo in password_algorithms:
				self.passwordAlgorithm = algo
			shv.close()
		except IOError:
			pass

		# Special handling for pam_cracklib and pam_passwdqc: there can be
	 	# only one.
		if self.enableCracklib and self.enablePasswdQC:
			self.enablePasswdQC = False
		if not self.enableCracklib and not self.enablePasswdQC:
			self.enableCracklib = True
	
		# Special handling for broken_shadow option
		if (self.brokenShadow and not self.enableLDAPAuth and
			not self.enableKerberos and not self.enableWinbindAuth and
			not self.enableSmartcard):
			self.forceBrokenShadow = True
			    	
		return True

	# Read hints from the network control file.
	def readNetwork(self):
		# Open the file.  Bail if it's not there.
		try:
			shv = shvfile.read(SYSCONFDIR+"/sysconfig/network")
		except IOError:
			return False
		
		tmp = shv.getValue("NISDOMAIN")
		if tmp:
			self.nisLocalDomain = tmp

		shv.close()

		if self.nisLocalDomain:
			self.nisDomain = self.nisLocalDomain

		return True

	# Compare two authInfoType structures and return True if they have any
	# meaningful differences.
	def differs(self, b):
		return (stringsDiffer(self.hesiodLHS, b.hesiodLHS, False) or
		stringsDiffer(self.hesiodRHS, b.hesiodRHS, False) or

		stringsDiffer(self.ldapServer, b.ldapServer, False) or
		stringsDiffer(self.ldapBaseDN, b.ldapBaseDN, True) or

		stringsDiffer(self.kerberosRealm, b.kerberosRealm, True) or
		(self.kerberosRealmviaDNS != b.kerberosRealmviaDNS) or
		stringsDiffer(self.kerberosKDC, b.kerberosKDC, False) or
		(self.kerberosKDCviaDNS != b.kerberosKDCviaDNS) or
		stringsDiffer(self.kerberosAdminServer,
			       b.kerberosAdminServer, False) or
		stringsDiffer(self.nisServer, b.nisServer, True) or
		stringsDiffer(self.nisDomain, b.nisDomain, True) or
		stringsDiffer(self.nisLocalDomain, b.nisLocalDomain, True) or

		stringsDiffer(self.smartcardModule, b.smartcardModule, True) or
		stringsDiffer(self.smartcardAction, b.smartcardAction, True) or

		stringsDiffer(self.smbWorkgroup, b.smbWorkgroup, False) or
		stringsDiffer(self.smbRealm, b.smbRealm, True) or
		stringsDiffer(self.smbServers, b.smbServers, False) or
		stringsDiffer(self.smbSecurity, b.smbSecurity, False) or
		stringsDiffer(self.smbIdmapUid, b.smbIdmapUid, False) or
		stringsDiffer(self.smbIdmapGid, b.smbIdmapGid, False) or

		stringsDiffer(self.winbindSeparator,
			       b.winbindSeparator, True) or
		stringsDiffer(self.winbindTemplateHomedir,
			       b.winbindTemplateHomedir, True) or
		stringsDiffer(self.winbindTemplatePrimaryGroup,
			       b.winbindTemplatePrimaryGroup, True) or
		stringsDiffer(self.winbindTemplateShell,
			       b.winbindTemplateShell, True) or
		
		stringsDiffer(self.passwordAlgorithm,
			       b.passwordAlgorithm, False) or
		stringsDiffer(self.algoRounds,
			       b.algoRounds, True) or

		(self.winbindUseDefaultDomain != b.winbindUseDefaultDomain) or
		(self.winbindOffline != b.winbindOffline) or
		(self.enableCache != b.enableCache) or

		(self.enableDB != b.enableDB) or
		(self.enableDirectories != b.enableDirectories) or
		(self.enableHesiod != b.enableHesiod) or
		(self.enableLDAP != b.enableLDAP) or
		(self.enableLDAPS != b.enableLDAPS) or
		(self.enableNIS != b.enableNIS) or
		(self.enableNIS3 != b.enableNIS3) or
		(self.enableDBbind != b.enableDBbind) or
		(self.enableDBIbind != b.enableDBIbind) or
		(self.enableHesiodbind != b.enableHesiodbind) or
		(self.enableLDAPbind != b.enableLDAPbind) or
		(self.enableOdbcbind != b.enableOdbcbind) or
		(self.enableWinbind != b.enableWinbind) or
		(self.enableWinbindAuth != b.enableWinbindAuth) or
		(self.enableWINS != b.enableWINS) or
		(self.preferDNSinHosts != b.preferDNSinHosts) or

		(self.enableAFS != b.enableAFS) or
		(self.enableAFSKerberos != b.enableAFSKerberos) or
		(self.enableNullOk != b.enableNullOk) or
		(self.enableCracklib != b.enableCracklib) or
		(self.enableEPS != b.enableEPS) or
		(self.enableKerberos != b.enableKerberos) or
		(self.enableLDAPAuth != b.enableLDAPAuth) or
		(self.enableSmartcard != b.enableSmartcard) or
		(self.forceSmartcard != b.forceSmartcard) or
		(self.enableOTP != b.enableOTP) or
		(self.enablePasswdQC != b.enablePasswdQC) or
		(self.enableShadow != b.enableShadow) or
		(self.enableSMB != b.enableSMB) or
		(self.enableLocAuthorize != b.enableLocAuthorize) or
		(self.enablePAMAccess != b.enablePAMAccess) or
		(self.enableMkHomeDir != b.enableMkHomeDir) or
		(self.enableSysNetAuth != b.enableSysNetAuth) or
		(self.brokenShadow != b.brokenShadow) or
		(self.forceBrokenShadow != b.forceBrokenShadow) or

		stringsDiffer(self.joinUser, b.joinUser, True) or
		stringsDiffer(self.joinPassword, b.joinPassword, True))


	# There's some serious strangeness in here, because we get called in two
	# different-but-closely-related scenarios.  The first case is when we're
	# initializing the authInfo structure and we want to fill in defaults with
	# suggestions we "know".  The second case is when the user has just made a
	# change to one field and we need to update another field to somehow
	# compensate for the change.
	def update(self):
		self.smbServers = cleanList(self.smbServers)
		self.kerberosKDC = cleanList(self.kerberosKDC)
		self.kerberosAdminServer = cleanList(self.kerberosAdminServer)
		if self.smbSecurity == "ads":
			# As of this writing, an ADS implementation always
			# upper-cases the realm name, even if only internally,
			# and we need to reflect that in the krb5.conf file.
			if self.smbRealm:
				self.smbRealm = self.smbRealm.upper()
		self.passwordAlgorithm = self.passwordAlgorithm.lower()

	def read(self):
		self.readHesiod()
		self.readSMB()
		self.readWinbind()
		self.readNetwork()
		self.readNIS()
		self.readLDAP()		
		self.readKerberos()
		self.readSmartcard()
		self.readNSS()
		self.readCache()
		self.readPAM()

		self.update()


	def copy(self):
		ret = copy.copy(self)
		ret.joinUser = ""
		ret.joinPassword = ""
		return ret

	def writeCache(self):
		if self.enableCache:
			os.system("/sbin/chkconfig --add nscd")
			os.system("/sbin/chkconfig --level 345 nscd on")
		else:
			try:
				os.stat(PATH_NSCD)
		    		os.system("/sbin/chkconfig --level 345 nscd off");
			except OSError:
				pass
		return True

	def writeHesiod(self):
		try:
			shv = shvfile.rcreate(SYSCONFDIR+"/hesiod.conf")
		except IOError:
			return False
		shv.setValue("lhs", self.hesiodLHS)
		shv.setValue("rhs", self.hesiodRHS)

		shv.write(0644)
		shv.close()

		return True

	# Write SMB setup to /etc/pam_smb.conf.
	def writeSMB(self):
		f = None
		try:
			f = openLocked(SYSCONFDIR+"/pam_smb.conf", 0644)
		
			f.truncate(0)
			
			f.write(self.smbWorkgroup+"\n")
			
			servers = self.smbServers.replace(",", " ")			
			servers = servers.split(None)
			
			if len(servers) > 0:
				f.write(servers[0])
			f.write("\n")
			if len(servers) > 1:
				f.write(servers[1])
			f.write("\n")
		finally:
			try:
				if f:
					f.close()
			except IOError:
				pass
		return True

	# Write NIS setup to /etc/yp.conf.
	def writeNIS(self):
		written = False
		f = None
		output = ""
		try:
			f = openLocked(SYSCONFDIR+"/yp.conf", 0644)

			# Read in the old file.
			for line in f:
				ls = line.strip()
				
				value = matchKey(ls, "domain")
				if value:
					# Save the domain's name.  To do that, find its end.
					value = value.split(None, 1)
					if len(value) < 1:
						continue
					if value[0] != self.nisDomain and value[0] != self.nisLocalDomain:
						# The domain name doesn't match current or previous domain
						output += line
						continue
 
					if not written and self.nisDomain:
						output += "domain " + self.nisDomain
						# Take an empty server name to mean that we
				 		# want to use broadcast.
						servers = self.nisServer.split(",")
						if self.nisServer:
							output += " server "
							output += servers[0]
						else:
							output += " broadcast"
						output += "\n"

						servers = servers[1:]
						for s in servers:
							if s:
								output += "ypserver " + s + "\n"

						written = True
				elif matchLine(ls, "ypserver"):
					# If it's a 'ypserver' line, insert ours instead.
					if not written and not self.nisDomain and self.nisServer:
						servers = self.nisServer.split(",")
						for s in servers:
							if s:
								output += "ypserver " + s + "\n"

						written = True
				else:
					# Otherwise, just copy the current line out.
					output += line

			# If we haven't encountered a domain line yet...
			if not written:
				servers = self.nisServer.split(",")
				if self.nisDomain:
					output += "domain " + self.nisDomain
					# Take an empty server name to mean that we
				 	# want to use broadcast.
					if servers[0]:
						output += " server "
						output += servers[0]
						servers = servers[1:]
					else:
						output += " broadcast"
					output += "\n"

				for s in servers:
					if s:
						output += "ypserver " + s + "\n"
			# Write it out and close it.
			f.seek(0)
			f.truncate(0)
			f.write(output)
		finally:
			try:
				if f:
					f.close()
			except IOError:
				pass
		return True

	# Write LDAP setup to an ldap.conf using host and base as keys.
	def writeLDAP2(self, filename, uri, host, base, writePadl):
		wrotebasedn = False
		wroteserver = False
		wrotessl = False
		wrotepass = False
		wrotecacertdir = False
		f = None
		output = ""
		if (self.passwordAlgorithm and self.passwordAlgorithm != "descrypt" and
			self.passwordAlgorithm != "bigcrypt"):
			passalgo = "md5"
		else: 
			passalgo = "crypt"
		try:
			f = openLocked(filename, 0644)

			# Read in the old file.
			for line in f:
				ls = line.strip()
				# If it's a 'uri' line, insert ours instead.
				if matchLine(ls, uri):
					if not wroteserver and self.ldapServer:
						output += uri + " " 
						output += " ".join(self.ldapHostsToURIs(self.ldapServer).split(","))
						output += "\n"
						wroteserver = True
				# If it's a 'host' line, comment it out.
				elif matchLine(ls, host):
					if self.ldapServer:
						output += "#" + line 
				elif matchLine(ls, base):
					# If it's a 'base' line, insert ours instead.
					if not wrotebasedn and self.ldapBaseDN:
						output += base + " "
						output += self.ldapBaseDN
						output += "\n"
						wrotebasedn = True
				elif writePadl and matchLine(ls, "ssl"):
					# If it's an 'ssl' line, insert ours instead.
					if not wrotessl:
						output += "ssl "
						if self.enableLDAPS:
							output += "start_tls"
						else:
							output += "no"
						output += "\n"
						wrotessl = True
				elif matchLineI(ls, "tls_cacertdir"):
					# If it's an 'tls_cacertdir' line, insert ours instead.
					if not wrotecacertdir:
						if writePadl:
							output += "tls_cacertdir"
						else:
							output += "TLS_CACERTDIR"
						output += " " + self.ldapCacertDir
						output += "\n"
						wrotecacertdir = True
				elif writePadl and matchLine(ls, "pam_password"):
					# If it's a 'pam_password' line, write the correct setting.
					if not wrotepass:
						output += "pam_password " + passalgo
						output += "\n"
						wrotepass = True
				else:
					# Otherwise, just copy the current line out.
					output += line

			# If we haven't encountered either of the config lines yet...
			if not wroteserver and self.ldapServer:
				output += uri + " " 
				output += " ".join(self.ldapHostsToURIs(self.ldapServer).split(","))
				output += "\n"
			if not wrotebasedn and self.ldapBaseDN:
				output += base + " "
				output += self.ldapBaseDN
				output += "\n"
			if writePadl and not wrotessl:
						output += "ssl "
						if self.enableLDAPS:
							output += "start_tls"
						else:
							output += "no"
						output += "\n"
			if not wrotecacertdir:
				if writePadl:
					output += "tls_cacertdir"
				else:
					output += "TLS_CACERTDIR"
				output += " " + self.ldapCacertDir
				output += "\n"
			if writePadl and not wrotepass:
				output += "pam_password " + passalgo
				output += "\n"
			# Write it out and close it.
			f.seek(0)
			f.truncate(0)
			f.write(output)
		finally:
			try:
				if f:
					f.close()
			except IOError:
				pass
		return True

	def writeLDAP(self):
		ret = self.writeLDAP2(SYSCONFDIR+"/ldap.conf",
					 "uri", "host", "base", True)
		if ret:
			# Ignore errors here.
			self.writeLDAP2(SYSCONFDIR+"/openldap/ldap.conf",
				   "URI", "HOST", "BASE", False)
		return ret

	def cryptStyle(self):
		ret = "crypt_style = "
		if self.passwordAlgorithm == "md5":
			return ret + "md5"
		elif self.passwordAlgorithm == "sha256" or self.passwordAlgorithm == "sha512":
			return ret + self.passwordAlgorithm
		else:
			return ret + "des"

	# Write libuser's password algo setting to /etc/libuser.conf.
	def writeLibuser(self):
		wrotecryptstyle = False
		wrotedefaults = False
		section = ""
		f = None
		output = ""
		try:
			f = openLocked(SYSCONFDIR+"/libuser.conf", 0644)

			# Read in the old file.
			for line in f:
				ls = line.strip()

				# If this is the "crypt_style" in the defaults section,
				# replace it with the values we now have.
				if section == "defaults" and matchLine(ls, "crypt_style"):
					output += self.cryptStyle() + "\n"
					wrotecryptstyle = True
					continue

				# If it's the beginning of a section, record its name.
				if matchLine(ls, "["):
					# If the previous section was "defaults", and we didn't
			 		# see the crypt_style setting , write it out.
					if section == "defaults" and not wrotecryptstyle:
						output += self.cryptStyle() + "\n"
						wrotecryptstyle = True
					section = ls[1:].split("]", 1)[0]
					if section == "defaults":
						wrotedefaults = True

				output += line

			# If we haven't encountered a defaults section yet...
			if not wrotedefaults:
				output += "[defaults]\n"
				output += self.cryptStyle() + "\n"
				wrotedefaults = True
				wrotecryptstyle = True
			# Write it out and close it.
			f.seek(0)
			f.truncate(0)
			f.write(output)
		finally:
			try:
				if f:
					f.close()
			except IOError:
				pass
		return True

	# Write shadow utils password algo setting to /etc/login.defs.
	def writeLogindefs(self):
		wrotemd5crypt = False
		wroteencmethod = False
		section = ""
		f = None
		output = ""

		if self.passwordAlgorithm == "md5":
			md5crypt = "MD5_CRYPT_ENAB yes\n"
		else:
			md5crypt = "MD5_CRYPT_ENAB no\n"

		if self.passwordAlgorithm == "descrypt" or self.passwordAlgorithm =="bigcrypt":
			encmethod = "ENCRYPT_METHOD DES\n"
		else:
			encmethod = "ENCRYPT_METHOD " + self.passwordAlgorithm.upper() + "\n"
		try:
			f = openLocked(SYSCONFDIR+"/login.defs", 0644)

			# Read in the old file.
			for line in f:
				ls = line.strip()

				if matchLine(ls, "MD5_CRYPT_ENAB"):
					output += md5crypt
					wrotemd5crypt = True
					continue

				if matchLine(ls, "ENCRYPT_METHOD"):
					output += encmethod
					wroteencmethod = True
					continue

				output += line

			# If we haven't encountered a defaults section yet...
			if not wrotemd5crypt:
				output += md5crypt
			if not wroteencmethod:
				output += encmethod
			# Write it out and close it.
			f.seek(0)
			f.truncate(0)
			f.write(output)
		finally:
			try:
				if f:
					f.close()
			except IOError:
				pass
		return True

	# Write Kerberos 5 setup to /etc/krb5.conf.
	def writeKerberos5(self):
		wroterealm = False
		wrotekdc = False
		wroteadmin = False
		wrotesmbrealm = False
		wrotesmbkdc = False
		wroterealms = False
		wrotelibdefaults = False
		wroterealms2 = False
		wrotelibdefaults2 = False
		wrotedefaultrealm = False
		wrotednsrealm = False
		wrotednskdc = False
		wroteourdomrealm = False
		wrotedomrealm = False
		wrotedomrealm2 = False
		section = ""
		subsection = ""
		f = None
		output = ""
		if self.enableKerberos and self.kerberosRealm:
			defaultrealm = self.kerberosRealm
		elif (self.enableWinbind or 
			self.enableWinbindAuth) and self.smbSecurity == "ads" and self.smbRealm:
			defaultrealm = self.smbRealm
		else:
			defaultrealm = self.kerberosRealm	
		if self.kerberosRealm == self.smbRealm:
			wrotesmbrealm = True
		try:
			f = openLocked(SYSCONFDIR+"/krb5.conf", 0644)

			# Read in the old file.
			for line in f:
				ls = line.strip()

				# If this is the "kdc" in our realm, replace it with
				# the values we now have.
				if (section == "realms" and subsection and subsection == self.kerberosRealm
					and matchLine(ls, "kdc")):
					if not wrotekdc:
						if self.kerberosKDC:
							output += krbKdc(self.kerberosKDC)
						wrotekdc = True
					continue
				# If this is the "kdc" in the SMB realm, replace it with
				# the values we now have.
				if (section == "realms" and self.smbSecurity == "ads" and subsection
					and subsection == self.smbRealm and matchLine(ls, "kdc")):
					if not wrotesmbkdc:
						if self.smbServers:
							output += krbKdc(self.smbServers)
						wrotesmbkdc = True
					continue
				# If this is the "admin_server" in our realm, replace it with
			 	# the values we now have.
				if (section == "realms" and subsection and subsection == self.kerberosRealm
					and matchLine(ls, "admin_server")):
					if not wroteadmin:
						if self.kerberosAdminServer:
							output += krbAdminServer(self.kerberosAdminServer)
						wroteadmin = True
					continue
				# If we're in the realms section, but not in a realm, we'd
			 	# better be looking at the beginning of one.
				if section == "realms" and not subsection:
					# Read the name of the realm.
					value = ls.split(None,1)
					if len(value) < 1:
						output += line
						continue
					subsection = value[0]					
					# If this is the section for our realm, mark
					# that.
					if self.kerberosRealm and subsection == self.kerberosRealm:
						wroterealm = True
					if self.smbRealm and subsection == self.smbRealm:
						wrotesmbrealm = True
				# If it's the end of a subsection, mark that.
				if section == "realms" and subsection and matchLine(ls, "}"):
					# If it's the right section of realms, write out
					# info we haven't already written.
					if self.kerberosRealm and subsection == self.kerberosRealm:
						if not wrotekdc:
							output += krbKdc(self.kerberosKDC)
							wrotekdc = True
						if not wroteadmin:
							output += krbAdminServer(self.kerberosAdminServer)
							wroteadmin = True
					if self.smbRealm and subsection == self.smbRealm:
						if not wrotesmbkdc:
							output += krbKdc(self.smbServers)
							wrotesmbkdc = True
					subsection = ""
				# If we're in the libdefaults section, and this is the
				# default_realm keyword, replace it with ours.
				if section == "libdefaults" and matchLine(ls, "default_realm"):
					if defaultrealm and not wrotedefaultrealm:
						output += " default_realm = "
						output += defaultrealm
						output += "\n"
						wrotedefaultrealm = True
					continue
				if section == "libdefaults" and matchLine(ls, "dns_lookup_realm"):
					if not wrotednsrealm:
						output += " dns_lookup_realm = "					
						output += str(bool(self.kerberosRealmviaDNS)).lower()
						output += "\n"
						wrotednsrealm = True
					continue
				if section == "libdefaults" and matchLine(ls, "dns_lookup_kdc"):
					if not wrotednskdc:
						output += " dns_lookup_kdc = "
						output += str(bool(self.kerberosKDCviaDNS)).lower()
						output += "\n"
						wrotednskdc = True
					continue
				# don't change the domain_realm mapping if it's already there
				if section == "domain_realm" and self.kerberosRealm and (matchLine(ls, self.kerberosRealm.lower())
					or matchLine(ls, "."+self.kerberosRealm.lower())):
					output += line
					wroteourdomrealm = True
					continue
				# If it's the beginning of a section, record its name.
				if matchLine(ls, "["):
					# If the previous section was "realms", and we didn't
					# see ours, write our realm out.
					if (section == "realms" and self.kerberosRealm
						and not wroterealm):
						output += krbRealm(self.kerberosRealm,
							self.kerberosKDC,
							self.kerberosAdminServer)
						wroterealm = True
					# If the previous section was "realms", and we didn't
					# see the SMB realm, write it out.
					if (section == "realms" and self.smbRealm
						and not wrotesmbrealm):
						output += krbRealm(self.smbRealm,
							self.smbServers, "")
						wrotesmbrealm = True
					# If the previous section was "libdefaults", and we
					# didn't see a "default_realm", write it out.
					if section == "libdefaults":
						if defaultrealm and not wrotedefaultrealm:
							output += " default_realm = "
							output += defaultrealm
							output +=  "\n"
							wrotedefaultrealm = True
						if not wrotednsrealm:
							output += " dns_lookup_realm = "					
							output += str(bool(self.kerberosRealmviaDNS)).lower()
							output += "\n"
							wrotednsrealm = True
						if not wrotednskdc:
							output += " dns_lookup_kdc = "
							output += str(bool(self.kerberosKDCviaDNS)).lower()
							output += "\n"
							wrotednskdc = True
					if section == "domain_realm":
						if self.kerberosRealm and not wroteourdomrealm:
							output += " " + self.kerberosRealm.lower()
							output += " = " + self.kerberosRealm
							output +=  "\n"
							output += " ." + self.kerberosRealm.lower()
							output += " = " + self.kerberosRealm
							output +=  "\n"
							wroteourdomrealm = True
					if section:
						if section == "realms":
							wroterealms2 = True
						elif section == "libdefaults":
							wrotelibdefaults2 = True
						elif section == "domain_realm":
							wrotedomrealm2 = True
					section = ls[1:].split("]", 1)[0]
					if section == "realms":
						wroterealms = True
					elif section == "libdefaults":
						wrotelibdefaults = True
					elif section == "domain_realm":
						wrotedomrealm = True

				# Otherwise, just copy the current line out.
				output += line

			# If we haven't encountered a libdefaults section yet...
			if not wrotelibdefaults2:
				if not wrotelibdefaults:
					output += "[libdefaults]\n"
				if defaultrealm and not wrotedefaultrealm:
					output += " default_realm = "
					output += defaultrealm
					output +=  "\n"
				if not wrotednsrealm:
					output += " dns_lookup_realm = "					
					output += str(bool(self.kerberosRealmviaDNS)).lower()
					output += "\n"
				if not wrotednskdc:
					output += " dns_lookup_kdc = "
					output += str(bool(self.kerberosKDCviaDNS)).lower()
					output += "\n"
			# If we haven't encountered a realms section yet...
			if not wroterealms2:
				if not wroterealms:
					output += "[realms]\n"
				if not wroterealm:
					output += krbRealm(self.kerberosRealm, self.kerberosKDC,
						self.kerberosAdminServer)
				if not wrotesmbrealm:
					output += krbRealm(self.smbRealm, self.smbServers, "")
			if not wrotedomrealm2:
				if not wrotedomrealm:
					output += "[domain_realm]\n"
				if self.kerberosRealm and not wroteourdomrealm:
					output += " " + self.kerberosRealm.lower()
					output += " = " + self.kerberosRealm
					output +=  "\n"
					output += " ." + self.kerberosRealm.lower()
					output += " = " + self.kerberosRealm
					output +=  "\n"

			# Write it out and close it.
			f.seek(0)
			f.truncate(0)
			f.write(output)
		finally:
			try:
				if f:
					f.close()
			except IOError:
				pass
		return True

	# Write Kerberos 4 setup to /etc/krb.conf,
	def writeKerberos4(self):
		if not self.kerberosRealm:
			return False
		readrealm = False
		f = None
		output = ""
		try:
			f = openLocked(SYSCONFDIR+"/krb.conf", 0644)
			# Set up the buffer with the parts of the file which pertain to our
			# realm.
			output += self.kerberosRealm + "\n"

			for kdc in self.kerberosKDC.split(","):
				if kdc:
					output += self.kerberosRealm + "\t" + kdc + "\n"
			for asrv in self.kerberosAdminServer.split(","):
				if asrv:
					output += self.kerberosRealm + "\t" + asrv 
					output += " admin server" + "\n"

			# Now append lines from the original file which have nothing to do
			# with our realm.
			for line in f:
				# Skip initial realm line
				if not readrealm:
					readrealm = True
					continue
				if not matchLine(line, self.kerberosRealm):
					output += line
			# Write it out and close it.
			f.seek(0)
			f.truncate(0)
			f.write(output)
		finally:
			try:
				if f:
					f.close()
			except IOError:
				pass
		return True

	# Write information to /etc/krb5.conf and /etc/krb.conf.
	def writeKerberos(self):
		ret = self.writeKerberos5()
		if ret:
			self.writeKerberos4()
		return ret

	def writeSmartcard(self):
		insact = "/usr/sbin/gdm-safe-restart"
		rmact = "/usr/sbin/gdm-safe-restart"
		if self.smartcardAction == _("Lock"):
			insact += ",/etc/pkcs11/lockhelper.sh -lock"
			rmact += ",/etc/pkcs11/lockhelper.sh -deactivate"
		
		callPKCS11Setup(["use_module="+self.smartcardModule,
			"ins_action="+insact, "rm_action="+rmact])
		return True

	def paramsWinbind(self):
		output =  "#--authconfig--start-line--\n"
		output += "\n"
		output += "# Generated by authconfig on " + time.strftime("%Y/%m/%d %H:%M:%S") + "\n"
		output += "# DO NOT EDIT THIS SECTION (delimited by --start-line--/--end-line--)\n"
		output += "# Any modification may be deleted or altered by authconfig in future\n"
		output += "\n"

		if self.smbWorkgroup:
			output += "   workgroup = "
			output += self.smbWorkgroup
			output += "\n"
			wroteworkgroup = True
		if self.smbServers:
			output += "   password server = "
			output += self.smbServers.replace(",", " ")
			output += "\n"
			wroteservers = True
		if self.smbRealm:
			output += "   realm = "
			output += self.smbRealm
			output += "\n"
			wroterealm = True
		if self.smbSecurity:
			output += "   security = "
			output += self.smbSecurity
			output += "\n"
			wrotesecurity = True
		if self.smbIdmapUid:
			output += "   idmap uid = "
			output += self.smbIdmapUid
			output += "\n"
			wroteidmapuid = True
		if self.smbIdmapGid:
			output += "   idmap gid = "
			output += self.smbIdmapGid
			output += "\n"
			wroteidmapgid = True
		if self.winbindSeparator:
			output += "   winbind separator = "
			output += self.winbindSeparator
			output += "\n"
			wroteseparator = True
		if self.winbindTemplateHomedir:
			output += "   template homedir = "
			output += self.winbindTemplateHomedir
			output += "\n"
			wrotetemplateh = True
		if self.winbindTemplatePrimaryGroup:
			output += "   template primary group = "
			output += self.winbindTemplatePrimaryGroup
			output += "\n"
			wrotetemplatep = True
		if self.winbindTemplateShell:
			output += "   template shell = "
			output += self.winbindTemplateShell
			output += "\n"
			wrotetemplates = True
		output += "   winbind use default domain = "
		output += str(bool(self.winbindUseDefaultDomain)).lower()
		output += "\n"
		output += "   winbind offline logon = "
		output += str(bool(self.winbindOffline)).lower()
		output += "\n"

		output += "\n"
		output += "#--authconfig--end-line--\n"

		return output

	def checkLineWinbind(self, line, ls, options):
		output = ""

		# Check if this is a setting we care about.
		for opt in options:
			if matchLineSMB(ls, opt):
				output = ";"
				break

		output += line
		return output;

	# Write winbind settings to /etc/smb/samba.conf.
	def writeWinbind(self):
		authsection = False
		wroteauthsection = False
		section = ""
		options = ["workgroup", "password server", "realm", "security",
			   "domain logons", "domain master",
			   "idmap uid", "idmap gid", "winbind separator",
			   "template homedir", "template primary group",
			   "template shell", "winbind use default domain",
			   "winbind offline logon"]
		f = None
		output = ""
		try:
			f = openLocked(SYSCONFDIR+"/samba/smb.conf", 0644)

			# Read in the old file.
			for line in f:
				ls = line.strip()

				if authsection:
					if matchLine(ls, "#--authconfig--end-line--"):
						authsection = False
					#skip all previous authconfig generated lines
					continue

				if matchLine(ls, "#--authconfig--start-line--"):
					authsection = True
					continue

				# If it's a comment, just pass it through.
				if matchLine(ls, ";") or matchLine(ls, "#"):
					output += line
					continue

				# If it's a section start, note the section name.
				value = matchKey(ls, "[")
				if value and "]" in value:

					section = value.split("]")[0].lower()

					output += line
					if section == "global":
						output += self.paramsWinbind()
						wroteauthsection = True

					continue

				# Comment out options we set.
				if section == "global":
					output += self.checkLineWinbind(line, ls, options)
					continue

				# Copy anything else as is.
				output += line

			if not wroteauthsection:
				output += "[global]\n"
				output += self.paramsWinbind()

			# Write it out and close it.
			f.seek(0)
			f.truncate(0)
			f.write(output)
		finally:
			try:
				if f:
					f.close()
			except IOError:
				pass
		return True

	# Write NSS setup to /etc/nsswitch.conf.
	def writeNSS(self):
		users = ""
		normal = ""
		hosts = ""
		wrotepasswd = False
		wrotegroup = False
		wroteshadow = False
		wrotenetgroup = False
		wroteautomount = False
		wrotehosts = False
		f = None
		output = ""
		try:
			f = openLocked(SYSCONFDIR+"/nsswitch.conf", 0644)

			# Determine what we want in that file for most of the databases. If
			# we're using DB, we're doing it for speed, so put it in first.  Then
			# comes files.  Then everything else in reverse alphabetic order.
			if self.enableDB:
				normal += " db"
			normal += " files"
			if self.enableDirectories:
				normal += " directories"
			if self.enableOdbcbind:
				normal += " odbcbind"
			if self.enableNIS3:
				normal += " nisplus"
			if self.enableNIS:
				normal += " nis"
			if self.enableLDAPbind:
				normal += " ldapbind"
			if self.enableLDAP:
				normal += " ldap"
			if self.enableHesiodbind:
				normal += " hesiodbind"
			if self.enableHesiod:
				normal += " hesiod"
			if self.enableDBIbind:
				normal += " dbibind"
			if self.enableDBbind:
				normal += " dbbind"

			# Generate the list for users and groups.  The same as most other
			# services, just use "compat" instead of "files" if "compat" is
			# enabled.
			if self.enableCompat:
				users = normal.replace("files", "compat")
			else:
				users = normal

			if self.enableWinbind:
				users += " winbind"

			# Hostnames we treat specially.
			hosts += " files"
			if self.preferDNSinHosts:
				hosts += " dns"
			if self.enableWINS:
				hosts += " wins"
			if self.enableNIS3:
				hosts += " nisplus"
			if self.enableNIS:
				hosts += " nis"
			if not self.preferDNSinHosts:
				hosts += " dns"

			# Read in the old file.
			for line in f:
				ls = line.strip()

				# If it's a 'passwd' line, insert ours instead.
				if matchLine(ls, "passwd:"):
					if not wrotepasswd:
						output += "passwd:    "
						output += users
						output += "\n"
						wrotepasswd = True

				# If it's a 'shadow' line, insert ours instead.
				elif matchLine(ls, "shadow:"):
					if not wroteshadow:
						output += "shadow:    "
						output += users
						output += "\n"
						wroteshadow = True
				# If it's a 'group' line, insert ours instead.
				elif matchLine(ls, "group:"):
					if not wrotegroup:
						output += "group:     "
						output += users
						output += "\n"
						wrotegroup = True
				# If it's a 'netgroup' line, insert ours instead.
				elif matchLine(ls, "netgroup:"):
					if not wrotenetgroup:
						output += "netgroup:  "
						output += normal
						output += "\n"
						wrotenetgroup = True
				# If it's a 'automount' line, insert ours instead.
				elif matchLine(ls, "automount:"):
					if not wroteautomount:
						output += "automount: "
						output += normal
						output += "\n"
						wroteautomount = True
				# If it's a 'hosts' line, insert ours instead.
				elif matchLine(ls, "hosts:"):
					if not wrotehosts:
						output += "hosts:     "
						output += hosts
						output += "\n"
						wrotehosts = True				
				# Otherwise, just copy the current line out.
				else:
					output += line

			# If we haven't encountered any of the config lines yet...
			if not wrotepasswd:
				output += "passwd:    "
				output += users
				output += "\n"
			if not wroteshadow:
				output += "shadow:    "
				output += users
				output += "\n"
			if not wrotegroup:
				output += "group:     "
				output += users
				output += "\n"
			if not wrotenetgroup:
				output += "netgroup:  "
				output += normal
				output += "\n"
			if not wroteautomount:
				output += "automount: "
				output += normal
				output += "\n"
			if not wrotehosts:
				output += "hosts:     "
				output += hosts
				output += "\n"

			# Write it out and close it.
			f.seek(0)
			f.truncate(0)
			f.write(output)
		finally:
			try:
				if f:
					f.close()
			except IOError:
				pass
		return True
		
	def formatPAMModule(self, module):
		stack = pam_stacks[module[STACK]]
		logic = module[LOGIC]
		output = ""
		if stack and logic:
			args = ""
			if module[NAME] == "pkcs11" and stack == "auth":
				if self.forceSmartcard:
					if self.enableKerberos:
						logic = LOGIC_FORCE_PKCS11_KRB5
					else:
						logic = LOGIC_FORCE_PKCS11
					args = " ".join(argv_force_pkcs11_auth)
				else:
					if self.enableKerberos:
						logic = LOGIC_PKCS11_KRB5
			if module[NAME] == "krb5" and stack == "account":
				if self.enableSmartcard:
					logic = LOGIC_IGNORE_AUTH_ERR
				else:
					logic = LOGIC_IGNORE_UNKNOWN
			if module[NAME] == "succeed_if" and stack == "auth" and logic == LOGIC_SKIPNEXT:
				if self.enableKerberos:
					logic = LOGIC_SKIPNEXT3
			output += "%-12s%-13s pam_%s.so" % (stack, logic,
				module[NAME])
			if not module[NAME] in self.module_missing and not os.access("%s/pam_%s.so"
				% (AUTH_MODULE_DIR, module[NAME]), os.X_OK):
				self.messageCB(_("Authentication module %s/pam_%s.so is missing. Authentication process will not work correctly." %
					(AUTH_MODULE_DIR, module[NAME])))				
				self.module_missing[module[NAME]] = True
			if module[NAME] == "cracklib":
				args = self.cracklibArgs
			if module[NAME] == "passwdqc":
				args = self.passwdqcArgs
			if module[NAME] == "localuser":
				args = self.localuserArgs
			if module[NAME] == "access":
				args = self.pamAccessArgs
			if module[NAME] == "mkhomedir":
				args = self.mkhomedirArgs
			if not args and module[ARGV]:
				args = " ".join(module[ARGV])
			if module[NAME] == "winbind" and self.winbindOffline:
				output += " cached_login"
			if module[NAME] == "unix":
				if stack == "password":
					if self.passwordAlgorithm and self.passwordAlgorithm != "descrypt":
						output += " " + self.passwordAlgorithm
					if self.algoRounds:
						output += " rounds=" + self.algoRounds
					if self.enableShadow:
						output +=  " shadow"
					if self.enableNIS:
						output += " nis"
					if self.enableNullOk:
						output += " nullok"
				if stack == "auth":
					if self.enableNullOk:
						output += " nullok"
				if stack == "account":
					if (self.forceBrokenShadow or self.enableLDAPAuth or
						self.enableKerberos or self.enableWinbindAuth):
						output += " broken_shadow"
			if args:
				output += " " + args
		output += "\n"
		return output

	def linkPAMService(self, src, dest):
		f = os.path.isfile(dest)
		l = os.path.islink(dest)
		if (f and not l) or (l and not f):
			# Create the link only if it doesn't exist yet or is invalid
			try:
				os.unlink(dest)
			except OSError:
				pass
			try:
				os.symlink(src, dest)
			except OSError:
				pass
	
	# Write PAM setup to the control file.
	def writePAM(self):
		f = None
		self.module_missing = {}
		output = ""
		try:
			f = openLocked(SYSCONFDIR+"/pam.d/"+AUTH_PAM_SERVICE_AC, 0644)

			output += "#%PAM-1.0\n"
			output += "# This file is auto-generated.\n"
			output += "# User changes will be destroyed the next time "
			output += "authconfig is run.\n"

			prevmodule = []
			for module in standard_pam_modules:
				if prevmodule and module[STACK] != prevmodule[STACK]:
					output += "\n"
				prevmodule = module
				if (module[MANDATORY] or
					(self.enableAFS and module[NAME] == "afs") or
					(self.enableAFSKerberos and module[NAME] == "afs.krb") or
					(self.enableCracklib and module[NAME] == "cracklib") or
					(self.enableEPS and module[NAME] == "eps") or
					(self.enableKerberos and module[NAME] == "krb5" and
						not module[ARGV] == argv_krb5_sc_auth) or
					(self.enableKerberos and self.enableSmartcard and
					    ((module[NAME] == "krb5" and module[ARGV] == argv_krb5_sc_auth) or
					    (module[NAME] == "permit" and module[STACK] == AUTH))) or
					(self.enableLDAPAuth and module[NAME] == "ldap") or
					(self.enableSmartcard and module[STACK] == AUTH and
						module[NAME] == "succeed_if" and module[LOGIC] == LOGIC_SKIPNEXT) or
					(self.enableSmartcard and module[NAME] == "pkcs11") or 
					(self.enableOTP and module[NAME] == "otp") or
					(self.enablePasswdQC and module[NAME] == "passwdqc") or
					(self.enableSMB and module[NAME] == "smb_auth") or
					(self.enableWinbindAuth and module[NAME] == "winbind") or
					(self.enableLocAuthorize and module[NAME] == "localuser") or
					(self.enablePAMAccess and module[NAME] == "access") or
					(self.enableMkHomeDir and module[NAME] == "mkhomedir") or
					(not self.enableSysNetAuth and module[STACK] == AUTH and
						module[NAME] == "succeed_if" and module[LOGIC] == LOGIC_REQUISITE)):
					output += self.formatPAMModule(module)

			# Write it out and close it.
			f.seek(0)
			f.truncate(0)
			f.write(output)
		finally:
			try:
				if f:
					f.close()
			except IOError:
				pass

		self.linkPAMService(AUTH_PAM_SERVICE_AC, SYSCONFDIR+"/pam.d/"+AUTH_PAM_SERVICE)

		return True

	def writeSysconfig(self):
		try:
			shv = shvfile.rcreate(SYSCONFDIR+"/sysconfig/authconfig")
		except IOError:
			return False

		shv.setBoolValue("USECRACKLIB", self.enableCracklib)
		shv.setBoolValue("USEDB", self.enableDB)
		shv.setBoolValue("USEHESIOD", self.enableHesiod)
		shv.setBoolValue("USELDAP", self.enableLDAP)
		shv.setBoolValue("USENIS", self.enableNIS)
		shv.setBoolValue("USEPASSWDQC", self.enablePasswdQC)
		shv.setBoolValue("USEWINBIND", self.enableWinbind)
		shv.setBoolValue("USEKERBEROS", self.enableKerberos)
		shv.setBoolValue("USELDAPAUTH", self.enableLDAPAuth)
		shv.setBoolValue("USESMARTCARD", self.enableSmartcard)
		shv.setBoolValue("FORCESMARTCARD", self.forceSmartcard)
		shv.setValue("PASSWDALGORITHM", self.passwordAlgorithm)
		shv.setValue("USEMD5", None)
		shv.setBoolValue("USESHADOW", self.enableShadow)
		shv.setBoolValue("USESMBAUTH", self.enableSMB)
		shv.setBoolValue("USEWINBINDAUTH", self.enableWinbindAuth)
		shv.setBoolValue("USELOCAUTHORIZE", self.enableLocAuthorize)
		shv.setBoolValue("USEPAMACCESS", self.enablePAMAccess)
		shv.setBoolValue("USEMKHOMEDIR", self.enableMkHomeDir)
		shv.setBoolValue("USESYSNETAUTH", self.enableSysNetAuth)

		shv.write(0644)
		shv.close()

		return True

	def writeNetwork(self):
		try:
			shv = shvfile.rcreate(SYSCONFDIR+"/sysconfig/network")
		except IOError:
			return False

		shv.setValue("NISDOMAIN", self.nisDomain)

		shv.write(0644)
		shv.close()

		return True

	def write(self):
		self.update()
		try:
			ret = self.writeLibuser()
			ret = ret and self.writeLogindefs()
			ret = ret and self.writeCache()

			if self.enableHesiod:
				ret = ret and self. writeHesiod()
			if self.enableLDAP:
				ret = ret and self.writeLDAP()
			if (self.enableKerberos or
				(self.enableWinbindAuth and
				self.smbSecurity == "ads")):
				ret = ret and self.writeKerberos()
			if self.enableSmartcard:
				ret = ret and self.writeSmartcard()
			if self.enableNIS:
				ret = ret and self.writeNIS()
			if self.enableSMB:
				ret = ret and self.writeSMB()
			if self.enableWinbind or self.enableWinbindAuth:
				ret = ret and self.writeWinbind()
			ret = ret and self.writeNSS()
			ret = ret and self.writePAM()
			ret = ret and self.writeSysconfig()
			ret = ret and self.writeNetwork()
		except IOError:
			return False
		return ret

	def writeChanged(self, ref):
		save_groups = [
	SaveGroup(self.writeCache, [("enableCache", "b")]),
	SaveGroup(self.writeHesiod, [("hesiodLHS", "i"), ("hesiodRHS", "i")]),
	SaveGroup(self.writeSMB, [("smbWorkgroup", "i"), ("smbServers", "i")]),
	SaveGroup(self.writeNIS, [("nisDomain", "c"), ("nisLocalDomain", "c"), ("nisServer", "c")]),
	SaveGroup(self.writeLDAP, [("ldapServer", "i"), ("ldapBaseDN", "c"), ("enableLDAPS", "b"),
		("ldapCacertDir", "c"), ("passwordAlgorithm", "i")]),
	SaveGroup(self.writeCache, [("enableCache", "b")]),
	SaveGroup(self.writeLibuser, [("passwordAlgorithm", "i")]),
	SaveGroup(self.writeLogindefs, [("passwordAlgorithm", "i")]),
	SaveGroup(self.writeKerberos5, [("kerberosRealm", "c"), ("kerberosKDC", "i"),
		("smbSecurity", "i"), ("smbRealm", "c"), ("smbServers", "i"),
		("kerberosAdminServer", "i"), ("kerberosRealmviaDNS", "b"),
		("kerberosKDCviaDNS", "b")]),
	SaveGroup(self.writeKerberos4, [("kerberosRealm", "c"), ("kerberosKDC", "i"),
		("kerberosAdminServer", "i")]),
	SaveGroup(self.writeSmartcard, [("smartcardAction", "i"), ("smartcardModule", "c")]),
	SaveGroup(self.writeWinbind, [("smbWorkgroup", "i"), ("smbServers", "i"),
		("smbRealm", "c"), ("smbSecurity", "i"), ("smbIdmapUid", "i"),
		("smbIdmapGid", "i"), ("winbindSeparator", "c"), ("winbindTemplateHomedir", "c"),
		("winbindTemplatePrimaryGroup", "c"), ("winbindTemplateShell", "c"),
		("winbindUseDefaultDomain", "b"), ("winbindOffline", "b")]),
	SaveGroup(self.writeNSS, [("enableDB", "b"), ("enableDirectories", "b"), ("enableWinbind", "b"),
		("enableOdbcbind", "b"), ("enableNIS3", "b"), ("enableNIS", "b"),
		("enableLDAPbind", "b"), ("enableLDAP", "b"), ("enableHesiodbind", "b"),
		("enableHesiod", "b"), ("enableDBIbind", "b"), ("enableDBbind", "b"),
		("enableCompat", "b"), ("enableWINS", "b"), ("enableNIS3", "b"), ("enableNIS", "b"),
		("preferDNSinHosts", "b")]),
	SaveGroup(self.writePAM, [("cracklibArgs", "c"), ("passwdqcArgs", "c"),
		("localuserArgs", "c"), ("pamAccessArgs", "c"), ("enablePAMAccess", "b"),
		("mkhomedirArgs", "c"), ("enableMkHomeDir", "b"), ("algoRounds", "c"),
		("passwordAlgorithm", "i"), ("enableShadow", "b"), ("enableNIS", "b"),
		("enableNullOk", "b"), ("forceBrokenShadow", "b"), ("enableLDAPAuth", "b"),
		("enableKerberos", "b"), ("enableSmartcard", "b"), ("forceSmartcard", "b"),
		("enableWinbindAuth", "b"), ("enableMkHomeDir", "b"), ("enableAFS", "b"),
		("enableAFSKerberos", "b"), ("enableCracklib", "b"), ("enableEPS", "b"),
		("enableOTP", "b"), ("enablePasswdQC", "b"), ("enableSMB", "b"),
		("enableLocAuthorize", "b"), ("enableSysNetAuth", "b"), ("winbindOffline", "b")]),
	SaveGroup(self.writeSysconfig, [("passwordAlgorithm", "i"), ("enableShadow", "b"), ("enableNIS", "b"),
		("enableLDAP", "b"), ("enableLDAPAuth", "b"), ("enableKerberos", "b"),
		("enableSmartcard", "b"), ("forceSmartcard", "b"),
		("enableWinbindAuth", "b"), ("enableWinbind", "b"), ("enableDB", "b"),
		("enableHesiod", "b"), ("enableCracklib", "b"), ("enablePasswdQC", "b"),
		("enableSMB", "b"), ("enableLocAuthorize", "b"), ("enablePAMAccess", "b"),
		("enableMkHomeDir", "b"), ("enableSysNetAuth", "b")]),
	SaveGroup(self.writeNetwork, [("nisDomain", "c")])]

		self.update()
		ret = True
		try:
			for group in save_groups:
				if group.attrsDiffer(self, ref):
					ret = ret and group.saveFunction()
		except IOError:
			return False
		return ret

	def probe(self):
		hostname = ""
		qname = ""
		results = []
		result = []
		hesiod = [
			[dnsclient.DNS_C_IN, "hs"],
			[dnsclient.DNS_C_IN, "ns"],
			[dnsclient.DNS_C_HS, "hs"],
			[dnsclient.DNS_C_HS, "ns"]
		]

		# get the local host name
		hostname = socket.getfqdn()
		if not hostname:
			return

		# terminate the host name
		if not hostname.endswith("."):
			hostname += "."

		# first, check for an LDAP server for the local domain
		domain = hostname[hostname.find("."):]
		qname = "_ldap._tcp" + domain
		results = dnsclient.query(qname, dnsclient.DNS_C_IN, dnsclient.DNS_T_SRV)

		for result in results:
			if result.dns_type == dnsclient.DNS_T_SRV:
				self.ldapServer = result.rdata.server.rstrip(".")
				self.ldapBaseDN = domain2dn(domain)

		# now, check for a Kerberos realm the local host or domain is in
		qname = "_kerberos." + hostname
		results = dnsclient.query(qname, dnsclient.DNS_C_IN, dnsclient.DNS_T_TXT)
		if not results:
			qname = "_kerberos" + domain
			results = dnsclient.query(qname, dnsclient.DNS_C_IN, dnsclient.DNS_T_TXT)

		for result in results:
			if result.dns_type == dnsclient.DNS_T_TXT:
				self.kerberosRealm = result.rdata.data
				if self.kerberosRealm:
					break

		if self.kerberosRealm:
			# now fetch server information for the realm
			qname = "_kerberos._udp." + self.kerberosRealm
			results = dnsclient.query(qname, dnsclient.DNS_C_IN, dnsclient.DNS_T_SRV)
			for result in results:
				if result.dns_type == dnsclient.DNS_T_SRV:
					qname = result.rdata.server.rstrip(".")
					if result.rdata.port:
						qname += ":" + result.rdata.port
					if self.kerberosKDC:
						self.kerberosKDC += "," + qname
					else:
						self.kerberosKDC = qname

			# now fetch admin server information for the realm
			qname = "_kerberos-adm._udp." + self.kerberosRealm
			results = dnsclient.query(qname, dnsclient.DNS_C_IN, dnsclient.DNS_T_SRV)
			for result in results:
				if result.dns_type == dnsclient.DNS_T_SRV:
					qname = result.rdata.server.rstrip(".")
					if result.rdata.port:
						qname += ":" + result.rdata.port
					if self.kerberosAdminServer:
						self.kerberosAdminServer += "," + qname
					else:
						self.kerberosAdminServer = qname

		# now check for SOA records for hesiod-style domains under .hs.DOMAIN
 		# and .ns.DOMAIN
		for h in hesiod:
			qname = h[1] + domain
			results = dnsclient.query(qname, h[0], dnsclient.DNS_T_SOA)
			for result in results:
				if (result.dns_type == dnsclient.DNS_T_SOA and
					result.dns_name == qname):
					self.hesiodLHS = "." + h[1]
					self.hesiodRHS = domain.rstrip(".")
					break

	def dump(self):
		'''return a printable representation of an object for debugging'''
		newobj={}
                for x in self.__dict__:
                    if not str(type(self.__dict__[x])) == "<type 'instancemethod'>":
                        newobj["authconfig_%s" % x] = self.__dict__[x]
		return newobj

	def printInfo(self):
		print simplejson.dumps(self.dump())

	def toggleShadow(self):
		# now, do file manipulation on the password files themselves.
		if self.enableShadow:
			os.system("/usr/sbin/pwconv")
			os.system("/usr/sbin/grpconv")
		else:
			os.system("/usr/sbin/pwunconv")
			os.system("/usr/sbin/grpunconv")
		return True

	def joinDomain(self, echo):
		if (self.enableWinbind or self.enableWinbindAuth) and self.joinUser:
			server = self.smbServers.split(",", 1)[0].split(" ", 1)[0].split("\t", 1)[0]
			domain = self.smbWorkgroup
			protocol = self.smbSecurity
			if not protocol:
				protocol = "ads"
			if protocol != "ads" and protocol != "domain":
				# Not needed -- "joining" is meaningless for other
				# models.
				return
			cmd = "/usr/bin/net join %s%s %s%s -U %s" % (
				domain and "-w " or "", domain,
				server and "-S " or "", server,
				self.joinUser)
			
			if echo:
				sys.stderr.write("[%s]\n" % cmd)
			if self.joinPassword:
				feedFork(cmd, echo, "sword:", self.joinPassword)
			else:
				os.system(cmd)

	def post(self, nostart):
		self.toggleShadow()
		toggleNisService(self.enableNIS, self.nisDomain, nostart)
		toggleSplatbindService(self.enableWinbind or self.enableWinbindAuth,
			PATH_WINBIND, PATH_WINBIND_PID,
			"winbind", nostart)
		toggleSplatbindService(self.enableDBbind,
			PATH_DBBIND, PATH_DBBIND_PID,
			"dbbind", nostart)
		toggleSplatbindService(self.enableDBIbind,
			PATH_DBIBIND, PATH_DBIBIND_PID,
			"dbibind", nostart)
		toggleSplatbindService(self.enableHesiodbind,
			PATH_HESIODBIND, PATH_HESIODBIND_PID,
			"hesiodbind", nostart)
		toggleSplatbindService(self.enableLDAPbind,
			PATH_LDAPBIND, PATH_LDAPBIND_PID,
			"ldapbind", nostart)
		toggleSplatbindService(self.enableOdbcbind,
			PATH_ODBCBIND, PATH_ODBCBIND_PID,
			"odbcbind", nostart)
		toggleCachingService(self.enableCache, nostart)

	def testLDAPCACerts(self):
		if self.enableLDAP or self.enableLDAPAuth:
			try:
				os.stat(self.ldapCacertDir)
			except OSError, (err, text):
				if err == errno.ENOENT:
					os.mkdir(self.ldapCacertDir, 0755)
		
			return isEmptyDir(self.ldapCacertDir)
		return False

	def rehashLDAPCACerts(self):
		if ((self.enableLDAP or self.enableLDAPAuth) and
			self.enableLDAPS):
			os.system("/usr/sbin/cacertdir_rehash " + self.ldapCacertDir)

	def downloadLDAPCACert(self):
		if not self.ldapCacertURL:
			return False
		self.testLDAPCACerts()
		try:
			readf = urllib2.urlopen(self.ldapCacertURL)
			writef = openLocked(self.ldapCacertDir + "/" + LDAP_CACERT_DOWNLOADED, 0644)
			writef.write(readf.read())
			readf.close()
			writef.close()
		except (IOError, OSError, ValueError):
			self.messageCB(_("Error downloading CA certificate"))
			return False
		self.rehashLDAPCACerts()
		return True
