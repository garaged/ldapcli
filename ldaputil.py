"""
LDAP Command Line interface.
"""

import ldap
import csv

class LdapUtil:
  """
  LdapUtil class.

  """
  def __init__(self, uri=None, base=None, basep=None, baseg=None, adm=None, passwd=None, verbose=False, test=False):
    """
    One big overloaded method
    """
    self.uri = uri
    self.base = base
    self.basep = basep+','+base
    self.baseg = baseg+','+base
    self.ldapconn = ldap.open(uri)
    self.ldapconn.simple_bind_s(adm, passwd)
    self.ldapconn.ldap_base_db = base
    self.ldapconn.set_option(ldap.VERSION, ldap.VERSION3)
    self.verbose = verbose
    self.test = test
    if self.verbose or self.test:
      print "Connection successful"
    pass
  #def connect(self):
  #  print self.uri

  def search(self, filter=None, attrib=None):
    """Testing basic search"""
    s = self.ldapconn.search_s(self.base, ldap.SCOPE_SUBTREE, filter, attrib)
    if self.verbose:
      print "searching"
    return s

  def getHighestUid(self):
    list = self.search("uidNumber=*", ['uidNumber', 'gidNumber'])
    big = 0
    for i in list:
      if big < i[1]['uidNumber'][0]:
        big = i[1]['uidNumber'][0]
      if self.verbose:
        print "biggest ID: %s" % big
    return big

  def addUser(self, filename=None, localuid=None, localgid=None):
    users = self.readFile(filename)
    for u in users:
      name = u[0]
      surname = u[1]
      login = u[2]
      ssh_key = u[3]
      dn = "uid=%s,%s" % (login, self.basep)
      if localuid == None:
        uid = str(int(self.getHighestUid()) + 1)
      if localgid == None:
        gid = uid
        self.addGroup(login, gid)
      else:
        gid = self.getGroupId(localgid)

      attrs = [
        ('objectclass', ['person', 'organizationalPerson',
          'inetOrgPerson',
          'posixAccount',
          'ldapPublicKey',
          'shadowAccount'
          ]),
        ('homeDirectory', ['/home/'+login]),
        ('loginShell', ['/bin/bash']),
        ('uid', [login]),
        ('sn', [surname]),
        ('givenName', [name]),
        ('cn', [name +' '+ surname]),
        ('uidNumber', [uid]),
        ('gidNumber', [gid]),
        ('sshPublicKey', [ssh_key]),
      ]
      try:
        self.ldapconn.add_s(dn, attrs)
        print "User '%s' added" % login
      except ldap.LDAPError, e:
        print "User ERROR: %s => %s" % (dn, e[0]['info'])
        #print "%s => %s" % (dn, attrs)
        #print e

  def delUser(self, filename=None):
    users = self.readFile(filename)
    for u in users:
      # search user
      s = self.search(self.basep, "uid="+u[2], ['dn','uidNumber'] )
      if len(s) > 0:
        dn = s[0][0]
        self.ldapconn.delete_s(dn)
        print "user '%s' deleted" % u[2]
      else:
        print "user '%s' not found" % u[2]
      # search corresponding group
      s = self.search(self.baseg, "cn="+u[2], ['dn','uidNumber'] )
      if len(s) > 0:
        dn = s[0][0]
        self.ldapconn.delete_s(dn)
        print "group '%s' deleted" % u[2]
      else:
        print "group '%s' not found" % u[2]

  def addGroup(self, group=None, gid=None):
    dn = "cn=%s,%s" % (group, self.baseg)
    print dn
    attrs = [
      ('objectclass', ['posixGroup']),
        ('gidNumber', [gid]),
        ('description', [group]),
        ('cn', [group]),
    ]
    try:
      print dn, attrs
      self.ldapconn.add_s(dn, attrs)
      print "Group '%s' added" % group
    except ldap.LDAPError, e:
      print "Group ERROR: %s => %s" % (dn, e[0]["desc"])


  def readFile(self, filename=None):
    if filename == None:
      print "I need a file to actually work"
      sys.exit(1)
    users = csv.reader(open(filename), delimiter=':', quoting=csv.QUOTE_NONE)
    list = []
    for row in users:
      (surname, name) = row[0].split(',', 2)
      login = row[1]
      ssh_key = row[2]
      list.append((name.lstrip(), surname, login, ssh_key))
    return list

