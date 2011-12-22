"""
LDAP Command Line interface.
"""

import ldap
import csv
import sys

class LdapUtil:
  """
  LdapUtil class.

  """
  #def __init__(self, uri=None, base=None, basep=None, baseg=None, adm=None,
  #             passwd=None, verbose=False, test=False):
  def __init__(self, args):
    """
    One big overloaded method
    """
    self.uri = args.uri
    self.base = args.basedn
    self.basep = args.basep+','+args.basedn
    self.baseg = args.baseg+','+args.basedn
    self.ldapconn = ldap.initialize(self.uri)
    self.scheme_ldapPublicKey = args.scheme_ldapPublicKey
    try:
      self.ldapconn.simple_bind_s(args.binddn, args.passwd)
      self.ldapconn.ldap_base_db = self.base
      self.ldapconn.set_option(ldap.VERSION, ldap.VERSION3)
    except ldap.LDAPError, e:
      print e[0]['desc']
      sys.exit(1)
    self.verbose = args.verbose
    self.test = args.test
    if self.verbose or self.test:
      print "Connection successful"
  #def connect(self):
  #  print self.uri

  def search(self, base=None, sfilter=None, attrib=None):
    """Perform a subtree scope search.
    """
    if base == None:
      base = self.base
    s_obj = self.ldapconn.search_s(base, ldap.SCOPE_SUBTREE, sfilter, attrib)
    if self.verbose:
      print "searching: %s, %s" % (base, sfilter)
    return s_obj

  def gethighestuid(self):
    """Get the Highest UID.
    """
    records = self.search(sfilter="uidNumber=*",
                          attrib=['uidNumber', 'gidNumber'])
    big = 0
    for record in records:
      if big < record[1]['uidNumber'][0]:
        big = record[1]['uidNumber'][0]
      if self.verbose:
        print "biggest ID: %s" % big
    return big

  def getgroupid(self, group=None):
    """Return gid if exists, else return guest group id.
    """
    search_group = self.search(self.baseg, "cn="+group, ['dn','gidNumber'])
    return search_group[0][1]['gidNumber'][0]

  def getgroups(self):
    """Retrieves a groupname with its ids.
    Returns a dictionaries with group name (cn) values on group ID (gidNumber)
    keys
    """
    search_group = self.search(self.baseg, "cn=*", ['cn','gidNumber'])
    groups = {}
    for group in search_group:
      key = group[1]['gidNumber'][0]
      val = group[1]['cn'][0]
      groups[key] = val
    return groups

  def adduser(self, filename=None, localuid=None, localgid=None,
              shell='/bin/bash'):
    """Add a user, using the next available UID.
    """
    users = self.readfile(filename)
    for user in users:
      name = user[0]
      surname = user[1]
      login = user[2]
      ssh_key = user[3]
      ldap_dn = "uid=%s,%s" % (login, self.basep)
      if localuid == None:
        uid = str(int(self.gethighestuid()) + 1)
      if localgid == None:
        gid = uid
        if self.test:
          print "test adding group: %s" % login
        else:
          self.addgroup(login, gid)
      else:
        gid = self.getgroupid(localgid)
      attrs = [
        ('objectclass', ['person',
          'organizationalPerson',
          'inetOrgPerson',
          'posixAccount',
          #'ldapPublicKey',
          'shadowAccount'
          ]),
        ('homeDirectory', ['/home/'+login]),
        ('loginShell', [shell]),
        ('uid', [login]),
        ('sn', [surname]),
        ('givenName', [name]),
        ('cn', [name +' '+ surname]),
        ('uidNumber', [uid]),
        ('gidNumber', [gid]),
        #('sshPublicKey', [ssh_key]),
      ]
      search_user = self.search(self.basep, "uid="+login, ['uid','uidNumber'])
      if search_user.__len__() > 0:
        user_exists = True
      else:
        user_exists = False
      if self.verbose:
        print ldap_dn, attrs
        if self.test:
          print "testing add user: %s" % login
      if user_exists:
        print "User already exists"
      else:
        if self.scheme_ldapPublicKey:
          attrs[0][1].append('ldapPublicKey')
          attrs.append(('sshPublicKey', [ssh_key]))
        else:
          try:
            self.ldapconn.add_s(ldap_dn, attrs)
            if self.verbose:
              print "User '%s' added" % login
          except ldap.LDAPError, err:
            print "User ERROR: %s => %s" % (ldap_dn, err[0]['desc'])

  def deluser(self, filename=None):
    """Delete a user.
    """
    users = self.readfile(filename)
    for user in users:
      # search user
      s_obj = self.search(self.basep, "uid="+user[2], ['dn','uidNumber'])
      if len(s_obj) > 0:
        if self.test:
          print "testing delete for: %s" % user[2]
        else:
          ldap_dn = s_obj[0][0]
          self.ldapconn.delete_s(ldap_dn)
          print "user '%s' deleted" % user[2]
      else:
        print "user '%s' not found" % user[2]
      # search corresponding group
      s_obj = self.search(self.baseg, "cn="+user[2], ['dn','uidNumber'])
      if len(s_obj) > 0:
        ldap_dn = s_obj[0][0]
        self.ldapconn.delete_s(ldap_dn)
        print "group '%s' deleted" % user[2]
      else:
        print "group '%s' not found" % user[2]

  def addgroup(self, group=None, gid=None):
    """Add a group.
    """
    ldap_dn = "cn=%s,%s" % (group, self.baseg)
    status = None
    attrs = [
      ('objectclass', ['posixGroup']),
        ('gidNumber', [gid]),
        ('description', [group]),
        ('cn', [group]),
    ]
    if self.verbose:
      print ldap_dn, attrs
      search_group = self.search(self.baseg, "cn="+group, ['dn','gidNumber'])
      if search_group.__len__() > 0:
        group_exists = True
      else:
        group_exists = False
    if self.test:
      print "would add: %s" % group
      if group_exists > 0:
        print "%s does exists, so that part would fail, account will created though" % group
      else:
        status = 1
    else:
      try:
        self.ldapconn.add_s(ldap_dn, attrs)
        if self.verbose:
          print "Group '%s' added" % group
        status = 1
      except ldap.LDAPError, err:
        print "Group ERROR: %s => %s" % (ldap_dn, err[0]["desc"])
    return status

  def readfile(self, filename=None):
    """Read a csv file to use as input.
    Format must be: "surname, name:login:ssh-key"
    """
    if filename == None:
      print "I need a file to actually work"
      sys.exit(1)
    users = csv.reader(open(filename), delimiter=':', quoting=csv.QUOTE_NONE)
    lines = []
    for row in users:
      (surname, name) = row[0].split(',', 2)
      login = row[1]
      ssh_key = row[2]
      lines.append((name.lstrip(), surname, login, ssh_key))
    return lines
