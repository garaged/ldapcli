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
  def __init__(self, args):
    """
    One big overloaded method
    """
    self.args = dict()
    tempo = vars(args)
    for k in vars(args):
      print k, tempo[k]
      self.args[k] = tempo[k]
    self.args['basep'] = args.basep+','+args.basedn
    self.args['baseg'] = args.baseg+','+args.basedn
    self.ldapconn = ldap.initialize(self.args['uri'])
    try:
      self.ldapconn.simple_bind_s(args.binddn, args.passwd)
      self.ldapconn.ldap_base_db = self.args['basedn']
      self.ldapconn.set_option(ldap.VERSION, ldap.VERSION3)
    except ldap.LDAPError, error:
      print error[0]['desc']
      sys.exit(1)
    if self.args['verbose'] or self.args['test']:
      print "Connection successful"

  def search(self, base=None, sfilter=None, attrib=None):
    """Perform a subtree scope search.
    """
    if self.args['verbose']:
      print "searching: %s, %s" % (base, sfilter)
    if base == None:
      base = self.args['basedn']
    s_obj = self.ldapconn.search_s(base, ldap.SCOPE_SUBTREE, sfilter, attrib)
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
      if self.args['verbose']:
        print "biggest ID: %s" % big
    return big

  def getgroupid(self, group=None):
    """Return gid if exists, else return guest group id.
    """
    search_group = self.search(self.args['baseg'],
      "cn="+group, ['dn','gidNumber'])
    print search_group
    return search_group[0][1]['gidNumber'][0]

  def getgroups(self):
    """Retrieves a groupname with its ids.
    Returns a dictionaries with group name (cn) values on group ID (gidNumber)
    keys
    """
    search_group = self.search(self.args['baseg'], "cn=*", ['cn','gidNumber'])
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
    users = readfile(filename)
    for user in users:
      name = user[0]
      surname = user[1]
      login = user[2]
      ssh_key = user[3]
      ldap_dn = "uid=%s,%s" % (login, self.args['basep'])
      if localuid == None:
        uid = str(int(self.gethighestuid()) + 1)
      if localgid == None:
        gid = uid
        if self.args['test']:
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
      ]
      user_exists = self.exists(self.args['basep'],
        "uid="+login, ['uid','uidNumber'])
      if self.args['verbose']:
        print ldap_dn, attrs
        if self.args['test']:
          print "testing add user: %s" % login
      if user_exists:
        print "User already exists"
      else:
        if self.args['scheme_ldappublickey']:
          attrs[0][1].append('ldapPublicKey')
          attrs.append(('sshPublicKey', [ssh_key]))
        if self.args['test']:
          print "test adding user: %s" % login
        else:
          try:
            self.ldapconn.add_s(ldap_dn, attrs)
            if self.args['verbose']:
              print "User '%s' added" % login
          except ldap.LDAPError, err:
            print "User ERROR: %s => %s" % (ldap_dn, err[0]['desc'])

  def deluser(self, filename=None):
    """Delete a user.
    """
    users = readfile(filename)
    for user in users:
      # search user
      if self.exists(self.args['basep'], "uid="+user[2], ['dn','uidNumber']):
        if self.args['test']:
          print "testing delete user: %s" % user[2]
        else:
          self.ldapconn.delete_s("uid="+user[2]+","+self.args['basep'])
          print "user '%s' deleted" % user[2]
      else:
        print "user '%s' not found" % user[2]
      # search corresponding group
      if self.exists(self.args['baseg'], "cn="+user[2], ['dn','gidNumber']):
        if self.args['test']:
          print "testing delete group: %s" % user[2]
        else:
          self.ldapconn.delete_s("cn="+user[2]+","+self.args['baseg'])
          print "group '%s' deleted" % user[2]
      else:
        print "group '%s' not found" % user[2]

  def exists(self, base, search, params):
    """Check for existing items"""
    exits = False
    s_obj = self.search(base, search, params)
    if len(s_obj) > 0:
      if self.args['verbose']:
        for row in s_obj:
          print row
        exits = True
    return exits

  def addgroup(self, group=None, gid=None):
    """Add a group.
    """
    ldap_dn = "cn=%s,%s" % (group, self.args['baseg'])
    attrs = [
      ('objectclass', ['posixGroup']),
        ('gidNumber', [gid]),
        ('description', [group]),
        ('cn', [group]),
    ]
    group_exists = self.exists(self.args['baseg'],
      "cn="+group, ['dn','gidNumber'])
    if self.args['verbose']:
      print ldap_dn, attrs
    if self.args['test']:
      if group_exists > 0:
        print "%s does exists, add will not be attempted" % group
      else:
        print "would add: %s" % group
    else:
      if group_exists > 0:
        print "Group exists, not trying to create it"
      else:
        try:
          self.ldapconn.add_s(ldap_dn, attrs)
          if self.args['verbose']:
            print "Group '%s' added" % group
        except ldap.LDAPError, err:
          print "Group ERROR: %s => %s" % (ldap_dn, err[0]["desc"])

def readfile(filename=None):
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
