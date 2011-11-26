#!/usr/bin/python2.6
"""LDAP CLI utility"""
import sys
import argparse
import ConfigParser
from ldaputil import LdapUtil

def parseargs():
  """Parses arguments using argparse.
  Options are defined in here and passed in two objetcs with args and options.

  Args: None

  Returns:
    options:
    args:
  """
  parser = argparse.ArgumentParser(description='LDAP cli')
  addgroup = parser.add_mutually_exclusive_group()
  parser.add_argument('-f', '--file', dest='filename', default=None,
                      help='Reads a file to parse.')
  addgroup.add_argument('-a', '--add', dest='add', action="store_true",
                      help='Add user(s) from file given at -f.')
  addgroup.add_argument('-d', '--delete', dest='delete', action="store_true",
                      help='Delete user(s) from file given at -f.')
  parser.add_argument('-g', '--group', dest='group', default=None,
                      help='Primary group for new users, only useful with -a.')
  addgroup.add_argument('-G', '--groups', dest='groups', action="store_true",
                      help='Show available groups to use on -g/--group.')
  parser.add_argument('-D', '--binddn', dest='binddn',
                      help='bind DN', metavar='DN',
                      default='cn=binddn,dc=example,dc=com')
  parser.add_argument('-b', '--base', dest='basedn',
                      help='base DN', metavar='DN',
                      default='dc=example,dc=com')
  parser.add_argument('-w', '--passwd', dest='passwd', default='ijFYNcSNctBYg',
                      help='bind password (for simple authentication)')
  parser.add_argument('-H', '--uri', dest='uri',
                      help='LDAP Uniform Resource Identifier',
                      default='localhost')
  parser.add_argument('-c', '--config', dest='configfile',
                      help='Reads a file to parse.', metavar='CONFIG')
  parser.add_argument('-n', '--test', dest='test', action='store_true',
                      help='Test mode, no action executed')
  parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                      help='Verbose output')
  parser.set_defaults(baseg='ou=Groups', basep='ou=People')
  args = parser.parse_args()
  if args.configfile:
    #print 'config', args.configfile
    config = ConfigParser.ConfigParser()
    config.read(args.configfile)
    try:
      args.basedn = config.get('Main', 'basedn')
      args.uri = config.get('Main', 'uri')
      args.binddn = config.get('Main', 'binddn')
      args.passwd = config.get('Main', 'passwd')
      print args
    except args.NoSectionError:
      print """Uncomplete ini file, please see sample file\n\nRequires a Main
section and basedn,bindn,passwd,uri options"""
      sys.exit(1)
  return args


def main():
  """Main function.
  """
  args = parseargs()
  myldap = LdapUtil(args.uri , args.basedn, args.basep, args.baseg, args.binddn,
                    args.passwd, args.verbose, args.test)
  if args.groups:
    groups = myldap.getgroups()
    for group in groups:
      print 'group[%s] = %s'% (group, groups[group])
  elif args.add:
    myldap.adduser(filename = args.filename, localgid = args.group)
  elif args.delete:
    myldap.deluser(args.filename)

  # testing search and addUser
  #myldap.search(filter='cn=*', attrib=['cn'])
  #for x in range(1,10):
  #  myldap.addUser("test"+str(x), "test"+str(x))

if __name__ == "__main__":
  if len(sys.argv) == 1:
    sys.argv.append('--help')
  main()
