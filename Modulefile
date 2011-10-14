name    'joejulian-authconfig'
version '0.1.1'
source 'git@github.com:joejulian/joejulian-authconfig.git'
author 'Joe Julian'
license 'GPLv2.1'
summary 'A module for managing auth mechanisms on RedHat/Fedora based distros'
description 'This module is used for managing the auth mechanisms on a RedHat/Fedora based distro.

This is implemented as a parameterized class. The default parameters are the default settings shipped with RHEL.

Example use:
class { authconfig:
    enableldap => "true",
    enableldapauth => "true",
    enableldaps => "true",
    ldapbasedn => "dc=example,dc=com",
    ldapserver => "ldap://ldap1/,ldap://ldap2/"
}

class { authconfig::ldap:
    suffix => "dc=example,dc=com",
    rootbinddn => "cn=manager,dc=example,dc=com",
    serverlist => [ "ldap://ldap1/" ],
    base => "dc=example,dc=com"
}
'
    
project_page 'https://github.com/joejulian/joejulian-authconfig'
