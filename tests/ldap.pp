class { authconfig::ldap:
    suffix => "dc=example,dc=com",
    rootbinddn => "cn=manager,dc=example,dc=com",
    serverlist => [ "ldap://ldap1/" ],
    base => "dc=example,dc=com"
}
