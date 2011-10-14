class { authconfig:
    enableldap => "true",
    enableldapauth => "true",
    enableldaps => "true",
    ldapbasedn => "dc=example,dc=com",
    ldapserver => "ldap://ldap1/,ldap://ldap2/"
}
