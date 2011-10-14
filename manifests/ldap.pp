class authconfig::ldap($suffix, 
    $rootbinddn, 
    $serverlist = "ldap://ldap1/", 
    $basepasswd = "ou=People,$base", 
    $baseshadow = "ou=People,$base", 
    $basegroup  = "ou=Group,$base", 
    $basehosts  = "ou=Hosts,$base", 
    $base) {

    file { "/etc/openldap/cacerts":
        source => "puppet://puppet/modules/authconfig/cacerts",
        recurse => true,
    }

    file { "/etc/ldap.conf":
        owner => root,
        group => root,
        mode  => 0644,
        content => template("authconfig/ldap.conf.erb"),
    }
}
