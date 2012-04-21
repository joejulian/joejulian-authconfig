class authconfig (
    $allkerberosadminservers = { 'EXAMPLE.COM' => 'kerberos.example.com:749'},
    $allkerberoskdcs = {'EXAMPLE.COM' => 'kerberos.example.com:88'},
    $brokenshadow = "true",
    $cracklibargs = 'try_first_pass retry=3',
    $enablecache = "true",
    $enablecompat = "false",
    $enablecracklib = "true",
    $enabledb = "false",
    $enabledirectories = "false",
    $enablehesiod = "false",
    $enablekerberos = "false",
    $enableldap = "false",
    $enableldapauth = "false",
    $enableldaps = "false",
    $enablelocauthorize = "true",
    $enablemkhomedir = "false",
    $enablenis = "false",
    $enablenis3 = "false",
    $enablenullok = "true",
    $enablepamaccess = "false",
    $enablepasswdqc = "false",
    $enableshadow = "true",
    $enablesmartcard = "false",
    $enablesmb = "false",
    $enablesysnetauth = "false",
    $enablewinbind = "false",
    $enablewinbindauth = "false",
    $enablewins = "false",
    $forcesmartcard = "false",
    $kerberosadminserver = 'kerberos.example.com:749',
    $kerberoskdc = 'kerberos.example.com:88',
    $kerberoskdcviadns = "false",
    $kerberosrealm = 'EXAMPLE.COM',
    $kerberosrealmviadns = "false",
    $ldapbasedn = 'dc=example,dc=com',
    $ldapcacertdir = '/etc/openldap/cacerts',
    $ldapserver = 'ldap:///',
    $passwordalgorithm = 'md5',
    $smartcardaction = 'Ignore',
    $smartcardmodule = 'coolkey',
    $smbidmapgid = '16777216-33554431',
    $smbidmapuid = '16777216-33554431',
    $smbsecurity = 'user',
    $smbworkgroup = 'MYGROUP',
    $winbindtemplateshell = '/bin/false'
    )
{
    package { "python-simplejson":
        ensure => latest,
    }
    package { "ruby-json":
        ensure => latest,
    }
    package { ["authconfig", "pam_pkcs11",]:
        ensure => latest,
    }
    file { "/usr/local/lib/python":
        ensure => directory,
        owner  => 'root',
        mode   => 755,
    }
    file { "/usr/local/lib/python/authjsondump":
        ensure => directory,
        owner  => 'root',
        mode   => 755,
    }
    file { "/usr/local/lib/python/authjsondump/authinfo.py":
        source => "puppet://puppet/modules/authconfig/authinfo.py",
        owner  => 'root',
        mode   => 644,
    }
    file { "/etc/facts.d":
        ensure => directory,
        owner  => 'root',
        mode   => 755,
    }
    file { "/etc/facts.d/authjsondump":
        ensure => directory,
        owner  => 'root',
        mode   => 755,
    }
    file { "/etc/facts.d/authjsondump/authjsondump":
        source => "puppet://puppet/modules/authconfig/authjsondump",
        owner  => 'root',
        mode   => 700,
    }

    /* TODO: figure out what command is needed here
    if $authconfig_allkerberosadminservers != $allkerberosadminservers {
        exec { "allkerberosadminservers":
            command => "/bin/true",
        }
    }
    if $authconfig_allkerberoskdcs != $allkerberoskdcs {
        exec { "allkerberoskdcs":
            command => "/bin/true",
        }
    }
    }
    if $authconfig_enabledirectories != $enabledirectories {
        exec { "enabledirectories":
            command => $enabledirectories ? {
            },
        }
    }
    if $authconfig_enablenis3 != $enablenis3 {
        exec { "enablenis3":
            command => "/usr/sbin/authconfig --update --",
        }
    }
    if $authconfig_enablenullok != $enablenullok {
        exec { "enablenullok":
            command => "/usr/sbin/authconfig --update --",
        }
    }
    if $authconfig_enablepasswdqc != $enablepasswdqc {
        exec { "enablepasswdqc":
            command => "/usr/sbin/authconfig --update --",
        }
    }
    if $authconfig_ldapcacertdir != $ldapcacertdir {
        exec { "ldapcacertdir":
            command => "/usr/sbin/authconfig --update --",
        }
    }
    */
    if $authconfig_enablecache != $enablecache {
        exec { "enablecache":
            command => $enablecache ? {
                "true"  => "/usr/sbin/authconfig --update --enablecache",
                "false" => "/usr/sbin/authconfig --update --disablecace",
            },
        }
    }
    if $authconfig_enablehesiod != $enablehesiod {
        exec { "enablehesiod":
            command => $enablehesiod ? {
                "true"  => "/usr/sbin/authconfig --update --enablehesiod",
                "false" => "/usr/sbin/authconfig --update --disablehesiod",
            },
        }
    }
    if $authconfig_enablekerberos != $enablekerberos {
        exec { "enablekerberos":
            command => $enablekerberos ? {
                "true"  => "/usr/sbin/authconfig --update --enablekrb5",
                "false" => "/usr/sbin/authconfig --update --disablekrb5",
            },
        }
    }
    if $authconfig_enableldap != $enableldap {
        exec { "enableldap":
            command => $enableldap ? { 
                "true"  => "/usr/sbin/authconfig --update --enableldap",
                "false" => "/usr/sbin/authconfig --update --disableldap",
            },
        }
    }
    if $authconfig_enableldapauth != $enableldapauth {
        exec { "enableldapauth":
            command => $enableldapauth ? {
                "true"  => "/usr/sbin/authconfig --update --enableldapauth",
                "false" => "/usr/sbin/authconfig --update --disableldapauth",
            },
        }
    }
    if $authconfig_enableldaps != $enableldaps {
        exec { "enableldaps":
            command => $enableldaps ? { 
                "true"  => "/usr/sbin/authconfig --update --enableldaptls",
                "false" => "/usr/sbin/authconfig --update --disableldaptls",
            },
        }
    }
    if $authconfig_enablelocauthorize != $enablelocauthorize {
        exec { "enablelocauthorize":
            command => $enablelocauthorize ? {
                "true"  => "/usr/sbin/authconfig --update --enablelocauthorize",
                "false" => "/usr/sbin/authconfig --update --disablelocauthorize",
            },
        }
    }
    if $authconfig_enablemkhomedir != $enablemkhomedir {
        exec { "enablemkhomedir":
            command => $enablemkhomedir ? {
                "true"  => "/usr/sbin/authconfig --update --enablemkhomedir",
                "false" => "/usr/sbin/authconfig --update --disablemkhomedir",
            },
        }
    }
    if $authconfig_enablenis != $enablenis {
        exec { "enablenis":
            command => $enablenis ? {
                "true"  => "/usr/sbin/authconfig --update --enablenis",
                "false" => "/usr/sbin/authconfig --update --disablenis",
            },
        }
    }
    if $authconfig_enablepamaccess != $enablepamaccess {
        exec { "enablepamaccess":
            command => $enablepamaccess ? {
                "true"  => "/usr/sbin/authconfig --update --enablepamaccess",
                "false" => "/usr/sbin/authconfig --update --disablepamaccess",
            },
        }
    }
    if $authconfig_enableshadow != $enableshadow {
        exec { "enableshadow":
            command => $enableshadow ? {
                "true"  => "/usr/sbin/authconfig --update --enableshadow",
                "false" => "/usr/sbin/authconfig --update --disableshadow",
            },
        }
    }
    if $authconfig_enablesmartcard != $enablesmartcard {
        exec { "enablesmartcard":
            command => $enablesmartcard ? {
                "true"  => "/usr/sbin/authconfig --update --enablesmartcard",
                "false" => "/usr/sbin/authconfig --update --disablesmartcard",
            },
        }
    }
    if $authconfig_enablesmb != $enablesmb {
        exec { "enablesmb":
            command => $enablesmb ? {
                "true"  => "/usr/sbin/authconfig --update --enablesmbauth",
                "false" => "/usr/sbin/authconfig --update --disablesmbauth",
            },
        }
    }
    if $authconfig_enablesysnetauth != $enablesysnetauth {
        exec { "enablesysnetauth":
            command => $enablesysnetauth ? {
                "true"  => "/usr/sbin/authconfig --update --enablesysnetauth",
                "false" => "/usr/sbin/authconfig --update --disablesysnetauth",
            },
        }
    }
    if $authconfig_enablewinbind != $enablewinbind {
        exec { "enablewinbind":
            command => $enablewinbind ? {
                "true"  => "/usr/sbin/authconfig --update --enablewinbind",
                "false" => "/usr/sbin/authconfig --update --disablewinbind",
            },
        }
    }
    if $authconfig_enablewinbindauth != $enablewinbindauth {
        exec { "enablewinbindauth":
            command => $enablewinbindauth ? {
                "true"  => "/usr/sbin/authconfig --update --enablewinbindauth",
                "false" => "/usr/sbin/authconfig --update --disablewinbindauth",
            },
        }
    }
    if $authconfig_enablewins != $enablewins {
        exec { "enablewins":
            command => $enablewins ? {
                "true"  => "/usr/sbin/authconfig --update --enablewins",
                "false" => "/usr/sbin/authconfig --update --disablewins",
            },
        }
    }
    if $authconfig_forcesmartcard != $forcesmartcard {
        exec { "forcesmartcard":
            command => $forcesmartcard ? {
                "true"  => "/usr/sbin/authconfig --update --enablerequiresmartcard",
                "false" => "/usr/sbin/authconfig --update --disablerequiresmartcard",
            },
        }
    }
    if $authconfig_kerberosadminserver != $kerberosadminserver {
        exec { "kerberosadminserver":
            command => "/usr/sbin/authconfig --update --krb5adminserver=${kerberosadminserver}",
        }
    }
    if $authconfig_kerberoskdc != $kerberoskdc {
        exec { "kerberoskdc":
            command => "/usr/sbin/authconfig --update --krb5kdc=${kerberoskdc}",
        }
    }
    if $authconfig_kerberoskdcviadns != $kerberoskdcviadns {
        exec { "kerberoskdcviadns":
            command => $kerberoskdcviadns ? {
                "true"  => "/usr/sbin/authconfig --update --enablekrb5kdcdns",
                "false" => "/usr/sbin/authconfig --update --disablekrb5kdcdns",
            },
        }
    }
    if $authconfig_kerberosrealm != $kerberosrealm {
        exec { "kerberosrealm":
            command => "/usr/sbin/authconfig --update --krb5realm=${kerberosrealm}",
        }
    }
    if $authconfig_kerberosrealmviadns != $kerberosrealmviadns {
        exec { "kerberosrealmviadns":
            command => $kerberosrealmviadns ? {
                "true"  => "/usr/sbin/authconfig --update --enablekrb5realmdns",
                "false" => "/usr/sbin/authconfig --update --disablekrb5realmdns",
            },
        }
    }
    if $authconfig_ldapbasedn != $ldapbasedn or $authconfig_ldapserver != $ldapserver {
        exec { "ldapbasedn":
            command => "/usr/sbin/authconfig --updateall --ldapbasedn='${ldapbasedn}' --ldapserver='${ldapserver}'",
        }
    }
    if $authconfig_passwordalgorithm != $passwordalgorithm {
        exec { "passwordalgorithm":
            command => "/usr/sbin/authconfig --update --passalgo=${passwordalgorithm}",
        }
    }
    if $authconfig_smartcardaction != $smartcardaction {
        exec { "smartcardaction":
            command => $smartcardaction ? {
                "Ignore" => "/usr/sbin/authconfig --update --smartcardaction=1",
                "Lock"   => "/usr/sbin/authconfig --update --smartcardaction=0",
            },
        }
    }
    if $authconfig_smartcardmodule != $smartcardmodule {
        exec { "smartcardmodule":
            command => "/usr/sbin/authconfig --update --smartcardmodule=${smartcardmodule}",
        }
    }
    if $authconfig_smbidmapgid != $smbidmapgid {
        exec { "smbidmapgid":
            command => "/usr/sbin/authconfig --update --smbidmapgid=${smbidmapgid}",
        }
    }
    if $authconfig_smbidmapuid != $smbidmapuid {
        exec { "smbidmapuid":
            command => "/usr/sbin/authconfig --update --smbidmapuid=${smbidmapuid}",
        }
    }
    if $authconfig_smbsecurity != $smbsecurity {
        exec { "smbsecurity":
            command => "/usr/sbin/authconfig --update --smbsecurity=${smbsecurity}",
        }
    }
    if $authconfig_smbworkgroup != $smbworkgroup {
        exec { "smbworkgroup":
            command => "/usr/sbin/authconfig --update --smbworkgroup=${smbworkgroup}",
        }
    }
    if $authconfig_winbindtemplateshell != $winbindtemplateshell {
        exec { "winbindtemplateshell":
            command => "/usr/sbin/authconfig --update --winbindtemplateshell=${winbindtemplateshell}",
        }
    }
}
