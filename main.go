package main

import (
	"fmt"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/siemens/GoScans/utils"
	"net"
	"strconv"
	"strings"
	"time"

	"AD_Discovery/active_directory"
)

type ldapConf struct {
	ldapServer   string // (Optional) Active Directory server to query host details
	ldapDomain   string // (Optional) Active Directory access credentials
	ldapUser     string // ...
	ldapPassword string // ...

	realm         string // (Optional) Default Realm for GSSAPI
	KrbConfigFile string // (Optional) Path to krb5.conf file
}

func NewGSSAPIOptionsFromLDAPConf(conf ldapConf, domain string, logger utils.Logger) *active_directory.GSSAPIOptions {
	defaultRealm := strings.ToUpper(conf.realm)

	opts := active_directory.GSSAPIOptions{
		DefaultRealm: defaultRealm,
	}

	if conf.KrbConfigFile != "" {
		opts.ConfigFilePath = conf.KrbConfigFile
		return &opts
	}

	var realms []config.Realm

	// Add default realm
	realmDomain := strings.ToLower(defaultRealm)
	kdcs := resolveSRVIPs("kerberos", "tcp", realmDomain, logger)

	realms = append(realms, config.Realm{
		Realm:         defaultRealm,
		KDC:           kdcs,
		DefaultDomain: realmDomain,
	})

	// Add second realm if applicable
	targetRealm := strings.ToUpper(domain)
	if targetRealm != "" && targetRealm != defaultRealm {
		targetDomain := strings.ToLower(targetRealm)
		targetKdcs := resolveSRVIPs("kerberos", "tcp", targetDomain, logger)

		realms = append(realms, config.Realm{
			Realm:         targetDomain,
			KDC:           targetKdcs,
			DefaultDomain: targetDomain,
		})
	}

	opts.Realms = realms
	return &opts
}

// resolveSRVIPs resolves SRV records to IP:port addresses
func resolveSRVIPs(service, proto, domain string, logger utils.Logger) []string {
	var results []string
	_, srvs, err := net.LookupSRV(service, proto, domain)
	if err != nil {
		logger.Debugf("SRV lookup failed for _%s._%s.%s: %v", service, proto, domain, err)
		return results
	}

	for _, srv := range srvs {
		target := strings.TrimSuffix(srv.Target, ".")
		ips, err := net.LookupHost(target)
		if err != nil {
			logger.Debugf("Failed to resolve SRV target host %s: %v", target, err)
			continue
		}
		for _, ip := range ips {
			results = append(results, net.JoinHostPort(ip, fmt.Sprint(srv.Port)))
		}
	}
	return results
}

func main() {
	logger := utils.NewTestLogger()

	fmt.Println("--- Starting Active Directory Functionality Demo ---")

	ldapHost := "TESTLAB2.LOCAL"
	fqdnLDAPHost := "DC2.TESTLAB2.LOCAL"
	ldapPort, _ := strconv.Atoi("389")
	ldapUser := "vboxuser"
	ldapPassword := "windows1"
	searchCnLdap := "DC2"

	fmt.Println("\n--- LDAP Query Demo ---")

	// Choose authentication method
	useGSSAPI := true

	var gssapiOptions *active_directory.GSSAPIOptions

	if useGSSAPI {
		conf := ldapConf{
			ldapServer:    ldapHost,
			ldapDomain:    ldapHost,
			ldapUser:      ldapUser,
			ldapPassword:  ldapPassword,
			realm:         "TESTLAB.LOCAL", // you can adjust
			KrbConfigFile: "",              // leave empty for dynamic mode
		}
		gssapiOptions = NewGSSAPIOptionsFromLDAPConf(conf, ldapHost, logger)
		gssapiOptions.ServicePrincipalName = fqdnLDAPHost
	} else {
		gssapiOptions = nil
	}

	adResultLdap := active_directory.LdapQuery(
		logger,
		searchCnLdap,
		ldapHost,
		ldapPort,
		ldapUser,
		ldapPassword,
		60*time.Second,
		gssapiOptions,
	)

	if adResultLdap != nil && adResultLdap.Name != "" {
		fmt.Printf("LDAP Query Result:\n%+v\n", adResultLdap)
	} else {
		fmt.Println("LDAP Query did not return a result or encountered an error.")
	}

	fmt.Println("\n--- Demo Finished ---")
}
