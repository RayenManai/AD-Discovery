package main

import (
	"fmt"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/siemens/GoScans/utils"
	"strconv"
	"time"

	"AD_Discovery/active_directory"
)

func main() {
	logger := utils.NewTestLogger()

	fmt.Println("--- Starting Active Directory Functionality Demo ---")

	ldapHost := "HBO.LOCAL"
	fqdnLDAPHost := "DC2.HBO.LOCAL"
	ldapPort, _ := strconv.Atoi("389")
	ldapUser := "administrator"
	ldapPassword := "windows"
	searchCnLdap := "DC2"

	fmt.Println("\n--- LDAP Query Demo ---")

	// Choose authentication method
	useGSSAPI := true

	var gssapiOptions *active_directory.GSSAPIOptions

	if useGSSAPI {
		// Decide between config file or programmatic config
		useConfigFile := false

		if useConfigFile {
			gssapiOptions = &active_directory.GSSAPIOptions{
				DefaultRealm:         "MARVEL.LOCAL",
				ConfigFilePath:       "/etc/krb5.conf",
				ServicePrincipalName: "ldap/DC2.HBO.local",
			}
		} else {
			gssapiOptions = &active_directory.GSSAPIOptions{
				DefaultRealm: "MARVEL.LOCAL",
				Realms: []config.Realm{
					{
						Realm:         "MARVEL.LOCAL",
						KDC:           []string{"192.168.56.101"},
						AdminServer:   []string{"192.168.56.101"},
						DefaultDomain: "marvel.local",
					},
					{
						Realm:         ldapHost,
						KDC:           []string{"192.168.56.111"},
						AdminServer:   []string{"192.168.56.111"},
						DefaultDomain: ldapHost,
					},
				},
				ServicePrincipalName: fqdnLDAPHost,
			}
		}
	} else {
		// Standard LDAP auth - no GSSAPI options
		gssapiOptions = nil
	}

	// Execute LDAP query
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
