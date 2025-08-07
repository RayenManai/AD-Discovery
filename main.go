package main

import (
	"fmt"
	"github.com/siemens/GoScans/utils"
	"strconv"
	"time"

	"AD_Discovery/active_directory"
)

func main() {
	logger := utils.NewTestLogger()

	fmt.Println("--- Starting Active Directory Functionality Demo ---")

	ldapHost := ""
	ldapPort, _ := strconv.Atoi("389")
	ldapUser := ""
	ldapPassword := ""
	searchCnLdap := ""

	fmt.Println("\n--- LDAP Query Demo ---")

	// Choose authentication method
	useGSSAPI := true

	var gssapiOptions *active_directory.GSSAPIOptions

	if useGSSAPI {
		// Decide between config file or programmatic config
		useConfigFile := true

		if useConfigFile {
			gssapiOptions = &active_directory.GSSAPIOptions{
				Realm:                "",
				ConfigFilePath:       "",
				ServicePrincipalName: "",
			}
		} else {
			gssapiOptions = &active_directory.GSSAPIOptions{
				Realm:                "",
				KDCs:                 []string{""},
				ServicePrincipalName: "",
				DefaultDomain:        "",
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
