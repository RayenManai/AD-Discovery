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

	// --- LDAP Query Demo ---
	fmt.Println("\n--- LDAP Query Demo ---")
	ldapHost := "HBO.LOCAL"
	ldapPortStr := "389"
	ldapUser := "administrator"
	ldapPassword := "windows"

	searchCnLdap := "DC2"

	if ldapHost == "" || ldapPortStr == "" || ldapUser == "" || ldapPassword == "" || searchCnLdap == "" {
		logger.Warningf("LDAP variables (LDAP_HOST, LDAP_PORT, LDAP_USER, LDAP_PASSWORD, LDAP_SEARCH_CN) are not fully set. Skipping LDAP query demo.")
		logger.Warningf("Please set them to run the LDAP demo.")
	} else {
		ldapPort, err := strconv.Atoi(ldapPortStr)
		if err != nil {
			logger.Errorf("Invalid LDAP_PORT environment variable: %s", err)
		} else {
			logger.Infof("Attempting LDAP query for CN: %s on %s:%d", searchCnLdap, ldapHost, ldapPort)
			adResultLdap := active_directory.LdapQuery(logger, searchCnLdap, ldapHost, ldapPort, ldapUser, ldapPassword, 60*time.Second, true)
			if adResultLdap != nil && adResultLdap.Name != "" {
				fmt.Printf("LDAP Query Result:\n%+v\n", adResultLdap)
			} else {
				fmt.Println("LDAP Query did not return a result or encountered an error.")
			}
		}
	}

	fmt.Println("\n--- Demo Finished ---")
}
