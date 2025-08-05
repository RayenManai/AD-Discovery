package main

import (
	"fmt"
	"github.com/siemens/GoScans/utils"
	"log"
	"runtime"
	"strconv"
	"time"

	"AD_Discovery/active_directory"
)

func main() {
	logger := utils.NewTestLogger()
	log.SetFlags(log.LstdFlags | log.Lshortfile) // For better logging output with file and line number

	fmt.Println("--- Starting Active Directory Functionality Demo ---")

	// --- LDAP Query Demo ---
	fmt.Println("\n--- LDAP Query Demo ---")
	ldapHost := "testlab.local"
	ldapPortStr := "389"
	ldapUser := "ldapuser@testlab.local"
	ldapPassword := "P@$$w0rd!"
	searchCnLdap := "TESTPC01"

	if ldapHost == "" || ldapPortStr == "" || ldapUser == "" || ldapPassword == "" || searchCnLdap == "" {
		logger.Warningf("LDAP environment variables (LDAP_HOST, LDAP_PORT, LDAP_USER, LDAP_PASSWORD, LDAP_SEARCH_CN) are not fully set. Skipping LDAP query demo.")
		logger.Warningf("Please set them to run the LDAP demo.")
	} else {
		ldapPort, err := strconv.Atoi(ldapPortStr)
		if err != nil {
			logger.Errorf("Invalid LDAP_PORT environment variable: %s", err)
		} else {
			logger.Infof("Attempting LDAP query for CN: %s on %s:%d", searchCnLdap, ldapHost, ldapPort)
			adResultLdap := active_directory.LdapQuery(logger, searchCnLdap, ldapHost, ldapPort, ldapUser, ldapPassword, 60*time.Second)
			if adResultLdap != nil && adResultLdap.Name != "" {
				fmt.Printf("LDAP Query Result:\n%+v\n", adResultLdap)
			} else {
				fmt.Println("LDAP Query did not return a result or encountered an error. Check logs for details.")
			}
		}
	}

	// --- ADODB Query Demo (Windows Only) ---
	fmt.Println("\n--- ADODB Query Demo (Windows Only) ---")
	if runtime.GOOS == "windows" {
		// Set these variables before running, e.g.,
		searchCnAdodb := "TESTPC01"
		searchDomainAdodb := "testlab.local"

		if searchCnAdodb == "" || searchDomainAdodb == "" {
			logger.Warningf("ADODB environment variables (ADODB_SEARCH_CN, ADODB_SEARCH_DOMAIN) are not fully set. Skipping ADODB query demo.")
			logger.Warningf("Please set them to run the ADODB demo.")
		} else {
			logger.Infof("Attempting ADODB query for CN: %s in domain: %s", searchCnAdodb, searchDomainAdodb)
			adResultAdodb := active_directory.AdodbQuery(logger, searchCnAdodb, searchDomainAdodb)
			if adResultAdodb != nil && adResultAdodb.Name != "" {
				fmt.Printf("ADODB Query Result:\n%+v\n", adResultAdodb)
			} else {
				fmt.Println("ADODB Query did not return a result or encountered an error. Check logs for details.")
			}
		}
	} else {
		fmt.Println("ADODB functionality is only available on Windows. Skipping demo.")
	}

	fmt.Println("\n--- Demo Finished ---")
}
