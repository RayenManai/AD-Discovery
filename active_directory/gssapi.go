package active_directory

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/siemens/GoScans/utils"
)

// GSSAPIOptions holds configuration for GSSAPI LDAP connections
type GSSAPIOptions struct {
	// Required fields
	Realm string // The Kerberos realm for which we have credentials

	// Configuration source
	ConfigFilePath string // Path to krb5.conf file (empty = build config programmatically)

	// Programmatic configuration (used when ConfigFilePath is empty)
	KDCs          []string // KDC servers (required for programmatic config)
	AdminServers  []string // Admin servers (defaults to KDCs if empty)
	DefaultDomain string   // Default domain (defaults to lowercase realm if empty)

	// Common options
	ServicePrincipalName string // SPN (generated from ldapAddress if empty)
}

// ldapConnectWithGSSAPI establishes an LDAP connection with GSSAPI (Kerberos) authentication
func ldapConnectWithGSSAPI(
	logger utils.Logger,
	ldapAddress string,
	ldapPort int,
	ldapUser string,
	ldapPassword string,
	dialTimeout time.Duration,
	options GSSAPIOptions,
) (*ldap.Conn, error) {
	// Validate required options
	if options.Realm == "" {
		return nil, fmt.Errorf("Kerberos realm is required for GSSAPI authentication")
	}

	// Sanitize LDAP address
	baseUrl := sanitizeLdapUrl(ldapAddress)

	// Open a standard LDAP connection
	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", baseUrl, ldapPort),
		ldap.DialWithDialer(&net.Dialer{Timeout: dialTimeout}))
	if err != nil {
		logger.Debugf("LDAP connection to '%s:%d' failed: %s", ldapAddress, ldapPort, err)
		return nil, err
	}

	// Create GSSAPI client based on provided options
	var gssapiClient *gssapi.Client

	if options.ConfigFilePath != "" {
		// Use config file since path is provided
		logger.Debugf("Using Kerberos config file: %s", options.ConfigFilePath)

		client, err := gssapi.NewClientWithPassword(
			ldapUser,
			options.Realm,
			ldapPassword,
			options.ConfigFilePath,
			client.DisablePAFXFAST(true),
		)

		if err != nil {
			conn.Close()
			logger.Debugf("Failed to create GSSAPI client with config file: %s", err)
			return nil, fmt.Errorf("gssapi client creation failed: %w", err)
		}

		gssapiClient = client
	} else {
		// Build config programmatically since no file path provided
		logger.Debugf("Building programmatic Kerberos config for realm: %s", options.Realm)

		// Validate required fields for programmatic config
		if len(options.KDCs) == 0 {
			conn.Close()
			return nil, fmt.Errorf("KDCs are required when not using a config file")
		}

		krb5Config := buildKrb5Config(options, logger)

		// Create Kerberos client with our config
		krbClient := client.NewWithPassword(
			ldapUser,
			options.Realm,
			ldapPassword,
			krb5Config,
			client.DisablePAFXFAST(true),
		)

		// Create GSSAPI client
		gssapiClient = &gssapi.Client{
			Client: krbClient,
		}
	}

	// Set default SPN if not provided
	spn := options.ServicePrincipalName
	if spn == "" {
		// Default to the LDAP service on the target host
		spn = fmt.Sprintf("ldap/%s", ldapAddress)
		logger.Debugf("Using default SPN: %s", spn)
	}

	// Bind using GSSAPI with mutual authentication
	err = conn.GSSAPIBindRequestWithAPOptions(gssapiClient, &ldap.GSSAPIBindRequest{
		ServicePrincipalName: spn,
		AuthZID:              "",
	}, []int{flags.APOptionMutualRequired})

	if err != nil {
		conn.Close()
		logger.Debugf("GSSAPI bind failed: %s", err)
		return nil, fmt.Errorf("GSSAPI bind failed: %w", err)
	}

	logger.Debugf("GSSAPI bind successful to %s", spn)
	return conn, nil
}

// buildKrb5Config builds a Kerberos configuration programmatically
func buildKrb5Config(options GSSAPIOptions, logger utils.Logger) *config.Config {
	krb5Conf := config.New()
	realm := strings.ToUpper(options.Realm) // Always use uppercase for realm

	// LibDefaults section
	krb5Conf.LibDefaults.AllowWeakCrypto = true
	krb5Conf.LibDefaults.DefaultRealm = realm
	krb5Conf.LibDefaults.DNSLookupRealm = false
	krb5Conf.LibDefaults.DNSLookupKDC = false
	krb5Conf.LibDefaults.TicketLifetime = time.Duration(24) * time.Hour
	krb5Conf.LibDefaults.RenewLifetime = time.Duration(24*7) * time.Hour
	krb5Conf.LibDefaults.Forwardable = true
	krb5Conf.LibDefaults.Proxiable = true
	krb5Conf.LibDefaults.RDNS = false
	krb5Conf.LibDefaults.UDPPreferenceLimit = 1 // Force use of TCP

	// Encryption types
	krb5Conf.LibDefaults.DefaultTGSEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "arcfour-hmac-md5"}
	krb5Conf.LibDefaults.DefaultTktEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "arcfour-hmac-md5"}
	krb5Conf.LibDefaults.PermittedEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "arcfour-hmac-md5"}
	krb5Conf.LibDefaults.PermittedEnctypeIDs = []int32{18, 17, 23}
	krb5Conf.LibDefaults.DefaultTGSEnctypeIDs = []int32{18, 17, 23}
	krb5Conf.LibDefaults.DefaultTktEnctypeIDs = []int32{18, 17, 23}
	krb5Conf.LibDefaults.PreferredPreauthTypes = []int{18, 17, 23}

	// Use provided admin servers or default to the KDC servers
	adminServers := options.AdminServers
	if len(adminServers) == 0 {
		adminServers = options.KDCs
	}

	// Use provided default domain or default to lowercase realm
	defaultDomain := options.DefaultDomain
	if defaultDomain == "" {
		defaultDomain = strings.ToLower(realm)
	}

	// Add the realm configuration
	krb5Conf.Realms = append(krb5Conf.Realms, config.Realm{
		Realm:         realm,
		AdminServer:   adminServers,
		DefaultDomain: defaultDomain,
		KDC:           formatServersWithPort(options.KDCs, 88),  // KDC port
		KPasswdServer: formatServersWithPort(options.KDCs, 464), // Kpasswd port
		MasterKDC:     options.KDCs,
	})

	// Domain Realm mappings
	lowerRealm := strings.ToLower(realm)
	krb5Conf.DomainRealm[lowerRealm] = realm
	krb5Conf.DomainRealm[fmt.Sprintf(".%s", lowerRealm)] = realm

	// Add any additional domain mappings if default domain differs from realm
	if defaultDomain != lowerRealm {
		krb5Conf.DomainRealm[defaultDomain] = realm
		krb5Conf.DomainRealm[fmt.Sprintf(".%s", defaultDomain)] = realm
	}

	return krb5Conf
}

// Helper functions
func formatServersWithPort(servers []string, port int) []string {
	result := make([]string, len(servers))
	for i, server := range servers {
		if !strings.Contains(server, ":") {
			result[i] = fmt.Sprintf("%s:%d", server, port)
		} else {
			result[i] = server
		}
	}
	return result
}

func sanitizeLdapUrl(ldapAddress string) string {
	baseUrl := strings.TrimPrefix(ldapAddress, "ldap://")
	baseUrl = strings.TrimPrefix(baseUrl, "ldaps://")
	baseUrl = strings.TrimPrefix(baseUrl, "ldapi://")
	return baseUrl
}
