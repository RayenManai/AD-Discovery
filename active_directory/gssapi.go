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
	DefaultRealm         string // The Kerberos realm for which we have credentials
	ConfigFilePath       string // Optional Config file
	Realms               []config.Realm
	ServicePrincipalName string
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
	if options.DefaultRealm == "" {
		return nil, fmt.Errorf("Kerberos realm is required for GSSAPI authentication")
	}

	// Sanitize LDAP address
	baseUrl := strings.TrimPrefix(ldapAddress, "ldap://")
	baseUrl = strings.TrimPrefix(baseUrl, "ldaps://")
	baseUrl = strings.TrimPrefix(baseUrl, "ldapi://")

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
			options.DefaultRealm,
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
		logger.Debugf("Building programmatic Kerberos config for realm: %s", options.DefaultRealm)

		krb5Config := buildKrb5Config(options, logger)

		// Create Kerberos client with our config
		krbClient := client.NewWithPassword(
			ldapUser,
			options.DefaultRealm,
			ldapPassword,
			krb5Config,
			client.DisablePAFXFAST(true),
		)

		// Create GSSAPI client
		gssapiClient = &gssapi.Client{
			Client: krbClient,
		}
	}

	// Bind using GSSAPI with mutual authentication
	err = conn.GSSAPIBindRequestWithAPOptions(gssapiClient, &ldap.GSSAPIBindRequest{
		ServicePrincipalName: fmt.Sprintf("ldap/%s", options.ServicePrincipalName),
		AuthZID:              "",
	}, []int{flags.APOptionMutualRequired})

	if err != nil {
		conn.Close()
		logger.Debugf("GSSAPI bind failed: %s", err)
		return nil, fmt.Errorf("GSSAPI bind failed: %w", err)
	}

	logger.Debugf("GSSAPI bind successful to %s", fmt.Sprintf("ldap/%s", options.ServicePrincipalName))
	return conn, nil
}

// buildKrb5Config builds a Kerberos configuration programmatically
func buildKrb5Config(options GSSAPIOptions, logger utils.Logger) *config.Config {
	krb5Conf := config.New()
	defaultRealm := strings.ToUpper(options.DefaultRealm) // Always use uppercase for realm

	// LibDefaults section
	krb5Conf.LibDefaults.AllowWeakCrypto = true
	krb5Conf.LibDefaults.DefaultRealm = defaultRealm
	krb5Conf.LibDefaults.DNSLookupRealm = false
	krb5Conf.LibDefaults.DNSLookupKDC = false
	krb5Conf.LibDefaults.TicketLifetime = time.Duration(24) * time.Hour
	krb5Conf.LibDefaults.RenewLifetime = time.Duration(24*7) * time.Hour
	krb5Conf.LibDefaults.Forwardable = true
	krb5Conf.LibDefaults.Proxiable = true
	krb5Conf.LibDefaults.RDNS = false
	krb5Conf.LibDefaults.UDPPreferenceLimit = 1

	// Encryption types
	krb5Conf.LibDefaults.DefaultTGSEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "arcfour-hmac-md5"}
	krb5Conf.LibDefaults.DefaultTktEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "arcfour-hmac-md5"}
	krb5Conf.LibDefaults.PermittedEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "arcfour-hmac-md5"}
	krb5Conf.LibDefaults.PermittedEnctypeIDs = []int32{18, 17, 23}
	krb5Conf.LibDefaults.DefaultTGSEnctypeIDs = []int32{18, 17, 23}
	krb5Conf.LibDefaults.DefaultTktEnctypeIDs = []int32{18, 17, 23}
	krb5Conf.LibDefaults.PreferredPreauthTypes = []int{18, 17, 23}

	// Add each realm
	for _, realmOpt := range options.Realms {
		realm := strings.ToUpper(realmOpt.Realm)

		adminServers := realmOpt.AdminServer
		if len(adminServers) == 0 {
			adminServers = realmOpt.KDC
		}

		defaultDomain := realmOpt.DefaultDomain
		if defaultDomain == "" {
			defaultDomain = strings.ToLower(realm)
		}

		krb5Conf.Realms = append(krb5Conf.Realms, config.Realm{
			Realm:         realm,
			AdminServer:   adminServers,
			DefaultDomain: defaultDomain,
			KDC:           formatServersWithPort(realmOpt.KDC, 88),
			KPasswdServer: formatServersWithPort(realmOpt.KPasswdServer, 464),
			MasterKDC:     realmOpt.MasterKDC,
		})
	}

	return krb5Conf
}

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
