package main

import (
	"crypto/tls"
	"fmt"
	"github.com/docopt/docopt-go"
	"github.com/kardianos/osext"
	"github.com/nmcclain/ldap"
	"github.com/vaughan0/go-ini"
	"log"
	"log/syslog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const version = "1.5"

var usage = `goklp: OpenSSH Keys LDAP Provider for AuthorizedKeysCommand

Usage:
  goklp <username>
  goklp --config=<cfile> <username>
  goklp --no-config-security <username>
  goklp --no-config-security --config=<cfile> <username>
  goklp -h --help
  goklp --version

Config file is required, named: goklp.ini
  goklp_ldap_uri              = ldaps://server1:636,ldaps://server2:636   (required)
  goklp_ldap_bind_dn          = CN=someuser,O=someorg,C=sometld           (required)
  goklp_ldap_base_dn          = O=someorg,C=sometld                       (required)
  goklp_ldap_bind_pw          = someSecretPassword                        (optional - default: "")
  goklp_ldap_timeout_secs     = 10                           (optional - default: 5)
  goklp_ldap_user_attr        = 10                           (optional - default: uid)
  goklp_debug                 = true                     (optional - default: false)
  goklp_insecure_skip_verify  = false                    (optional - default: false)

Options:
  --version             Show version.
  --config=<cfile>      Path to config file
  --no-config-security  Disable config file security checks
  -h, --help            Show this screen.
`

type opts struct {
	username                   string
	goklp_ldap_base_dn         string
	goklp_ldap_bind_dn         string
	goklp_ldap_bind_pw         string
	goklp_ldap_user_attr       string
	goklp_ldap_uris            []string
	goklp_debug                bool
	goklp_insecure_skip_verify bool
	goklp_ldap_timeout         time.Duration
}

type query struct {
	ldapURL    string
	baseDN     string
	filter     string
	Attributes []string
	user       string
	passwd     string
	timeout    time.Duration
}

type result struct {
	sr      *ldap.SearchResult
	ldapURL string
}

////
func main() {
	// parse options and config file
	o, err := getOpts()
	if err != nil {
		log.Fatal(err)
	}

	// setup logging
	logger, err := syslog.New(syslog.LOG_ALERT|syslog.LOG_USER, "goklp")
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(logger)

	// run ldapsearch
	keys, err := o.ldapsearch()
	if err != nil {
		logger.Alert(err.Error())
	}

	// output keys
	if len(keys) > 0 {
		fmt.Println(strings.Join(keys, "\n"))
	}
	if o.goklp_debug {
		logger.Debug(fmt.Sprintf("Successfully found %d keys for %s", len(keys), o.username))
	}
}

////
func (o *opts) ldapsearch() ([]string, error) {
	keys := []string{}

	// parallel search
	ch := make(chan result, 1)
	outstanding := len(o.goklp_ldap_uris)
	errCh := make(chan error, outstanding)

	for _, server_url := range o.goklp_ldap_uris {
		q := query{
			baseDN:     o.goklp_ldap_base_dn,
			filter:     fmt.Sprintf("(%s=%s)", o.goklp_ldap_user_attr, o.username),
			Attributes: []string{"sshPublicKey"},
			user:       o.goklp_ldap_bind_dn,
			passwd:     o.goklp_ldap_bind_pw,
			ldapURL:    server_url,
		}
		go func() {
			sr, err := o.doquery(q)
			if err != nil {
				errCh <- err
				return
			}
			r := result{sr: sr, ldapURL: q.ldapURL}
			select {
			case ch <- r:
			default:
			}
		}()
	}

	for {
		select {
		case r := <-ch:
			if len(r.sr.Entries) > 1 {
				return keys, fmt.Errorf("Too many results found.")
			}
			if len(r.sr.Entries) == 1 {
				for _, attr := range r.sr.Entries[0].Attributes {
					if attr.Name == "sshPublicKey" {
						keys = append(keys, attr.Values...)
					}
				}
			}
			return keys, nil
		case err := <-errCh:
			outstanding--
			if outstanding == 0 {
				return keys, err
			}

		case <-time.After(o.goklp_ldap_timeout):
			return keys, fmt.Errorf("No response before timeout.")
		}
	}

	return keys, nil
}

////
func (o *opts) doquery(q query) (*ldap.SearchResult, error) {
	sr := &ldap.SearchResult{}

	// parse the ldap URL
	u, err := url.Parse(q.ldapURL)
	if err != nil {
		return sr, err
	}
	var port int
	if u.Scheme == "ldaps" {
		port = 636
	} else if u.Scheme == "ldap" {
		port = 389
	} else {
		return sr, fmt.Errorf("Unknown LDAP scheme: %s", u.Scheme)
	}
	parts := strings.Split(u.Host, ":")
	hostname := parts[0]
	if len(parts) > 1 {
		port, err = strconv.Atoi(parts[1])
		if err != nil {
			return sr, err
		}
	}

	// connect to the ldap server
	var l *ldap.Conn
	if u.Scheme == "ldaps" {
		tlsConfig := tls.Config{}
		if o.goklp_insecure_skip_verify {
			tlsConfig.InsecureSkipVerify = true
		}
		l, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", hostname, port), &tlsConfig)
		if err != nil {
			return sr, err
		}
	} else if u.Scheme == "ldap" {
		l, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", hostname, port))
		if err != nil {
			return sr, err
		}
	}
	defer l.Close()

	// do an ldap bind
	if q.passwd != "" {
		err = l.Bind(q.user, q.passwd)
		if err != nil {
			return sr, err
		}
	}

	// do the ldap search
	search := ldap.NewSearchRequest(
		q.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false,
		q.filter,
		q.Attributes,
		nil)

	sr, err = l.Search(search)
	if err != nil {
		return sr, err
	}
	return sr, nil
}

////
func getOpts() (*opts, error) {
	o := &opts{}
	arguments, err := docopt.Parse(usage, nil, true, version, false)
	if err != nil {
		return o, err
	}

	o.username = arguments["<username>"].(string)

	configFileRaw, exists := arguments["--config"]
	var configFile string
	if !exists || configFileRaw == nil {
		// handle config file
		myDirectory, err := osext.ExecutableFolder()
		if err != nil {
			return o, err
		}
		configFile = myDirectory + "/goklp.ini"
	} else {
		var ok bool
		configFile, ok = configFileRaw.(string)
		if !ok {
			return o, fmt.Errorf("config file must be a string")
		}
	}

	if _, exists := arguments["--no-config-security"]; !exists && false {
		fileInfo, err := os.Stat(configFile)
		if err != nil {
			return o, err
		}

		// enforce reasonable config file security
		if !strings.HasSuffix(fileInfo.Mode().String(), "------") {
			return o, fmt.Errorf("Permissions on goklp.ini are too loose - try a 'chmod 600 goklp.ini'")
		}
	}

	config, err := ini.LoadFile(configFile)
	if err != nil {
		return o, err
	}

	goklp_ldap_uri, exists := config[""]["goklp_ldap_uri"]
	if !exists {
		return o, fmt.Errorf("Config option goklp_ldap_uri is not set.")
	}
	o.goklp_ldap_uris = strings.Split(goklp_ldap_uri, ",")
	o.goklp_ldap_bind_dn, exists = config[""]["goklp_ldap_bind_dn"]
	if !exists {
		return o, fmt.Errorf("Config option goklp_ldap_bind_dn is not set.")
	}
	o.goklp_ldap_base_dn, exists = config[""]["goklp_ldap_base_dn"]
	if !exists {
		return o, fmt.Errorf("Config option goklp_ldap_base_dn is not set.")
	}
	o.goklp_ldap_bind_pw, _ = config[""]["goklp_ldap_bind_pw"]

	// default to 5 second timeout
	goklp_ldap_timeout_secs := 5
	goklp_ldap_timeout_str, exists := config[""]["goklp_ldap_timeout"]
	if exists {
		goklp_ldap_timeout_secs, err = strconv.Atoi(goklp_ldap_timeout_str)
		if err != nil {
			return o, fmt.Errorf("Invalid timeout in goklp_ldap_timeout.")
		}
	}
	o.goklp_ldap_timeout = time.Duration(goklp_ldap_timeout_secs) * time.Second

	goklp_ldap_user_attr, exists := config[""]["goklp_ldap_user_attr"]
	if !exists {
		o.goklp_ldap_user_attr = "uid"
	} else {
		o.goklp_ldap_user_attr = goklp_ldap_user_attr
	}

	// debugging goes to syslog
	if s, exists := config[""]["goklp_debug"]; exists && s == "true" {
		o.goklp_debug = true
	}
	if s, exists := config[""]["goklp_insecure_skip_verify"]; exists && s == "true" {
		o.goklp_insecure_skip_verify = true
	}
	return o, nil
}
