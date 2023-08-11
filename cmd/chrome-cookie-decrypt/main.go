package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"

	"github.com/kinghrothgar/chrome-cookie-decrypt/internal/cookies"
	"github.com/kinghrothgar/chrome-cookie-decrypt/internal/database"
	"github.com/kinghrothgar/chrome-cookie-decrypt/internal/keychain"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
)

var (
	cookiesPath = "/Users/lukejolly/Library/Application Support/Google/Chrome/Default/Cookies"
	selectRegex string
)

func main() {
	flag.StringVar(&selectRegex, "regex", ".*", "a regex to match cookie host key (domain) against")
	flag.Parse()

	if _, err := regexp.Compile(selectRegex); err != nil {
		log.WithError(err).WithField("regex", selectRegex).Fatal("invalid argument for -regex")
	}

	if _, err := os.Stat(cookiesPath); errors.Is(err, os.ErrNotExist) {
		log.Fatal("cookie file missing")
	}

	encryptionKey, err := keychain.GetEncryptionKey()
	if err != nil {
		log.WithError(err).Fatal("failed to get encryption key")
	}

	db, err := database.InitDB(cookiesPath)
	if err != nil {
		log.WithError(err).Fatal("failed to open cookies sqlite DB")
	}
	defer db.Close()

	chromeCookies := []*cookies.ChromeCookie{}
	query, err := db.Preparex("SELECT * FROM cookies WHERE host_key REGEXP $1")
	if err != nil {
		log.WithError(err).Fatal("failed to prepare select query")
	}
	if err := query.Select(&chromeCookies, selectRegex); err != nil {
		log.WithError(err).Fatal("failed to query cookies sqlite DB")
	}

	netscapeCookies := []*cookies.NetscapeCookie{}
	for _, c := range chromeCookies {
		if err := c.Decrypt(encryptionKey); err != nil {
			log.WithError(err).WithFields(log.Fields{
				"name":     c.Name,
				"host_key": c.HostKey,
			}).Warn("failed to decrypt cookie")
		}
		netscapeCookies = append(netscapeCookies, c.NetscapeCookie())
	}
	for _, c := range netscapeCookies {
		fmt.Println(c.String())
	}
}
