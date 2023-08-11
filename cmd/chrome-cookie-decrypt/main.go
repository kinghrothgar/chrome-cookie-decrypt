package main

import (
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"

	"github.com/jmoiron/sqlx"
	"github.com/kinghrothgar/chrome-cookie-decrypt/internal/cookies"
	"github.com/kinghrothgar/chrome-cookie-decrypt/internal/keychain"
	"github.com/mattn/go-sqlite3"
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

	db, err := initDB(cookiesPath)
	if err != nil {
		log.WithError(err).Fatal("failed to open cookies sqlite DB")
	}
	defer db.Close() // Defer Closing the database

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

func initDB(dbPath string) (*sqlx.DB, error) {
	sql.Register("sqlite3_with_regex",
		&sqlite3.SQLiteDriver{
			ConnectHook: func(conn *sqlite3.SQLiteConn) error {
				return conn.RegisterFunc("regexp", regex, true)
			},
		})
	return sqlx.Open("sqlite3_with_regex", dbPath)
}

func regex(re, s string) (bool, error) {
	return regexp.MatchString(re, s)
}
