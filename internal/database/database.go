package database

import (
	"database/sql"
	"regexp"

	"github.com/jmoiron/sqlx"
	"github.com/mattn/go-sqlite3"
)

func InitDB(dbPath string) (*sqlx.DB, error) {
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
