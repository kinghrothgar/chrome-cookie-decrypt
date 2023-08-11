package keychain

import (
	"fmt"

	gokeychain "github.com/keybase/go-keychain"
)

func GetEncryptionKey() ([]byte, error) {
	var err error

	query := gokeychain.NewItem()
	query.SetSecClass(gokeychain.SecClassGenericPassword)
	query.SetService("Chrome Safe Storage")
	query.SetAccount("Chrome")
	query.SetMatchLimit(gokeychain.MatchLimitOne)
	query.SetReturnData(true)
	results, err := gokeychain.QueryItem(query)
	if err != nil {
		return nil, err
	} else if len(results) != 1 {
		return nil, fmt.Errorf("password not found")
	}

	return results[0].Data, nil
}
