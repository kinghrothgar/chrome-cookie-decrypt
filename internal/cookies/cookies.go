package cookies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

type ChromeCookie struct {
	CreationUTC     int    `db:"creation_utc"`
	HostKey         string `db:"host_key"`
	TopFrameSiteKey string `db:"top_frame_site_key"`
	Name            string `db:"name"`
	Value           string `db:"value"`
	EncryptedValue  []byte `db:"encrypted_value"`
	Path            string `db:"path"`
	ExpiresUTC      int    `db:"expires_utc"`
	IsSecure        int    `db:"is_secure"`
	IsHttponly      int    `db:"is_httponly"`
	LastAccessUTC   int    `db:"last_access_utc"`
	HasExpires      int    `db:"has_expires"`
	IsPersistent    int    `db:"is_persistent"`
	Priority        int    `db:"priority"`
	Samesite        int    `db:"samesite"`
	SourceScheme    int    `db:"source_scheme"`
	SourcePort      int    `db:"source_port"`
	IsSameParty     int    `db:"is_same_party"`
	LastUpdateUTC   int    `db:"last_update_utc"`
}

func (c *ChromeCookie) NetscapeCookie() *NetscapeCookie {
	return &NetscapeCookie{
		Domain:            c.HostKey,
		IncludeSubdomains: capBool(strings.HasPrefix(c.HostKey, ".")),
		Path:              c.Path,
		IsSecure:          c.IsSecure == 1,
		ExpiresUTC:        c.ExpiresUTC,
		Name:              c.Name,
		Value:             c.Value,
	}
}

const (
	aescbcSalt            = `saltysalt`
	aescbcIV              = `                `
	aescbcIterationsLinux = 1
	aescbcIterationsMacOS = 1003
	aescbcLength          = 16
)

func (c *ChromeCookie) Decrypt(password []byte) error {
	key := pbkdf2.Key(password, []byte(aescbcSalt), aescbcIterationsMacOS, aescbcLength, sha1.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// The EncryptedValue is prefixed with "v10", remove it
	// TODO check if prefix is v10
	if len(c.EncryptedValue) < 3 {
		return errors.New("encrypted length less than 3")
	}
	version := string(c.EncryptedValue[0:3])
	if version != "v10" {
		return fmt.Errorf("unsported encrypted value version: %s", version)
	}
	encryptedValue := c.EncryptedValue[3:]
	decrypted := make([]byte, len(encryptedValue))
	cbc := cipher.NewCBCDecrypter(block, []byte(aescbcIV))
	cbc.CryptBlocks(decrypted, encryptedValue)

	if len(decrypted) == 0 {
		return errors.New("not enough bits")
	}

	if len(decrypted)%aescbcLength != 0 {
		return fmt.Errorf("decrypted data block length is not a multiple of %d", aescbcLength)
	}
	paddingLen := int(decrypted[len(decrypted)-1])
	if paddingLen > 16 {
		return fmt.Errorf("invalid last block padding length: %d", paddingLen)
	}

	c.Value = string(decrypted[:len(decrypted)-paddingLen])
	return nil
}

type NetscapeCookie struct {
	Domain            string
	IncludeSubdomains capBool
	Path              string
	IsSecure          capBool
	ExpiresUTC        int
	Name              string
	Value             string
}

type capBool bool

func (c capBool) String() string {
	return strings.ToUpper(fmt.Sprintf("%t", c))
}

func (n *NetscapeCookie) String() string {
	return fmt.Sprintf("%s\t%s\t%s\t%s\t%d\t%s\t%s", n.Domain, n.IncludeSubdomains.String(), n.Path, n.IsSecure.String(), n.ExpiresUTC, n.Name, n.Value)
}
