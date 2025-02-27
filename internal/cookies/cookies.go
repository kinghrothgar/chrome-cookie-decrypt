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
	CreationUTC          int    `db:"creation_utc"`
	EncryptedValue       []byte `db:"encrypted_value"`
	ExpiresUTC           int    `db:"expires_utc"`
	HasCrossSiteAncestor int    `db:"has_cross_site_ancestor"`
	HasExpires           int    `db:"has_expires"`
	HostKey              string `db:"host_key"`
	IsHttponly           int    `db:"is_httponly"`
	IsPersistent         int    `db:"is_persistent"`
	IsSecure             int    `db:"is_secure"`
	LastAccessUTC        int    `db:"last_access_utc"`
	LastUpdateUTC        int    `db:"last_update_utc"`
	Name                 string `db:"name"`
	Path                 string `db:"path"`
	Priority             int    `db:"priority"`
	Samesite             int    `db:"samesite"`
	SourcePort           int    `db:"source_port"`
	SourceScheme         int    `db:"source_scheme"`
	SourceType           int    `db:"source_type"`
	TopFrameSiteKey      string `db:"top_frame_site_key"`
	Value                string `db:"value"`
}

func (c *ChromeCookie) NetscapeCookie() *NetscapeCookie {
	expires := 0
	if c.HasExpires == 1 {
		expires = (c.ExpiresUTC / 1000000) - 11644473600
	}
	return &NetscapeCookie{
		Domain:            c.HostKey,
		IncludeSubdomains: capBool(strings.HasPrefix(c.HostKey, ".")),
		Path:              c.Path,
		IsSecure:          c.IsSecure == 1,
		ExpiresUTC:        expires,
		Name:              c.Name,
		Value:             c.Value,
		IsHttponly:        c.IsHttponly,
	}
}

const (
	aescbcSalt            = `saltysalt`
	aescbcIV              = `                `
	aescbcIterationsLinux = 1
	aescbcIterationsMacOS = 1003
	aescbcLength          = 16
)

// Details found here https://gist.github.com/creachadair/937179894a24571ce9860e2475a2d2ec
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

	// First 32 bytes is the SHA256 of the HostKey
	c.Value = string(decrypted[32 : len(decrypted)-paddingLen])
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
	IsHttponly        int
}

type capBool bool

func (c capBool) String() string {
	return strings.ToUpper(fmt.Sprintf("%t", c))
}

// String outputs cookie this format https://curl.se/docs/http-cookies.html
func (n *NetscapeCookie) String() string {
	s := fmt.Sprintf("%s\t%s\t%s\t%s\t%d\t%s\t%s", n.Domain, n.IncludeSubdomains.String(), n.Path, n.IsSecure.String(), n.ExpiresUTC, n.Name, n.Value)
	if n.IsHttponly == 1 {
		return "#HttpOnly_" + s
	}
	return s
}
