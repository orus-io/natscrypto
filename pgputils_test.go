package natscrypto

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/openpgp"
)

var (
	keyCounter      int
	lastT           *testing.T
	lastTKeyCounter int
)

// GetEntity returns an openpgp entity suitable for tests according to a name
// WARNING there is a limited number of keys in the pool and you will
// get a test failure if calling this method in the same test more than the
// number of available keys
// At the moment the number of keys is 4
func GetEntity(t *testing.T) *openpgp.Entity {
	if lastT == t {
		lastTKeyCounter++
	} else {
		lastT = t
		lastTKeyCounter = 0
	}
	if lastTKeyCounter >= len(keysList) {
		t.Errorf("Not enough keys for this test")
	}
	entity, err := preparePrivateKey(strings.NewReader(keysList[keyCounter]))
	assert.Nil(t, err)
	keyCounter++
	if keyCounter >= len(keysList) {
		keyCounter = 0
	}
	return entity
}

// PreparePrivateKey prepare a private key in a pgp entity
func preparePrivateKey(secretKeyring io.Reader) (*openpgp.Entity, error) {
	entityList, err := openpgp.ReadArmoredKeyRing(secretKeyring)
	if err != nil {
		err = fmt.Errorf("invalid ascii armor for key: %s", err)
		return nil, err
	}
	for _, entity := range entityList {
		// return first key
		return entity, nil
	}
	return nil, fmt.Errorf("no private key found")
}

var keysList = []string{
	`-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1

lQHYBFfjnfEBBACkSVB8eCwoh68tkAi/Ph4N7rFA0sVXZ5elJPTV6Pb8Hhusbp47
ra1LQxGM/xmJ3RkRHxlF7dnTB1N9wiwZG6hnz8+kirlXMiFUjk0ksV6I3YMR/3LK
IS+lwpf5+WZ5y90P6bg2NaHfUGpVqnQW3RKopnGChgArUVlv06mlHZTLRQARAQAB
AAP+JNM7O59LVK1vZrDnyQhxP7G+oTdtnUU/AHlbeTx+am6MSPdFuD5avylSPI7t
CFJbXVNhfKOPZUZ54FFfRaSFt51e2IDwEJI24xsQryE3yvZW/7czvBosBpjMlvis
FTNJGYzkWwDHW803SKOxH+2goBdKKvRzM9dytSjD+tcZOiECAMRsp1Zc6rV1yfqJ
QCAaZAX0im5p9MQJzQnej8rJlsaFuL/gUPXwfDzhGVr3Afff5ADeROK4qjfCmYwk
mjA6eqUCANYdTpTa2CbjhLkEn+d/ku1rRBnBUqCZbXtXJ6tPzqE4dqqYtFNq9NFA
t7Zmk9j1qII/QPScStXi5KpaEAt6TCEB/iaql4qVN9G/zh/rKwYFZ3iKoEUu5TfC
OwOew5kVQImGzaYglCNOHjNvJ+7AR9WyggzjPKBeFQrkt7In1hmnDWufgbQJeGJ1
cyB0ZXN0iLgEEwECACIFAlfjnfECGwMGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheA
AAoJEKE6kesjmN84BOwEAIC0q3Xmw4ATDxXlD0wnIRhy6PPjibPjg5adEuI0LNaC
3rn3osngKSzcs8dJ6fhBizyMzUwnIg9Ezj30XnU/Us79SxQd3NT1uSTuNpGsqfTZ
YNZx/QU4t+cx1/Di+lgGjlLkpGzBpCCeuzkdK6oGvzdaS4A/mKSrdsPDxBFapFq9
nQHYBFfjnfEBBADV30wWHZ3rxSJyblxel2SjVQG6GbbklSX9XujImSZcGRZQTM36
zZlakenDJzlNdhj6kZjw/V9sc89R2Giluk/UekGPC0b/9yiQlAZiEyLptGotS8a6
ZSZwiLZ4ZogoPgmfAopTcezjm0NBkUyDS2GdkgXxvWjpBBp57qOpT9E91wARAQAB
AAP9E1AMsNqPziCJEchBcxE8tzsP4tw7lbyaJ50QbDzYJ+zkBPBKkWFLfdA7SbIb
DJGjg8zuAKUAnux+RifCm2SNnLn8lwrh40VO98wwhZvgHDrNGzQwwGYy9vA/nWu+
uBcw9NCE+2Ouq50pFyquCZriWfmGAkpgW+Tm1qYXUz8KtoECAOIBWTKIVNNb8fsD
fKRb44S7m9fzcbieiknu/qrGUmwjn394XsXhyj6Ivxt35sR6SA6hnuoOgeKrEuFT
AJIoYfcCAPJBuR0jc+QdCAKiGAb4gbD3EXCKJxCSDx1cNdiluYh84Zmo19VlMT90
rWHLFRcKbBlpLSyyHjrWzurL4t0RCyECAOZl3gHpXnzKPC6M7G0UnGi1+xx8D2hx
WNPB9V1VEQZRWOj9B1GSwdUMK/X0aTRb8fDhNwLG9C2RgOhC3EYRUXGemIifBBgB
AgAJBQJX453xAhsMAAoJEKE6kesjmN84L4AEAJ/33sfVqXYqMnH6LsD3AKvdzm+X
gQVPhpHriXCE2QplTUdzg9q3KzbOwOtXBVv3QXSJIi9LI6+b0NuwKE+0o08j90AX
X/SD45sORczzxS/C8mJaicBWodBLdwUG990kTJxqWg+9nyvNLbSVmhFKOZE5B4kC
nq6tvUIMK3K8x7Ok
=Rnlp
-----END PGP PRIVATE KEY BLOCK-----`,
	`-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1

lQHYBFfj28QBBACWgPfMKAXuZcgm1niOqEaUtkVzfOdpLm+jGpFIyMnSMGFrXNaP
lFAdzuDA24xHMg94MGdEIVPExtPWTXaOjCuSx1+4iR3jwyG+Y2SCStefOa7wXbNV
Zj+6x4UcB0lrW4GZVHHcF81Lz1SCAXEwQajlnK216HwRFzXJOcx8eAZE7wARAQAB
AAP9FD/G1zN9VM1h6APMFZmDYYfCgV7JPcgPIhk1ed719G8o9Ep53bh9LP2EFL6V
OZD9LtUIV8zKGfwMTVV/wX8Pb4vKVT16lk39QDTgW7IQuFWZbI3OHwQHAm6xOI24
P0xTpPnslklGCbY2655grKwZQnMxSGjMWeBC3fdJXOj1aO0CAMB7DqOOO2nwhGE8
xvR8WS44DkVsAZZ64fVz+l3Wg1VnfYfeScvKqVJVRQUKASx0HWdmYmawpD4eRz6I
uX5gjIMCAMgrqdRg5+3ITz4T6iBi5dHPv9CEnyJEFgRCxWVuDqoy+zFgtrkbh/WJ
9qxofSyUceiNPDDmkO7YWp9hMg+wUiUB/1tce0xS/ZcfL4eiVdg+fxkxpS9O/5AM
trUvA5CA+QeCAbogvVqJUQhgYhNProuUfJqoSsCBpSWIHNlB/Vx6lRSaFbQLeGJ1
cyB0ZXN0IDKIuAQTAQIAIgUCV+PbxAIbAwYLCQgHAwIGFQgCCQoLBBYCAwECHgEC
F4AACgkQri800meIm2fJrQP8CmgsmA/qucTUum3cfGm/yzmNBpWZhC2tNoUHJfAE
8EiGzPAt2s7tmdnGyxN0em6xeWKzvxu4zp58BM3eJH5UKUiyLyxWu1KtiDIXDR3T
EOvj4VNDcHmfqKFOSFlVqy8aiR6JUd5/yZHpN0KhYkeFtPbjMqBNvsG+QkpSAxBj
Q+mdAdgEV+PbxAEEAPH2CR7yvLrsrXHnHdeM7DHIn/FPdJJjGnz0RTaQuWwvynpt
Kjht5JBAfQKJYu2IsjF0SP17gKs08M2dyp5FJOSR+c7UiSkizk0ACiDIdIoGLsCB
aIP6zJrB2OzCR/SGYQwa3U/4Y2FrDGRLYbcyyAecNVmP334YaGbJLWa8AwJBABEB
AAEAA/sE7iXkOvJivxao3udTw6vyA78gLdjkcFKGc0lc9RJiKvZUPxjNV45NuV95
ISi744osY2Zm8kPkuTDWIvEq/zuvxnuwYcC5Nf51BH27Xsi49mrD08/zHatm+MPN
APfM/uoMzyadhuf3s8ZEYP9IsENwKwWdvWp3VNGTTcO3UZ3kFQIA80qNhpdyFvTA
pKw9NfhF0kfedA9Fscx03cIIUMmLV9f2m+7t18hwNmbTcQwNH+qNLmYCAnBE/ApR
igrqazHdCwIA/pmx+rmXZI6NSXitX+9MYYCyZjAn7c3WVzFuF4vCpYks4ibh5Kkq
OqwN6FEfrJ/5UyC/EN1iu3+vKD3YRO31YwIApxQ6aWPhIG4H0yp1PZmshwSSbOJO
k21paeUG3WlAFVdOdAbdSU2VYrltN0opr35LTE9fB6+uTJvhVivVtShY+KQ3iJ8E
GAECAAkFAlfj28QCGwwACgkQri800meIm2dN9wP/bpcvelP4wHsAiGxXt6MeADNN
azDp/+HNJBNL8/x+tw7IatzDYDpgLeVRKryT3FiOb7Kv7oGAuOjtDl8xVdSIIcGC
vvDCb52W7cm8QX7tJx2z0IdYA3VTMKxVTeshNXZYM6dKh0cN3xIU6wNLgNcmVibT
iFRpVzKtVZfdSO1qJ+U=
=sQ0n
-----END PGP PRIVATE KEY BLOCK-----`,
}
