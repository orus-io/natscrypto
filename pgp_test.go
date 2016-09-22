package natscrypto

// Tests for the PGPEncrypter
//
// TODO Missing tests are :
// - encrypt errors
// - decrypt errors
// - signature errors

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/openpgp"
)

func TestPGPEncrypterAccessors(t *testing.T) {
	ec := NewPGPEncrypter()
	assert.NotNil(t, ec.Identities)

	e := GetEntity(t)

	id := string(e.PrimaryKey.Fingerprint[:20])

	assert.Panics(t, func() { ec.AddEntity(nil) })

	ec.AddEntity(e)

	assert.Equal(t, openpgp.EntityList{e}, ec.AllEntities)
	assert.Equal(t, 1, len(ec.Identities))
	assert.Equal(t, e, ec.Identities[id])

	ec.RemoveID(id)

	assert.Equal(t, openpgp.EntityList{}, ec.AllEntities)
	assert.Equal(t, 0, len(ec.Identities))

	e.PrimaryKey = nil
	assert.Panics(t, func() { ec.AddEntity(e) })
}

func TestEncryptDecryptData(t *testing.T) {
	signer := GetEntity(t)
	signerID := string(signer.PrimaryKey.Fingerprint[:20])

	recipient := GetEntity(t)
	recipientID := string(recipient.PrimaryKey.Fingerprint[:20])
	recipient.PrivateKey = nil

	ec := NewPGPEncrypter()
	ec.AddEntity(signer, recipient)

	data, err := ec.EncryptData([]byte("Bonjour !"), []string{recipientID}, "unknown")
	assert.Nil(t, data)
	assert.Equal(t, "Unknown signer id: unknown", err.Error())

	data, err = ec.EncryptData([]byte("Bonjour !"), []string{"jojo"}, signerID)
	assert.Nil(t, data)
	assert.Equal(t, "Unknown recipient id: jojo", err.Error())

	data, err = ec.EncryptData([]byte("Bonjour !"), []string{signerID}, recipientID)
	assert.Nil(t, data)
	assert.Equal(t, "No private key for this identity: "+recipientID, err.Error())

	data, err = ec.EncryptData([]byte("Bonjour !"), []string{recipientID}, signerID)
	assert.Nil(t, err)
	assert.NotEqual(t, "", data)

	decData, decRecipients, decSigner, decErr := ec.DecryptData(data)
	assert.Nil(t, decErr)
	assert.Equal(t, "Bonjour !", string(decData))
	assert.Equal(t, signerID, decSigner)
	assert.Equal(t, []string{recipientID}, decRecipients)
}
