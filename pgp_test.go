package natscrypto

// Tests for the PGPEncrypter

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
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

func TestOneShotEntity(t *testing.T) {
	entity := GetEntity(t)
	entityID := string(entity.PrimaryKey.Fingerprint[:20])

	ec := NewPGPEncrypter()
	ec.AddOneShotEntity(entity)

	assert.Equal(t, entity, ec.getEntity(entityID))
	assert.Nil(t, ec.getEntity(entityID))
}

func failingEncrypt(io.Writer, []*openpgp.Entity, *openpgp.Entity, *openpgp.FileHints, *packet.Config) (io.WriteCloser, error) {
	return nil, fmt.Errorf("Some error")
}

type WriteCloserWithFailingWrite struct{}

func (WriteCloserWithFailingWrite) Write([]byte) (int, error) { return 0, fmt.Errorf("Write failed") }
func (WriteCloserWithFailingWrite) Close() error              { return nil }

type WriteCloserWithFailingClose struct{}

func (WriteCloserWithFailingClose) Write([]byte) (int, error) { return 0, nil }
func (WriteCloserWithFailingClose) Close() error              { return fmt.Errorf("Close failed") }

func failingWriterWrite(io.Writer, []*openpgp.Entity, *openpgp.Entity, *openpgp.FileHints, *packet.Config) (io.WriteCloser, error) {
	return WriteCloserWithFailingWrite{}, nil
}
func failingWriterClose(io.Writer, []*openpgp.Entity, *openpgp.Entity, *openpgp.FileHints, *packet.Config) (io.WriteCloser, error) {
	return WriteCloserWithFailingClose{}, nil
}

func TestEncryptErrors(t *testing.T) {
	openpgpEncrypt = failingEncrypt
	defer func() { openpgpEncrypt = openpgp.Encrypt }()

	signer := GetEntity(t)
	signerID := string(signer.PrimaryKey.Fingerprint[:20])

	recipient := GetEntity(t)
	recipientID := string(recipient.PrimaryKey.Fingerprint[:20])
	recipient.PrivateKey = nil

	ec := NewPGPEncrypter()
	ec.AddEntity(signer, recipient)

	_, err := ec.EncryptData([]byte("Bonjour !"), []string{recipientID}, signerID)
	assert.EqualError(t, err, "Some error")

	openpgpEncrypt = failingWriterWrite
	_, err = ec.EncryptData([]byte("Bonjour !"), []string{recipientID}, signerID)
	assert.EqualError(t, err, "Write failed")

	openpgpEncrypt = failingWriterClose
	_, err = ec.EncryptData([]byte("Bonjour !"), []string{recipientID}, signerID)
	assert.EqualError(t, err, "Close failed")
}

var readMessageEntity = GetEntity(nil)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, fmt.Errorf("Read failed")
}

func failingReadMessage(io.Reader, openpgp.KeyRing, openpgp.PromptFunction, *packet.Config) (*openpgp.MessageDetails, error) {
	return nil, fmt.Errorf("ReadMessage failed")
}

func readMessageReturnsFaultyBodyReader(io.Reader, openpgp.KeyRing, openpgp.PromptFunction, *packet.Config) (*openpgp.MessageDetails, error) {
	return &openpgp.MessageDetails{UnverifiedBody: failingReader{}}, nil
}

func readMessageUnsigned(io.Reader, openpgp.KeyRing, openpgp.PromptFunction, *packet.Config) (*openpgp.MessageDetails, error) {
	return &openpgp.MessageDetails{
		UnverifiedBody: strings.NewReader(""),
		DecryptedWith:  openpgp.Key{Entity: readMessageEntity},
	}, nil
}

func readMessageUnknownSigner(io.Reader, openpgp.KeyRing, openpgp.PromptFunction, *packet.Config) (*openpgp.MessageDetails, error) {
	return &openpgp.MessageDetails{
		UnverifiedBody: strings.NewReader(""),
		DecryptedWith:  openpgp.Key{Entity: readMessageEntity},
		IsSigned:       true,
	}, nil
}

func readMessageSignatureError(io.Reader, openpgp.KeyRing, openpgp.PromptFunction, *packet.Config) (*openpgp.MessageDetails, error) {
	return &openpgp.MessageDetails{
		UnverifiedBody: strings.NewReader(""),
		DecryptedWith:  openpgp.Key{Entity: readMessageEntity},
		IsSigned:       true,
		SignatureError: fmt.Errorf("Signature Error"),
	}, nil
}

func TestDecryptionErrors(t *testing.T) {
	defer func() { openpgpEncrypt = openpgp.Encrypt }()
	signer := GetEntity(t)

	recipient := GetEntity(t)
	recipient.PrivateKey = nil

	ec := NewPGPEncrypter()
	ec.AddEntity(signer, recipient)

	openpgpReadMessage = failingReadMessage
	_, _, _, err := ec.DecryptData([]byte(""))
	assert.EqualError(t, err, "Error decrypting message: ReadMessage failed")

	openpgpReadMessage = readMessageReturnsFaultyBodyReader
	_, _, _, err = ec.DecryptData([]byte(""))
	assert.EqualError(t, err, "Read failed")

	openpgpReadMessage = readMessageUnsigned
	_, _, _, err = ec.DecryptData([]byte(""))
	assert.Equal(t, err, ErrUnsignedMessage)

	openpgpReadMessage = readMessageUnknownSigner
	_, _, _, err = ec.DecryptData([]byte(""))
	assert.Equal(t, err, ErrUnknownSigner)

	openpgpReadMessage = readMessageSignatureError
	_, _, _, err = ec.DecryptData([]byte(""))
	assert.Equal(t, "Signature Error", err.Error())
}
