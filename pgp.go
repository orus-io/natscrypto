package natscrypto

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"sync"

	"golang.org/x/crypto/openpgp"
)

var (
	// ErrNilEntity is returned or panicked by functions expecting a non-nil
	// *openpgp.Entity
	ErrNilEntity = errors.New("Nil Entity")
)

// NewPGPEncrypter initialize a PGPEncrypter
func NewPGPEncrypter(entities ...*openpgp.Entity) *PGPEncrypter {
	e := PGPEncrypter{
		Identities:      make(map[string]*openpgp.Entity),
		OneShotEntities: make(map[string]*openpgp.Entity),
	}
	e.AddEntity(entities...)
	return &e
}

// PGPEncrypter is a openpgp based Encrypter for EncryptedConn
type PGPEncrypter struct {
	Identities      map[string]*openpgp.Entity
	AllEntities     openpgp.EntityList
	OneShotEntities map[string]*openpgp.Entity
	entitiesLock    sync.RWMutex
}

// AddEntity add one of more openpgp entities to the encrypter.
// If the entity contains a private key, it is added to the PrivateIdentities too,
// which means the PGPEncrypter will be able to decrypt messages to it
// Panics if the entity is nil or has no PrimaryKey
func (e *PGPEncrypter) AddEntity(entities ...*openpgp.Entity) {
	e.entitiesLock.Lock()
	defer e.entitiesLock.Unlock()
	for _, entity := range entities {
		if entity == nil {
			panic(ErrNilEntity)
		}

		if entity.PrimaryKey == nil {
			panic("Entity has no PrimaryKey")
		}

		id := string(entity.PrimaryKey.Fingerprint[:20])

		e.Identities[id] = entity

		e.AllEntities = append(e.AllEntities, entity)
	}
}

// AddOneShotEntity add an entity that can be used only once for encrypting only
// (not for verification)
func (e *PGPEncrypter) AddOneShotEntity(entity *openpgp.Entity) string {
	e.entitiesLock.Lock()
	defer e.entitiesLock.Unlock()
	id := string(entity.PrimaryKey.Fingerprint[:20])
	e.OneShotEntities[id] = entity
	return id
}

// RemoveID removes an entity from the encrypter given its fingerprint
func (e *PGPEncrypter) RemoveID(id string) {
	e.entitiesLock.Lock()
	defer e.entitiesLock.Unlock()
	for i, entity := range e.AllEntities {
		if string(entity.PrimaryKey.Fingerprint[:20]) == id {
			e.AllEntities = append(e.AllEntities[:i], e.AllEntities[i+1:]...)
			break
		}
	}
	delete(e.Identities, id)
}

func (e *PGPEncrypter) getEntity(id string) *openpgp.Entity {
	e.entitiesLock.RLock()
	entity, ok := e.Identities[id]
	e.entitiesLock.RUnlock()
	if !ok {
		e.entitiesLock.Lock()
		if entity, ok = e.OneShotEntities[id]; ok {
			delete(e.OneShotEntities, id)
		}
		e.entitiesLock.Unlock()
	}
	return entity
}

// EncryptData encrypt the data with the recipients public keys and sign it
// sith signer private key
func (e *PGPEncrypter) EncryptData(data []byte, recipients []string, signer string) ([]byte, error) {
	var (
		recipientEntityList openpgp.EntityList
	)

	signerEntity := e.getEntity(signer)
	if signerEntity == nil {
		return nil, fmt.Errorf("Unknown signer id: %s", signer)
	}
	if signerEntity.PrivateKey == nil {
		return nil, fmt.Errorf("No private key for this identity: %s", signer)
	}
	for _, id := range recipients {
		entity := e.getEntity(id)
		if entity == nil {
			return nil, fmt.Errorf("Unknown recipient id: %s", id)
		}
		recipientEntityList = append(recipientEntityList, entity)
	}
	// create a buffer that will server as a io.Writer during encryption and
	// will be returned as an io.Reader after success
	buf := new(bytes.Buffer)

	w, err := openpgp.Encrypt(buf, recipientEntityList, signerEntity, nil, nil)

	if err != nil {
		return nil, err
	}

	_, err = w.Write(data)
	if err != nil {
		return nil, err
	}
	err = w.Close()
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecryptData decrypt the data and extract the recipients and signer
func (e *PGPEncrypter) DecryptData(data []byte) (cleardata []byte, recipients []string, signer string, err error) {
	buf := bytes.NewBuffer(data)
	md, err := openpgp.ReadMessage(buf, &e.AllEntities, nil, nil)

	if err != nil {
		err = fmt.Errorf("Error decrypting message: %s", err)
		return
	}

	cleardata, err = ioutil.ReadAll(md.UnverifiedBody)

	if err != nil {
		cleardata = []byte{}
		return
	}

	if !md.IsSigned {
		err = ErrUnsignedMessage
	} else {
		if md.SignedBy != nil {
			signer = string(md.SignedBy.PublicKey.Fingerprint[:20])
		} else {
			err = ErrUnknownSigner
		}
		if md.SignatureError != nil {
			err = md.SignatureError
		}
	}

	recipients = []string{string(md.DecryptedWith.Entity.PrimaryKey.Fingerprint[:20])}

	return
}
