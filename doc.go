/*
Package natscrypto provides a PKI encryption layout on top of nats.Conn,
as well a port of nats.EncodedConn on top of it.

Introduction

Once connected to a nats server, any client can subscribe and publish to any
subject. When the nats server is shared among entities that should not be
able to eardrop on each other, it can be a problem.

Our approach is to encrypt and sign each message with openpgp, so the actors
can keep information private and certify the origin of the message.

This package is our implementation of this approach. The openpgp encrytion
is the only provided one, but adding one would be pretty straighforward.

Basic usage

Once a connection is established with the nats server, we can wrap it in
a natscrypto connection. Any message sent through this wrapper will be
encrypted for the desired recipients, and any incoming message will be
first decrypted and its signer verified

First, we need to setup an encrypter that hold our keyring:

	var (
		publicEntities openpgp.EntityList
		privateEntity *openpgp.Entity
	)

	// Init the encrypter
    encrypter := natscrypto.NewPGPEncrypter(publicEntities...)
	encrypter.AddEntity(privateEntity)

	// myidentity is my private key fingerprint. Only the encrypter
	// needs to handle the actual keys, the rest of natscrypto only
	// manipulates string ids. Their exact signification depends on
	// the encrypter
	myidentity := string(privateEntity.PrimaryKey.FingerPrint[:20])

	// Get the identity of the potential recipients for future use
	rec1 := string(publicEntities[0].PrimaryKey.FingerPrint[:20])
	rec2 := string(publicEntities[1].PrimaryKey.FingerPrint[:20])
	rec3 := string(publicEntities[2].PrimaryKey.FingerPrint[:20])

Then we can wrap the connection:

	conn := nats.Connect(...)
	eConn := natscrypto.NewConn(conn, myidentity, encrypter)

Post a message:

	// Declare for which identities should the messages sent to "test" be
	// encrypted
	eConn.SetSubjectRecipients("test", rec1)

	// The message ("hello") will be signed using the private key
	eConn.Publish("test", []byte("hello"))

	// We can publish for arbitrary recipients on a single call
	eConn.PublishFor("test", []byte("hello"), rec2, rec3)

Subscribe:

	// any known emitter will be accepted on this subscription
	sub, err := eConn.SubscribeSync("incoming")

	// only rec1 will be accepted on this one
	sub, err := eConn.Subscribe("other", func(*natscrypto Msg) {}, rec1)

The received messages have 3 extra attributes in addition to a classic
nats.Msg:

- Signer: the id of the verified signer, or empty.
- Recipients: the ids of the recipients (only one when receiving, but could be more
  when emitting).
- Error: in some cases we can get messages that could be decrypted but have a signer
  problem. In a error handler, the 'Error' attribute of the message will be set so
  we can handle unknown signers gracefully (for example)


Encoding

The nats.EncodedConn cannot work on top of a natscrypto.Conn, so we ported it.
natscrypto.EncodedConn has both the features of natscrypto.Conn and nats.EncodedConn

*/
package natscrypto
