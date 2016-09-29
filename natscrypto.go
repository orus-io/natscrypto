package natscrypto

import (
	"bytes"
	"errors"
	"github.com/nats-io/nats"
	"sync"
	"time"
)

// NoReply can be used as the "reply" argument when no reply is needed
const NoReply = ""

var (
	// ErrNilConnection A nil connection was passed to a function expecting a non-nil one
	ErrNilConnection = errors.New("Nil Connection")
	// ErrNilEncrypter A nil encrypter was passed to a function expecting a non-nil one
	ErrNilEncrypter = errors.New("Nil Encrypter")
	// ErrNoRecipient An empty list of recipients was passed.
	ErrNoRecipient = errors.New("No Recipient. An empty list of recipient was passed.")

	// ErrUnknownSigner is returned by DecryptData is the message is signed by an
	// unknown identity
	ErrUnknownSigner = errors.New("Unknown Signer")
	// ErrUnsignedMessage is returned by DecryptData if the message is not pgp signed
	ErrUnsignedMessage = errors.New("Unsigned Message")

	// ErrSignerNotAuthorized is set on Msg when the signer is not authorized on a
	// subscription
	ErrSignerNotAuthorized = errors.New("natscrypto: Signer not authorized")
)

// NewConn wraps a nats.Conn in a Conn that uses the
// passed encrypter
// A same nats.Conn can be share among several natscrypto.Conn.
func NewConn(c *nats.Conn, identity string, encrypter Encrypter) (*Conn, error) {
	if c == nil {
		return nil, ErrNilConnection
	}
	if encrypter == nil {
		return nil, ErrNilEncrypter
	}
	if c.IsClosed() {
		return nil, nats.ErrConnectionClosed
	}
	ec := Conn{
		Conn:                       c,
		Encrypter:                  encrypter,
		Identity:                   identity,
		SubjectRecipients:          make(map[string][]string),
		ReplyRecipients:            make(map[string]replyRecipient),
		exitWatchReplyRecipients:   make(chan interface{}),
		defaultDecryptErrorHandler: nil,
	}
	go ec.watchReplyRecipients()
	return &ec, nil
}

// NewMsg initialize a Msg
func NewMsg(subject string, data []byte, sender string, recipients ...string) *Msg {
	return &Msg{
		Msg: &nats.Msg{
			Subject: subject,
			Data:    data,
		},
		Signer:     sender,
		Recipients: recipients,
	}
}

// Msg is a wrapper for nats.Msg with added Signer and Recipients
// There fields are filled by decryption or by the user for proper encryption
// The identities can be any string that the encoder will recognize as a unique
// identity, generally a fingerprint
type Msg struct {
	*nats.Msg
	Signer     string
	Recipients []string
	Error      error
}

// Encrypter is implemented by message encrypters
// Both function should be routine-safe as they may be called in parallel
// routines
type Encrypter interface {
	EncryptData(data []byte, recipients []string, signer string) ([]byte, error)
	DecryptData(data []byte) (cleardata []byte, recipients []string, signer string, err error)
}

type replyRecipient struct {
	Recipient string
	Expire    time.Time
}

// Conn is a nats connection on which every message
// sent is encrypted for recipients of the subject,
// and every message received is decrypted automatically
type Conn struct {
	*nats.Conn
	Encrypter                  Encrypter
	Identity                   string
	SubjectRecipients          map[string][]string
	ReplyRecipients            map[string]replyRecipient
	exitWatchReplyRecipients   chan interface{}
	recipientsLock             sync.RWMutex
	defaultDecryptErrorHandler DecryptErrorHandler
}

// MsgHandler is a callback function that processes messages delived
// to asynchronous subscribers
type MsgHandler func(msg *Msg)

// This var is to allow tests to provide a tweaked ticker
var timeNewTicker = time.NewTicker

func (c *Conn) cleanupReplyRecipients(t time.Time) {
	c.recipientsLock.Lock()
	defer c.recipientsLock.Unlock()
	for subject, entry := range c.ReplyRecipients {
		if t.After(entry.Expire) {
			delete(c.ReplyRecipients, subject)
		}
	}
}

func (c *Conn) watchReplyRecipients() {
	ticker := timeNewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-c.exitWatchReplyRecipients:
			break
		case t := <-ticker.C:
			c.cleanupReplyRecipients(t)
		}
	}
}

// Close closes the encrypted connection, _not_ the underlying nats.Conn.
// To close both the encryption layer and the actual nats.Conn, use
// CloseAll()
func (c *Conn) Close() {
	c.exitWatchReplyRecipients <- nil
}

// CloseAll closes the encrypted connection _and_ the underlying nats.Conn
func (c *Conn) CloseAll() {
	c.Close()
	c.Conn.Close()
}

// SetDefaultDecryptErrorHandler sets the default decrypt error handler of
// all the subscriptions to come.
// Already created subscriptions will be untouched
func (c *Conn) SetDefaultDecryptErrorHandler(handler DecryptErrorHandler) {
	c.defaultDecryptErrorHandler = handler
}

// SetSubjectRecipients associates a list of recipients to a subject
// if subject is "", the recipients are used as default for subjects having no
// explicit recipients
func (c *Conn) SetSubjectRecipients(subject string, recipients []string) {
	c.recipientsLock.Lock()
	defer c.recipientsLock.Unlock()
	c.SubjectRecipients[subject] = recipients
}

// SetMultiSubjectRecipients associates recipients to subjects
func (c *Conn) SetMultiSubjectRecipients(recipients map[string][]string) {
	c.recipientsLock.Lock()
	defer c.recipientsLock.Unlock()
	for subject, recipients := range recipients {
		c.SubjectRecipients[subject] = recipients
	}
}

// GetRecipients returns the default recipients for a given subject.
func (c *Conn) GetRecipients(subject string) []string {
	c.recipientsLock.RLock()
	defer c.recipientsLock.RUnlock()
	recipients, ok := c.SubjectRecipients[subject]
	if ok {
		return recipients
	}
	replyRecipient, ok := c.ReplyRecipients[subject]
	if ok {
		// A reply is supposed to serve only once
		delete(c.ReplyRecipients, subject)
		return []string{replyRecipient.Recipient}
	}
	recipients, ok = c.SubjectRecipients[""]
	if ok {
		return recipients
	}
	return []string{}
}

func (c *Conn) encryptData(data []byte, reply string, recipients []string) ([]byte, error) {
	return c.encryptDataWithSender(data, reply, recipients, c.Identity)
}

func (c *Conn) encryptDataWithSender(data []byte, reply string, recipients []string, sender string) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, ErrNoRecipient
	}
	if reply != NoReply {
		data = append([]byte("@@reply@@="+reply+";"), data...)
	}
	return c.Encrypter.EncryptData(data, recipients, sender)
}

func (c *Conn) decryptMsg(msg *nats.Msg) *Msg {
	data, recipients, signer, err := c.Encrypter.DecryptData(msg.Data)
	m := Msg{
		Msg:        msg,
		Signer:     signer,
		Recipients: recipients,
		Error:      err,
	}
	if m.Reply != "" {
		m.Reply = ""
	}
	if len(data) != 0 {
		if bytes.HasPrefix(data, []byte("@@reply@@=")) {
			lastPos := bytes.Index(data, []byte(";"))
			m.Reply = string(data[10:lastPos])
			data = data[lastPos+1:]
			if m.Reply != "" && signer != "" {
				c.ReplyRecipients[m.Reply] = replyRecipient{
					Recipient: signer,
					// TODO make the timeout into a per-subject setting
					Expire: time.Now().Add(5 * time.Minute),
				}
			}
		}
		m.Data = data
	}
	return &m
}

// Publish publishes the data argument to the given subject. The data argument
// will be encrypted for the destination identities of the subject
func (c *Conn) Publish(subject string, data []byte) error {
	return c.PublishFor(subject, data, c.GetRecipients(subject)...)
}

// PublishFor publishes to a subject for specific recipients
func (c *Conn) PublishFor(subject string, data []byte, recipients ...string) error {
	b, err := c.encryptData(data, NoReply, recipients)
	if err != nil {
		return err
	}
	return c.Conn.Publish(subject, b)
}

// PublishMsg publishes the Msg structure, which includes the
// Subject, an optional Reply and an optional Data field.
func (c *Conn) PublishMsg(m *Msg) error {
	if m == nil {
		return nats.ErrInvalidMsg
	}
	if m.Recipients == nil || len(m.Recipients) == 0 {
		m.Recipients = c.GetRecipients(m.Subject)
	}
	if m.Signer == "" {
		m.Signer = c.Identity
	}
	var reply = m.Reply
	if m.Reply != "" {
		m.Reply = ""
	}
	var err error
	m.Data, err = c.encryptDataWithSender(m.Data, reply, m.Recipients, m.Signer)
	if err != nil {
		return err
	}
	return c.Conn.PublishMsg(m.Msg)
}

// PublishRequest will perform a Publish() excpecting a response on the
// reply subject. Use Request() for automatically waiting for a response
// inline.
// In this specific version of PublishRequest, the 'reply' gets encrypted too
func (c *Conn) PublishRequest(subj, reply string, data []byte) error {
	return c.PublishRequestFor(subj, reply, data, c.GetRecipients(subj)...)
}

// PublishRequestFor is PublishRequest with explicit recipients
func (c *Conn) PublishRequestFor(subj, reply string, data []byte, recipients ...string) error {
	b, err := c.encryptData(data, reply, recipients)
	if err != nil {
		return err
	}
	return c.Conn.Publish(subj, b)
}

// Request will create an Inbox and perform a Request() call
// with the Inbox reply for the data v. A response will be
// decrypted.
// This implementation is copied from nats.Conn.Request, but using
// our own PublishRequest that will encrypt the reply, and our
// own Subscription that will decrypt the incoming message
func (c *Conn) Request(subj string, data []byte, timeout time.Duration) (*Msg, error) {
	return c.RequestFor(subj, data, timeout, c.GetRecipients(subj)...)
}

// RequestFor is Request with explicit recipients
func (c *Conn) RequestFor(subj string, data []byte, timeout time.Duration, recipients ...string) (*Msg, error) {
	inbox := nats.NewInbox()
	ch := make(chan *nats.Msg, nats.RequestChanLen)

	s, err := c.Conn.ChanSubscribe(inbox, ch)
	if err != nil {
		return nil, err
	}
	s.AutoUnsubscribe(1)
	defer s.Unsubscribe()

	es := newSubscription(c).setSub(s)

	err = c.PublishRequestFor(subj, inbox, data, recipients...)
	if err != nil {
		return nil, err
	}
	return es.NextMsg(timeout)
}

// DecryptErrorHandler are callbacks for decryption errors
// if the function returns a nil Msg, the message will stop its course and
// never make it down the to final handler.
type DecryptErrorHandler func(sub *Subscription, msg *Msg) *Msg

func newSubscription(c *Conn) *Subscription {
	s := Subscription{
		Conn:                c,
		decryptErrorHandler: c.defaultDecryptErrorHandler,
	}
	return &s
}

// Subscription wraps nats.Subscription and override its 'NextMsg' function
// it also provides callbacks on decryption errors, so a subscriber can
// handle such errors or even reply to badly or unsigned requests.
// The default error handler will drop the message so the final handler
// never sees it.
type Subscription struct {
	*nats.Subscription
	Conn                *Conn
	decryptErrorHandler DecryptErrorHandler
	upChan              chan *nats.Msg
	authorizedSigners   []string
}

func (s *Subscription) setSub(sub *nats.Subscription) *Subscription {
	s.Subscription = sub
	return s
}

// SetAuthorizedSigners changes the list of signers allowed on this subscription.
// Any message received from a signer outside this list will be stopped
// and handled as error
func (s *Subscription) SetAuthorizedSigners(signers ...string) {
	s.authorizedSigners = signers
}

// SetDecryptErrorHandler sets a callback that is called when a decryption
// error occurs.
// The handler can:
// - return a Msg, possibly the original one. In this case, the message will
//   be passed down to the final subscriptor (cb, sync or chan)
// - return nil, which will make the message disappear and never reach the final
//   handler. NextMsg() will however return the original Msg.Error as an error
func (s *Subscription) SetDecryptErrorHandler(handler DecryptErrorHandler) {
	s.decryptErrorHandler = handler
}

func (s *Subscription) decryptMsg(msg *nats.Msg) (decryptedMsg *Msg, err error) {
	decryptedMsg = s.Conn.decryptMsg(msg)

	if decryptedMsg.Error == nil {
		as := s.authorizedSigners
		if len(as) != 0 {
			var authorized bool
			for _, s := range as {
				if decryptedMsg.Signer == s {
					authorized = true
					break
				}
			}
			if !authorized {
				decryptedMsg.Error = ErrSignerNotAuthorized
			}
		}
	}

	if decryptedMsg.Error == nil {
		return
	}

	err = decryptedMsg.Error
	if s.decryptErrorHandler != nil {
		decryptedMsg = s.decryptErrorHandler(s, decryptedMsg)
		if decryptedMsg != nil {
			// the 'new' decryptedMsg may still carry an Error,
			// but this error will not stop the current flow anymore.
			// It will need to be handled by the final handler
			err = nil
		}
	}
	// at this point decryptedMsg may be nil, meaning the decryption
	// failed and the error handler decided not to let it go through
	return
}

// makeHandler returns a decrypting message handler
func (s *Subscription) makeHandler(handler MsgHandler) nats.MsgHandler {
	if handler == nil {
		return nil
	}
	return func(msg *nats.Msg) {
		decryptedMsg, err := s.decryptMsg(msg)
		if err != nil {
			// An error stopped the message from going further.
			// The error handler, if any, was already called by
			// decryptMsg
			return
		}

		handler(decryptedMsg)
	}
}

// makeDecryptingChan returns a *nats.Msg chan. Its output is consumed by
// a goroutine that decrypt the messages and push them to the given chan
func (s *Subscription) makeDecryptingChan(ch chan *Msg) chan *nats.Msg {
	if s.upChan != nil {
		panic("Subscription already have an upstream channel.")
	}
	s.upChan = make(chan *nats.Msg)
	go func() {
		// loop will stop when upChan is closed by Unsubscribe
		for msg := range s.upChan {
			decryptedMsg, err := s.decryptMsg(msg)
			if err != nil {
				// An error stopped the message from going further.
				// The error handler, if any, was already called by
				// decryptMsg
				return
			}

			ch <- decryptedMsg
		}
	}()
	return s.upChan
}

// NextMsg returns the next message available to a synchronous subscriber of block
// until one is available.
// Badly encrypted incoming messages will return an error
func (s *Subscription) NextMsg(timeout time.Duration) (*Msg, error) {
	msg, err := s.Subscription.NextMsg(timeout)
	if err != nil {
		return nil, err
	}
	nextMsg, err := s.decryptMsg(msg)
	if err != nil {
		return nil, err
	}
	return nextMsg, nil
}

// Unsubscribe will remove interest in the given subject.
func (s *Subscription) Unsubscribe() error {
	err := s.Subscription.Unsubscribe()
	if s.upChan != nil {
		// release the conversion goroutine
		close(s.upChan)
	}
	return err
}

// Subscribe will create a subscription on the given subject and process incoming
// messages using the specified Handler. The Handler should be a func that matches
// a signature from the description of Handler from above.
// signers is an optional list of authorized signers
func (c *Conn) Subscribe(subject string, cb MsgHandler, signers ...string) (*Subscription, error) {
	return c.QueueSubscribe(subject, "", cb, signers...)
}

// ChanSubscribe will place all messages received on the channel.
// You should not close the channel until sub.Unsubscribe() has been called.
func (c *Conn) ChanSubscribe(subject string, ch chan *Msg, signers ...string) (*Subscription, error) {
	return c.ChanQueueSubscribe(subject, "", ch, signers...)
}

// QueueSubscribe will create a queue subscription on the given subject and process
// incoming messages using the specified Handler.
func (c *Conn) QueueSubscribe(subject, queue string, cb MsgHandler, signers ...string) (*Subscription, error) {
	var err error
	sub := newSubscription(c)
	if len(signers) != 0 {
		sub.SetAuthorizedSigners(signers...)
	}
	sub.Subscription, err = c.Conn.QueueSubscribe(subject, queue, sub.makeHandler(cb))
	if err != nil {
		return nil, err
	}
	return sub, nil
}

// ChanQueueSubscribe will place all messages received on the channel.
// You should not close the channel until sub.Unsubscribe() has been called.
func (c *Conn) ChanQueueSubscribe(subject, group string, ch chan *Msg, signers ...string) (*Subscription, error) {
	var err error
	sub := newSubscription(c)
	if len(signers) != 0 {
		sub.SetAuthorizedSigners(signers...)
	}
	sub.Subscription, err = c.Conn.ChanQueueSubscribe(subject, group, sub.makeDecryptingChan(ch))
	if err != nil {
		return nil, err
	}
	return sub, nil
}

// SubscribeSync is syntactic sugar for Subscribe(subject, nil).
func (c *Conn) SubscribeSync(subj string, signers ...string) (*Subscription, error) {
	var err error
	sub := newSubscription(c)
	if len(signers) != 0 {
		sub.SetAuthorizedSigners(signers...)
	}
	sub.Subscription, err = c.Conn.SubscribeSync(subj)
	if err != nil {
		return nil, err
	}
	return sub, nil
}
