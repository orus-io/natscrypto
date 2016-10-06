package natscrypto

import (
	"errors"
	"fmt"
	"github.com/nats-io/nats"
	"reflect"
	"time"
)

// ErrNonEncryptedResponse is returned by PublishUnencrypted if the response
// is not encrypted.
var ErrNonEncryptedResponse = errors.New("Non encrypted Response")

// Dissect the cb Handler's signature (copied from nats/enc.go)
func argInfo(cb nats.Handler) (reflect.Type, int) {
	cbType := reflect.TypeOf(cb)
	if cbType.Kind() != reflect.Func {
		panic("nats: Handler needs to be a func")
	}
	numArgs := cbType.NumIn()
	if numArgs == 0 {
		return nil, numArgs
	}
	return cbType.In(numArgs - 1), numArgs
}

var emptyMsgType = reflect.TypeOf(&Msg{})

// EncodedConn is a Conn with encoding/decoding capabilities
type EncodedConn struct {
	*Conn
	Enc nats.Encoder
}

// EncodedSubscription wraps a Conn and add a Next() function
// That decode incoming messages
type EncodedSubscription struct {
	*Subscription
	Enc nats.Encoder
}

// Next decodes the next message available to a synchronous subscriber or block
// until one is available.
func (s EncodedSubscription) Next(vPtr interface{}, timeout time.Duration) error {
	msg, err := s.NextMsg(timeout)
	if err != nil {
		return err
	}
	return s.Enc.Decode(msg.Subject, msg.Data, vPtr)
}

// NextSubject decodes the next message available to a synchronous subscriber or block
// until one is available.
func (s EncodedSubscription) NextSubject(subject *string, vPtr interface{}, timeout time.Duration) error {
	msg, err := s.NextMsg(timeout)
	if err != nil {
		return err
	}
	*subject = msg.Subject
	return s.Enc.Decode(msg.Subject, msg.Data, vPtr)
}

// NextSubjectReply decodes the next message available to a synchronous subscriber or block
// until one is available.
func (s EncodedSubscription) NextSubjectReply(subject, reply *string, vPtr interface{}, timeout time.Duration) error {
	msg, err := s.NextMsg(timeout)
	if err != nil {
		return err
	}
	*subject = msg.Subject
	*reply = msg.Reply
	return s.Enc.Decode(msg.Subject, msg.Data, vPtr)
}

func (s *EncodedSubscription) makeMsgHandler(cb nats.Handler) (MsgHandler, error) {
	argType, numArgs := argInfo(cb)
	if argType == nil {
		return nil, errors.New("natscrypto: Handler requires at least one argument")
	}
	if numArgs > 4 {
		return nil, errors.New("natscrypto: Handler requires at most 4 arguments")
	}

	cbValue := reflect.ValueOf(cb)
	if argType == emptyMsgType {
		return cb.(func(*Msg)), nil
	}

	oValueType := argType
	argTypeIsPtr := false

	if argType.Kind() == reflect.Ptr {
		oValueType = argType.Elem()
		argTypeIsPtr = true
	}

	return func(m *Msg) {
		var oV []reflect.Value
		var oPtr = reflect.New(oValueType)

		if err := s.Enc.Decode(m.Subject, m.Data, oPtr.Interface()); err != nil {
			if s.Subscription.decryptErrorHandler != nil {
				m.Error = err
				s.Subscription.decryptErrorHandler(s.Subscription, m)
			}
			return
		}

		var oValue reflect.Value

		if argTypeIsPtr {
			oValue = oPtr
		} else {
			oValue = reflect.Indirect(oPtr)
		}

		// Callback Arity
		switch numArgs {
		case 1:
			oV = []reflect.Value{oValue}
		case 2:
			subV := reflect.ValueOf(m.Subject)
			oV = []reflect.Value{subV, oValue}
		case 3:
			subV := reflect.ValueOf(m.Subject)
			replyV := reflect.ValueOf(m.Reply)
			oV = []reflect.Value{subV, replyV, oValue}
		case 4:
			subV := reflect.ValueOf(m.Subject)
			replyV := reflect.ValueOf(m.Reply)
			signerV := reflect.ValueOf(m.Signer)
			oV = []reflect.Value{subV, replyV, signerV, oValue}
		}
		cbValue.Call(oV)
	}, nil
}

// NewEncodedConn wraps a Conn with encoding/decoding utilities
func NewEncodedConn(c *Conn, encType string) (*EncodedConn, error) {
	if c == nil {
		return nil, ErrNilConnection
	}
	if c.IsClosed() {
		return nil, nats.ErrConnectionClosed
	}
	encoder := nats.EncoderForType(encType)
	if encoder == nil {
		return nil, fmt.Errorf("natscrypto: No encoder registered for '%s'", encType)
	}
	return &EncodedConn{Conn: c, Enc: encoder}, nil
}

// Publish publishes the data argument to the given subject. The data argument
// will be encoded using the associated encoder.
func (c *EncodedConn) Publish(subject string, v interface{}) error {
	return c.PublishFor(subject, v, c.GetRecipients(subject)...)
}

// PublishFor same as Publish for a specific recipient
func (c *EncodedConn) PublishFor(subject string, v interface{}, recipients ...string) error {
	b, err := c.Enc.Encode(subject, v)
	if err != nil {
		return err
	}
	return c.Conn.PublishFor(subject, b, recipients...)
}

// PublishUnencrypted publishes the data encoded only, not encrypted
func (c *EncodedConn) PublishUnencrypted(subject string, v interface{}) error {
	b, err := c.Enc.Encode(subject, v)
	if err != nil {
		return err
	}
	return c.Conn.Conn.Publish(subject, b)
}

// PublishRequest will perform a Publish() expecting a response on the
// reply subject. Use Request() for automatically waiting for a response
// inline.
func (c *EncodedConn) PublishRequest(subject, reply string, v interface{}) error {
	return c.PublishRequestFor(subject, reply, v, c.GetRecipients(subject)...)
}

// PublishRequestFor same as PublishRequest for specific recipients
func (c *EncodedConn) PublishRequestFor(subject, reply string, v interface{}, recipients ...string) error {
	b, err := c.Enc.Encode(subject, v)
	if err != nil {
		return err
	}
	return c.Conn.PublishRequestFor(subject, reply, b, recipients...)
}

// PublishRequestUnencrypted publishes the data encoded only, not encrypted.
func (c *EncodedConn) PublishRequestUnencrypted(subject, reply string, v interface{}) error {
	b, err := c.Enc.Encode(subject, v)
	if err != nil {
		return err
	}
	return c.Conn.Conn.PublishRequest(subject, reply, b)
}

// Request will create an Inbox and perform a Request() call
// with the Inbox reply for the data v. A response will be
// decoded into the vPtrResponse.
func (c *EncodedConn) Request(subject string, v interface{}, vPtr interface{}, timeout time.Duration) error {
	return c.RequestFor(subject, v, vPtr, timeout, c.GetRecipients(subject)...)
}

// RequestFor same as Request for specific recipients
func (c *EncodedConn) RequestFor(subject string, v interface{}, vPtr interface{}, timeout time.Duration, recipients ...string) error {
	b, err := c.Enc.Encode(subject, v)
	if err != nil {
		return err
	}
	m, err := c.Conn.RequestFor(subject, b, timeout, recipients...)
	if err != nil {
		return err
	}
	if reflect.TypeOf(vPtr) == emptyMsgType {
		mPtr := vPtr.(*Msg)
		*mPtr = *m
	} else {
		err = c.Enc.Decode(m.Subject, m.Data, vPtr)
	}
	return err
}

// RequestUnsafe same as Request but if the response is not encryted or signed,
// the message will be decoded anyway
func (c *EncodedConn) RequestUnsafe(subject string, v interface{}, vPtr interface{}, timeout time.Duration) (encrypted bool, err error) {
	inbox := nats.NewInbox()
	ch := make(chan *nats.Msg, nats.RequestChanLen)

	s, err := c.Conn.Conn.ChanSubscribe(inbox, ch)
	if err != nil {
		return false, err
	}
	s.AutoUnsubscribe(1)
	defer s.Unsubscribe()

	es := newSubscription(c.Conn).setSub(s)
	ecs := EncodedSubscription{es, c.Enc}

	encrypted = true
	es.SetDecryptErrorHandler(func(sub *Subscription, msg *Msg) *Msg {
		encrypted = false
		msg.Error = nil
		return msg
	})

	err = c.PublishRequest(subject, inbox, v)
	if err != nil {
		return false, err
	}
	return encrypted, ecs.Next(vPtr, timeout)
}

// RequestUnencrypted same as Request but the emitted message will _not_ be
// encrypted. The reponse may be encrypted though, in which case it is transparenly
// decrypted, and the returned bool is 'true'
func (c *EncodedConn) RequestUnencrypted(subject string, v interface{}, vPtr interface{}, timeout time.Duration) (encrypted bool, err error) {
	inbox := nats.NewInbox()
	ch := make(chan *nats.Msg, nats.RequestChanLen)

	s, err := c.Conn.Conn.ChanSubscribe(inbox, ch)
	if err != nil {
		return false, err
	}
	s.AutoUnsubscribe(1)
	defer s.Unsubscribe()

	es := newSubscription(c.Conn).setSub(s)
	ecs := EncodedSubscription{es, c.Enc}

	encrypted = true
	es.SetDecryptErrorHandler(func(sub *Subscription, msg *Msg) *Msg {
		encrypted = false
		msg.Error = nil
		return msg
	})

	err = c.PublishRequestUnencrypted(subject, inbox, v)
	if err != nil {
		return false, err
	}
	return encrypted, ecs.Next(vPtr, timeout)
}

// Subscribe will create a subscription on the given subject and process incoming
// messages using the specified Handler. The Handler should be a func that matches
// a signature from the description of Handler from above.
func (c *EncodedConn) Subscribe(subject string, cb nats.Handler) (*EncodedSubscription, error) {
	return c.subscribe(subject, "", cb)
}

// QueueSubscribe will create a queue subscription on the given subject and process
// incoming messages using the specified Handler. The Handler should be a func that
// matches a signature from the description of Handler from above.
func (c *EncodedConn) QueueSubscribe(subject, queue string, cb nats.Handler) (*EncodedSubscription, error) {
	return c.subscribe(subject, queue, cb)
}

// SubscribeSync is syntactic sugar for Subscribe(subject, nil).
func (c *EncodedConn) SubscribeSync(subj string) (*EncodedSubscription, error) {
	sub, err := c.Conn.SubscribeSync(subj)
	if err != nil {
		return nil, err
	}
	return &EncodedSubscription{sub, c.Enc}, nil
}

// Internal implementation that all public functions will use.
func (c *EncodedConn) subscribe(subject, queue string, cb nats.Handler) (*EncodedSubscription, error) {
	if cb == nil {
		return c.SubscribeSync(subject)
	}
	es := EncodedSubscription{nil, c.Enc}
	handler, err := es.makeMsgHandler(cb)
	if err != nil {
		return nil, err
	}
	es.Subscription, err = c.Conn.QueueSubscribe(subject, queue, handler)
	if err != nil {
		return nil, err
	}
	return &es, nil
}
