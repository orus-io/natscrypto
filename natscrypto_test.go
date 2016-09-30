package natscrypto

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats"
	"github.com/stretchr/testify/assert"
)

type RunSupport interface {
	Run(string, func(t *testing.T)) bool
}

// Poorly Immitate testing.T.Run on go<1.7 versions
func Run(t testing.TB, name string, test func(t *testing.T)) bool {
	if runner, ok := t.(RunSupport); ok {
		return runner.Run(name, test)
	}
	test(t.(*testing.T))
	return t.Failed()
}

func TimeoutChan(duration time.Duration) chan bool {
	timeout := make(chan bool, 1)
	go func() {
		time.Sleep(duration)
		timeout <- true
	}()
	return timeout
}

type DummyEncrypter struct{}

func (DummyEncrypter) EncryptData(data []byte, recipients []string, signer string) ([]byte, error) {
	out := []byte{}
	out = append(out, "From: "...)
	out = append(out, signer...)
	out = append(out, '\n')
	for _, r := range recipients {
		out = append(out, "To: "...)
		out = append(out, r...)
		out = append(out, '\n')
	}
	out = append(out, data...)
	return out, nil
}

func (DummyEncrypter) DecryptData(data []byte) (cleardata []byte, recipients []string, signer string, err error) {
	lines := bytes.Split(data, []byte{'\n'})

	for i, line := range lines {
		l := string(line)
		if strings.HasPrefix(l, "From: ") {
			signer = l[6:]
		} else if strings.HasPrefix(l, "To: ") {
			recipients = append(recipients, l[4:])
		} else {
			cleardata = bytes.Join(lines[i:], []byte{'\n'})
			break
		}
	}
	return
}

var ErrEncryptFailed = errors.New("Encrypt Failed")
var ErrDecryptFailed = errors.New("Decrypt Failed")

type FailingEncrypter struct{}

func (FailingEncrypter) EncryptData(data []byte, recipients []string, signer string) ([]byte, error) {
	return data, ErrEncryptFailed
}

func (FailingEncrypter) DecryptData(data []byte) (cleardata []byte, recipients []string, signer string, err error) {
	err = ErrDecryptFailed
	return
}

func TestNewConn(t *testing.T) {
	natsSrv := InitNatsTestServer(t)
	defer natsSrv.Shutdown()

	c := natsSrv.Connect(t)
	c.Close()

	_, err := NewConn(nil, "me", nil)
	assert.Equal(t, "Nil Connection", err.Error())

	_, err = NewConn(c, "me", nil)
	assert.Equal(t, "Nil Encrypter", err.Error())

	_, err = NewConn(c, "me", DummyEncrypter{})
	assert.Equal(t, nats.ErrConnectionClosed, err)

}

func TestSetSubject(t *testing.T) {
	natsSrv := InitNatsTestServer(t)
	defer natsSrv.Shutdown()

	c := natsSrv.Connect(t)

	ec, err := NewConn(c, "me", DummyEncrypter{})
	assert.Nil(t, err)

	ec.SetSubjectRecipients("test", []string{"riri", "fifi", "loulou"})
	assert.Equal(t, []string{"riri", "fifi", "loulou"}, ec.GetRecipients("test"))

	ec.SetMultiSubjectRecipients(map[string][]string{
		"ducks": []string{"Picsou", "Donald"},
	})
	assert.Equal(t, []string{"riri", "fifi", "loulou"}, ec.GetRecipients("test"))
	assert.Equal(t, []string{"Picsou", "Donald"}, ec.GetRecipients("ducks"))
	assert.Equal(t, []string{}, ec.GetRecipients("any"))

	ec.SetSubjectRecipients("", []string{"juju"})
	assert.Equal(t, []string{"riri", "fifi", "loulou"}, ec.GetRecipients("test"))
	assert.Equal(t, []string{"Picsou", "Donald"}, ec.GetRecipients("ducks"))
	assert.Equal(t, []string{"juju"}, ec.GetRecipients("any"))

}

func TestWatchReplyRecipients(t *testing.T) {
	var (
		tickerChan chan time.Time
	)

	t1 := time.Date(2016, 9, 21, 17, 44, 0, 0, time.UTC)
	t2 := time.Date(2016, 9, 21, 17, 45, 0, 0, time.UTC)
	t3 := time.Date(2016, 9, 21, 17, 46, 0, 0, time.UTC)

	timeNewTicker = func(time.Duration) *time.Ticker {
		// We will generate the ticks ourselves, to we need to
		// make sure the ticker does no send anything.
		// It is safe to assume that a passing test run will not run for more
		// than 1 hour
		ticker := time.NewTicker(time.Hour)
		tickerChan = make(chan time.Time)
		ticker.C = tickerChan
		return ticker
	}
	defer func() { timeNewTicker = time.NewTicker }()

	natsSrv := InitNatsTestServer(t)
	defer natsSrv.Shutdown()

	c := natsSrv.Connect(t)
	if c == nil {
		return
	}

	assert.Nil(t, tickerChan)

	ec, err := NewConn(c, "me", DummyEncrypter{})
	if err != nil {
		t.Errorf("Could not init the encrypted conn: %s", err)
		c.Close()
		return
	}
	defer ec.Close()

	time.Sleep(time.Millisecond)
	assert.NotNil(t, tickerChan)

	ec.ReplyRecipients["test"] = replyRecipient{Recipient: "me", Expire: t2}

	select {
	case tickerChan <- t1:
	default:
		t.Error("Could not write to the channed")
	}
	time.Sleep(time.Millisecond)
	assert.Equal(t, 1, len(ec.ReplyRecipients))

	select {
	case tickerChan <- t3:
	default:
		t.Error("Could not write to the channed")
	}

	time.Sleep(time.Millisecond)
	assert.Equal(t, 0, len(ec.ReplyRecipients))
}

func TestSubscriptions(t *testing.T) {
	natsSrv := InitNatsTestServer(t)
	defer natsSrv.Shutdown()

	c := natsSrv.Connect(t)
	if c == nil {
		return
	}

	ec, err := NewConn(c, "me", DummyEncrypter{})
	if err != nil {
		t.Errorf("Could not init the encrypted conn: %s", err)
		c.Close()
		return
	}
	defer ec.Close()
	ec.SetSubjectRecipients("test", []string{"riri", "fifi", "loulou"})

	sub, err := ec.SubscribeSync("test")
	if err != nil {
		assert.Error(t, err)
		return
	}
	sub.SetAuthorizedSigners("me")
	defer sub.Unsubscribe()

	received := make(chan *Msg, 1)
	s, err := ec.Subscribe("test", func(msg *Msg) { received <- msg }, "me")
	if err != nil {
		assert.Error(t, err)
		return
	}
	defer s.Unsubscribe()

	ch := make(chan *Msg)
	s, err = ec.ChanSubscribe("test", ch)
	if err != nil {
		assert.Error(t, err)
		return
	}
	defer s.Unsubscribe()

	ec.Publish("test", []byte("Salut !"))

	// Test sync subscription
	msg, err := sub.NextMsg(time.Second)
	assert.Nil(t, err)
	assert.Equal(t, "me", msg.Signer)
	assert.Equal(t, []string{"riri", "fifi", "loulou"}, msg.Recipients)

	// Test acync subscription
	timeout := TimeoutChan(time.Second)
	select {
	case <-timeout:
		t.Errorf("async subscription callback never called")
	case msg := <-received:
		assert.NotNil(t, msg)
		assert.Equal(t, "me", msg.Signer)
		assert.Equal(t, []string{"riri", "fifi", "loulou"}, msg.Recipients)
	}

	// Test chan subscription
	timeout = TimeoutChan(time.Second)
	select {
	case <-timeout:
		t.Errorf("chan subscription never received msg")
	case msg := <-ch:
		assert.Equal(t, "me", msg.Signer)
		assert.Equal(t, []string{"riri", "fifi", "loulou"}, msg.Recipients)
	}
}

func TestEncryptionFailures(t *testing.T) {
	natsSrv := InitNatsTestServer(t)
	defer natsSrv.Shutdown()

	c := natsSrv.Connect(t)
	if c == nil {
		return
	}

	ec, err := NewConn(c, "me", FailingEncrypter{})
	if err != nil {
		t.Errorf("Could not init the encrypted conn: %s", err)
		c.Close()
		return
	}
	defer ec.Close()

	ec.SetSubjectRecipients("test", []string{"somebody"})

	err = ec.Publish("test", []byte("Coucou"))
	assert.Equal(t, err, ErrEncryptFailed)

	err = ec.PublishMsg(NewMsg("test", []byte("Coucou"), ""))
	assert.Equal(t, err, ErrEncryptFailed)

	err = ec.PublishRequest("test", "replysubj", []byte("Coucou"))
	assert.Equal(t, err, ErrEncryptFailed)
}

func TestDecryptionFailures(t *testing.T) {
	natsSrv := InitNatsTestServer(t)
	defer natsSrv.Shutdown()

	c := natsSrv.Connect(t)
	if c == nil {
		return
	}

	ec, err := NewConn(c, "me", FailingEncrypter{})
	if err != nil {
		t.Errorf("Could not init the encrypted conn: %s", err)
		c.Close()
		return
	}
	defer ec.Close()

	Run(t, "Subscribe no error handler", func(t *testing.T) {
		sub, err := ec.Subscribe("test", func(*Msg) { t.Error("Callback was called") })
		assert.Nil(t, err)
		defer func() { assert.Nil(t, sub.Unsubscribe()) }()

		// send an unencrypted message
		assert.Nil(t, ec.Conn.Publish("test", []byte("Hello")))

		// Make sure our callback would be called if attempted to
		time.Sleep(time.Millisecond)
	})

	Run(t, "SyncSubscribe no error handler", func(t *testing.T) {
		sub, err := ec.SubscribeSync("test")
		assert.Nil(t, err)
		defer func() { assert.Nil(t, sub.Unsubscribe()) }()

		// send an unencrypted message
		assert.Nil(t, ec.Conn.Publish("test", []byte("Hello")))

		msg, err := sub.NextMsg(time.Millisecond)
		assert.Nil(t, msg)
		assert.Equal(t, ErrDecryptFailed, err)
	})

	Run(t, "ChanSubscribe no error handler", func(t *testing.T) {
		ch := make(chan *Msg)
		defer close(ch)
		go func() {
			_, ok := <-ch
			if !ok {
				return
			}
			t.Errorf("Received a message")
		}()
		sub, err := ec.ChanSubscribe("test", ch)
		assert.Nil(t, err)
		defer func() { assert.Nil(t, sub.Unsubscribe()) }()

		// send an unencrypted message
		assert.Nil(t, ec.Conn.Publish("test", []byte("Hello")))

		// Make sure our callback would be called if attempted to
		time.Sleep(time.Millisecond)

	})

	ec.SetDefaultDecryptErrorHandler(
		func(sub *Subscription, msg *Msg) *Msg { return msg },
	)

	Run(t, "Subscribe pass through handler", func(t *testing.T) {
		var hit = make(chan bool, 1)
		sub, err := ec.Subscribe("test", func(msg *Msg) {
			hit <- true
			assert.Equal(t, ErrDecryptFailed, msg.Error)
		})
		assert.Nil(t, err)
		defer func() { assert.Nil(t, sub.Unsubscribe()) }()

		// send an unencrypted message
		assert.Nil(t, ec.Conn.Publish("test", []byte("Hello")))

		timeout := TimeoutChan(time.Second)
		select {
		case <-timeout:
			t.Error("The callback was never called")
		case <-hit:
			t.Log("Callback hit !")
		}
	})

	Run(t, "Subscribe pass through handler", func(t *testing.T) {
		sub, err := ec.SubscribeSync("test")
		assert.Nil(t, err)
		defer func() { assert.Nil(t, sub.Unsubscribe()) }()

		// send an unencrypted message
		assert.Nil(t, ec.Conn.Publish("test", []byte("Hello")))

		msg, err := sub.NextMsg(time.Second)
		assert.Nil(t, err)
		assert.Equal(t, ErrDecryptFailed, msg.Error)
	})

	Run(t, "ChanSubscribe pass through handler", func(t *testing.T) {
		hit := make(chan bool, 1)
		ch := make(chan *Msg)
		defer close(ch)
		go func() {
			msg, ok := <-ch
			if !ok {
				t.Errorf("No message received")
			}
			hit <- true
			assert.Equal(t, ErrDecryptFailed, msg.Error)
		}()
		sub, err := ec.ChanSubscribe("test", ch)
		assert.Nil(t, err)
		defer func() { assert.Nil(t, sub.Unsubscribe()) }()

		// send an unencrypted message
		assert.Nil(t, ec.Conn.Publish("test", []byte("Hello")))

		timeout := TimeoutChan(time.Second)
		select {
		case <-timeout:
			t.Error("The chan received nothing")
		case <-hit:
			t.Log("The chan go a message !")
		}
	})

	ec.SetDefaultDecryptErrorHandler(nil)

	makeBlockingHandler := func(t *testing.T, hit chan bool) DecryptErrorHandler {
		return func(sub *Subscription, msg *Msg) *Msg {
			hit <- true
			assert.Equal(t, ErrDecryptFailed, msg.Error)
			return nil
		}
	}

	Run(t, "Subscribe blocking handler", func(t *testing.T) {
		sub, err := ec.Subscribe("test", func(*Msg) { t.Error("Callback was called") })
		assert.Nil(t, err)
		defer func() { assert.Nil(t, sub.Unsubscribe()) }()

		hit := make(chan bool, 1)
		timeout := TimeoutChan(time.Second * 1)
		sub.SetDecryptErrorHandler(makeBlockingHandler(t, hit))

		// send an unencrypted message
		assert.Nil(t, ec.Conn.Publish("test", []byte("Hello")))

		select {
		case <-timeout:
			t.Error("Error handler not called")
		case <-hit:
			t.Logf("Error handler hit")
		}
	})

	Run(t, "SyncSubscribe blocking handler", func(t *testing.T) {
		sub, err := ec.SubscribeSync("test")
		assert.Nil(t, err)
		defer func() { assert.Nil(t, sub.Unsubscribe()) }()

		hit := make(chan bool, 1)
		timeout := TimeoutChan(time.Second / 2)
		sub.SetDecryptErrorHandler(makeBlockingHandler(t, hit))

		// send an unencrypted message
		assert.Nil(t, ec.Conn.Publish("test", []byte("Hello")))

		msg, err := sub.NextMsg(time.Second)
		assert.Nil(t, msg)
		assert.Equal(t, ErrDecryptFailed, err)

		select {
		case <-timeout:
			t.Error("Error handler not called")
		case <-hit:
			t.Logf("Error handler hit")
		}
	})

	Run(t, "ChanSubscribe blocking handler", func(t *testing.T) {
		ch := make(chan *Msg)
		defer close(ch)
		go func() {
			_, ok := <-ch
			if !ok {
				return
			}
			t.Errorf("Received a message")
		}()
		sub, err := ec.ChanSubscribe("test", ch)
		assert.Nil(t, err)
		defer func() { assert.Nil(t, sub.Unsubscribe()) }()

		hit := make(chan bool, 1)
		timeout := TimeoutChan(time.Second / 2)
		sub.SetDecryptErrorHandler(makeBlockingHandler(t, hit))

		// send an unencrypted message
		assert.Nil(t, ec.Conn.Publish("test", []byte("Hello")))

		select {
		case <-timeout:
			t.Error("Error handler not called")
		case <-hit:
			t.Logf("Error handler hit")
		}
	})

}

func TestPublishFunctions(t *testing.T) {
	natsSrv := InitNatsTestServer(t)
	defer natsSrv.Shutdown()

	c := natsSrv.Connect(t)
	if c == nil {
		return
	}

	ec, err := NewConn(c, "me", DummyEncrypter{})
	if err != nil {
		t.Errorf("Could not init the encrypted conn: %s", err)
		c.Close()
		return
	}
	defer ec.Close()
	ec.SetSubjectRecipients("test", []string{"riri", "fifi", "loulou"})

	sub, err := ec.SubscribeSync("test")
	if err != nil {
		assert.Error(t, err)
		return
	}
	defer sub.Unsubscribe()

	err = ec.PublishMsg(nil)
	assert.Equal(t, err, nats.ErrInvalidMsg)

	err = ec.PublishMsg(NewMsg("test", []byte("Bonjour:"), ""))
	assert.Nil(t, err)

	msg, err := sub.NextMsg(time.Millisecond)
	assert.Nil(t, err)
	assert.Equal(t, "test", msg.Subject)
	assert.Equal(t, "me", msg.Signer)
	assert.Equal(t, []string{"riri", "fifi", "loulou"}, msg.Recipients)
	assert.Equal(t, "Bonjour:", string(msg.Data))

	err = ec.PublishRequest("test", "replysubj", []byte("Coucou"))
	assert.Nil(t, err)

	msg, err = sub.NextMsg(time.Millisecond)
	assert.Nil(t, err)
	assert.Equal(t, "test", msg.Subject)
	assert.Equal(t, "me", msg.Signer)
	assert.Equal(t, "replysubj", msg.Reply)
	assert.Equal(t, []string{"riri", "fifi", "loulou"}, msg.Recipients)
	assert.Equal(t, "Coucou", string(msg.Data))

	go func() {
		msg, err := sub.NextMsg(time.Millisecond)
		assert.Nil(t, err)
		assert.Equal(t, "test", msg.Subject)
		assert.Equal(t, "me", msg.Signer)
		assert.Equal(t, []string{"riri", "fifi", "loulou"}, msg.Recipients)
		assert.Equal(t, "The question", string(msg.Data))

		err = ec.PublishMsg(NewMsg(msg.Reply, []byte("The Reply"), "riri", "me"))
		assert.Nil(t, err)
	}()

	msg, err = ec.Request("test", []byte("The question"), time.Millisecond)
	assert.Nil(t, err)
	assert.Equal(t, "me", msg.Recipients[0])
	assert.Equal(t, "riri", msg.Signer)
	assert.Equal(t, "The Reply", string(msg.Data))
}

type (
	QuestionMsg struct {
		Text    string
		Integer int
	}
	AnswerMsg struct {
		Text string
	}
)
