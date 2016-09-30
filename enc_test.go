package natscrypto

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/nats-io/nats"
	"github.com/stretchr/testify/assert"
)

var argInfoTests = []struct {
	cb              nats.Handler
	expectedType    reflect.Type
	expectedNumArgs int
	panics          bool
}{
	{
		cb:              (func(string, *Msg) {}),
		expectedType:    reflect.TypeOf(&Msg{}),
		expectedNumArgs: 2,
	},
	{
		cb:              (func(*Msg) {}),
		expectedType:    reflect.TypeOf(&Msg{}),
		expectedNumArgs: 1,
	},
	{
		cb:              (func() {}),
		expectedType:    nil,
		expectedNumArgs: 0,
	},
	{
		cb:     0,
		panics: true,
	},
}

func TestArgInfo(t *testing.T) {
	for _, tt := range argInfoTests {
		if tt.panics {
			assert.Panics(t, func() { argInfo(tt.cb) })
		} else {
			typ, numArgs := argInfo(tt.cb)
			assert.Equal(t, tt.expectedType, typ)
			assert.Equal(t, tt.expectedNumArgs, numArgs)
		}
	}
}

func TestEncodedConnConstructor(t *testing.T) {
	natsSrv := InitNatsTestServer(t)
	defer natsSrv.Shutdown()

	c := natsSrv.Connect(t)
	if c == nil {
		return
	}
	defer c.Close()

	ec, err := NewConn(c, "me", DummyEncrypter{})
	if err != nil {
		t.Errorf("Could not init the encrypted conn: %s", err)
		c.Close()
		return
	}
	ec.SetSubjectRecipients("test", []string{"riri", "fifi", "loulou"})

	_, err = NewEncodedConn(nil, "json")
	assert.Equal(t, ErrNilConnection, err)

	_, err = NewEncodedConn(ec, "unknown")
	assert.Equal(t, "natscrypto: No encoder registered for 'unknown'", err.Error())

	ec.CloseAll()
	_, err = NewEncodedConn(ec, "json")
	assert.Equal(t, nats.ErrConnectionClosed, err)

}

func TestEncodedConn(t *testing.T) {
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
	ec.SetSubjectRecipients("test", []string{"riri", "fifi", "loulou"})

	enc, err := NewEncodedConn(ec, "json")
	if err != nil {
		t.Errorf("Could not init the encoded conn: %s", err)
		ec.Close()
		return
	}
	defer enc.CloseAll()

	Run(t, "SubscribeSync", func(t *testing.T) {
		s, err := enc.SubscribeSync("test")
		assert.Nil(t, err)
		defer s.Unsubscribe()

		{
			question := QuestionMsg{Text: "A question", Integer: 12}
			assert.Nil(t, enc.Publish("test", &question))
			question.Text = "Another"
			assert.Nil(t, enc.Publish("test", &question))
			question.Integer = 42
			assert.Nil(t, enc.PublishRequest("test", "zereply", &question))
		}

		{
			var (
				subject  string
				reply    string
				question QuestionMsg
			)

			assert.Nil(t, s.Next(&question, time.Millisecond))
			assert.Equal(t, "A question", question.Text)
			assert.Equal(t, 12, question.Integer)

			assert.Nil(t, s.NextSubject(&subject, &question, time.Millisecond))
			assert.Equal(t, "test", subject)
			assert.Equal(t, "Another", question.Text)
			assert.Equal(t, 12, question.Integer)

			assert.Nil(t, s.NextSubjectReply(&subject, &reply, &question, time.Millisecond))
			assert.Equal(t, "test", subject)
			assert.Equal(t, "zereply", reply)
			assert.Equal(t, "Another", question.Text)
			assert.Equal(t, 42, question.Integer)
		}

	})
	Run(t, "SubscribeSync NextMsg error", func(t *testing.T) {
		s, err := enc.SubscribeSync("test")
		assert.Nil(t, err)
		defer s.Unsubscribe()

		var (
			subject  string
			reply    string
			question QuestionMsg
		)
		err = s.Next(&question, time.Millisecond)
		assert.Equal(t, "nats: timeout", err.Error())
		err = s.NextSubject(&subject, &question, time.Millisecond)
		assert.Equal(t, "nats: timeout", err.Error())
		err = s.NextSubjectReply(&subject, &reply, &question, time.Millisecond)
		assert.Equal(t, "nats: timeout", err.Error())
	})

	Run(t, "Subscribe Raw", func(t *testing.T) {
		var lastMsg *Msg
		cb := func(msg *Msg) {
			lastMsg = msg
		}
		s, err := enc.QueueSubscribe("test", "", cb)
		assert.Nil(t, err)
		defer s.Unsubscribe()

		question := QuestionMsg{Text: "Question", Integer: 38}
		assert.Nil(t, enc.Publish("test", &question))
		time.Sleep(time.Millisecond)
		assert.NotNil(t, lastMsg)
		assert.Equal(t, "test", lastMsg.Subject)
		assert.Equal(t, `{"Text":"Question","Integer":38}`, string(lastMsg.Data))
	})

	Run(t, "Subscribe invalid handler", func(t *testing.T) {
		_, err := enc.Subscribe("test", func() {})
		assert.Equal(t, "natscrypto: Handler requires at least one argument", err.Error())
		_, err = enc.Subscribe("test", func(a1, a2, a3, a4, a5 string) {})
		assert.Equal(t, "natscrypto: Handler requires at most 4 arguments", err.Error())
	})

	Run(t, "Subscribe value", func(t *testing.T) {
		var lastQuestion *QuestionMsg
		cb := func(q QuestionMsg) {
			lastQuestion = &q
		}
		s, err := enc.Subscribe("test", cb)
		assert.Nil(t, err)
		defer s.Unsubscribe()

		question := QuestionMsg{Text: "Question", Integer: 38}
		assert.Nil(t, enc.Publish("test", &question))
		time.Sleep(time.Millisecond)
		assert.NotNil(t, lastQuestion)
		assert.Equal(t, "Question", lastQuestion.Text)
		assert.Equal(t, 38, lastQuestion.Integer)
	})

	Run(t, "Subscribe subject/value", func(t *testing.T) {
		var (
			lastSubject  string
			lastQuestion *QuestionMsg
		)
		cb := func(subject string, q QuestionMsg) {
			lastSubject = subject
			lastQuestion = &q
		}
		s, err := enc.Subscribe("test", cb)
		assert.Nil(t, err)
		defer s.Unsubscribe()

		question := QuestionMsg{Text: "Question", Integer: 38}
		assert.Nil(t, enc.Publish("test", &question))
		time.Sleep(time.Millisecond)
		assert.NotNil(t, lastQuestion)
		assert.Equal(t, "test", lastSubject)
		assert.Equal(t, "Question", lastQuestion.Text)
		assert.Equal(t, 38, lastQuestion.Integer)
	})

	Run(t, "Subscribe subject/reply/value", func(t *testing.T) {
		var (
			lastSubject  string
			lastReply    string
			lastQuestion *QuestionMsg
		)
		cb := func(subject string, reply string, q *QuestionMsg) {
			lastSubject = subject
			lastReply = reply
			lastQuestion = q
		}
		s, err := enc.Subscribe("test", cb)
		assert.Nil(t, err)
		defer s.Unsubscribe()

		question := QuestionMsg{Text: "Question", Integer: 38}
		assert.Nil(t, enc.PublishRequest("test", "zereply", &question))
		time.Sleep(time.Millisecond)
		assert.NotNil(t, lastQuestion)
		assert.Equal(t, "test", lastSubject)
		assert.Equal(t, "zereply", lastReply)
		assert.Equal(t, "Question", lastQuestion.Text)
		assert.Equal(t, 38, lastQuestion.Integer)
	})

	Run(t, "Subscribe subject/reply/signer/value", func(t *testing.T) {
		var (
			lastSubject  string
			lastReply    string
			lastSigner   string
			lastQuestion *QuestionMsg
			hit          = make(chan bool, 1)
		)
		cb := func(subject string, reply string, signer string, q *QuestionMsg) {
			lastSubject = subject
			lastReply = reply
			lastSigner = signer
			lastQuestion = q
			hit <- true
		}
		s, err := enc.Subscribe("test", cb)
		assert.Nil(t, err)
		defer s.Unsubscribe()

		question := QuestionMsg{Text: "Question", Integer: 38}
		assert.Nil(t, enc.PublishRequest("test", "zereply", &question))
		timeout := TimeoutChan(time.Millisecond * 250)
		select {
		case <-timeout:
			t.Errorf("Callback not called")
		case <-hit:

			assert.NotNil(t, lastQuestion)
			assert.Equal(t, "test", lastSubject)
			assert.Equal(t, "zereply", lastReply)
			assert.Equal(t, "Question", lastQuestion.Text)
			assert.Equal(t, "me", lastSigner)
			assert.Equal(t, 38, lastQuestion.Integer)
		}
	})

	Run(t, "Request", func(t *testing.T) {
		go func() {
			s, err := enc.SubscribeSync("test")
			assert.Nil(t, err)
			defer s.Unsubscribe()

			var (
				subject, reply string
				question       QuestionMsg
			)

			assert.Nil(t, s.NextSubjectReply(&subject, &reply, &question, 10*time.Millisecond))
			assert.Nil(t,
				enc.Publish(reply, &AnswerMsg{Text: "The answer"}),
			)

			assert.Nil(t, s.NextSubjectReply(&subject, &reply, &question, 10*time.Millisecond))
			assert.Nil(t,
				enc.Publish(reply, &AnswerMsg{Text: "The answer"}),
			)
		}()

		time.Sleep(time.Millisecond)

		var answer AnswerMsg
		q := QuestionMsg{Text: "The question", Integer: 9}

		err := enc.Request("test", q, &answer, time.Second)
		assert.Nil(t, err)

		var msg Msg
		err = enc.Request("test", q, &msg, time.Second)
		assert.Nil(t, err)
		assert.Equal(t, `{"Text":"The answer"}`, string(msg.Data))

		err = enc.Request("test", 42, &msg, time.Microsecond)
		assert.Equal(t, "nats: timeout", err.Error())
	})

	Run(t, "SubscribeSync error handling", func(t *testing.T) {
		s, err := enc.SubscribeSync("test")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { assert.Nil(t, s.Unsubscribe()) }()
		assert.Nil(t, enc.Conn.Publish("test", []byte("Invalid json")))

		var answer AnswerMsg
		err = s.Next(&answer, time.Second)
		assert.EqualError(t, err, "invalid character 'I' looking for beginning of value")
	})

	Run(t, "Subscribe error handling", func(t *testing.T) {
		var hit = false
		cb := func(answer AnswerMsg) {
			t.Error("Callback was called")
			hit = true
		}
		s, err := enc.Subscribe("test", cb)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { assert.Nil(t, s.Unsubscribe()) }()
		s.SetDecryptErrorHandler(func(sub *Subscription, msg *Msg) *Msg {
			assert.EqualError(t, msg.Error, "invalid character 'I' looking for beginning of value")
			return nil
		})
		assert.Nil(t, enc.Conn.Publish("test", []byte("Invalid json")))

		time.Sleep(time.Millisecond)

		assert.False(t, hit)
	})
}

type BadEncoder struct{}

func (BadEncoder) Encode(string, interface{}) ([]byte, error) {
	return nil, fmt.Errorf("Encoding failed")
}

func (BadEncoder) Decode(string, []byte, interface{}) error {
	return fmt.Errorf("Decoding failed")
}

func TestEncoderErrors(t *testing.T) {
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
	ec.SetSubjectRecipients("test", []string{"riri", "fifi", "loulou"})

	nats.RegisterEncoder("bad", &BadEncoder{})
	enc, err := NewEncodedConn(ec, "bad")
	if err != nil {
		t.Errorf("Could not init the encoded conn: %s", err)
		ec.Close()
		return
	}
	defer enc.CloseAll()

	err = enc.Publish("test", 42)
	assert.Equal(t, "Encoding failed", err.Error())

	err = enc.PublishRequest("test", "reply", 42)
	assert.Equal(t, "Encoding failed", err.Error())

	var response int
	err = enc.Request("test", 42, &response, time.Second)
	assert.Equal(t, "Encoding failed", err.Error())
}

func TestRequestErrors(t *testing.T) {
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
	ec.SetSubjectRecipients("test", []string{"riri", "fifi", "loulou"})

	enc, err := NewEncodedConn(ec, "json")
	if err != nil {
		t.Errorf("Could not init the encoded conn: %s", err)
		ec.Close()
		return
	}
	defer enc.CloseAll()

	var response int
	err = enc.Request("test", 42, &response, time.Microsecond)
	assert.Equal(t, "nats: timeout", err.Error())
}

func TestSubscribeErrors(t *testing.T) {
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
	ec.SetSubjectRecipients("test", []string{"riri", "fifi", "loulou"})

	enc, err := NewEncodedConn(ec, "json")
	if err != nil {
		t.Errorf("Could not init the encoded conn: %s", err)
		ec.Close()
		return
	}
	defer enc.CloseAll()

	enc.Conn.Conn = nil
	_, err = enc.Subscribe("test", nil)
	assert.Equal(t, "nats: invalid connection", err.Error())

	_, err = enc.QueueSubscribe("test", "queue", func(*Msg) {})
	assert.Equal(t, "nats: invalid connection", err.Error())

	enc.Conn.Conn = c
}
