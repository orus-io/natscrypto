package natscrypto

import (
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
	defer enc.Close()

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

	Run(t, "Subscribe Raw", func(t *testing.T) {
		var lastMsg *Msg
		cb := func(msg *Msg) {
			lastMsg = msg
		}
		s, err := enc.Subscribe("test", cb)
		assert.Nil(t, err)
		defer s.Unsubscribe()

		question := QuestionMsg{Text: "Question", Integer: 38}
		assert.Nil(t, enc.Publish("test", &question))
		time.Sleep(time.Millisecond)
		assert.NotNil(t, lastMsg)
		assert.Equal(t, "test", lastMsg.Subject)
		assert.Equal(t, `{"Text":"Question","Integer":38}`, string(lastMsg.Data))
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
		}()

		time.Sleep(time.Millisecond)

		var answer AnswerMsg

		assert.Nil(t, enc.Request(
			"test",
			QuestionMsg{Text: "The question", Integer: 9},
			&answer,
			10*time.Millisecond,
		))
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
