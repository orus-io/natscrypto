# Nats Crypto

[![Build Status](https://travis-ci.org/orus-io/natscrypto.svg?branch=master)](https://travis-ci.org/orus-io/natscrypto)
[![Go Report Card](https://goreportcard.com/badge/github.com/orus-io/natscrypto)](https://goreportcard.com/report/github.com/orus-io/natscrypto)
[![Coverage Status](https://coveralls.io/repos/github/orus-io/natscrypto/badge.svg?branch=master)](https://coveralls.io/github/orus-io/natscrypto?branch=master)
[![License (MIT)](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)](https://opensource.org/licenses/MIT)

natscrypto is a golang package that wraps nats.Conn to provide transparent
PKI encryption to nats messages

The encryption part is pluggable and a PGP implemention is provided

The complete documentation is available here:
https://godoc.org/github.com/orus-io/natscrypto
