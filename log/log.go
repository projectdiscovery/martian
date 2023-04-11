// Copyright 2015 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package log provides a universal logger for martian packages.
package log

import (
	"fmt"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"
)

const (
	// Silent is a level that logs nothing.
	Silent int = iota
	// Error is a level that logs error logs.
	Error
	// Info is a level that logs error, and info logs.
	Info
	// Debug is a level that logs error, info, and debug logs.
	Debug
)

// GologgerInstance is actual logger used internally
var GologgerInstance *gologger.Logger

// Default log level is Error.
var (
	level      = Error
	lock       sync.Mutex
	currLogger Logger = &logger{}
	ShowHidden bool
)

type Logger interface {
	Infof(format string, args ...interface{})
	Debugf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// SetLogger changes the default logger. This must be called very first,
// before interacting with rest of the martian package. Changing it at
// runtime is not supported.
// Deprecated : Use GologgerInstance to configure logger
func SetLogger(l Logger) {
	currLogger = l
}

// SetLevel sets the global log level.
// Deprecated : Use GologgerInstance to configure logger
func SetLevel(l int) {
	lock.Lock()
	defer lock.Unlock()

	level = l
}

// Infof logs an info message.
func Infof(format string, args ...interface{}) {
	currLogger.Infof(format, args...)
}

// Debugf logs a debug message.
func Debugf(format string, args ...interface{}) {
	currLogger.Debugf(format, args...)
}

// Errorf logs an error message.
func Errorf(format string, args ...interface{}) {
	currLogger.Errorf(format, args...)
}

type logger struct{}

func (l *logger) Infof(format string, args ...interface{}) {
	if hideErr(format, args...) {
		return
	}
	GologgerInstance.Info().Msgf(format, args...)
}

func (l *logger) Debugf(format string, args ...interface{}) {
	if hideErr(format, args...) {
		return
	}
	GologgerInstance.Debug().Msgf(format, args...)
}

func (l *logger) Errorf(format string, args ...interface{}) {
	if hideErr(format, args...) {
		return
	}
	GologgerInstance.Error().Msgf(format, args...)
}

func init() {
	GologgerInstance = &gologger.Logger{}
	GologgerInstance.SetMaxLevel(levels.LevelInfo)
	GologgerInstance.SetFormatter(formatter.NewCLI(false))
	GologgerInstance.SetWriter(writer.NewCLI())
}

// Context:
// when golang server closes a tcp connection it is assumed to be closen
// however that isn't true because os considers/assumes the connection is still alive until it receive the final FIN-ACK packet.
// and if os waits too long to gracefully close it golang internal scheduler considers this as active connection as reuses it
// for subsequent request . which in turn causes `broken pipe`=>write on closed connection and `connection reset by peer`=> read of closed connection
// to avoid such cases it is good idea to set linger to x sec (we use 3 sec) . Linger tells os to only wait for 3 sec for ^ FIN-ACK packet
// Note: we can't make it zero for proxy use cases since the original behaviour of os connections ^ was introduced so that data is successfully commited
// before it is sent . Since Both Client and Server in proxy are on same host 3 sec seems more than enough
// Ref:
// https://itnext.io/forcefully-close-tcp-connections-in-golang-e5f5b1b14ce6
// https://gosamples.dev/broken-pipe/
//
// hideErr: hide error hides ^ errors since they don't have anything to do with http requests and are caused due to abrupt connection closures
// hence we by default supress this errors
func hideErr(format string, args ...any) bool {

	value := fmt.Sprintf(format, args...)
	if !ShowHidden && (strings.Contains(value, "broken pipe") || strings.Contains(value, "connection reset by peer")) {
		return true
	}
	return false
}
