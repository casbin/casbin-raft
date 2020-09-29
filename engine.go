// Copyright 2020 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package casbinraft

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/persist"
	"github.com/casbin/casbin/v3/util"
)

const (
	addCommand = iota
	removeCommand
	removeFilteredCommand
	clearCommand
)

// Engine is a wapper for casbin enforcer
type Engine struct {
	enforcer *casbin.Enforcer
	isLeader uint32
	mutex    sync.Mutex
}

// Command represents an instruction to change the state of the engine
type Command struct {
	Op          int        `json:"op"`
	Sec         string     `json:"sec"`
	Ptype       string     `json:"ptype"`
	Rules       [][]string `json:"rules"`
	FiledIndex  int        `json:"filed_index"`
	FiledValues []string   `json:"filed_values"`
}

func newEngine(enforcer *casbin.Enforcer) *Engine {
	return &Engine{
		enforcer: enforcer,
	}
}

// Apply applies a Raft log entry to the casbin engine.
func (e *Engine) Apply(c Command) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	shouldPersist := atomic.LoadUint32(&e.isLeader) == 1
	switch c.Op {
	case addCommand:
		_, _, err := e.enforcer.GetPolicyManager().AddPolicies(c.Sec, c.Ptype, c.Rules, shouldPersist)
		if err != nil {
			// need a way to notify the caller, panic temporarily, the same as following
			panic(err)
		}
	case removeCommand:
		_, _, err := e.enforcer.GetPolicyManager().RemovePolicies(c.Sec, c.Ptype, c.Rules, shouldPersist)
		if err != nil {
			panic(err)
		}
	case removeFilteredCommand:
		_, _, err := e.enforcer.GetPolicyManager().RemoveFilteredPolicy(c.Sec, c.Ptype, shouldPersist, c.FiledIndex, c.FiledValues...)
		if err != nil {
			panic(err)
		}
	case clearCommand:
		e.enforcer.GetModel().ClearPolicy()
		if atomic.LoadUint32(&e.isLeader) == 1 {
			err := e.enforcer.SavePolicy()
			if err != nil {
				panic(err)
			}
		}
	default:
		panic(errors.New("wrong command option"))
	}
}

// getSnapshot convert model data to snapshot
func (e *Engine) getSnapshot() ([]byte, error) {
	var tmp bytes.Buffer
	model := e.enforcer.GetModel()
	ptypes := model.GetPtypes("p")
	for _, ptype := range ptypes {
		for _, rule := range model.GetPolicy("p", ptype) {
			tmp.WriteString(ptype + ", ")
			tmp.WriteString(util.ArrayToString(rule))
			tmp.WriteString("\n")
		}
	}

	ptypes = model.GetPtypes("g")
	for _, ptype := range ptypes {
		for _, rule := range model.GetPolicy("g", ptype) {
			tmp.WriteString(ptype + ", ")
			tmp.WriteString(util.ArrayToString(rule))
			tmp.WriteString("\n")
		}
	}

	return bytes.TrimRight(tmp.Bytes(), "\n"), nil
}

// recoverFromSnapshot save the snapshot data to model
func (e *Engine) recoverFromSnapshot(snapshot []byte) error {
	e.enforcer.GetModel().ClearPolicy()
	model := e.enforcer.GetModel()
	scanner := bufio.NewScanner(bytes.NewReader(snapshot))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		persist.LoadPolicyLine(line, model)
	}
	return scanner.Err()
}
