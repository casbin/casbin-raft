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
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/persist"
	"github.com/casbin/casbin/v2/util"
)

const (
	addCommand = iota
	removeCommand
	removeFilteredCommand
	clearCommand
	updateCommand
)

// Engine is a wapper for casbin enforcer
type Engine struct {
	enforcer casbin.IDistributedEnforcer
	isLeader uint32
	mutex    *sync.Mutex
}

// Command represents an instruction to change the state of the engine
type Command struct {
	Op          int        `json:"op"`
	Sec         string     `json:"sec"`
	Ptype       string     `json:"ptype"`
	Rules       [][]string `json:"rules"`
	FiledIndex  int        `json:"filed_index"`
	FiledValues []string   `json:"filed_values"`
	// UpdatePolicy Field
	NewRule []string `json:"newRule"`
	OldRule []string `json:"oldRule"`
}

func newEngine(enforcer casbin.IDistributedEnforcer) *Engine {
	return &Engine{
		enforcer: enforcer,
		mutex:    &sync.Mutex{},
	}
}

// shouldPersist checks whether adapter can be called. Note that only the leader can call adapter.
func (e *Engine) shouldPersist() bool {
	return e.isLeader == 1
}

// Apply applies a Raft log entry to the casbin engine.
func (e *Engine) Apply(c Command) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf(fmt.Sprintf("panic: %v", r))
		}
	}()
	e.mutex.Lock()
	defer e.mutex.Unlock()
	switch c.Op {
	case addCommand:
		_, err := e.enforcer.AddPolicySelf(e.shouldPersist, c.Sec, c.Ptype, c.Rules)
		if err != nil {
			// need a way to notify the caller, panic temporarily, the same as following
			panic(err)
		}
	case removeCommand:
		_, err := e.enforcer.RemovePolicySelf(e.shouldPersist, c.Sec, c.Ptype, c.Rules)
		if err != nil {
			panic(err)
		}
	case removeFilteredCommand:
		_, err := e.enforcer.RemoveFilteredPolicySelf(e.shouldPersist, c.Sec, c.Ptype, c.FiledIndex, c.FiledValues...)
		if err != nil {
			panic(err)
		}
	case clearCommand:
		err := e.enforcer.ClearPolicySelf(e.shouldPersist)
		if err != nil {
			panic(err)
		}
	case updateCommand:
		_, err := e.enforcer.UpdatePolicySelf(e.shouldPersist, c.Sec, c.Ptype, c.OldRule, c.NewRule)
		if err != nil {
			panic(err)
		}
	default:
		panic(errors.New("unknown command"))
	}
}

// getSnapshot convert model data to snapshot
func (e *Engine) getSnapshot() ([]byte, error) {
	var tmp bytes.Buffer
	model := e.enforcer.GetModel()
	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			tmp.WriteString(ptype + ", ")
			tmp.WriteString(util.ArrayToString(rule))
			tmp.WriteString("\n")
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
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
