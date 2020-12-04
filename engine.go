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
	"go.uber.org/zap"
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
	logger   *zap.Logger
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

func newEngine(logger *zap.Logger, enforcer casbin.IDistributedEnforcer) (*Engine, error) {
	e := &Engine{
		enforcer: enforcer,
		mutex:    &sync.Mutex{},
		logger:   logger,
	}
	if e.logger == nil {
		logger, err := zap.NewProduction()
		if err != nil {
			return nil, err
		}
		e.logger = logger
	}
	return e, nil
}

// shouldPersist checks whether adapter can be called. Note that only the leader can call adapter.
func (e *Engine) shouldPersist() bool {
	return e.isLeader == 1
}

// Apply applies a Raft log entry to the casbin engine.
func (e *Engine) Apply(c Command) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	switch c.Op {
	case addCommand:
		_, err := e.enforcer.AddPolicySelf(e.shouldPersist, c.Sec, c.Ptype, c.Rules)
		if err != nil {
			e.logger.Panic(err.Error(), zap.Any("command", c))
		}
	case removeCommand:
		_, err := e.enforcer.RemovePolicySelf(e.shouldPersist, c.Sec, c.Ptype, c.Rules)
		if err != nil {
			e.logger.Panic(err.Error(), zap.Any("command", c))
		}
	case removeFilteredCommand:
		_, err := e.enforcer.RemoveFilteredPolicySelf(e.shouldPersist, c.Sec, c.Ptype, c.FiledIndex, c.FiledValues...)
		if err != nil {
			e.logger.Panic(err.Error(), zap.Any("command", c))
		}
	case clearCommand:
		err := e.enforcer.ClearPolicySelf(e.shouldPersist)
		if err != nil {
			e.logger.Panic(err.Error(), zap.Any("command", c))
		}
	case updateCommand:
		_, err := e.enforcer.UpdatePolicySelf(e.shouldPersist, c.Sec, c.Ptype, c.OldRule, c.NewRule)
		if err != nil {
			e.logger.Panic(err.Error(), zap.Any("command", c))
		}
	default:
		e.logger.Panic("unknown command", zap.Any("command", c))
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
