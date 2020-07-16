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
	"sync/atomic"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/casbin/casbin/v2/util"
)

const (
	addCommand    = 0
	removeCommand = 1
)

const notImplemented = "not implemented"

// Engine is a wapper for casbin enforcer
type Engine struct {
	enforcer *casbin.SyncedEnforcer
	isLeader uint32
}

// Command represents an instruction to change the state of the engine
type Command struct {
	Op    int        `json:"op"`
	Sec   string     `json:"sec"`
	Ptype string     `json:"ptype"`
	Rules [][]string `json:"rules"`
}

func newEngine(enforcer *casbin.SyncedEnforcer) *Engine {
	return &Engine{
		enforcer: enforcer,
	}
}

// Apply applies a Raft log entry to the casbin engine.
func (e *Engine) Apply(c Command) {
	switch c.Op {
	case addCommand:
		_, err := e.applyAdd(c.Sec, c.Ptype, c.Rules)
		if err != nil {
			// need a way to notify the caller, panic temporarily, the same as following
			panic(err)
		}
	case removeCommand:
		_, err := e.applyRemove(c.Sec, c.Ptype, c.Rules)
		if err != nil {
			panic(err)
		}
	default:
		panic(errors.New("wrong command option"))
	}
}

func (e *Engine) applyAdd(sec string, ptype string, rules [][]string) (bool, error) {
	if e.enforcer.GetModel().HasPolicies(sec, ptype, rules) {
		return false, nil
	}

	if atomic.LoadUint32(&e.isLeader) == 1 && e.enforcer.GetAdapter() != nil {
		if err := e.enforcer.GetAdapter().(persist.BatchAdapter).AddPolicies(sec, ptype, rules); err != nil {
			if err.Error() != notImplemented {
				return false, err
			}
		}
	}

	e.enforcer.GetModel().AddPolicies(sec, ptype, rules)

	if sec == "g" {
		err := e.enforcer.BuildIncrementalRoleLinks(model.PolicyAdd, ptype, rules)
		if err != nil {
			return false, err
		}
	}

	return true, nil
}

func (e *Engine) applyRemove(sec string, ptype string, rules [][]string) (bool, error) {
	if !e.enforcer.GetModel().HasPolicies(sec, ptype, rules) {
		return false, nil
	}

	if atomic.LoadUint32(&e.isLeader) == 1 && e.enforcer.GetAdapter() != nil {
		if err := e.enforcer.GetAdapter().(persist.BatchAdapter).RemovePolicies(sec, ptype, rules); err != nil {
			if err.Error() != notImplemented {
				return false, err
			}
		}
	}

	ruleRemoved := e.enforcer.GetModel().RemovePolicies(sec, ptype, rules)
	if !ruleRemoved {
		return ruleRemoved, nil
	}

	if sec == "g" {
		err := e.enforcer.BuildIncrementalRoleLinks(model.PolicyRemove, ptype, rules)
		if err != nil {
			return false, err
		}
	}

	return ruleRemoved, nil
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
	e.enforcer.ClearPolicy()
	model := e.enforcer.GetModel()
	scanner := bufio.NewScanner(bytes.NewReader(snapshot))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		persist.LoadPolicyLine(line, model)
	}
	return scanner.Err()
}
