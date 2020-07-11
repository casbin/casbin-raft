package casbinraft

import (
	"encoding/json"
	"errors"
	"sync/atomic"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
)

const (
	addCommand     = 0
	removeCommand  = 1
	notImplemented = "not implemented"
)

// Engine is a wapper for casbin enforcer
type Engine struct {
	enforcer *casbin.SyncedEnforcer
	isLeader uint32
}

// Command represents an instruction to change the state of the engine
type Command struct {
	Op    int      `json:"op"`
	Sec   string   `json:"sec"`
	Ptype string   `json:"ptype"`
	Rule  []string `json:"rules"`
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
		_, err := e.applyAdd(c.Sec, c.Ptype, c.Rule)
		if err != nil {
			panic(err)
		}
	case removeCommand:
		_, err := e.applyRemove(c.Sec, c.Ptype, c.Rule)
		if err != nil {
			panic(err)
		}
	default:
		panic(errors.New("wrong command option"))
	}
}

func (e *Engine) applyAdd(sec string, ptype string, rule []string) (bool, error) {
	if atomic.LoadUint32(&e.isLeader) == 1 && e.enforcer.GetAdapter() != nil {
		if err := e.enforcer.GetAdapter().AddPolicy(sec, ptype, rule); err != nil {
			if err.Error() != notImplemented {
				return false, err
			}
		}
	}

	e.enforcer.GetModel().AddPolicy(sec, ptype, rule)

	if sec == "g" {
		err := e.enforcer.BuildIncrementalRoleLinks(model.PolicyAdd, ptype, [][]string{rule})
		if err != nil {
			return false, err
		}
	}

	return true, nil
}

func (e *Engine) applyRemove(sec string, ptype string, rule []string) (bool, error) {
	if atomic.LoadUint32(&e.isLeader) == 1 && e.enforcer.GetAdapter() != nil {
		if err := e.enforcer.GetAdapter().RemovePolicy(sec, ptype, rule); err != nil {
			if err.Error() != notImplemented {
				return false, err
			}
		}
	}

	ruleRemoved := e.enforcer.GetModel().RemovePolicy(sec, ptype, rule)
	if !ruleRemoved {
		return ruleRemoved, nil
	}

	if sec == "g" {
		err := e.enforcer.BuildIncrementalRoleLinks(model.PolicyRemove, ptype, [][]string{rule})
		if err != nil {
			return false, err
		}
	}

	return ruleRemoved, nil
}

// getSnapshot convert model data to snapshot
func (e *Engine) getSnapshot() ([]byte, error) {
	return json.Marshal(e.enforcer.GetModel())
}

// recoverFromSnapshot save the snapshot data to model
func (e *Engine) recoverFromSnapshot(snapshot []byte) error {
	var model model.Model
	if err := json.Unmarshal(snapshot, &model); err != nil {
		return err
	}
	e.enforcer.SetModel(model)
	return nil
}
