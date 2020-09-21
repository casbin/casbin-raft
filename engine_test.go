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
	"log"
	"testing"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	"github.com/casbin/casbin/v3/util"
)

func testGetRoles(t *testing.T, e *Engine, res []string, name string, domain ...string) {
	t.Helper()
	myRes, err := e.enforcer.GetRolesForUser(name, domain...)
	if err != nil {
		t.Error("Roles for ", name, " could not be fetched: ", err.Error())
	}
	t.Log("Roles for ", name, ": ", myRes)

	if !util.SetEquals(res, myRes) {
		t.Error("Roles for ", name, ": ", myRes, ", supposed to be ", res)
	}
}

func newTestEngine() *Engine {
	enforcer, err := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	if err != nil {
		panic(err)
	}
	return newEngine(enforcer)
}

func testEngineGetPolicy(t *testing.T, e *Engine, res [][]string) {
	t.Helper()
	myRes := e.enforcer.GetPolicy()
	t.Log("Policy: ", myRes)

	if !util.Array2DEquals(res, myRes) {
		t.Error("Policy: ", myRes, ", supposed to be ", res)
	}
}

func TestEngineSnapshot(t *testing.T) {
	e := newTestEngine()
	testEngineGetPolicy(t, e, [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
	})

	data, err := e.getSnapshot()
	if err != nil {
		t.Fatal(err)
	}

	_ = e.enforcer.ClearPolicy()
	testEngineGetPolicy(t, e, [][]string{})
	err = e.recoverFromSnapshot(data)
	if err != nil {
		t.Fatal(err)
	}
	testEngineGetPolicy(t, e, [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
	})
	_ = e.enforcer.SavePolicy()
}

func TestEngineApplyPolicy(t *testing.T) {
	e := newTestEngine()
	testEngineGetPolicy(t, e, [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
	})

	tests := []struct {
		c   Command
		res [][]string
	}{
		{
			Command{
				Op:    removeCommand,
				Sec:   "p",
				Ptype: "p",
				Rules: [][]string{{"alice", "data1", "read"}},
			},
			[][]string{
				{"bob", "data2", "write"},
				{"data2_admin", "data2", "read"},
				{"data2_admin", "data2", "write"},
			},
		},
		{
			Command{
				Op:    removeCommand,
				Sec:   "p",
				Ptype: "p",
				Rules: [][]string{{"bob", "data2", "write"}},
			},
			[][]string{
				{"data2_admin", "data2", "read"},
				{"data2_admin", "data2", "write"},
			},
		},
		{
			Command{
				Op:    removeCommand,
				Sec:   "p",
				Ptype: "p",
				Rules: [][]string{{"alice", "data1", "read"}},
			},
			[][]string{
				{"data2_admin", "data2", "read"},
				{"data2_admin", "data2", "write"},
			},
		},
		{
			Command{
				Op:    addCommand,
				Sec:   "p",
				Ptype: "p",
				Rules: [][]string{{"eve", "data3", "read"}},
			},
			[][]string{
				{"data2_admin", "data2", "read"},
				{"data2_admin", "data2", "write"},
				{"eve", "data3", "read"},
			},
		},
		{
			Command{
				Op:    addCommand,
				Sec:   "p",
				Ptype: "p",
				Rules: [][]string{{"eve", "data3", "read"}},
			},
			[][]string{
				{"data2_admin", "data2", "read"},
				{"data2_admin", "data2", "write"},
				{"eve", "data3", "read"},
			},
		},

		{
			Command{
				Op:    addCommand,
				Sec:   "p",
				Ptype: "p",
				Rules: [][]string{
					{"jack", "data4", "read"},
					{"katy", "data4", "write"},
					{"leyo", "data4", "read"},
					{"ham", "data4", "write"},
				},
			},
			[][]string{
				{"data2_admin", "data2", "read"},
				{"data2_admin", "data2", "write"},
				{"eve", "data3", "read"},
				{"jack", "data4", "read"},
				{"katy", "data4", "write"},
				{"leyo", "data4", "read"},
				{"ham", "data4", "write"},
			},
		},
		{
			Command{
				Op:    removeCommand,
				Sec:   "p",
				Ptype: "p",
				Rules: [][]string{
					{"jack", "data4", "read"},
					{"katy", "data4", "write"},
				},
			},
			[][]string{
				{"data2_admin", "data2", "read"},
				{"data2_admin", "data2", "write"},
				{"eve", "data3", "read"},
				{"leyo", "data4", "read"},
				{"ham", "data4", "write"},
			},
		},
		{
			Command{
				Op:          removeFilteredCommand,
				Sec:         "p",
				Ptype:       "p",
				FiledIndex:  1,
				FiledValues: []string{"data2"},
			},
			[][]string{
				{"eve", "data3", "read"},
				{"leyo", "data4", "read"},
				{"ham", "data4", "write"},
			},
		},
		{
			Command{
				Op:          removeFilteredCommand,
				Sec:         "p",
				Ptype:       "p",
				FiledIndex:  2,
				FiledValues: []string{"read"},
			},
			[][]string{
				{"ham", "data4", "write"},
			},
		},
		{
			Command{
				Op: clearCommand,
			},
			[][]string{},
		},
	}

	for _, tt := range tests {
		e.Apply(tt.c)
		testEngineGetPolicy(t, e, tt.res)
	}
}

func TestEngineApplyGroupPolicy(t *testing.T) {
	e := newTestEngine()
	testGetRoles(t, e, []string{"data2_admin"}, "alice")
	testGetRoles(t, e, []string{}, "bob")
	testGetRoles(t, e, []string{}, "eve")
	testGetRoles(t, e, []string{}, "non_exist")

	tests := []Command{
		{

			Op:    removeCommand,
			Sec:   "g",
			Ptype: "g",
			Rules: [][]string{{"alice", "data2_admin"}},
		},
		{

			Op:    addCommand,
			Sec:   "g",
			Ptype: "g",
			Rules: [][]string{{"bob", "data1_admin"}},
		},
		{

			Op:    addCommand,
			Sec:   "g",
			Ptype: "g",
			Rules: [][]string{{"eve", "data3_admin"}},
		},
	}

	for _, tt := range tests {
		e.Apply(tt)
	}

	testGetRoles(t, e, []string{}, "alice")
	testGetRoles(t, e, []string{"data1_admin"}, "bob")
	testGetRoles(t, e, []string{"data3_admin"}, "eve")
	testGetRoles(t, e, []string{}, "non_exist")
}

func TestEngineLeader(t *testing.T) {
	enforcer, err := casbin.NewEnforcer("examples/rbac_model.conf", new(fakeAdapter))
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(enforcer)
	e.isLeader = 1

	tests := []struct {
		c   Command
		res [][]string
	}{
		{
			Command{
				Op:    addCommand,
				Sec:   "p",
				Ptype: "p",
				Rules: [][]string{{"alice", "data1", "read"}},
			},
			[][]string{
				{"alice", "data1", "read"},
			},
		},
		{
			Command{
				Op:    addCommand,
				Sec:   "p",
				Ptype: "p",
				Rules: [][]string{{"bob", "data2", "write"}},
			},
			[][]string{
				{"alice", "data1", "read"},
				{"bob", "data2", "write"},
			},
		},
		{
			Command{
				Op:    removeCommand,
				Sec:   "p",
				Ptype: "p",
				Rules: [][]string{{"alice", "data1", "read"}},
			},
			[][]string{
				{"bob", "data2", "write"},
			},
		},
		{
			Command{
				Op:    addCommand,
				Sec:   "p",
				Ptype: "p",
				Rules: [][]string{{"eve", "data3", "read"}},
			},
			[][]string{
				{"bob", "data2", "write"},
				{"eve", "data3", "read"},
			},
		},
		{
			Command{
				Op:    addCommand,
				Sec:   "p",
				Ptype: "p",
				Rules: [][]string{{"eve", "data3", "read"}},
			},
			[][]string{
				{"bob", "data2", "write"},
				{"eve", "data3", "read"},
			},
		},
	}

	for _, tt := range tests {
		e.Apply(tt.c)
		testEngineGetPolicy(t, e, tt.res)
	}
}

type fakeAdapter struct{}

var _ persist.Adapter = &fakeAdapter{}

func (a *fakeAdapter) LoadPolicy(model *model.Model) error {
	return nil
}

func (a *fakeAdapter) SavePolicy(model *model.Model) error {
	return nil
}

func (a *fakeAdapter) AddPolicy(sec string, ptype string, rule []string) error {
	log.Printf("add policy: %s, %s, %s", sec, ptype, rule)
	return nil
}

func (a *fakeAdapter) RemovePolicy(sec string, ptype string, rule []string) error {
	log.Printf("remove policy: %s, %s, %s", sec, ptype, rule)
	return nil
}

func (a *fakeAdapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return nil
}

func (a *fakeAdapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	for _, rule := range rules {
		log.Printf("add policy: %s, %s, %s", sec, ptype, rule)
	}
	return nil
}

func (a *fakeAdapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	for _, rule := range rules {
		log.Printf("remove policy: %s, %s, %s", sec, ptype, rule)
	}
	return nil
}
