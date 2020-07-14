package casbinraft

import (
	"log"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/casbin/casbin/v2/util"
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
	enforcer, err := casbin.NewSyncedEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	if err != nil {
		panic(err)
	}
	return newEngine(enforcer)
}

func testGetPolicy(t *testing.T, e *Engine, res [][]string) {
	t.Helper()
	myRes := e.enforcer.GetPolicy()
	t.Log("Policy: ", myRes)

	if !util.Array2DEquals(res, myRes) {
		t.Error("Policy: ", myRes, ", supposed to be ", res)
	}
}

func TestEngineSnapshot(t *testing.T) {
	e := newTestEngine()
	testGetPolicy(t, e, [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
	})

	data, err := e.getSnapshot()
	if err != nil {
		t.Fatal(err)
	}

	e.enforcer.ClearPolicy()
	testGetPolicy(t, e, [][]string{})
	err = e.recoverFromSnapshot(data)
	if err != nil {
		t.Fatal(err)
	}
	testGetPolicy(t, e, [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
	})
}

func TestEngineApplyPolicy(t *testing.T) {
	e := newTestEngine()
	testGetPolicy(t, e, [][]string{
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
				Rule:  []string{"alice", "data1", "read"},
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
				Rule:  []string{"bob", "data2", "write"},
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
				Rule:  []string{"alice", "data1", "read"},
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
				Rule:  []string{"eve", "data3", "read"},
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
				Rule:  []string{"eve", "data3", "read"},
			},
			[][]string{
				{"data2_admin", "data2", "read"},
				{"data2_admin", "data2", "write"},
				{"eve", "data3", "read"},
			},
		},
	}

	for _, tt := range tests {
		e.Apply(tt.c)
		testGetPolicy(t, e, tt.res)
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
			Rule:  []string{"alice", "data2_admin"},
		},
		{

			Op:    addCommand,
			Sec:   "g",
			Ptype: "g",
			Rule:  []string{"bob", "data1_admin"},
		},
		{

			Op:    addCommand,
			Sec:   "g",
			Ptype: "g",
			Rule:  []string{"eve", "data3_admin"},
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
	enforcer, err := casbin.NewSyncedEnforcer("examples/rbac_model.conf", new(fakeAdapter))
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
				Rule:  []string{"alice", "data1", "read"},
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
				Rule:  []string{"bob", "data2", "write"},
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
				Rule:  []string{"alice", "data1", "read"},
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
				Rule:  []string{"eve", "data3", "read"},
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
				Rule:  []string{"eve", "data3", "read"},
			},
			[][]string{
				{"bob", "data2", "write"},
				{"eve", "data3", "read"},
			},
		},
	}

	for _, tt := range tests {
		e.Apply(tt.c)
		testGetPolicy(t, e, tt.res)
	}
}

type fakeAdapter struct{}

var _ persist.Adapter = &fakeAdapter{}

func (a *fakeAdapter) LoadPolicy(model model.Model) error {
	return nil
}

func (a *fakeAdapter) SavePolicy(model model.Model) error {
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
