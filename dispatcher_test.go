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
	"encoding/json"
	"fmt"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/util"
	"github.com/coreos/etcd/pkg/pbutil"
	"github.com/coreos/etcd/raft/raftpb"
)

type node struct {
	e *casbin.Enforcer
	d *Dispatcher
}

type cluster []*node

func GetFreePort() int {
	addr, _ := net.ResolveTCPAddr("tcp", "localhost:0")

	l, _ := net.ListenTCP("tcp", addr)

	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func testEnforce(t *testing.T, n *node, sub string, obj string, act string, res bool) {
	t.Helper()
	if myRes, _ := n.e.Enforce(sub, obj, act); myRes != res {
		t.Errorf("%s, %v, %s: %t, node %d supposed to be %t", sub, obj, act, myRes, n.d.id, res)
	}
}

func testClusterEnforce(t *testing.T, c cluster, sub string, obj string, act string, res bool) {
	for _, e := range c {
		testEnforce(t, e, sub, obj, act, res)
	}
}

func testGetPolicy(t *testing.T, n *node, res [][]string) {
	t.Helper()
	myRes := n.e.GetPolicy()
	t.Log("Policy: ", myRes)

	if !util.Array2DEquals(res, myRes) {
		t.Error("Policy: ", myRes, ", node %d supposed to be ", n.d.id, res)
	}
}

func testClusterGetPolicy(t *testing.T, c cluster, res [][]string) {
	for _, e := range c {
		testGetPolicy(t, e, res)
	}
}

func newNode(id uint64) *node {
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d", id))
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d-snap", id))
	peers := make(map[uint64]string)
	peers[id] = fmt.Sprintf("http://127.0.0.1:%d", GetFreePort())
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	if err != nil {
		panic(err)
	}
	d := NewDispatcher(id, peers)
	_ = e.SetDispatcher(d)
	e.EnableautoNotifyDispatcher(true)
	go func() {
		if err := d.Start(); err != nil {
			panic(err)
		}
	}()
	return &node{e, d}
}

func newCluster(num int) cluster {
	peers := make(map[uint64]string)

	for i := 1; i <= num; i++ {
		peers[uint64(i)] = fmt.Sprintf("http://127.0.0.1:%d", GetFreePort())
	}
	var c cluster
	for id := range peers {
		_ = os.RemoveAll(fmt.Sprintf("casbin-%d", id))
		_ = os.RemoveAll(fmt.Sprintf("casbin-%d-snap", id))
		e, err := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
		if err != nil {
			panic(err)
		}
		d := NewDispatcher(id, peers)
		_ = e.SetDispatcher(d)
		e.EnableautoNotifyDispatcher(true)
		go func() {
			if err := d.Start(); err != nil {
				panic(err)
			}
		}()
		c = append(c, &node{e, d})
	}
	return c
}

func TestModifyPolicy(t *testing.T) {
	n := newNode(1)
	<-time.After(time.Second * 3)
	testGetPolicy(t, n, [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"}})

	_, _ = n.e.RemovePolicy("alice", "data1", "read")
	_, _ = n.e.RemovePolicy("bob", "data2", "write")
	_, _ = n.e.RemovePolicy("alice", "data1", "read")
	_, _ = n.e.AddPolicy("eve", "data3", "read")
	_, _ = n.e.AddPolicy("eve", "data3", "read")
	<-time.After(time.Second * 3)
	rules := [][]string{
		{"jack", "data4", "read"},
		{"jack", "data4", "read"},
		{"jack", "data4", "read"},
		{"katy", "data4", "write"},
		{"leyo", "data4", "read"},
		{"katy", "data4", "write"},
		{"katy", "data4", "write"},
		{"ham", "data4", "write"},
	}

	_, _ = n.e.AddPolicies(rules)
	_, _ = n.e.AddPolicies(rules)
	<-time.After(time.Second * 3)
	testGetPolicy(t, n, [][]string{
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
		{"eve", "data3", "read"},
		{"jack", "data4", "read"},
		{"katy", "data4", "write"},
		{"leyo", "data4", "read"},
		{"ham", "data4", "write"}})

	_, _ = n.e.RemovePolicies(rules)
	_, _ = n.e.RemovePolicies(rules)
	<-time.After(time.Second * 3)
	testGetPolicy(t, n, [][]string{
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
		{"eve", "data3", "read"}})

	_, _ = n.e.RemoveFilteredPolicy(1, "data2")
	<-time.After(time.Second * 3)
	testGetPolicy(t, n, [][]string{{"eve", "data3", "read"}})
}

func TestModifyPolicyCluster(t *testing.T) {
	c := newCluster(3)
	<-time.After(time.Second * 3)
	testClusterGetPolicy(t, c, [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"}})

	_, _ = c[0].e.RemovePolicy("alice", "data1", "read")
	_, _ = c[1].e.RemovePolicy("bob", "data2", "write")
	_, _ = c[2].e.RemovePolicy("alice", "data1", "read")
	_, _ = c[2].e.AddPolicy("eve", "data3", "read")
	_, _ = c[2].e.AddPolicy("eve", "data3", "read")
	<-time.After(time.Second * 3)
	rules := [][]string{
		{"jack", "data4", "read"},
		{"jack", "data4", "read"},
		{"jack", "data4", "read"},
		{"katy", "data4", "write"},
		{"leyo", "data4", "read"},
		{"katy", "data4", "write"},
		{"katy", "data4", "write"},
		{"ham", "data4", "write"},
	}

	_, _ = c[0].e.AddPolicies(rules)
	_, _ = c[1].e.AddPolicies(rules)
	<-time.After(time.Second * 3)
	testClusterGetPolicy(t, c, [][]string{
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
		{"eve", "data3", "read"},
		{"jack", "data4", "read"},
		{"katy", "data4", "write"},
		{"leyo", "data4", "read"},
		{"ham", "data4", "write"}})

	_, _ = c[2].e.RemovePolicies(rules)
	_, _ = c[2].e.RemovePolicies(rules)
	<-time.After(time.Second * 3)
	testClusterGetPolicy(t, c, [][]string{
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
		{"eve", "data3", "read"}})

	_, _ = c[1].e.RemoveFilteredPolicy(1, "data2")
	<-time.After(time.Second * 3)
	testClusterGetPolicy(t, c, [][]string{{"eve", "data3", "read"}})
}

func TestModifyRBACPolicy(t *testing.T) {
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d", 1))
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d-snap", 1))
	peers := make(map[uint64]string)
	peers[1] = fmt.Sprintf("http://127.0.0.1:%d", GetFreePort())
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(1, peers)
	_ = e.SetDispatcher(d)
	e.EnableautoNotifyDispatcher(true)
	go func() {
		if err := d.Start(); err != nil {
			panic(err)
		}
	}()
	<-time.After(time.Second * 3)
	_, _ = e.AddGroupingPolicy("bob", "data2_admin")
	_, _ = e.RemoveGroupingPolicy("alice", "data2_admin")
	<-time.After(time.Second * 3)
	testEnforce(t, &node{e, d}, "alice", "data2", "read", false)
	testEnforce(t, &node{e, d}, "alice", "data2", "write", false)
	testEnforce(t, &node{e, d}, "bob", "data2", "read", true)
	testEnforce(t, &node{e, d}, "bob", "data2", "write", true)
}

func TestAddMember(t *testing.T) {
	peers := make(map[uint64]string)

	for i := 1; i <= 3; i++ {
		peers[uint64(i)] = fmt.Sprintf("http://127.0.0.1:%d", 10000+i)
	}
	var c cluster
	for id := range peers {
		_ = os.RemoveAll(fmt.Sprintf("casbin-%d", id))
		_ = os.RemoveAll(fmt.Sprintf("casbin-%d-snap", id))
		e, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
		if err != nil {
			t.Fatal(err)
		}
		d := NewDispatcher(id, peers)
		_ = e.SetDispatcher(d)
		e.EnableautoNotifyDispatcher(true)
		go func() {
			if err := d.Start(); err != nil {
				panic(err)
			}
		}()
		c = append(c, &node{e, d})
	}

	_ = os.RemoveAll(fmt.Sprintf("casbin-%d", 4))
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d-snap", 4))
	p := make(map[uint64]string)
	p[1] = "http://127.0.0.1:10001"
	p[2] = "http://127.0.0.1:10002"
	p[3] = "http://127.0.0.1:10003"
	p[4] = "http://127.0.0.1:10004"
	e, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatal(err)
	}

	d := NewDispatcher(4, p, true)
	_ = e.SetDispatcher(d)
	e.EnableautoNotifyDispatcher(true)
	go func() {
		if err := d.Start(); err != nil {
			panic(err)
		}
	}()
	<-time.After(time.Second * 3)
	err = c[0].d.AddMember(4, "http://127.0.0.1:10004")
	if err != nil {
		t.Fatal(err)
	}

	<-time.After(time.Second * 3)
	_, _ = e.AddPolicy("alice", "data2", "write")
	<-time.After(time.Second * 3)
	testClusterEnforce(t, c, "alice", "data2", "write", true)
	testEnforce(t, &node{e, d}, "alice", "data2", "write", true)
}

func TestRemoveMember(t *testing.T) {
	c := newCluster(3)
	<-time.After(time.Second * 3)
	_ = c[1].d.RemoveMember(1)
	<-time.After(time.Second * 3)
	for _, n := range c {
		if n.d.id == 1 {
			continue
		}
		_, _ = n.e.AddPolicy("bob", "data2", "read")
		break
	}

	<-time.After(time.Second * 3)
	for _, n := range c {
		result := true
		if n.d.id == 1 {
			result = false
		}
		testEnforce(t, n, "bob", "data2", "read", result)
	}
}

func TestAddMemberRunning(t *testing.T) {
	peers := make(map[uint64]string)

	for i := 1; i <= 3; i++ {
		peers[uint64(i)] = fmt.Sprintf("http://127.0.0.1:%d", 8000+i)
	}
	var c cluster
	for id := range peers {
		_ = os.RemoveAll(fmt.Sprintf("casbin-%d", id))
		_ = os.RemoveAll(fmt.Sprintf("casbin-%d-snap", id))
		e, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
		if err != nil {
			t.Fatal(err)
		}
		d := NewDispatcher(id, peers)
		_ = e.SetDispatcher(d)
		e.EnableautoNotifyDispatcher(true)
		go func() {
			if err := d.Start(); err != nil {
				panic(err)
			}
		}()
		c = append(c, &node{e, d})
	}
	<-time.After(time.Second * 3)
	for i := 0; i < 50; i++ {
		_, _ = c[0].e.AddPolicy(fmt.Sprintf("user%d", i), fmt.Sprintf("data%d", i/10), "read")
	}
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d", 4))
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d-snap", 4))
	p := make(map[uint64]string)
	p[1] = "http://127.0.0.1:8001"
	p[2] = "http://127.0.0.1:8002"
	p[3] = "http://127.0.0.1:8003"
	p[4] = "http://127.0.0.1:8004"
	e, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatal(err)
	}

	d := NewDispatcher(4, p, true)
	_ = e.SetDispatcher(d)
	e.EnableautoNotifyDispatcher(true)
	go func() {
		if err := d.Start(); err != nil {
			panic(err)
		}
	}()
	<-time.After(time.Second * 3)
	err = c[0].d.AddMember(4, "http://127.0.0.1:8004")
	if err != nil {
		t.Fatal(err)
	}
	for i := 50; i < 100; i++ {
		_, _ = c[0].e.AddPolicy(fmt.Sprintf("user%d", i), fmt.Sprintf("data%d", i/10), "read")
	}
	<-time.After(time.Second * 3)
	for i := 0; i < 100; i++ {
		testClusterEnforce(t, c, fmt.Sprintf("user%d", i), fmt.Sprintf("data%d", i/10), "read", true)
		testEnforce(t, &node{e, d}, fmt.Sprintf("user%d", i), fmt.Sprintf("data%d", i/10), "read", true)
	}
}

func TestSaveSnapshot(t *testing.T) {
	node := newNode(1)
	node.d.SetSnapshotCount(10)
	<-time.After(time.Second * 3)
	for i := 0; i < 101; i++ {
		_, _ = node.e.AddPolicy(fmt.Sprintf("user%d", i), fmt.Sprintf("data%d", i/10), "read")
	}
	<-time.After(time.Second * 3)
}

func TestRestartFromWAL(t *testing.T) {
	n := newNode(1)
	<-time.After(time.Second * 3)
	_, _ = n.e.AddPolicy("alice", "data2", "write")
	<-time.After(time.Second * 3)
	testEnforce(t, n, "alice", "data2", "write", true)
	n.d.Stop()
	<-time.After(time.Second * 3)
	peers := make(map[uint64]string)
	peers[1] = fmt.Sprintf("http://127.0.0.1:%d", GetFreePort())
	e, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(1, peers)
	_ = e.SetDispatcher(d)
	e.EnableautoNotifyDispatcher(true)
	go func() {
		err := d.Restart()
		if err != nil {
			panic(err)
		}
	}()
	<-time.After(time.Second * 3)
	testEnforce(t, &node{e, d}, "alice", "data2", "write", true)
}

func TestRestartFromLockedWAL(t *testing.T) {
	_ = newNode(1)

	<-time.After(time.Second * 3)
	peers := make(map[uint64]string)
	peers[1] = fmt.Sprintf("http://127.0.0.1:%d", GetFreePort())
	e, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(1, peers)
	_ = e.SetDispatcher(d)
	e.EnableautoNotifyDispatcher(true)
	err = d.Restart()
	if err == nil {
		t.Errorf("Should not be error here.")
	} else {
		t.Log("Test on error: ")
		t.Log(err.Error())
	}
}

func TestRestartFromSnapshot(t *testing.T) {
	n := newNode(1)
	n.d.SetSnapshotCount(10)
	<-time.After(time.Second * 3)
	for i := 0; i < 101; i++ {
		_, _ = n.e.AddPolicy(fmt.Sprintf("user%d", i), fmt.Sprintf("data%d", i/10), "read")
	}
	<-time.After(time.Second * 3)
	n.d.Stop()
	<-time.After(time.Second * 3)
	peers := make(map[uint64]string)
	peers[1] = fmt.Sprintf("http://127.0.0.1:%d", GetFreePort())
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(1, peers)
	_ = e.SetDispatcher(d)
	e.EnableautoNotifyDispatcher(true)
	go func() {
		err := d.Restart()
		if err != nil {
			panic(err)
		}
	}()
	<-time.After(time.Second * 3)
	for i := 0; i < 101; i++ {
		testEnforce(t, &node{e, d}, fmt.Sprintf("user%d", i), fmt.Sprintf("data%d", i/10), "read", true)
	}
}

func TestRestartFromEmpty(t *testing.T) {
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d", 1))
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d-snap", 1))
	e, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(1, nil)
	_ = e.SetDispatcher(d)
	e.EnableautoNotifyDispatcher(true)
	err = d.Restart()
	t.Log(err)
	if err == nil {
		t.Error("expect err, get nil")
	}
}

func TestRequestToRemovedMember(t *testing.T) {
	c := newCluster(3)
	<-time.After(time.Second * 3)
	err := c[1].d.RemoveMember(1)
	if err != nil {
		t.Fatal(err)
	}
	<-time.After(time.Second * 3)
	for _, n := range c {
		if n.d.id == 1 {
			_, err := n.e.AddPolicy("alice", "data2", "write")
			if err == nil {
				t.Errorf("Should not be error here.")
			} else {
				t.Log("Test on error: ")
				t.Log(err.Error())
			}
			break
		}
	}
}

func TestInit(t *testing.T) {
	var d *Dispatcher
	tests := []struct {
		beforeFunc func()
		hasErr     bool
	}{
		{
			func() {
				_ = os.RemoveAll(fmt.Sprintf("casbin-%d", 1))
				_ = os.RemoveAll(fmt.Sprintf("casbin-%d-snap", 1))
			},
			false,
		},
		{
			func() {
				_ = os.RemoveAll(fmt.Sprintf("casbin-%d", 1))
			},
			true,
		},
		{
			func() {
				_ = os.RemoveAll(fmt.Sprintf("casbin-%d", 1))
				_ = os.RemoveAll(fmt.Sprintf("casbin-%d-snap", 1))
			},
			false,
		},
		{
			func() {
				_ = os.RemoveAll(fmt.Sprintf("casbin-%d-snap", 1))
			},
			true,
		},
		{
			func() {},
			true,
		},
	}

	for _, tt := range tests {
		e, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
		if err != nil {
			t.Fatal(err)
		}
		d = NewDispatcher(1, nil)
		_ = e.SetDispatcher(d)
		e.EnableautoNotifyDispatcher(true)
		tt.beforeFunc()
		err = d.init()
		if ok := err != nil; ok != tt.hasErr {
			t.Errorf("get err %s", err)
		}
	}
}

func TestRestartNode(t *testing.T) {
	tests := []struct {
		beforeFunc func()
		hasErr     bool
	}{
		{
			func() {
				_ = os.Mkdir(fmt.Sprintf("casbin-%d", 1), 0750)
				_ = os.RemoveAll(fmt.Sprintf("casbin-%d-snap", 1))
			},
			true,
		},
		{
			func() {
				_ = os.RemoveAll(fmt.Sprintf("casbin-%d", 1))
				_ = os.Mkdir(fmt.Sprintf("casbin-%d-snap", 1), 0750)
			},
			true,
		},
		{
			func() {
				_ = os.Mkdir(fmt.Sprintf("casbin-%d", 1), 0750)
				_ = os.Mkdir(fmt.Sprintf("casbin-%d-snap", 1), 0750)
			},
			true,
		},
	}

	for _, tt := range tests {
		e, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
		if err != nil {
			t.Fatal(err)
		}
		d := NewDispatcher(1, nil)
		_ = e.SetDispatcher(d)
		tt.beforeFunc()
		err = d.Restart()
		t.Log(err)

		if ok := err != nil; ok != tt.hasErr {
			t.Errorf("get err: %s", err)
		}
	}
}

func TestProcessNormal(t *testing.T) {
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d", 1))
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d-snap", 1))
	e, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(1, nil)
	_ = e.SetDispatcher(d)
	err = d.init()
	if err != nil {
		t.Fatal(err)
	}
	command1 := Command{
		Op:    addCommand,
		Sec:   "p",
		Ptype: "p",
		Rules: [][]string{{"eve", "data3", "read"}},
	}
	data1, err := json.Marshal(&command1)
	if err != nil {
		t.Fatal(err)
	}
	command2 := Command{
		Op:    removeCommand,
		Sec:   "p",
		Ptype: "p",
		Rules: [][]string{{"eve", "data3", "read"}},
	}
	data2, err := json.Marshal(&command2)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		entry raftpb.Entry
		res   bool
	}{
		{
			raftpb.Entry{Term: 1, Index: 2, Type: raftpb.EntryNormal, Data: data1},
			true,
		},
		{
			raftpb.Entry{Term: 1, Index: 2, Type: raftpb.EntryNormal, Data: data1},
			true,
		},
		{
			raftpb.Entry{Term: 1, Index: 3, Type: raftpb.EntryNormal, Data: data2},
			false,
		},
	}

	for _, tt := range tests {
		d.process(tt.entry)
		testEnforce(t, &node{e, d}, "eve", "data3", "read", tt.res)
	}
}

func TestProcessConfchange(t *testing.T) {
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d", 1))
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d-snap", 1))
	e, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	peers := make(map[uint64]string)
	d := NewDispatcher(1, peers)
	_ = e.SetDispatcher(d)
	err = d.init()
	if err != nil {
		t.Fatal(err)
	}
	err = d.initTransport()
	if err != nil {
		t.Fatal(err)
	}

	addcc1 := &raftpb.ConfChange{Type: raftpb.ConfChangeAddNode, NodeID: 1, Context: []byte("http://127.0.0.1:8081")}
	addcc2 := &raftpb.ConfChange{Type: raftpb.ConfChangeAddNode, NodeID: 2, Context: []byte("http://127.0.0.1:8082")}
	addcc3 := &raftpb.ConfChange{Type: raftpb.ConfChangeAddNode, NodeID: 3, Context: []byte("http://127.0.0.1:8083")}
	removecc2 := &raftpb.ConfChange{Type: raftpb.ConfChangeRemoveNode, NodeID: 2}
	removecc3 := &raftpb.ConfChange{Type: raftpb.ConfChangeRemoveNode, NodeID: 3}
	tests := []struct {
		entry raftpb.Entry
		state raftpb.ConfState
	}{
		{
			raftpb.Entry{Term: 1, Index: 2, Type: raftpb.EntryConfChange, Data: pbutil.MustMarshal(addcc1)},
			raftpb.ConfState{Nodes: []uint64{1}},
		},
		{
			raftpb.Entry{Term: 2, Index: 3, Type: raftpb.EntryConfChange, Data: pbutil.MustMarshal(addcc2)},
			raftpb.ConfState{Nodes: []uint64{1, 2}},
		},
		{
			raftpb.Entry{Term: 2, Index: 3, Type: raftpb.EntryConfChange, Data: pbutil.MustMarshal(addcc3)},
			raftpb.ConfState{Nodes: []uint64{1, 2, 3}},
		},
		{
			raftpb.Entry{Term: 2, Index: 4, Type: raftpb.EntryConfChange, Data: pbutil.MustMarshal(removecc2)},
			raftpb.ConfState{Nodes: []uint64{1, 3}},
		},
		{
			raftpb.Entry{Term: 2, Index: 3, Type: raftpb.EntryConfChange, Data: pbutil.MustMarshal(removecc3)},
			raftpb.ConfState{Nodes: []uint64{1}},
		},
	}

	for _, tt := range tests {
		d.process(tt.entry)
		if !reflect.DeepEqual(&tt.state, d.confState) {
			t.Errorf("confState %v \n want %v", d.confState, tt.state)
		}
	}

}

func TestProcessSnapshot(t *testing.T) {
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d", 1))
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d-snap", 1))
	e, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(1, nil)
	_ = e.SetDispatcher(d)
	if err := d.init(); err != nil {
		t.Fatal(err)
	}
	data1, err := d.engine.getSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = e.AddPolicy("eve", "data3", "write")
	data2, err := d.engine.getSnapshot()
	if err != nil {
		t.Fatal(err)
	}

	_, _ = e.RemovePolicy("bob", "data2", "write")
	data3, err := d.engine.getSnapshot()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		snapshot raftpb.Snapshot
		res      [][]string
	}{
		{
			raftpb.Snapshot{Metadata: raftpb.SnapshotMetadata{Index: 1000, Term: 1}, Data: data1},
			[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}},
		},
		{
			raftpb.Snapshot{Metadata: raftpb.SnapshotMetadata{Index: 1001, Term: 1}, Data: data2},
			[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"eve", "data3", "write"}},
		},
		{
			raftpb.Snapshot{Metadata: raftpb.SnapshotMetadata{Index: 1002, Term: 1}, Data: data3},
			[][]string{{"alice", "data1", "read"}, {"eve", "data3", "write"}},
		},
		{
			raftpb.Snapshot{Metadata: raftpb.SnapshotMetadata{Index: 1003, Term: 1}, Data: data1},
			[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}},
		},
	}

	for _, tt := range tests {
		err = d.processSnapshot(tt.snapshot)
		if err != nil {
			t.Fatal(err)
		}
		testGetPolicy(t, &node{e, d}, tt.res)
	}
}
