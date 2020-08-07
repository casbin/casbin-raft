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

type cluster []*Node

func GetFreePort() int {
	addr, _ := net.ResolveTCPAddr("tcp", "localhost:0")

	l, _ := net.ListenTCP("tcp", addr)

	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func testEnforce(t *testing.T, n *Node, sub string, obj string, act string, res bool) {
	t.Helper()
	if myRes, _ := n.engine.enforcer.Enforce(sub, obj, act); myRes != res {
		t.Errorf("%s, %v, %s: %t, node %d supposed to be %t", sub, obj, act, myRes, n.id, res)
	}
}

func testClusterEnforce(t *testing.T, c cluster, sub string, obj string, act string, res bool) {
	for _, n := range c {
		testEnforce(t, n, sub, obj, act, res)
	}
}

func testEnforcerGetPolicy(t *testing.T, e *casbin.Enforcer, res [][]string) {
	t.Helper()
	myRes := e.GetPolicy()
	t.Log("Policy: ", myRes)

	if !util.Array2DEquals(res, myRes) {
		t.Error("Policy: ", myRes, ", supposed to be ", res)
	}
}

func newNode(id uint64) *Node {
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d", id))
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d-snap", id))
	peers := make(map[uint64]string)
	peers[id] = fmt.Sprintf("http://127.0.0.1:%d", GetFreePort())
	enforcer, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		panic(err)
	}
	node := NewNode(id, peers)
	_ = node.SetEnforcer(enforcer)

	go func() {
		if err := node.Start(); err != nil {
			panic(err)
		}
	}()
	return node
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
		enforcer, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
		if err != nil {
			panic(err)
		}
		n := NewNode(id, peers)
		_ = n.SetEnforcer(enforcer)
		go func() {
			if err := n.Start(); err != nil {
				panic(err)
			}
		}()
		c = append(c, n)
	}
	return c
}

func TestModifyPolicy(t *testing.T) {
	node := newNode(1)
	<-time.After(time.Second * 3)
	_ = node.AddPolicies("p", "p", [][]string{{"alice", "data2", "write"}})
	_ = node.AddPolicies("p", "p", [][]string{{"eve", "data3", "read"}})
	_ = node.RemovePolicies("p", "p", [][]string{{"alice", "data1", "read"}})
	_ = node.RemovePolicies("p", "p", [][]string{{"bob", "data2", "write"}})
	<-time.After(time.Second * 3)
	testEnforce(t, node, "alice", "data2", "write", true)
	testEnforce(t, node, "eve", "data3", "read", true)
	testEnforce(t, node, "alice", "data1", "read", false)
	testEnforce(t, node, "bob", "data2", "write", false)

	_ = node.RemoveFilteredPolicy("p", "p", 0, "alice")
	<-time.After(time.Second * 3)
	testEnforce(t, node, "alice", "data2", "write", false)
	testEnforce(t, node, "eve", "data3", "read", true)
	testEnforce(t, node, "alice", "data1", "read", false)
	testEnforce(t, node, "bob", "data2", "write", false)
}

func TestModifyPolicyCluster(t *testing.T) {
	c := newCluster(3)
	<-time.After(time.Second * 3)
	_ = c[0].AddPolicies("p", "p", [][]string{{"alice", "data2", "write"}})
	_ = c[1].RemovePolicies("p", "p", [][]string{{"alice", "data1", "read"}})
	_ = c[2].RemovePolicies("p", "p", [][]string{{"bob", "data2", "write"}})
	_ = c[2].AddPolicies("p", "p", [][]string{{"eve", "data3", "read"}})
	<-time.After(time.Second * 3)

	testClusterEnforce(t, c, "alice", "data2", "write", true)
	testClusterEnforce(t, c, "alice", "data1", "read", false)
	testClusterEnforce(t, c, "bob", "data2", "write", false)
	testClusterEnforce(t, c, "eve", "data3", "read", true)

	_ = c[2].RemoveFilteredPolicy("p", "p", 0, "alice")
	<-time.After(time.Second * 3)
	testClusterEnforce(t, c, "alice", "data2", "write", false)
	testClusterEnforce(t, c, "alice", "data1", "read", false)
	testClusterEnforce(t, c, "bob", "data2", "write", false)
	testClusterEnforce(t, c, "eve", "data3", "read", true)
}

func TestModifyRBACPolicy(t *testing.T) {
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d", 1))
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d-snap", 1))
	peers := make(map[uint64]string)
	peers[1] = fmt.Sprintf("http://127.0.0.1:%d", GetFreePort())
	enforcer, err := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	node := NewNode(1, peers)
	_ = node.SetEnforcer(enforcer)
	go func() {
		if err := node.Start(); err != nil {
			panic(err)
		}
	}()
	<-time.After(time.Second * 3)
	_ = node.AddPolicies("g", "g", [][]string{{"bob", "data2_admin"}})
	_ = node.RemovePolicies("g", "g", [][]string{{"alice", "data2_admin"}})
	<-time.After(time.Second * 3)
	testEnforce(t, node, "alice", "data2", "read", false)
	testEnforce(t, node, "alice", "data2", "write", false)
	testEnforce(t, node, "bob", "data2", "read", true)
	testEnforce(t, node, "bob", "data2", "write", true)
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
		enforcer, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
		if err != nil {
			t.Fatal(err)
		}
		n := NewNode(id, peers)
		_ = n.SetEnforcer(enforcer)
		go func() {
			if err := n.Start(); err != nil {
				panic(err)
			}
		}()
		c = append(c, n)
	}

	_ = os.RemoveAll(fmt.Sprintf("casbin-%d", 4))
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d-snap", 4))
	p := make(map[uint64]string)
	p[1] = "http://127.0.0.1:10001"
	p[2] = "http://127.0.0.1:10002"
	p[3] = "http://127.0.0.1:10003"
	p[4] = "http://127.0.0.1:10004"
	enforcer, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatal(err)
	}

	node := NewNode(4, p, true)
	_ = node.SetEnforcer(enforcer)
	go func() {
		if err := node.Start(); err != nil {
			panic(err)
		}
	}()
	<-time.After(time.Second * 3)
	err = c[0].AddMember(4, "http://127.0.0.1:10004")
	if err != nil {
		t.Fatal(err)
	}

	<-time.After(time.Second * 3)
	_ = node.AddPolicies("p", "p", [][]string{{"alice", "data2", "write"}})
	<-time.After(time.Second * 3)
	testClusterEnforce(t, c, "alice", "data2", "write", true)
	testEnforce(t, node, "alice", "data2", "write", true)
}

func TestRemoveMember(t *testing.T) {
	c := newCluster(3)
	<-time.After(time.Second * 3)
	_ = c[1].RemoveMember(1)
	<-time.After(time.Second * 3)
	for _, n := range c {
		if n.id == 1 {
			continue
		}
		_ = n.AddPolicies("p", "p", [][]string{{"alice", "data2", "write"}})
		break
	}

	<-time.After(time.Second * 3)
	for _, n := range c {
		result := true
		if n.id == 1 {
			result = false
		}
		testEnforce(t, n, "alice", "data2", "write", result)
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
		enforcer, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
		if err != nil {
			t.Fatal(err)
		}
		n := NewNode(id, peers)
		_ = n.SetEnforcer(enforcer)
		go func() {
			if err := n.Start(); err != nil {
				panic(err)
			}
		}()
		c = append(c, n)
	}
	<-time.After(time.Second * 3)
	for i := 0; i < 50; i++ {
		_ = c[0].AddPolicies("p", "p", [][]string{{fmt.Sprintf("user%d", i), fmt.Sprintf("data%d", i/10), "read"}})
	}
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d", 4))
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d-snap", 4))
	p := make(map[uint64]string)
	p[1] = "http://127.0.0.1:8001"
	p[2] = "http://127.0.0.1:8002"
	p[3] = "http://127.0.0.1:8003"
	p[4] = "http://127.0.0.1:8004"
	enforcer, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatal(err)
	}

	node := NewNode(4, p, true)
	_ = node.SetEnforcer(enforcer)
	go func() {
		if err := node.Start(); err != nil {
			panic(err)
		}
	}()
	<-time.After(time.Second * 3)
	err = c[0].AddMember(4, "http://127.0.0.1:8004")
	if err != nil {
		t.Fatal(err)
	}
	for i := 50; i < 100; i++ {
		_ = c[0].AddPolicies("p", "p", [][]string{{fmt.Sprintf("user%d", i), fmt.Sprintf("data%d", i/10), "read"}})
	}
	<-time.After(time.Second * 3)
	for i := 0; i < 100; i++ {
		testClusterEnforce(t, c, fmt.Sprintf("user%d", i), fmt.Sprintf("data%d", i/10), "read", true)
		testEnforce(t, node, fmt.Sprintf("user%d", i), fmt.Sprintf("data%d", i/10), "read", true)
	}
}

func TestSaveSnapshot(t *testing.T) {
	node := newNode(1)
	node.SetSnapshotCount(10)
	<-time.After(time.Second * 3)
	for i := 0; i < 101; i++ {
		_ = node.AddPolicies("p", "p", [][]string{{fmt.Sprintf("user%d", i), fmt.Sprintf("data%d", i/10), "read"}})
	}
	<-time.After(time.Second * 3)
}

func TestRestartFromWAL(t *testing.T) {
	node := newNode(1)
	<-time.After(time.Second * 3)
	_ = node.AddPolicies("p", "p", [][]string{{"alice", "data2", "write"}})
	<-time.After(time.Second * 3)
	testEnforce(t, node, "alice", "data2", "write", true)
	node.Stop()
	<-time.After(time.Second * 3)
	peers := make(map[uint64]string)
	peers[1] = fmt.Sprintf("http://127.0.0.1:%d", GetFreePort())
	enforcer, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	nodeRestart := NewNode(1, peers)
	_ = nodeRestart.SetEnforcer(enforcer)
	go func() {
		err := nodeRestart.Restart()
		if err != nil {
			panic(err)
		}
	}()
	<-time.After(time.Second * 3)
	testEnforce(t, nodeRestart, "alice", "data2", "write", true)
}

func TestRestartFromLockedWAL(t *testing.T) {
	_ = newNode(1)

	<-time.After(time.Second * 3)
	peers := make(map[uint64]string)
	peers[1] = fmt.Sprintf("http://127.0.0.1:%d", GetFreePort())
	enforcer, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	nodeRestart := NewNode(1, peers)
	_ = nodeRestart.SetEnforcer(enforcer)
	err = nodeRestart.Restart()
	if err == nil {
		t.Errorf("Should not be error here.")
	} else {
		t.Log("Test on error: ")
		t.Log(err.Error())
	}
}

func TestRestartFromSnapshot(t *testing.T) {
	node := newNode(1)
	node.SetSnapshotCount(10)
	<-time.After(time.Second * 3)
	for i := 0; i < 101; i++ {
		_ = node.AddPolicies("p", "p", [][]string{{fmt.Sprintf("user%d", i), fmt.Sprintf("data%d", i/10), "read"}})
	}
	<-time.After(time.Second * 3)
	node.Stop()
	<-time.After(time.Second * 3)
	peers := make(map[uint64]string)
	peers[1] = fmt.Sprintf("http://127.0.0.1:%d", GetFreePort())
	enforcer, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	nodeRestart := NewNode(1, peers)
	_ = nodeRestart.SetEnforcer(enforcer)
	go func() {
		err := nodeRestart.Restart()
		if err != nil {
			panic(err)
		}
	}()
	<-time.After(time.Second * 3)
	for i := 0; i < 101; i++ {
		testEnforce(t, nodeRestart, fmt.Sprintf("user%d", i), fmt.Sprintf("data%d", i/10), "read", true)
	}
}

func TestRestartFromEmpty(t *testing.T) {
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d", 1))
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d-snap", 1))
	enforcer, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	n := NewNode(1, nil)
	_ = n.SetEnforcer(enforcer)
	err = n.Restart()
	t.Log(err)
	if err == nil {
		t.Error("expect err, get nil")
	}
}

func TestRequestToRemovedMember(t *testing.T) {
	c := newCluster(3)
	<-time.After(time.Second * 3)
	err := c[1].RemoveMember(1)
	if err != nil {
		t.Fatal(err)
	}
	<-time.After(time.Second * 3)
	for _, n := range c {
		if n.id == 1 {
			err := n.AddPolicies("p", "p", [][]string{{"alice", "data2", "write"}})
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

func TestInitNode(t *testing.T) {
	var n *Node
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
		enforcer, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
		if err != nil {
			t.Fatal(err)
		}
		n = NewNode(1, nil)
		_ = n.SetEnforcer(enforcer)
		tt.beforeFunc()
		err = n.init()
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
		enforcer, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
		if err != nil {
			t.Fatal(err)
		}
		n := NewNode(1, nil)
		_ = n.SetEnforcer(enforcer)
		tt.beforeFunc()
		err = n.Restart()
		t.Log(err)

		if ok := err != nil; ok != tt.hasErr {
			t.Errorf("get err: %s", err)
		}
	}
}

func TestProcessNormal(t *testing.T) {
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d", 1))
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d-snap", 1))
	enforcer, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	n := NewNode(1, nil)
	_ = n.SetEnforcer(enforcer)
	err = n.init()
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
		n.process(tt.entry)
		testEnforce(t, n, "eve", "data3", "read", tt.res)
	}
}

func TestProcessConfchange(t *testing.T) {
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d", 1))
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d-snap", 1))
	enforcer, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	peers := make(map[uint64]string)
	n := NewNode(1, peers)
	_ = n.SetEnforcer(enforcer)
	err = n.init()
	if err != nil {
		t.Fatal(err)
	}
	err = n.initTransport()
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
		n.process(tt.entry)
		if !reflect.DeepEqual(&tt.state, n.confState) {
			t.Errorf("confState %v \n want %v", n.confState, tt.state)
		}
	}

}

func TestProcessSnapshot(t *testing.T) {
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d", 1))
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d-snap", 1))
	enforcer, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	n := NewNode(1, nil)
	_ = n.SetEnforcer(enforcer)
	if err := n.init(); err != nil {
		t.Fatal(err)
	}
	data1, err := n.engine.getSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = enforcer.AddPolicies([][]string{{"eve", "data3", "write"}})
	data2, err := n.engine.getSnapshot()
	if err != nil {
		t.Fatal(err)
	}

	_, _ = enforcer.RemovePolicies([][]string{{"bob", "data2", "write"}})
	data3, err := n.engine.getSnapshot()
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
		err = n.processSnapshot(tt.snapshot)
		if err != nil {
			t.Fatal(err)
		}
		testGetPolicy(t, n.engine, tt.res)
	}
}

func TestModifyPolicyAPI(t *testing.T) {
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d", 1))
	_ = os.RemoveAll(fmt.Sprintf("casbin-%d-snap", 1))
	peers := make(map[uint64]string)
	peers[1] = fmt.Sprintf("http://127.0.0.1:%d", GetFreePort())
	node := NewNode(1, peers)
	_ = e.SetDispatcher(node)
	go func() {
		if err := node.Start(); err != nil {
			panic(err)
		}
	}()
	<-time.After(time.Second * 3)
	testEnforcerGetPolicy(t, e, [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"}})

	_, _ = e.RemovePolicy("alice", "data1", "read")
	_, _ = e.RemovePolicy("bob", "data2", "write")
	_, _ = e.RemovePolicy("alice", "data1", "read")
	_, _ = e.AddPolicy("eve", "data3", "read")
	_, _ = e.AddPolicy("eve", "data3", "read")
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

	_, _ = e.AddPolicies(rules)
	_, _ = e.AddPolicies(rules)
	<-time.After(time.Second * 3)
	testEnforcerGetPolicy(t, e, [][]string{
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
		{"eve", "data3", "read"},
		{"jack", "data4", "read"},
		{"katy", "data4", "write"},
		{"leyo", "data4", "read"},
		{"ham", "data4", "write"}})

	_, _ = e.RemovePolicies(rules)
	_, _ = e.RemovePolicies(rules)
	<-time.After(time.Second * 3)
	testEnforcerGetPolicy(t, e, [][]string{
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
		{"eve", "data3", "read"}})

	_, _ = e.RemoveFilteredPolicy(1, "data2")
	<-time.After(time.Second * 3)
	testEnforcerGetPolicy(t, e, [][]string{{"eve", "data3", "read"}})
}
