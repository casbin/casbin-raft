package casbinraft

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/casbin/casbin/v2"
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

func newNode(id uint64) *Node {
	os.RemoveAll(fmt.Sprintf("casbin-%d", id))
	os.RemoveAll(fmt.Sprintf("casbin-%d-snap", id))
	peers := make(map[uint64]string)
	peers[id] = fmt.Sprintf("http://127.0.0.1:%d", GetFreePort())
	enforcer, err := casbin.NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		panic(err)
	}
	node := NewNode(enforcer, id, peers)
	go node.Start()
	return node
}

func newCluster(num int) cluster {
	peers := make(map[uint64]string)

	for i := 1; i <= num; i++ {
		peers[uint64(i)] = fmt.Sprintf("http://127.0.0.1:%d", GetFreePort())
	}
	var c cluster
	for id := range peers {
		os.RemoveAll(fmt.Sprintf("casbin-%d", id))
		os.RemoveAll(fmt.Sprintf("casbin-%d-snap", id))
		enforcer, err := casbin.NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
		if err != nil {
			panic(err)
		}
		n := NewNode(enforcer, id, peers)
		go n.Start()
		c = append(c, n)
	}
	return c
}

func TestAddPolicy(t *testing.T) {
	node := newNode(1)
	<-time.After(time.Second)
	node.AddPolicy("p", "p", []string{"alice", "data2", "write"})
	node.AddPolicy("p", "p", []string{"eve", "data3", "read"})
	node.RemovePolicy("p", "p", []string{"alice", "data1", "read"})
	node.RemovePolicy("p", "p", []string{"bob", "data2", "write"})
	<-time.After(time.Second)
	testEnforce(t, node, "alice", "data2", "write", true)
	testEnforce(t, node, "eve", "data3", "read", true)
	testEnforce(t, node, "alice", "data1", "read", false)
	testEnforce(t, node, "bob", "data2", "write", false)
}

func TestAddPolicyCluster(t *testing.T) {
	c := newCluster(3)
	<-time.After(time.Second)
	c[0].AddPolicy("p", "p", []string{"alice", "data2", "write"})
	c[1].RemovePolicy("p", "p", []string{"alice", "data1", "read"})
	c[2].RemovePolicy("p", "p", []string{"bob", "data2", "write"})
	c[2].AddPolicy("p", "p", []string{"eve", "data3", "read"})
	<-time.After(time.Second)

	testClusterEnforce(t, c, "alice", "data2", "write", true)
	testClusterEnforce(t, c, "alice", "data1", "read", false)
	testClusterEnforce(t, c, "bob", "data2", "write", false)
	testClusterEnforce(t, c, "eve", "data3", "read", true)
}

func TestAddMember(t *testing.T) {
	peers := make(map[uint64]string)

	for i := 1; i <= 3; i++ {
		peers[uint64(i)] = fmt.Sprintf("http://127.0.0.1:%d", 10000+i)
	}
	var c cluster
	for id := range peers {
		os.RemoveAll(fmt.Sprintf("casbin-%d", id))
		os.RemoveAll(fmt.Sprintf("casbin-%d-snap", id))
		enforcer, err := casbin.NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
		if err != nil {
			panic(err)
		}
		n := NewNode(enforcer, id, peers)
		go n.Start()
		c = append(c, n)
	}

	os.RemoveAll(fmt.Sprintf("casbin-%d", 4))
	os.RemoveAll(fmt.Sprintf("casbin-%d-snap", 4))
	p := make(map[uint64]string)
	p[1] = "http://127.0.0.1:10001"
	p[2] = "http://127.0.0.1:10002"
	p[3] = "http://127.0.0.1:10003"
	p[4] = "http://127.0.0.1:10004"
	enforcer, err := casbin.NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatal(err)
	}

	node := NewNode(enforcer, 4, p)
	go node.Start()
	<-time.After(time.Second)
	err = c[0].AddMember(4, "http://127.0.0.1:10004")
	if err != nil {
		t.Fatal(err)
	}

	<-time.After(time.Second)
	node.AddPolicy("p", "p", []string{"alice", "data2", "write"})
	<-time.After(time.Second)
	testClusterEnforce(t, c, "alice", "data2", "write", true)
}

func TestSaveSnapshot(t *testing.T) {
	node := newNode(1)
	node.SetSnapshotCount(10)
	<-time.After(time.Second)
	for i := 0; i < 101; i++ {
		node.AddPolicy("p", "p", []string{fmt.Sprintf("user%d", i), fmt.Sprintf("data%d", i/10), "read"})
	}
	<-time.After(time.Second)
}

func TestRestartNode(t *testing.T) {
	node := newNode(1)
	<-time.After(time.Second)
	node.AddPolicy("p", "p", []string{"alice", "data2", "write"})
	<-time.After(time.Second)
	testEnforce(t, node, "alice", "data2", "write", true)
	node.Stop()
	<-time.After(time.Second)
	peers := make(map[uint64]string)
	peers[1] = fmt.Sprintf("http://127.0.0.1:%d", GetFreePort())
	enforcer, err := casbin.NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		panic(err)
	}
	noderestart := NewNode(enforcer, 1, peers)
	go noderestart.Restart()
	<-time.After(time.Second)
	testEnforce(t, noderestart, "alice", "data2", "write", true)
}
