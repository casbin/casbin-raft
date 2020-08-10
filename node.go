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
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/casbin/casbin/v3"
	"github.com/coreos/etcd/etcdserver/stats"
	"github.com/coreos/etcd/pkg/transport"
	"github.com/coreos/etcd/pkg/types"
	"github.com/coreos/etcd/raft"
	"github.com/coreos/etcd/raft/raftpb"
	"github.com/coreos/etcd/rafthttp"
	"github.com/coreos/etcd/snap"
	"github.com/coreos/etcd/wal"
	"github.com/coreos/etcd/wal/walpb"
	"github.com/pkg/errors"
)

const (
	defaultSnapshotCount uint64 = 10000
	defaultHeartBeatTick int    = 1
	defaultElectionTick  int    = 10
)

// Node is a casbin enforcer backed by raft
type Node struct {
	id         uint64
	isJoin     bool
	ctx        context.Context
	engine     *Engine
	store      *raft.MemoryStorage
	cfg        *raft.Config
	raft       raft.Node
	membership *Cluster
	ticker     *time.Ticker
	done       chan struct{}

	snapdir     string
	snapshotter *snap.Snapshotter

	confState     *raftpb.ConfState
	snapshotIndex uint64
	appliedIndex  uint64
	snapCount     uint64

	transport  *rafthttp.Transport
	httpServer *http.Server
	waldir     string
	wal        *wal.WAL

	enableTLS bool
	keyFile   string
	certFile  string
	caFile    string
}

// NewNode return a instance of node, the peers is a collection of
// id and url of all nodes in the cluster
func NewNode(id uint64, peers map[uint64]string, join ...bool) *Node {
	isJoin := false
	if len(join) > 0 {
		// the join parameter takes only the first to ignore the rest
		isJoin = join[0]
	}
	store := raft.NewMemoryStorage()
	membership := NewCluster(peers)
	n := &Node{
		id:     id,
		ctx:    context.TODO(),
		isJoin: isJoin,
		store:  store,
		cfg: &raft.Config{
			ID:              id,
			ElectionTick:    defaultElectionTick,
			HeartbeatTick:   defaultHeartBeatTick,
			Storage:         store,
			MaxSizePerMsg:   math.MaxUint16,
			MaxInflightMsgs: 256,
		},
		membership: membership,
		ticker:     time.NewTicker(100 * time.Millisecond),
		done:       make(chan struct{}),
		snapdir:    fmt.Sprintf("casbin-%d-snap", id),
		snapCount:  defaultSnapshotCount,
		waldir:     fmt.Sprintf("casbin-%d", id),
	}

	return n
}

// SetEnforcer set up the instance that need to be maintained.
// The parameter should be SyncedEnforced
func (n *Node) SetEnforcer(enforcer interface{}) error {
	value, ok := enforcer.(*casbin.Enforcer)
	if !ok {
		return errors.New("type of parameter should be *casbin.Enforcer")
	}
	n.engine = newEngine(value)
	return nil
}

// SetSnapshotCount set the number of logs that trigger a snapshot save.
// This function must be called before call node.Start().
func (n *Node) SetSnapshotCount(count uint64) {
	n.snapCount = count
}

// SetSnapDirName set the directory name that store sanpshot file.
// This function must be called before call node.Start().
func (n *Node) SetSnapDirName(name string) {
	n.snapdir = name
}

// SetWalDirName set the directory name that store write ahead log file.
// This function must be called before call node.Start().
func (n *Node) SetWalDirName(name string) {
	n.waldir = name
}

// SetHeartbeatTick set the number of Node.Tick invocations that must pass between
// heartbeats. That is, a leader sends heartbeat messages to maintain its
// leadership every HeartbeatTick ticks.
// This function must be called before call node.Start().
func (n *Node) SetHeartbeatTick(num int) {
	n.cfg.HeartbeatTick = num
}

// SetElectionTick set the number of Node.Tick invocations that must pass between
// elections. ElectionTick must be greater than HeartbeatTick.
// We suggest ElectionTick = 10 * HeartbeatTick to avoid
// unnecessary leader switching.
// This function must be called before call node.Start().
func (n *Node) SetElectionTick(num int) {
	n.cfg.ElectionTick = num
}

// EnableTLSTransport make transport protected by TLS.
// This function must be called before call node.Start().
func (n *Node) EnableTLSTransport(keyFile string, certFile string, caFile string) {
	n.keyFile = keyFile
	n.certFile = certFile
	n.caFile = caFile
	n.enableTLS = true
}

// Start performs any initialization of the Server necessary for it to
// begin serving requests.
func (n *Node) Start() error {
	if err := n.init(); err != nil {
		return err
	}

	if err := n.initTransport(); err != nil {
		return err
	}

	go n.serveRaft()
	return n.run()
}

// Restart init raft from wal and snapshot that already existing,
// then begin serving requests
func (n *Node) Restart() error {
	n.snapshotter = snap.New(n.snapdir)
	snapshot, err := n.snapshotter.Load()
	if err != nil && err != snap.ErrNoSnapshot {
		return errors.Wrap(err, "Failed loading snapshot")
	}

	walsnap := walpb.Snapshot{}
	if snapshot != nil {
		walsnap.Index, walsnap.Term = snapshot.Metadata.Index, snapshot.Metadata.Term

		if err := n.store.ApplySnapshot(*snapshot); err != nil {
			return errors.Wrap(err, "Save snapshot to store fail")
		}

		if err := n.engine.recoverFromSnapshot(snapshot.Data); err != nil {
			return errors.Wrap(err, "Recover from snapshot fail")
		}
	}

	n.wal, err = wal.Open(n.waldir, walsnap)
	if err != nil {
		return errors.Wrap(err, "Failed loading wal")
	}

	_, st, ents, err := n.wal.ReadAll()
	if err != nil {
		return errors.Wrap(err, "Failed reading WAL")
	}

	if err := n.store.SetHardState(st); err != nil {
		return errors.Wrap(err, "Failed saving hard state")
	}

	if err := n.store.Append(ents); err != nil {
		return errors.Wrap(err, "Failed saving log")
	}
	n.raft = raft.RestartNode(n.cfg)

	if err := n.initTransport(); err != nil {
		return errors.Wrap(err, "Failed init transport")
	}

	go n.serveRaft()
	return n.run()
}

// Stop close the raft node and http server
func (n *Node) Stop() {
	close(n.done)
	n.httpServer.Close()
	n.raft.Stop()
	n.transport.Stop()
	n.wal.Close()
}

// init initialize the resources required by the raft node
func (n *Node) init() error {
	if err := os.Mkdir(n.snapdir, 0750); err != nil {
		return errors.Wrap(err, "Failed creating snapshot dir")
	}

	n.snapshotter = snap.New(n.snapdir)

	err := os.Mkdir(n.waldir, 0750)
	if err != nil {
		return errors.Wrap(err, "Failed creating WAL dir")
	}

	n.wal, err = wal.Create(n.waldir, nil)
	if err != nil {
		return errors.Wrap(err, "Failed creating WAL")
	}

	var p []raft.Peer
	// If the node needs to join the cluster, the peers passed in StartNode should be empty.
	if !n.isJoin {
		for k, v := range n.membership.members {
			p = append(p, raft.Peer{ID: k, Context: []byte(v)})
		}
	}

	n.raft = raft.StartNode(n.cfg, p)

	snap, err := n.store.Snapshot()
	if err != nil {
		return errors.Wrap(err, "Failed getting snapshot from memorystore")
	}
	n.confState = &snap.Metadata.ConfState
	n.snapshotIndex = snap.Metadata.Index
	n.appliedIndex = snap.Metadata.Index
	return nil
}

// serveRaft start the server for internal transmission of raft
func (n *Node) serveRaft() {
	u, err := url.Parse(n.membership.GetURL(n.id))
	if err != nil {
		log.Fatalf("Failed parsing URL (%v)", err)
	}

	var ln net.Listener
	if n.enableTLS {
		cert, err := tls.LoadX509KeyPair(n.certFile, n.keyFile)
		if err != nil {
			log.Fatalf("Failed loading cert (%v)", err)
		}
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
		ln, err = tls.Listen("tcp", u.Host, tlsConfig)
		if err != nil {
			log.Fatalf("Failed listening (%v)", err)
		}
	} else {
		ln, err = net.Listen("tcp", u.Host)
		if err != nil {
			log.Fatalf("Failed listening (%v)", err)
		}
	}
	n.httpServer = &http.Server{Handler: n.transport.Handler()}
	err = n.httpServer.Serve(ln)
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("Http server close (%v)", err)
	}
}

func (n *Node) run() error {
	for {
		select {
		case <-n.ticker.C:
			n.raft.Tick()
		case rd := <-n.raft.Ready():
			if err := n.wal.Save(rd.HardState, rd.Entries); err != nil {
				// runtime errors are only printed to the log, as are the following
				log.Printf("Failed saving wal (%v)", err)
			}
			n.saveToStorage(rd.HardState, rd.Entries, rd.Snapshot)
			n.transport.Send(rd.Messages)
			if !raft.IsEmptySnap(rd.Snapshot) {
				err := n.processSnapshot(rd.Snapshot)
				if err != nil {
					// runtime errors are only printed to the log, as are the following
					log.Printf("Failed saving snapshot (%v)", err)
				}
			}
			for _, entry := range rd.CommittedEntries {
				n.process(entry)

				if n.appliedIndex-n.snapshotIndex > n.snapCount {
					n.triggerSnapshot()
				}
			}
			n.raft.Advance()
		case err := <-n.transport.ErrorC:
			if err != nil {
				log.Printf("Wrong raft transport (%s)", err)
			}
		case <-n.done:
			return nil
		}
	}
}

func (n *Node) initTransport() error {
	n.transport = &rafthttp.Transport{
		ID:          types.ID(n.id),
		ClusterID:   1,
		Raft:        n,
		ServerStats: stats.NewServerStats("", ""),
		LeaderStats: stats.NewLeaderStats(strconv.Itoa(int(n.id))),
		ErrorC:      make(chan error),
	}

	if n.enableTLS {
		n.transport.TLSInfo = transport.TLSInfo{
			KeyFile:        n.keyFile,
			CertFile:       n.certFile,
			TrustedCAFile:  n.caFile,
			ClientCertAuth: true,
		}
	}
	if err := n.transport.Start(); err != nil {
		return err
	}

	for key, value := range n.membership.members {
		if key == n.id {
			continue
		}
		n.transport.AddPeer(types.ID(key), []string{value})
	}
	return nil
}

func (n *Node) triggerSnapshot() {
	data, err := n.engine.getSnapshot()
	if err != nil {
		log.Printf("Failed getting snapshot data (%v)", err)
	}

	snap, err := n.store.CreateSnapshot(n.appliedIndex, n.confState, data)
	if err != nil {
		log.Printf("Can't create snapshot from memory store (%v)", err)
	}

	if err := n.snapshotter.SaveSnap(snap); err != nil {
		log.Printf("Failed saving snapshot (%v)", err)
	}

	n.snapshotIndex = n.appliedIndex
}

func (n *Node) saveToStorage(hardState raftpb.HardState, entries []raftpb.Entry, snapshot raftpb.Snapshot) {
	if err := n.store.Append(entries); err != nil {
		log.Printf("Failed storing entries (%v)", err)
	}

	if !raft.IsEmptyHardState(hardState) {
		if err := n.store.SetHardState(hardState); err != nil {
			log.Printf("Failed storing hardstate (%v)", err)
		}
	}

	if !raft.IsEmptySnap(snapshot) {
		if err := n.store.ApplySnapshot(snapshot); err != nil {
			log.Printf("Failed storing snapshot (%v)", err)
		}
	}
}

// processSnapshot will
func (n *Node) processSnapshot(snap raftpb.Snapshot) error {
	walSnap := walpb.Snapshot{
		Index: snap.Metadata.Index,
		Term:  snap.Metadata.Term,
	}

	if err := n.wal.SaveSnapshot(walSnap); err != nil {
		return err
	}

	if err := n.snapshotter.SaveSnap(snap); err != nil {
		return err
	}

	if err := n.wal.ReleaseLockTo(snap.Metadata.Index); err != nil {
		return err
	}

	if err := n.store.ApplySnapshot(snap); err != nil {
		return err
	}

	if err := n.engine.recoverFromSnapshot(snap.Data); err != nil {
		return err
	}

	n.confState = &snap.Metadata.ConfState
	n.snapshotIndex = snap.Metadata.Index
	n.appliedIndex = snap.Metadata.Index
	return nil
}

func (n *Node) process(entry raftpb.Entry) {
	// set the leader state, determine if need to apply in adapter
	if n.raft.Status().Lead == n.id {
		atomic.CompareAndSwapUint32(&n.engine.isLeader, 0, 1)
	}
	switch entry.Type {
	case raftpb.EntryNormal:
		if entry.Data != nil {
			var command Command
			err := json.Unmarshal(entry.Data, &command)
			if err != nil {
				// need a way to notify the caller, panic temporarily
				panic(err)
			}
			n.engine.Apply(command)
			n.appliedIndex = entry.Index
		}
	case raftpb.EntryConfChange:
		var cc raftpb.ConfChange
		if err := cc.Unmarshal(entry.Data); err != nil {
			log.Printf("Failed unmarshal confchange data (%v)", err)
		}
		n.confState = n.raft.ApplyConfChange(cc)
		n.membership.ApplyConfigChange(cc)
		switch cc.Type {
		case raftpb.ConfChangeAddNode, raftpb.ConfChangeAddLearnerNode:
			if len(cc.Context) > 0 {
				n.transport.AddPeer(types.ID(cc.NodeID), []string{string(cc.Context)})
			}

		case raftpb.ConfChangeRemoveNode:
			if cc.NodeID == uint64(n.id) {
				log.Println("have been removed from the cluster! Shutting down.")
				n.Stop()
				return
			}
			n.transport.RemovePeer(types.ID(cc.NodeID))
		}
	}

}

// These functions are to satisfy the raft interface in transport.
func (n *Node) Process(ctx context.Context, m raftpb.Message) error {
	return n.raft.Step(ctx, m)
}

func (n *Node) IsIDRemoved(id uint64) bool {
	return !n.membership.HasMember(id)
}

func (n *Node) ReportUnreachable(id uint64) {
	n.raft.ReportUnreachable(id)
}

func (n *Node) ReportSnapshot(id uint64, status raft.SnapshotStatus) {
	n.raft.ReportSnapshot(id, status)
}

// AddMember add a new node to Cluster.
func (n *Node) AddMember(id uint64, addr string) error {
	if n.membership.HasMember(id) {
		return fmt.Errorf("the node %d has existed in cluster", id)
	}

	cc := raftpb.ConfChange{
		ID:      1,
		Type:    raftpb.ConfChangeAddNode,
		NodeID:  id,
		Context: []byte(addr),
	}

	return n.raft.ProposeConfChange(n.ctx, cc)
}

// RemoveMember remove a exist Node from Cluster.
func (n *Node) RemoveMember(id uint64) error {
	if !n.membership.HasMember(id) {
		return fmt.Errorf("the node %d don't exist in cluster", id)
	}

	cc := raftpb.ConfChange{
		Type:   raftpb.ConfChangeRemoveNode,
		NodeID: id,
	}

	return n.raft.ProposeConfChange(n.ctx, cc)
}

// AddPolicies add policies to casbin enforcer
// This function will be call by casbin. Please call casbin ManagementAPI for use.
func (n *Node) AddPolicies(sec string, ptype string, rules [][]string) error {
	if n.engine.enforcer.GetModel().HasPolicies(sec, ptype, rules) {
		return errors.New("policy already exists")
	}

	command := Command{
		Op:    addCommand,
		Sec:   sec,
		Ptype: ptype,
		Rules: rules,
	}

	buf, err := json.Marshal(command)
	if err != nil {
		return err
	}
	return n.raft.Propose(n.ctx, buf)
}

// RemovePolicies remove policies from casbin enforcer
// This function will be call by casbin. Please call casbin ManagementAPI for use.
func (n *Node) RemovePolicies(sec string, ptype string, rules [][]string) error {
	if !n.engine.enforcer.GetModel().HasPolicies(sec, ptype, rules) {
		return errors.New("policy does not exist")
	}

	command := Command{
		Op:    removeCommand,
		Sec:   sec,
		Ptype: ptype,
		Rules: rules,
	}

	buf, err := json.Marshal(command)
	if err != nil {
		return err
	}
	return n.raft.Propose(n.ctx, buf)
}

// RemoveFilteredPolicy  removes a role inheritance rule from the current named policy, field filters can be specified.
// This function will be call by casbin. Please call casbin ManagementAPI for use.
func (n *Node) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	command := Command{
		Op:          removeFilteredCommand,
		Sec:         sec,
		Ptype:       ptype,
		FiledIndex:  fieldIndex,
		FiledValues: fieldValues,
	}

	buf, err := json.Marshal(command)
	if err != nil {
		return err
	}
	return n.raft.Propose(n.ctx, buf)
}

// ClearPolicy clears all policy.
// This function will be call by casbin. Please call casbin ManagementAPI for use.
func (n *Node) ClearPolicy() error {
	command := Command{
		Op: clearCommand,
	}

	buf, err := json.Marshal(command)
	if err != nil {
		return err
	}
	return n.raft.Propose(n.ctx, buf)
}
