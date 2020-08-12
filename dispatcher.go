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

// Dispatcher is a casbin enforcer backed by raft
type Dispatcher struct {
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

// NewDispatcher return a instance of dispatcher, the peers is a collection of
// id and url of all nodes in the cluster
func NewDispatcher(id uint64, peers map[uint64]string, join ...bool) *Dispatcher {
	isJoin := false
	if len(join) > 0 {
		// the join parameter takes only the first to ignore the rest
		isJoin = join[0]
	}
	store := raft.NewMemoryStorage()
	membership := NewCluster(peers)
	d := &Dispatcher{
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

	return d
}

// SetEnforcer set up the instance that need to be maintained.
// The parameter should be SyncedEnforced
func (d *Dispatcher) SetEnforcer(enforcer interface{}) error {
	value, ok := enforcer.(*casbin.Enforcer)
	if !ok {
		return errors.New("type of parameter should be *casbin.Enforcer")
	}
	d.engine = newEngine(value)
	return nil
}

// SetSnapshotCount set the number of logs that trigger a snapshot save.
// This function must be called before call node.Start().
func (d *Dispatcher) SetSnapshotCount(count uint64) {
	d.snapCount = count
}

// SetSnapDirName set the directory name that store sanpshot file.
// This function must be called before call node.Start().
func (d *Dispatcher) SetSnapDirName(name string) {
	d.snapdir = name
}

// SetWalDirName set the directory name that store write ahead log file.
// This function must be called before call node.Start().
func (d *Dispatcher) SetWalDirName(name string) {
	d.waldir = name
}

// SetHeartbeatTick set the number of Node.Tick invocations that must pass between
// heartbeats. That is, a leader sends heartbeat messages to maintain its
// leadership every HeartbeatTick ticks.
// This function must be called before call node.Start().
func (d *Dispatcher) SetHeartbeatTick(num int) {
	d.cfg.HeartbeatTick = num
}

// SetElectionTick set the number of Node.Tick invocations that must pass between
// elections. ElectionTick must be greater than HeartbeatTick.
// We suggest ElectionTick = 10 * HeartbeatTick to avoid
// unnecessary leader switching.
// This function must be called before call node.Start().
func (d *Dispatcher) SetElectionTick(num int) {
	d.cfg.ElectionTick = num
}

// EnableTLSTransport make transport protected by TLS.
// This function must be called before call node.Start().
func (d *Dispatcher) EnableTLSTransport(keyFile string, certFile string, caFile string) {
	d.keyFile = keyFile
	d.certFile = certFile
	d.caFile = caFile
	d.enableTLS = true
}

// Start performs any initialization of the Server necessary for it to
// begin serving requests.
func (d *Dispatcher) Start() error {
	if err := d.init(); err != nil {
		return err
	}

	if err := d.initTransport(); err != nil {
		return err
	}

	go d.serveRaft()
	return d.run()
}

// Restart init raft from wal and snapshot that already existing,
// then begin serving requests
func (d *Dispatcher) Restart() error {
	d.snapshotter = snap.New(d.snapdir)
	snapshot, err := d.snapshotter.Load()
	if err != nil && err != snap.ErrNoSnapshot {
		return errors.Wrap(err, "Failed loading snapshot")
	}

	walsnap := walpb.Snapshot{}
	if snapshot != nil {
		walsnap.Index, walsnap.Term = snapshot.Metadata.Index, snapshot.Metadata.Term

		if err := d.store.ApplySnapshot(*snapshot); err != nil {
			return errors.Wrap(err, "Save snapshot to store fail")
		}

		if err := d.engine.recoverFromSnapshot(snapshot.Data); err != nil {
			return errors.Wrap(err, "Recover from snapshot fail")
		}
	}

	d.wal, err = wal.Open(d.waldir, walsnap)
	if err != nil {
		return errors.Wrap(err, "Failed loading wal")
	}

	_, st, ents, err := d.wal.ReadAll()
	if err != nil {
		return errors.Wrap(err, "Failed reading WAL")
	}

	if err := d.store.SetHardState(st); err != nil {
		return errors.Wrap(err, "Failed saving hard state")
	}

	if err := d.store.Append(ents); err != nil {
		return errors.Wrap(err, "Failed saving log")
	}
	d.raft = raft.RestartNode(d.cfg)

	if err := d.initTransport(); err != nil {
		return errors.Wrap(err, "Failed init transport")
	}

	go d.serveRaft()
	return d.run()
}

// Stop close the raft node and http server
func (d *Dispatcher) Stop() {
	close(d.done)
	d.httpServer.Close()
	d.raft.Stop()
	d.transport.Stop()
	d.wal.Close()
}

// init initialize the resources required by the raft node
func (d *Dispatcher) init() error {
	if err := os.Mkdir(d.snapdir, 0750); err != nil {
		return errors.Wrap(err, "Failed creating snapshot dir")
	}

	d.snapshotter = snap.New(d.snapdir)

	err := os.Mkdir(d.waldir, 0750)
	if err != nil {
		return errors.Wrap(err, "Failed creating WAL dir")
	}

	d.wal, err = wal.Create(d.waldir, nil)
	if err != nil {
		return errors.Wrap(err, "Failed creating WAL")
	}

	var p []raft.Peer
	// If the node needs to join the cluster, the peers passed in StartNode should be empty.
	if !d.isJoin {
		for k, v := range d.membership.members {
			p = append(p, raft.Peer{ID: k, Context: []byte(v)})
		}
	}

	d.raft = raft.StartNode(d.cfg, p)

	snap, err := d.store.Snapshot()
	if err != nil {
		return errors.Wrap(err, "Failed getting snapshot from memorystore")
	}
	d.confState = &snap.Metadata.ConfState
	d.snapshotIndex = snap.Metadata.Index
	d.appliedIndex = snap.Metadata.Index
	return nil
}

// serveRaft start the server for internal transmission of raft
func (d *Dispatcher) serveRaft() {
	u, err := url.Parse(d.membership.GetURL(d.id))
	if err != nil {
		log.Fatalf("Failed parsing URL (%v)", err)
	}

	var ln net.Listener
	if d.enableTLS {
		cert, err := tls.LoadX509KeyPair(d.certFile, d.keyFile)
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
	d.httpServer = &http.Server{Handler: d.transport.Handler()}
	err = d.httpServer.Serve(ln)
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("Http server close (%v)", err)
	}
}

func (d *Dispatcher) run() error {
	for {
		select {
		case <-d.ticker.C:
			d.raft.Tick()
		case rd := <-d.raft.Ready():
			if err := d.wal.Save(rd.HardState, rd.Entries); err != nil {
				// runtime errors are only printed to the log, as are the following
				log.Printf("Failed saving wal (%v)", err)
			}
			d.saveToStorage(rd.HardState, rd.Entries, rd.Snapshot)
			d.transport.Send(rd.Messages)
			if !raft.IsEmptySnap(rd.Snapshot) {
				err := d.processSnapshot(rd.Snapshot)
				if err != nil {
					// runtime errors are only printed to the log, as are the following
					log.Printf("Failed saving snapshot (%v)", err)
				}
			}
			for _, entry := range rd.CommittedEntries {
				d.process(entry)

				if d.appliedIndex-d.snapshotIndex > d.snapCount {
					d.triggerSnapshot()
				}
			}
			d.raft.Advance()
		case err := <-d.transport.ErrorC:
			if err != nil {
				log.Printf("Wrong raft transport (%s)", err)
			}
		case <-d.done:
			return nil
		}
	}
}

func (d *Dispatcher) initTransport() error {
	d.transport = &rafthttp.Transport{
		ID:          types.ID(d.id),
		ClusterID:   1,
		Raft:        d,
		ServerStats: stats.NewServerStats("", ""),
		LeaderStats: stats.NewLeaderStats(strconv.Itoa(int(d.id))),
		ErrorC:      make(chan error),
	}

	if d.enableTLS {
		d.transport.TLSInfo = transport.TLSInfo{
			KeyFile:        d.keyFile,
			CertFile:       d.certFile,
			TrustedCAFile:  d.caFile,
			ClientCertAuth: true,
		}
	}
	if err := d.transport.Start(); err != nil {
		return err
	}

	for key, value := range d.membership.members {
		if key == d.id {
			continue
		}
		d.transport.AddPeer(types.ID(key), []string{value})
	}
	return nil
}

func (d *Dispatcher) triggerSnapshot() {
	data, err := d.engine.getSnapshot()
	if err != nil {
		log.Printf("Failed getting snapshot data (%v)", err)
	}

	snap, err := d.store.CreateSnapshot(d.appliedIndex, d.confState, data)
	if err != nil {
		log.Printf("Can't create snapshot from memory store (%v)", err)
	}

	if err := d.snapshotter.SaveSnap(snap); err != nil {
		log.Printf("Failed saving snapshot (%v)", err)
	}

	d.snapshotIndex = d.appliedIndex
}

func (d *Dispatcher) saveToStorage(hardState raftpb.HardState, entries []raftpb.Entry, snapshot raftpb.Snapshot) {
	if err := d.store.Append(entries); err != nil {
		log.Printf("Failed storing entries (%v)", err)
	}

	if !raft.IsEmptyHardState(hardState) {
		if err := d.store.SetHardState(hardState); err != nil {
			log.Printf("Failed storing hardstate (%v)", err)
		}
	}

	if !raft.IsEmptySnap(snapshot) {
		if err := d.store.ApplySnapshot(snapshot); err != nil {
			log.Printf("Failed storing snapshot (%v)", err)
		}
	}
}

// processSnapshot will
func (d *Dispatcher) processSnapshot(snap raftpb.Snapshot) error {
	walSnap := walpb.Snapshot{
		Index: snap.Metadata.Index,
		Term:  snap.Metadata.Term,
	}

	if err := d.wal.SaveSnapshot(walSnap); err != nil {
		return err
	}

	if err := d.snapshotter.SaveSnap(snap); err != nil {
		return err
	}

	if err := d.wal.ReleaseLockTo(snap.Metadata.Index); err != nil {
		return err
	}

	if err := d.store.ApplySnapshot(snap); err != nil {
		return err
	}

	if err := d.engine.recoverFromSnapshot(snap.Data); err != nil {
		return err
	}

	d.confState = &snap.Metadata.ConfState
	d.snapshotIndex = snap.Metadata.Index
	d.appliedIndex = snap.Metadata.Index
	return nil
}

func (d *Dispatcher) process(entry raftpb.Entry) {
	// set the leader state, determine if need to apply in adapter
	if d.raft.Status().Lead == d.id {
		atomic.CompareAndSwapUint32(&d.engine.isLeader, 0, 1)
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
			d.engine.Apply(command)
			d.appliedIndex = entry.Index
		}
	case raftpb.EntryConfChange:
		var cc raftpb.ConfChange
		if err := cc.Unmarshal(entry.Data); err != nil {
			log.Printf("Failed unmarshal confchange data (%v)", err)
		}
		d.confState = d.raft.ApplyConfChange(cc)
		d.membership.ApplyConfigChange(cc)
		switch cc.Type {
		case raftpb.ConfChangeAddNode, raftpb.ConfChangeAddLearnerNode:
			if len(cc.Context) > 0 {
				d.transport.AddPeer(types.ID(cc.NodeID), []string{string(cc.Context)})
			}

		case raftpb.ConfChangeRemoveNode:
			if cc.NodeID == uint64(d.id) {
				log.Println("have been removed from the cluster! Shutting down.")
				d.Stop()
				return
			}
			d.transport.RemovePeer(types.ID(cc.NodeID))
		}
	}

}

// These functions are to satisfy the raft interface in transport.
func (d *Dispatcher) Process(ctx context.Context, m raftpb.Message) error {
	return d.raft.Step(ctx, m)
}

func (d *Dispatcher) IsIDRemoved(id uint64) bool {
	return !d.membership.HasMember(id)
}

func (d *Dispatcher) ReportUnreachable(id uint64) {
	d.raft.ReportUnreachable(id)
}

func (d *Dispatcher) ReportSnapshot(id uint64, status raft.SnapshotStatus) {
	d.raft.ReportSnapshot(id, status)
}

// AddMember add a new node to Cluster.
func (d *Dispatcher) AddMember(id uint64, addr string) error {
	if d.membership.HasMember(id) {
		return fmt.Errorf("the node %d has existed in cluster", id)
	}

	cc := raftpb.ConfChange{
		ID:      1,
		Type:    raftpb.ConfChangeAddNode,
		NodeID:  id,
		Context: []byte(addr),
	}

	return d.raft.ProposeConfChange(d.ctx, cc)
}

// RemoveMember remove a exist Node from Cluster.
func (d *Dispatcher) RemoveMember(id uint64) error {
	if !d.membership.HasMember(id) {
		return fmt.Errorf("the node %d don't exist in cluster", id)
	}

	cc := raftpb.ConfChange{
		Type:   raftpb.ConfChangeRemoveNode,
		NodeID: id,
	}

	return d.raft.ProposeConfChange(d.ctx, cc)
}

// AddPolicies add policies to casbin enforcer
// This function will be call by casbin. Please call casbin ManagementAPI for use.
func (d *Dispatcher) AddPolicies(sec string, ptype string, rules [][]string) error {
	if d.engine.enforcer.GetModel().HasPolicies(sec, ptype, rules) {
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
	return d.raft.Propose(d.ctx, buf)
}

// RemovePolicies remove policies from casbin enforcer
// This function will be call by casbin. Please call casbin ManagementAPI for use.
func (d *Dispatcher) RemovePolicies(sec string, ptype string, rules [][]string) error {
	if !d.engine.enforcer.GetModel().HasPolicies(sec, ptype, rules) {
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
	return d.raft.Propose(d.ctx, buf)
}

// RemoveFilteredPolicy  removes a role inheritance rule from the current named policy, field filters can be specified.
// This function will be call by casbin. Please call casbin ManagementAPI for use.
func (d *Dispatcher) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
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
	return d.raft.Propose(d.ctx, buf)
}

// ClearPolicy clears all policy.
// This function will be call by casbin. Please call casbin ManagementAPI for use.
func (d *Dispatcher) ClearPolicy() error {
	command := Command{
		Op: clearCommand,
	}

	buf, err := json.Marshal(command)
	if err != nil {
		return err
	}
	return d.raft.Propose(d.ctx, buf)
}
