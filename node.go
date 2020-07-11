package casbinraft

import (
	"context"
	"encoding/json"
	"errors"
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

	"github.com/casbin/casbin/v2"
	"github.com/coreos/etcd/etcdserver/stats"
	"github.com/coreos/etcd/pkg/types"
	"github.com/coreos/etcd/raft"
	"github.com/coreos/etcd/raft/raftpb"
	"github.com/coreos/etcd/rafthttp"
	"github.com/coreos/etcd/snap"
	"github.com/coreos/etcd/wal"
	"github.com/coreos/etcd/wal/walpb"
)

const defaultSnapshotCount uint64 = 10000

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
	ticker     <-chan time.Time
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
}

// NewNode return a instance of node, the peers is a collection of
// id and url of all nodes in the cluster
func NewNode(enforcer *casbin.SyncedEnforcer, id uint64, peers map[uint64]string, join ...bool) *Node {
	isJoin := false
	if len(join) > 0 {
		isJoin = join[0]
	}
	store := raft.NewMemoryStorage()
	membership := NewCluster(peers)
	engine := newEngine(enforcer)
	n := &Node{
		id:     id,
		ctx:    context.TODO(),
		isJoin: isJoin,
		store:  store,
		cfg: &raft.Config{
			ID:              id,
			ElectionTick:    10,
			HeartbeatTick:   1,
			Storage:         store,
			MaxSizePerMsg:   math.MaxUint16,
			MaxInflightMsgs: 256,
		},
		engine:     engine,
		membership: membership,
		ticker:     time.Tick(100 * time.Millisecond),
		done:       make(chan struct{}),
		snapdir:    fmt.Sprintf("casbin-%d-snap", id),
		snapCount:  defaultSnapshotCount,
		waldir:     fmt.Sprintf("casbin-%d", id),
	}

	return n
}

// SetSnapshotCount set the number of logs that trigger a snapshot save
func (n *Node) SetSnapshotCount(count uint64) {
	n.snapCount = count
}

// SetSnapDirName set the directory name that store sanpshot file
func (n *Node) SetSnapDirName(name string) {
	n.snapdir = name
}

// SetWalDirName set the directory name that store write ahead log file
func (n *Node) SetWalDirName(name string) {
	n.waldir = name
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
		return fmt.Errorf("casbin: error loading snapshot (%v)", err)
	}

	walsnap := walpb.Snapshot{}
	if snapshot != nil {
		walsnap.Index, walsnap.Term = snapshot.Metadata.Index, snapshot.Metadata.Term
		n.store.ApplySnapshot(*snapshot)
		if err := n.engine.recoverFromSnapshot(snapshot.Data); err != nil {
			return fmt.Errorf("casbin: recover from snapshot fail (%s)", err)
		}
	}

	n.wal, err = wal.Open(n.waldir, walsnap)
	if err != nil {
		return fmt.Errorf("casbin: error loading wal (%v)", err)
	}

	_, st, ents, err := n.wal.ReadAll()
	if err != nil {
		return fmt.Errorf("casbin: failed to read WAL (%v)", err)
	}

	if err := n.store.SetHardState(st); err != nil {
		return fmt.Errorf("casbin: failed to save hard state (%v)", err)
	}

	n.store.Append(ents)
	n.raft = raft.RestartNode(n.cfg)

	if err := n.initTransport(); err != nil {
		return fmt.Errorf("casbin: failed to init transport (%v)", err)
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
		return fmt.Errorf("casbin: failed to create snapshot dir (%v)", err)
	}

	n.snapshotter = snap.New(n.snapdir)

	err := os.Mkdir(n.waldir, 0750)
	if err != nil {
		return fmt.Errorf("casbin: failed to create WAL dir (%v)", err)
	}

	n.wal, err = wal.Create(n.waldir, nil)
	if err != nil {
		return fmt.Errorf("casbin: failed to create WAL (%v)", err)
	}

	var p []raft.Peer
	if !n.isJoin {
		for id, url := range n.membership.members {
			p = append(p, raft.Peer{ID: id, Context: []byte(url)})
		}
	}

	n.raft = raft.StartNode(n.cfg, p)

	snap, err := n.store.Snapshot()
	if err != nil {
		return fmt.Errorf("casbin: failed to get snapshot from memorystore (%v)", err)
	}
	n.confState = &snap.Metadata.ConfState
	n.snapshotIndex = snap.Metadata.Index
	n.appliedIndex = snap.Metadata.Index
	return nil
}

// serveRaft start the server for internal transmission of raft
func (n *Node) serveRaft() {
	url, err := url.Parse(n.membership.GetURL(n.id))
	if err != nil {
		log.Fatalf("casbin: Failed parsing URL (%v)", err)
	}
	ln, err := net.Listen("tcp", url.Host)
	if err != nil {
		log.Fatalf("casbin: Failed listen (%v)", err)
	}
	n.httpServer = &http.Server{Handler: n.transport.Handler()}
	err = n.httpServer.Serve(ln)
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("casbin: http server close (%v)", err)
	}
}

func (n *Node) run() error {
	for {
		select {
		case <-n.ticker:
			n.raft.Tick()
		case rd := <-n.raft.Ready():
			n.wal.Save(rd.HardState, rd.Entries)
			n.saveToStorage(rd.HardState, rd.Entries, rd.Snapshot)
			for _, m := range rd.Messages {
				if !m.Reject {
					continue
				}
				log.Printf("Message %d send to %d, reject %v", m.From, m.To, m.RejectHint)
			}
			n.transport.Send(rd.Messages)
			if !raft.IsEmptySnap(rd.Snapshot) {
				err := n.processSnapshot(rd.Snapshot)
				if err != nil {
					log.Printf("casbin: failed save snapshot (%v)", err)
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
				log.Printf("casbin: wrong raft transport (%s)", err)
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
		log.Printf("casbin: fail get snapshot data (%v)", err)
	}

	snap, err := n.store.CreateSnapshot(n.appliedIndex, n.confState, data)
	if err != nil {
		log.Printf("casbin: can't create snapshot from memory store (%v)", err)
	}

	if err := n.snapshotter.SaveSnap(snap); err != nil {
		log.Printf("casbin: fail save snapshot (%v)", err)
	}

	n.snapshotIndex = n.appliedIndex
}

func (n *Node) saveToStorage(hardState raftpb.HardState, entries []raftpb.Entry, snapshot raftpb.Snapshot) {
	n.store.Append(entries)

	if !raft.IsEmptyHardState(hardState) {
		n.store.SetHardState(hardState)
	}

	if !raft.IsEmptySnap(snapshot) {
		n.store.ApplySnapshot(snapshot)
	}
}

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
	// log.Printf("Node %v: processing entry: %v\n", n.id, entry)
	if n.raft.Status().Lead == n.id {
		atomic.CompareAndSwapUint32(&n.engine.isLeader, 0, 1)
	}
	switch entry.Type {
	case raftpb.EntryNormal:
		if entry.Data != nil {
			var command Command
			err := json.Unmarshal(entry.Data, &command)
			if err != nil {
				panic(err)
			}
			n.engine.Apply(command)
			n.appliedIndex = entry.Index
		}
	case raftpb.EntryConfChange:
		var cc raftpb.ConfChange
		cc.Unmarshal(entry.Data)
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

func (n *Node) IsIDRemoved(id uint64) bool { return false }

func (n *Node) ReportUnreachable(id uint64) {
	n.raft.ReportUnreachable(id)
}

func (n *Node) ReportSnapshot(id uint64, status raft.SnapshotStatus) {
	n.raft.ReportSnapshot(id, status)
}

// AddMember add a new node to Cluster.
func (n *Node) AddMember(id uint64, url string) error {
	if n.membership.HasMember(id) {
		return fmt.Errorf("the node %d has existed in cluster", id)
	}

	cc := raftpb.ConfChange{
		ID:      1,
		Type:    raftpb.ConfChangeAddLearnerNode,
		NodeID:  id,
		Context: []byte(url),
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

// AddPolicy add a policy to casbin enforcer
// This function is just used for testing.
func (n *Node) AddPolicy(sec string, ptype string, rules []string) error {
	if n.engine.enforcer.GetModel().HasPolicy(sec, ptype, rules) {
		return errors.New("casbin: policy already exists")
	}

	command := Command{
		Op:    addCommand,
		Sec:   sec,
		Ptype: ptype,
		Rule:  rules,
	}

	buf, err := json.Marshal(command)
	if err != nil {
		return err
	}
	return n.raft.Propose(n.ctx, buf)
}

// RemovePolicy remove a policy from casbin enforcer
// This function is just used for testing.
func (n *Node) RemovePolicy(sec string, ptype string, rules []string) error {
	if !n.engine.enforcer.GetModel().HasPolicy(sec, ptype, rules) {
		return errors.New("casbin: policy does not exist")
	}

	command := Command{
		Op:    removeCommand,
		Sec:   sec,
		Ptype: ptype,
		Rule:  rules,
	}

	buf, err := json.Marshal(command)
	if err != nil {
		return err
	}
	return n.raft.Propose(n.ctx, buf)
}
