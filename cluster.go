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
	"sync"

	"go.etcd.io/etcd/raft/raftpb"
)

// Cluster manage the node id and url
type Cluster struct {
	members map[uint64]string
	mutex   *sync.RWMutex
}

// NewCluster create a Cluster frome map
func NewCluster(peers map[uint64]string) *Cluster {
	return &Cluster{
		members: peers,
		mutex:   &sync.RWMutex{},
	}
}

// GetURL find the url
func (c *Cluster) GetURL(id uint64) string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.members[id]
}

// AddMember add a new member to Cluster
func (c *Cluster) AddMember(id uint64, url string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.members[id] = url
}

// RemoveMember remove a existed member from Cluster
func (c *Cluster) RemoveMember(id uint64) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.members, id)
}

// HasMember check if the member in the Cluster
func (c *Cluster) HasMember(id uint64) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	_, ok := c.members[id]
	return ok
}

// ApplyConfigChange apply the Ready ConfChange Message
func (c *Cluster) ApplyConfigChange(cc raftpb.ConfChange) {
	switch cc.Type {
	case raftpb.ConfChangeAddNode, raftpb.ConfChangeAddLearnerNode:
		c.AddMember(cc.NodeID, string(cc.Context))
	case raftpb.ConfChangeRemoveNode:
		c.RemoveMember(cc.NodeID)
	}
}
