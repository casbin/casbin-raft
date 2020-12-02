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
	"fmt"
	"reflect"
	"testing"

	"go.etcd.io/etcd/raft/raftpb"
)

func testClusterMembers(t *testing.T, c *Cluster, res map[uint64]string) {
	if !reflect.DeepEqual(res, c.members) {
		t.Errorf("members %v \n want %v", c.members, res)
	}
}

func newTestCluster(peers []string) *Cluster {
	c := NewCluster(make(map[uint64]string))

	for i, v := range peers {
		c.members[uint64(i+1)] = v
	}

	return c
}
func TestClusterAddMember(t *testing.T) {
	c := newTestCluster(nil)

	res := make(map[uint64]string)
	for i := 1; i < 10; i++ {
		value := fmt.Sprintf("http://127.0.0.1:%d", 8000+i)
		res[uint64(i)] = value
		c.AddMember(uint64(i), value)
		testClusterMembers(t, c, res)
	}

	c.AddMember(7, "http://127.0.0.1:8007")
	c.AddMember(7, "http://127.0.0.1:8007")
	testClusterMembers(t, c, res)
}

func TestClusterRemoveMember(t *testing.T) {
	peers := []string{
		"http://127.0.0.1:8081",
		"http://127.0.0.1:8082",
		"http://127.0.0.1:8083",
	}
	c := newTestCluster(peers)

	for i := range peers {
		c.RemoveMember(uint64(i + 1))
	}
	c.RemoveMember(7)
	c.RemoveMember(7)
	testClusterMembers(t, c, make(map[uint64]string))
}

func TestClusterApplyConfChange(t *testing.T) {
	c := newTestCluster(nil)
	tests := []struct {
		cc raftpb.ConfChange
	}{
		{
			raftpb.ConfChange{
				Type:   raftpb.ConfChangeRemoveNode,
				NodeID: 3,
			},
		},
		{
			raftpb.ConfChange{
				Type:   raftpb.ConfChangeAddNode,
				NodeID: 4,
			},
		},
		{
			raftpb.ConfChange{
				Type:   raftpb.ConfChangeRemoveNode,
				NodeID: 4,
			},
		},
		{
			raftpb.ConfChange{
				Type:    raftpb.ConfChangeAddNode,
				NodeID:  1,
				Context: []byte("http://127.0.0.1:8081"),
			},
		},
		{
			raftpb.ConfChange{
				Type:    raftpb.ConfChangeAddNode,
				NodeID:  5,
				Context: []byte("http://127.0.0.1:8085"),
			},
		},
		{
			raftpb.ConfChange{
				Type:   raftpb.ConfChangeRemoveNode,
				NodeID: 5,
			},
		},
		{
			raftpb.ConfChange{
				Type:    raftpb.ConfChangeAddNode,
				NodeID:  5,
				Context: []byte("http://127.0.0.1:8085"),
			},
		},
		{
			raftpb.ConfChange{
				Type:    raftpb.ConfChangeAddNode,
				NodeID:  3,
				Context: []byte("http://127.0.0.1:8083"),
			},
		},
		{
			raftpb.ConfChange{
				Type:    raftpb.ConfChangeAddNode,
				NodeID:  6,
				Context: []byte("http://127.0.0.1:8086"),
			},
		},
	}
	res := make(map[uint64]string)
	res[1] = "http://127.0.0.1:8081"
	res[5] = "http://127.0.0.1:8085"
	res[3] = "http://127.0.0.1:8083"
	res[6] = "http://127.0.0.1:8086"
	for _, tt := range tests {
		c.ApplyConfigChange(tt.cc)
	}

	testClusterMembers(t, c, res)
}
