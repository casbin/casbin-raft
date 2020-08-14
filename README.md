# casbin-raft

casbin-raft is the `Dispatcher` for Casbin. Provide a way to synchronize incremental changes of policy based on etcd/raft. With this library, Casbin can ensure the consistency of multiple Casbin instances in distributed situations.

## Installation

```
    go get -u github.com/casbin/casbin-raft
```
Only casbin v3 supports the use of dispatcher, so you need to use the code of the beta branch

```
    go get -u github.com/casbin/casbin/v3@beta
```

## Simple Example

```go
package main

import (
	"github.com/casbin/casbin/v3"
	casbinraft "github.com/casbin/casbin-raft"
)

func main() {
    // Must guarantee that the initial state of all instances is the same, 
    e, _ := casbin.NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")

    // Need to provide the ID and URL of all nodes in the cluster. 
    peers := make(map[uint64]string)
    peers[1] = "127.0.0.1:8001"
    peers[2] = "127.0.0.1:8002"
    d := casbinraft.NewDispathcer(1, peers)

    e.SetDispathcer(d)
    e.EnableautoNotifyDispatcher(true)

    go d.Start()

    // Then you can continue to use the enforcer normally, and when the policy changes, dispathcer will automatically synchronize all clusters
    e.AddPolicy("alice", "data2", "read")
}
```

### Dynamic Membership

casbin-raft supports dynamically adding/removing nodes while runtime, for the new node, you need set the param `join` to true.
```go
    // peers should also contain all nodes info, although this is not needed by raft, it will be used for tranport between nodes
    peers := make(map[uint64]string)
    peers[1] = "http://127.0.0.1:8001"
    peers[2] = "http://127.0.0.1:8002"
    peers[3] = "http://127.0.0.1:8003"
    peers[4] = "http://127.0.0.1:8004"
    e, err := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
    if err != nil {
        t.Fatal(err)
    }

    d := casbinraft.NewDispatcher(4, peers, true)
    _ = e.SetDispatcher(d)
    e.EnableautoNotifyDispatcher(true)
    
    go d.Start()
```

for the existing cluster, you can call `AddMember` on any node
```
    d.AddMember(4, "http://127.0.0.1:8004")
```

If you need to remove the node, you can call `RemoveMember` on any node
```
    d.RemoveMember(3)
```

## Getting Help

- [Casbin](https://github.com/casbin/casbin)

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.