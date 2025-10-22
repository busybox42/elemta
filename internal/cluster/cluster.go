package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valkey-io/valkey-go"
)

// Node represents a cluster node
type Node struct {
	ID          string                 `json:"id"`
	Address     string                 `json:"address"`
	Role        NodeRole               `json:"role"`
	Status      NodeStatus             `json:"status"`
	LastSeen    time.Time              `json:"last_seen"`
	StartedAt   time.Time              `json:"started_at"`
	Version     string                 `json:"version"`
	Metadata    map[string]interface{} `json:"metadata"`
	Connections int32                  `json:"connections"`
	QueueDepth  int32                  `json:"queue_depth"`
	Load        float64                `json:"load"` // 0.0 to 1.0
}

// NodeRole defines the role of a node in the cluster
type NodeRole string

const (
	RoleMaster  NodeRole = "master"
	RoleWorker  NodeRole = "worker"
	RoleStandby NodeRole = "standby"
)

// NodeStatus defines the status of a node
type NodeStatus string

const (
	StatusHealthy   NodeStatus = "healthy"
	StatusDegraded  NodeStatus = "degraded"
	StatusUnhealthy NodeStatus = "unhealthy"
	StatusOffline   NodeStatus = "offline"
)

// Cluster manages a cluster of SMTP nodes
type Cluster struct {
	// Configuration
	nodeID         string
	valkeyClient   valkey.Client
	valkeyKeyspace string
	heartbeatInt   time.Duration
	ttl            time.Duration
	logger         *slog.Logger

	// Local node state
	localNode *Node
	mu        sync.RWMutex

	// Cluster state
	nodes      map[string]*Node
	nodesMu    sync.RWMutex
	leadership atomic.Bool
	masterNode atomic.Value // stores string (node ID)

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Callbacks
	onMasterChange    func(oldMaster, newMaster string)
	onNodeJoin        func(node *Node)
	onNodeLeave       func(node *Node)
	onHealthChange    func(node *Node, oldStatus, newStatus NodeStatus)
	healthCheckFunc   func(context.Context) bool
	metricsUpdateFunc func(node *Node)
}

// ClusterConfig configures the cluster
type ClusterConfig struct {
	NodeID            string
	Address           string
	Role              NodeRole
	ValkeyURL         string
	ValkeyKeyspace    string
	HeartbeatInterval time.Duration
	NodeTTL           time.Duration
	Logger            *slog.Logger
	OnMasterChange    func(oldMaster, newMaster string)
	OnNodeJoin        func(node *Node)
	OnNodeLeave       func(node *Node)
	OnHealthChange    func(node *Node, oldStatus, newStatus NodeStatus)
	HealthCheckFunc   func(context.Context) bool
	MetricsUpdateFunc func(node *Node)
}

// NewCluster creates a new cluster manager
func NewCluster(config ClusterConfig) (*Cluster, error) {
	if config.NodeID == "" {
		return nil, fmt.Errorf("node ID is required")
	}
	if config.ValkeyURL == "" {
		return nil, fmt.Errorf("valkey URL is required")
	}

	// Set defaults
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = 5 * time.Second
	}
	if config.NodeTTL == 0 {
		config.NodeTTL = 30 * time.Second
	}
	if config.ValkeyKeyspace == "" {
		config.ValkeyKeyspace = "elemta:cluster"
	}

	// Connect to Valkey
	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{config.ValkeyURL},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Valkey: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	localNode := &Node{
		ID:        config.NodeID,
		Address:   config.Address,
		Role:      config.Role,
		Status:    StatusHealthy,
		LastSeen:  time.Now(),
		StartedAt: time.Now(),
		Version:   "1.0.0", // TODO: Get from version package
		Metadata:  make(map[string]interface{}),
	}

	cluster := &Cluster{
		nodeID:            config.NodeID,
		valkeyClient:      client,
		valkeyKeyspace:    config.ValkeyKeyspace,
		heartbeatInt:      config.HeartbeatInterval,
		ttl:               config.NodeTTL,
		logger:            config.Logger,
		localNode:         localNode,
		nodes:             make(map[string]*Node),
		ctx:               ctx,
		cancel:            cancel,
		onMasterChange:    config.OnMasterChange,
		onNodeJoin:        config.OnNodeJoin,
		onNodeLeave:       config.OnNodeLeave,
		onHealthChange:    config.OnHealthChange,
		healthCheckFunc:   config.HealthCheckFunc,
		metricsUpdateFunc: config.MetricsUpdateFunc,
	}

	// Start cluster operations
	if err := cluster.start(); err != nil {
		cancel()
		client.Close()
		return nil, fmt.Errorf("failed to start cluster: %w", err)
	}

	return cluster, nil
}

// start begins cluster operations
func (c *Cluster) start() error {
	// Register self
	if err := c.registerNode(); err != nil {
		return fmt.Errorf("failed to register node: %w", err)
	}

	// Start heartbeat
	c.wg.Add(1)
	go c.heartbeatLoop()

	// Start discovery
	c.wg.Add(1)
	go c.discoveryLoop()

	// Start health checks
	c.wg.Add(1)
	go c.healthCheckLoop()

	// Start leader election if role is master or standby
	if c.localNode.Role == RoleMaster || c.localNode.Role == RoleStandby {
		c.wg.Add(1)
		go c.leaderElectionLoop()
	}

	c.logger.Info("cluster node started",
		"node_id", c.nodeID,
		"address", c.localNode.Address,
		"role", c.localNode.Role)

	return nil
}

// registerNode registers the node in the cluster
func (c *Cluster) registerNode() error {
	c.mu.RLock()
	nodeData, err := json.Marshal(c.localNode)
	c.mu.RUnlock()

	if err != nil {
		return fmt.Errorf("failed to marshal node data: %w", err)
	}

	key := fmt.Sprintf("%s:nodes:%s", c.valkeyKeyspace, c.nodeID)
	cmd := c.valkeyClient.B().Set().
		Key(key).
		Value(string(nodeData)).
		Ex(c.ttl).
		Build()

	if err := c.valkeyClient.Do(c.ctx, cmd).Error(); err != nil {
		return fmt.Errorf("failed to register node: %w", err)
	}

	return nil
}

// heartbeatLoop sends periodic heartbeats
func (c *Cluster) heartbeatLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.heartbeatInt)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return

		case <-ticker.C:
			if err := c.sendHeartbeat(); err != nil {
				c.logger.Error("heartbeat failed", "error", err)
			}
		}
	}
}

// sendHeartbeat updates node information
func (c *Cluster) sendHeartbeat() error {
	c.mu.Lock()
	c.localNode.LastSeen = time.Now()

	// Update metrics if callback provided
	if c.metricsUpdateFunc != nil {
		c.metricsUpdateFunc(c.localNode)
	}

	nodeData, err := json.Marshal(c.localNode)
	c.mu.Unlock()

	if err != nil {
		return fmt.Errorf("failed to marshal node data: %w", err)
	}

	key := fmt.Sprintf("%s:nodes:%s", c.valkeyKeyspace, c.nodeID)
	cmd := c.valkeyClient.B().Set().
		Key(key).
		Value(string(nodeData)).
		Ex(c.ttl).
		Build()

	return c.valkeyClient.Do(c.ctx, cmd).Error()
}

// discoveryLoop discovers other cluster nodes
func (c *Cluster) discoveryLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.heartbeatInt * 2)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return

		case <-ticker.C:
			if err := c.discoverNodes(); err != nil {
				c.logger.Error("node discovery failed", "error", err)
			}
		}
	}
}

// discoverNodes discovers cluster nodes
func (c *Cluster) discoverNodes() error {
	pattern := fmt.Sprintf("%s:nodes:*", c.valkeyKeyspace)
	cmd := c.valkeyClient.B().Keys().Pattern(pattern).Build()

	keys, err := c.valkeyClient.Do(c.ctx, cmd).AsStrSlice()
	if err != nil {
		return fmt.Errorf("failed to list nodes: %w", err)
	}

	currentNodes := make(map[string]bool)

	for _, key := range keys {
		getCmd := c.valkeyClient.B().Get().Key(key).Build()
		data, err := c.valkeyClient.Do(c.ctx, getCmd).ToString()
		if err != nil {
			continue
		}

		var node Node
		if err := json.Unmarshal([]byte(data), &node); err != nil {
			c.logger.Warn("failed to unmarshal node data", "key", key, "error", err)
			continue
		}

		currentNodes[node.ID] = true

		// Check if node is new
		c.nodesMu.Lock()
		_, exists := c.nodes[node.ID]
		c.nodes[node.ID] = &node
		c.nodesMu.Unlock()

		if !exists && node.ID != c.nodeID {
			c.logger.Info("discovered new node",
				"node_id", node.ID,
				"address", node.Address,
				"role", node.Role)

			if c.onNodeJoin != nil {
				c.onNodeJoin(&node)
			}
		}
	}

	// Check for nodes that left
	c.nodesMu.Lock()
	for id, node := range c.nodes {
		if !currentNodes[id] && id != c.nodeID {
			c.logger.Info("node left cluster",
				"node_id", id,
				"address", node.Address)

			if c.onNodeLeave != nil {
				c.onNodeLeave(node)
			}

			delete(c.nodes, id)
		}
	}
	c.nodesMu.Unlock()

	return nil
}

// healthCheckLoop performs periodic health checks
func (c *Cluster) healthCheckLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return

		case <-ticker.C:
			c.performHealthCheck()
		}
	}
}

// performHealthCheck checks node health
func (c *Cluster) performHealthCheck() {
	c.mu.Lock()
	oldStatus := c.localNode.Status

	// Perform health check if callback provided
	if c.healthCheckFunc != nil {
		healthy := c.healthCheckFunc(c.ctx)
		if healthy {
			c.localNode.Status = StatusHealthy
		} else {
			c.localNode.Status = StatusDegraded
		}
	}

	newStatus := c.localNode.Status
	c.mu.Unlock()

	// Notify status change
	if oldStatus != newStatus {
		c.logger.Info("health status changed",
			"old_status", oldStatus,
			"new_status", newStatus)

		if c.onHealthChange != nil {
			c.mu.RLock()
			node := *c.localNode
			c.mu.RUnlock()
			c.onHealthChange(&node, oldStatus, newStatus)
		}
	}
}

// leaderElectionLoop performs leader election
func (c *Cluster) leaderElectionLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return

		case <-ticker.C:
			c.performLeaderElection()
		}
	}
}

// performLeaderElection performs leader election
func (c *Cluster) performLeaderElection() {
	key := fmt.Sprintf("%s:leader", c.valkeyKeyspace)

	// Try to acquire leadership
	if !c.leadership.Load() {
		cmd := c.valkeyClient.B().Set().
			Key(key).
			Value(c.nodeID).
			Nx().
			Ex(c.ttl).
			Build()

		err := c.valkeyClient.Do(c.ctx, cmd).Error()
		if err == nil {
			c.leadership.Store(true)
			oldMaster := c.masterNode.Swap(c.nodeID)

			c.logger.Info("became cluster leader", "node_id", c.nodeID)

			if c.onMasterChange != nil && oldMaster != nil {
				c.onMasterChange(oldMaster.(string), c.nodeID)
			}
		}
	} else {
		// Maintain leadership
		cmd := c.valkeyClient.B().Expire().
			Key(key).
			Seconds(int64(c.ttl.Seconds())).
			Build()

		err := c.valkeyClient.Do(c.ctx, cmd).Error()
		if err != nil {
			c.leadership.Store(false)
			c.logger.Warn("lost cluster leadership", "error", err)
		}
	}

	// Check current leader
	getCmd := c.valkeyClient.B().Get().Key(key).Build()
	leaderID, err := c.valkeyClient.Do(c.ctx, getCmd).ToString()
	if err == nil && leaderID != "" {
		oldMaster := c.masterNode.Swap(leaderID)

		if oldMaster != nil && oldMaster.(string) != leaderID {
			c.logger.Info("cluster leader changed",
				"old_leader", oldMaster,
				"new_leader", leaderID)

			if c.onMasterChange != nil {
				c.onMasterChange(oldMaster.(string), leaderID)
			}
		}
	}
}

// GetNodes returns all known nodes
func (c *Cluster) GetNodes() []*Node {
	c.nodesMu.RLock()
	defer c.nodesMu.RUnlock()

	nodes := make([]*Node, 0, len(c.nodes))
	for _, node := range c.nodes {
		nodeCopy := *node
		nodes = append(nodes, &nodeCopy)
	}

	return nodes
}

// GetNode returns a specific node
func (c *Cluster) GetNode(nodeID string) (*Node, bool) {
	c.nodesMu.RLock()
	defer c.nodesMu.RUnlock()

	node, exists := c.nodes[nodeID]
	if !exists {
		return nil, false
	}

	nodeCopy := *node
	return &nodeCopy, true
}

// IsLeader returns whether this node is the leader
func (c *Cluster) IsLeader() bool {
	return c.leadership.Load()
}

// GetLeader returns the current leader node ID
func (c *Cluster) GetLeader() string {
	leader := c.masterNode.Load()
	if leader == nil {
		return ""
	}
	return leader.(string)
}

// UpdateMetrics updates local node metrics
func (c *Cluster) UpdateMetrics(connections int32, queueDepth int32, load float64) {
	c.mu.Lock()
	c.localNode.Connections = connections
	c.localNode.QueueDepth = queueDepth
	c.localNode.Load = load
	c.mu.Unlock()
}

// GetClusterStats returns cluster statistics
func (c *Cluster) GetClusterStats() map[string]interface{} {
	c.nodesMu.RLock()
	defer c.nodesMu.RUnlock()

	var totalConnections int32
	var totalQueueDepth int32
	var totalLoad float64
	healthyNodes := 0
	degradedNodes := 0
	unhealthyNodes := 0

	for _, node := range c.nodes {
		totalConnections += node.Connections
		totalQueueDepth += node.QueueDepth
		totalLoad += node.Load

		switch node.Status {
		case StatusHealthy:
			healthyNodes++
		case StatusDegraded:
			degradedNodes++
		case StatusUnhealthy, StatusOffline:
			unhealthyNodes++
		}
	}

	nodeCount := len(c.nodes)
	avgLoad := 0.0
	if nodeCount > 0 {
		avgLoad = totalLoad / float64(nodeCount)
	}

	return map[string]interface{}{
		"total_nodes":       nodeCount,
		"healthy_nodes":     healthyNodes,
		"degraded_nodes":    degradedNodes,
		"unhealthy_nodes":   unhealthyNodes,
		"total_connections": totalConnections,
		"total_queue_depth": totalQueueDepth,
		"avg_load":          avgLoad,
		"leader":            c.GetLeader(),
		"is_leader":         c.IsLeader(),
		"local_node_id":     c.nodeID,
		"local_node_status": c.localNode.Status,
	}
}

// Close shuts down the cluster manager
func (c *Cluster) Close() error {
	c.cancel()
	c.wg.Wait()

	// Deregister node
	key := fmt.Sprintf("%s:nodes:%s", c.valkeyKeyspace, c.nodeID)
	cmd := c.valkeyClient.B().Del().Key(key).Build()
	_ = c.valkeyClient.Do(context.Background(), cmd).Error()

	// Release leadership if held
	if c.leadership.Load() {
		leaderKey := fmt.Sprintf("%s:leader", c.valkeyKeyspace)
		delCmd := c.valkeyClient.B().Del().Key(leaderKey).Build()
		_ = c.valkeyClient.Do(context.Background(), delCmd).Error()
	}

	c.valkeyClient.Close()

	c.logger.Info("cluster node stopped", "node_id", c.nodeID)
	return nil
}
