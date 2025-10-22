package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/valkey-io/valkey-go"
)

// DistributedQueue manages a distributed work queue across cluster nodes
type DistributedQueue struct {
	client   valkey.Client
	keyspace string
	nodeID   string
	logger   *slog.Logger
	ctx      context.Context
	cancel   context.CancelFunc
}

// QueueItem represents an item in the distributed queue
type QueueItem struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Priority    int                    `json:"priority"`
	Data        map[string]interface{} `json:"data"`
	CreatedAt   time.Time              `json:"created_at"`
	ScheduledAt time.Time              `json:"scheduled_at"`
	Attempts    int                    `json:"attempts"`
	MaxAttempts int                    `json:"max_attempts"`
	Owner       string                 `json:"owner,omitempty"`
	LeaseExpiry time.Time              `json:"lease_expiry,omitempty"`
}

// NewDistributedQueue creates a new distributed queue
func NewDistributedQueue(valkeyURL, keyspace, nodeID string, logger *slog.Logger) (*DistributedQueue, error) {
	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{valkeyURL},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Valkey: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &DistributedQueue{
		client:   client,
		keyspace: keyspace,
		nodeID:   nodeID,
		logger:   logger,
		ctx:      ctx,
		cancel:   cancel,
	}, nil
}

// Enqueue adds an item to the queue
func (q *DistributedQueue) Enqueue(ctx context.Context, item *QueueItem) error {
	if item.ID == "" {
		item.ID = fmt.Sprintf("%s-%d", q.nodeID, time.Now().UnixNano())
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = time.Now()
	}
	if item.ScheduledAt.IsZero() {
		item.ScheduledAt = time.Now()
	}
	if item.MaxAttempts == 0 {
		item.MaxAttempts = 3
	}

	data, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("failed to marshal item: %w", err)
	}

	// Add to sorted set with priority and scheduled time as score
	score := float64(item.ScheduledAt.Unix()*1000 - int64(item.Priority)*1000000)
	queueKey := fmt.Sprintf("%s:queue:pending", q.keyspace)

	cmd := q.client.B().Zadd().Key(queueKey).
		ScoreMember().ScoreMember(score, item.ID).Build()

	if err := q.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("failed to add to queue: %w", err)
	}

	// Store item data
	dataKey := fmt.Sprintf("%s:queue:items:%s", q.keyspace, item.ID)
	setCmd := q.client.B().Set().Key(dataKey).Value(string(data)).Build()

	if err := q.client.Do(ctx, setCmd).Error(); err != nil {
		return fmt.Errorf("failed to store item data: %w", err)
	}

	q.logger.Debug("enqueued item",
		"item_id", item.ID,
		"type", item.Type,
		"priority", item.Priority)

	return nil
}

// Dequeue retrieves and locks an item from the queue
func (q *DistributedQueue) Dequeue(ctx context.Context, leaseDuration time.Duration) (*QueueItem, error) {
	// Get items ready for processing
	queueKey := fmt.Sprintf("%s:queue:pending", q.keyspace)
	now := float64(time.Now().Unix() * 1000)

	// Use ZPOPMIN to atomically get and remove the lowest score item
	cmd := q.client.B().Zpopmin().Key(queueKey).Count(1).Build()
	result := q.client.Do(ctx, cmd)

	members, err := result.AsZScores()
	if err != nil {
		return nil, fmt.Errorf("failed to dequeue: %w", err)
	}

	if len(members) == 0 {
		return nil, nil // Queue empty
	}

	itemID := members[0].Member
	score := members[0].Score

	// Check if item is ready (score <= now)
	if score > now {
		// Put it back - not ready yet
		addCmd := q.client.B().Zadd().Key(queueKey).
			ScoreMember().ScoreMember(score, itemID).Build()
		_ = q.client.Do(ctx, addCmd).Error()
		return nil, nil
	}

	// Get item data
	dataKey := fmt.Sprintf("%s:queue:items:%s", q.keyspace, itemID)
	getCmd := q.client.B().Get().Key(dataKey).Build()

	itemData, err := q.client.Do(ctx, getCmd).ToString()
	if err != nil {
		return nil, fmt.Errorf("failed to get item data: %w", err)
	}

	var item QueueItem
	if err := json.Unmarshal([]byte(itemData), &item); err != nil {
		return nil, fmt.Errorf("failed to unmarshal item: %w", err)
	}

	// Acquire lease
	item.Owner = q.nodeID
	item.LeaseExpiry = time.Now().Add(leaseDuration)
	item.Attempts++

	// Update item with lease info
	updatedData, err := json.Marshal(&item)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal updated item: %w", err)
	}

	updateCmd := q.client.B().Set().Key(dataKey).Value(string(updatedData)).Build()
	if err := q.client.Do(ctx, updateCmd).Error(); err != nil {
		return nil, fmt.Errorf("failed to update item: %w", err)
	}

	// Move to processing set
	processingKey := fmt.Sprintf("%s:queue:processing", q.keyspace)
	addCmd := q.client.B().Zadd().Key(processingKey).
		ScoreMember().ScoreMember(float64(item.LeaseExpiry.Unix()), item.ID).Build()

	if err := q.client.Do(ctx, addCmd).Error(); err != nil {
		q.logger.Warn("failed to add to processing set", "error", err)
	}

	q.logger.Debug("dequeued item",
		"item_id", item.ID,
		"type", item.Type,
		"attempts", item.Attempts)

	return &item, nil
}

// Complete marks an item as successfully completed
func (q *DistributedQueue) Complete(ctx context.Context, itemID string) error {
	// Remove from processing
	processingKey := fmt.Sprintf("%s:queue:processing", q.keyspace)
	remCmd := q.client.B().Zrem().Key(processingKey).Member(itemID).Build()

	if err := q.client.Do(ctx, remCmd).Error(); err != nil {
		return fmt.Errorf("failed to remove from processing: %w", err)
	}

	// Delete item data
	dataKey := fmt.Sprintf("%s:queue:items:%s", q.keyspace, itemID)
	delCmd := q.client.B().Del().Key(dataKey).Build()

	if err := q.client.Do(ctx, delCmd).Error(); err != nil {
		q.logger.Warn("failed to delete item data", "error", err)
	}

	q.logger.Debug("completed item", "item_id", itemID)
	return nil
}

// Fail marks an item as failed and optionally retries
func (q *DistributedQueue) Fail(ctx context.Context, itemID string, retry bool, retryDelay time.Duration) error {
	// Remove from processing
	processingKey := fmt.Sprintf("%s:queue:processing", q.keyspace)
	remCmd := q.client.B().Zrem().Key(processingKey).Member(itemID).Build()

	if err := q.client.Do(ctx, remCmd).Error(); err != nil {
		return fmt.Errorf("failed to remove from processing: %w", err)
	}

	// Get item data
	dataKey := fmt.Sprintf("%s:queue:items:%s", q.keyspace, itemID)
	getCmd := q.client.B().Get().Key(dataKey).Build()

	itemData, err := q.client.Do(ctx, getCmd).ToString()
	if err != nil {
		return fmt.Errorf("failed to get item data: %w", err)
	}

	var item QueueItem
	if err := json.Unmarshal([]byte(itemData), &item); err != nil {
		return fmt.Errorf("failed to unmarshal item: %w", err)
	}

	if retry && item.Attempts < item.MaxAttempts {
		// Retry with exponential backoff
		item.ScheduledAt = time.Now().Add(retryDelay)
		item.Owner = ""
		item.LeaseExpiry = time.Time{}

		// Re-enqueue
		if err := q.Enqueue(ctx, &item); err != nil {
			return fmt.Errorf("failed to re-enqueue item: %w", err)
		}

		q.logger.Debug("re-queued failed item",
			"item_id", itemID,
			"attempts", item.Attempts,
			"retry_at", item.ScheduledAt)
	} else {
		// Move to failed queue
		failedKey := fmt.Sprintf("%s:queue:failed", q.keyspace)
		addCmd := q.client.B().Zadd().Key(failedKey).
			ScoreMember().ScoreMember(float64(time.Now().Unix()), itemID).Build()

		if err := q.client.Do(ctx, addCmd).Error(); err != nil {
			q.logger.Warn("failed to add to failed queue", "error", err)
		}

		q.logger.Debug("moved item to failed queue",
			"item_id", itemID,
			"attempts", item.Attempts)
	}

	return nil
}

// ExtendLease extends the lease on an item
func (q *DistributedQueue) ExtendLease(ctx context.Context, itemID string, extension time.Duration) error {
	// Get item data
	dataKey := fmt.Sprintf("%s:queue:items:%s", q.keyspace, itemID)
	getCmd := q.client.B().Get().Key(dataKey).Build()

	itemData, err := q.client.Do(ctx, getCmd).ToString()
	if err != nil {
		return fmt.Errorf("failed to get item data: %w", err)
	}

	var item QueueItem
	if err := json.Unmarshal([]byte(itemData), &item); err != nil {
		return fmt.Errorf("failed to unmarshal item: %w", err)
	}

	// Verify ownership
	if item.Owner != q.nodeID {
		return fmt.Errorf("item not owned by this node")
	}

	// Extend lease
	item.LeaseExpiry = item.LeaseExpiry.Add(extension)

	// Update item
	updatedData, err := json.Marshal(&item)
	if err != nil {
		return fmt.Errorf("failed to marshal updated item: %w", err)
	}

	setCmd := q.client.B().Set().Key(dataKey).Value(string(updatedData)).Build()
	if err := q.client.Do(ctx, setCmd).Error(); err != nil {
		return fmt.Errorf("failed to update item: %w", err)
	}

	// Update processing set
	processingKey := fmt.Sprintf("%s:queue:processing", q.keyspace)
	addCmd := q.client.B().Zadd().Key(processingKey).
		ScoreMember().ScoreMember(float64(item.LeaseExpiry.Unix()), itemID).Build()

	if err := q.client.Do(ctx, addCmd).Error(); err != nil {
		return fmt.Errorf("failed to update processing set: %w", err)
	}

	return nil
}

// RecoverExpiredLeases moves items with expired leases back to pending
func (q *DistributedQueue) RecoverExpiredLeases(ctx context.Context) (int, error) {
	processingKey := fmt.Sprintf("%s:queue:processing", q.keyspace)
	now := float64(time.Now().Unix())

	// Get expired items
	cmd := q.client.B().Zrangebyscore().Key(processingKey).
		Min("-inf").Max(fmt.Sprintf("%f", now)).Build()

	expiredIDs, err := q.client.Do(ctx, cmd).AsStrSlice()
	if err != nil {
		return 0, fmt.Errorf("failed to get expired items: %w", err)
	}

	recovered := 0
	for _, itemID := range expiredIDs {
		// Get item data
		dataKey := fmt.Sprintf("%s:queue:items:%s", q.keyspace, itemID)
		getCmd := q.client.B().Get().Key(dataKey).Build()

		itemData, err := q.client.Do(ctx, getCmd).ToString()
		if err != nil {
			q.logger.Warn("failed to get expired item data",
				"item_id", itemID,
				"error", err)
			continue
		}

		var item QueueItem
		if err := json.Unmarshal([]byte(itemData), &item); err != nil {
			q.logger.Warn("failed to unmarshal expired item",
				"item_id", itemID,
				"error", err)
			continue
		}

		// Clear lease info
		item.Owner = ""
		item.LeaseExpiry = time.Time{}

		// Remove from processing
		remCmd := q.client.B().Zrem().Key(processingKey).Member(itemID).Build()
		_ = q.client.Do(ctx, remCmd).Error()

		// Re-enqueue with delay
		retryDelay := time.Duration(item.Attempts*item.Attempts) * time.Minute
		item.ScheduledAt = time.Now().Add(retryDelay)

		if err := q.Enqueue(ctx, &item); err != nil {
			q.logger.Error("failed to recover expired item",
				"item_id", itemID,
				"error", err)
			continue
		}

		recovered++
		q.logger.Info("recovered expired lease",
			"item_id", itemID,
			"attempts", item.Attempts,
			"retry_at", item.ScheduledAt)
	}

	return recovered, nil
}

// GetStats returns queue statistics
func (q *DistributedQueue) GetStats(ctx context.Context) (map[string]interface{}, error) {
	pendingKey := fmt.Sprintf("%s:queue:pending", q.keyspace)
	processingKey := fmt.Sprintf("%s:queue:processing", q.keyspace)
	failedKey := fmt.Sprintf("%s:queue:failed", q.keyspace)

	// Get counts
	pendingCmd := q.client.B().Zcard().Key(pendingKey).Build()
	processingCmd := q.client.B().Zcard().Key(processingKey).Build()
	failedCmd := q.client.B().Zcard().Key(failedKey).Build()

	pendingCount, _ := q.client.Do(ctx, pendingCmd).AsInt64()
	processingCount, _ := q.client.Do(ctx, processingCmd).AsInt64()
	failedCount, _ := q.client.Do(ctx, failedCmd).AsInt64()

	return map[string]interface{}{
		"pending":    pendingCount,
		"processing": processingCount,
		"failed":     failedCount,
		"total":      pendingCount + processingCount + failedCount,
	}, nil
}

// Close closes the distributed queue
func (q *DistributedQueue) Close() error {
	q.cancel()
	q.client.Close()
	return nil
}
