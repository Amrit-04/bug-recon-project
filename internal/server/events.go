package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// EventType defines valid real-time event categories emitted via SSE.
type EventType string

const (
	EventJobStart            EventType = "job_start"
	EventStageChange         EventType = "stage_change"
	EventProgress            EventType = "progress"
	EventEndpointDiscovered  EventType = "endpoint_discovered"
	EventCandidateDiscovered EventType = "candidate_discovered"
	EventValidationResult    EventType = "validation_result"
	EventWarning             EventType = "warning"
	EventError               EventType = "error"
	EventJobCompleted        EventType = "job_completed"
	EventJobCancelled        EventType = "job_cancelled"
	EventLog                 EventType = "log"
	EventSyncRequired        EventType = "sync_required"
)

// Event represents an individual Server-Sent Event sent to browser clients.
type Event struct {
	ID        int64     `json:"id"`
	JobID     string    `json:"job_id,omitempty"`
	Type      EventType `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Data      any       `json:"data"`
}

// EventBroker manages active SSE subscribers and maintains a ring buffer for reconnection replay.
type EventBroker struct {
	mu          sync.RWMutex
	subscribers map[chan Event]string // chan -> optional jobID filter ("" matches all)
	ringBuffer  []Event
	ringCap     int
	ringHead    int
	eventSeq    int64
	closed      bool
}

// NewEventBroker creates an initialized SSE event broker.
func NewEventBroker(bufferCapacity int) *EventBroker {
	if bufferCapacity <= 0 {
		bufferCapacity = 500
	}
	return &EventBroker{
		subscribers: make(map[chan Event]string),
		ringBuffer:  make([]Event, 0, bufferCapacity),
		ringCap:     bufferCapacity,
	}
}

// Broadcast dispatches an event to all interested active clients and records it in the ring buffer.
func (b *EventBroker) Broadcast(jobID string, eventType EventType, data any) Event {
	ev := Event{
		ID:        atomic.AddInt64(&b.eventSeq, 1),
		JobID:     jobID,
		Type:      eventType,
		Timestamp: time.Now(),
		Data:      data,
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ev
	}

	// Append to ring buffer
	if len(b.ringBuffer) < b.ringCap {
		b.ringBuffer = append(b.ringBuffer, ev)
	} else {
		b.ringBuffer[b.ringHead] = ev
		b.ringHead = (b.ringHead + 1) % b.ringCap
	}

	// Dispatch non-blockingly to subscribers
	for ch, filterJobID := range b.subscribers {
		if filterJobID == "" || filterJobID == jobID {
			select {
			case ch <- ev:
			default:
				// Subscriber too slow; drop to prevent head-of-line blocking
			}
		}
	}

	return ev
}

// Subscribe registers a new subscriber channel with an optional job filter.
func (b *EventBroker) Subscribe(filterJobID string) (chan Event, func()) {
	ch := make(chan Event, 64)

	b.mu.Lock()
	b.subscribers[ch] = filterJobID
	b.mu.Unlock()

	unsubscribe := func() {
		b.mu.Lock()
		delete(b.subscribers, ch)
		close(ch)
		b.mu.Unlock()
	}

	return ch, unsubscribe
}

// EventsSince returns buffered events with ID greater than lastID matching optional jobID filter.
// Events are strictly sorted in ascending ID order.
// If lastID > 0 and older events were evicted from the ring buffer, an EventSyncRequired event is prepended.
func (b *EventBroker) EventsSince(lastID int64, jobID string) []Event {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.ringBuffer) == 0 {
		return nil
	}

	var replay []Event
	var minID int64 = 0
	first := true

	for _, ev := range b.ringBuffer {
		if first || ev.ID < minID {
			minID = ev.ID
			first = false
		}
		if ev.ID > lastID {
			if jobID == "" || jobID == ev.JobID {
				replay = append(replay, ev)
			}
		}
	}

	// Guarantee chronological order regardless of ring buffer head position
	sort.Slice(replay, func(i, j int) bool {
		return replay[i].ID < replay[j].ID
	})

	// Detect buffer overrun: client reconnected with lastID, but oldest event in ringBuffer is greater than lastID + 1
	if lastID > 0 && minID > lastID+1 {
		syncEv := Event{
			ID:        minID - 1,
			JobID:     jobID,
			Type:      EventSyncRequired,
			Timestamp: time.Now(),
			Data: map[string]any{
				"message":             "event buffer overrun; resynchronization required",
				"last_id":             lastID,
				"oldest_available_id": minID,
			},
		}
		replay = append([]Event{syncEv}, replay...)
	}

	return replay
}

// Close terminates all active subscriber channels.
func (b *EventBroker) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	for ch := range b.subscribers {
		close(ch)
	}
	b.subscribers = make(map[chan Event]string)
}

// HandleEvents serves the SSE HTTP endpoint (`GET /api/events` or `GET /api/jobs/{id}/events`).
func (b *EventBroker) HandleEvents(w http.ResponseWriter, r *http.Request, filterJobID string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported by client transport", http.StatusInternalServerError)
		return
	}

	// SSE Headers (CORS is handled strictly by loopback corsMiddleware)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Determine last event ID for reconnect recovery
	var lastEventID int64
	if lastHdr := r.Header.Get("Last-Event-ID"); lastHdr != "" {
		if id, err := strconv.ParseInt(lastHdr, 10, 64); err == nil {
			lastEventID = id
		}
	} else if lastQuery := r.URL.Query().Get("last_id"); lastQuery != "" {
		if id, err := strconv.ParseInt(lastQuery, 10, 64); err == nil {
			lastEventID = id
		}
	}

	// Subscribe to live events
	eventsChan, unsubscribe := b.Subscribe(filterJobID)
	defer unsubscribe()

	// Replay missed events if client reconnected
	if lastEventID > 0 {
		missed := b.EventsSince(lastEventID, filterJobID)
		for _, ev := range missed {
			if err := writeSSE(w, ev); err != nil {
				return
			}
		}
		flusher.Flush()
	} else {
		// Send initial connected heartbeat
		connectedEvent := Event{
			ID:        0,
			JobID:     filterJobID,
			Type:      EventProgress,
			Timestamp: time.Now(),
			Data: map[string]any{
				"status":  "connected",
				"message": "SSE stream established",
			},
		}
		_ = writeSSE(w, connectedEvent)
		flusher.Flush()
	}

	// Heartbeat ticker to keep proxies from closing idle connections
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	notify := r.Context().Done()
	for {
		select {
		case <-notify:
			return
		case <-ticker.C:
			// SSE comment comment line for keepalive
			if _, err := fmt.Fprintf(w, ": keepalive %d\n\n", time.Now().Unix()); err != nil {
				return
			}
			flusher.Flush()
		case ev, ok := <-eventsChan:
			if !ok {
				return
			}
			if err := writeSSE(w, ev); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, ev Event) error {
	raw, err := json.Marshal(ev.Data)
	if err != nil {
		raw = []byte(fmt.Sprintf(`{"raw":"%s"}`, strings.ReplaceAll(fmt.Sprintf("%v", ev.Data), `"`, `\"`)))
	}

	_, err = fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", ev.ID, ev.Type, raw)
	return err
}
