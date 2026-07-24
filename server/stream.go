// Package server provides a built-in event pub/sub hub for Hush.
//
// Hush supports two communication patterns:
//   - Request-response (standard handlers registered via HandleFunc)
//   - Server push events (streaming handlers registered via HandleStreamFunc)
//
// The Hub type implements an in-memory topic-based pub/sub that can be
// wired up as streaming handlers for real-time event delivery.
package server

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/feralbureau/hush-go/frame"
	"github.com/feralbureau/hush-go/tlv"
)

// ── Event ──────────────────────────────────────────────────

// Event is a named payload delivered to topic subscribers.
type Event struct {
	Topic   string
	Payload *tlv.Map
	Time    time.Time
}

// ── Subscriber ──────────────────────────────────────────────

// Subscriber receives events published to a topic.
type Subscriber struct {
	ID      string
	Topic   string
	Events  chan Event
	Created time.Time
	done    chan struct{}
}

// NewSubscriber creates a new subscriber with a buffered event channel.
func NewSubscriber(id, topic string) *Subscriber {
	return &Subscriber{
		ID:      id,
		Topic:   topic,
		Events:  make(chan Event, 64),
		Created: time.Now(),
		done:    make(chan struct{}),
	}
}

// Close marks the subscriber as done.
func (s *Subscriber) Close() {
	close(s.done)
}

// Done returns a channel that's closed when the subscriber is done.
func (s *Subscriber) Done() <-chan struct{} {
	return s.done
}

// ── Hub ─────────────────────────────────────────────────────

// Hub is a topic-based in-memory event bus for Hush streaming handlers.
// It manages subscribers and routes published events to interested subscribers.
type Hub struct {
	mu          sync.Mutex
	subscribers map[string]map[string]*Subscriber // topic → subID → sub
}

// NewHub creates a new event hub.
func NewHub() *Hub {
	return &Hub{
		subscribers: make(map[string]map[string]*Subscriber),
	}
}

// Subscribe adds a subscriber for a topic. Returns the subscriber.
func (h *Hub) Subscribe(topic, subID string) *Subscriber {
	sub := NewSubscriber(subID, topic)

	h.mu.Lock()
	if h.subscribers[topic] == nil {
		h.subscribers[topic] = make(map[string]*Subscriber)
	}
	h.subscribers[topic][subID] = sub
	h.mu.Unlock()

	return sub
}

// Unsubscribe removes a subscriber from a topic.
func (h *Hub) Unsubscribe(topic, subID string) {
	h.mu.Lock()
	if subs, ok := h.subscribers[topic]; ok {
		if sub, exists := subs[subID]; exists {
			sub.Close()
			delete(subs, subID)
		}
		if len(subs) == 0 {
			delete(h.subscribers, topic)
		}
	}
	h.mu.Unlock()
}

// Publish sends an event to all subscribers of a topic.
// Non-blocking: if a subscriber's channel is full, the event is dropped for them.
func (h *Hub) Publish(topic string, payload *tlv.Map) {
	evt := Event{
		Topic:   topic,
		Payload: payload,
		Time:    time.Now(),
	}

	h.mu.Lock()
	subs := h.subscribers[topic]
	// Copy the map so we can send outside the lock
	dest := make(map[string]*Subscriber, len(subs))
	for id, sub := range subs {
		dest[id] = sub
	}
	h.mu.Unlock()

	for _, sub := range dest {
		select {
		case sub.Events <- evt:
		default:
			// Drop if buffer full
		}
	}
}

// Topics returns a list of all active topics.
func (h *Hub) Topics() []string {
	h.mu.Lock()
	defer h.mu.Unlock()

	topics := make([]string, 0, len(h.subscribers))
	for t := range h.subscribers {
		topics = append(topics, t)
	}
	return topics
}

// SubscriberCount returns the number of subscribers for a topic.
func (h *Hub) SubscriberCount(topic string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subscribers[topic])
}

// ── Streaming Handler Builders ─────────────────────────────

// SubscribeHandler returns a StreamHandler that subscribes to a hub topic
// and pushes events to the client as they arrive. The client receives
// frames with opcode 0x0000 (server push).
//
// Usage:
//
//	hub := server.NewHub()
//	srv.HandleStreamFunc(0x0401, hub.PublishHandler())
//	srv.HandleStreamFunc(0x0402, hub.SubscribeHandler())
func (h *Hub) SubscribeHandler() StreamHandlerFunc {
	return func(ctx context.Context, req *Request, stream io.ReadWriteCloser, key []byte) error {
		topic, _ := req.Payload.GetString("topic")
		if topic == "" {
			return fmt.Errorf("subscribe: topic required")
		}

		subID := fmt.Sprintf("%s:%d", topic, req.SessionID)
		sub := h.Subscribe(topic, subID)
		defer h.Unsubscribe(topic, subID)

		// Send initial acknowledgement
		frame.WriteResponse(stream, key, 0, &frame.Response{
			Status: frame.StatusSuccess,
			Payload: tlv.NewMap().
				Set("event", tlv.String("subscribed")).
				Set("topic", tlv.String(topic)),
		})

		seq := uint32(0)
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-sub.Done():
				return nil
			case evt := <-sub.Events:
				seq++
				resp := &frame.Response{
					Status: frame.StatusSuccess,
					Payload: tlv.NewMap().
						Set("event", tlv.String("message")).
						Set("topic", tlv.String(evt.Topic)).
						Set("payload", tlv.MapValue(evt.Payload)).
						Set("time", tlv.Timestamp(evt.Time)),
				}
				// Best-effort delivery
				frame.WriteResponse(stream, key, seq, resp)
			}
		}
	}
}

// PublishHandler returns a handler that publishes an event to a hub topic.
//
// Input: topic (string), payload (map)
// Output: subscriber_count (uint64)
func (h *Hub) PublishHandler() HandlerFunc {
	return func(ctx context.Context, req *Request) (*frame.Response, error) {
		topic, _ := req.Payload.GetString("topic")
		if topic == "" {
			return ErrorResponse(frame.StatusBadRequest, "topic required"), nil
		}

		payloadRaw, ok := req.Payload.GetMap("payload")
		if !ok {
			return ErrorResponse(frame.StatusBadRequest, "payload required"), nil
		}

		h.Publish(topic, payloadRaw)

		return NewResponse(tlv.NewMap().
			Set("subscriber_count", tlv.Uint64(uint64(h.SubscriberCount(topic)))).
			Set("topic", tlv.String(topic)),
		), nil
	}
}

// ListTopicsHandler returns a handler that lists active topics.
func (h *Hub) ListTopicsHandler() HandlerFunc {
	return func(ctx context.Context, req *Request) (*frame.Response, error) {
		topics := h.Topics()
		arr := make([]tlv.Value, len(topics))
		for i, t := range topics {
			arr[i] = tlv.String(t)
		}
		return NewResponse(tlv.NewMap().
			Set("topics", tlv.Array(arr)).
			Set("count", tlv.Uint64(uint64(len(topics)))),
		), nil
	}
}
