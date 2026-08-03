package control

import "sync"

type Notifier struct {
	mu          sync.Mutex
	nextID      uint64
	subscribers map[string]map[uint64]chan struct{}
}

func NewNotifier() *Notifier {
	return &Notifier{subscribers: make(map[string]map[uint64]chan struct{})}
}

func (n *Notifier) Subscribe(nodeID string) (<-chan struct{}, func()) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.nextID++
	id := n.nextID
	channel := make(chan struct{}, 1)
	if n.subscribers[nodeID] == nil {
		n.subscribers[nodeID] = make(map[uint64]chan struct{})
	}
	n.subscribers[nodeID][id] = channel
	return channel, func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		if listeners := n.subscribers[nodeID]; listeners != nil {
			delete(listeners, id)
			if len(listeners) == 0 {
				delete(n.subscribers, nodeID)
			}
		}
	}
}

func (n *Notifier) Notify(nodeID string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, channel := range n.subscribers[nodeID] {
		select {
		case channel <- struct{}{}:
		default:
		}
	}
}
