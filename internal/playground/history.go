package playground

import "sync"

const maxHistory = 50

type historyRing struct {
	mu    sync.Mutex
	items []Result
}

func newHistoryRing() *historyRing {
	return &historyRing{
		items: make([]Result, 0, maxHistory),
	}
}

func (h *historyRing) Add(r Result) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.items = append([]Result{r}, h.items...)
	if len(h.items) > maxHistory {
		h.items = h.items[:maxHistory]
	}
}

func (h *historyRing) List() []Result {
	h.mu.Lock()
	defer h.mu.Unlock()

	res := make([]Result, len(h.items))
	copy(res, h.items)
	return res
}
