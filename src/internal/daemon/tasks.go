package daemon

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"ksu_proxy_manager/internal/fsutil"
)

const (
	TaskRunning   = "running"
	TaskSucceeded = "succeeded"
	TaskFailed    = "failed"
	TaskCancelled = "cancelled"
)

type Task struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	State     string `json:"state"`
	Message   string `json:"message,omitempty"`
	Done      int64  `json:"done,omitempty"`
	Total     int64  `json:"total,omitempty"`
	Error     string `json:"error,omitempty"`
	Result    any    `json:"result,omitempty"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
	cancel    context.CancelFunc
}

type TaskManager struct {
	mu     sync.Mutex
	tasks  map[string]*Task
	wg     sync.WaitGroup
	closed bool
}

func NewTaskManager() *TaskManager { return &TaskManager{tasks: map[string]*Task{}} }

// ErrTaskBusy is returned when a task of the same kind and key is running.
var ErrTaskBusy = errors.New("同类任务正在进行，请稍候")

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// Start runs fn in the background. Only one running task per kind is allowed.
func (m *TaskManager) Start(parent context.Context, kind string, fn func(ctx context.Context, t *TaskHandle) (any, error)) (*Task, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, unavailable("管理服务正在退出")
	}
	for _, t := range m.tasks {
		if t.Kind == kind && t.State == TaskRunning {
			m.mu.Unlock()
			return nil, ErrTaskBusy
		}
	}
	ctx, cancel := context.WithCancel(parent)
	t := &Task{ID: fsutil.RandomHex(8), Kind: kind, State: TaskRunning, CreatedAt: now(), UpdatedAt: now(), cancel: cancel}
	m.tasks[t.ID] = t
	m.gcLocked()
	m.wg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.wg.Done()
		defer cancel()
		h := &TaskHandle{m: m, id: t.ID}
		res, err := fn(ctx, h)
		m.mu.Lock()
		defer m.mu.Unlock()
		t.UpdatedAt = now()
		switch {
		case err != nil && ctx.Err() != nil:
			t.State, t.Error = TaskCancelled, "已取消"
		case err != nil:
			t.State, t.Error = TaskFailed, err.Error()
		default:
			t.State, t.Result = TaskSucceeded, res
		}
	}()
	return m.Get(t.ID)
}

// TaskHandle lets a running task report progress.
type TaskHandle struct {
	m  *TaskManager
	id string
}

func (h *TaskHandle) Progress(msg string, done, total int64) {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	if t := h.m.tasks[h.id]; t != nil {
		t.Message, t.Done, t.Total, t.UpdatedAt = msg, done, total, now()
	}
}

func (m *TaskManager) Get(id string) (*Task, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tasks[id]
	if !ok {
		return nil, errNotFound
	}
	c := *t
	c.cancel = nil
	return &c, nil
}

func (m *TaskManager) List() []Task {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Task, 0, len(m.tasks))
	for _, t := range m.tasks {
		c := *t
		c.cancel = nil
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

func (m *TaskManager) Cancel(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tasks[id]
	if !ok {
		return errNotFound
	}
	if t.State == TaskRunning && t.cancel != nil {
		t.cancel()
	}
	return nil
}

func (m *TaskManager) gcLocked() {
	cutoff := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	for id, t := range m.tasks {
		if t.State != TaskRunning && t.UpdatedAt < cutoff {
			delete(m.tasks, id)
		}
	}
}

// Shutdown cancels running tasks and waits for them.
func (m *TaskManager) Shutdown(timeout time.Duration) {
	m.mu.Lock()
	m.closed = true
	for _, t := range m.tasks {
		if t.cancel != nil {
			t.cancel()
		}
	}
	m.mu.Unlock()
	done := make(chan struct{})
	go func() { m.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}
