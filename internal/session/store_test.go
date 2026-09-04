package session

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewIndexesCompleteEnvelope(t *testing.T) {
	store := NewMemory()
	sess := store.New("corr", "oauth", "opaque client state", "B-B", time.Minute)

	if sess.CorrelationID != "corr" || sess.OAuthState != "oauth" || sess.ClientState != "opaque client state" {
		t.Fatalf("New() session = %+v", sess)
	}
	if sess.Status != StatusAuthorizing || sess.Conformance != "B-B" {
		t.Fatalf("New() session = %+v", sess)
	}
	if got, err := store.Get("corr"); err != nil || got != sess {
		t.Fatalf("Get() = %p, %v", got, err)
	}
	if got, err := store.GetByState("oauth"); err != nil || got != sess {
		t.Fatalf("GetByState() = %p, %v", got, err)
	}
	view, err := store.ViewByID("corr")
	if err != nil {
		t.Fatalf("ViewByID() error = %v", err)
	}
	if view.CorrelationID != "corr" || view.ClientState != "opaque client state" || view.Status != StatusAuthorizing {
		t.Fatalf("ViewByID() = %+v", view)
	}
}

func TestMissingIdentifiers(t *testing.T) {
	store := NewMemory()
	store.New("corr", "", "client", "B-B", time.Minute)

	if _, err := store.Get("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() error = %v", err)
	}
	if _, err := store.GetByState("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetByState() error = %v", err)
	}
	if _, err := store.ViewByID("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ViewByID() error = %v", err)
	}
}

func TestTerminalStatusSet(t *testing.T) {
	for _, test := range []struct {
		status Status
		want   bool
	}{
		{StatusPending, false},
		{StatusAuthorizing, false},
		{StatusCompleted, true},
		{StatusDeclined, true},
		{StatusFailed, true},
	} {
		sess := &Session{Status: test.status}
		if got := sess.Terminal(); got != test.want {
			t.Fatalf("Terminal() for %q = %v, want %v", test.status, got, test.want)
		}
		if got := test.status.Terminal(); got != test.want {
			t.Fatalf("Status.Terminal() for %q = %v, want %v", test.status, got, test.want)
		}
	}
}

func TestSetStateReindexesAndEndsResume(t *testing.T) {
	store := NewMemory()
	sess := store.New("corr", "first", "client", "B-B", time.Minute)
	store.Update(sess, func() { sess.Handle = []byte("handle") })
	if _, err := store.ConsumeForResume(sess); err != nil {
		t.Fatalf("ConsumeForResume() error = %v", err)
	}
	if _, err := store.ConsumeForResume(sess); !errors.Is(err, ErrResuming) {
		t.Fatalf("second ConsumeForResume() error = %v", err)
	}

	store.SetState(sess, "second")
	if _, err := store.GetByState("first"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old state error = %v", err)
	}
	if got, err := store.GetByState("second"); err != nil || got != sess {
		t.Fatalf("new state = %p, %v", got, err)
	}
	if got, err := store.ConsumeForResume(sess); err != nil || string(got) != "handle" {
		t.Fatalf("consume after reindex = %q, %v", got, err)
	}
}

func TestFinalizeScrubsSecretsAndState(t *testing.T) {
	store := NewMemory()
	sess := store.New("corr", "state", "client", "B-B", time.Minute)
	store.Update(sess, func() {
		sess.Handle = []byte("secret")
		sess.Status = StatusCompleted
		sess.ResultPDF = []byte("pdf")
		sess.Evidence = []byte("evidence")
	})
	store.Finalize(sess)

	if sess.Handle != nil || sess.OAuthState != "" {
		t.Fatalf("Finalize() left secrets/state: %+v", sess)
	}
	if _, err := store.GetByState("state"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("finalized state error = %v", err)
	}
	view, err := store.ViewByID("corr")
	if err != nil || string(view.ResultPDF) != "pdf" || string(view.Evidence) != "evidence" {
		t.Fatalf("terminal view = %+v, %v", view, err)
	}
}

func TestConsumeForResumeHasOneWinner(t *testing.T) {
	const goroutines = 64
	store := NewMemory()
	sess := store.New("corr", "state", "client", "B-B", time.Minute)
	store.Update(sess, func() { sess.Handle = []byte("handle") })

	start := make(chan struct{})
	errorsSeen := make(chan error, goroutines)
	var wait sync.WaitGroup
	var winners atomic.Int64
	for range goroutines {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			handle, err := store.ConsumeForResume(sess)
			if err == nil {
				winners.Add(1)
				if string(handle) != "handle" {
					errorsSeen <- errors.New("winner received wrong handle")
					return
				}
			}
			errorsSeen <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errorsSeen)

	for err := range errorsSeen {
		if err != nil && !errors.Is(err, ErrResuming) && !errors.Is(err, ErrTerminal) {
			t.Fatalf("loser error = %v", err)
		}
	}
	if got := winners.Load(); got != 1 {
		t.Fatalf("resume winners = %d, want 1", got)
	}
	if _, err := store.GetByState("state"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("consumed state error = %v", err)
	}
}

func TestConsumeReturnsHandleCopyAndRejectsTerminal(t *testing.T) {
	store := NewMemory()
	sess := store.New("corr", "state", "client", "B-B", time.Minute)
	store.Update(sess, func() { sess.Handle = []byte("handle") })
	handle, err := store.ConsumeForResume(sess)
	if err != nil {
		t.Fatalf("ConsumeForResume() error = %v", err)
	}
	handle[0] = 'H'
	if string(sess.Handle) != "handle" {
		t.Fatalf("returned handle aliases stored handle: %q", sess.Handle)
	}
	store.Update(sess, func() { sess.Status = StatusDeclined })
	store.Finalize(sess)
	if _, err := store.ConsumeForResume(sess); !errors.Is(err, ErrTerminal) {
		t.Fatalf("terminal consume error = %v", err)
	}
}

func TestConcurrentViewAndUpdate(_ *testing.T) {
	store := NewMemory()
	sess := store.New("corr", "state", "client", "B-B", time.Minute)
	done := make(chan struct{})
	go func() {
		for range 2000 {
			store.Update(sess, func() {
				sess.Status = StatusCompleted
				sess.ResultPDF = []byte("pdf")
			})
		}
		close(done)
	}()
	for range 2000 {
		_, _ = store.ViewByID("corr")
	}
	<-done
}

func TestExpiryFailsAndDeindexesSession(t *testing.T) {
	store := NewMemory()
	base := time.Now()
	store.clock = func() time.Time { return base }
	sess := store.New("corr", "state", "client", "B-B", time.Minute)
	store.Update(sess, func() { sess.Handle = []byte("handle") })
	store.clock = func() time.Time { return base.Add(2 * time.Minute) }

	view, err := store.ViewByID("corr")
	if err != nil || view.Status != StatusFailed || view.Reason != "session_expired" {
		t.Fatalf("expired view = %+v, %v", view, err)
	}
	if sess.Handle != nil {
		t.Fatalf("expired handle = %q", sess.Handle)
	}
	if _, err := store.GetByState("state"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired state error = %v", err)
	}
}

func TestGetByStateExpiresOnCallback(t *testing.T) {
	store := NewMemory()
	base := time.Now()
	store.clock = func() time.Time { return base }
	store.New("corr", "state", "client", "B-B", time.Minute)
	store.clock = func() time.Time { return base.Add(2 * time.Minute) }

	if _, err := store.GetByState("state"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired callback error = %v", err)
	}
}

func TestNewEvictsOnlyOldInactiveSessions(t *testing.T) {
	store := NewMemory()
	base := time.Now()
	store.clock = func() time.Time { return base }
	old := store.New("old", "old-state", "client", "B-B", time.Minute)
	active := store.New("active", "active-state", "client", "B-B", time.Minute)
	if _, err := store.ConsumeForResume(active); err != nil {
		t.Fatalf("ConsumeForResume() error = %v", err)
	}
	store.clock = func() time.Time { return base.Add(time.Minute + evictGrace + time.Second) }
	store.New("new", "new-state", "client", "B-B", time.Minute)

	if _, err := store.Get(old.CorrelationID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old session error = %v", err)
	}
	if _, err := store.Get(active.CorrelationID); err != nil {
		t.Fatalf("resuming session error = %v", err)
	}
	if _, err := store.Get("new"); err != nil {
		t.Fatalf("new session error = %v", err)
	}
}
