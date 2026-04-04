//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
)

// isWindowsService reports whether the process is running as a Windows service.
func isWindowsService() bool {
	is, _ := svc.IsWindowsService()
	return is
}

// certhoundService implements svc.Handler so the Service Control Manager
// can start, stop, and query the agent.
type certhoundService struct {
	runWatch func(ctx context.Context) // injected from main — runs the watch loop
}

func (s *certhoundService) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (svcSpecificExitCode bool, exitCode uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})

	go func() {
		defer close(done)
		s.runWatch(ctx)
	}()

	status <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				// Wait for the watch loop to finish, with a timeout
				select {
				case <-done:
				case <-time.After(10 * time.Second):
				}
				return false, 0
			}
		case <-done:
			// Watch loop exited on its own (shouldn't happen, but handle it)
			return false, 0
		}
	}
}

// runAsService starts the agent as a Windows service. The provided function
// is called with a context that is cancelled when the service is stopped.
func runAsService(runWatch func(ctx context.Context)) {
	err := svc.Run("CertHoundAgent", &certhoundService{runWatch: runWatch})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Service failed: %v\n", err)
		os.Exit(1)
	}
}
