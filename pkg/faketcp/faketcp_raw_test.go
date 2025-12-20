package faketcp

import "testing"

const minRawRecvQueueSize = 2048

func TestRawRecvQueueSize(t *testing.T) {
	if rawRecvQueueSize < minRawRecvQueueSize {
		t.Fatalf("rawRecvQueueSize too small: %d", rawRecvQueueSize)
	}
}
