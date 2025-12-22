package tunnel

import (
	"encoding/binary"
	"sync"
	"time"

	"github.com/openbmx/lightweight-tunnel/pkg/fec"
)

const (
	fecBlockExpiry = 5 * time.Second
	fecHeaderSize  = 9 // 1 (type) + 4 (id) + 1 (idx) + 1 (total) + 2 (origLen)
)

type fecBlock struct {
	shards       [][]byte
	shardPresent []bool
	count        int
	total        int
	origLen      int
	expiry       time.Time
}

type FECManager struct {
	fec         *fec.FEC
	blocks      map[uint32]*fecBlock
	mu          sync.Mutex
	dataShards  int
	totalShards int
}

func NewFECManager(f *fec.FEC) *FECManager {
	m := &FECManager{
		fec:         f,
		blocks:      make(map[uint32]*fecBlock),
		dataShards:  f.DataShards(),
		totalShards: f.TotalShards(),
	}
	go m.cleanupLoop()
	return m
}

func (m *FECManager) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for id, block := range m.blocks {
			if now.After(block.expiry) {
				delete(m.blocks, id)
			}
		}
		m.mu.Unlock()
	}
}

// AddShard adds a shard and returns the reconstructed data if possible.
// Returns nil if more shards are needed or reconstruction failed.
func (m *FECManager) AddShard(packetID uint32, shardIdx int, totalShards int, origLen int, data []byte) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()

	block, ok := m.blocks[packetID]
	if !ok {
		block = &fecBlock{
			shards:       make([][]byte, totalShards),
			shardPresent: make([]bool, totalShards),
			total:        totalShards,
			origLen:      origLen,
			expiry:       time.Now().Add(fecBlockExpiry),
		}
		m.blocks[packetID] = block
	}

	if shardIdx < 0 || shardIdx >= len(block.shards) {
		return nil
	}

	if block.shardPresent[shardIdx] {
		return nil
	}

	block.shards[shardIdx] = data
	block.shardPresent[shardIdx] = true
	block.count++

	// If we have enough shards, try to reconstruct
	if block.count >= m.dataShards {
		// Check if we already reconstructed this block
		if block.count > m.dataShards && m.isDataComplete(block) {
			return nil
		}

		reconstructed, err := m.fec.Decode(block.shards, block.shardPresent)
		if err == nil {
			// Mark as complete
			for i := 0; i < m.dataShards; i++ {
				block.shardPresent[i] = true
			}
			// Trim to original length
			if len(reconstructed) > block.origLen {
				return reconstructed[:block.origLen]
			}
			return reconstructed
		}
	}

	return nil
}

func (m *FECManager) isDataComplete(block *fecBlock) bool {
	for i := 0; i < m.dataShards; i++ {
		if !block.shardPresent[i] {
			return false
		}
	}
	return true
}

// EncodePacket splits a packet into FEC shards with headers
func (m *FECManager) EncodePacket(packetID uint32, data []byte) ([][]byte, error) {
	shards, err := m.fec.Encode(data)
	if err != nil {
		return nil, err
	}

	total := len(shards)
	origLen := len(data)
	result := make([][]byte, total)
	for i := 0; i < total; i++ {
		// Header: [0]Type [1-4]ID [5]Idx [6]Total [7-8]OrigLen
		shardPacket := make([]byte, fecHeaderSize+len(shards[i]))
		shardPacket[0] = PacketTypeFEC
		binary.BigEndian.PutUint32(shardPacket[1:5], packetID)
		shardPacket[5] = byte(i)
		shardPacket[6] = byte(total)
		binary.BigEndian.PutUint16(shardPacket[7:9], uint16(origLen))
		copy(shardPacket[fecHeaderSize:], shards[i])
		result[i] = shardPacket
	}

	return result, nil
}
