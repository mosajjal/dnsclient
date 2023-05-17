package dnsclient

import (
	"hash/fnv"
	"time"

	"github.com/miekg/dns"
)

type msgHash uint64

// CacheEntry is a single entry in the cache. LastSeen is the unix timestamp
type CacheEntry struct {
	Msg       dns.Msg
	Responses []dns.RR
	LastSeen  int64
}

// Cache is a simple cache for dns messages
type Cache struct {
	Entries map[msgHash]CacheEntry
}

// newCache creates a new cache
func newCache() *Cache {
	return &Cache{make(map[msgHash]CacheEntry)}
}

// InitCache initializes the cache and starts the cleanup routine
func InitCache() *Cache {
	c := newCache()
	go c.Clean()
	return c
}

// Add adds a message to the cache
func (c *Cache) Add(msg *dns.Msg, responses ...dns.RR) {
	c.Entries[msgHash(msg.Id)] = CacheEntry{*msg, responses, time.Now().Unix()}
}

// Get returns a message from the cache
func (c *Cache) Get(msg *dns.Msg) ([]dns.RR, bool) {
	if len(msg.Question) == 0 {
		return nil, false
	}
	h := hash(msg)
	entry, ok := c.Entries[h]
	if !ok {
		return nil, false
	}
	return entry.Responses, true
}

// Update updates the last seen timestamp for a message
func (c *Cache) Update(h msgHash) {
	entry, ok := c.Entries[h]
	if !ok {
		return
	}
	entry.LastSeen = time.Now().Unix()
	c.Entries[msgHash(h)] = entry
}

// Remove removes a message from the cache
func (c *Cache) Remove(h msgHash) {
	delete(c.Entries, h)
}

// Clean removes all entries older than 60 seconds
func (c *Cache) Clean() {
	now := time.Now().Unix()
	for k, v := range c.Entries {
		if now-v.LastSeen > 60 {
			c.Remove(k)
		}
	}
}

// hash returns a hash of a message
func hash(msg *dns.Msg) msgHash {
	hasher := fnv.New64a()
	if len(msg.Question) == 0 {
		return 0
	}
	hasher.Write([]byte(msg.Question[0].String()))
	return msgHash(hasher.Sum64())
}
