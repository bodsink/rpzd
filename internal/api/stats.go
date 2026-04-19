package api

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/bodsink/rpzd/internal/store"
)

// ─── Dashboard zone stats ─────────────────────────────────────────────────────

// DashboardStats holds aggregate data for the overview page.
type DashboardStats struct {
	TotalZones    int
	EnabledZones  int
	TotalRecords  int64
	RecentHistory []recentSyncEntry
}

type recentSyncEntry struct {
	ZoneName       string
	Status         string
	StartedAt      string
	RecordsAdded   int
	RecordsRemoved int
}

// ─── System resource stats ────────────────────────────────────────────────────

// cpuSample holds raw /proc/stat CPU counters.
type cpuSample struct {
	total uint64
	idle  uint64
}

// SysStats is the payload returned by /api/system-stats.
type SysStats struct {
	CPUPercent  float64 `json:"cpu_percent"`
	MemUsedMB   uint64  `json:"mem_used_mb"`
	MemTotalMB  uint64  `json:"mem_total_mb"`
	MemPercent  float64 `json:"mem_percent"`
	DiskUsedGB  float64 `json:"disk_used_gb"`
	DiskTotalGB float64 `json:"disk_total_gb"`
	DiskPercent float64 `json:"disk_percent"`
	DNSUp       bool    `json:"dns_up"`
}

// sysStatsCache holds the latest sampled system stats and the previous CPU sample.
type sysStatsCache struct {
	mu      sync.Mutex
	stats   SysStats
	prevCPU cpuSample
}

// readCPUSample reads aggregate CPU time from /proc/stat.
func readCPUSample() (cpuSample, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuSample{}, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		// cpu user nice system idle iowait irq softirq steal guest guest_nice
		if len(fields) < 5 {
			break
		}
		vals := make([]uint64, len(fields)-1)
		for i, s := range fields[1:] {
			vals[i], _ = strconv.ParseUint(s, 10, 64)
		}
		idle := vals[3] // idle
		if len(vals) > 4 {
			idle += vals[4] // iowait
		}
		var total uint64
		for _, v := range vals {
			total += v
		}
		return cpuSample{total: total, idle: idle}, nil
	}
	return cpuSample{}, fmt.Errorf("cpu line not found in /proc/stat")
}

// readMemStats reads MemTotal, MemFree, Buffers, Cached from /proc/meminfo.
func readMemStats() (usedMB, totalMB uint64, percent float64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer f.Close()

	var memTotal, memFree, memBuffers, memCached, sReclaimable uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		val, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			memTotal = val
		case "MemFree:":
			memFree = val
		case "Buffers:":
			memBuffers = val
		case "Cached:":
			memCached = val
		case "SReclaimable:":
			sReclaimable = val
		}
	}
	// available ≈ free + buffers + cached + SReclaimable
	available := memFree + memBuffers + memCached + sReclaimable
	used := memTotal - available
	totalMB = memTotal / 1024
	usedMB = used / 1024
	if memTotal > 0 {
		percent = float64(used) / float64(memTotal) * 100
	}
	return
}

// readDiskStats returns disk usage for the given path.
func readDiskStats(path string) (usedGB, totalGB float64, percent float64) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	used := total - free
	totalGB = float64(total) / (1 << 30)
	usedGB = float64(used) / (1 << 30)
	if total > 0 {
		percent = float64(used) / float64(total) * 100
	}
	return
}

// checkDNSUp attempts a TCP connection to the DNS service address.
// 0.0.0.0 / :: is replaced with 127.0.0.1 for the local health check.
func checkDNSUp(addr string) bool {
	if addr == "" {
		return false
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "0.0.0.0" || host == "::" || host == "" {
		host = "127.0.0.1"
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// runSysStatsWorker refreshes the cached system stats every 5 seconds.
// It should be launched as a goroutine from Start.
func (s *Server) runSysStatsWorker(ctx context.Context) {
	// Take initial CPU sample so the first real update has a valid diff.
	s.sysCache.mu.Lock()
	s.sysCache.prevCPU, _ = readCPUSample()
	s.sysCache.mu.Unlock()

	// Sample immediately, then every 5 s.
	s.refreshSysStats()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refreshSysStats()
		}
	}
}

// refreshSysStats samples all resources and updates the cache.
func (s *Server) refreshSysStats() {
	var st SysStats

	// CPU: calculate usage from diff of two consecutive /proc/stat samples.
	curr, err := readCPUSample()
	s.sysCache.mu.Lock()
	prev := s.sysCache.prevCPU
	s.sysCache.prevCPU = curr
	s.sysCache.mu.Unlock()
	if err == nil {
		totalDiff := curr.total - prev.total
		idleDiff := curr.idle - prev.idle
		if totalDiff > 0 {
			st.CPUPercent = (1 - float64(idleDiff)/float64(totalDiff)) * 100
		}
	}

	// Memory
	st.MemUsedMB, st.MemTotalMB, st.MemPercent = readMemStats()

	// Disk (root partition)
	st.DiskUsedGB, st.DiskTotalGB, st.DiskPercent = readDiskStats("/")

	// DNS service reachability
	st.DNSUp = checkDNSUp(s.dnsAddr)

	s.sysCache.mu.Lock()
	s.sysCache.stats = st
	s.sysCache.mu.Unlock()
}

// handleSystemStats returns the latest system resource stats as JSON.
func (s *Server) handleSystemStats(c *gin.Context) {
	s.sysCache.mu.Lock()
	st := s.sysCache.stats
	s.sysCache.mu.Unlock()
	c.JSON(http.StatusOK, st)
}

// handleDashboard renders the main overview page.
func (s *Server) handleDashboard(c *gin.Context) {
	ctx := c.Request.Context()

	var (
		wg           sync.WaitGroup
		zones        []store.Zone
		zonesErr     error
		totalRecords int64
		recent       []recentSyncEntry
	)

	wg.Add(3)

	go func() {
		defer wg.Done()
		zones, zonesErr = s.db.ListZones(ctx)
	}()

	go func() {
		defer wg.Done()
		if err := s.db.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM rpz_records r JOIN rpz_zones z ON z.id=r.zone_id WHERE z.enabled=TRUE`,
		).Scan(&totalRecords); err != nil {
			s.logger.Warn("dashboard: failed to count records", "err", err)
		}
	}()

	go func() {
		defer wg.Done()
		rows, err := s.db.Pool.Query(ctx, `
			SELECT z.name, h.status, h.started_at, h.records_added, h.records_removed
			FROM sync_history h
			JOIN rpz_zones z ON z.id = h.zone_id
			ORDER BY h.started_at DESC
			LIMIT 10`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var e recentSyncEntry
				var t interface{}
				if err := rows.Scan(&e.ZoneName, &e.Status, &t, &e.RecordsAdded, &e.RecordsRemoved); err == nil {
					if ts, ok := t.(interface{ Format(string) string }); ok {
						e.StartedAt = ts.Format("2006-01-02 15:04:05")
					}
					recent = append(recent, e)
				}
			}
		}
	}()

	wg.Wait()

	if zonesErr != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to load zones", zonesErr)
		return
	}

	totalZones := len(zones)
	enabledZones := 0
	for _, z := range zones {
		if z.Enabled {
			enabledZones++
		}
	}

	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"User":         currentUser(c),
		"CSRFToken":    csrfToken(c),
		"ActivePage":   "dashboard",
		"TotalZones":   totalZones,
		"EnabledZones": enabledZones,
		"TotalRecords": totalRecords,
		"RecentSync":   recent,
	})
}

// handleStatisticsPage renders the DNS query statistics page.
func (s *Server) handleStatisticsPage(c *gin.Context) {
	ctx := c.Request.Context()

	period := c.DefaultQuery("period", "24h")
	var since time.Time
	switch period {
	case "1h":
		since = time.Now().Add(-1 * time.Hour)
	case "6h":
		since = time.Now().Add(-6 * time.Hour)
	case "7d":
		since = time.Now().Add(-7 * 24 * time.Hour)
	case "30d":
		since = time.Now().Add(-30 * 24 * time.Hour)
	default:
		period = "24h"
		since = time.Now().Add(-24 * time.Hour)
	}

	stats, err := s.db.GetQueryStats(ctx, since)
	if err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to load statistics", err)
		return
	}

	c.HTML(http.StatusOK, "statistics.html", gin.H{
		"User":       currentUser(c),
		"CSRFToken":  csrfToken(c),
		"ActivePage": "statistics",
		"Period":     period,
		"Stats":      stats,
	})
}

// renderError renders the error page with a given HTTP status.
func (s *Server) renderError(c *gin.Context, status int, message string, err error) {
	if err != nil {
		s.logger.Error(message, "err", err, "path", c.Request.URL.Path)
	}
	c.HTML(status, "error.html", gin.H{
		"Title":   http.StatusText(status),
		"Message": message,
		"User":    currentUser(c),
	})
}
