// Package dashboard provides a simple HTTP server for displaying the status of blocked IPs.
package dashboard

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/tomMoulard/fail2ban/pkg/cloudflare"
	"github.com/tomMoulard/fail2ban/pkg/fail2ban"
)

var (
	dashboardTemplate = `<!DOCTYPE html>
	<html>
	  <head>
		<title>Fail2Ban Dashboard</title>
		<style>
		  body {
			font-family: system-ui, -apple-system, sans-serif;
			max-width: 1200px;
			margin: 0 auto;
			padding: 20px;
			background: #f5f5f5;
		  }
		  .header { margin-bottom: 20px; }
		  .blocks {
			background: white;
			border-radius: 8px;
			box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
			overflow: hidden;
		  }
		  table { width: 100%; border-collapse: collapse; }
		  th, td {
			padding: 12px;
			text-align: left;
			border-bottom: 1px solid #eee;
		  }
		  th { background: #f8f9fa; font-weight: 600; }
		  .source-badge {
			display: inline-block;
			padding: 4px 8px;
			border-radius: 4px;
			font-size: 12px;
			font-weight: 500;
		  }
		  .source-local { background: #e3f2fd; color: #1565c0; }
		  .source-cloudflare { background: #f3e5f5; color: #7b1fa2; }
		  .refresh { margin-bottom: 20px; }
		</style>
	  </head>
	  <body>
		<div class="header">
		  <h1>Fail2Ban Dashboard</h1>
		</div>
		<div class="refresh">
		  <button onclick="refreshData()">Refresh</button>
		</div>
		<div class="blocks">
		  <table>
			<thead>
			  <tr>
				<th>IP Address</th>
				<th>Source</th>
				<th>Banned At</th>
				<th>Ban Until</th>
				<th>Remaining Time</th>
			  </tr>
			</thead>
			<tbody id="blocks-table">
			  {{range .Blocks}}
			  <tr>
				<td>{{.IP}}</td>
				<td><span class="source-badge source-{{.Source}}">{{.Source}}</span></td>
				<td>{{.BannedAt.Format "2006-01-02 15:04:05"}}</td>
				<td>{{.BanUntil.Format "2006-01-02 15:04:05"}}</td>
				<td>{{.RemainingTime}}</td>
			  </tr>
			  {{end}}
			</tbody>
		  </table>
		</div>
		<script>` + jsTemplate + `</script>
	  </body>
	</html>`

	jsTemplate = `
		function refreshData() {
		  fetch('/api/blocks')
			.then((response) => response.json())
			.then((data) => {
			  const tbody = document.getElementById('blocks-table');
			  tbody.innerHTML = data
				.map(
				  (block) => ` + "`" + `
					<tr>
					  <td>${block.ip}</td>
					  <td><span class="source-badge source-${block.source}">${block.source}</span></td>
					  <td>${new Date(block.bannedAt).toLocaleString()}</td>
					  <td>${new Date(block.banUntil).toLocaleString()}</td>
					  <td>${block.remainingTime}</td>
					</tr>
				  ` + "`" + `
				)
				.join('');
			});
		}
		setInterval(refreshData, 30000);`
)

type Dashboard struct {
	f2b  *fail2ban.Fail2Ban
	cf   *cloudflare.Client
	tmpl *template.Template
}

type BlockedIP struct {
	IP            string    `json:"ip"`
	BannedAt      time.Time `json:"bannedAt"`
	BanUntil      time.Time `json:"banUntil"`
	Source        string    `json:"source"` // "local" or "cloudflare"
	RemainingTime string    `json:"remainingTime"`
}

func New(f2b *fail2ban.Fail2Ban, cf *cloudflare.Client) (*Dashboard, error) {
	tmpl, err := template.New("dashboard").Parse(dashboardTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dashboard template: %w", err)
	}

	return &Dashboard{
		f2b:  f2b,
		cf:   cf,
		tmpl: tmpl,
	}, nil
}

func (d *Dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/blocks":
		d.handleAPIBlocks(w)
	default:
		d.handleDashboard(w, r)
	}
}

func (d *Dashboard) handleDashboard(w http.ResponseWriter, _ *http.Request) {
	blocks := d.getBlocks()
	data := struct {
		Blocks []BlockedIP
	}{
		Blocks: blocks,
	}

	w.Header().Set("Content-Type", "text/html")

	if err := d.tmpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (d *Dashboard) handleAPIBlocks(w http.ResponseWriter) {
	blocks := d.getBlocks()

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(blocks); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (d *Dashboard) getBlocks() []BlockedIP {
	var blocks []BlockedIP

	now := time.Now()

	// Get local blocks
	d.f2b.RangeBlocks(func(ip string, bannedAt time.Time, banUntil time.Time) {
		remaining := banUntil.Sub(now)
		if remaining > 0 {
			blocks = append(blocks, BlockedIP{
				IP:            ip,
				BannedAt:      bannedAt,
				BanUntil:      banUntil,
				Source:        "local",
				RemainingTime: remaining.String(),
			})
		}
	})

	// Get Cloudflare blocks if enabled
	if d.cf != nil {
		d.cf.RangeBlocks(func(ip string, banUntil time.Time) {
			remaining := banUntil.Sub(now)
			if remaining > 0 {
				blocks = append(blocks, BlockedIP{
					IP:            ip,
					BannedAt:      banUntil.Add(-24 * time.Hour), // Approximate
					BanUntil:      banUntil,
					Source:        "cloudflare",
					RemainingTime: remaining.String(),
				})
			}
		})
	}

	return blocks
}
