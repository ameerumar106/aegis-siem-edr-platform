const COLORS = {
  CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#22c55e',
  windows: '#60a5fa', linux: '#34d399', firewall: '#f97316', webserver: '#a78bfa'
};

const chartDefaults = {
  responsive: true, maintainAspectRatio: false,
  plugins: { legend: { labels: { color: '#8892a4', font: { size: 12 } } } }
};

async function loadStats() {
  const res  = await fetch('/api/stats');
  const data = await res.json();

  // Severity doughnut
  const sevData = data.by_severity || {};
  new Chart(document.getElementById('chartSeverity'), {
    type: 'doughnut',
    data: {
      labels: Object.keys(sevData),
      datasets: [{ data: Object.values(sevData),
        backgroundColor: Object.keys(sevData).map(k => COLORS[k] || '#888'),
        borderWidth: 0, hoverOffset: 6 }]
    },
    options: { ...chartDefaults, cutout: '65%' }
  });

  // Source bar
  const srcData = data.by_source || {};
  new Chart(document.getElementById('chartSource'), {
    type: 'bar',
    data: {
      labels: Object.keys(srcData),
      datasets: [{ label: 'Events', data: Object.values(srcData),
        backgroundColor: Object.keys(srcData).map(k => COLORS[k] || '#60a5fa'),
        borderRadius: 6, borderSkipped: false }]
    },
    options: { ...chartDefaults,
      scales: {
        x: { ticks: { color: '#8892a4' }, grid: { color: '#2e3250' } },
        y: { ticks: { color: '#8892a4' }, grid: { color: '#2e3250' } }
      },
      plugins: { ...chartDefaults.plugins, legend: { display: false } }
    }
  });

  // Hourly line chart
  const hourly = data.by_hour || [];
  new Chart(document.getElementById('chartHourly'), {
    type: 'line',
    data: {
      labels: hourly.map(h => h.hour + ':00'),
      datasets: [{ label: 'Events', data: hourly.map(h => h.count),
        borderColor: '#3b82f6', backgroundColor: 'rgba(59,130,246,.1)',
        fill: true, tension: 0.4, pointRadius: 3, pointBackgroundColor: '#3b82f6' }]
    },
    options: { ...chartDefaults,
      scales: {
        x: { ticks: { color: '#8892a4' }, grid: { color: '#2e3250' } },
        y: { ticks: { color: '#8892a4' }, grid: { color: '#2e3250' } }
      }
    }
  });

  // Top IPs
  const topIps = data.top_ips || [];
  const ipList  = document.getElementById('topIpList');
  if (ipList) {
    ipList.innerHTML = topIps.map(ip =>
      `<tr>
        <td style="font-family:monospace">${ip.ip}</td>
        <td><div style="background:#2e3250;border-radius:4px;height:8px;width:100%">
          <div style="background:#3b82f6;border-radius:4px;height:8px;width:${Math.min(ip.count*8,100)}%"></div>
        </div></td>
        <td style="text-align:right;color:#8892a4">${ip.count}</td>
      </tr>`
    ).join('');
  }
}

document.addEventListener('DOMContentLoaded', loadStats);
