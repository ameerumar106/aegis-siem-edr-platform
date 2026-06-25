/*
live_feed.js
Dynamically updates the live raw log feed block using correct backend keys.
*/

let lastCount = 0;

async function fetchFeed() {
  try {
    const res  = await fetch('/api/logs?limit=20');
    const logs = await res.json();
    const feed = document.getElementById('liveFeed');
    if (!feed) return;

    if (logs.length !== lastCount) {
      lastCount = logs.length;
      
      feed.innerHTML = logs.slice(0, 20).map(log => {
        const sevColor = {
          'CRITICAL': '#ef4444', 
          'HIGH': '#f97316', 
          'MEDIUM': '#f59e0b', 
          'LOW': '#22c55e'
        }[log.severity] || '#888';

        // FIXED: Using log.src_ip, log.event_type, and log.message to match your exact JSON schema
        return `<div class="feed-line" style="font-family: monospace; font-size: 0.85rem; padding: 6px 8px; border-bottom: 1px solid #1e293b; display: flex; gap: 12px; align-items: center; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
          <span style="color:#8892a4">${log.timestamp}</span>
          <span style="color:${sevColor}; font-weight:bold; min-width: 75px;">[${log.severity}]</span>
          <span style="color:#a855f7; min-width: 110px;">${log.src_ip || 'unknown'}</span>
          <span style="color:#60a5fa; min-width: 80px;">${log.source.toUpperCase()}</span>
          <span style="color:#34d399; min-width: 120px;">${log.event_type}</span>
          <span style="color:#e2e8f0; font-style: italic; overflow: hidden; text-overflow: ellipsis;">${log.message}</span>
        </div>`;
      }).join('');
      
      feed.scrollTop = 0;
    }
  } catch(e) { 
    console.error('[-] Live Feed tracking error:', e); 
  }
}

// Initial pull
fetchFeed();

// Poll every 3 seconds for active clicks
setInterval(fetchFeed, 3000);