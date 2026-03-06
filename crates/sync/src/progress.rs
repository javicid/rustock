use crate::state::SyncState;
use std::time::Instant;
use tracing::info;

/// Tracks sync progress metrics and produces periodic log reports.
pub(crate) struct SyncProgress {
    pub sync_started_at: Option<Instant>,
    pub sync_start_block: u64,
    pub last_report_at: Instant,
    pub last_report_block: u64,
}

impl SyncProgress {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            sync_started_at: None,
            sync_start_block: 0,
            last_report_at: now,
            last_report_block: 0,
        }
    }

    /// Resets tracking for a fresh sync session starting at `head_block`.
    pub fn reset(&mut self, head_block: u64) {
        let now = Instant::now();
        self.sync_started_at = Some(now);
        self.sync_start_block = head_block;
        self.last_report_at = now;
        self.last_report_block = head_block;
    }

    /// Logs sync progress if enough time has elapsed since the last report.
    /// Returns without logging for `Idle` or `Following` states.
    pub fn log(&mut self, state: &SyncState, current: u64, peer_count: usize) {
        let peer_best = match state {
            SyncState::DownloadingHeaders { peer_best, .. } => *peer_best,
            SyncState::DownloadingSkeleton { peer_best, .. } => *peer_best,
            SyncState::FindingConnectionPoint { peer_best, .. } => *peer_best,
            SyncState::Idle | SyncState::Following => return,
        };

        if current == 0 || peer_best == 0 {
            return;
        }

        let now = Instant::now();

        if self.sync_started_at.is_none() {
            self.sync_started_at = Some(now);
            self.sync_start_block = current;
            self.last_report_at = now;
            self.last_report_block = current;
        }

        let elapsed_since_report = now.duration_since(self.last_report_at).as_secs_f64();
        if elapsed_since_report < 1.0 {
            return;
        }

        let blocks_since_report = current.saturating_sub(self.last_report_block);
        let recent_speed = blocks_since_report as f64 / elapsed_since_report;

        let total_elapsed = now
            .duration_since(self.sync_started_at.unwrap_or(now))
            .as_secs_f64();
        let total_blocks = current.saturating_sub(self.sync_start_block);
        let avg_speed = if total_elapsed > 0.0 {
            total_blocks as f64 / total_elapsed
        } else {
            0.0
        };

        let pct = (current as f64 / peer_best as f64 * 100.0).min(100.0);

        let remaining = peer_best.saturating_sub(current);
        let eta = if avg_speed > 0.0 {
            let secs = remaining as f64 / avg_speed;
            format_duration(secs)
        } else {
            "unknown".to_string()
        };

        let state_label = match state {
            SyncState::FindingConnectionPoint { .. } => "finding connection point",
            SyncState::DownloadingSkeleton { .. } => "downloading skeleton",
            SyncState::DownloadingHeaders { .. } => "downloading headers",
            SyncState::Idle => "idle",
            SyncState::Following => "following",
        };

        info!(
            target: "rustock::sync",
            "Sync progress: #{} / #{} ({:.2}%) | {:.0} blk/s (avg {:.0}) | ETA {} | {} peers | {}",
            current, peer_best, pct,
            recent_speed, avg_speed,
            eta, peer_count, state_label
        );

        self.last_report_at = now;
        self.last_report_block = current;
    }
}

fn format_duration(secs: f64) -> String {
    let secs = secs as u64;
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        format!("{}h {}m", h, m)
    }
}
