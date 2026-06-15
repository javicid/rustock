use crate::state::SyncState;
use std::time::Instant;
use tracing::info;

/// Tracks sync progress metrics and produces periodic log reports.
pub(crate) struct SyncProgress {
    pub sync_started_at: Option<Instant>,
    pub sync_start_block: u64,
    pub sync_start_downloaded: u64,
    pub last_report_at: Instant,
    pub last_report_block: u64,
    pub last_report_downloaded: u64,
}

impl SyncProgress {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            sync_started_at: None,
            sync_start_block: 0,
            sync_start_downloaded: 0,
            last_report_at: now,
            last_report_block: 0,
            last_report_downloaded: 0,
        }
    }

    /// Resets tracking for a fresh sync session starting at `head_block`.
    /// The download frontier starts at the same height (downloads for the new
    /// session have not run ahead yet).
    pub fn reset(&mut self, head_block: u64) {
        let now = Instant::now();
        self.sync_started_at = Some(now);
        self.sync_start_block = head_block;
        self.sync_start_downloaded = head_block;
        self.last_report_at = now;
        self.last_report_block = head_block;
        self.last_report_downloaded = head_block;
    }

    /// Logs sync progress if enough time has elapsed since the last report.
    /// Returns without logging for `Idle` or `Following` states.
    ///
    /// `executed` is the executed-chain head (the headline sync position);
    /// `downloaded` the downloaded-header head, which runs ahead by design
    /// (pipelined skeleton sync). The reported rate and ETA follow whichever
    /// frontier is currently advancing: the download head during the initial
    /// download phase (when execution has not started yet), the execution head
    /// once it is the bottleneck. This keeps the line from reporting 0 blk/s
    /// and an unknown ETA while the node is plainly downloading blocks.
    pub fn log(&mut self, state: &SyncState, executed: u64, downloaded: u64, peer_count: usize) {
        let current = executed;
        let peer_best = match state {
            SyncState::DownloadingHeaders { peer_best, .. } => *peer_best,
            SyncState::DownloadingSkeleton { peer_best, .. } => *peer_best,
            SyncState::FindingConnectionPoint { peer_best, .. } => *peer_best,
            SyncState::DownloadingBodies { peer_best, .. } => *peer_best,
            SyncState::Idle | SyncState::Following => return,
        };

        if current == 0 || peer_best == 0 {
            return;
        }

        let now = Instant::now();

        if self.sync_started_at.is_none() {
            self.sync_started_at = Some(now);
            self.sync_start_block = current;
            self.sync_start_downloaded = downloaded;
            self.last_report_at = now;
            self.last_report_block = current;
            self.last_report_downloaded = downloaded;
        }

        let elapsed_since_report = now.duration_since(self.last_report_at).as_secs_f64();
        if elapsed_since_report < 1.0 {
            return;
        }

        let total_elapsed = now
            .duration_since(self.sync_started_at.unwrap_or(now))
            .as_secs_f64();

        let (recent_speed, avg_speed, frontier) = frontier_rates(
            HeadProgress {
                current,
                start: self.sync_start_block,
                last_report: self.last_report_block,
            },
            HeadProgress {
                current: downloaded,
                start: self.sync_start_downloaded,
                last_report: self.last_report_downloaded,
            },
            elapsed_since_report,
            total_elapsed,
        );

        let pct = (current as f64 / peer_best as f64 * 100.0).min(100.0);
        let eta = format_eta(peer_best.saturating_sub(frontier), avg_speed);

        let state_label = match state {
            SyncState::FindingConnectionPoint { .. } => "finding connection point",
            SyncState::DownloadingSkeleton { .. } => "downloading skeleton",
            SyncState::DownloadingHeaders { .. } => "downloading headers",
            SyncState::DownloadingBodies { .. } => "downloading bodies",
            SyncState::Idle => "idle",
            SyncState::Following => "following",
        };

        info!(
            target: "rustock::sync",
            "Sync progress: exec #{} | dl #{} | peer #{} ({:.2}%) | {:.0} blk/s (avg {:.0}) | ETA {} | {} peers | {}",
            executed, downloaded, peer_best, pct,
            recent_speed, avg_speed,
            eta, peer_count, state_label
        );

        self.last_report_at = now;
        self.last_report_block = current;
        self.last_report_downloaded = downloaded;
    }
}

/// Per-head progress snapshot used to compute rates: where the head is now
/// (`current`), where it started this session (`start`), and where it was at the
/// previous report (`last_report`).
struct HeadProgress {
    current: u64,
    start: u64,
    last_report: u64,
}

/// Selects the reporting frontier and computes `(recent_speed, avg_speed,
/// frontier_height)`.
///
/// The executed head is the headline sync position, but during the pipelined
/// download phase execution may not have advanced this interval while the
/// download frontier climbs. We report the rate of whichever frontier moved this
/// interval — preferring execution when it advanced — and return that frontier's
/// height so the ETA targets it. Only when neither head advanced (genuinely idle
/// or stalled) does `avg_speed` stay 0, which surfaces as an "unknown" ETA.
fn frontier_rates(
    exec: HeadProgress,
    downloaded: HeadProgress,
    elapsed_since_report: f64,
    total_elapsed: f64,
) -> (f64, f64, u64) {
    let head = if exec.current > exec.last_report { &exec } else { &downloaded };

    let recent = head.current.saturating_sub(head.last_report) as f64 / elapsed_since_report;
    let avg = if total_elapsed > 0.0 {
        head.current.saturating_sub(head.start) as f64 / total_elapsed
    } else {
        0.0
    };
    (recent, avg, head.current)
}

/// Formats the ETA for `remaining` blocks at `avg_speed` blocks/s, or "unknown"
/// when there is no measurable forward progress.
fn format_eta(remaining: u64, avg_speed: f64) -> String {
    if avg_speed > 0.0 {
        format_duration(remaining as f64 / avg_speed)
    } else {
        "unknown".to_string()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Download phase: execution is flat but the download frontier is climbing.
    /// The rate must reflect download progress (not 0), the ETA must be known,
    /// and the reporting frontier must be the download head.
    #[test]
    fn downloading_reports_download_rate_not_zero() {
        // exec parked at 1000; download advanced 1000 -> 1100 over the last 2s,
        // and 1000 -> 1500 over the 10s session.
        let (recent, avg, frontier) = frontier_rates(
            HeadProgress { current: 1000, start: 1000, last_report: 1000 },
            HeadProgress { current: 1500, start: 1000, last_report: 1100 },
            2.0,
            10.0,
        );
        assert_eq!(recent, (1500 - 1100) as f64 / 2.0, "recent = download rate");
        assert_eq!(avg, (1500 - 1000) as f64 / 10.0, "avg = download rate");
        assert_eq!(frontier, 1500, "frontier is the download head");
        assert_eq!(format_eta(2000u64.saturating_sub(frontier), avg), "10s");
    }

    /// Execution phase: once the executed head advances it is the frontier, even
    /// if the download head also moved (execution is the bottleneck).
    #[test]
    fn executing_reports_exec_rate() {
        let (recent, avg, frontier) = frontier_rates(
            HeadProgress { current: 1200, start: 1000, last_report: 1100 },
            HeadProgress { current: 5000, start: 1000, last_report: 4000 },
            2.0,
            10.0,
        );
        assert_eq!(recent, (1200 - 1100) as f64 / 2.0, "recent = exec rate");
        assert_eq!(avg, (1200 - 1000) as f64 / 10.0, "avg = exec rate");
        assert_eq!(frontier, 1200, "frontier is the exec head");
    }

    /// Genuinely idle: neither head advanced this interval and nothing moved all
    /// session. avg stays 0 and the ETA is reported as "unknown".
    #[test]
    fn idle_reports_unknown_eta() {
        let (recent, avg, frontier) = frontier_rates(
            HeadProgress { current: 1000, start: 1000, last_report: 1000 },
            HeadProgress { current: 1000, start: 1000, last_report: 1000 },
            2.0,
            10.0,
        );
        assert_eq!(recent, 0.0);
        assert_eq!(avg, 0.0);
        assert_eq!(frontier, 1000);
        assert_eq!(format_eta(2000u64.saturating_sub(frontier), avg), "unknown");
    }

    #[test]
    fn format_eta_known_and_unknown() {
        assert_eq!(format_eta(100, 10.0), "10s");
        assert_eq!(format_eta(6000, 10.0), "10m 0s");
        assert_eq!(format_eta(72_000, 10.0), "2h 0m");
        assert_eq!(format_eta(100, 0.0), "unknown");
    }
}
