//! Traffic-chart layout: pure port of `Ledger.chartLayout(_:now:)`
//! (Ledger.swift:445-471). The window shrinks to the data that exists (never
//! a lone sliver on the right edge) and the bars are sized so they tile it
//! completely; bar heights use a square-root scale so quiet traffic stays
//! visible next to a burst.

/// Ledger.swift:10-23 TimeRange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeRange {
    FiveMinutes,
    Hour,
    Day,
    Week,
}

impl TimeRange {
    pub fn seconds(self) -> f64 {
        match self {
            TimeRange::FiveMinutes => 300.0,
            TimeRange::Hour => 3600.0,
            TimeRange::Day => 86_400.0,
            TimeRange::Week => 604_800.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ChartBar {
    pub start_ms: u64,
    pub end_ms: u64,
    pub rx: f64,
    pub tx: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChartLayout {
    pub bars: Vec<ChartBar>,
    pub start_ms: u64,
    pub end_ms: u64,
    /// Suggested y-axis maximum: the tallest (sqrt-scaled) bar, at least 1,
    /// with 10% headroom.
    pub peak: f64,
}

/// `samples` are `(timestamp_ms, rx, tx)` points — live samples for ranges up
/// to an hour, minute buckets beyond (Swift picks `history` vs `buckets` the
/// same way; the caller owns which feed it passes). Samples older than the
/// window are ignored.
pub fn chart_layout(range: TimeRange, now_ms: u64, samples: &[(u64, f64, f64)]) -> ChartLayout {
    let now = now_ms as f64 / 1000.0;
    let window_start = now - range.seconds();

    let in_window: Vec<(f64, f64, f64)> = samples
        .iter()
        .map(|&(t_ms, rx, tx)| (t_ms as f64 / 1000.0, rx, tx))
        .filter(|&(t, _, _)| t >= window_start)
        .collect();

    let min_span = range.seconds().min(60.0);
    let first = in_window
        .iter()
        .map(|&(t, _, _)| t)
        .fold(None::<f64>, |m, t| Some(m.map_or(t, |m: f64| m.min(t))))
        .unwrap_or(now - min_span);
    let start = window_start.max(first).min(now - min_span);
    let span = now - start;

    let floor_size = if range.seconds() <= 3600.0 { 1.5 } else { 60.0 };
    let size = (span / 60.0).max(floor_size);
    let count = ((span / size).ceil() as usize).max(1);

    let mut rx = vec![0.0f64; count];
    let mut tx = vec![0.0f64; count];
    for (t, r, x) in in_window {
        let i = (((t - start) / size) as isize).clamp(0, count as isize - 1) as usize;
        rx[i] += r;
        tx[i] += x;
    }

    // Square-root scale so quiet traffic stays visible next to a burst.
    for i in 0..count {
        rx[i] = rx[i].sqrt();
        tx[i] = tx[i].sqrt();
    }

    let ms = |secs: f64| ((start + secs) * 1000.0).round() as u64;
    let bars = (0..count)
        .map(|i| ChartBar {
            start_ms: ms(i as f64 * size),
            end_ms: ms((i + 1) as f64 * size),
            rx: rx[i],
            tx: tx[i],
        })
        .collect();

    let tallest = rx
        .iter()
        .zip(&tx)
        .map(|(r, x)| r + x)
        .fold(0.0f64, f64::max);
    let peak = tallest.max(1.0) * 1.1;

    ChartLayout {
        bars,
        start_ms: ms(0.0),
        end_ms: ms(count as f64 * size),
        peak,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: u64 = 1000;

    #[test]
    fn test_empty_history_floor_bars() {
        // No data: a minimum 60s window tiled by 1.5s bars (5m range).
        let now = 600 * SEC;
        let l = chart_layout(TimeRange::FiveMinutes, now, &[]);
        assert_eq!(l.bars.len(), 40, "60s / 1.5s = 40 bars");
        assert_eq!(l.start_ms, now - 60 * SEC);
        assert_eq!(l.end_ms, now);
        assert!((l.peak - 1.1).abs() < 1e-9, "peak floors at 1 * 1.1");
        assert!(l.bars.iter().all(|b| b.rx == 0.0 && b.tx == 0.0));
    }

    #[test]
    fn test_binning_accumulates_then_sqrt() {
        // Window is pinned to at least 60s (first sample at now-30s must not
        // shrink it to a sliver); two samples in the same bar add up BEFORE
        // the square root.
        let now = 600 * SEC;
        let samples = [
            (now - 30 * SEC, 4.0, 0.0),
            (now - 29 * SEC, 5.0, 9.0),
            (now - 5 * SEC, 0.0, 0.0),
        ];
        let l = chart_layout(TimeRange::FiveMinutes, now, &samples);
        assert_eq!(l.start_ms, now - 60 * SEC);
        // start + 30s lands in bar 20 of 40 (1.5s each); sqrt(4+5)=3, sqrt(9)=3.
        assert_eq!(l.bars.len(), 40);
        assert!((l.bars[20].rx - 3.0).abs() < 1e-9, "rx: {}", l.bars[20].rx);
        assert!((l.bars[20].tx - 3.0).abs() < 1e-9, "tx: {}", l.bars[20].tx);
        // peak = (sqrt(9)+sqrt(9)) ... no: (3+3) is the tallest = 6 -> 6.6
        assert!((l.peak - 6.6).abs() < 1e-9, "peak: {}", l.peak);
    }

    #[test]
    fn test_out_of_window_samples_dropped() {
        let now = 600 * SEC;
        let samples = [(now - 400 * SEC, 100.0, 100.0), (now - 10 * SEC, 4.0, 0.0)];
        let l = chart_layout(TimeRange::FiveMinutes, now, &samples);
        assert!(
            (l.peak - (2.0 * 1.1)).abs() < 1e-9,
            "only the in-window sample counts"
        );
        assert!(l.bars.iter().all(|b| b.tx == 0.0));
    }

    #[test]
    fn test_week_range_uses_minute_floor_and_shrinks_to_data() {
        // A single bucket an hour old: the window starts at the data, bars
        // are at least 60s wide.
        let now = 10_000 * SEC;
        let samples = [(now - 3600 * SEC, 9.0, 16.0)];
        let l = chart_layout(TimeRange::Week, now, &samples);
        assert_eq!(l.start_ms, now - 3600 * SEC, "window shrinks to the data");
        assert_eq!(l.bars.len(), 60, "3600s / 60s bars");
        assert!((l.bars[0].rx - 3.0).abs() < 1e-9);
        assert!((l.bars[0].tx - 4.0).abs() < 1e-9);
        assert!((l.peak - 7.7).abs() < 1e-9, "(3+4) * 1.1");
    }

    #[test]
    fn test_sample_at_now_lands_in_last_bar() {
        // (now - start) / size can equal count; the clamp must keep it in the
        // last bar instead of indexing past the end.
        let now = 600 * SEC;
        let samples = [(now, 4.0, 0.0)];
        let l = chart_layout(TimeRange::FiveMinutes, now, &samples);
        let last = l.bars.last().unwrap();
        assert!((last.rx - 2.0).abs() < 1e-9, "sqrt(4) in the last bar");
    }
}
