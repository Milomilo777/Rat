export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  // Replace parseFloat/toFixed to avoid Sonar warning about precision
  const val = Math.round((bytes / (k ** i)) * 10) / 10;
  return `${val} ${sizes[i]}`;
}

export function formatRate(bytesPerSecond: number): string {
  return `${formatBytes(bytesPerSecond)}/s`;
}

export function formatDuration(ms: number): string {
  const ONE_SECOND_MS = 1000;
  const SECONDS_IN_MINUTE = 60;

  if (ms < ONE_SECOND_MS) return `${ms}ms`;
  const s = Math.floor(ms / ONE_SECOND_MS);
  if (s < SECONDS_IN_MINUTE) return `${s}s`;
  const m = Math.floor(s / SECONDS_IN_MINUTE);
  return `${m}m`;
}
