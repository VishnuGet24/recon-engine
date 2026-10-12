/**
 * Date and time utilities for handling UTC timestamps from the backend.
 * Ensures that naive ISO strings (without trailing 'Z' or timezone offset)
 * are properly treated as UTC rather than the browser's local time.
 */

export function parseUtcDate(value: string | number | Date | null | undefined): Date | null {
  if (!value) return null;
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  if (typeof value === 'number') {
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? null : d;
  }
  let str = String(value).trim();
  if (!str) return null;

  // If it's a date-time string without a timezone designator (no 'Z' and no '+' or '-' offset),
  // assume UTC so browsers in non-UTC time zones convert it accurately to local time.
  if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(str)) {
    str = str.replace(' ', 'T') + 'Z';
  }

  const d = new Date(str);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function formatDateTime(
  value: string | number | Date | null | undefined,
  fallback = '—',
  options?: Intl.DateTimeFormatOptions
): string {
  const d = parseUtcDate(value);
  if (!d) return fallback;
  return d.toLocaleString(undefined, options || {
    year: 'numeric',
    month: 'numeric',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    second: '2-digit',
    hour12: true,
  });
}

export function formatDateOnly(value: string | number | Date | null | undefined, fallback = '—'): string {
  const d = parseUtcDate(value);
  if (!d) return fallback;
  return d.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'numeric',
    day: 'numeric',
  });
}
