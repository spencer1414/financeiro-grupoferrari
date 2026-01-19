const dayjs = require('dayjs');

function toISODate(input) {
  if (!input) return null;
  // input expected yyyy-mm-dd
  const d = dayjs(input);
  if (!d.isValid()) return null;
  return d.format('YYYY-MM-DD');
}

function daysUntil(dateISO) {
  const d = dayjs(dateISO);
  if (!d.isValid()) return null;
  const today = dayjs().startOf('day');
  return d.startOf('day').diff(today, 'day');
}

function monthKey(dateISO) {
  const d = dayjs(dateISO);
  if (!d.isValid()) return null;
  return d.format('YYYY-MM');
}

module.exports = { toISODate, daysUntil, monthKey };
