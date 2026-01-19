function parseMoneyBRL(str) {
  if (str === null || str === undefined) return null;
  const s = String(str).trim();
  if (!s) return null;
  // Accept: 1234,56 | 1.234,56 | 1234.56
  const normalized = s
    .replace(/\s/g, '')
    .replace(/\./g, '')
    .replace(/,/g, '.');
  const n = Number(normalized);
  if (Number.isNaN(n)) return null;
  return Math.round(n * 100); // store cents
}

function formatMoneyBRL(cents) {
  if (cents === null || cents === undefined) return '';
  const n = Number(cents) / 100;
  return n.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
}

module.exports = { parseMoneyBRL, formatMoneyBRL };
