const path = require('path');
const fs = require('fs');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '../../data/db.json');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const DEFAULT = {
  counters: { store: 1, user: 1, bill: 1, attachment: 1 },
  stores: [],
  users: [],
  bills: [],
  attachments: []
};

function load() {
  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify(DEFAULT, null, 2));
  }
  const raw = fs.readFileSync(DB_PATH, 'utf8');
  try {
    const obj = JSON.parse(raw);
    return { ...DEFAULT, ...obj };
  } catch {
    fs.writeFileSync(DB_PATH, JSON.stringify(DEFAULT, null, 2));
    return { ...DEFAULT };
  }
}

function save(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

function now() {
  return new Date().toISOString();
}

// Simple DB API
const db = {
  load,
  save,
  now,
  nextId(data, key) {
    const id = data.counters[key] || 1;
    data.counters[key] = id + 1;
    return id;
  }
};

module.exports = { db, DB_PATH };
