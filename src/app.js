require('dotenv').config();

const path = require('path');
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);

const { initSchema, db } = require('./db/db');
const { verifyPassword, hashPassword, randomTempPassword } = require('./utils/security');
const { parseMoneyToCents, centsToBRL } = require('./utils/money');
const { daysUntil, bucketForDays, bucketLabel } = require('./utils/dates');
const { sendInviteEmail } = require('./utils/email');

const multer = require('multer');

initSchema();

const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: path.join(__dirname, '../data') }),
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 10, // 10h
  },
}));

app.use('/public', express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.use((req, res, next) => {
  res.locals.centsToBRL = centsToBRL;
  res.locals.bucketLabel = bucketLabel;
  res.locals.env = process.env.NODE_ENV || 'development';
  res.locals.currentUser = req.session.user || null;
  next();
});

// Upload config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
  filename: (req, file, cb) => {
    const safe = Date.now() + '-' + Math.random().toString(16).slice(2);
    const ext = path.extname(file.originalname || '');
    cb(null, safe + ext);
  }
});
const upload = multer({ storage, limits: { fileSize: 15 * 1024 * 1024 } });

function ensureSeedAdmin() {
  const count = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  if (count > 0) return;
  const name = 'Administrador';
  const email = process.env.SEED_ADMIN_EMAIL || 'admin@local';
  const pass = process.env.SEED_ADMIN_PASSWORD || 'Admin@12345';
  return hashPassword(pass).then((hash) => {
    db.prepare('INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,?)')
      .run(name, email, hash, 'ADMIN');
    console.log('\n[SEED] Admin criado');
    console.log('Login:', email);
    console.log('Senha:', pass);
  });
}
ensureSeedAdmin();

// ---------- Auth ----------
app.get('/', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  return res.redirect('/dashboard');
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT id,name,email,password_hash,role,store_id,is_active FROM users WHERE email = ?').get(email);
  if (!user || !user.is_active) return res.status(401).render('login', { error: 'Usuário ou senha inválidos.' });
  verifyPassword(password, user.password_hash).then((ok) => {
    if (!ok) return res.status(401).render('login', { error: 'Usuário ou senha inválidos.' });
    req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role, store_id: user.store_id };
    res.redirect('/dashboard');
  }).catch(() => res.status(500).render('login', { error: 'Erro ao autenticar.' }));
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// ---------- Dashboard ----------
const { requireAuth, requireRole } = require('./middleware/auth');

app.get('/dashboard', requireAuth, (req, res) => {
  const u = req.session.user;

  // scope for bills
  let bills;
  if (u.role === 'MANAGER') {
    bills = db.prepare(`
      SELECT b.*, s.name as store_name
      FROM bills b
      JOIN stores s ON s.id = b.store_id
      WHERE b.store_id = ? AND b.status = 'OPEN'
      ORDER BY date(b.due_date) ASC, b.urgent_today DESC
    `).all(u.store_id);
  } else {
    bills = db.prepare(`
      SELECT b.*, s.name as store_name
      FROM bills b
      JOIN stores s ON s.id = b.store_id
      WHERE b.status = 'OPEN'
      ORDER BY date(b.due_date) ASC, b.urgent_today DESC
    `).all();
  }

  const grouped = {};
  for (const b of bills) {
    const d = daysUntil(b.due_date);
    const bucket = bucketForDays(d);
    grouped[bucket] = grouped[bucket] || [];
    grouped[bucket].push({ ...b, days: d });
  }

  // reminders: due today or within 2 days
  const reminders = (grouped['VENCE_HOJE'] || []).concat(grouped['ATE_2_DIAS'] || []).concat((bills.filter(x => x.urgent_today === 1)));

  res.render('dashboard', { grouped, reminders });
});

// ---------- Bills ----------
app.get('/bills', requireAuth, (req, res) => {
  const u = req.session.user;
  const { status = 'OPEN', month } = req.query;

  let sql = `
    SELECT b.*, s.name as store_name, u.name as created_by_name
    FROM bills b
    JOIN stores s ON s.id = b.store_id
    JOIN users u ON u.id = b.created_by_user_id
    WHERE b.status = ?
  `;
  const params = [status];

  if (u.role === 'MANAGER') {
    sql += ' AND b.store_id = ?';
    params.push(u.store_id);
  }

  if (month) {
    // month format YYYY-MM
    sql += " AND strftime('%Y-%m', b.due_date) = ?";
    params.push(month);
  }

  sql += ' ORDER BY date(b.due_date) ASC, b.id DESC';

  const bills = db.prepare(sql).all(...params);
  res.render('bills_list', { bills, filters: { status, month } });
});

app.get('/bills/new', requireAuth, (req, res) => {
  const u = req.session.user;
  const stores = (u.role === 'MANAGER')
    ? db.prepare('SELECT id,name FROM stores WHERE id = ?').all(u.store_id)
    : db.prepare('SELECT id,name FROM stores ORDER BY name').all();
  res.render('bill_form', { mode: 'create', bill: null, stores, error: null });
});

app.post('/bills/new', requireAuth, upload.single('attachment'), (req, res) => {
  const u = req.session.user;
  const {
    store_id,
    title,
    reason,
    amount,
    due_date,
    payment_method,
    barcode,
    pix_key,
    urgent_today,
    notes,
  } = req.body;

  if (u.role === 'MANAGER' && Number(store_id) !== Number(u.store_id)) {
    return res.status(403).render('error', { message: 'Você só pode cadastrar contas da sua loja.' });
  }

  if (!title || !due_date) {
    const stores = (u.role === 'MANAGER')
      ? db.prepare('SELECT id,name FROM stores WHERE id = ?').all(u.store_id)
      : db.prepare('SELECT id,name FROM stores ORDER BY name').all();
    return res.status(400).render('bill_form', { mode: 'create', bill: req.body, stores, error: 'Preencha pelo menos: Nome do débito e Vencimento.' });
  }

  const amountCents = parseMoneyToCents(amount);

  const info = db.prepare(`
    INSERT INTO bills
      (store_id, created_by_user_id, title, reason, amount_cents, due_date, payment_method, barcode, pix_key, urgent_today, notes, updated_at)
    VALUES
      (?,?,?,?,?,?,?,?,?,?,?, datetime('now'))
  `).run(
    Number(store_id),
    u.id,
    title,
    reason || null,
    amountCents,
    due_date,
    payment_method || 'BOLETO',
    (barcode || '').trim() || null,
    (pix_key || '').trim() || null,
    urgent_today ? 1 : 0,
    notes || null,
  );

  if (req.file) {
    db.prepare(`
      INSERT INTO bill_attachments (bill_id, original_name, storage_name, mime_type, size_bytes)
      VALUES (?,?,?,?,?)
    `).run(info.lastInsertRowid, req.file.originalname, req.file.filename, req.file.mimetype, req.file.size);
  }

  res.redirect('/bills');
});

app.get('/bills/:id', requireAuth, (req, res) => {
  const u = req.session.user;
  const id = Number(req.params.id);
  const bill = db.prepare(`
    SELECT b.*, s.name as store_name, u.name as created_by_name
    FROM bills b
    JOIN stores s ON s.id = b.store_id
    JOIN users u ON u.id = b.created_by_user_id
    WHERE b.id = ?
  `).get(id);
  if (!bill) return res.status(404).render('error', { message: 'Conta não encontrada.' });
  if (u.role === 'MANAGER' && Number(bill.store_id) !== Number(u.store_id)) return res.status(403).render('error', { message: 'Acesso negado.' });

  const attachments = db.prepare('SELECT * FROM bill_attachments WHERE bill_id = ? ORDER BY id DESC').all(id);
  res.render('bill_view', { bill, attachments, days: daysUntil(bill.due_date) });
});

app.post('/bills/:id/pay', requireAuth, (req, res) => {
  const u = req.session.user;
  const id = Number(req.params.id);
  const bill = db.prepare('SELECT * FROM bills WHERE id = ?').get(id);
  if (!bill) return res.status(404).render('error', { message: 'Conta não encontrada.' });
  if (u.role === 'MANAGER' && Number(bill.store_id) !== Number(u.store_id)) return res.status(403).render('error', { message: 'Acesso negado.' });

  db.prepare(`
    UPDATE bills
    SET status = 'PAID', paid_at = datetime('now'), updated_at = datetime('now')
    WHERE id = ?
  `).run(id);

  res.redirect('/bills/' + id);
});

app.post('/bills/:id/cancel', requireRole(['ADMIN','OWNER']), (req, res) => {
  const id = Number(req.params.id);
  db.prepare("UPDATE bills SET status='CANCELLED', updated_at=datetime('now') WHERE id=?").run(id);
  res.redirect('/bills/' + id);
});

// ---------- Export ----------
const ExcelJS = require('exceljs');

app.get('/export.xlsx', requireAuth, (req, res) => {
  const u = req.session.user;
  const { month } = req.query; // YYYY-MM optional

  let sql = `
    SELECT b.*, s.name as store_name, u.name as created_by_name
    FROM bills b
    JOIN stores s ON s.id = b.store_id
    JOIN users u ON u.id = b.created_by_user_id
    WHERE 1=1
  `;
  const params = [];

  if (u.role === 'MANAGER') {
    sql += ' AND b.store_id = ?';
    params.push(u.store_id);
  }
  if (month) {
    sql += " AND strftime('%Y-%m', b.due_date) = ?";
    params.push(month);
  }

  sql += ' ORDER BY date(b.due_date) ASC';
  const bills = db.prepare(sql).all(...params);

  const wb = new ExcelJS.Workbook();
  const ws = wb.addWorksheet('Contas');

  ws.columns = [
    { header: 'Loja', key: 'store_name', width: 22 },
    { header: 'Título', key: 'title', width: 30 },
    { header: 'Motivo', key: 'reason', width: 28 },
    { header: 'Valor (R$)', key: 'amount', width: 14 },
    { header: 'Vencimento', key: 'due_date', width: 14 },
    { header: 'Método', key: 'payment_method', width: 10 },
    { header: 'Código de Barras', key: 'barcode', width: 32 },
    { header: 'PIX', key: 'pix_key', width: 26 },
    { header: 'Urgente Hoje', key: 'urgent_today', width: 12 },
    { header: 'Status', key: 'status', width: 10 },
    { header: 'Pago em', key: 'paid_at', width: 18 },
    { header: 'Cadastrado por', key: 'created_by_name', width: 18 },
    { header: 'Criado em', key: 'created_at', width: 18 },
  ];

  for (const b of bills) {
    ws.addRow({
      store_name: b.store_name,
      title: b.title,
      reason: b.reason || '',
      amount: b.amount_cents != null ? (b.amount_cents / 100) : '',
      due_date: b.due_date,
      payment_method: b.payment_method,
      barcode: b.barcode || '',
      pix_key: b.pix_key || '',
      urgent_today: b.urgent_today ? 'SIM' : 'NÃO',
      status: b.status,
      paid_at: b.paid_at || '',
      created_by_name: b.created_by_name,
      created_at: b.created_at,
    });
  }

  ws.getRow(1).font = { bold: true };
  ws.autoFilter = { from: 'A1', to: 'M1' };

  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  const fname = month ? `contas-${month}.xlsx` : 'contas.xlsx';
  res.setHeader('Content-Disposition', `attachment; filename="${fname}"`);

  wb.xlsx.write(res).then(() => res.end());
});

// ---------- Admin (stores/users) ----------
app.get('/admin', requireRole('ADMIN'), (req, res) => {
  res.redirect('/admin/stores');
});

app.get('/admin/stores', requireRole('ADMIN'), (req, res) => {
  const stores = db.prepare('SELECT * FROM stores ORDER BY id DESC').all();
  res.render('admin_stores', { stores, error: null });
});

app.post('/admin/stores', requireRole('ADMIN'), (req, res) => {
  const { name, email } = req.body;
  if (!name) {
    const stores = db.prepare('SELECT * FROM stores ORDER BY id DESC').all();
    return res.status(400).render('admin_stores', { stores, error: 'Informe o nome da loja.' });
  }
  db.prepare('INSERT INTO stores (name,email) VALUES (?,?)').run(name.trim(), (email || '').trim() || null);
  res.redirect('/admin/stores');
});

app.get('/admin/users', requireRole('ADMIN'), (req, res) => {
  const users = db.prepare(`
    SELECT u.*, s.name as store_name
    FROM users u
    LEFT JOIN stores s ON s.id = u.store_id
    ORDER BY u.id DESC
  `).all();
  const stores = db.prepare('SELECT id,name FROM stores ORDER BY name').all();
  res.render('admin_users', { users, stores, error: null, info: null });
});

app.post('/admin/users', requireRole('ADMIN'), async (req, res) => {
  const { name, email, role, store_id } = req.body;

  const users = db.prepare(`
    SELECT u.*, s.name as store_name
    FROM users u
    LEFT JOIN stores s ON s.id = u.store_id
    ORDER BY u.id DESC
  `).all();
  const stores = db.prepare('SELECT id,name FROM stores ORDER BY name').all();

  if (!name || !email || !role) {
    return res.status(400).render('admin_users', { users, stores, error: 'Preencha nome, email e perfil.', info: null });
  }

  if (role === 'MANAGER' && !store_id) {
    return res.status(400).render('admin_users', { users, stores, error: 'Para GERENTE, selecione a loja.', info: null });
  }

  const tempPassword = randomTempPassword();
  const hash = await hashPassword(tempPassword);

  try {
    db.prepare('INSERT INTO users (name,email,password_hash,role,store_id) VALUES (?,?,?,?,?)')
      .run(name.trim(), email.trim().toLowerCase(), hash, role, role === 'MANAGER' ? Number(store_id) : null);
  } catch (e) {
    return res.status(400).render('admin_users', { users, stores, error: 'Não foi possível criar (email já existe?).', info: null });
  }

  const appUrl = process.env.APP_URL || 'http://localhost:3000';
  await sendInviteEmail({ to: email.trim().toLowerCase(), name: name.trim(), role, tempPassword, appUrl });

  const users2 = db.prepare(`
    SELECT u.*, s.name as store_name
    FROM users u
    LEFT JOIN stores s ON s.id = u.store_id
    ORDER BY u.id DESC
  `).all();
  res.render('admin_users', { users: users2, stores, error: null, info: 'Usuário criado. Convite enviado (ou impresso no console se SMTP não estiver configurado).' });
});

app.post('/admin/users/:id/reset-password', requireRole('ADMIN'), async (req, res) => {
  const id = Number(req.params.id);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).render('error', { message: 'Usuário não encontrado.' });

  const tempPassword = randomTempPassword();
  const hash = await hashPassword(tempPassword);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, id);

  const appUrl = process.env.APP_URL || 'http://localhost:3000';
  await sendInviteEmail({ to: user.email, name: user.name, role: user.role, tempPassword, appUrl });

  res.redirect('/admin/users');
});

app.post('/admin/users/:id/toggle', requireRole('ADMIN'), (req, res) => {
  const id = Number(req.params.id);
  db.prepare('UPDATE users SET is_active = CASE WHEN is_active=1 THEN 0 ELSE 1 END WHERE id=?').run(id);
  res.redirect('/admin/users');
});

// ---------- Account ----------
app.get('/account', requireAuth, (req, res) => {
  const u = req.session.user;
  const full = db.prepare('SELECT id,name,email,role FROM users WHERE id = ?').get(u.id);
  res.render('account', { user: full, error: null, info: null });
});

app.post('/account/password', requireAuth, async (req, res) => {
  const u = req.session.user;
  const { current_password, new_password } = req.body;
  const full = db.prepare('SELECT * FROM users WHERE id = ?').get(u.id);
  const ok = await verifyPassword(current_password, full.password_hash);
  if (!ok) return res.status(400).render('account', { user: full, error: 'Senha atual incorreta.', info: null });
  if (!new_password || new_password.length < 8) return res.status(400).render('account', { user: full, error: 'Nova senha precisa ter pelo menos 8 caracteres.', info: null });
  const hash = await hashPassword(new_password);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, u.id);
  res.render('account', { user: full, error: null, info: 'Senha alterada com sucesso.' });
});

// ---------- Error ----------
app.use((req, res) => res.status(404).render('error', { message: 'Página não encontrada.' }));

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
