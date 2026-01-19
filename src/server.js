require('dotenv').config();

const path = require('path');
const express = require('express');
const session = require('express-session');
const multer = require('multer');

const { db, DB_PATH } = require('./db');
const { hashPassword, verifyPassword, generateTempPassword } = require('./utils/security');
const { parseMoneyBRL, formatMoneyBRL } = require('./utils/money');
const { toISODate, daysUntil } = require('./utils/dates');
const { sendInviteEmail } = require('./utils/email');
const { requireAuth, requireRole } = require('./middleware/auth');

const ExcelJS = require('exceljs');
const dayjs = require('dayjs');

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 }
  })
);

app.use('/public', express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const upload = multer({
  dest: path.join(__dirname, 'uploads'),
  limits: { fileSize: 15 * 1024 * 1024 }
});

// view helpers
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.formatMoneyBRL = formatMoneyBRL;
  res.locals.dayjs = dayjs;
  next();
});

function safeRedirectAfterLogin(user) {
  if (user.role === 'ADMIN') return '/admin';
  if (user.role === 'OWNER') return '/owner';
  return '/bills';
}

async function ensureSeedAdmin() {
  const data = db.load();
  if (data.users.length > 0) return;

  const defaultAdminEmail = (process.env.SEED_ADMIN_EMAIL || 'admin@exemplo.com').toLowerCase();
  const defaultAdminPass = process.env.SEED_ADMIN_PASSWORD || 'Admin@12345';
  const hash = await hashPassword(defaultAdminPass);

  const id = db.nextId(data, 'user');
  data.users.push({
    id,
    name: 'Administrador',
    email: defaultAdminEmail,
    password_hash: hash,
    role: 'ADMIN',
    store_id: null,
    is_active: true,
    created_at: db.now()
  });
  db.save(data);

  console.log('--- PRIMEIRO ACESSO ---');
  console.log('Banco:', DB_PATH);
  console.log('Admin criado:');
  console.log('Email:', defaultAdminEmail);
  console.log('Senha:', defaultAdminPass);
  console.log('Altere a senha depois do primeiro login.');
  console.log('-----------------------');
}

ensureSeedAdmin();

// ---------- Auth ----------
app.get('/', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  return res.redirect(safeRedirectAfterLogin(req.session.user));
});

app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.render('login', { title: 'Entrar', error: null });
});

app.post('/login', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  const data = db.load();
  const user = data.users.find(u => u.email === email);

  if (!user || !user.is_active) {
    return res.status(401).render('login', { title: 'Entrar', error: 'Usuário ou senha inválidos.' });
  }

  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) {
    return res.status(401).render('login', { title: 'Entrar', error: 'Usuário ou senha inválidos.' });
  }

  req.session.user = {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    store_id: user.store_id
  };
  return res.redirect('/');
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// ---------- Account ----------
app.get('/account', requireAuth, (req, res) => {
  res.render('account', { title: 'Minha conta', error: null, ok: null });
});

app.post('/account/password', requireAuth, async (req, res) => {
  const { current_password, new_password } = req.body;
  const data = db.load();
  const me = data.users.find(u => u.id === req.session.user.id);
  if (!me) return res.redirect('/login');

  const ok = await verifyPassword(String(current_password || ''), me.password_hash);
  if (!ok) {
    return res.render('account', { title: 'Minha conta', error: 'Senha atual incorreta.', ok: null });
  }
  if (!new_password || String(new_password).length < 8) {
    return res.render('account', { title: 'Minha conta', error: 'A nova senha deve ter pelo menos 8 caracteres.', ok: null });
  }

  me.password_hash = await hashPassword(String(new_password));
  db.save(data);
  res.render('account', { title: 'Minha conta', error: null, ok: 'Senha atualizada com sucesso.' });
});

// ---------- Admin ----------
app.get('/admin', requireAuth, requireRole('ADMIN'), (req, res) => {
  const data = db.load();
  const stores = [...data.stores].sort((a, b) => a.name.localeCompare(b.name));
  const users = [...data.users]
    .map(u => ({ ...u, store_name: data.stores.find(s => s.id === u.store_id)?.name || '' }))
    .sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
  res.render('admin/dashboard', { title: 'Admin', stores, users, message: null });
});

app.post('/admin/stores', requireAuth, requireRole('ADMIN'), (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim();
  if (!name) return res.redirect('/admin');

  const data = db.load();
  const id = db.nextId(data, 'store');
  data.stores.push({ id, name, email: email || null, created_at: db.now() });
  db.save(data);
  res.redirect('/admin');
});

app.post('/admin/users', requireAuth, requireRole('ADMIN'), async (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const role = String(req.body.role || '').trim();
  const store_id = req.body.store_id ? Number(req.body.store_id) : null;

  if (!name || !email || !['ADMIN', 'OWNER', 'MANAGER'].includes(role)) return res.redirect('/admin');
  if (role === 'MANAGER' && !store_id) return res.redirect('/admin');

  const data = db.load();
  if (data.users.some(u => u.email === email)) return res.redirect('/admin');

  const tempPassword = generateTempPassword(12);
  const hash = await hashPassword(tempPassword);

  const id = db.nextId(data, 'user');
  data.users.push({
    id,
    name,
    email,
    password_hash: hash,
    role,
    store_id: role === 'MANAGER' ? store_id : null,
    is_active: true,
    created_at: db.now()
  });
  db.save(data);

  const appName = process.env.APP_NAME || 'Financeiro Rede';
  const baseUrl = process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`;
  const html = `
    <div style="font-family:Arial,sans-serif;line-height:1.5">
      <h2>${appName} - Acesso liberado</h2>
      <p>Olá, <b>${name}</b>! Seu acesso foi criado.</p>
      <p><b>Login:</b> ${email}<br/>
         <b>Senha temporária:</b> ${tempPassword}</p>
      <p>Acesse: <a href="${baseUrl}/login">${baseUrl}/login</a></p>
      <p>Por segurança, altere sua senha no primeiro acesso.</p>
    </div>`;

  try {
    await sendInviteEmail({ to: email, subject: `${appName} - Seu acesso`, html });
  } catch (e) {
    console.error(e);
  }

  res.redirect('/admin');
});

// ---------- Owner dashboard ----------
app.get('/owner', requireAuth, requireRole(['OWNER', 'ADMIN']), (req, res) => {
  const data = db.load();
  const stores = [...data.stores].sort((a, b) => a.name.localeCompare(b.name));
  const openBills = data.bills
    .filter(b => b.status === 'OPEN')
    .map(b => ({ ...b, store_name: data.stores.find(s => s.id === b.store_id)?.name || '' }))
    .sort((a, b) => (a.due_date || '').localeCompare(b.due_date || ''));

  const organized = organizeBills(openBills);
  res.render('owner/dashboard', { title: 'Painel do Patrão', stores, organized });
});

// ---------- Bills ----------
app.get('/bills', requireAuth, (req, res) => {
  const user = req.session.user;
  const data = db.load();

  let bills = data.bills.filter(b => b.status === 'OPEN');
  if (user.role === 'MANAGER') bills = bills.filter(b => b.store_id === user.store_id);

  bills = bills
    .map(b => ({ ...b, store_name: data.stores.find(s => s.id === b.store_id)?.name || '' }))
    .sort((a, b) => (a.due_date || '').localeCompare(b.due_date || ''));

  const organized = organizeBills(bills);

  const stores =
    user.role === 'MANAGER'
      ? data.stores.filter(s => s.id === user.store_id)
      : [...data.stores].sort((a, b) => a.name.localeCompare(b.name));

  res.render('bills/index', { title: 'Contas a pagar', organized, stores });
});

app.get('/bills/new', requireAuth, (req, res) => {
  const user = req.session.user;
  const data = db.load();

  const stores =
    user.role === 'MANAGER'
      ? data.stores.filter(s => s.id === user.store_id)
      : [...data.stores].sort((a, b) => a.name.localeCompare(b.name));

  res.render('bills/new', { title: 'Cadastrar conta', stores, error: null });
});

app.post('/bills', requireAuth, upload.single('attachment'), (req, res) => {
  const user = req.session.user;
  const title = String(req.body.title || '').trim();
  const reason = String(req.body.reason || '').trim();
  const due_date = toISODate(req.body.due_date);
  const payment_method = String(req.body.payment_method || 'BOLETO');
  const barcode = String(req.body.barcode || '').trim();
  const pix_key = String(req.body.pix_key || '').trim();
  const urgent_today = req.body.urgent_today ? true : false;
  const notes = String(req.body.notes || '').trim();
  const amount_cents = parseMoneyBRL(req.body.amount);

  let store_id = user.store_id;
  if (user.role !== 'MANAGER') store_id = Number(req.body.store_id);

  const data = db.load();

  if (!title || !due_date || !store_id) {
    const stores =
      user.role === 'MANAGER'
        ? data.stores.filter(s => s.id === user.store_id)
        : [...data.stores].sort((a, b) => a.name.localeCompare(b.name));
    return res.status(400).render('bills/new', {
      title: 'Cadastrar conta',
      stores,
      error: 'Preencha pelo menos: Loja, Nome do débito e Data de vencimento.'
    });
  }

  const id = db.nextId(data, 'bill');
  data.bills.push({
    id,
    store_id,
    created_by_user_id: user.id,
    title,
    reason: reason || null,
    amount_cents: amount_cents === null ? null : amount_cents,
    due_date,
    payment_method: ['BOLETO', 'PIX', 'OUTRO'].includes(payment_method) ? payment_method : 'OUTRO',
    barcode: barcode || null,
    pix_key: pix_key || null,
    urgent_today,
    status: 'OPEN',
    paid_at: null,
    notes: notes || null,
    created_at: db.now(),
    updated_at: db.now()
  });

  if (req.file) {
    const aid = db.nextId(data, 'attachment');
    data.attachments.push({
      id: aid,
      bill_id: id,
      original_name: req.file.originalname,
      storage_name: req.file.filename,
      mime_type: req.file.mimetype,
      size_bytes: req.file.size,
      created_at: db.now()
    });
  }

  db.save(data);
  res.redirect('/bills');
});

app.get('/bills/:id', requireAuth, (req, res) => {
  const user = req.session.user;
  const id = Number(req.params.id);
  const data = db.load();

  const bill = data.bills.find(b => b.id === id);
  if (!bill) {
    return res.status(404).render('error', { title: 'Não encontrado', message: 'Conta não encontrada.', user });
  }
  if (user.role === 'MANAGER' && bill.store_id !== user.store_id) {
    return res.status(403).render('error', { title: 'Acesso negado', message: 'Você não pode ver contas de outras lojas.', user });
  }

  const store_name = data.stores.find(s => s.id === bill.store_id)?.name || '';
  const created_by = data.users.find(u => u.id === bill.created_by_user_id)?.name || '';
  const attachments = data.attachments.filter(a => a.bill_id === id).sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));

  res.render('bills/show', {
    title: 'Detalhes da conta',
    bill: { ...bill, store_name, created_by },
    attachments
  });
});

app.post('/bills/:id/attach', requireAuth, upload.single('attachment'), (req, res) => {
  const user = req.session.user;
  const id = Number(req.params.id);
  const data = db.load();
  const bill = data.bills.find(b => b.id === id);
  if (!bill) return res.redirect('/bills');
  if (user.role === 'MANAGER' && bill.store_id !== user.store_id) return res.redirect('/bills');

  if (req.file) {
    const aid = db.nextId(data, 'attachment');
    data.attachments.push({
      id: aid,
      bill_id: id,
      original_name: req.file.originalname,
      storage_name: req.file.filename,
      mime_type: req.file.mimetype,
      size_bytes: req.file.size,
      created_at: db.now()
    });
    db.save(data);
  }
  res.redirect(`/bills/${id}`);
});

app.post('/bills/:id/pay', requireAuth, (req, res) => {
  const user = req.session.user;
  const id = Number(req.params.id);
  const data = db.load();
  const bill = data.bills.find(b => b.id === id);
  if (!bill) return res.redirect('/bills');
  if (user.role === 'MANAGER' && bill.store_id !== user.store_id) return res.redirect('/bills');

  bill.status = 'PAID';
  bill.paid_at = db.now();
  bill.updated_at = db.now();
  db.save(data);

  res.redirect(`/bills/${id}`);
});

app.post('/bills/:id/cancel', requireAuth, requireRole(['ADMIN', 'OWNER']), (req, res) => {
  const id = Number(req.params.id);
  const data = db.load();
  const bill = data.bills.find(b => b.id === id);
  if (!bill) return res.redirect('/bills');

  bill.status = 'CANCELLED';
  bill.updated_at = db.now();
  db.save(data);

  res.redirect('/bills');
});

app.get('/history', requireAuth, (req, res) => {
  const user = req.session.user;
  const month = String(req.query.month || dayjs().format('YYYY-MM'));
  const data = db.load();

  let items = data.bills.filter(b => String(b.due_date || '').slice(0, 7) === month);
  if (user.role === 'MANAGER') items = items.filter(b => b.store_id === user.store_id);

  items = items
    .map(b => ({ ...b, store_name: data.stores.find(s => s.id === b.store_id)?.name || '' }))
    .sort((a, b) => (a.due_date || '').localeCompare(b.due_date || ''));

  res.render('history', { title: 'Histórico mensal', month, items });
});

app.get('/export.xlsx', requireAuth, async (req, res) => {
  const user = req.session.user;
  const month = String(req.query.month || dayjs().format('YYYY-MM'));
  const data = db.load();

  let rows = data.bills.filter(b => String(b.due_date || '').slice(0, 7) === month);
  if (user.role === 'MANAGER') rows = rows.filter(b => b.store_id === user.store_id);

  rows = rows
    .map(b => ({ ...b, store_name: data.stores.find(s => s.id === b.store_id)?.name || '' }))
    .sort((a, b) => (a.due_date || '').localeCompare(b.due_date || ''));

  const wb = new ExcelJS.Workbook();
  const ws = wb.addWorksheet(`Contas ${month}`);

  ws.columns = [
    { header: 'ID', key: 'id', width: 8 },
    { header: 'Loja', key: 'store_name', width: 20 },
    { header: 'Débito', key: 'title', width: 28 },
    { header: 'Motivo', key: 'reason', width: 26 },
    { header: 'Valor (R$)', key: 'amount', width: 14 },
    { header: 'Vencimento', key: 'due_date', width: 14 },
    { header: 'Método', key: 'payment_method', width: 10 },
    { header: 'Código de barras', key: 'barcode', width: 28 },
    { header: 'Pix', key: 'pix_key', width: 28 },
    { header: 'Urgente hoje', key: 'urgent_today', width: 12 },
    { header: 'Status', key: 'status', width: 10 },
    { header: 'Pago em', key: 'paid_at', width: 24 },
    { header: 'Criado em', key: 'created_at', width: 24 }
  ];

  rows.forEach(r => {
    ws.addRow({
      id: r.id,
      store_name: r.store_name,
      title: r.title,
      reason: r.reason || '',
      amount: r.amount_cents !== null && r.amount_cents !== undefined ? (r.amount_cents / 100) : '',
      due_date: r.due_date,
      payment_method: r.payment_method,
      barcode: r.barcode || '',
      pix_key: r.pix_key || '',
      urgent_today: r.urgent_today ? 'SIM' : 'NÃO',
      status: r.status,
      paid_at: r.paid_at || '',
      created_at: r.created_at || ''
    });
  });

  ws.getRow(1).font = { bold: true };

  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', `attachment; filename="contas_${month}.xlsx"`);
  await wb.xlsx.write(res);
  res.end();
});

// ---------- Helpers ----------
function organizeBills(bills) {
  const buckets = {
    overdue: [],
    today: [],
    in2days: [],
    in5days: [],
    in10days: [],
    in15days: [],
    in30days: [],
    in60days: [],
    later: []
  };

  bills.forEach(b => {
    const d = daysUntil(b.due_date);
    if (d === null) return;

    if (d < 0) buckets.overdue.push(b);
    else if (d === 0) buckets.today.push(b);
    else if (d <= 2) buckets.in2days.push(b);
    else if (d <= 5) buckets.in5days.push(b);
    else if (d <= 10) buckets.in10days.push(b);
    else if (d <= 15) buckets.in15days.push(b);
    else if (d <= 30) buckets.in30days.push(b);
    else if (d <= 60) buckets.in60days.push(b);
    else buckets.later.push(b);
  });

  return buckets;
}

app.use((req, res) => {
  res.status(404).render('error', { title: '404', message: 'Página não encontrada.', user: req.session.user || null });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log("Servidor rodando na porta:", PORT);
});
