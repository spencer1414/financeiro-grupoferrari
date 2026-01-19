function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.redirect('/login');
}

function requireRole(roles) {
  const allowed = Array.isArray(roles) ? roles : [roles];
  return (req, res, next) => {
    const user = req.session.user;
    if (!user) return res.redirect('/login');
    if (allowed.includes(user.role)) return next();
    return res.status(403).render('error', {
      title: 'Acesso negado',
      message: 'Você não tem permissão para acessar esta página.',
      user
    });
  };
}

module.exports = { requireAuth, requireRole };
