/**
 * FidelizApp — Servidor AFIP
 * Deploy en Render igual que el servidor de WhatsApp
 * 
 * Variables de entorno requeridas en Render:
 *   AFIP_API_KEY   → clave secreta para autenticar llamadas desde FidelizApp
 *   PORT           → lo pone Render automáticamente
 */

const express  = require('express');
const fs       = require('fs');
const path     = require('path');
const os       = require('os');

const app = express();
app.use(express.json({ limit: '10mb' }));
// CORS: sólo nuestros dominios, no '*'
app.set('trust proxy', 1);
app.use((req, res, next) => {
  const origen = req.headers.origin;
  const permitidos = (process.env.ALLOWED_ORIGINS ||
    'https://fidelizapp.com.ar,https://www.fidelizapp.com.ar')
    .split(',').map(s => s.trim()).filter(Boolean);

  if (origen && permitidos.includes(origen)) {
    res.header('Access-Control-Allow-Origin', origen);
    res.header('Vary', 'Origin');
  }
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-api-key');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
  res.header('X-Content-Type-Options', 'nosniff');
  res.header('Referrer-Policy', 'no-referrer');

  if (req.method === 'OPTIONS') {
    if (origen && !permitidos.includes(origen)) return res.sendStatus(403);
    return res.sendStatus(204);
  }
  next();
});

// ── Configuración ──────────────────────────────────────────────────────────
const API_KEY   = process.env.AFIP_API_KEY || '';
const CERTS_DIR = process.env.CERTS_DIR    || path.join(os.tmpdir(), 'afip-certs');

// Autenticación de usuarios reales contra Supabase
const SUPABASE_URL   = process.env.SUPABASE_URL   || '';
const SUPABASE_ANON  = process.env.SUPABASE_ANON_KEY || '';
const SUPERADMIN     = (process.env.SUPERADMIN_EMAIL || '').toLowerCase().trim();

// Sólo estos orígenes pueden llamar al servidor desde un navegador
const ORIGENES = (process.env.ALLOWED_ORIGINS ||
  'https://fidelizapp.com.ar,https://www.fidelizapp.com.ar')
  .split(',').map(s => s.trim()).filter(Boolean);

if (!fs.existsSync(CERTS_DIR)) fs.mkdirSync(CERTS_DIR, { recursive: true });

// ── Límite de solicitudes por IP ───────────────────────────────────────────
const _hits = new Map();
function rateLimit(max, ventanaMs) {
  return (req, res, next) => {
    const ip = (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
    const ahora = Date.now();
    const clave = ip + '|' + req.path;
    let reg = _hits.get(clave);
    if (!reg || ahora - reg.desde > ventanaMs) reg = { desde: ahora, n: 0 };
    reg.n++;
    _hits.set(clave, reg);
    if (_hits.size > 5000) {   // limpieza periódica
      for (const [k, v] of _hits) if (ahora - v.desde > ventanaMs) _hits.delete(k);
    }
    if (reg.n > max) {
      return res.status(429).json({ error: 'Demasiadas solicitudes. Esperá un momento.' });
    }
    next();
  };
}

// ── Verificación del usuario contra Supabase ───────────────────────────────
const _userCache = new Map();   // token → { user, exp }

async function verificarUsuario(token) {
  if (!token) return null;
  if (!SUPABASE_URL || !SUPABASE_ANON) {
    throw new Error('El servidor no tiene configurado SUPABASE_URL / SUPABASE_ANON_KEY');
  }

  const cacheado = _userCache.get(token);
  if (cacheado && cacheado.exp > Date.now()) return cacheado.user;

  const r = await fetch(SUPABASE_URL.replace(/\/+$/, '') + '/auth/v1/user', {
    headers: { 'Authorization': 'Bearer ' + token, 'apikey': SUPABASE_ANON }
  });
  if (!r.ok) return null;

  const u = await r.json();
  if (!u || !u.id) return null;

  const user = { id: u.id, email: (u.email || '').toLowerCase() };
  _userCache.set(token, { user, exp: Date.now() + 5 * 60 * 1000 });   // 5 minutos
  if (_userCache.size > 2000) _userCache.clear();
  return user;
}

// ── Middleware: exige un usuario logueado en FidelizApp ────────────────────
async function requiereUsuario(req, res, next) {
  try {
    // Origen: sólo desde nuestra web
    const origen = req.headers.origin || req.headers.referer || '';
    if (origen && !ORIGENES.some(o => origen.startsWith(o))) {
      console.warn('[SEG] Origen rechazado:', origen);
      return res.status(403).json({ error: 'Origen no permitido' });
    }

    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7).trim() : '';
    const user = await verificarUsuario(token);
    if (!user) return res.status(401).json({ error: 'Sesión inválida o expirada. Volvé a iniciar sesión.' });

    req.user = user;
    req.esSuperadmin = !!SUPERADMIN && user.email === SUPERADMIN;
    next();
  } catch (e) {
    console.error('[SEG] error verificando usuario:', e.message);
    res.status(500).json({ error: 'No se pudo verificar la sesión' });
  }
}

// ── Middleware: sólo el superadmin ─────────────────────────────────────────
async function requiereSuperadmin(req, res, next) {
  requiereUsuario(req, res, () => {
    if (!req.esSuperadmin) {
      console.warn('[SEG] Intento de acceso admin por', req.user && req.user.email);
      return res.status(403).json({ error: 'Sólo el administrador de la plataforma puede hacer esto' });
    }
    next();
  });
}

// ── Compatibilidad: llamadas servidor-a-servidor con clave ────────────────
// Se usa sólo si configurás AFIP_API_KEY. No la usa el navegador.
function auth(req, res, next) {
  const k = req.headers['x-api-key'];
  if (API_KEY && k === API_KEY) { req.esSuperadmin = true; return next(); }
  return requiereSuperadmin(req, res, next);
}

// ══════════════════════════════════════════════════════════════════════════════
// ALMACÉN DE CERTIFICADOS — Supabase (permanente) con respaldo en disco
//
// El disco de Render se borra en cada reinicio. Los certificados viven en
// Supabase, cifrados, y se copian al disco sólo mientras el servidor corre.
// ══════════════════════════════════════════════════════════════════════════════
const crypto = require('crypto');

// El CUIT puede llegar con guiones o puntos. Adentro siempre se usa sólo dígitos.
function _cuit(x) { return String(x || '').replace(/\D/g, ''); }


// Clave para cifrar los certificados antes de guardarlos
const CERT_SECRET = process.env.CERT_SECRET || '';
const _claveCifrado = CERT_SECRET
  ? crypto.createHash('sha256').update(CERT_SECRET).digest()
  : null;

function cifrar(texto) {
  if (!_claveCifrado) return texto;                 // sin clave, se guarda tal cual
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', _claveCifrado, iv);
  const enc = Buffer.concat([c.update(texto, 'utf8'), c.final()]);
  return 'v1:' + iv.toString('base64') + ':' + c.getAuthTag().toString('base64') + ':' + enc.toString('base64');
}

function descifrar(dato) {
  if (!dato || !String(dato).startsWith('v1:')) return dato;
  if (!_claveCifrado) throw new Error('Falta CERT_SECRET para descifrar los certificados');
  const [, ivB, tagB, datosB] = String(dato).split(':');
  const d = crypto.createDecipheriv('aes-256-gcm', _claveCifrado, Buffer.from(ivB, 'base64'));
  d.setAuthTag(Buffer.from(tagB, 'base64'));
  return Buffer.concat([d.update(Buffer.from(datosB, 'base64')), d.final()]).toString('utf8');
}

// Acceso a la tabla afip_certificados de Supabase
const SUPA_SERVICE = process.env.SUPABASE_SERVICE_KEY || '';

function supaDisponible() {
  return !!(SUPABASE_URL && SUPA_SERVICE);
}

async function supaFetch(ruta, opciones = {}) {
  const r = await fetch(SUPABASE_URL.replace(/\/+$/, '') + '/rest/v1' + ruta, {
    ...opciones,
    headers: {
      'apikey': SUPA_SERVICE,
      'Authorization': 'Bearer ' + SUPA_SERVICE,
      'Content-Type': 'application/json',
      'Prefer': 'resolution=merge-duplicates,return=representation',
      ...(opciones.headers || {})
    }
  });
  const txt = await r.text();
  let data; try { data = txt ? JSON.parse(txt) : null; } catch (_) { data = txt; }
  if (!r.ok) throw new Error((data && data.message) || ('Supabase HTTP ' + r.status));
  return data;
}

// Guarda el certificado de un CUIT de forma permanente
async function guardarCertificado(cuitRaw, cert, key, userId) {
  const cuit = _cuit(cuitRaw);
  // 1) Siempre al disco, para uso inmediato
  fs.writeFileSync(path.join(CERTS_DIR, `${cuit}.crt`), cert, 'utf8');
  fs.writeFileSync(path.join(CERTS_DIR, `${cuit}.key`), key,  'utf8');
  fs.writeFileSync(path.join(CERTS_DIR, `${cuit}.owner`), userId, 'utf8');

  // 2) Y a Supabase, para que sobreviva a los reinicios
  if (!supaDisponible()) {
    console.warn('⚠️  Sin SUPABASE_SERVICE_KEY: el certificado de', cuit, 'se pierde al reiniciar.');
    return { permanente: false };
  }
  await supaFetch('/afip_certificados', {
    method: 'POST',
    body: JSON.stringify({
      cuit: cuit,
      cert: cifrar(cert),
      key_privada: cifrar(key),
      user_id: userId,
      actualizado: new Date().toISOString()
    })
  });
  console.log('[AFIP] Certificado de', cuit, 'guardado en Supabase');
  return { permanente: true };
}

// Recupera el certificado desde Supabase si no está en disco
async function asegurarCertificado(cuitRaw) {
  const cuit = _cuit(cuitRaw);
  const certPath = path.join(CERTS_DIR, `${cuit}.crt`);
  if (fs.existsSync(certPath)) return true;
  if (!supaDisponible()) return false;

  const filas = await supaFetch('/afip_certificados?cuit=eq.' + encodeURIComponent(cuit) + '&select=*');
  if (!filas || !filas.length) return false;

  const f = filas[0];
  fs.writeFileSync(certPath, descifrar(f.cert), 'utf8');
  fs.writeFileSync(path.join(CERTS_DIR, `${cuit}.key`), descifrar(f.key_privada), 'utf8');
  fs.writeFileSync(path.join(CERTS_DIR, `${cuit}.owner`), f.user_id || '', 'utf8');
  console.log('[AFIP] Certificado de', cuit, 'restaurado desde Supabase');
  return true;
}

// Quién registró ese CUIT (consulta disco, y si no está, Supabase)
async function dueñoDelCuit(cuitRaw) {
  const cuit = _cuit(cuitRaw);
  const p = path.join(CERTS_DIR, `${cuit}.owner`);
  if (fs.existsSync(p)) return fs.readFileSync(p, 'utf8').trim();
  if (!supaDisponible()) return null;
  const filas = await supaFetch('/afip_certificados?cuit=eq.' + encodeURIComponent(cuit) + '&select=user_id');
  return (filas && filas.length) ? filas[0].user_id : null;
}

// ── Cache de instancias Afip por CUIT ──────────────────────────────────────
const cache = {};

async function getAfip(cuitRaw, test) {
  const cuit = _cuit(cuitRaw);
  if (cuit.length !== 11) throw new Error('CUIT inválido: ' + cuitRaw);
  const certPath  = path.join(CERTS_DIR, `${cuit}.crt`);
  const keyPath   = path.join(CERTS_DIR, `${cuit}.key`);
  const tokensDir = path.join(CERTS_DIR, `${cuit}_tokens`);

  // Si el disco se borró por un reinicio, lo recuperamos de Supabase
  if (!fs.existsSync(certPath)) await asegurarCertificado(cuit);

  const Afip = require('@afipsdk/afip.js');

  if (!fs.existsSync(certPath)) {
    throw new Error(`Certificado no registrado para CUIT ${cuit}. Cargalo en Configuración → AFIP primero.`);
  }

  if (!fs.existsSync(tokensDir)) fs.mkdirSync(tokensDir, { recursive: true });

  const key = `${cuit}_${test ? 'test' : 'prod'}`;
  if (!cache[key]) {
    cache[key] = new Afip({
      CUIT:       parseInt(cuit),
      cert:       certPath,
      key:        keyPath,
      production: !test,
      res_folder: tokensDir
    });
  }
  return cache[key];
}

// ── POST /register-cert — cargar certificado AFIP de un negocio ───────────
app.post('/register-cert', rateLimit(10, 60000), requiereUsuario, async (req, res) => {
  try {
    const { cuit, cert, key } = req.body;
    if (!cuit || !cert || !key)
      return res.status(400).json({ error: 'Faltan datos: cuit, cert, key' });

    const limpio = _cuit(cuit);
    if (limpio.length !== 11) return res.status(400).json({ error: 'CUIT inválido' });

    // Validación mínima del contenido: que sean archivos PEM de verdad
    if (!/-----BEGIN CERTIFICATE-----/.test(cert))
      return res.status(400).json({ error: 'El archivo de certificado no parece un .crt válido' });
    if (!/-----BEGIN (RSA )?PRIVATE KEY-----/.test(key))
      return res.status(400).json({ error: 'El archivo de clave no parece un .key válido' });

    // Cada CUIT queda asociado al usuario que lo registró primero.
    // Después, sólo ese usuario (o el superadmin) puede reemplazarlo.
    const dueño = await dueñoDelCuit(limpio);
    if (dueño && dueño !== req.user.id && !req.esSuperadmin) {
      console.warn('[SEG]', req.user.email, 'quiso pisar el certificado del CUIT', limpio);
      return res.status(403).json({
        error: 'Ese CUIT ya tiene un certificado cargado por otra cuenta. Contactate con soporte.'
      });
    }

    const guardado = await guardarCertificado(limpio, cert, key, req.user.id);
    console.log('[AFIP] Certificado de CUIT', limpio, 'registrado por', req.user.email);

    // Limpiar cache para forzar nueva instancia con el nuevo certificado
    delete cache[`${limpio}_test`];
    delete cache[`${limpio}_prod`];

    res.json({
      ok: true,
      mensaje: `Certificado registrado para CUIT ${limpio}`,
      permanente: guardado.permanente,
      aviso: guardado.permanente ? null
        : 'Guardado sólo en memoria: configurá SUPABASE_SERVICE_KEY para que sobreviva a los reinicios.'
    });
  } catch (e) {
    console.error('[AFIP] register-cert error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── POST /ultimo-cbte — último número de comprobante emitido ──────────────
app.post('/ultimo-cbte', rateLimit(60, 60000), requiereUsuario, async (req, res) => {
  try {
    const { cuit, ptoVenta, tipoCbte, test } = req.body;
    await verificarCuitPropio(req, cuit);
    const afip  = await getAfip(cuit, !!test);
    const ultimo = await afip.ElectronicBilling.getLastVoucher(
      parseInt(ptoVenta), parseInt(tipoCbte)
    );
    res.json({ ok: true, ultimo });
  } catch (e) {
    console.error('[AFIP] ultimo-cbte error:', e.message);
    res.status(e.status || 500).json({ error: e.message });
  }
});

// ── POST /factura — emitir comprobante y obtener CAE ─────────────────────
// Verifica que el usuario sea dueño del CUIT con el que quiere operar
async function verificarCuitPropio(req, cuit) {
  const limpio = _cuit(cuit);
  const dueño = await dueñoDelCuit(limpio);
  if (!dueño) {
    const e = new Error(`No hay certificado registrado para el CUIT ${limpio}. Cargalo en Configuración → AFIP.`);
    e.status = 400; throw e;
  }
  if (dueño !== req.user.id && !req.esSuperadmin) {
    const e = new Error('No podés facturar con un CUIT que no es tuyo');
    e.status = 403; throw e;
  }
  return limpio;
}

app.post('/factura', rateLimit(60, 60000), requiereUsuario, async (req, res) => {
  try {
    const { cuit, test, factura } = req.body;
    await verificarCuitPropio(req, cuit);
    // factura = { PtoVta, CbteTipo, Concepto, DocTipo, DocNro,
    //             CbteFch, ImpTotal, ImpNeto, ImpIVA, ImpTrib,
    //             MonId, MonCotiz, Iva[] }

    const afip = await getAfip(cuit, !!test);

    // Obtener próximo número
    const ultimo = await afip.ElectronicBilling.getLastVoucher(
      factura.PtoVta, factura.CbteTipo
    );
    const nro = ultimo + 1;

    const data = {
      CantReg:    1,
      PtoVta:     factura.PtoVta,
      CbteTipo:   factura.CbteTipo,
      Concepto:   factura.Concepto   || 1,
      DocTipo:    factura.DocTipo    || 99,   // 99 = consumidor final
      DocNro:     factura.DocNro     || 0,
      CbteDesde:  nro,
      CbteHasta:  nro,
      CbteFch:    factura.CbteFch    || _hoy(),
      ImpTotal:   factura.ImpTotal,
      ImpTotConc: 0,
      ImpNeto:    factura.ImpNeto,
      ImpOpEx:    0,
      ImpIVA:     factura.ImpIVA     || 0,
      ImpTrib:    0,
      MonId:      'PES',
      MonCotiz:   1,
      ...(factura.Iva && factura.Iva.length ? { Iva: factura.Iva } : {})
    };

    const result = await afip.ElectronicBilling.createVoucher(data);

    console.log(`[AFIP] Factura emitida CUIT ${cuit} — CAE: ${result.CAE} Nro: ${nro}`);
    res.json({
      ok:             true,
      cae:            result.CAE,
      caeFechaVto:    result.CAEFchVto,
      nroComprobante: nro,
      ptoVenta:       factura.PtoVta,
      tipoCbte:       factura.CbteTipo
    });
  } catch (e) {
    console.error('[AFIP] factura error:', e.message);
    res.status(e.status || 500).json({ error: e.message });
  }
});

// ── POST /puntos-venta — listar puntos de venta habilitados ───────────────
app.post('/puntos-venta', rateLimit(30, 60000), requiereUsuario, async (req, res) => {
  try {
    const { cuit, test } = req.body;
    await verificarCuitPropio(req, cuit);
    const afip = await getAfip(cuit, !!test);
    const pts  = await afip.ElectronicBilling.getSalesPoints();
    res.json({ ok: true, puntos: pts });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── GET /padron?cuit=XXXXXXXXXXX — razón social real desde el padrón AFIP ──
// Usa el primer CUIT con certificado registrado como "consultante" ante AFIP.
app.get('/padron', rateLimit(30, 60000), requiereUsuario, async (req, res) => {
  try {
    const cuitConsultado = _cuit(req.query.cuit);
    if (cuitConsultado.length !== 11) {
      return res.status(400).json({ ok: false, error: 'CUIT inválido (deben ser 11 dígitos)' });
    }

    // CUIT que hace la consulta: el propio, o el primero con certificado cargado
    let cuitConsultante = _cuit(req.query.desde);
    if (!cuitConsultante) {
      const disponibles = fs.existsSync(CERTS_DIR)
        ? fs.readdirSync(CERTS_DIR).filter(f => f.endsWith('.crt')).map(f => f.replace('.crt', ''))
        : [];
      cuitConsultante = disponibles.includes(cuitConsultado) ? cuitConsultado : disponibles[0];
    }
    if (!cuitConsultante) {
      return res.status(400).json({ ok: false, error: 'No hay ningún certificado registrado en el servidor' });
    }

    const afip = await getAfip(cuitConsultante, false);

    let data = null;
    // Padrón A13 es el más completo; si el CUIT no tiene ese WS habilitado, probamos A5 y A4
    for (const ws of ['RegisterScopeThirteen', 'RegisterScopeFive', 'RegisterScopeFour']) {
      if (!afip[ws]) continue;
      try {
        data = await afip[ws].getTaxpayerDetails(Number(cuitConsultado));
        if (data) break;
      } catch (_) { /* probamos el siguiente */ }
    }

    if (!data) {
      return res.json({ ok: false, error: 'AFIP no devolvió datos para ese CUIT' });
    }

    const p = data.datosGenerales || data;
    const razonSocial = (
      p.razonSocial ||
      [p.apellido, p.nombre].filter(Boolean).join(', ')
    );

    if (!razonSocial) {
      return res.json({ ok: false, error: 'El padrón no devolvió razón social' });
    }

    // Determinar condición frente al IVA
    let ivaCodigo = '';
    let condicionIva = '';
    const mono = data.datosMonotributo;
    const reg  = data.datosRegimenGeneral;
    if (mono) {
      ivaCodigo = 'MO';
      condicionIva = 'Monotributista' + (mono.categoriaMonotributo ? ' Cat. ' + mono.categoriaMonotributo : '');
    } else if (reg) {
      const impuestos = (reg.impuesto || []).map(i => i.idImpuesto);
      if (impuestos.includes(30)) { ivaCodigo = 'RI'; condicionIva = 'Responsable Inscripto'; }
      else { ivaCodigo = 'EX'; condicionIva = 'Exento / No alcanzado'; }
    }

    res.json({
      ok: true,
      cuit: cuitConsultado,
      razonSocial: String(razonSocial).trim(),
      tipoPersona: p.tipoPersona || '',
      estado: p.estadoClave || '',
      domicilio: (p.domicilioFiscal && p.domicilioFiscal.direccion) || '',
      localidad: (p.domicilioFiscal && p.domicilioFiscal.localidad) || '',
      provincia: (p.domicilioFiscal && p.domicilioFiscal.descripcionProvincia) || '',
      condicionIva,
      ivaCodigo
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// MERCADO PAGO — Suscripciones recurrentes (preapproval)
//
// El Access Token NUNCA debe estar en el HTML. Vive sólo acá, como variable
// de entorno en Render: MP_ACCESS_TOKEN
// ══════════════════════════════════════════════════════════════════════════════
const MP_TOKEN   = process.env.MP_ACCESS_TOKEN || '';
const MP_API     = 'https://api.mercadopago.com';
const APP_URL    = process.env.APP_URL || 'https://fidelizapp.com.ar';

async function mpFetch(ruta, opciones = {}) {
  if (!MP_TOKEN) throw new Error('Falta configurar MP_ACCESS_TOKEN en el servidor');
  const r = await fetch(MP_API + ruta, {
    ...opciones,
    headers: {
      'Authorization': 'Bearer ' + MP_TOKEN,
      'Content-Type': 'application/json',
      ...(opciones.headers || {})
    }
  });
  const texto = await r.text();
  let data;
  try { data = texto ? JSON.parse(texto) : {}; } catch (_) { data = { raw: texto }; }
  if (!r.ok) {
    const msg = data.message || data.error || ('HTTP ' + r.status);
    const err = new Error(msg);
    err.detalle = data;
    err.status = r.status;
    throw err;
  }
  return data;
}

// ── POST /mp/suscribir — crea la suscripción recurrente ───────────────────
// body: { email, cardTokenId, monto, plan, negocioId, dni }
app.post('/mp/suscribir', rateLimit(10, 60000), requiereUsuario, async (req, res) => {
  try {
    const { email, cardTokenId, monto, plan, negocioId } = req.body;
    if (!email)       return res.status(400).json({ ok:false, error:'Falta el email del pagador' });
    if (!cardTokenId) return res.status(400).json({ ok:false, error:'Falta el token de tarjeta' });
    if (!monto || monto <= 0) return res.status(400).json({ ok:false, error:'Importe inválido' });

    // La referencia externa siempre la pone el SERVIDOR con el id del usuario
    // autenticado. Así nadie puede hacerse pasar por otro negocio.
    const body = {
      reason: 'FidelizApp — ' + (plan || 'Suscripción mensual'),
      external_reference: req.user.id + (negocioId ? ('|' + negocioId) : ''),
      payer_email: req.user.email || email,
      card_token_id: cardTokenId,
      back_url: APP_URL,
      status: 'authorized',              // cobra el primer período de inmediato
      auto_recurring: {
        frequency: 1,
        frequency_type: 'months',
        transaction_amount: Number(monto),
        currency_id: 'ARS'
      }
    };

    // Si el plan fue creado en el panel de Mercado Pago, lo asociamos.
    // Así las suscripciones quedan agrupadas bajo ese plan en el panel.
    const planId = req.body.preapprovalPlanId;
    if (planId) body.preapproval_plan_id = String(planId).trim();

    const sub = await mpFetch('/preapproval', { method:'POST', body: JSON.stringify(body) });

    res.json({
      ok: true,
      id: sub.id,
      status: sub.status,
      proximoCobro: sub.next_payment_date || null,
      init_point: sub.init_point || null,
      resumen: {
        plan: plan || '',
        importe: Number(monto),
        periodicidad: 'mensual',
        email: email
      }
    });
  } catch (e) {
    res.status(e.status || 500).json({ ok:false, error: e.message, detalle: e.detalle || null });
  }
});

// ── Comprueba que la suscripción le pertenezca a quien la quiere tocar ────
async function verificarPropiedad(req, preapprovalId) {
  const sub = await mpFetch('/preapproval/' + preapprovalId);
  const ref = String(sub.external_reference || '');
  const esDelUsuario = ref === req.user.id || ref.startsWith(req.user.id + '|');
  if (!esDelUsuario && !req.esSuperadmin) {
    const err = new Error('Esa suscripción no te pertenece');
    err.status = 403;
    throw err;
  }
  return sub;
}

// ── GET /mp/planes — lista los planes creados en el panel de Mercado Pago ──
app.get('/mp/planes', rateLimit(30, 60000), requiereSuperadmin, async (req, res) => {
  try {
    const r = await mpFetch('/preapproval_plan/search?status=active');
    const planes = (r.results || []).map(p => ({
      id: p.id,
      nombre: p.reason,
      importe: p.auto_recurring ? p.auto_recurring.transaction_amount : null,
      frecuencia: p.auto_recurring ? (p.auto_recurring.frequency + ' ' + p.auto_recurring.frequency_type) : '',
      suscriptores: p.subscribed || 0,
      link: p.init_point || null
    }));
    res.json({ ok: true, planes });
  } catch (e) {
    res.status(e.status || 500).json({ ok:false, error: e.message });
  }
});

// ── POST /mp/cancelar — BOTÓN DE BAJA: corta el débito de verdad ──────────
// body: { preapprovalId }
app.post('/mp/cancelar', rateLimit(10, 60000), requiereUsuario, async (req, res) => {
  try {
    const { preapprovalId } = req.body;
    if (!preapprovalId) return res.status(400).json({ ok:false, error:'Falta el id de la suscripción' });

    await verificarPropiedad(req, preapprovalId);

    const sub = await mpFetch('/preapproval/' + preapprovalId, {
      method: 'PUT',
      body: JSON.stringify({ status: 'cancelled' })
    });

    console.log('[BAJA]', req.user.email, '→', preapprovalId, sub.status);
    res.json({ ok:true, id: sub.id, status: sub.status, cancelada: sub.status === 'cancelled' });
  } catch (e) {
    res.status(e.status || 500).json({ ok:false, error: e.message, detalle: e.detalle || null });
  }
});

// ── POST /mp/pausar — suspende sin dar de baja ────────────────────────────
app.post('/mp/pausar', rateLimit(10, 60000), requiereUsuario, async (req, res) => {
  try {
    const { preapprovalId } = req.body;
    if (!preapprovalId) return res.status(400).json({ ok:false, error:'Falta el id de la suscripción' });
    await verificarPropiedad(req, preapprovalId);
    const sub = await mpFetch('/preapproval/' + preapprovalId, {
      method: 'PUT', body: JSON.stringify({ status: 'paused' })
    });
    res.json({ ok:true, id: sub.id, status: sub.status });
  } catch (e) {
    res.status(e.status || 500).json({ ok:false, error: e.message });
  }
});

// ── GET /mp/suscripcion/:id — estado real en Mercado Pago ─────────────────
app.get('/mp/suscripcion/:id', rateLimit(60, 60000), requiereUsuario, async (req, res) => {
  try {
    const sub = await verificarPropiedad(req, req.params.id);
    res.json({
      ok: true,
      id: sub.id,
      status: sub.status,
      importe: sub.auto_recurring ? sub.auto_recurring.transaction_amount : null,
      proximoCobro: sub.next_payment_date || null,
      email: sub.payer_email || null,
      creada: sub.date_created || null
    });
  } catch (e) {
    res.status(e.status || 500).json({ ok:false, error: e.message });
  }
});

// ── POST /mp/reembolsar — ARREPENTIMIENTO: cancela y devuelve lo cobrado ──
// body: { preapprovalId }
app.post('/mp/reembolsar', rateLimit(5, 60000), requiereUsuario, async (req, res) => {
  try {
    const { preapprovalId } = req.body;
    if (!preapprovalId) return res.status(400).json({ ok:false, error:'Falta el id de la suscripción' });

    await verificarPropiedad(req, preapprovalId);

    // 1) Cancelamos la suscripción para que no se generen más cobros
    await mpFetch('/preapproval/' + preapprovalId, {
      method: 'PUT', body: JSON.stringify({ status: 'cancelled' })
    });

    // 2) Buscamos los pagos ya realizados por esa suscripción
    const busq = await mpFetch('/v1/payments/search?preapproval_id=' + encodeURIComponent(preapprovalId));
    const pagos = (busq.results || []).filter(p => p.status === 'approved');

    // 3) Reembolsamos cada uno
    const reembolsos = [];
    for (const pago of pagos) {
      try {
        const r = await mpFetch('/v1/payments/' + pago.id + '/refunds', { method:'POST', body: JSON.stringify({}) });
        reembolsos.push({ pagoId: pago.id, monto: pago.transaction_amount, refundId: r.id, ok: true });
      } catch (err) {
        reembolsos.push({ pagoId: pago.id, monto: pago.transaction_amount, ok: false, error: err.message });
      }
    }

    res.json({ ok:true, cancelada:true, pagosEncontrados: pagos.length, reembolsos });
  } catch (e) {
    res.status(e.status || 500).json({ ok:false, error: e.message, detalle: e.detalle || null });
  }
});

// ── POST /mp/webhook — notificaciones de Mercado Pago ─────────────────────
// Configurar esta URL en el panel de MP. NO lleva x-api-key: la llama Mercado Pago.
app.post('/mp/webhook', async (req, res) => {
  try {
    const tipo = req.body.type || req.query.type;
    const id   = (req.body.data && req.body.data.id) || req.query['data.id'];
    console.log('[MP webhook]', tipo, id);

    if (tipo === 'subscription_preapproval' && id) {
      const sub = await mpFetch('/preapproval/' + id);
      console.log('[MP] suscripción', sub.id, '→', sub.status, '| ref:', sub.external_reference);
      // Acá podés actualizar tu base (Supabase) con el estado real.
    }
    if (tipo === 'payment' && id) {
      const pago = await mpFetch('/v1/payments/' + id);
      console.log('[MP] pago', pago.id, '→', pago.status, '| $', pago.transaction_amount);
    }
    res.sendStatus(200);   // MP reintenta si no devolvés 200/201
  } catch (e) {
    console.error('[MP webhook] error:', e.message);
    res.sendStatus(200);
  }
});

// ── GET /mp/estado — diagnóstico de la configuración ──────────────────────
app.get('/mp/estado', rateLimit(30, 60000), requiereSuperadmin, async (req, res) => {
  if (!MP_TOKEN) return res.json({ ok:false, configurado:false, error:'Falta MP_ACCESS_TOKEN' });
  try {
    const me = await mpFetch('/users/me');
    res.json({
      ok: true, configurado: true,
      cuenta: me.nickname || me.email,
      pais: me.site_id,
      modo: MP_TOKEN.startsWith('TEST-') ? 'PRUEBA' : 'PRODUCCIÓN'
    });
  } catch (e) {
    res.json({ ok:false, configurado:true, error:'Token inválido o sin permisos: ' + e.message });
  }
});

// ── GET /health ────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    ok: true,
    servicio: 'FidelizApp AFIP Server',
    version: '2.0.0',
    seguridad: {
      autenticacion: (SUPABASE_URL && SUPABASE_ANON) ? 'Supabase (usuario real)' : '⚠️ SIN CONFIGURAR',
      superadmin:    SUPERADMIN ? 'configurado' : '⚠️ SIN CONFIGURAR',
      certificados:  supaDisponible()
        ? (CERT_SECRET ? 'Supabase, cifrados' : '⚠️ Supabase SIN CIFRAR (falta CERT_SECRET)')
        : '⚠️ Sólo en disco temporal — se pierden al reiniciar',
      origenes:      ORIGENES
    }
  });
});

// Aviso al arrancar si falta configuración de seguridad
if (!SUPABASE_URL || !SUPABASE_ANON) {
  console.warn('⚠️  FALTAN SUPABASE_URL y/o SUPABASE_ANON_KEY: las llamadas del navegador serán rechazadas.');
}
if (!SUPERADMIN) {
  console.warn('⚠️  FALTA SUPERADMIN_EMAIL: nadie va a poder usar los endpoints de administración.');
}
if (!supaDisponible()) {
  console.warn('⚠️  FALTA SUPABASE_SERVICE_KEY: los certificados AFIP se van a perder en cada reinicio.');
} else if (!CERT_SECRET) {
  console.warn('⚠️  FALTA CERT_SECRET: los certificados se guardan SIN CIFRAR.');
}

// ── Helper: fecha hoy YYYYMMDD ─────────────────────────────────────────────
function _hoy() {
  return new Date().toISOString().slice(0,10).replace(/-/g, '');
}

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`[AFIP] Servidor corriendo en puerto ${PORT}`));
