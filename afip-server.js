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
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, x-api-key');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ── Configuración ──────────────────────────────────────────────────────────
const API_KEY   = process.env.AFIP_API_KEY || 'fidelizapp-afip-key';
const CERTS_DIR = process.env.CERTS_DIR    || path.join(os.tmpdir(), 'afip-certs');

if (!fs.existsSync(CERTS_DIR)) fs.mkdirSync(CERTS_DIR, { recursive: true });

// ── Auth middleware ────────────────────────────────────────────────────────
function auth(req, res, next) {
  const k = req.headers['x-api-key'] || (req.body && req.body.apiKey);
  if (k !== API_KEY) return res.status(401).json({ error: 'No autorizado' });
  next();
}

// ── Cache de instancias Afip por CUIT ──────────────────────────────────────
const cache = {};

async function getAfip(cuit, test) {
  const Afip = require('@afipsdk/afip.js');
  const certPath  = path.join(CERTS_DIR, `${cuit}.crt`);
  const keyPath   = path.join(CERTS_DIR, `${cuit}.key`);
  const tokensDir = path.join(CERTS_DIR, `${cuit}_tokens`);

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
app.post('/register-cert', auth, async (req, res) => {
  try {
    const { cuit, cert, key } = req.body;
    if (!cuit || !cert || !key)
      return res.status(400).json({ error: 'Faltan datos: cuit, cert, key' });

    fs.writeFileSync(path.join(CERTS_DIR, `${cuit}.crt`), cert, 'utf8');
    fs.writeFileSync(path.join(CERTS_DIR, `${cuit}.key`), key,  'utf8');

    // Limpiar cache para forzar nueva instancia con nuevo certificado
    delete cache[`${cuit}_test`];
    delete cache[`${cuit}_prod`];

    console.log(`[AFIP] Certificado guardado para CUIT ${cuit}`);
    res.json({ ok: true, mensaje: `Certificado registrado para CUIT ${cuit}` });
  } catch (e) {
    console.error('[AFIP] register-cert error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── POST /ultimo-cbte — último número de comprobante emitido ──────────────
app.post('/ultimo-cbte', auth, async (req, res) => {
  try {
    const { cuit, ptoVenta, tipoCbte, test } = req.body;
    const afip  = await getAfip(cuit, !!test);
    const ultimo = await afip.ElectronicBilling.getLastVoucher(
      parseInt(ptoVenta), parseInt(tipoCbte)
    );
    res.json({ ok: true, ultimo });
  } catch (e) {
    console.error('[AFIP] ultimo-cbte error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── POST /factura — emitir comprobante y obtener CAE ─────────────────────
app.post('/factura', auth, async (req, res) => {
  try {
    const { cuit, test, factura } = req.body;
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
    res.status(500).json({ error: e.message });
  }
});

// ── POST /puntos-venta — listar puntos de venta habilitados ───────────────
app.post('/puntos-venta', auth, async (req, res) => {
  try {
    const { cuit, test } = req.body;
    const afip = await getAfip(cuit, !!test);
    const pts  = await afip.ElectronicBilling.getSalesPoints();
    res.json({ ok: true, puntos: pts });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── GET /padron?cuit=XXXXXXXXXXX — razón social real desde el padrón AFIP ──
// Usa el primer CUIT con certificado registrado como "consultante" ante AFIP.
app.get('/padron', auth, async (req, res) => {
  try {
    const cuitConsultado = String(req.query.cuit || '').replace(/\D/g, '');
    if (cuitConsultado.length !== 11) {
      return res.status(400).json({ ok: false, error: 'CUIT inválido (deben ser 11 dígitos)' });
    }

    // CUIT que hace la consulta: el propio, o el primero con certificado cargado
    let cuitConsultante = String(req.query.desde || '').replace(/\D/g, '');
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
app.post('/mp/suscribir', auth, async (req, res) => {
  try {
    const { email, cardTokenId, monto, plan, negocioId } = req.body;
    if (!email)       return res.status(400).json({ ok:false, error:'Falta el email del pagador' });
    if (!cardTokenId) return res.status(400).json({ ok:false, error:'Falta el token de tarjeta' });
    if (!monto || monto <= 0) return res.status(400).json({ ok:false, error:'Importe inválido' });

    const body = {
      reason: 'FidelizApp — ' + (plan || 'Suscripción mensual'),
      external_reference: String(negocioId || ''),
      payer_email: email,
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

// ── GET /mp/planes — lista los planes creados en el panel de Mercado Pago ──
app.get('/mp/planes', auth, async (req, res) => {
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
app.post('/mp/cancelar', auth, async (req, res) => {
  try {
    const { preapprovalId } = req.body;
    if (!preapprovalId) return res.status(400).json({ ok:false, error:'Falta el id de la suscripción' });

    const sub = await mpFetch('/preapproval/' + preapprovalId, {
      method: 'PUT',
      body: JSON.stringify({ status: 'cancelled' })
    });

    res.json({ ok:true, id: sub.id, status: sub.status, cancelada: sub.status === 'cancelled' });
  } catch (e) {
    res.status(e.status || 500).json({ ok:false, error: e.message, detalle: e.detalle || null });
  }
});

// ── POST /mp/pausar — suspende sin dar de baja ────────────────────────────
app.post('/mp/pausar', auth, async (req, res) => {
  try {
    const { preapprovalId } = req.body;
    if (!preapprovalId) return res.status(400).json({ ok:false, error:'Falta el id de la suscripción' });
    const sub = await mpFetch('/preapproval/' + preapprovalId, {
      method: 'PUT', body: JSON.stringify({ status: 'paused' })
    });
    res.json({ ok:true, id: sub.id, status: sub.status });
  } catch (e) {
    res.status(e.status || 500).json({ ok:false, error: e.message });
  }
});

// ── GET /mp/suscripcion/:id — estado real en Mercado Pago ─────────────────
app.get('/mp/suscripcion/:id', auth, async (req, res) => {
  try {
    const sub = await mpFetch('/preapproval/' + req.params.id);
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
app.post('/mp/reembolsar', auth, async (req, res) => {
  try {
    const { preapprovalId } = req.body;
    if (!preapprovalId) return res.status(400).json({ ok:false, error:'Falta el id de la suscripción' });

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
app.get('/mp/estado', auth, async (req, res) => {
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
  res.json({ ok: true, servicio: 'FidelizApp AFIP Server', version: '1.0.0' });
});

// ── Helper: fecha hoy YYYYMMDD ─────────────────────────────────────────────
function _hoy() {
  return new Date().toISOString().slice(0,10).replace(/-/g, '');
}

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`[AFIP] Servidor corriendo en puerto ${PORT}`));
