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
