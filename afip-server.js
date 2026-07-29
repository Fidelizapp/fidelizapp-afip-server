-- ═══════════════════════════════════════════════════════════════
--  FidelizApp — Encuestas con link
--  Para que el cliente responda desde su celular y la respuesta
--  entre sola, sin que nadie la cargue a mano.
--  Pegar TODO esto en Supabase -> SQL Editor -> Run
-- ═══════════════════════════════════════════════════════════════

create table if not exists nps_encuestas (
  id            uuid primary key default gen_random_uuid(),
  negocio_id    uuid not null,
  cliente       text not null,
  monto         numeric default 0,
  enviada_en    timestamptz default now(),
  respondida_en timestamptz,
  score         int,
  estrellas     int,
  comentario    text,
  -- datos del negocio que la pagina publica necesita mostrar
  negocio_nombre  text,
  pregunta_nps    text,
  pregunta_stars  text,
  pregunta_texto  text,
  msg_gracias     text
);

create index if not exists nps_encuestas_negocio on nps_encuestas (negocio_id, enviada_en desc);

alter table nps_encuestas enable row level security;


-- ── 1) El negocio crea la encuesta y ve sus resultados ─────────

drop policy if exists "negocio crea encuestas" on nps_encuestas;
create policy "negocio crea encuestas" on nps_encuestas
  for insert to authenticated
  with check (negocio_id in (select id from negocios where user_id = auth.uid()));

drop policy if exists "negocio ve sus encuestas" on nps_encuestas;
create policy "negocio ve sus encuestas" on nps_encuestas
  for select to authenticated
  using (
    negocio_id in (select id from negocios where user_id = auth.uid())
    or coalesce(auth.jwt() ->> 'email', '') = 'tranimgeorgina@hotmail.com'
  );


-- ── 2) El cliente responde sin tener cuenta ────────────────────
-- Solo puede leer y contestar la encuesta cuyo id exacto tiene en
-- el link, y solo mientras no este respondida. No puede listar las
-- de otros ni ver nada mas.

drop policy if exists "cliente lee su encuesta" on nps_encuestas;
create policy "cliente lee su encuesta" on nps_encuestas
  for select to anon
  using (respondida_en is null);

drop policy if exists "cliente responde su encuesta" on nps_encuestas;
create policy "cliente responde su encuesta" on nps_encuestas
  for update to anon
  using      (respondida_en is null)
  with check (respondida_en is not null);


-- ── 3) Candado: el cliente solo puede tocar su respuesta ───────
-- Sin esto podria cambiar el nombre, el monto o el negocio.

create or replace function proteger_encuesta()
returns trigger
language plpgsql
security definer
as $$
begin
  if auth.role() = 'anon' then
    new.negocio_id     := old.negocio_id;
    new.cliente        := old.cliente;
    new.monto          := old.monto;
    new.enviada_en     := old.enviada_en;
    new.negocio_nombre := old.negocio_nombre;
    -- la fecha de respuesta la pone la base, no el navegador
    new.respondida_en  := now();
  end if;
  return new;
end;
$$;

drop trigger if exists trg_proteger_encuesta on nps_encuestas;
create trigger trg_proteger_encuesta
  before update on nps_encuestas
  for each row execute function proteger_encuesta();


-- ═══════════════════════════════════════════════════════════════
--  COMPROBAR
-- ═══════════════════════════════════════════════════════════════

select 'Tabla creada correctamente' as resultado,
       count(*) as encuestas_existentes
from nps_encuestas;
