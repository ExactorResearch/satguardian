# Adaptadores de motores externos

Uno existe ya: `aegis_replay.py` (Aegis Community v1.1.0 sobre HTTP real;
resultados en `../results/aegis/`). Los demás pendientes se rigen por este
fichario, que fija lo que cada uno tiene que cumplir antes de que su salida
entre en `results/`. La razón de escribirlo antes que el código: el comparativo
solo vale si los motores miden lo mismo, y eso se decide aquí, no después de
tener números.

Cada adaptador hace exactamente tres cosas:

1. leer `corpus/unified_v1.jsonl` (o `crs_v430.jsonl`) línea a línea, en orden;
2. construir la petición HTTP equivalente y pasarla por el motor real;
3. escribir un `verdicts.jsonl` con el contrato de `../README.md` §3.

Reglas que no se pueden romper:

- **Un caso, una decisión.** `blocked` es booleano. Un motor que registra sin
  bloquear corre en modo detección y `blocked` significa "hubo coincidencia"; un
  motor que corta la conexión corre en modo bloqueo. El modo va en `reason` y en
  el fichero de resultados. Nunca se comparan modos distintos entre sí.
- **Sin reetiquetado.** El adaptador no decide si un caso es ataque. Usa `label`
  y `split` del corpus tal cual. Si un motor necesita un campo que el corpus no
  da (p. ej. `client_ip`), se envía vacío y se anota, no se inventa.
- **Latencia con la misma lente.** `latency_us` es la llamada al motor, sin TLS,
  sin hop de proxy y sin upstream. Si un adaptador solo puede medirse por HTTP
  real, va a `Fase 3` con su propia columna y su línea base sin WAF; no se mezcla
  con los números en memoria.
- **Versionado por digest.** Cada corrida deja en `results/<engine>/RUN.json`:
  imagen o binario usado, digest SHA-256 o `imageID`, versión declarada, commit
  de CRS, paranoia level, modo del motor, fecha y `uname -a`. Sin eso, la corrida
  no existe.
- **Fracaso ruidoso.** Si el motor no carga las reglas, o carga menos de las
  esperadas, el adaptador sale con error. Una corrida con reglas sin cargar da
  un 0 % de detección que parece un resultado.

## Motores previstos

| motor | cómo se obtiene real | qué falta |
| :--- | :--- | :--- |
| Aegis Community v1.1.0 | release oficial Windows/Linux, `aegis.exe run -c config.yaml` + PostgreSQL local | **hecho** — `aegis_replay.py`, resultados en `results/aegis/` (Fase 3: HTTP real, latencia no comparable con satbench) |
| ModSecurity v3 + CRS v4.30 | `libmodsecurity-dev` 3.0.4 (apt) y un programa C con `msc_init` / `msc_load_configuration_string` / `msc_new_transaction` / `msc_process_uri` / `msc_process_request_headers` / `msc_process_body` / `msc_is_interrupted` | sudo para apt; luego compilar con `gcc` contra los headers |
| Coraza v3.8.1 + CRS v4.30 | imagen oficial `coraza-crsproxy` (digest pineable), o binario Go propio | Go >= 1.25 en `~/.local` si se compila; Docker arrancado si se usa la imagen |
| SafeLine | imagen oficial de la appliance | Docker arrancado; además es un producto completo, así que su número no es comparable a un motor de reglas suelto y hay que decirlo |
| línea base sin WAF | el mismo proxy, con el motor desactivado | Fase 3 |

## Orden de trabajo

Primero ModSecurity, porque es el que menos dependencias del entorno necesita y
porque CRS se escribió históricamente sobre él: si ModSecurity + CRS no carga en esta
máquina, el problema es la máquina. Después Coraza. SafeLine al final, y solo
como tabla de coste operativo, no como fila en la tabla de detección.
