#!/usr/bin/env python3
"""
analizar_linea_base.py — Analiza las alertas generadas durante el Escenario 1
(linea base de trafico normal, sin actividad maliciosa intencional).

Como no hay ataques reales en este escenario, CUALQUIER alerta generada en la
ventana de tiempo se considera un falso positivo del SIEM. Reporta el total,
la tasa de falsos positivos por hora, y el desglose por regla/severidad para
poder documentar qué reglas tienden a disparar sobre tráfico legítimo.

Uso:
  python3 analizar_linea_base.py --alertas alertas_ventana.json \
      --inicio 2026-10-21T00:00:00Z --fin 2026-10-21T00:30:00Z --out reporte.md
"""
import argparse
import json
from collections import Counter
from datetime import datetime, timezone


def parse_ts(ts):
    ts = ts.strip()
    if ts.endswith("Z"):
        ts = ts[:-1] + "+0000"
    try:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S%z")
    return dt.astimezone(timezone.utc)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--alertas", required=True, help="Alertas ya filtradas a la ventana del escenario 1 (JSON)")
    ap.add_argument("--inicio", required=True)
    ap.add_argument("--fin", required=True)
    ap.add_argument("--out", default="reporte_linea_base.md")
    args = ap.parse_args()

    with open(args.alertas, encoding="utf-8") as f:
        alertas = json.load(f)

    t_ini, t_fin = parse_ts(args.inicio), parse_ts(args.fin)
    duracion_h = (t_fin - t_ini).total_seconds() / 3600.0

    total = len(alertas)
    por_nivel = Counter()
    por_regla = Counter()
    por_descripcion = {}
    por_grupo_attack = 0

    for al in alertas:
        rule = al.get("rule", {})
        nivel = rule.get("level", "?")
        rid = rule.get("id", "?")
        desc = rule.get("description", "(sin descripcion)")
        por_nivel[nivel] += 1
        por_regla[rid] += 1
        por_descripcion[rid] = desc
        if "attack" in rule.get("groups", []):
            por_grupo_attack += 1

    tasa_hora = (total / duracion_h) if duracion_h > 0 else 0.0

    with open(args.out, "w", encoding="utf-8") as f:
        f.write("# Reporte Escenario 1 — Linea base de trafico normal\n\n")
        f.write(f"- Ventana analizada: **{args.inicio}** a **{args.fin}** "
                f"({duracion_h*60:.0f} min)\n")
        f.write(f"- Total de alertas generadas: **{total}** "
                f"(todas se consideran **falsos positivos**, al no existir actividad maliciosa)\n")
        f.write(f"- Tasa de falsos positivos: **{tasa_hora:.1f} alertas/hora**\n")
        f.write(f"- De esas, con el grupo 'attack' (las mismas reglas que detectan ataques reales): "
                f"**{por_grupo_attack}**\n\n")

        f.write("## Alertas por nivel de severidad\n\n")
        f.write("| Nivel | Cantidad |\n|---|---|\n")
        for nivel, cnt in sorted(por_nivel.items(), key=lambda x: str(x[0])):
            f.write(f"| {nivel} | {cnt} |\n")

        f.write("\n## Top reglas disparadas (posibles ajustes de tuning recomendados)\n\n")
        f.write("| Regla ID | Descripcion | Cantidad |\n|---|---|---|\n")
        for rid, cnt in por_regla.most_common(25):
            f.write(f"| {rid} | {por_descripcion[rid]} | {cnt} |\n")

    print(f"Total alertas (falsos positivos): {total}")
    print(f"Tasa: {tasa_hora:.1f} alertas/hora")
    print(f"Reporte guardado en {args.out}")


if __name__ == "__main__":
    main()
