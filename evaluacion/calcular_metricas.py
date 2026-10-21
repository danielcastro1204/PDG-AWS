#!/usr/bin/env python3
"""
calcular_metricas.py — Calcula tasa de deteccion, falsos positivos y matriz de
correlacion cruzando log_ataques.csv (Gestion/scripts/ataques/) con las alertas
reales exportadas por recolectar_alertas.py.

IMPORTANTE: este script NO inventa resultados. Debe ejecutarse sobre datos reales
obtenidos tras correr los escenarios 1, 2 y 3 en el laboratorio.

Uso:
  python3 calcular_metricas.py --ataques log_ataques.csv --alertas alertas_ventana.json \
      --margen-seg 30 --out reporte_metricas.md
"""
import argparse
import csv
import json
from datetime import datetime, timedelta, timezone

import pandas as pd


def parse_ts(ts):
    # Los timestamps de log_ataques.csv son UTC con sufijo "Z"; los de las
    # alertas de Wazuh traen el offset de la zona horaria local del servidor
    # (p.ej. "-0500"). Ambos deben normalizarse a UTC antes de comparar, o
    # cualquier correlación cruzando medianoche local queda mal calculada.
    ts = ts.strip()
    if ts.endswith("Z"):
        ts = ts[:-1] + "+0000"
    try:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S%z")
    return dt.astimezone(timezone.utc)


def cargar_ataques(path):
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def cargar_alertas(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ataques", required=True)
    ap.add_argument("--alertas", required=True)
    ap.add_argument("--margen-seg", type=int, default=30,
                     help="Margen (s) alrededor de [inicio,fin] del ataque para considerar una alerta relacionada")
    ap.add_argument("--escenario", default=None,
                     help="Si se indica, solo se consideran filas de log_ataques.csv con esta columna 'escenario'")
    ap.add_argument("--titulo", default="Reporte de metricas — Validacion SIEM")
    ap.add_argument("--out", default="reporte_metricas.md")
    args = ap.parse_args()

    ataques = cargar_ataques(args.ataques)
    if args.escenario is not None:
        ataques = [a for a in ataques if a.get("escenario", "2") == str(args.escenario)]
    alertas = cargar_alertas(args.alertas)

    filas = []
    total_ataques = len(ataques)
    detectados = 0
    tiempos_deteccion = []  # segundos entre inicio del ataque y la primera alerta correlacionada

    for a in ataques:
        t_ini = parse_ts(a["inicio"]) - timedelta(seconds=args.margen_seg)
        t_fin = parse_ts(a["fin"]) + timedelta(seconds=args.margen_seg)
        matches = []
        primera_alerta = None
        for al in alertas:
            ts = al.get("timestamp")
            if not ts:
                continue
            try:
                t = parse_ts(ts)
            except ValueError:
                continue
            if t_ini <= t <= t_fin:
                rule = al.get("rule", {})
                matches.append(rule.get("id", "?"))
                if primera_alerta is None or t < primera_alerta:
                    primera_alerta = t

        detectado = len(matches) > 0
        if detectado:
            detectados += 1
            ttd = (primera_alerta - parse_ts(a["inicio"])).total_seconds()
            tiempos_deteccion.append(max(ttd, 0.0))
        filas.append({
            "ataque": a["ataque"],
            "mitre_id": a["mitre_id"],
            "objetivo": a["target_ip"],
            "inicio": a["inicio"],
            "detectado": "Si" if detectado else "No",
            "ttd_seg": f"{ttd:.1f}" if detectado else "-",
            "reglas_disparadas": ",".join(sorted(set(matches))) if matches else "-",
        })

    df = pd.DataFrame(filas)
    tasa_deteccion = (detectados / total_ataques * 100) if total_ataques else 0.0
    mttd = (sum(tiempos_deteccion) / len(tiempos_deteccion)) if tiempos_deteccion else None

    # Falsos positivos: alertas de grupo 'attack' que NO caen en ninguna ventana de ataque real
    ventanas = [(parse_ts(a["inicio"]) - timedelta(seconds=args.margen_seg),
                 parse_ts(a["fin"]) + timedelta(seconds=args.margen_seg)) for a in ataques]

    def en_alguna_ventana(t):
        return any(ini <= t <= fin for ini, fin in ventanas)

    total_alertas_attack = 0
    falsos_positivos = 0
    for al in alertas:
        rule = al.get("rule", {})
        if "attack" not in rule.get("groups", []):
            continue
        ts = al.get("timestamp")
        if not ts:
            continue
        try:
            t = parse_ts(ts)
        except ValueError:
            continue
        total_alertas_attack += 1
        if not en_alguna_ventana(t):
            falsos_positivos += 1
    alertas_verdaderas = total_alertas_attack - falsos_positivos

    # Metricas tipo clasificador binario (a nivel de intento de ataque / alerta):
    #   Recall (sensibilidad)   = detectados / total_ataques            (ya es la "tasa de deteccion")
    #   Precision (a nivel de alertas de grupo 'attack') = TP_alertas / (TP_alertas + FP_alertas)
    #   F1 = 2 * (precision * recall) / (precision + recall)
    recall = detectados / total_ataques if total_ataques else None
    precision = (alertas_verdaderas / total_alertas_attack) if total_alertas_attack else None
    f1 = (2 * precision * recall / (precision + recall)) if (precision and recall) else None

    # Desglose por tipo de ataque (recall por tecnica)
    resumen_tipo = df.groupby("ataque").agg(
        intentos=("detectado", "count"),
        detectados=("detectado", lambda s: (s == "Si").sum()),
    )
    resumen_tipo["tasa_deteccion_%"] = (resumen_tipo["detectados"] / resumen_tipo["intentos"] * 100).round(1)

    with open(args.out, "w", encoding="utf-8") as f:
        f.write(f"# {args.titulo}\n\n")
        f.write(f"- Total de ataques ejecutados: **{total_ataques}**\n")
        f.write(f"- Ataques detectados (Verdaderos Positivos): **{detectados}**\n")
        f.write(f"- Ataques no detectados (Falsos Negativos): **{total_ataques - detectados}**\n")
        f.write(f"- **Tasa de deteccion / Recall: {tasa_deteccion:.1f}%** "
                f"(criterio de exito del proyecto: >= 80%)\n")
        if mttd is not None:
            f.write(f"- Tiempo medio de deteccion (MTTD): **{mttd:.1f} s** "
                    f"(desde el inicio del ataque hasta la primera alerta correlacionada)\n")
        f.write(f"- Alertas de grupo 'attack' dentro de la ventana de prueba: **{total_alertas_attack}** "
                f"(verdaderas: {alertas_verdaderas}, falsos positivos: **{falsos_positivos}**)\n")
        if precision is not None:
            f.write(f"- **Precision (alertas 'attack' correctas / total alertas 'attack'): {precision*100:.1f}%**\n")
        if f1 is not None:
            f.write(f"- **F1-score: {f1*100:.1f}%**\n")
        f.write("\n## Desglose por tipo de ataque\n\n")
        f.write(resumen_tipo.to_markdown())
        f.write("\n\n## Detalle por intento de ataque\n\n")
        f.write(df.to_markdown(index=False))
        f.write("\n\n## Matriz de correlacion (tipo de ataque -> reglas Wazuh disparadas)\n\n")
        matriz = df.groupby("ataque")["reglas_disparadas"].apply(
            lambda s: ", ".join(sorted(set(",".join(s).split(","))))
        )
        f.write(matriz.to_markdown())
        f.write("\n")

    print(df.to_string(index=False))
    print(f"\nTasa de deteccion (recall): {tasa_deteccion:.1f}%")
    if precision is not None:
        print(f"Precision: {precision*100:.1f}%")
    if f1 is not None:
        print(f"F1-score: {f1*100:.1f}%")
    if mttd is not None:
        print(f"MTTD: {mttd:.1f} s")
    print(f"Falsos positivos: {falsos_positivos} / {total_alertas_attack} alertas 'attack'")
    print(f"Reporte completo guardado en {args.out}")


if __name__ == "__main__":
    main()
