"""Analizador de logs de autenticación SSH.

Lee un archivo de log con el formato de sshd (syslog), cuenta los intentos fallidos por
IP y por usuario y marca como sospechosas las IP que superan un umbral de fallos.
También detecta si una IP sospechosa logró entrar después de fallar.

Uso:
    python analizador.py ejemplos/auth.log
    python analizador.py ejemplos/auth.log --umbral 3 --csv reporte.csv
"""
import argparse
import csv
import re
from collections import Counter, defaultdict

PATRON = re.compile(
    r"^(?P<fecha>\w{3}\s+\d+\s[\d:]{8})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<resultado>Failed|Accepted) password for (?:invalid user )?"
    r"(?P<usuario>\S+) from (?P<ip>\S+) port \d+"
)


def parsear_linea(linea):
    """Devuelve un diccionario con fecha, resultado, usuario e ip, o None si no coincide."""
    m = PATRON.match(linea.strip())
    if not m:
        return None
    return m.groupdict()


def analizar(lineas, umbral=5):
    """Analiza las líneas de un log y devuelve un diccionario con las estadísticas."""
    fallos_ip = Counter()
    fallos_usuario = Counter()
    aciertos = defaultdict(list)  # ip -> usuarios que lograron entrar
    ignoradas = 0

    for linea in lineas:
        evento = parsear_linea(linea)
        if evento is None:
            ignoradas += 1
            continue
        if evento["resultado"] == "Failed":
            fallos_ip[evento["ip"]] += 1
            fallos_usuario[evento["usuario"]] += 1
        else:
            aciertos[evento["ip"]].append(evento["usuario"])

    sospechosas = sorted(ip for ip, n in fallos_ip.items() if n >= umbral)
    comprometidas = sorted(ip for ip in sospechosas if ip in aciertos)

    return {
        "fallos_por_ip": fallos_ip,
        "fallos_por_usuario": fallos_usuario,
        "aciertos_por_ip": dict(aciertos),
        "ip_sospechosas": sospechosas,
        "ip_con_acceso_tras_fallos": comprometidas,
        "lineas_ignoradas": ignoradas,
        "umbral": umbral,
    }


def formatear_reporte(resultado):
    """Genera el reporte en texto plano."""
    r = resultado
    salida = ["REPORTE DE INTENTOS DE ACCESO", "=" * 30]
    salida.append(f"Umbral de fallos: {r['umbral']}")
    salida.append(f"Líneas ignoradas (formato desconocido): {r['lineas_ignoradas']}")
    salida.append("")
    salida.append("Fallos por IP:")
    for ip, n in r["fallos_por_ip"].most_common():
        marca = "  <-- SOSPECHOSA" if ip in r["ip_sospechosas"] else ""
        salida.append(f"  {ip:<16} {n}{marca}")
    salida.append("")
    salida.append("Usuarios más atacados:")
    for usuario, n in r["fallos_por_usuario"].most_common(5):
        salida.append(f"  {usuario:<16} {n}")
    salida.append("")
    if r["ip_con_acceso_tras_fallos"]:
        salida.append("ALERTA: IP sospechosas que lograron iniciar sesión:")
        for ip in r["ip_con_acceso_tras_fallos"]:
            usuarios = ", ".join(sorted(set(r["aciertos_por_ip"][ip])))
            salida.append(f"  {ip} entró como: {usuarios}")
    else:
        salida.append("Ninguna IP sospechosa logró iniciar sesión.")
    return "\n".join(salida)


def exportar_csv(resultado, ruta):
    """Guarda los fallos por IP en un CSV (se abre en Excel)."""
    with open(ruta, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "fallos", "sospechosa", "logro_acceso"])
        for ip, n in resultado["fallos_por_ip"].most_common():
            w.writerow([
                ip,
                n,
                ip in resultado["ip_sospechosas"],
                ip in resultado["ip_con_acceso_tras_fallos"],
            ])


def main():
    parser = argparse.ArgumentParser(description="Analizador de logs de autenticación SSH")
    parser.add_argument("archivo", help="ruta del log a analizar")
    parser.add_argument("--umbral", type=int, default=5, help="fallos para marcar una IP como sospechosa")
    parser.add_argument("--csv", help="ruta de un CSV donde guardar el detalle")
    args = parser.parse_args()

    with open(args.archivo, encoding="utf-8", errors="replace") as f:
        resultado = analizar(f, umbral=args.umbral)
    print(formatear_reporte(resultado))
    if args.csv:
        exportar_csv(resultado, args.csv)
        print(f"\nDetalle guardado en {args.csv}")


if __name__ == "__main__":
    main()
