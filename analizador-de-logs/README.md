# Analizador de logs de autenticación SSH

Script en Python que lee un log de `sshd` (formato syslog), cuenta los intentos fallidos por IP y por usuario, marca las IP que superan un umbral y avisa si alguna de ellas **logró entrar** después de fallar (señal típica de fuerza bruta exitosa).

No usa librerías externas: solo la biblioteca estándar de Python 3.

## Uso
```bash
python analizador.py ejemplos/auth.log
python analizador.py ejemplos/auth.log --umbral 3 --csv reporte.csv
```

| Opción | Descripción |
|---|---|
| `--umbral N` | Fallos necesarios para marcar una IP como sospechosa (por defecto 5) |
| `--csv RUTA` | Guarda el detalle en un CSV |

## Salida de ejemplo
Ejecutado sobre `ejemplos/auth.log` (datos ficticios; las IP son de rangos reservados para documentación):

```
REPORTE DE INTENTOS DE ACCESO
==============================
Umbral de fallos: 5
Líneas ignoradas (formato desconocido): 1

Fallos por IP:
  203.0.113.5      8  <-- SOSPECHOSA
  203.0.113.99     5  <-- SOSPECHOSA
  198.51.100.7     3

Usuarios más atacados:
  root             8
  admin            3
  maria            3
  test             1
  ubuntu           1

ALERTA: IP sospechosas que lograron iniciar sesión:
  203.0.113.5 entró como: admin
```

## Tests
```bash
python -m unittest discover -s tests -v
```
También se pueden correr con `pytest` si lo tenés instalado.

## Cómo funciona
1. Una expresión regular extrae fecha, resultado (`Failed`/`Accepted`), usuario e IP de cada línea.
2. Se cuentan los fallos por IP y por usuario con `collections.Counter`.
3. Las IP con fallos >= umbral son sospechosas; si además tienen un `Accepted`, se genera una alerta.
4. Las líneas que no coinciden con el patrón se cuentan como ignoradas.

## Ejercicios para profundizar
- Agregar soporte para el log de Windows (eventos 4625 y 4624 exportados a CSV).
- Agrupar los fallos por hora para ver en qué momentos hubo más ataques.
- Agregar un `--top N` para limitar la lista de IP.
- Detectar ráfagas: 5 fallos en menos de 1 minuto.
