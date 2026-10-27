import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import analizador  # noqa: E402

FALLO = "Oct 26 08:01:02 srv sshd[1]: Failed password for root from 10.0.0.5 port 22 ssh2"
FALLO_INVALIDO = "Oct 26 08:01:03 srv sshd[2]: Failed password for invalid user admin from 10.0.0.5 port 22 ssh2"
ACIERTO = "Oct 26 08:02:00 srv sshd[3]: Accepted password for juan from 10.0.0.9 port 22 ssh2"
RUIDO = "Oct 26 08:03:00 srv CRON[4]: session opened for user root"


class TestParseo(unittest.TestCase):
    def test_linea_de_fallo(self):
        e = analizador.parsear_linea(FALLO)
        self.assertEqual(e["resultado"], "Failed")
        self.assertEqual(e["usuario"], "root")
        self.assertEqual(e["ip"], "10.0.0.5")

    def test_usuario_invalido(self):
        e = analizador.parsear_linea(FALLO_INVALIDO)
        self.assertEqual(e["usuario"], "admin")

    def test_linea_que_no_corresponde(self):
        self.assertIsNone(analizador.parsear_linea(RUIDO))
        self.assertIsNone(analizador.parsear_linea(""))


class TestAnalisis(unittest.TestCase):
    def test_cuenta_fallos_y_umbral(self):
        lineas = [FALLO] * 3 + [FALLO_INVALIDO] * 2 + [ACIERTO, RUIDO]
        r = analizador.analizar(lineas, umbral=5)
        self.assertEqual(r["fallos_por_ip"]["10.0.0.5"], 5)
        self.assertEqual(r["ip_sospechosas"], ["10.0.0.5"])
        self.assertEqual(r["lineas_ignoradas"], 1)

    def test_por_debajo_del_umbral_no_es_sospechosa(self):
        r = analizador.analizar([FALLO] * 4, umbral=5)
        self.assertEqual(r["ip_sospechosas"], [])

    def test_detecta_acceso_tras_fallos(self):
        entra = "Oct 26 08:09:00 srv sshd[9]: Accepted password for root from 10.0.0.5 port 22 ssh2"
        r = analizador.analizar([FALLO] * 5 + [entra], umbral=5)
        self.assertEqual(r["ip_con_acceso_tras_fallos"], ["10.0.0.5"])

    def test_acceso_normal_no_genera_alerta(self):
        r = analizador.analizar([ACIERTO], umbral=1)
        self.assertEqual(r["ip_con_acceso_tras_fallos"], [])


class TestSalida(unittest.TestCase):
    def test_reporte_menciona_ip_sospechosa(self):
        r = analizador.analizar([FALLO] * 5, umbral=5)
        texto = analizador.formatear_reporte(r)
        self.assertIn("SOSPECHOSA", texto)
        self.assertIn("10.0.0.5", texto)

    def test_exportar_csv(self):
        r = analizador.analizar([FALLO] * 5, umbral=5)
        with tempfile.TemporaryDirectory() as d:
            ruta = os.path.join(d, "r.csv")
            analizador.exportar_csv(r, ruta)
            with open(ruta, encoding="utf-8") as f:
                contenido = f.read()
        self.assertIn("ip,fallos,sospechosa,logro_acceso", contenido)
        self.assertIn("10.0.0.5,5,True,False", contenido)


if __name__ == "__main__":
    unittest.main()
