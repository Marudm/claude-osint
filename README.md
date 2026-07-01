# 🔍 Claude OSINT Intelligence Platform

![Python](https://img.shields.io/badge/Python-3.13-blue)
![Django](https://img.shields.io/badge/Django-4.2-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

Plataforma de inteligencia OSINT desarrollada con Django y Python, orientada a tareas de análisis de seguridad, threat intelligence y operaciones SOC.

## 🚀 Features

- 🌐 **IP Intelligence** — geolocalización, ASN, ISP, reverse DNS y escaneo de puertos
- 🚨 **Threat Intelligence** — integración con AbuseIPDB para abuse score en tiempo real
- 🗺️ **Mapa interactivo** — geolocalización visual con Leaflet.js
- ⚠️ **Risk Score automático** — calculado en base a múltiples indicadores
- 🔎 **Hallazgos OSINT** — detección automática de indicadores de riesgo
- 📋 **Export JSON** — resultados exportables para análisis externo
- 💻 **Terminal en tiempo real** — logs del proceso de análisis en vivo

## 🛠️ Stack Tecnológico

| Categoría | Tecnología |
|-----------|-----------|
| Backend | Python 3.13, Django 4.2 |
| Frontend | HTML5, CSS3, JavaScript |
| APIs | AbuseIPDB, ip-api.com |
| Mapas | Leaflet.js + OpenStreetMap |
| Herramientas | Git, VS Code |

## ⚙️ Instalación

```bash
# Clonar el repositorio
git clone https://github.com/Marudm/claude-osint.git
cd claude-osint

# Instalar dependencias
pip install django requests python-whois dnspython reportlab folium

# Aplicar migraciones
python manage.py migrate

# Iniciar servidor
python manage.py runserver
```

Accedé a `http://127.0.0.1:8000` en tu navegador.

## 🔑 Configuración API Key

Para activar el análisis de abuso en tiempo real, registrate gratis en [AbuseIPDB](https://www.abuseipdb.com/register) y reemplazá `TU_API_KEY_AQUI` en `dashboard/views.py`.

## 📸 Screenshots

*Dashboard principal con análisis de IP en tiempo real*

## 🎯 Casos de Uso

- Análisis de IPs sospechosas en incidentes de seguridad
- Threat intelligence para equipos SOC
- Investigación OSINT de infraestructura maliciosa
- Enriquecimiento de IOCs durante respuesta a incidentes

## 👩‍💻 Autora

**Marina Andrea Della Mattia**
- 🔗 [LinkedIn](https://linkedin.com/in/marinadellamattia)
- 🐙 [GitHub](https://github.com/Marudm)
- 📧 marinadellamattia.estudio@gmail.com