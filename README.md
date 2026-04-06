# saa_grafana
This project includes congiguration files to run grafana and influxdb plus a python
script used to parse and clean http access logs.

![Archiutecture](/images/non-profit.drawio.png)

## Technology Stack

### Backend
* Python
* Pandas

### Observability
* Influx DB - A timeseries database used to store fields parsed from the http access logs.
* Grafana - An opensource tool used for visualizations.

#### How to generate a pdf report
```
cd ~/repos/ExportGrafanaDashboardToPDF
docker compose build
docker compose up
docker exec -it grafana-export-to-pdf /usr/src/app/generate-pdf.sh GF_DASH_URL 'http://127.0.0.1:3000/d/admhpr6/[<optional params>]'
docker cp grafana-export-to-pdf:/usr/src/app/output/<report name>.pdf .
docker compose stop
```