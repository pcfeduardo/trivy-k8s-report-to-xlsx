# README
## About
Processes the k8s cluster assessment in json and transforms it into xlsx (needs Trivy).

## Recommendations
### Create your own venv
```bash
python -m venv .venv
```
## Prerequisites
1. Trivy (https://github.com/aquasecurity/trivy)
2. pandas (python package)
2. openpyxl (python package)
### Install python modules:
```bash
pip3 install pandas
pip3 install openpyxl
```
## Generate report file in json
```bash
trivy k8s --report summary all  --format json -o cluster_xyz.json
```

## Usage
```bash
./trivy-k8s-report-to-xlsx.py cluster_xyz.json report.xslx
```