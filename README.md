# README

## Prerequisites
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