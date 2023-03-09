#!/usr/bin/env python
import json
import pandas
import argparse

'''
Prerequisites
1. Install python modules:
pip3 install pandas
pip3 install openpyxl

2. Generate report file in json:
trivy k8s --report summary all  --format json -o cluster_xyz.json

3. Start Scan
Usage:
./trivy-k8s-report-to-xlsx.py cluster_xyz.json report.xslx
'''

__version__ = '1.0.0'
__prog__ = 'trivy-k8s-report-to-xlsx.py'

parser = argparse.ArgumentParser(description='processes the k8s cluster assessment in json and transforms it into xlsx', prog=f'{__prog__}')
parser.add_argument('input', help='specify the file to be processed')
parser.add_argument('output', help='inform the name of the file that will be generated with its respective extension (xlsx)')
parser.add_argument('--version', '-v', action='version', version=f'%(prog)s {__version__}')
args = parser.parse_args()

report_file = args.input

all_misconfigurations = []
all_vulns = []

with open(report_file, 'r') as all_reports:
    reports = json.load(all_reports)
    cluster_name = reports['ClusterName']
    findings = reports['Findings']

    for finding in findings:
        results = finding['Results']
        kind = finding['Kind']
        name = finding['Name']
        for result in results:
            target = result['Target']
            if 'Misconfigurations' in result:
                misconfigurations = result['Misconfigurations']
                for misconfiguration in misconfigurations:
                    result_misconfiguration = {
                        "Id": misconfiguration['ID'],
                        "Target": target,
                        "Kind": kind,
                        "Name": name,
                        "Type": misconfiguration['Type'],
                        "Title": misconfiguration['Title'],
                        "Message": misconfiguration['Message'],
                        "Resolution": misconfiguration['Resolution'],
                        "Severity": misconfiguration['Severity'],
                        "Status": misconfiguration['Status'],
                        "PrimaryURL": misconfiguration['PrimaryURL'],
                        "References": misconfiguration['References']
                    }
                    all_misconfigurations.append(result_misconfiguration)
                    
            if 'Vulnerabilities' in result:
                vulnerabilities = result['Vulnerabilities']
                for vuln in vulnerabilities:
                    if 'Title' in vuln:
                        title = vuln['Title']
                    else:
                        title = None

                    if 'PkgID' in vuln:
                        pkg_id = vuln['PkgID']
                    else:
                        pkg_id = None
                    
                    if 'InstalledVersion' in vuln:
                        installed_version = vuln['InstalledVersion']
                    else:
                        installed_version = None
                    
                    if 'FixedVersion' in vuln:
                        fixed_version = vuln['FixedVersion']
                    else:
                        fixed_version = None

                    if 'SeveritySource' in vuln:
                        severity_source = vuln['SeveritySource']
                    else:
                        severity_source = None

                    if 'Description' in vuln:
                        description = vuln['Description']
                    else:
                        description = None
                    
                    if 'References' in vuln:
                        references = vuln['References']
                    else:
                        references = None
                    if 'PrimaryURL' in vuln:
                        primary_url = vuln['PrimaryURL']
                    else:
                        primary_url = None
                    result_vuln = {
                        "VulnerabilityID": vuln['VulnerabilityID'],
                        "Target": target,
                        "Target": target,
                        "Kind": kind,
                        "Name": name,
                        "PkgName": vuln['PkgName'],
                        "PkgID": pkg_id,
                        'InstalledVersion': installed_version,
                        'FixedVersion': fixed_version,
                        "SeveritySource": severity_source,
                        "Title": title,
                        "Description": description,
                        "Severity": vuln['Severity'],
                        "Status": 'FAIL',
                        "PrimaryURL": primary_url,
                        "References": references
                        
                    }
                    # print(result_vuln)
                    all_vulns.append(result_vuln)
all_reports.close()

with pandas.ExcelWriter(f'report.xlsx') as report_file:
    misc = pandas.DataFrame(all_misconfigurations)
    vuln = pandas.DataFrame(all_vulns)

    misc.to_excel(report_file, sheet_name=f'Misconfigurations', index=False)
    vuln.to_excel(report_file, sheet_name=f'Vulnerabilities', index=False)