import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
from plotly import graph_objects as go
import plotly.express as px
import os

import subprocess
import re

import pandas as pd
import subprocess
from urllib.request import urlopen
import json
import time


def call_cmd(cmd, password='pwdno'):
    if password != "pwdno":
        output = subprocess.check_output('echo {} | sudo -S {}'.format(password, cmd), shell=True)
        op1 = output.decode()
        return op1
    else:
        output = subprocess.check_output('{}'.format(cmd), shell=True)
        op1 = output.decode()
        return op1


def get_cve_details(cve):
    time.sleep(6.3)
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve
    cve_deets = json.loads(urlopen(url).read())
    return cve_deets


def get_ip():
    ip_cmd = "ip -o -f inet addr show | awk '/scope global/ {print $4}'"
    ip_addresses = call_cmd(ip_cmd).split("\n")[0]
    ip_addr = ip_addresses.split("/")[0]
    return ip_addresses, ip_addr


def install_packages(password):
    nmap_install = "sudo apt-get install nmap -y"
    call_cmd(nmap_install, password)
    rootkit_install = "sudo apt install chkrootkit -y"
    call_cmd(rootkit_install, password)



def all_scans(ip_address, single_ip, password, scan_name):
    if not (os.path.exists("./scan_results/{}".format(scan_name))):
        print("Making the directory {}...".format(scan_name))
        os.mkdir("./scan_results/{}".format(scan_name))
        print("Making the directory {}/imgs...".format(scan_name))
        os.mkdir("./scan_results/{}/imgs".format(scan_name))

    print("commencing Network discovery...")
    nmap_only_host_disc(ip_addresss=ip_address, password=password, scan_name=scan_name)
    print("commencing Port Scan...")
    open_ports_check(single_ip=single_ip, password=password, scan_name=scan_name)
    print("commencing vulnerabilaty Scan...")
    nmap_vulner_scanner(single_ip=single_ip, scan_name=scan_name)
    print("commencing Rootkit Scan...")
    scan_rookits(password=password, scan_name=scan_name)
    print("Done...")




def nmap_only_host_disc(ip_addresss, password, scan_name):
    """ NMAP -sn only host discovery"""
    cmd = 'nmap -sn ' + ip_addresss

    # scan_res = call('echo {} | sudo -S {}'.format(password, cmd), shell=True)

    # output = subprocess.check_output('echo {} | sudo -S {}'.format(password, cmd), shell=True)
    op1 = call_cmd(cmd=cmd, password=password)

    scan_results = {}
    ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    host_is_pattern = r'\w+ \w+ (\w+)'
    lat_pattern = r"\w+ \w+ (\w+) \((-?\d+.\d+)\w{1} \w+\)"
    dn_pattern = r"\w+ \w+ \w+ \w+ (\S+)"
    done_pattern = r"\w+\s\w+: (\d+) \w+\s\w+\s\((\d+)\s\w+\s\w+\) \w+ \w+ (\d+.\d+) \w+"

    ip_addr = None
    for n, line in enumerate(op1.split('\n')):
        if line.startswith("Nmap scan") and ip_addr == None:
            ip_addr = ip_pattern.search(line)[0]
            device_name = re.findall(dn_pattern, line)[0]
            # print(ip_addr)

        if line.startswith("Host") and ip_addr != None:
            # print(line)
            try:
                hostis = re.findall(host_is_pattern, line)[0]
            except:
                print("HOSTISSSSSSSSSSSSS")
                print(line)
                print(re.findall(host_is_pattern, line))
            if hostis == "up":
                hostis = True

                lat = re.findall(lat_pattern, line)
                if lat:
                    lat = lat[0]
                    lat = float(lat[1])
                else:
                    lat = "None"


            else:
                hostis = False

            scan_results[ip_addr] = {'host_up': hostis, "latency": lat, "name": device_name}
            ip_addr = None

        else:
            pass

    res = scan_results
    plot_dict = {"ip": [], "host_up": [], 'latency': [], 'start': [], "name": []}
    for i in res:
        ip = i
        host_up = res[i]['host_up']
        latency = res[i]['latency']
        name = res[i]['name']

        plot_dict['ip'].append(ip)
        plot_dict['latency'].append(latency)
        plot_dict['start'].append(1)
        plot_dict['name'].append(name)

        if host_up:
            plot_dict['host_up'].append("#59CE8F")

        else:
            plot_dict['host_up'].append("#FF1E00")

    # unfiltered_plot
    df = pd.DataFrame.from_dict(plot_dict)
    df = df[:15]
    G = nx.from_pandas_edgelist(df,
                                source='start',
                                target='name',
                                edge_attr='latency')

    cols = df['host_up'].to_list()
    if len(G.nodes) != len(cols):
        cols = ["blue"] + cols

    nx.draw(G,
            with_labels=True,
            # node_size=[300] + [i * 1000000 for i in df['latency'].to_list()],
            node_color=cols,
            font_size=10,
            font_color="black")
    plt.savefig('./scan_results/{}/imgs/network_diagram_auto.png'.format(scan_name),
                dpi=300,
                bbox_inches='tight')


def open_ports_check(single_ip, password, scan_name):
    nmap_cmd = "nmap -p0-65535 " + single_ip

    ports_op = call_cmd(cmd=nmap_cmd, password=password)
    ports_op = ports_op.split("\n")

    port_dict = {"Port": [], "Protocol": [], "Status": [], "Service": []}
    for n, line in enumerate(ports_op):
        # print(line)
        if line.startswith("PORT"):
            start_line = n + 1
        if line.startswith("Nmap done"):
            end_line = n - 1

    ports_lines = ports_op[start_line: end_line]

    for port_line in ports_lines:
        list_of_lines = []
        list_of_lines = port_line.split(" ")

        port_proto, status, service = [i for i in list_of_lines if i != ""]
        port, proto = port_proto.split("/")
        port_dict['Port'].append(port)
        port_dict['Protocol'].append(proto)
        port_dict['Status'].append(status)
        port_dict['Service'].append(service)

    df = pd.DataFrame.from_dict(port_dict)
    fig = go.Figure()

    tab = go.Table(header=dict(values=list(df.columns),
                               line_color="#AEAEAE",
                               fill_color='#009A44',
                               font=dict(color='white', size=14),
                               height=30
                               ),
                   cells=dict(values=[df['Port'],
                                      df['Protocol'],
                                      df['Status'],
                                      df['Service']],
                              # font_color='black',
                              font_size=14,
                              height=30))
    fig.add_trace(tab)
    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)')

    fig.write_image("./scan_results/{}/imgs/open_ports.png".format(scan_name))


def nmap_vulner_scanner(single_ip, scan_name):
    current_dir = os.getcwd()
    new_path = os.path.join(current_dir, "scripts", "vulner.nse")
    nmap_cmd = "nmap -sV -p21-8080 --script " + new_path + " " + single_ip
    cves_op = call_cmd(nmap_cmd).split("\n")

    cve_identification_collection = []
    for cve_line in cves_op:
        if cve_line.startswith("|"):

            cve_split = cve_line.split("\t")
            if len(cve_split) > 1:
                # print(cve_split)
                if cve_split[1].startswith("CVE"):
                    # print(cve_split)
                    cve_indentified = cve_split[1]
                    cve_score = cve_split[2]
                    cve_identification_collection.append({"cve_identity": cve_indentified, "score": cve_score})

    cve_collection = {"cve": [], "desc": [], "base_score": [], "base_severity": [], "att_vector": [], "att_complex": [],
                      "exploitabilaty": [], "refs": []}
    for a_cve in cve_identification_collection:
        cve_ident = a_cve['cve_identity']

        try:
            cve_dict = get_cve_details(cve_ident)
        except:
            continue

        cve_collection['cve'].append(cve_ident)
        descriptions = ""
        for des in cve_dict['vulnerabilities'][0]['cve']['descriptions']:
            if des['lang'] == 'en':
                desc_text = des['value']
                descriptions += desc_text

        cve_collection['desc'].append(descriptions)
        source = cve_dict['vulnerabilities'][0]['cve']['sourceIdentifier']
        # print(cve_dict['vulnerabilities'][0]['cve']['metrics'])

        metric_keys = list(cve_dict['vulnerabilities'][0]['cve']['metrics'].keys())
        for metric_key in metric_keys:
            try:
                base_severity = cve_dict['vulnerabilities'][0]['cve']['metrics'][metric_key][0]['cvssData'][
                    "baseSeverity"]
                att_vector = cve_dict['vulnerabilities'][0]['cve']['metrics'][metric_key][0]['cvssData']["attackVector"]
                base_score = cve_dict['vulnerabilities'][0]['cve']['metrics'][metric_key][0]['cvssData']["baseScore"]
                att_complex = cve_dict['vulnerabilities'][0]['cve']['metrics'][metric_key][0]['cvssData'][
                    "attackComplexity"]
                exploitabilaty = cve_dict['vulnerabilities'][0]['cve']['metrics'][metric_key][0]["exploitabilityScore"]
                refs = cve_dict['vulnerabilities'][0]['cve']['references']
                break
            except Exception as e:
                print(e)
                continue

        if len(cve_collection['exploitabilaty']) == 0:
            if "cvssMetricV2" in metric_keys:
                metric_key = "cvssMetricV2"
                base_severity = cve_dict['vulnerabilities'][0]['cve']['metrics'][metric_key][0]['cvssData'][
                    "baseSeverity"]
                att_vector = cve_dict['vulnerabilities'][0]['cve']['metrics'][metric_key][0]['cvssData']["accessVector"]
                base_score = cve_dict['vulnerabilities'][0]['cve']['metrics'][metric_key][0]['cvssData']["baseScore"]
                att_complex = cve_dict['vulnerabilities'][0]['cve']['metrics'][metric_key][0]['cvssData'][
                    "accessComplexity"]
                exploitabilaty = cve_dict['vulnerabilities'][0]['cve']['metrics'][metric_key][0]["exploitabilityScore"]
                refs = cve_dict['vulnerabilities'][0]['cve']['references']

            else:
                base_severity = "Unable to Locate"
                att_vector = "Unable to Locate"
                base_score = "Unable to Locate"
                att_complex = "Unable to Locate"
                exploitabilaty = "Unable to Locate"
                refs = "Unable to Locate"

        cve_collection['base_severity'].append(base_severity)
        cve_collection['att_vector'].append(att_vector)
        cve_collection['base_score'].append(base_score)
        cve_collection['att_complex'].append(att_complex)
        cve_collection['exploitabilaty'].append(exploitabilaty)
        cve_collection['refs'].append(refs)

    cve_df = pd.DataFrame.from_dict(cve_collection)

    base_scores_plot_data = cve_df['base_severity'].value_counts()
    fig = px.bar(x=base_scores_plot_data.index,
                 y=base_scores_plot_data)
    fig.update_layout(template="plotly_white",
                      title="Distribution of Base Severity",
                      xaxis_title="Severity",
                      yaxis_title="Counts")
    fig.update_traces(marker_color='#009A44', marker_line_color='#000',
                      marker_line_width=1.5, opacity=0.65)
    fig.write_image("./scan_results/{}/imgs/severity_count.png".format(scan_name))

    single_plot_data = cve_df['base_score'].value_counts()
    fig = px.bar(x=single_plot_data.index,
                 y=single_plot_data)
    fig.update_layout(template="plotly_white",
                      title="Distribution of Base Score",
                      yaxis_title="Count",
                      xaxis_title="Base Score")
    fig.update_traces(marker_color='#009A44', marker_line_color='#000',
                      marker_line_width=1.5, opacity=0.6)
    fig.write_image("./scan_results/{}/imgs/base_score_count.png".format(scan_name))

    single_plot_data = cve_df['exploitabilaty'].value_counts()
    fig = px.bar(x=single_plot_data.index,
                 y=single_plot_data)
    fig.update_layout(template="plotly_white",
                      title="Distribution of Exploitabilaty Score",
                      yaxis_title="Count",
                      xaxis_title="Exploitabilaty Score")
    fig.update_traces(marker_color='#009A44', marker_line_color='#000',
                      marker_line_width=1.5, opacity=0.6)
    fig.write_image("./scan_results/{}/imgs/exploitabilaty_score_count.png".format(scan_name))

    single_plot_data = cve_df['att_complex'].value_counts()
    fig = px.bar(x=single_plot_data.index,
                 y=single_plot_data)
    fig.update_layout(template="plotly_white",
                      title="Distribution of Attack Complexity",
                      yaxis_title="Count",
                      xaxis_title="Attack Complexity")
    fig.update_traces(marker_color='#009A44', marker_line_color='#000',
                      marker_line_width=1.5, opacity=0.6)
    # fig.show()
    fig.write_image("./scan_results/{}/imgs/attack_complexity_count.png".format(scan_name))

    fig = go.Figure()

    tab = go.Table(header=dict(values=[i for i in list(cve_df.columns) if i not in ["desc", "refs"]],
                               line_color="#AEAEAE",
                               fill_color='#009A44',
                               font=dict(color='white', size=14),
                               height=30
                               ),
                   cells=dict(values=[cve_df['cve'],
                                      cve_df['base_score'],
                                      cve_df['base_severity'],
                                      cve_df['att_vector'],
                                      cve_df['att_complex'],
                                      cve_df['exploitabilaty']],
                              # font_color='black',
                              font_size=14,
                              height=30))

    fig.add_trace(tab)
    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)')

    fig.write_image("./scan_results/{}/imgs/cve_table.png".format(scan_name))
    cve_df.to_csv("./scan_results/{}/imgs/cve.csv".format(scan_name))


def scan_rookits(password, scan_name):
    rootkit_scan_cmd = "chkrootkit"
    rootkit_out = call_cmd(rootkit_scan_cmd, password=password)

    detected_problems = {}
    broken_lines = rootkit_out.split("\n")
    for n, line in enumerate(broken_lines):
        if line.startswith("Checking") or line.startswith("Searching") or line.startswith("Checking"):
            split_line = [i.strip() for i in line.split("...")]
            if len(split_line) == 2:
                if 'not' not in split_line[-1]:
                    if "no " not in split_line[-1]:
                        if "were found" in split_line[-1]:
                            issue_line = n
                            detected_problems[split_line[1]] = ''
                            while True:
                                issue_line += 1
                                next_lines_check = broken_lines[issue_line]
                                # print(next_lines_check)
                                if not (next_lines_check.startswith("Checking") or next_lines_check.startswith(
                                        "Searching") or next_lines_check.startswith(
                                    "Checking") or next_lines_check.startswith("!")):
                                    detected_problems[split_line[1]] += " " + next_lines_check
                                else:
                                    break

    if len(detected_problems) != 0:
        fig = go.Figure()

        cell_vals1 = []
        cell_vals2 = []
        for i in detected_problems:
            cell_vals1.append(i)
            cell_vals2.append(detected_problems[i])

        tab = go.Table(
            cells=dict(values=[cell_vals1, cell_vals2],
                       # font_color='black',
                       font_size=14,
                       height=30))

        fig.add_trace(tab)
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)')

        fig.show()
        fig.write_image("./scan_results/{}/imgs/rootkit_scans.png".format(scan_name))



