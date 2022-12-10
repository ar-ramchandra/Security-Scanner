from fpdf import FPDF
from datetime import datetime, timedelta, date
import os

width = 210
height = 297

testDate = (datetime.today()).strftime("%m/%d/%y").replace("/0", "/").lstrip("0")


def undGreenFont(pdf):
    pdf.set_text_color(r=0, g=158, b=68)


def blackFont(pdf):
    pdf.set_text_color(r=0, g=0, b=0)


def createTitle(day, pdf):
    pdf.set_font('Arial', '', 24)
    pdf.ln(40)
    pdf.write(5, f"Security Scan Report")
    pdf.ln(10)
    pdf.set_font('Arial', '', 16)
    pdf.write(4, f'{day}')
    pdf.ln(5)


def createDisclaimer(pdf):
    pdf.set_font('Times', 'BU', 14)
    pdf.ln(5)
    pdf.set_text_color(r=235, g=41, b=57)
    pdf.write(5, f"Disclaimer:")
    pdf.ln(10)
    blackFont(pdf)
    pdf.set_font('Times', '', 12)
    pdf.multi_cell(0, 4,
                   f'To protect plants, systems, machines, and networks against cyber threats, it is necessary to implement and continuously maintain a holistic, state-of-the-art security program. In such a program, the Software reports and suggests only one element. It is your responsibility to prevent unauthorized access to systems, machines, and networks that should only be connected to an enterprise network or the internet if and to the extent that such a connection is necessary, and only when appropriate security measures (e.g. firewalls and/or network segmentation) are in place. Periodically, CySeT and/or its licensors update the Software. Such Updates should be applied as soon as they are available and the latest version should be used. Faultiness in reports generated may be increased by using outdated Update versions and failing to apply the latest Updates. In order to stay on top of the latest security threats, patches, and other related measures, CySeT encourages you to use the generated report as a means of keeping up with public security advisories. \n\n\nNote: It is important to note that even if the report indicates that the system is 100% safe, it does not necessarily mean that you are safe. Make sure you are protected from cyber threats, they are everywhere.',
                   0, 'J')
    pdf.ln(5)


def createScanText(pdf):
    pdf.set_font('Times', 'BU', 14)
    pdf.ln(3)
    undGreenFont(pdf)
    # pdf.set_text_color(r = 0 , g = 158 , b = 68)
    pdf.write(5, f"Scans Results:")
    pdf.ln(10)
    pdf.set_font('Times', '', 12)
    blackFont(pdf)
    pdf.multi_cell(0, 4,
                   f'The below figure and tables represent the results of the scan that was conducted to test the security of the system provided. Please note that, these results might not be 100% accurate and the figures were purposefully made for a better understanding. ',
                   0, 'J')


# pdf.write(4, f'The Scans were conducted using the curated open source scanners, which is tested against the host system to ensure the security levels')

def makeReport(scan_name):
    filename = f"./scan_results/{scan_name}/Security_Scan_Report.pdf"
    pdf = FPDF()
    day = (datetime.today()).strftime("%m/%d/%y").replace("/0", "/").lstrip("0")

    '''First Page'''
    pdf.add_page()
    pdf.image("./static/headerCropped.png", 0, 0, width)

    createTitle(day, pdf),
    createDisclaimer(pdf)
    createScanText(pdf)

    # Network Diagram
    pdf.ln(5)
    pdf.set_font('times', 'B', 14)
    pdf.write(5, f'1. Host Discovery:\n')
    pdf.set_font('times', '', 12)
    pdf.multi_cell(0, 5,
                   f'The scan is made on the network to identify the devices that are active on the network. The scan found these devices on your network. The figure visualizes the devices that are connected to your network.\n  ',
                   0, 'J')
    pdf.ln(5)

    pdf.image(f"./scan_results/{scan_name}/imgs/network_diagram_auto.png", 50, 185, width / 2, )
    pdf.ln(70)
    pdf.set_font('times', '', 12)
    pdf.multi_cell(0, 0, f'Network Diagram', 0, 'C')
    pdf.set_font('', 'BU', 12)

    '''Second Page'''
    pdf.add_page()
    # pdf.ln(40)
    # pdf.write(5, f'What to do:\n')
    # pdf.set_font('times', '', 12)
    # pdf.multi_cell(0, 5, f'If you find any malicious or unknown devices in your network, please remove them from your network space and safeguard your system.', 0, "J")

    # open ports
    pdf.ln(5)
    pdf.set_font('times', 'B', 14)
    pdf.write(5, f'2. Open Ports:\n')
    pdf.ln(3)
    pdf.set_font('times', '', 12)
    '''The following table represents the ports that are open in the system scanned. Please take effective measures on closing the unnecessary open ports'''
    pdf.multi_cell(0, 5,
                   f'The device was scanned for open ports, which resulted in the following table. The table depicts the ports that are open, the protocol in use and the services that are currently running. List of suggestive measures can be found in section x.x.',
                   0, 'J')
    pdf.image(f"./scan_results/{scan_name}/imgs/open_ports.png", 20, 25, width / 1.2, )
    pdf.ln(40)
    pdf.multi_cell(0, 5, f'List of Open Ports', 0, 'C')

    # cve table
    pdf.ln(5)
    pdf.set_font('times', 'B', 14)
    pdf.write(5, f'3. Vulnerabilities found:\n')
    pdf.ln(3)
    pdf.set_font('times', '', 12)
    pdf.multi_cell(0, 5,
                   f'The device is scanned for vulnerabilities, the following visualizations depict the severity of the vulnerabilities that are present in the system using various metrics.',
                   0, 'J')
    pdf.ln(5)
    pdf.image(f"./scan_results/{scan_name}/imgs/exploitabilaty_score_count.png", 10, 120, width / 2 - 10, )
    pdf.image(f"./scan_results/{scan_name}/imgs/severity_count.png", width / 2, 120, width / 2 - 10, )
    pdf.image(f"./scan_results/{scan_name}/imgs/attack_complexity_count.png", 10, 200, width / 2 - 10, )
    pdf.image(f"./scan_results/{scan_name}/imgs/base_score_count.png", width / 2, 200, width / 2 - 10, )

    # pdf.image("./scan_results/scan1/imgs/cve_table.png", 50, 30, width / 2, )
    # pdf.ln(55)
    # pdf.set_font('times', '', 12)
    # pdf.multi_cell(
    #     0,
    #     5,
    #     f'CVE, short for Common Vulnerabilities and Exposures, is a list of publicly disclosed computer security flaws. When someone refers to a CVE, they mean a security flaw that has been assigned a CVE ID number.\n\n The above table show the common vulnerabilities that has been identified during the testing process.',
    #     0,
    #     'J'
    #     )
    # pdf.ln(3)

    # pdf.set_font('', 'BU', 14)
    # pdf.write(5, f'What to do:\n')
    # pdf.set_font('times', '', 12)
    # pdf.multi_cell(0,5,f'you can either solve the vulnerabilities that are present by referring to any of the available open source vulnerability database or consult a cyber security professional to deal with it\n ',0,"J")
    # pdf.set_font('', 'B', 12)
    # pdf.write(5, f'Open Source Vulnerability Databases: \n')
    # pdf.ln(3)

    # pdf.set_text_color(r = 0 , g = 0 , b = 238)
    # pdf.set_font('', 'U', 12)
    # pdf.write(5, f'1. NIST Vulnerability Database (NVD)\n','https://www.nist.gov/programs-projects/national-vulnerability-database-nvd')
    # pdf.write(5, f'2. Mend Open source Vulnerability Database\n', 'https://www.mend.io/vulnerability-database/')
    # pdf.write(5, f'3. Ubuntu CVE Reports\n', 'https://ubuntu.com/security/cves\n\n')
    # pdf.ln(5)

    # pdf.set_font('Times', 'BU', 14)
    # pdf.set_text_color(r = 235 , g = 41 , b = 57)
    # pdf.write(5, f'Note:\n')
    # pdf.set_font('times', '', 12)
    # blackFont(pdf)
    # pdf.multi_cell(0,5,f'CySeT recommends to consult a cyber security freelancer or a professional. However, CySeT is not to be held account for the consequences or problems by mishandling the system security.',0,"J")

    # pdf.ln(5)
    # pdf.set_font('times', 'B', 14)
    # pdf.write(5, f'Attack Complexity:\n')
    # pdf.set_font('times', '', 12)
    # pdf.multi_cell(0,5,f'The complexity of the system to make it hard for bad actors to exploit is referred to as attack complexity. The higher the attack complexity, the harder it is to exploit and get into the system.', 0, 'J')
    # pdf.image("./scan_results/scan1/imgs/attack_complexity_count.png", 70, 200, width / 3, )
    # pdf.ln(60)
    # pdf.multi_cell(0,5,f'High - Your system is less probably to be compromised.\nMedium - Your system probably have weak spots that can be compromised.\nLow - Your system is at risk and can be compromised easily.', 0, 'J')

    '''third page'''
    pdf.add_page()
    pdf.ln(5)
    pdf.multi_cell(0, 5, f'The vulnerabilities present in the scanned system are summarized in the following table.', 0,
                   'J')
    pdf.image(f"./scan_results/{scan_name}/imgs/cve_table.png", 50, 10, width / 2, )
    pdf.ln(50)
    pdf.set_font('times', 'B', 14)
    pdf.write(5, f'4. Rootkit Scan:\n')
    pdf.set_font('times', '', 12)
    pdf.multi_cell(0, 5,
                   f'The system is scanned to detect if there is any presence of rootkit (malware program) that can be used to compromise the device controls. The findings or result of the rootkit scan conducted is depicted below in the form of a table.',
                   0, 'J')
    pdf.image(f"./scan_results/{scan_name}/imgs/rootkit_scans.png", 50, 80, width / 2, )
    pdf.ln(65)
    pdf.set_font('times', 'B', 14)


    # pdf.write(5, f'Static Suggestions:\n')

    # pdf.set_font('times', 'B', 14)
    # pdf.write(5, f'Open Ports:\n')
    # pdf.set_font('times', '', 12)
    # pdf.multi_cell(0,5,f'The following table represents the ports that are open in the system scanned. Please take effective measures on closing the unnecessary open ports.', 0, 'J')

    # pdf.image("./scan_results/scan1/imgs/open_ports.png", 20 , 10, width / 1.2, )
    # pdf.ln(40)
    # pdf.set_font('times', 'B', 14)
    # pdf.write(5, f'Other Score Reports:\n')
    # pdf.image("./scan_results/scan1/imgs/exploitabilaty_score_count.png", 5 , 80, width / 2-10, )
    # pdf.image("./scan_results/scan1/imgs/severity_count.png", width/2 , 80, width / 2 - 10, )

    # output renderer
    pdf.output(filename, 'F')
