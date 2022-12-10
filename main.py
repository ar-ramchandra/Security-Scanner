if __name__ == "__main__":
    from getpass import getpass

    from funcs.scans import all_scans, get_ip, install_packages
    from generateReport import makeReport
    scan_name = input("Name the scan")
    ip_addresses, single_ip = get_ip()
    sudo_pass = getpass("Please Enter Sudo Password: ")
    install_packages(sudo_pass)
    all_scans(ip_address=ip_addresses,
              single_ip=single_ip,
              password=sudo_pass,
              scan_name=scan_name
              )
    print("All scans Completed... Generating report...")
    makeReport(scan_name=scan_name)
