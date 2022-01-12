ports = [21, 22, 23, 24, 25, 9200, 8080, 8081, 8085, 8443, 443, 8000, 8888, 8983]

f = open("ips_and_ports.txt", "w")

with open("partialips.txt") as allips:
    for ip in allips:
        ip = str(ip.strip())
        for port in ports:
            ip_with_port = ip + ":" + str(port)
            f.write(ip_with_port + "\n")
