import socket

with open("targets.txt") as targets:
    for target in targets:
        try:
            addr1 = socket.gethostbyname(target.strip())
            print(addr1)
        except:
            pass
