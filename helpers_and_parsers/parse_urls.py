with open("nk_hostnames.txt") as hostnames:
    for hostline in hostnames:
        hostline = hostline.strip()
        print(hostline.split("-")[0].strip())
