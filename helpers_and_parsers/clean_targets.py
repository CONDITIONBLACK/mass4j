with open("targets.txt") as targets:
    for target in targets:
        try:
            int(target.split(".")[0])
            print(target.strip())
        except:
            pass
