import time
import os



def read_gen(filepath, follow):
    while not os.path.exists(filepath) and follow:
        print(f"[*] Waiting for log file {filepath} to be created...")
        time.sleep(1)

    with open(filepath, "r", encoding="utf-8") as f:
        while True:
            line = f.readline()
            if line:
                yield line
            else:
                if follow:
                    time.sleep(0.2)
                else:
                    break

