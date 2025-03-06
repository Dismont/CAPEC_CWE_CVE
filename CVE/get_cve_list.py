import os

def get_list_cves(*, path:str) -> int:
    iteration = 0
    with open("cves_list.txt", "a") as f:
        for root, _, files in os.walk(path):
            for file in  files:
                iteration += 1
                f.write(f"{file.replace(".json","")}\n")
        f.close()

    return iteration



def main():
    iteration = get_list_cves(path="G:/Projects/cvelistV5/cves")
    print(f"Создано {iteration} записей")



if __name__ == "__main__":
    main()