from time import sleep

import aiohttp, aiofiles, asyncio, json, os, requests
from bs4 import BeautifulSoup
from typing import Any


def read_init_file(*,path:str) -> str:

    try:
        if os.path.exists(path):
            with open(path,"r",encoding="utf-8") as file:
                number = file.readlines()[-1]
                print(f"> Start with {number}")
                file.close()
                return number

        else:
            with open(path, "a",encoding="utf-8") as file:
                print(f"> Create file `{path}`")
                file.close()
                return "None"
    except IndexError:
        return "None"



def find_needed_line(*,text:str) -> list[str]:

    if text == "None":
        with open("example.txt", "r", encoding="utf-8") as file:
            return file.readlines()

    else:
        lines = []
        with open("example.txt", "r", encoding="utf-8") as file:
            lines = file.readlines()
        code = 0
        for i in range(len(lines)):
            if lines[i].strip() == text.strip():
                code = i
                return lines[code::]
        if code == 0:
            return lines




def query_to_API(*,list_to_query:list[str]) -> None:

    cve_link = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
    cpe_link = f"https://services.nvd.nist.gov/rest/json/cpematch/2.0?cveId="

    for line in list_to_query:
        sleep(8)
        response_cve = requests.get(cve_link + line.strip())
        sleep(8)
        response_cpe = requests.get(cpe_link + line.strip())

        to_json_cve = BeautifulSoup(response_cve.content, "html.parser")
        to_json_cpe = BeautifulSoup(response_cpe.content, "html.parser")

        print(f"> LOG (query_to_API): CVE -> {to_json_cve}")
        print(f"> LOG (query_to_API): CPE -> {to_json_cpe}")

        json_cve = json.loads(to_json_cve.text)
        json_cpe = json.loads(to_json_cpe.text)

        cve_id = ""
        cve_name = ""
        cve_description = ""
        cve_cvss_v2_vector = "N/A"
        cve_cvss_v2_basescore = "0"
        cve_cvss_v3_vector = "N/A"
        cve_cvss_v3_basescore = "0"

        try:
            cve_id = json_cve["Data"]["vulnerabilities"][0]["cve"]["id"].replace("CVE", "").replace("-", "")
            cve_name = json_cve["Data"]["vulnerabilities"][0]["cve"]["id"]
            cve_description = json_cve["Data"]["vulnerabilities"][0]["cve"]["descriptions"][0]["value"]
            cve_cvss_v2_vector = json_cve["Data"]["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["vectorString"]
            cve_cvss_v2_basescore = json_cve["Data"]["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"]
            cve_cvss_v3_vector = json_cve["Data"]["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["vectorString"]
            cve_cvss_v3_basescore = json_cve["Data"]["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]

        except KeyError as key_error:
            print(f"Error (parsing_json) CVE NO KEY! -> {key_error}")

        with open("continue.txt","a",encoding="utf-8") as cont:
            cont.write(f"{line}")

        print(f"LOG (query_to_API):"
              f"cve_id - {cve_id},\n"
              f"cve_name - {cve_name},\n"
              f"cve_description - {cve_description},\n"
              f"cve_cvss_v2_vector - {cve_cvss_v2_vector},\n"
              f"cve_cvss_v2_basescore - {cve_cvss_v2_basescore},\n"
              f"cve_cvss_v3_vector - {cve_cvss_v3_vector},\n"
              f"cve_cvss_v3_basescore - {cve_cvss_v3_basescore}\n")




def main():
    line = read_init_file(path="continue.txt")
    print(f"- LOG (read_init_file): {line}")
    list_to_query = find_needed_line(text=line)
    print(f"- LOG (find_needed_line): {list_to_query}")

    query_to_API(list_to_query=list_to_query)



if __name__ == "__main__":
    main()