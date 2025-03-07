import aiohttp, aiofiles, asyncio, json
from typing import Any

from selenium.webdriver.common.devtools.v85.fetch import continue_request


async def get_data_txt(*, path:str) -> list[dict[str, bool | Any]] | None:

    lines = None
    async with aiofiles.open(path, "r") as file:
        try:
            lines = await file.readlines()
            await file.close()
        except Exception as exc:
            print(f"Error (get_data_txt): READ FILE! -> {exc}")


    tasks = []
    async with aiohttp.ClientSession() as session:
        try:
            for line in lines:

                cve_link = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={line}"
                cpe_link = f"https://services.nvd.nist.gov/rest/json/cpematch/2.0?cveId={line}"

                task = asyncio.create_task(fetch_API(session=session,link=cve_link,isCve=True))
                tasks.append(task)
                # print(f"Create task for {cve_link}")
                await asyncio.sleep(7)

                task = asyncio.create_task(fetch_API(session=session,link=cpe_link, isCve=False))
                # print(f"Create task for {cpe_link}")
                tasks.append(task)
                await asyncio.sleep(7)

            data_list = await asyncio.gather(*tasks)
            return data_list


        except aiohttp.ClientError as http_err:
            print(f"Error (get_data_txt) : {http_err}")


async def parsing_json(*, dump:dict[str]) -> dict[str,str] | None:
    if dump["isCve"] and dump["Data"] != "":
        print(" --- ---  --- CVE --- --- --- ")
        # print(f"Data: {dump["Data"]}")

        # VALUEs
        cve_name = ""
        cve_description = ""

        cve_cvss_v2_vector = ""
        cve_cvss_v2_basescore = ""

        cve_cvss_v3_vector = ""
        cve_cvss_v3_basescore = ""

        try:
            # CVE Name
            cve_name = dump["Data"]["vulnerabilities"][0]["cve"]["id"]
            print(f"Name:               {cve_name}")
            # CVE Description
            cve_description = dump["Data"]["vulnerabilities"][0]["cve"]["descriptions"][0]["value"]
            print(f"Description:        {cve_description}")
            # CVE CVSS v2 VECTOR
            cve_cvss_v2_vector = dump["Data"]["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["vectorString"]
            print(f"CVSS v2 Vector:     {cve_cvss_v2_vector}")
            # CVE CVSS v2 BASESCORE
            cve_cvss_v2_basescore = dump["Data"]["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"]
            print(f"CVSS v2 BaseScore:  {cve_cvss_v2_basescore}")
            # CVE CVSS v3 VECTOR
            cve_cvss_v3_vector = dump["Data"]["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["vectorString"]
            print(f"CVSS v3 Vector:     {cve_cvss_v3_vector}")
            # CVE CVSS v3 BASESCORE
            cve_cvss_v3_basescore = dump["Data"]["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
            print(f"CVSS v3 BaseScore:  {cve_cvss_v3_basescore}")

        except KeyError as key_error:
            print(f"Error (parsing_json) CVE NO KEY! -> {key_error}")

        finally:
            return {"cve_name": cve_name,
                "cve_description": cve_description,
                "cve_cvss_v2_vector": cve_cvss_v2_vector,
                "cve_cvss_v2_basescore": cve_cvss_v2_basescore,
                "cve_cvss_v3_vector": cve_cvss_v3_vector,
                "cve_cvss_v3_basescore": cve_cvss_v3_basescore}

    if dump["isCve"] == False and dump["Data"] != "":
        print(" --- ---  --- CPE --- --- --- ")
        print(f"Data: {dump["Data"]}")

        # VALUEs
        cve_name = ""
        cpes_strings = []
        cpes_status = []
        cpes_id = []

        try:
            # CPE cve_name
            cve_name = dump["Link"].replace("https://services.nvd.nist.gov/rest/json/cpematch/2.0?cveId=","").replace(".json","")
            # print(f"CVE Name:               {cve_name}")
            matchStrings = dump["Data"]["matchStrings"]
            for matchString in matchStrings:
                cpes_id.append(matchString["matchString"]["matchCriteriaId"])
                cpes_strings.append(matchString["matchString"]["criteria"])
                cpes_status.append(matchString["matchString"]["status"])

            for i in range(len(cpes_strings)):
                print(f"CPE ID:                 {cpes_id[i]}")
                print(f"CPE String:             {cpes_strings[i]}")
                print(f"CPE Status:             {cpes_status[i]}")
                cpe_slices = cpes_strings[i].split(":")
                match cpe_slices[2]:
                    case "a":
                        print("CPE part:               Application")
                    case "o":
                        print("CPE part:               OS")
                    case "h":
                        print("CPE part:               Hardware")

                print(f"CPE vendor:             {cpe_slices[3]}")
                print(f"CPE product:            {cpe_slices[4]}")
                # print(f"CPE version:            {cpe_slices[5]}")
                match cpe_slices[5]:
                    case "*":
                        print(f"CPE version:            Any")
                    case "-":
                        print(f"CPE version:            N/A")
                    case _:
                        print(f"CPE version:            {cpe_slices[5]}")
                # print(f"CPE update:             {cpe_slices[6]}")
                match cpe_slices[6]:
                    case "*":
                        print(f"CPE update:             Any")
                    case "-":
                        print(f"CPE update:             N/A")
                    case _:
                        print(f"CPE update:             {cpe_slices[6]}")
                # print(f"CPE edition:            {cpe_slices[7]}")
                match cpe_slices[7]:
                    case "*":
                        print(f"CPE edition:            Any")
                    case "-":
                        print(f"CPE edition:            N/A")
                    case _:
                        print(f"CPE edition:            {cpe_slices[7]}")
                # print(f"CPE language:           {cpe_slices[8]}")
                match cpe_slices[8]:
                    case "*":
                        print(f"CPE language:           Any")
                    case "-":
                        print(f"CPE language:           N/A")
                    case _:
                        print(f"CPE language:           {cpe_slices[8]}")
                # print(f"CPE edition_sw:         {cpe_slices[9]}")
                match cpe_slices[9]:
                    case "*":
                        print(f"CPE edition_sw:         Any")
                    case "-":
                        print(f"CPE edition_sw:         N/A")
                    case _:
                        print(f"CPE edition_sw:         {cpe_slices[9]}")
                # print(f"CPE target_sw:          {cpe_slices[10]}")
                match cpe_slices[10]:
                    case "*":
                        print(f"CPE target_sw:          Any")
                    case "-":
                        print(f"CPE target_sw:          N/A")
                    case _:
                        print(f"CPE target_sw:          {cpe_slices[10]}")
                # print(f"CPE target_hw:          {cpe_slices[11]}")
                match cpe_slices[11]:
                    case "*":
                        print(f"CPE target_hw:          Any")
                    case "-":
                        print(f"CPE target_hw:          N/A")
                    case _:
                        print(f"CPE target_hw:          {cpe_slices[11]}")
                # print(f"Other:                  {cpe_slices[12]}")
                match cpe_slices[12]:
                    case "*":
                        print(f"Other:                  Any")
                    case "-":
                        print(f"Other:                  N/A")
                    case _:
                        print(f"Other:                  {cpe_slices[12]}")





        except KeyError as key_error:
            print(f"Error (parsing_json) CPE NO KEY! -> {key_error}")




async def fetch_API(*,session:aiohttp.ClientSession, link:str, isCve:bool) : #-> dict[str, bool | Any] | None:
    async with session.get(link) as response:
        try:
            await asyncio.sleep(10)
            if response.status == 200:
                print(f"Access: HTTP Code -> {response.status}")
                data = await response.text()
                json_dump = json.loads(data)
                dump = { "isCve" : isCve,
                        "Data" : json_dump,
                        "Link" : link }
                await parsing_json(dump=dump)
                # return dump
            else:
                print(f"Error: HTTP Code -> {response.status}")
                dump =  { "isCve": isCve,
                        "Data": "",
                        "Link" : link }
                await parsing_json(dump=dump)
                # return dump
        except aiohttp.ClientError as http_err:
            print(f"Error (fetch_API) :{http_err}")




async def main():
    data_txt = await get_data_txt(path="cves_list.txt")
    full_dump = []
    # for item in data_txt:
        # data_json_dump = await parsing_json(dump=item)
        # full_dump.append(data_json_dump)
    # print(*full_dump, sep=" ")

        # print("Данные API не были получены!")


if __name__ == "__main__":
    asyncio.run(main())