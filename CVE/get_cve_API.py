import aiohttp, aiofiles, asyncio, json
from typing import Any



async def get_data_txt(*, path:str) :#-> list[dict[str, str]] | None:

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
            # return data_list


        except aiohttp.ClientError as http_err:
            print(f"Error (get_data_txt) : {http_err}")




async def parsing_json(*, dump:dict[str, bool | str | Any]) -> None:
    if dump["isCve"] and dump["Data"] != "":
        print(" --- ---  --- CVE --- --- --- ")
        # print(f"Data: {dump["Data"]}")

        # VALUEs
        cve_id = ""
        cve_name = ""
        cve_description = ""

        cve_cvss_v2_vector = "N/A"
        cve_cvss_v2_basescore = "0"

        cve_cvss_v3_vector = "N/A"
        cve_cvss_v3_basescore = "0"

        try:
            # CVE Name
            cve_id = dump["Data"]["vulnerabilities"][0]["cve"]["id"].replace("CVE", "").replace("-", "")
            print(f"ID:                     {cve_id}")
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

            data = {
                "isCve"                 : dump["isCve"],
                "cve_id"                : cve_id,
                "cve_name"              : cve_name,
                "cve_description"       : cve_description,
                "cve_link"              : dump["Link"],
                "cve_cvss_v2_vector"    : cve_cvss_v2_vector,
                "cve_cvss_v2_basescore" : cve_cvss_v2_basescore,
                "cve_cvss_v3_vector"    : cve_cvss_v3_vector,
                "cve_cvss_v3_basescore" : cve_cvss_v3_basescore
            }
            await writer(data=data)
            # return {
            #     "isCve"                 : dump["isCve"],
            #     "cve_link"              : dump["Link"],
            #     "cve_id"                : cve_id,
            #     "cve_name"              : cve_name,
            #     "cve_description"       : cve_description,
            #     "cve_cvss_v2_vector"    : cve_cvss_v2_vector,
            #     "cve_cvss_v2_basescore" : cve_cvss_v2_basescore,
            #     "cve_cvss_v3_vector"    : cve_cvss_v3_vector,
            #     "cve_cvss_v3_basescore" : cve_cvss_v3_basescore
            # }

    if dump["isCve"] == False and dump["Data"] != "":
        print(" --- ---  --- CPE --- --- --- ")
        # print(f"Data: {dump["Data"]}")

        # VALUEs
        cve_id = ""
        cpes_id =       []
        cpes_strings =  []
        cpes_status =   []
        cpes_part =     []
        cpes_vendor =   []
        cpes_product =  []
        cpes_version =  []
        cpes_update =   []
        cpes_edition =  []
        cpes_language = []
        cpes_edition_sw = []
        cpes_target_sw = []
        cpes_target_hw = []
        cpes_other =    []

        try:
            # CPE cve_name
            cve_id = dump["Link"].replace("https://services.nvd.nist.gov/rest/json/cpematch/2.0?cveId=","").replace(".json","").replace("CVE","").replace("-","")
            print(f"CVE Id:               {cve_id}")
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

                    case 'a':
                        print("CPE part:               Application")
                        cpes_part.append("Application")
                    case "o":
                        print("CPE part:               OS")
                        cpes_part.append("OS")
                    case 'h':
                        print("CPE part:               Hardware")
                        cpes_part.append("Hardware")
                # print(f"CPE part:            {cpe_slices[2]}")

                print(f"CPE vendor:             {cpe_slices[3]}")
                cpes_vendor.append(cpe_slices[3])

                print(f"CPE product:            {cpe_slices[4]}")
                cpes_product.append(cpe_slices[4])
                # print(f"CPE version:            {cpe_slices[5]}")

                match cpe_slices[5]:
                    case "*":
                        print(f"CPE version:            Any")
                        cpes_version.append("Any")
                    case "-":
                        print(f"CPE version:            N/A")
                        cpes_version.append("N/A")
                    case _:
                        print(f"CPE version:            {cpe_slices[5]}")
                        cpes_version.append(cpe_slices[5])
                # print(f"CPE update:             {cpe_slices[6]}")

                match cpe_slices[6]:
                    case "*":
                        print(f"CPE update:             Any")
                        cpes_update.append("Any")
                    case "-":
                        print(f"CPE update:             N/A")
                        cpes_update.append("N/A")
                    case _:
                        print(f"CPE update:             {cpe_slices[6]}")
                        cpes_update.append(cpe_slices[6])
                # print(f"CPE edition:            {cpe_slices[7]}")

                match cpe_slices[7]:
                    case "*":
                        print(f"CPE edition:            Any")
                        cpes_edition.append("Any")
                    case "-":
                        print(f"CPE edition:            N/A")
                        cpes_edition.append("N/A")
                    case _:
                        print(f"CPE edition:            {cpe_slices[7]}")
                        cpes_edition.append(cpe_slices[7])
                # print(f"CPE language:           {cpe_slices[8]}")

                match cpe_slices[8]:
                    case "*":
                        print(f"CPE language:           Any")
                        cpes_language.append("Any")
                    case "-":
                        print(f"CPE language:           N/A")
                        cpes_language.append("N/A")
                    case _:
                        print(f"CPE language:           {cpe_slices[8]}")
                        cpes_language.append(cpe_slices[8])
                # print(f"CPE edition_sw:         {cpe_slices[9]}")

                match cpe_slices[9]:
                    case "*":
                        print(f"CPE edition_sw:         Any")
                        cpes_edition_sw.append("Any")
                    case "-":
                        print(f"CPE edition_sw:         N/A")
                        cpes_edition_sw.append("N/A")
                    case _:
                        print(f"CPE edition_sw:         {cpe_slices[9]}")
                        cpes_edition_sw.append(cpe_slices[9])
                # print(f"CPE target_sw:          {cpe_slices[10]}")

                match cpe_slices[10]:
                    case "*":
                        print(f"CPE target_sw:          Any")
                        cpes_target_sw.append("Any")
                    case "-":
                        print(f"CPE target_sw:          N/A")
                        cpes_target_sw.append("N/A")
                    case _:
                        print(f"CPE target_sw:          {cpe_slices[10]}")
                        cpes_target_sw.append(cpe_slices[10])
                # print(f"CPE target_hw:          {cpe_slices[11]}")

                match cpe_slices[11]:
                    case "*":
                        print(f"CPE target_hw:          Any")
                        cpes_target_hw.append("Any")
                    case "-":
                        print(f"CPE target_hw:          N/A")
                        cpes_target_hw.append("N/A")
                    case _:
                        print(f"CPE target_hw:          {cpe_slices[11]}")
                        cpes_target_hw.append(cpe_slices[11])
                # print(f"Other:                  {cpe_slices[12]}")

                match cpe_slices[12]:
                    case "*":
                        print(f"Other:                  Any")
                        cpes_other.append("Any")
                    case "-":
                        print(f"Other:                  N/A")
                        cpes_other.append("N/A")
                    case _:
                        print(f"Other:                  {cpe_slices[12]}")
                        cpes_other.append(cpe_slices[12])


        except KeyError as key_error:
            print(f"Error (parsing_json) CPE NO KEY! -> {key_error}")

        finally:
            data = {
                "isCve": dump["isCve"],
                "cve_id": cve_id,
                "cpe_link" : dump["Link"],
                "cpes_strings" : cpes_strings,
                "cpes_status" : cpes_status,
                "cpes_part":cpes_part,
                "cpes_vendor":cpes_vendor,
                "cpes_product":cpes_product,
                "cpes_version":cpes_version,
                "cpes_update":cpes_update,
                "cpes_edition":cpes_edition,
                "cpes_language":cpes_language,
                "cpes_edition_sw":cpes_edition_sw,
                "cpes_target_sw":cpes_target_sw,
                "cpes_target_hw":cpes_target_hw,
                "cpes_other":cpes_other
            }
            await writer(data=data)
            # return {
            #         "isCve"  : dump["isCve"],
            #         "cve_id" : cve_id ,
            #         "cpe_link" : dump["Link"],
            #         "cpes_strings" : cpes_strings,
            #         "cpes_status" : cpes_status,
            #         "cpes_part":cpes_part,
            #         "cpes_vendor":cpes_vendor,
            #         "cpes_product":cpes_product,
            #         "cpes_version":cpes_version,
            #         "cpes_update":cpes_update,
            #         "cpes_edition":cpes_edition,
            #         "cpes_language":cpes_language,
            #         "cpes_edition_sw":cpes_edition_sw,
            #         "cpes_target_sw":cpes_target_sw,
            #         "cpes_target_hw":cpes_target_hw,
            #         "cpes_other":cpes_other
            # }




async def fetch_API(*,session:aiohttp.ClientSession, link:str, isCve:bool) -> dict[str,  str ] | None:
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
                pars_dict = await parsing_json(dump=dump)
                return pars_dict
            else:
                print(f"Error: HTTP Code -> {response.status}")
                dump =  { "isCve": isCve,
                        "Data": "",
                        "Link" : link }
                pars_dict = await parsing_json(dump=dump)
                return pars_dict

        except aiohttp.ClientError as http_err:
            print(f"Error (fetch_API) :{http_err}")



async def writer (*, data:dict[str, str]) -> None:

    print(data)
    if data["isCve"]:
        async with aiofiles.open("INSERT_cve_ENTITY_query.sql","a") as file:
                #     "cve_id"                : cve_id,
                #     "cve_name"              : cve_name,
                #     "cve_description"       : cve_description,
                #     "cve_link"              : dump["Link"],
                #     "cve_cvss_v2_vector"    : cve_cvss_v2_vector,
                #     "cve_cvss_v2_basescore" : cve_cvss_v2_basescore,
                #     "cve_cvss_v3_vector"    : cve_cvss_v3_vector,
                #     "cve_cvss_v3_basescore" : cve_cvss_v3_basescore
            await file.write(f"({data["cve_id"]}, '{data["cve_name"]}', '{data["cve_description"].replace("\n","").replace("'","`").replace("\t"," ").strip()}', '{data["cve_link"].replace("\n","").strip()}', '{data["cve_cvss_v2_vector"]}', {data["cve_cvss_v2_basescore"]}, '{data["cve_cvss_v3_vector"]}', {data["cve_cvss_v3_basescore"]}),\n")

    if not data["isCve"]:
        async with aiofiles.open("INSERT_cpe_ENTITY_query.sql", "a") as file:
            print("")
            #         "cve_id" : cve_id ,
            #         "cpes_strings" : cpes_strings,
            #         "cpes_status" : cpes_status,
            #         "cpe_link": dump["Link"],
            #         "cpes_part":cpes_part,
            #         "cpes_vendor":cpes_vendor,
            #         "cpes_product":cpes_product,
            #         "cpes_version":cpes_version,
            #         "cpes_update":cpes_update,
            #         "cpes_edition":cpes_edition,
            #         "cpes_language":cpes_language,
            #         "cpes_edition_sw":cpes_edition_sw,
            #         "cpes_target_sw":cpes_target_sw,
            #         "cpes_target_hw":cpes_target_hw,
            #         "cpes_other":cpes_other
            for i in range(len(data["cpes_strings"])):
                await file.write(f"( {data["cve_id"].replace("\n","")}, '{data["cpes_strings"][i]}', '{data["cpes_status"][i]}', '{data["cpe_link"].replace("\n", "").strip()}', '{data["cpes_part"][i]}', '{data["cpes_vendor"][i]}', '{data["cpes_product"][i]}', '{data["cpes_version"][i]}', '{data["cpes_update"][i]}', '{data["cpes_edition"][i]}', '{data["cpes_language"][i]}', '{data["cpes_edition_sw"][i]}', '{data["cpes_target_sw"][i]}', '{data["cpes_target_hw"][i]}', '{data["cpes_other"][i]}' ),\n")



async def main():
    await get_data_txt(path="cves_list.txt")
    # print(*data_txt)





if __name__ == "__main__":
    asyncio.run(main())