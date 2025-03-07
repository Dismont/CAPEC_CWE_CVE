from pydoc import describe

import aiohttp, aiofiles, asyncio, json
from typing import Any



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
                await asyncio.sleep(2)

                task = asyncio.create_task(fetch_API(session=session,link=cpe_link, isCve=False))
                # print(f"Create task for {cpe_link}")
                tasks.append(task)
                await asyncio.sleep(2)

            data_list = await asyncio.gather(*tasks)
            return data_list


        except aiohttp.ClientError as http_err:
            print(f"Error (get_data_txt) : {http_err}")


async def parsing_json(*, dump:dict[str, bool | None]) -> dict[str,str]:
    if dump["isCve"]:
        print(f"Data: {dump["Data"]}")
        cve_name = dump["Data"]["vulnerabilities"][0]["cve"]["id"]
        cve_description = dump["Data"]["vulnerabilities"][0]["cve"]["descriptions"][0]["value"]
        cve_metrics = dump["Data"]["vulnerabilities"][0]["cve"]["descriptions"][0]["value"]
        print(f"Name:         {cve_name}")
        print(f"Description:  {cve_description}")




async def fetch_API(*,session:aiohttp.ClientSession, link:str, isCve:bool) -> dict[str, bool | Any] | None:
    async with session.get(link) as response:
        try:
            await asyncio.sleep(5)
            if response.status == 200:
                data = await response.text()
                json_dump = json.loads(data)
                return {"isCve" : isCve,
                        "Data" : json_dump}
            else:
                print(f"Error: HTTP Code -> {response.status}")
                return {"isCve": isCve,
                        "Data": None}
        except aiohttp.ClientError as http_err:
            print(f"Error (fetch_API) :{http_err}")




async def main():
    data_txt = await get_data_txt(path="example.txt")
    for item in data_txt:
        data_json_dump = await parsing_json(dump=item)


if __name__ == "__main__":
    asyncio.run(main())