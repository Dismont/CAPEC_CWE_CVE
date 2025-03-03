import asyncio, aiohttp, aiofiles
from typing import Any

async def fetch_link(*,session: aiohttp.ClientSession, link:str) -> Any:

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={link}"
    try:
        async with session.get(link) as response:
            response.raise_for_status()
            data = await response.text()
            print(f"Response from: {link}")
            return data

    except aiohttp.ClientError as client_error:
        print(f"ERROR: {client_error}")


async def read_urls (*,links:list[str]) -> Any:

    async with aiohttp.ClientSession() as session:
        tasks = []
        for link in links:
            task = asyncio.create_task(fetch_link(session=session, link=link))
            tasks.append(task)
        data = await asyncio.gather(*tasks)

    return data


async def main():

    links = None
    with open("cve_list.txt","r") as file:
        links = file.readlines()
    data = await read_urls(links=links)
    print(data)


if __name__ == "__main__":
    asyncio.run(main())