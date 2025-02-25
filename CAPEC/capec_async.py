import asyncio, aiohttp, requests, aiofiles
from bs4 import BeautifulSoup
from typing import Any

def get_base_urls(*,url:str,base_url:str) -> list[str] | None:
    """
     Делает запрос к основной странице CAPEC и получает все необходимые ссылки из <a></a>
    :param url: str -> .../data/definitions/1000.html
    :param base_url: str -> https://capec.mitre.org/
    :return: list[str] -> [https://capec.mitre.org/111, https://capec.mitre.org/222]
    """
    try:
        response = requests.get(url)
        http = BeautifulSoup(response.content, "html.parser")
        all_tag_a = http.find_all('a')

        links = []
        iterations = 0

        if len(all_tag_a) != 0:
            for part_tag_a in all_tag_a:
                if "data/definitions/" in str(part_tag_a.get("href")):
                    iterations += 1
                    links.append(base_url + part_tag_a.get("href"))
            # for i in range(len(links)):
                # print(f"URL №{i+1} -> {links[i]}")
            print(f" Total records: {iterations}")
            return links
        else:
            return None

    except requests.exceptions.ReadTimeout() as reRT:
        print("Сервис не отвечает!")
        exit(404)



async def fetch_link(*,link: str, session: aiohttp.ClientSession) -> dict[str,str] | None:
    """
    Асинхронный метод для запроса ко всем перечисленным ссылками и передает html в формате str
    :param link: str
    :param session: aiohttp.ClientSession -> session
    :return: session.get(link) -> html (str)
    """
    try:
        async with session.get(link) as response:
            response.raise_for_status()
            html = await response.text()
            print(f"Response from: {link}")
            return {
                "html" : html,
                "link" : link
            }

    except aiohttp.ClientError as client_error:
        print(f"ERROR: {client_error}")



async def http_request_of_url(*, links:list[str]) -> list[dict[str,str]] | None:
    """
    Асинхронный метод для последующего перебора URL путем передачи в fetch()
    :param links: list[str]
    :return: aiohttp.ClientSeesion
    """
    if links:
        async with aiohttp.ClientSession() as session:
            links.sort()
            tasks = []
            for link in links:
                print(f"Request to: {link}")
                task = asyncio.create_task(fetch_link(link=link,session=session))
                tasks.append(task)
            html_data = await asyncio.gather(*tasks)
            # print(f"Type of html_data: {type(html_data)}")
            # print(f"Type of html_data[0]: {type(html_data[0])}")
            # print(f"{html_data[0]}")
            # return выполнится 1 РАЗ!
            return html_data



async def parsing_html_data(*,sites:list[dict[str,str]],full_url:str) -> list[str] | None:
    """
    Асинхронный метод для конечного парсинга сайта конкретного CAPEC
    Получение: CapecID, CapecName, CapecDescription, CapecUrl, CapecToCweLinks, CapecToCweId
    :param sites: list[ dict{ 'html' : html(str), 'url' : url(str) }, ... ]
    :param full_url: 'https://capec.mitre.org/data/ ...'
    :return: ??? -> maybe file .sql  (insert into db ... )
    """
    # create file for writting sql query
    async with aiofiles.open("capec_insert_query.sql", "a") as file:
        await file.write("insert into capec (id, capec_id, capec_name, capec_description, capec_url, capec_type) values \n")


    for i in range(len(sites)):
        html_data = BeautifulSoup(sites[i]['html'], "html.parser")
        # part 1 - Name (<h2> ... </h2>)
        h2_name = html_data.find("h2")
        name = h2_name.get_text().strip()

        # part 2 - Description ( <div class='indent'> ... </div> )
        div_description = html_data.find("div", class_ = "indent")
        description = div_description.get_text().strip()

        # part 3 - Relationship
        # <div id='Related_Weaknesses'>
        #   <table>
        #       <tr>
        #   this -->|   <td> <a href='XXXX'> 522 </a> </td>
        #   this -->|   <td> text-to-text </td>
        #       </tr>
        #   </table>
        # </div>

        cwe_link = []
        cwe = {}
        div_related_weaknesses = html_data.find("div", id="Related_Weaknesses")
        if div_related_weaknesses:
            table_related_weaknesses = div_related_weaknesses.find("table")
            if table_related_weaknesses:
                td_related_weaknesses = table_related_weaknesses.find_all("td")
                for i in range(0,len(td_related_weaknesses),2):
                    cwe.update({td_related_weaknesses[i].get_text():td_related_weaknesses[i+1].get_text()})
                    if td_related_weaknesses[i]:
                        a_related_weaknesses = td_related_weaknesses[i].find_all("a")
                        cwe_link.append(a_related_weaknesses[0].get("href"))

                    # print(*cwe_link,sep="\n")
            # ---> stdout dict
        print(f"CAPEC ID:    {name.strip().split(":")[0].split("-")[-1]}")
        print(f"CAPEC NAME:  {name.strip()}")
        print(f"DESCRIPTION: {description}")
        print(f"URL:         {full_url.replace("1000",f"{name.strip().split(":")[0].split("-")[-1]}")}")
        print(f"CWE links:   "), print(*cwe_link,sep="\n")
        print(f"CWE ID - NAME: "), print(*cwe.items(),sep="\n")
        print("###################################################################")

            #write it as sql query
        async with aiofiles.open("capec_insert_query.sql", "a") as file:
            if i + 1 != len(sites):
                #                       CapecID,                                    CapecName,       CapecDescription,                                      CapecUrl,                                          CapecType -
                if name.strip().split(":")[0].split("-")[-1].isdigit():
                    await file.write(f"({name.strip().split(":")[0].split("-")[-1]}, '{name.strip().replace("\'", "`")}', '{description.replace("\'", "`")}', '{full_url.replace("1000",f"{name.strip().split(":")[0].split("-")[-1]}")}', '', \n")
                else:
                    print("Пропущенно!")
                    print(f"({name.strip().split(":")[0].split("-")[-1]}, '{name.strip()}', '{description}', '{full_url.replace("1000",f"{name.strip().split(":")[0].split("-")[-1]}")}', '', \n")
            else:
                if name.strip().split(":")[0].split("-")[-1].isdigit():
                    await file.write(f"({name.strip().split(":")[0].split("-")[-1]}, '{name.strip()}', '{description}', '{full_url.replace("1000",f"{name.strip().split(":")[0].split("-")[-1]}")}', '' ; \n")
                    print("Пропущенно!")
                    print(f"({name.strip().split(":")[0].split("-")[-1]}, '{name.strip()}', '{description}', '{full_url.replace("1000", f"{name.strip().split(":")[0].split("-")[-1]}")}', '', \n")








async def main():
    # --- CONST ---
    #     CAPEC
    CAPEC_NAME = "CAPEC"
    CAPEC_BASE_URL = "https://capec.mitre.org/"
    CAPEC_FULL_URL = "https://capec.mitre.org/data/definitions/1000.html"

    # main code
    links = get_base_urls(url=CAPEC_FULL_URL, base_url=CAPEC_BASE_URL)
    if links:
        html_data = await http_request_of_url(links=links)
        await parsing_html_data(sites=html_data,full_url=CAPEC_FULL_URL)




if __name__ == "__main__":
    asyncio.run(main())
