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
            print(f"Total records (Links): {iterations}")
            return links
        else:
            return None

    except Exception as e:
        print(f"Что-то пошло не так!\n Error: {e}")
        exit()



def get_type_of_capec (*,url:str) -> list[str] | None:
    try:
        response = requests.get(url)
        http = BeautifulSoup(response.content, "html.parser")
        all_tag_img = http.find_all('img')

        types = []
        iterations = 0

        if len(all_tag_img) != 0:
            for part_tag_img in all_tag_img:

                # Category - C
                if "category.gif" in str(part_tag_img.get("src")):
                    types.append("Category")
                    iterations += 1

                # Meta Attack Pattern - M
                if "meta_ap.gif" in str(part_tag_img.get("src")):
                    types.append("Meta Attack Pattern")
                    iterations += 1

                # Detail Attack Pattern - D
                if "detailed_ap.gif" in str(part_tag_img.get("src")):
                    types.append("Detail Attack Pattern")
                    iterations += 1

                # Standard Attack Pattern - S
                if "standard_ap.gif" in str(part_tag_img.get("src")):
                    types.append("Standard Attack Pattern")
                    iterations += 1

            print(f"Total records (Type): {iterations}")
            # print(f"List type Capce:", *types, sep="\n")
            return types
        else:
            return None

    except Exception as e:
        print(f"Что-то пошло не так!\n Error: {e}")
        exit()



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



async def http_request_of_url(*, links:list[str]) -> list[dict[str, str]] | None:
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



async def parsing_html_data(*,sites:list[dict[str,str]],full_url:str) -> list[dict[str, int]] | None:
    """
    Асинхронный метод для конечного парсинга сайта конкретного CAPEC
    Получение: CapecID, CapecName, CapecDescription, CapecUrl, CapecToCweLinks, CapecToCweId
    :param sites: list[ dict{ 'html' : html(str), 'url' : url(str) }, ... ]
    :param full_url: 'https://capec.mitre.org/data/ ...'
    :return: dict [ str ]
    """
    block_two = []
    for i in range(len(sites)):

        # part 0 - Initialisation
        html_data = BeautifulSoup(sites[i]['html'], "html.parser")

        # part 1 - Name (<h2> ... </h2>)
        h2_name = html_data.find("h2")
        name = h2_name.get_text().strip()

        # part 2 - Description ( <div class='indent'> ... </div> )
        div_description = html_data.find("div", class_ = "indent")
        description = div_description.get_text().strip()

        # part 3 - Related Weaknesses (<div class="Related_Weaknesses"> <table> <td> ... )
        cwe_link = []
        cwe = {}
        div_related_weaknesses = html_data.find("div", id="Related_Weaknesses")
        if div_related_weaknesses:
            table_related_weaknesses = div_related_weaknesses.find("table")
            if table_related_weaknesses:
                td_related_weaknesses = table_related_weaknesses.find_all("td")
                for j in range(0,len(td_related_weaknesses),2):
                    cwe.update({td_related_weaknesses[j].get_text():td_related_weaknesses[j+1].get_text()})
                    if td_related_weaknesses[j]:
                        a_related_weaknesses = td_related_weaknesses[j].find_all("a")
                        cwe_link.append(a_related_weaknesses[0].get("href"))


        # part 4 - Relationship (<div class="relevant_table"> <table> <td> <tr> ParentOf ... )
        parent_list = []
        div_relationship = html_data.find("div", id="relevant_table")
        if div_relationship:
            # print(f"Total Relationship {name}: {len(div_relationship)}")
            table_relationship = div_relationship.find("table")
            if table_relationship:
                td_relationship = table_relationship.find_all("td")
                # print(f"Parent Of Table - {name}:")
                for j in range(0,len(td_relationship),4):
                    if td_relationship[j].get_text() == "ParentOf":
                        parent_list.append(int(td_relationship[j+2].get_text()))
                        # print(f"{td_relationship[j].get_text()} : {td_relationship[j+2].get_text()} ")



        # ---> stdout dict
        # print(f"Capec Id:      {name.strip().split(":")[0].split("-")[-1]}")
        # print(f"Capec Name:    {name.strip()}")
        # print(f"Description:   {description}")
        # print(f"Url:           {full_url.replace("1000",f"{name.strip().split(":")[0].split("-")[-1]}")}")
        # print(f"ParentOf:      "), print(*parent_list, sep="\n")
        # print(f"Cwe Links:     "), print(*cwe_link,sep="\n")
        # print(f"Cwe Id - Name: "), print(*cwe.items(),sep="\n")
        # print("###################################################################")
        if name.strip().split(":")[0].split("-")[-1].isdigit():
            block_two.append({  "id"   :   int(name.strip().split(":")[0].split("-")[-1]),
                                "name" :   name.strip(),
                                "description" : description,
                                "url" : full_url.replace("1000",f"{name.strip().split(":")[0].split("-")[-1]}"),
                                "parentOf" : [*parent_list] })
    return block_two



async def main():
    # --- CONST ---
    #     CAPEC
    # CAPEC_NAME = "CAPEC"
    CAPEC_BASE_URL = "https://capec.mitre.org/"
    CAPEC_FULL_URL = "https://capec.mitre.org/data/definitions/1000.html"

    # main code
    types = get_type_of_capec(url=CAPEC_FULL_URL)
    links = get_base_urls(url=CAPEC_FULL_URL, base_url=CAPEC_BASE_URL)

    # - Создаю словарь block_one = {Id : value(int), Link : value(str), Type: value(str)}
    block_one = []
    for i in range(len(types)):
        data_one_block = {"Id": int(links[i].split("/")[6].replace(".html", "")),
                          "Link" : f"{links[i]}",
                          "Type" : f"{types[i]}" }
        block_one.append(data_one_block)

    block_two = None
    # - Собираю второй словарь block_two = {Id : value(int), Name : value(str), Description : value(str), ParentOf: [1, 2, 3]}
    if links:
        html_data = await http_request_of_url(links=links)
        block_two = await parsing_html_data(sites=html_data,full_url=CAPEC_FULL_URL)

    print(*block_one, sep="\n")
    print("??? ??? ??? ??? ??? ??? ??? ??? ??? ??? ??? ??? ??? ??? ??? ??? ??? ??? ??? ??? ??? ")
    print(*block_two, sep="\n")









if __name__ == "__main__":
    asyncio.run(main())
