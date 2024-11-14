# ---------------------------------------------------------------------
# IMPORTS

import re
import json
from enum import Enum
from bs4 import BeautifulSoup
import aiohttp
import requests
from fake_useragent import UserAgent

# ---------------------------------------------------------------------


class SearchModifiers(Enum):
    NONE = ""
    # ISOLATE_DLC shows only DLC in the search result
    ISOLATE_DLC = "only_dlc"
    # HIDE_DLC hide DLCs in the search result
    HIDE_DLC = "hide_dlc"


class HTMLRequests:
    BASE_URL = 'https://howlongtobeat.com/'
    REFERER_HEADER = BASE_URL
    SEARCH_URL = BASE_URL + "api/search"
    GAME_URL = BASE_URL + "game"

    @staticmethod
    def get_search_request_headers():
        """
        Generate the headers for the search request
        @return: The headers object for the request
        """
        ua = UserAgent()
        headers = {
            'content-type': 'application/json',
            'accept': '*/*',
            'User-Agent': ua.random.strip(),
            'referer': HTMLRequests.REFERER_HEADER
        }
        return headers

    @staticmethod
    def get_search_request_data(game_name: str, search_modifiers: SearchModifiers, page: int, api_key: str):
        """
        Generate the data payload for the search request
        @param game_name: The name of the game to search
        @param search_modifiers: The search modifiers to use in the search
        @param page: The page to search
        @return: The request (data) payload object for the request
        """
        payload = {
            'searchType': "games",
            'searchTerms': game_name.split(),
            'searchPage': page,
            'size': 20,
            'searchOptions': {
                'games': {
                    'userId': 0,
                    'platform': "",
                    'sortCategory': "popular",
                    'rangeCategory': "main",
                    'rangeTime': {
                        'min': 0,
                        'max': 0
                    },
                    'gameplay': {
                        'perspective': "",
                        'flow': "",
                        'genre': ""
                    },
                    'modifier': search_modifiers.value,
                },
                'users': {
                    'id': api_key,
                    'sortCategory': "postcount"
                },
                'filter': "",
                'sort': 0,
                'randomizer': 0
            }
        }
        return json.dumps(payload)

    @staticmethod
    def send_web_request(game_name: str, search_modifiers: SearchModifiers = SearchModifiers.NONE,
                         page: int = 1):
        """
        Function that search the game using a normal request
        @param game_name: The original game name received as input
        @param search_modifiers: The "Modifiers" list in "Search Options", allow to show/isolate/hide DLCs
        @param page: The page to explore of the research, unknown if this is actually used
        @return: The HTML code of the research if the request returned 200(OK), None otherwise
        """
        headers = HTMLRequests.get_search_request_headers()
        api_key_result = HTMLRequests.send_website_request_getcode(False)
        if api_key_result is None:
            api_key_result = HTMLRequests.send_website_request_getcode(True)
        payload = HTMLRequests.get_search_request_data(game_name, search_modifiers, page, api_key_result)
        # Make the post request and return the result if is valid
        search_url_with_key = HTMLRequests.SEARCH_URL
        resp = requests.post(search_url_with_key, headers=headers, data=payload, timeout=60)
        if resp.status_code == 200:
            return resp.text
        return None

    @staticmethod
    async def send_async_web_request(game_name: str, search_modifiers: SearchModifiers = SearchModifiers.NONE,
                                     page: int = 1):
        """
        Function that search the game using an async request
        @param game_name: The original game name received as input
        @param search_modifiers: The "Modifiers" list in "Search Options", allow to show/isolate/hide DLCs
        @param page: The page to explore of the research, unknown if this is actually used
        @return: The HTML code of the research if the request returned 200(OK), None otherwise
        """
        headers = HTMLRequests.get_search_request_headers()
        api_key_result = await HTMLRequests.async_send_website_request_getcode(False)
        if api_key_result is None:
            api_key_result = await HTMLRequests.async_send_website_request_getcode(True)
        payload = HTMLRequests.get_search_request_data(game_name, search_modifiers, page, api_key_result)
        # Make the post request and return the result if is valid
        search_url_with_key = HTMLRequests.SEARCH_URL + "/" + api_key_result
        async with aiohttp.ClientSession() as session:
            async with session.post(search_url_with_key, headers=headers, data=payload) as resp:
                if resp is not None and str(resp.status) == "200":
                    return await resp.text()
                return None

    @staticmethod
    def __cut_game_title(page_source: str):
        """
        Function that extract the game title from the html title of the howlongtobeat page
        @param game_title: The HowLongToBeat page title of the game
        (For example "How long is A Way Out? | HowLongToBeat")
        @return: The cut game-title, without howlongtobeat names and grammatical symbols
        (So, in this example: "A Way Out")
        """

        if page_source is None or len(page_source) == 0:
            return None

        soup = BeautifulSoup(page_source, 'html.parser')
        title_tag = soup.title
        title_text = title_tag.string

        # The position of start and end of this method may change if the website change
        cut_title = title_text[12:-17].strip()
        return cut_title

    @staticmethod
    def get_title_request_parameters(game_id: int):
        """
        Generate the parameters for the search request
        @param game_id: The game id to search in HLTB
        @return: The parameters object for the request
        """
        params = {
            'id': str(game_id)
        }
        return params

    @staticmethod
    def get_title_request_headers():
        """
        Generate the headers for the search request
        @return: The headers object for the request
        """
        ua = UserAgent()
        headers = {
            'User-Agent': ua.random,
            'referer': HTMLRequests.REFERER_HEADER
        }
        return headers

    @staticmethod
    def get_game_title(game_id: int):
        """
        Function that gets the title of a game from the game (howlongtobeat) id
        @param game_id: id of the game to get the title
        @return: The game title from the given id
        """

        params = HTMLRequests.get_title_request_parameters(game_id)
        headers = HTMLRequests.get_title_request_headers()

        # Request and extract title
        contents = requests.get(HTMLRequests.GAME_URL, params=params, headers=headers, timeout=60)
        return HTMLRequests.__cut_game_title(contents.text)

    @staticmethod
    async def async_get_game_title(game_id: int):
        """
        Function that gets the title of a game from the game (howlongtobeat) id
        @param game_id: id of the game to get the title
        @return: The game title from the given id
        """

        params = HTMLRequests.get_title_request_parameters(game_id)
        headers = HTMLRequests.get_title_request_headers()

        # Request and extract title
        async with aiohttp.ClientSession() as session:
            async with session.post(HTMLRequests.GAME_URL, params=params, headers=headers) as resp:
                if resp is not None and str(resp.status) == "200":
                    text = await resp.text()
                    return HTMLRequests.__cut_game_title(text)
                return None

    @staticmethod
    def send_website_request_getcode(parse_all_scripts: bool):
        """
        Function that send a request to howlongtobeat to scrape the /api/search key
        @return: The string key to use on /api/search
        """
        # Make the post request and return the result if is valid
        headers = HTMLRequests.get_title_request_headers()
        resp = requests.get(HTMLRequests.BASE_URL, headers=headers, timeout=60)
        if resp.status_code == 200 and resp.text is not None:
            # Parse the HTML content using BeautifulSoup
            soup = BeautifulSoup(resp.text, 'html.parser')
            # Find all <script> tags with a src attribute containing the substring
            scripts = soup.find_all('script', src=True)
            if parse_all_scripts:
                matching_scripts = [script['src'] for script in scripts]
            else:
                matching_scripts = [script['src'] for script in scripts if '_app-' in script['src']]
            for script_url in matching_scripts:
                script_url = HTMLRequests.BASE_URL + script_url
                script_resp = requests.get(script_url, headers=headers, timeout=60)
                if script_resp.status_code == 200 and script_resp.text is not None:
                    pattern = r'users\s*:\s*{\s*id\s*:\s*"([^"]+)"'
                    matches = re.findall(pattern, script_resp.text)
                    for match in matches:
                        return match
        return None

    @staticmethod
    async def async_send_website_request_getcode(parse_all_scripts: bool):
        """
        Function that send a request to howlongtobeat to scrape the /api/search key
        @return: The string key to use on /api/search
        """
        # Make the post request and return the result if is valid
        headers = HTMLRequests.get_title_request_headers()
        async with aiohttp.ClientSession() as session:
            async with session.get(HTMLRequests.BASE_URL, headers=headers) as resp:
                if resp is not None and str(resp.status) == "200":
                    resp_text = await resp.text()
                    # Parse the HTML content using BeautifulSoup
                    soup = BeautifulSoup(resp_text, 'html.parser')
                    # Find all <script> tags with a src attribute containing the substring
                    scripts = soup.find_all('script', src=True)
                    if parse_all_scripts:
                        matching_scripts = [script['src'] for script in scripts]
                    else:
                        matching_scripts = [script['src'] for script in scripts if '_app-' in script['src']]
                    for script_url in matching_scripts:
                        script_url = HTMLRequests.BASE_URL + script_url
                        async with aiohttp.ClientSession() as session:
                            async with session.get(script_url, headers=headers) as script_resp:
                                if script_resp is not None and str(resp.status) == "200":
                                    script_resp_text = await script_resp.text()
                                    pattern = r'users\s*:\s*{\s*id\s*:\s*"([^"]+)"'
                                    matches = re.findall(pattern, script_resp_text)
                                    for match in matches:
                                        return match
                                else:
                                    return None
                else:
                    return None
