import urllib.request
import json
import urllib.parse

def search_dockerhub(query):
    url = "https://hub.docker.com/v2/search/repositories?query=" + urllib.parse.quote(query)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            results = data.get("results", [])
            print("--- Search:", query, "---")
            for r in results[:3]:
                print("repo:", r.get("repo_name"), "| desc:", r.get("short_description")[:50])
    except Exception as e:
        print("Error searching", query, ":", e)

search_dockerhub("moments")
search_dockerhub("pansou")
search_dockerhub("haozi")
search_dockerhub("amh")
search_dockerhub("videogen")
search_dockerhub("stock")
search_dockerhub("pve")
