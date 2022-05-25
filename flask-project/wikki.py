import requests

def findBirths(monthDay,year,size=10):
    #monthDay is in form "mm/dd"
    #year is in form "yyyy"
    #returns a list of names, birth years and thumbnails
    #sortedbyClosestYear[i]['text'] has name of ith match
    #sortedbyClosestYear[i]['year'] has year of ith match's birthdate
    #sortedbyClosestYear[i]['thumbnail'] has url of ith match's thumbnail picture or localhost if there is none
    size=int(size)
    year=int(year)
    path="https://api.wikimedia.org/feed/v1/wikipedia/en/onthisday"
    response= requests.get(path+"/births/"+monthDay)
    data=response.json()
    sortedbyClosestYear=sorted(data["births"], key=lambda i: abs(int(i['year'])-year))
    if len(sortedbyClosestYear) > size:
        sortedbyClosestYear=sortedbyClosestYear[0:size]
    for item in sortedbyClosestYear:
        item['thumbnail'] = "localhost"
        if "thumbnail" in item['pages'][0]:
            item['thumbnail'] = item['pages'][0]["thumbnail"]["source"]
        if "content_urls" in item['pages'][0]:
            item['content_urls'] = item['pages'][0]["content_urls"]["desktop"]["page"]

    return sortedbyClosestYear
#
# output = findBirths("05/04","1993", 1)
# print(output[0]['content_urls'])
# print(output)
