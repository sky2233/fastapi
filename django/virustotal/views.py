from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from django.views import View
import requests, json, datetime, time

from .forms import searchForm

# Create your views here.

template = 'main.html'
ipdomainsearch = 'ipDomain.html'
filehashsearch = 'file.html'

def get(request):
    return render(request, template)

def searchGet(request):
    if request.method == "GET":
        form = searchForm(request.GET)
        if form.is_valid():
            type = form.cleaned_data['type']
            searchValue = form.cleaned_data['searchValue']
            url = "/" + type + "/" + searchValue
            return HttpResponseRedirect(url)
    else:
        form = searchForm()
    return render(request, template)

def searchIp(request, searchValue):
    searchValue = searchValue
    url = "http://127.0.0.1:8000/scan/ipdomain/" + searchValue
    r = requests.get(url = url)
    result = r.json()

    commFiles = result["comm_files"]
    refFiles = result["ref_files"]

    for x in commFiles:
        timestamp = int(x["date"])
        x["date"] = time.strftime('%m/%d/%Y %H:%M:%S',  time.gmtime(timestamp))
    for x in refFiles:
        timestamp = int(x["date"])
        x["date"] = time.strftime('%m/%d/%Y %H:%M:%S',  time.gmtime(timestamp))

    context = {
        "ipDomain" : result,
        "commFiles" : commFiles,
        "refFiles" : refFiles
    }

    return render(request, ipdomainsearch, context)

def searchFile(request, searchValue):
    url = "http://127.0.0.1:8000/scan/files/" + searchValue
    r = requests.get(url = url)
    result = r.json()

    exeParents = result["exe_parents"]
    
    timestamp = int(result["date"])
    result["date"] = time.strftime('%m/%d/%Y %H:%M:%S',  time.gmtime(timestamp))

    for x in exeParents:
        timestamp = int(x["date"])
        x["date"] = time.strftime('%m/%d/%Y %H:%M:%S',  time.gmtime(timestamp))

    context = {
        "filehash" : result,
        "exeParents" : exeParents,
    }

    return render(request, filehashsearch, context)

def changetimestamp(json):
    timestamp = int(json)
    json = time.strftime('%m/%d/%Y %H:%M:%S',  time.gmtime(timestamp))

