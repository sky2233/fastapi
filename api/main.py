from typing import List

from fastapi import Depends, FastAPI, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session

from . import crud, models, schemas
from .database import SessionLocal, engine

import requests
import json
import re

import asyncio
import threading
from multiprocessing import Process
from threading import Thread

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

key = "2a2b0078e1330eb0bb858b047935aba7ddc8921a32cfc129ab2132c2d082b3a5"
header = {"x-apikey" : key}

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    # except:
    #     db.rollback()
    finally:
        db.close()

# collect more communicating files and referring files in the background
def backgroundIP(resultId, commFilesUrl, refFilesUrl, db):
    print(resultId, commFilesUrl, refFilesUrl)
    # recursive function to collect more communicating files
    def commFiles(urlCommFiles):
        if urlCommFiles != "":
            # retrive commnuncating files data 
            rCommFiles = requests.get(url = urlCommFiles, headers = header)
            resultCommFiles = rCommFiles.json()

            # get next link
            try:
                nextLink = resultCommFiles["links"]["next"]
                print(nextLink)
            except Exception:
                nextLink = ""

            # values for communcating files
            for element in resultCommFiles["data"]:
                try:
                    fileId = element["id"]
                    type = element["attributes"]["type_tag"]
                    names = element["attributes"]["names"]
                    names = ", ".join(names)
                    stats = element["attributes"]["last_analysis_stats"]
                    reputation = element["attributes"]["reputation"]
                    date = element["attributes"]["last_analysis_date"]
                    tags = element["attributes"]["tags"]
                    tags = ", ".join(tags)
                    try:
                        sandboxVerdicts = element["attributes"]["sandbox_verdicts"]
                        for sandbox in sandboxVerdicts:
                            malwareType = sandboxVerdicts[sandbox]["malware_classification"]
                            malwareType = ", ".join(malwareType)
                    except Exception:
                        malwareType = ""
                    
                    totalScore = 0
                    x = 0
                    for item in stats:
                        itemScore = stats[item]
                        totalScore = totalScore + itemScore
                        if item == "malicious" or item == "suspicious":
                            x = x + itemScore
                        if item == "timeout" or item == "type-unsupported" or item == "failure":
                            totalScore = totalScore - itemScore
                    score = str(x) + "/" + str(totalScore)

                    # insert data to match model
                    commFilesData = schemas.comm_files(id = resultId, file_id = fileId, type =  type, names = names, score = score, reputation = reputation, date = date, tags = tags, sandbox_classification = malwareType)
                    # insert to database
                    try:
                        crud.insert_CommFiles(db, commFilesData)
                    except Exception as error:
                        print(error)
                except:
                    pass
        
            # repeat the whole precess with the next link
            return commFiles(nextLink)

        else:
            pass
    # recursive function to collect more referring files
    def refFiles(urlRefFiles):
        if urlRefFiles != "":
            # retrive referring files data 
            rRefFiles = requests.get(url = urlRefFiles, headers = header)
            resultRefFiles = rRefFiles.json()

            # get next link
            try:
                nextLink = resultRefFiles["links"]["next"]
                print("next link", nextLink)
            except Exception:
                nextLink = ""
            
            # values for referring files
            for element in resultRefFiles["data"]:
                try:
                    fileId = element["id"]
                    try:
                        type = element["attributes"]["type_tag"]
                    except Exception:
                        type = ""
                    names = element["attributes"]["names"]
                    names = ", ".join(names)
                    stats = element["attributes"]["last_analysis_stats"]
                    reputation = element["attributes"]["reputation"]
                    date = element["attributes"]["last_analysis_date"]
                    tags = element["attributes"]["tags"]
                    tags = ", ".join(tags)

                    totalScore = 0
                    x = 0
                    for item in stats:
                        itemScore = stats[item]
                        totalScore = totalScore + itemScore
                        if item == "malicious" or item == "suspicious":
                            x = x + itemScore
                        if item == "timeout" or item == "type-unsupported" or item == "failure":
                            totalScore = totalScore - itemScore
                    score = str(x) + "/" + str(totalScore)

                    # insert data to match model
                    refFilesData = schemas.ref_files(id = resultId, file_id = fileId, type =  type, names = names, score = score, reputation = reputation, date = date, tags = tags)
                    # insert into database
                    crud.insert_RefFiles(db, refFilesData)

                except Exception:
                    pass

            # repeat the whole precess with the next link
            return refFiles(nextLink)

        else:
            pass
    
    print("hello, im background")
    if commFilesUrl != "":
        commFiles(commFilesUrl)
    if refFilesUrl !="":
        refFiles(refFilesUrl)
    print("done")

@app.get("/scan/ipdomain/{ipdomain}", response_model = schemas.ip_domain)
async def getIpDomain(background_tasks: BackgroundTasks, ipdomain: str, db:Session = Depends(get_db)):
    ipDomainData = crud.getIpDomain(db, id=ipdomain)
    if ipDomainData is None:
        key = "2a2b0078e1330eb0bb858b047935aba7ddc8921a32cfc129ab2132c2d082b3a5"
        header = {"x-apikey" : key}

        # check if search value is ip or domain name
        ipRegex = re.search(r"^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\.(?!$)|$)){4}$", ipdomain)
        if ipRegex:
            url = "https://www.virustotal.com/api/v3/ip_addresses/" + ipdomain
            urlCommFiles = "https://www.virustotal.com/api/v3/ip_addresses/" + ipdomain + "/communicating_files"
            urlRefFiles = "https://www.virustotal.com/api/v3/ip_addresses/" + ipdomain + "/referrer_files"
        else:
            url = "https://www.virustotal.com/api/v3/domains/" + ipdomain
            urlCommFiles = "https://www.virustotal.com/api/v3/domains/" + ipdomain + "/communicating_files"
            urlRefFiles = "https://www.virustotal.com/api/v3/domains/" + ipdomain + "/referrer_files"

        # retrive ip/domain data
        r = requests.get(url = url, headers = header)
        result = r.json()

        # check for errors
        try:
            error = result["error"]
            print(error)
            raise HTTPException(status_code=404, detail=error)
        except Exception:
            error = ""

        if error != "":
            error = result["error"]
            raise HTTPException(status_code=404, detail=error)

        else:
            # values for ip.domain
            resultId = result["data"]["id"]
            resultType = result["data"]["type"]
            resultStats = result["data"]["attributes"]["last_analysis_stats"]
            totalScore = 0
            score = 0
            for x in resultStats:
                itemScore = resultStats[x]
                totalScore = totalScore + itemScore
                if x == "malicious" or x == "suspicious":
                    score = score + itemScore
                if x == "timeout" or x == "type-unsupported" or x == "failure":
                    totalScore = totalScore - itemScore
            resultScore = str(score) + "/" + str(totalScore)
            resultReputation = result["data"]["attributes"]["reputation"]

            resultData = schemas.ip_domain_base(id = resultId, type = resultType, score = resultScore, reputation = resultReputation)

            # keep communication and referring files data as a list
            commFilesList = []
            refFilesList = []

            # retrive commnuncating files data 
            rCommFiles = requests.get(url = urlCommFiles, headers = header)
            resultCommFiles = rCommFiles.json()

            # get next link for background task
            try:
                nextCommLink = resultCommFiles["links"]["next"]
            except:
                pass

            # values for communcating files
            for element in resultCommFiles["data"]:
                try:
                    fileId = element["id"]
                    type = element["attributes"]["type_tag"]
                    names = element["attributes"]["names"]
                    names = ", ".join(names)
                    stats = element["attributes"]["last_analysis_stats"]
                    reputation = element["attributes"]["reputation"]
                    date = element["attributes"]["last_analysis_date"]
                    tags = element["attributes"]["tags"]
                    tags = ", ".join(tags)
                    try:
                        sandboxVerdicts = element["attributes"]["sandbox_verdicts"]
                        for sandbox in sandboxVerdicts:
                            malwareType = sandboxVerdicts[sandbox]["malware_classification"]
                            malwareType = ", ".join(malwareType)
                    except Exception:
                        malwareType = ""
                    
                    totalScore = 0
                    x = 0
                    for item in stats:
                        itemScore = stats[item]
                        totalScore = totalScore + itemScore
                        if item == "malicious" or item == "suspicious":
                            x = x + itemScore
                        if item == "timeout" or item == "type-unsupported" or item == "failure":
                            totalScore = totalScore - itemScore
                    score = str(x) + "/" + str(totalScore)

                    # insert data to match model
                    commFilesData = schemas.comm_files(id = resultId, file_id = fileId, type =  type, names = names, score = score, reputation = reputation, date = date, tags = tags, sandbox_classification = malwareType)
                    commFilesList.append(commFilesData)
                except:
                    pass


            # retrive referring files data 
            rRefFiles = requests.get(url = urlRefFiles, headers = header)
            resultRefFiles = rRefFiles.json()

            # get next link for background task
            try:
                nextRefLink = resultRefFiles["links"]["next"]
            except:
                pass
            
            # values for referring files
            for element in resultRefFiles["data"]:
                try:
                    fileId = element["id"]
                    try:
                        type = element["attributes"]["type_tag"]
                    except Exception:
                        type = ""
                    names = element["attributes"]["names"]
                    names = ", ".join(names)
                    stats = element["attributes"]["last_analysis_stats"]
                    reputation = element["attributes"]["reputation"]
                    date = element["attributes"]["last_analysis_date"]
                    tags = element["attributes"]["tags"]
                    tags = ", ".join(tags)

                    totalScore = 0
                    x = 0
                    for item in stats:
                        itemScore = stats[item]
                        totalScore = totalScore + itemScore
                        if item == "malicious" or item == "suspicious":
                            x = x + itemScore
                        if item == "timeout" or item == "type-unsupported" or item == "failure":
                            totalScore = totalScore - itemScore
                    score = str(x) + "/" + str(totalScore)

                    # insert data to match model
                    refFilesData = schemas.ref_files(id = resultId, file_id = fileId, type =  type, names = names, score = score, reputation = reputation, date = date, tags = tags)
                    refFilesList.append(refFilesData)

                except Exception:
                    pass

            def insert():
                # insert data into ip_domain
                try:
                    crud.insert_IpDomain(db, resultData)
                except:
                    # db.rollback()
                    pass

                # insert data into comm_files
                for item in commFilesList:
                    try:
                        crud.insert_CommFiles(db, item)
                    except Exception as error:
                        # db.rollback()
                        print("insert commFiles")
                        print(error)
                        pass

                # insert data into ref_files
                for item in refFilesList:
                    try:
                        crud.insert_RefFiles(db, item)
                    except Exception as error:
                        print("insert refFiles")
                        print(error)
                        # db.rollback()
                        pass

            insert()

            ipDomainResult = schemas.ip_domain(id = resultId, type = resultType, score = resultScore, reputation = resultReputation, comm_files = commFilesList, ref_files = refFilesList)

            # background task
            background_tasks.add_task(backgroundIP, resultId, nextCommLink, nextRefLink, db)

            return ipDomainResult
    
    return ipDomainData

def backgroundFiles(filehash, urlExecutionParents, db):
    print(filehash, urlExecutionParents)
    # recursive function to collect more execution parents
    def exeParents(urlExecutionParents):
        if urlExecutionParents != "":
            # retrive execution parents data
            requestExe = requests.get(url = urlExecutionParents, headers = header)
            responseExe = requestExe.json()

            # get next link
            try:
                nextLink = responseExe["links"]["next"]
                print("next link", nextLink)
            except Exception as error:
                nextLink = ""

            # values for execution parents
            for element in responseExe["data"]:
                try:
                    exeId = element["id"]
                    type = element["attributes"]["type_tag"]
                    names = element["attributes"]["names"]
                    names = ", ".join(names)
                    date = element["attributes"]["last_analysis_date"]
                    stats = element["attributes"]["last_analysis_stats"]
                    totalScore = 0
                    x = 0
                    for item in stats:
                        itemScore = stats[item]
                        totalScore = totalScore + itemScore
                        if item == "malicious" or item == "suspicious":
                            x = x + itemScore
                        if item == "timeout" or item == "type-unsupported" or item == "failure":
                            totalScore = totalScore - itemScore
                    score = str(x) + "/" + str(totalScore)
                    reputation = element["attributes"]["reputation"]
                    tags = element["attributes"]["tags"]
                    tags = ", ".join(tags)

                    # insert data to match model
                    exeParentsData = schemas.exe_parents(id = filehash, file_id = exeId, type = type, names = names, score = score, reputation = reputation, date = date, tags = tags)
                    # insert into database
                    crud.insert_exeParents(db, exeParentsData)
                except Exception as error:
                    pass

            # repeat the whole precess with the next link
            return exeParents(nextLink)

        else:
            pass

    print("background")
    if urlExecutionParents != "":
        exeParents(urlExecutionParents)
    print("done")

@app.get("/scan/files/{filehash}", response_model = schemas.files)
async def getFiles(background_tasks: BackgroundTasks, filehash: str, db:Session = Depends(get_db)):
    fileData = crud.getFiles(db, id=filehash)
    if fileData is None:
        key = "2a2b0078e1330eb0bb858b047935aba7ddc8921a32cfc129ab2132c2d082b3a5"
        header = {"x-apikey" : key}

        # retrive file data
        urlRequest = "https://www.virustotal.com/api/v3/files/" + filehash
        r = requests.get(url = urlRequest, headers = header)
        result = r.json()

        # check for errors
        try:
            error = result["error"]
            # print(error)
            raise HTTPException(status_code=404, detail=error)
        except Exception:
            pass

        print(result)

        # values for file
        resultType = result["data"]["attributes"]["type_tag"]
        resultNames = result["data"]["attributes"]["names"]
        resultNames = ", ".join(resultNames)
        resultDate = result["data"]["attributes"]["last_analysis_date"]
        resultStats = result["data"]["attributes"]["last_analysis_stats"]
        totalScore = 0
        x = 0
        for item in resultStats:
            itemScore = resultStats[item]
            totalScore = totalScore + itemScore
            if item == "malicious" or item == "suspicious":
                x = x + itemScore
            if item == "timeout" or item == "type-unsupported" or item == "failure":
                totalScore = totalScore - itemScore
        resultScore = str(x) + "/" + str(totalScore)
        resultReputation = result["data"]["attributes"]["reputation"]
        resultTag = result["data"]["attributes"]["tags"]
        resultTag = ", ".join(resultTag)

        resultData = schemas.files_base(id = filehash, type = resultType, name = resultNames, score = resultScore, reputation = resultReputation, date = resultDate, tags = resultTag)

        exeParentsList = []

        urlExecutionParents = "https://www.virustotal.com/api/v3/files/" + filehash + "/execution_parents"

        if urlExecutionParents != "":
            # retrive execution parents data
            requestExe = requests.get(url = urlExecutionParents, headers = header)
            responseExe = requestExe.json()

            # get next link
            try:
                nextExeLink = responseExe["links"]["next"]
            except Exception as error:
                nextLink = ""

            # values for execution parents
            for element in responseExe["data"]:
                try:
                    exeId = element["id"]
                    type = element["attributes"]["type_tag"]
                    names = element["attributes"]["names"]
                    names = ", ".join(names)
                    date = element["attributes"]["last_analysis_date"]
                    stats = element["attributes"]["last_analysis_stats"]
                    totalScore = 0
                    x = 0
                    for item in stats:
                        itemScore = stats[item]
                        totalScore = totalScore + itemScore
                        if item == "malicious" or item == "suspicious":
                            x = x + itemScore
                        if item == "timeout" or item == "type-unsupported" or item == "failure":
                            totalScore = totalScore - itemScore
                    score = str(x) + "/" + str(totalScore)
                    reputation = element["attributes"]["reputation"]
                    tags = element["attributes"]["tags"]
                    tags = ", ".join(tags)

                    # insert data to match model
                    exeParentsData = schemas.exe_parents(id = filehash, file_id = exeId, type = type, names = names, score = score, reputation = reputation, date = date, tags = tags)
                    exeParentsList.append(exeParentsData)
                except Exception as error:
                    print(error)
                    pass

        else:
            pass

        def insert():
            # inesrt data into files
            try:
                crud.insert_Files(db, resultData)
            except Exception as error:
                # db.rollback()
                # print(error)
                pass

            # insert data into exe_parents
            for item in exeParentsList:
                try:
                    crud.insert_exeParents(db, item)
                except Exception as error:
                    # db.rollback()
                    # print(error)
                    pass

        insert()

        filesResult = schemas.files(id = filehash, type = resultType, name = resultNames, score = resultScore, reputation = resultReputation, date = resultDate, tags = resultTag, exe_parents = exeParentsList)

        # background task
        background_tasks.add_task(backgroundFiles, filehash, nextExeLink, db)

        return filesResult

    return fileData