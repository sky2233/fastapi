from sqlalchemy.orm import Session

from . import models, schemas

def getIpDomain(db: Session, id: str):
    return db.query(models.ip_domain).filter(models.ip_domain.id == id).first()

def getCommFiles(db: Session, id: str):
    return db.query(models.comm_files).filter(models.comm_files.id == id).first()

def getRefFiles(db: Session, id: str):
    return db.query(models.ref_files).filter(models.ref_files.id == id).first()

def getFiles(db: Session, id: str):
    return db.query(models.files).filter(models.files.id == id).first()

def getExeParents(db: Session, id: str):
    return db.query(models.exe_parents).filter(models.exe_parents.id == id).first()

def insert_IpDomain(db: Session, data: schemas.ip_domain_base):
    IpDomainData = models.ip_domain(**data.dict())
    db.add(IpDomainData)
    db.commit()
    db.refresh(IpDomainData)
    return IpDomainData

def insert_CommFiles(db: Session, data: schemas.comm_files):
    CommFilesData = models.comm_files(**data.dict())
    db.add(CommFilesData)
    db.commit()
    db.refresh(CommFilesData)
    return CommFilesData

def insert_RefFiles(db: Session, data: schemas.ref_files):
    RefFilesData = models.ref_files(**data.dict())
    db.add(RefFilesData)
    db.commit()
    db.refresh(RefFilesData)
    return RefFilesData

def insert_Files(db: Session, data: schemas.files_base):
    FilesData = models.files(**data.dict())
    db.add(FilesData)
    db.commit()
    db.refresh(FilesData)
    return FilesData

def insert_exeParents(db: Session, data: schemas.exe_parents):
    ExeParentsData = models.exe_parents(**data.dict())
    db.add(ExeParentsData)
    db.commit()
    db.refresh(ExeParentsData)
    return ExeParentsData
