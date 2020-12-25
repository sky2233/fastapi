from typing import List, Optional

from pydantic import BaseModel

class comm_files_base(BaseModel):
    pass
class comm_files_create(comm_files_base):
    pass
class comm_files(comm_files_base):
    id: str
    file_id: str
    type: str
    names: str
    score: str
    reputation: str
    date: str
    tags: str
    sandbox_classification: str

    class Config:
        orm_mode = True

class ref_files_base(BaseModel):
    pass
class ref_files_create(comm_files_base):
    pass
class ref_files(comm_files_base):
    id: str
    file_id: str
    type: str
    names: str
    score: str
    reputation: str
    date: str
    tags: str

    class Config:
        orm_mode = True
        
class ip_domain_base(BaseModel):
    id: str
    type: str
    score: str
    reputation: str

class ip_domain_create(ip_domain_base):
    pass

class ip_domain(ip_domain_base):
    # id: str
    # type: str
    # score: str
    # reputation: str

    comm_files: List[comm_files]
    ref_files: List[ref_files]

    class Config:
        orm_mode = True

class exe_parents_base(BaseModel):
    pass
class exe_parents_create(exe_parents_base):
    pass
class exe_parents(exe_parents_base):
    id: str
    file_id: str
    type: str
    names: str
    score: str
    reputation: str
    date: str
    tags: str

    class Config:
        orm_mode = True

class files_base(BaseModel):
    id: str
    type: str
    name: str
    score: str
    reputation: str
    date: str
    tags: str

class files_create(files_base):
    pass
class files(files_base):
    # id: str
    # type: str
    # name: str
    # score: str
    # reputation: str
    # date: str
    # tags: str

    exe_parents: List[exe_parents]

    class Config:
        orm_mode = True