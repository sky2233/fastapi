from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from .database import Base

class ip_domain(Base):
    __tablename__ = "ip_domain"

    id = Column(String, primary_key=True)
    type = Column(String)
    score = Column(String)
    reputation = Column(String)

    comm_files = relationship("comm_files")

    ref_files = relationship("ref_files")


class comm_files(Base):
    __tablename__ = "comm_files"

    id = Column(String, ForeignKey("ip_domain.id"))
    file_id = Column(String, primary_key = True)
    type = Column(String)
    names = Column(String)
    score = Column(String)
    reputation = Column(String)
    date = Column(String)
    tags = Column(String)
    sandbox_classification = Column(String)

class ref_files(Base):
    __tablename__ = "ref_files"

    id = Column(String, ForeignKey("ip_domain.id"))
    file_id = Column(String, primary_key = True)
    type = Column(String)
    names = Column(String)
    score = Column(String)
    reputation = Column(String)
    date = Column(String)
    tags = Column(String)

class files(Base):
    __tablename__ = "files"

    id = Column(String, primary_key=True)
    type = Column(String)
    name = Column(String)
    date = Column(String)
    score = Column(String)
    reputation = Column(String)
    tags = Column(String)

    exe_parents = relationship("exe_parents")

class exe_parents(Base):
    __tablename__ = "exe_parents"

    id = Column(String, ForeignKey("files.id"))
    file_id = Column(String, primary_key=True)
    type = Column(String)
    names = Column(String)
    score = Column(String)
    reputation = Column(String)
    date = Column(String)
    tags = Column(String)
