# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Make sure each ForeignKey and OneToOneField has `on_delete` set to the desired behavior
#   * Remove `managed = False` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
from django.db import models
import time

class CommFiles(models.Model):
    id = models.ForeignKey('IpDomain', models.DO_NOTHING, db_column='id')
    file_id = models.CharField(max_length=255, primary_key=True)
    type = models.CharField(max_length=50)
    names = models.TextField()
    score = models.CharField(max_length=10)
    reputation = models.CharField(max_length=10)
    date = models.CharField(max_length=15)
    tags = models.CharField(max_length=255)
    sandbox_classification = models.CharField(max_length=255, blank=True, null=True)

    @property
    def time(self):
        timestamp = int(self.date)
        calculated_time = time.strftime('%m/%d/%Y %H:%M:%S',  time.gmtime(timestamp)) + " UTC"
        return calculated_time

    @property
    def scoreRange(self):
        score = self.score
        scoreNum = int(score.split("/", 1)[0])
        if scoreNum <= 20:
            return "0 - 20"
        elif scoreNum <= 40:
            return "21 - 40"
        else:
            return "41 <"
        return scoreNum

    class Meta:
        managed = False
        db_table = 'comm_files'
        verbose_name = "Communicating File"
        verbose_name_plural = "Communicating Files"

    def __str__(self):
        return self.file_id

class ExeParents(models.Model):
    id = models.ForeignKey('Files', models.DO_NOTHING, db_column='id')
    file_id = models.CharField(max_length=255, primary_key=True)
    type = models.CharField(max_length=50)
    names = models.TextField()
    score = models.CharField(max_length=10)
    reputation = models.CharField(max_length=10)
    date = models.CharField(max_length=15)
    tags = models.CharField(max_length=255)

    @property
    def time(self):
        timestamp = int(self.date)
        calculated_time = time.strftime('%m/%d/%Y %H:%M:%S',  time.gmtime(timestamp)) + " UTC"
        return calculated_time

    class Meta:
        managed = False
        db_table = 'exe_parents'
        verbose_name = "Execution Parent"
        verbose_name_plural = "Execution Parents"

    def __str__(self):
        return self.file_id


class Files(models.Model):
    id = models.CharField(primary_key=True, max_length=255)
    type = models.CharField(max_length=50)
    name = models.TextField()
    date = models.CharField(max_length=15)
    score = models.CharField(max_length=10)
    reputation = models.CharField(max_length=10)
    tags = models.CharField(max_length=255)

    @property
    def time(self):
        timestamp = int(self.date)
        calculated_time = time.strftime('%m/%d/%Y %H:%M:%S',  time.gmtime(timestamp)) + " UTC"
        return calculated_time

    class Meta:
        managed = False
        db_table = 'files'
        verbose_name = "File"
        verbose_name_plural = "Files"

    def __str__(self):
        return self.id


class IpDomain(models.Model):
    id = models.CharField(primary_key=True, max_length=255)
    type = models.CharField(max_length=50)
    score = models.CharField(max_length=10)
    reputation = models.CharField(max_length=10)

    class Meta:
        managed = False
        db_table = 'ip_domain'
        verbose_name = "Ip Domain"
        verbose_name_plural = "Ip Domain"
    
    def __str__(self):
        return self.id


class RefFiles(models.Model):
    id = models.ForeignKey(IpDomain, models.DO_NOTHING, db_column='id')
    file_id = models.CharField(max_length=255, primary_key=True)
    type = models.CharField(max_length=50)
    names = models.TextField()
    score = models.CharField(max_length=10)
    reputation = models.CharField(max_length=10)
    date = models.CharField(max_length=15)
    tags = models.CharField(max_length=255, blank=True, null=True)

    @property
    def time(self):
        timestamp = int(self.date)
        calculated_time = time.strftime('%m/%d/%Y %H:%M:%S',  time.gmtime(timestamp)) + " UTC"
        return calculated_time

    class Meta:
        managed = False
        db_table = 'ref_files'
        verbose_name = "Referring File"
        verbose_name_plural = "Referring Files"

    def __str__(self):
        return self.file_id
