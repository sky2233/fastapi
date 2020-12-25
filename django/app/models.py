from django.db import models

# Create your models here.
class ipDomain(models.Model):
    id = models.TextField
    type = models.CharField(max_length=50)
    score = models.CharField(max_length=10)
    reputation = models.CharField(max_length=10)

    def __str__(self):
        return self.id

class commFiles(models.Model):
    id = models.CharField(max_length=255, primary_key=True)
    file_id = models.CharField(max_length=255)
    type = models.CharField(max_length=50)
    names = models.TextField
    score = models.CharField(max_length=10)
    reputation = models.CharField(max_length=10)
    date = models.CharField(max_length=15)
    tags = models.CharField(max_length=255)

    def __str__(self):
        return self.id

class refFiles(models.Model):
    id = models.CharField(max_length=255, primary_key=True)
    file_id = models.CharField(max_length=255)
    type = models.CharField(max_length=50)
    names = models.TextField
    score = models.CharField(max_length=10)
    reputation = models.CharField(max_length=10)
    date = models.CharField(max_length=15)
    tags = models.CharField(max_length=255)

    def __str__(self):
        return self.id