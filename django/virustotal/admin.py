from django.contrib import admin
from django.utils.translation import ugettext_lazy as _
from django.utils.html import format_html
import time

from .models import *

# Register your models here.
@admin.register(IpDomain)
class ipDomain(admin.ModelAdmin):
    list_display = ("idLink", "type", "score")
    search_fields = (['id'])
    list_filter = (["type"])

    def idLink(self, obj):
        return format_html("<a href='{url}'>{name}</a>", url="/ipdomain/" + obj.id, name=obj.id)

    idLink.short_description = "Id"

@admin.register(CommFiles)
class commFiles(admin.ModelAdmin):
    list_display = ("fileIdLink", "id", "type", "score", "time")
    search_fields = (['=id__id', 'file_id'])
    list_filter = (["type"])
    readonly_fields = (["time"])

    def fileIdLink(self, obj):
        return format_html("<a href='{url}'>{name}</a>", url="/files/" + obj.file_id, name=obj.file_id)

    fileIdLink.short_description = "File Id"

@admin.register(RefFiles)
class refFiles(admin.ModelAdmin):
    list_display = ("fileIdLink", "id", "type", "score", "time")
    search_fields = (['=id__id',  'file_id'])
    list_filter = (["type"])
    readonly_fields = (["time"])

    def fileIdLink(self, obj):
        return format_html("<a href='{url}'>{name}</a>", url="/files/" + obj.file_id, name=obj.file_id)

    fileIdLink.short_description = "File Id"

@admin.register(Files)
class files(admin.ModelAdmin):
    list_display = ("changeLink", "type", "time", "score")
    search_fields = (['id'])
    list_filter = (["type"])
    readonly_fields = (["time"])

    def changeLink(self, obj):
        return format_html("<a href='{url}'>{name}</a>", url="/files/" + obj.id, name=obj.id)

    changeLink.short_description = "Id"

@admin.register(ExeParents)
class exeParents(admin.ModelAdmin):
    list_display = ("fileIdLink", "id", "type", "score", "time")
    search_fields = (['=id__id',  'file_id'])
    list_filter = (["type"])
    readonly_fields = (["time"])

    def fileIdLink(self, obj):
        return format_html("<a href='{url}'>{name}</a>", url="/files/" + obj.file_id, name=obj.file_id)

    fileIdLink.short_description = "File Id"