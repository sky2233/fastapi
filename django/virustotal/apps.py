from django.apps import AppConfig


class appConfig(AppConfig):
    name = 'virustotal'

from suit.apps import DjangoSuitConfig
from suit.menu import ParentItem, ChildItem

class SuitConfig(DjangoSuitConfig):
    ADMIN_NAME = "VirusTotal"
    layout = 'horizontal'
    menu = (
        ParentItem('Files', children=[
            ChildItem(model='virustotal.IpDomain'),
            ChildItem(model='virustotal.files'),
            ChildItem(model='virustotal.exeparents'),
        ]),

        ParentItem('Ipdomain', children=[
            ChildItem(model='virustotal.ipdomain'),
            ChildItem(model='virustotal.commfiles'),
            ChildItem(model='virustotal.reffiles'),
        ]),

        ParentItem('Users', children=[
            ChildItem(model='auth.user'),
            ChildItem('User groups', 'auth.group'),
        ], icon='fa fa-users'),

        # ParentItem('View Site', url="/", align_right=True, icon='fa fa-cog'),
    )

