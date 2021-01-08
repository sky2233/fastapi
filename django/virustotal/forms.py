from django import forms

class searchForm(forms.Form):
    searchValue = forms.CharField(label='searchValue', max_length=255)
    type = forms.CharField(label='type', max_length=20)