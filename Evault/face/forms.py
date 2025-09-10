from django import forms

class FileUploadForm(forms.Form):
    folder_name = forms.CharField(max_length=100, label='Folder Name')
    file = forms.FileField(label='Select a file')
