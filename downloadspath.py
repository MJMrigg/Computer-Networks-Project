import os
import winreg

def get_download_path():
    """Returns the default downloads path for linux or windows"""
    if os.name == 'nt':
        sub_key = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
        downloads_guid = '{374DE290-123F-4565-9164-39C4925E467B}'
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub_key) as key:
            location = winreg.QueryValueEx(key, downloads_guid)[0]
        return location
    else:
        return os.path.join(os.path.expanduser('~'), 'downloads')

f = None
filename = "Myfile.txt"
downloads = get_download_path()
path = f"{downloads}\{filename}"
number = 0
while(1):
    if(os.path.exists(path)):
        number += 1
        filename = filename.split("(")[0]
        filename = f"{filename}({number})"
        path = f"{downloads}\{filename}"
    else:
        break
f = open(f"{path}", "x")
f.write("TEST")
f.close()