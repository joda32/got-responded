```
  ______  _____    __         _____   ______  ______  _____  _____  ____   _  _____   ______  _____   
 |   ___|/     \ _|  |_  ___ |     | |   ___||   ___||     |/     \|    \ | ||     \ |   ___||     \  
 |   |  ||     ||_    _||___||     \ |   ___| `-.`-. |    _||     ||     \| ||      \|   ___||      \ 
 |______|\_____/  |__|       |__|\__\|______||______||___|  \_____/|__/\____||______/|______||______/
 
Author: @_w_m__   
A simple tool to detect NBT-NS and LLMNR spoofing (and messing with them a bit)
```
![gif](https://i.imgur.com/myBGqLz.gif)

## What is it?
Pentesters, Redteamers and even real attackers love to use tools like Responder to spoof LLMNR and/or NBT-NS responses. There are some awesome other tools to help with detection, such as [respounder](https://github.com/codeexpress/respounder). But I wanted to figure it out for myself, and at the same time add a way to push "honey" tokens (fake AD credentials) to people using these spoofing tools.

## How to install
```
git clone https://github.com/joda32/got-responded.git
cd got-responded
python3 -m venv responded-env
source responded-env/bin/activate
pip install -r requirements.txt
```
## How to use it

#### Simple mode
This will start it in default mode, will check for both LLMNR and NBT-NS spoofing, but will not send fake SMB creds
``` 
python got-responded.py
```
