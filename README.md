## HOW TO USE

1. Edit the plain text as you want
2. Encrypt it using CBC or ECB
For CBC use this command to encrypt :
```
python Data_Encryption_Assignment.py encrypt CBC --key "SecrKey!" plaintext.txt cipher.enc
```
and use this command for decrypt :
```
python Data_Encryption_Assignment.py decrypt CBC --key "SecrKey!" cipher.enc hasil.txt
``` 
(If you want to use ECB, just replace the CBC on the command)
