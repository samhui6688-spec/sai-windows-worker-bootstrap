#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SAi Windows Worker 一次性安裝（bootstrap）v2。
.DESCRIPTION
    由 SAi 預先產生，綁定當次安裝。__PIN_*__ 佔位符由 SAi 喺產生嗰陣填入 pin 死嘅值，
    唔好手改。用戶只需：管理員 PowerShell → 貼上 → Enter → 按指示貼 token → 等完成。
    對應設計：~/workspace/goals/cloud-hands-sai/files/windows-worker-agent-design.md §5
    填 pin 程序：同目錄 PIN-PROCEDURE.md（邊個填、邊個獨立核對）
    狀態：草稿，等獨立 re-review，未 publish，唔准用。
.NOTES
    - #Requires 經 iex 貼上唔會生效（只認檔案執行）；下面有手動管理員檢查，嗰個先係真防線。
    - Get-Credential 要 GUI：假設 Desktop Experience（而家部 VM 係）。
    - Worker 純標準庫（argparse/json/os/sys/time/hashlib/hmac/re/tempfile/urllib），
      所以唔用 PyInstaller：直接用 pin 死嘅 embeddable Python 跑源碼。
      建構輸入 = Python zip hash＋源碼 zip hash，冇 pip、冇第三方依賴，冇嘢漂移。
#>
$ErrorActionPreference = 'Stop'

# ============ 由 SAi 產生嗰陣填（pin 死，全部喺頂，唔好散落）============
$Pin_BusRepoSha    = '9c331311002156773ee4c578d2075ab9c6f5d015'    # sai-windows-worker-bus 嘅 commit SHA
$Pin_SrcZipSha256  = 'd75a43b272884152066902e6b51998e4d338eb2e2def7e3a6349055a9900dc40'  # 上面個 commit 嘅 zipball SHA-256（產生嗰陣即拉即計）
$Pin_PythonUrl     = 'https://www.python.org/ftp/python/3.14.7/python-3.14.7-embed-amd64.zip'      # Python embeddable amd64 zip（官方 python.org）
$Pin_PythonSha256  = 'd297e5ff019966817ad8502465176139f2d3d840fa4ed84b13bed399a6ab1f15'
$Pin_TrialUrl      = 'https://raw.githubusercontent.com/samhui6688-spec/sai-windows-worker-bootstrap/7dbdcdac3c22c2d7667e90357df5198d85b9f2ce/bootstrap/trial-1.txt'       # 白名單內公開小檔（raw.githubusercontent.com），試驗任務用
$Pin_TrialSha256   = 'ba0d868f1c53351e50206428f13bf5cc0be02ca13e1dbae16cda3af705d2cbf0'
$Pin_NssmUrl       = 'https://nssm.cc/release/nssm-2.24.zip'
$Pin_NssmSha256    = '727d1e42275c605e0f04aba98095c38a8e1e46def453cdffce42869428aa6743'
# ========================================================================

$WorkDir   = 'C:\ProgramData\sai-worker'
$LogFile   = Join-Path $WorkDir 'install.log'
$SvcName   = 'sai-worker'
$BusRepo   = 'samhui6688-spec/sai-windows-worker-bus'

function Log($msg) {
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $msg"
    $line | Out-File -FilePath $LogFile -Append -Encoding utf8
    Write-Host $line
}

function Get-FileWithHash($url, $dest, $expectedSha256, $headers) {
    Log "下載 $url"
    $params = @{ Uri = $url; OutFile = $dest; UseBasicParsing = $true }
    if ($headers) { $params['Headers'] = $headers }
    Invoke-WebRequest @params
    $actual = (Get-FileHash -Path $dest -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $expectedSha256.ToLower()) {
        throw "HASH_MISMATCH: $dest`n預期 $expectedSha256`n實際 $actual"
    }
    Log "校驗通過 $dest"
}

# LSA 授權（SeServiceLogonRight／SeBatchLogonRight）：唔假設預設有
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class LsaUtil {
    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_UNICODE_STRING {
        public UInt16 Length; public UInt16 MaximumLength; public IntPtr Buffer;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_OBJECT_ATTRIBUTES {
        public int Length; public IntPtr RootDirectory; public IntPtr ObjectName;
        public int Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService;
    }
    [DllImport("advapi32.dll", PreserveSig=true)]
    public static extern uint LsaOpenPolicy(ref LSA_UNICODE_STRING SystemName,
        ref LSA_OBJECT_ATTRIBUTES ObjectAttributes, int DesiredAccess, out IntPtr PolicyHandle);
    [DllImport("advapi32.dll", PreserveSig=true)]
    public static extern uint LsaAddAccountRights(IntPtr PolicyHandle, byte[] AccountSid,
        LSA_UNICODE_STRING[] UserRights, int CountOfRights);
    [DllImport("advapi32.dll", PreserveSig=true)]
    public static extern uint LsaClose(IntPtr PolicyHandle);
    [DllImport("advapi32.dll", PreserveSig=true)]
    public static extern uint LsaNtStatusToWinError(uint status);
}
"@

function Grant-LsaRight($accountName, $rightName) {
    $sid = (New-Object Security.Principal.NTAccount($accountName)).Translate(
        [Security.Principal.SecurityIdentifier])
    $sidBytes = New-Object byte[] $sid.BinaryLength
    $sid.GetBinaryForm($sidBytes, 0)
    $systemName = New-Object LsaUtil+LSA_UNICODE_STRING
    $attrs = New-Object LsaUtil+LSA_OBJECT_ATTRIBUTES
    $attrs.Length = [Runtime.InteropServices.Marshal]::SizeOf($attrs)
    [IntPtr]$handle = [IntPtr]::Zero
    $st = [LsaUtil]::LsaOpenPolicy([ref]$systemName, [ref]$attrs, 0x810, [ref]$handle)
    if ($st -ne 0) { throw "LsaOpenPolicy 失敗：$([LsaUtil]::LsaNtStatusToWinError($st))" }
    try {
        $right = New-Object LsaUtil+LSA_UNICODE_STRING
        $right.Buffer = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($rightName)
        $right.Length = [UInt16]($rightName.Length * 2)
        $right.MaximumLength = [UInt16](($rightName.Length + 1) * 2)
        $st = [LsaUtil]::LsaAddAccountRights($handle, $sidBytes, @($right), 1)
        [Runtime.InteropServices.Marshal]::FreeHGlobal($right.Buffer)
        if ($st -ne 0) { throw "LsaAddAccountRights 失敗：$([LsaUtil]::LsaNtStatusToWinError($st))" }
    } finally { [void][LsaUtil]::LsaClose($handle) }
    Log "已授 $rightName 畀 $accountName"
}

# Credential Manager 寫入（唔經 cmdkey，唔將明文放 process 命令行）
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class CredMan {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct CREDENTIAL {
        public int Flags; public int Type; public string TargetName; public string Comment;
        public long LastWritten; public int CredentialBlobSize; public IntPtr CredentialBlob;
        public int Persist; public int AttributeCount; public IntPtr Attributes;
        public string TargetAlias; public string UserName;
    }
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool CredWrite([In] ref CREDENTIAL cred, [In] int flags);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool CredDelete(string target, int type, int flags);
}
"@

function Write-CredentialBlob($target, $userName, $secretPlain) {
    $blob = [Text.Encoding]::Unicode.GetBytes($secretPlain)
    $ptr = [Runtime.InteropServices.Marshal]::AllocHGlobal($blob.Length)
    try {
        [Runtime.InteropServices.Marshal]::Copy($blob, 0, $ptr, $blob.Length)
        $c = New-Object CredMan+CREDENTIAL
        $c.Flags = 0; $c.Type = 1  # CRED_TYPE_GENERIC
        $c.TargetName = $target; $c.UserName = $userName
        $c.CredentialBlobSize = $blob.Length; $c.CredentialBlob = $ptr
        $c.Persist = 2  # CRED_PERSIST_LOCAL_MACHINE
        if (-not [CredMan]::CredWrite([ref]$c, 0)) { throw "CredWrite 失敗" }
    } finally {
        for ($i = 0; $i -lt $blob.Length; $i++) { $blob[$i] = 0 }
        [Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
    }
    Log "Token 已寫入 Credential Manager（$target，屬安裝帳戶；Phase 1 worker 唔用，留 Phase 2+ 配對）"
}

# ---- 0. 管理員檢查（真防線）＋冪等：清走舊嘅再裝 ----
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '請用「系統管理員」身份開 PowerShell 再跑。'
}
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
Log '=== SAi Worker 安裝開始（v2） ==='
if (Get-Service -Name $SvcName -ErrorAction SilentlyContinue) {
    Log '發現舊 service，先清走（冪等重跑）'
    Stop-Service -Name $SvcName -Force -ErrorAction SilentlyContinue
    sc.exe delete $SvcName | Out-Null
    Start-Sleep -Seconds 2
}
if (Get-ScheduledTask -TaskName $SvcName -ErrorAction SilentlyContinue) {
    Log '發現舊排程任務，先清走（冪等重跑）'
    Unregister-ScheduledTask -TaskName $SvcName -Confirm:$false
}

# ---- 1. 攞 GitHub token（密碼盒，唔回顯；同一個 BSTR 配置，try/finally 清）----
$cred = Get-Credential -UserName 'sai-worker-token' -Message '貼上 GitHub token（開咗呢個 repo 讀權就得），撳確定'
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password)
try {
    $tokenPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}
Write-CredentialBlob 'sai-worker/github' 'sai-worker-token' $tokenPlain
$authHeader = @{ Authorization = "Bearer $tokenPlain" }

# ---- 2. 建本地服務帳戶 sai-worker（隨機密碼；密碼留到註冊完成先清）----
if (-not (Get-LocalUser -Name $SvcName -ErrorAction SilentlyContinue)) {
    $chars = (48..57) + (65..90) + (97..122)
    $pwPlain = -join ($chars | Get-Random -Count 32 | ForEach-Object { [char]$_ })
    $secPw = ConvertTo-SecureString $pwPlain -AsPlainText -Force
    New-LocalUser -Name $SvcName -Password $secPw `
        -Description 'SAi Windows Worker 專用帳戶' `
        -PasswordNeverExpires -UserMayNotChangePassword | Out-Null
    $secPw = $null
    Log '已建立本地帳戶 sai-worker（隨機密碼）'
} else {
    # 帳戶已存在（例如上次裝到一半斷咗）：真係重設密碼，唔係淨 log
    Log '帳戶 sai-worker 已存在，重設密碼再繼續（冪等重跑）'
    $chars = (48..57) + (65..90) + (97..122)
    $pwPlain = -join ($chars | Get-Random -Count 32 | ForEach-Object { [char]$_ })
    $secPw = ConvertTo-SecureString $pwPlain -AsPlainText -Force
    Set-LocalUser -Name $SvcName -Password $secPw
    $secPw = $null
}
# worker 要寫 state／logs／evidence／trial：授修改權（NEW-1）
icacls $WorkDir /grant "sai-worker:(OI)(CI)M" | Out-Null
Log "WorkDir ACL：$(icacls $WorkDir | Select-String 'sai-worker')"

# ---- 3. 下載＋校驗 Python embeddable（純標準庫，唔裝 pip）----
$pyZip = Join-Path $WorkDir 'python-embed.zip'
$pyDir  = Join-Path $WorkDir 'python'
Get-FileWithHash $Pin_PythonUrl $pyZip $Pin_PythonSha256
if (-not (Test-Path (Join-Path $pyDir 'python.exe'))) {
    Expand-Archive -Path $pyZip -DestinationPath $pyDir -Force
}
$pyExe = Join-Path $pyDir 'python.exe'
$stdlibOk = & $pyExe -c "import argparse,json,os,sys,time,hashlib,hmac,re,tempfile,urllib.request; print('stdlib-ok')"
if ($stdlibOk -ne 'stdlib-ok') { throw 'Python 標準庫自檢失敗' }
Log "Python 就緒：$pyExe（標準庫自檢通過）"

# ---- 4. 核對 commit SHA（防 zipball 漂移）＋下載＋校驗 Worker 源碼 ----
$commitInfo = Invoke-RestMethod -Uri "https://api.github.com/repos/$BusRepo/commits/$Pin_BusRepoSha" `
    -Headers $authHeader
if ($commitInfo.sha -ne $Pin_BusRepoSha.ToLower()) {
    throw "commit SHA 核對失敗：API 回 $($commitInfo.sha)，pin 係 $Pin_BusRepoSha"
}
Log "commit SHA 核對通過：$Pin_BusRepoSha"
$srcZip = Join-Path $WorkDir 'worker-src.zip'
$srcDir = Join-Path $WorkDir 'src'
Get-FileWithHash "https://api.github.com/repos/$BusRepo/zipball/$Pin_BusRepoSha" `
    $srcZip $Pin_SrcZipSha256 $authHeader
if (Test-Path $srcDir) { Remove-Item $srcDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $srcDir | Out-Null
Expand-Archive -Path $srcZip -DestinationPath $srcDir -Force
$unpacked = Get-ChildItem $srcDir | Select-Object -First 1
$workerPy = Join-Path $unpacked.FullName 'worker-v1\worker.py'
if (-not (Test-Path $workerPy)) { throw "源碼包入面搵唔到 worker-v1\worker.py" }
Log "Worker 源碼就緒：$workerPy"
# token 用完：盡力清（immutable string 清唔乾淨，盡量縮短壽命）
$tokenPlain = ('x' * 256); $tokenPlain = $null; $authHeader = $null
Log '安裝用 token 已盡力清除（只留 Credential Manager 入面嗰份）'

# ---- 5. 寫入初始任務池（無 BOM UTF-8）＋試驗任務（白名單內公開 URL）----
$poolPath = Join-Path $WorkDir 'pool.json'
$poolObj = @{
    pool_version = 1
    tasks        = @(
        @{
            task_id    = 'trial-1'
            capability = 'download_file'
            params     = @{
                url    = $Pin_TrialUrl
                dest   = 'trial/trial-file'
                sha256 = $Pin_TrialSha256
            }
            status     = 'pending'
        }
    )
}
$poolJson = ($poolObj | ConvertTo-Json -Depth 6)
[IO.File]::WriteAllText($poolPath, $poolJson, [Text.UTF8Encoding]::new($false))
$firstBytes = [IO.File]::ReadAllBytes($poolPath)[0..2]
if ($firstBytes[0] -eq 0xEF -and $firstBytes[1] -eq 0xBB -and $firstBytes[2] -eq 0xBF) {
    throw 'pool.json 有 BOM，唔應該發生'
}
Log "任務池已寫入（無 BOM）：$poolPath（含試驗任務 trial-1）"

# ---- 6. 授登入權＋註冊開機自動行 ----
Grant-LsaRight $SvcName 'SeServiceLogonRight'
Grant-LsaRight $SvcName 'SeBatchLogonRight'
$workerArgs = "`"$workerPy`" --pool `"$poolPath`" --base-dir `"$WorkDir`""
$registered = $null
$nssmFailed = $false
try {
    $nssmZip = Join-Path $WorkDir 'nssm.zip'
    Get-FileWithHash $Pin_NssmUrl $nssmZip $Pin_NssmSha256
    $nssmDir = Join-Path $WorkDir 'nssm'
    if (Test-Path $nssmDir) { Remove-Item $nssmDir -Recurse -Force }
    Expand-Archive -Path $nssmZip -DestinationPath $nssmDir -Force
    $nssm = Get-ChildItem -Path $nssmDir -Recurse -Filter 'nssm.exe' |
        Where-Object { $_.FullName -match 'win64' } | Select-Object -First 1
    if (-not $nssm) { throw 'NSSM 包入面搵唔到 win64/nssm.exe' }
    & $nssm.FullName install $SvcName $pyExe | Out-Null
    & $nssm.FullName set $SvcName AppDirectory (Split-Path $workerPy) | Out-Null
    & $nssm.FullName set $SvcName AppParameters $workerArgs | Out-Null
    & $nssm.FullName set $SvcName DisplayName 'SAi Windows Worker' | Out-Null
    & $nssm.FullName set $SvcName ObjectName ".\$SvcName" $pwPlain | Out-Null
    Start-Service $SvcName
    $svc = Get-Service -Name $SvcName
    if ($svc.Status -ne 'Running') { throw "service 狀態係 $($svc.Status)，唔係 Running" }
    $registered = 'nssm-service'
    Log '已用 NSSM 註冊為 Windows service 並啟動（Running）'
} catch {
    $nssmFailed = $true
    Log "NSSM 路徑失敗（$($_.Exception.Message)）"
}
if ($nssmFailed) {
    # 唔留爛 service：清走先降級
    if (Get-Service -Name $SvcName -ErrorAction SilentlyContinue) {
        Stop-Service -Name $SvcName -Force -ErrorAction SilentlyContinue
        sc.exe delete $SvcName | Out-Null
        Log '已清走失敗嘅 service 註冊'
    }
    Log '降級：改用開機排程任務'
    $action = New-ScheduledTaskAction -Execute $pyExe -Argument $workerArgs `
        -WorkingDirectory (Split-Path $workerPy)
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\$SvcName" `
        -LogonType Password -RunLevel Highest
    Register-ScheduledTask -TaskName $SvcName -Action $action -Trigger $trigger `
        -Principal $principal -User "$env:COMPUTERNAME\$SvcName" -Password $pwPlain `
        -Force | Out-Null
    Start-ScheduledTask -TaskName $SvcName
    $task = Get-ScheduledTask -TaskName $SvcName
    if ($task.State -notin @('Running', 'Ready')) { throw "排程任務狀態係 $($task.State)" }
    $registered = 'scheduled-task'
    Log '已用開機排程任務啟動（後備方案）'
}
# 註冊完成：盡力清密碼
$pwPlain = ('x' * 256); $pwPlain = $null
Log '服務帳戶密碼已盡力清除'

# ---- 7. 等心跳＋驗證 trial-1 真係跑完（唔係淨睇新鮮度）----
$hbPath = Join-Path $WorkDir 'state\heartbeat.json'
$evPath = Join-Path $WorkDir 'evidence\trial-1.json'
$deadline = (Get-Date).AddMinutes(8)
$healthy = $false
while ((Get-Date) -lt $deadline) {
    if (Test-Path $hbPath) {
        $hb = Get-Content $hbPath -Raw | ConvertFrom-Json
        $age = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - $hb.timestamp_unix
        $noErr = ($hb.consecutive_errors -eq 0) -and [string]::IsNullOrEmpty($hb.last_error)
        if ($age -lt 180 -and $noErr -and $hb.cycle_outcome -eq 'TASK_DONE' `
            -and (Test-Path $evPath)) {
            $ev = Get-Content $evPath -Raw | ConvertFrom-Json
            if ($ev.cycle_outcome -eq 'TASK_DONE') { $healthy = $true; break }
        }
    }
    Start-Sleep -Seconds 10
}
if (-not $healthy) {
    $diag = if (Test-Path $hbPath) { Get-Content $hbPath -Raw } else { '（冇心跳檔）' }
    throw "安裝失敗：8 分鐘內 trial-1 冇成功。心跳現狀：$diag"
}
$hbTime = ([DateTimeOffset]::FromUnixTimeSeconds([long]$hb.timestamp_unix)).ToLocalTime()
Write-Host ''
Write-Host '=============================================='
Write-Host '  ✅ Worker 上線（trial-1 下載＋對 hash 成功）'
Write-Host "  模式：$registered"
Write-Host "  心跳時間：$hbTime"
Write-Host "  心跳：$hbPath"
Write-Host "  證據：$evPath"
Write-Host "  Python：$pyExe"
Write-Host "  源碼：$workerPy"
Write-Host '=============================================='
Write-Host ''
Write-Host '解除安裝一鍵指令（出事先用）：'
Write-Host "  Stop-Service $SvcName -ErrorAction SilentlyContinue; sc.exe delete $SvcName; schtasks /delete /tn $SvcName /f 2>`$null | Out-Null; cmdkey /delete:sai-worker/github 2>`$null | Out-Null; Remove-LocalUser $SvcName -ErrorAction SilentlyContinue; Remove-Item '$WorkDir' -Recurse -Force -ErrorAction SilentlyContinue"
Write-Host ''
Log '=== SAi Worker 安裝完成 ==='
