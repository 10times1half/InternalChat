#requires -version 5.1
<#
    내부망 ORCA 챗 클라이언트. PS 5.1 + WinForms, 외부 의존성 없음.
    실행  : powershell.exe -ExecutionPolicy Bypass -File .\InternalChat.ps1
    진단  : powershell.exe -File .\InternalChat.ps1 -SelfTest
#>
param(
    [switch]$SelfTest
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---- 어셈블리 -----------------------------------------------------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Security
[System.Windows.Forms.Application]::EnableVisualStyles()

# PS 런타임은 백그라운드 스레드에서 못 돌림 → HTTP 폴링은 순수 C# 클래스로
try {
    Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Net;
using System.Text;
public static class InternalChatPollHttp {
    public static string Get(string uri, string cookieHeader, int timeoutMs) {
        if (timeoutMs < 3000) timeoutMs = 3000;
        if (timeoutMs > 120000) timeoutMs = 120000;
        HttpWebRequest req = (HttpWebRequest)WebRequest.Create(uri);
        req.Method = "GET";
        req.Timeout = timeoutMs;
        req.ReadWriteTimeout = timeoutMs;
        req.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
        req.UserAgent = "InternalChat-PS/1.0";
        req.Headers["X-Requested-With"] = "XMLHttpRequest";
        if (!string.IsNullOrEmpty(cookieHeader)) {
            req.Headers[HttpRequestHeader.Cookie] = cookieHeader;
        }
        using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
        using (Stream stream = resp.GetResponseStream())
        using (StreamReader reader = new StreamReader(stream, Encoding.UTF8)) {
            return reader.ReadToEnd();
        }
    }
}
"@ -ErrorAction Stop
} catch {
    # 재실행 시 중복 로드 무시
}

# WM_SETREDRAW. ListView 깜빡임 방지
try {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class NativeMethods {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
}
"@ -ErrorAction Stop
} catch {
    # 재실행 시 중복 로드 무시
}



# ---- 기본 서버 설정 (data/config.json이 우선) ---------------------------------
$script:ApiBase = 'http://localhost:9080/orca'
$script:PathLogin       = '/cmn/login/login.do'
$script:PathUserList    = '/note/retrieveSearchList.do?rows=999&page=1&s_prjt_id=PROJECT'
$script:PathMessageList = '/note/retrieveNoteListJson.do?nd=&rows=100&page=1'
$script:PathSendMessage = '/note/insertNote.do'

$script:LoginUrl = $null
$script:GetUserListUrl = $null
$script:GetMessageListUrl = $null
$script:SendMessageUrl = $null
$script:HttpSession = $null

$script:MaxRetry = 3
$script:RetryDelayMs = 800
$script:RequestTimeoutSec = 60
$script:ReloginCallback = $null


# ---- Logger ------------------------------------------------------------------

$script:LogDirectory = $null
$script:LogFilePath  = $null

function Initialize-AppLogger {
    # 로그 디렉토리 생성 + 30일 지난 로그 삭제
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogDirectory,

        [int]$LogRetentionDays = 30
    )

    $script:LogDirectory = $LogDirectory

    if (-not (Test-Path -LiteralPath $script:LogDirectory)) {
        New-Item -ItemType Directory -Path $script:LogDirectory -Force | Out-Null
    }

    # 30일 지난 로그 정리
    try {
        $cutoff = (Get-Date).AddDays(-$LogRetentionDays)
        Get-ChildItem -LiteralPath $script:LogDirectory -Filter 'app_*.log' -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $cutoff } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    } catch { }

    $dateStamp = Get-Date -Format 'yyyyMMdd'
    $script:LogFilePath = Join-Path $script:LogDirectory "app_$dateStamp.log"
}

function Write-AppLog {
    param(
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO',
        [Parameter(Mandatory = $true)][string]$Message,
        [System.Exception]$Exception
    )
    if (-not $script:LogFilePath) { return }
    try {
        $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
        if ($Exception) { $line += ' | ' + $Exception.Message }
        Add-Content -LiteralPath $script:LogFilePath -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch { }
}



# ---- Security (DPAPI + ACL) ---------------------------------------------------

$script:CredentialFilePath = $null
$script:MemoryToken        = $null
$script:MemoryUserId       = $null
$script:MemoryPassword     = $null

function Initialize-SecurityModule {
    # credentials.dat 경로 설정 + data 폴더 ACL 현재 사용자 전용으로
    param(
        [Parameter(Mandatory = $true)]
        [string]$DataDirectory
    )

    $script:CredentialFilePath = Join-Path $DataDirectory 'credentials.dat'

    # 상속 제거하고 현재 사용자만 FullControl
    try {
        $acl = Get-Acl -LiteralPath $DataDirectory
        $acl.SetAccessRuleProtection($true, $false)
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $currentUser,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $DataDirectory -AclObject $acl
        Write-AppLog -Level INFO -Message "데이터 폴더 ACL 설정 완료: $DataDirectory"
    } catch {
        Write-AppLog -Level WARN -Message "데이터 폴더 ACL 설정 실패 (계속 진행)" -Exception $_.Exception
    }
}


function Protect-StringData {
    # DPAPI CurrentUser 범위로 암호화 → Base64
    param(
        [Parameter(Mandatory = $true)]
        [string]$PlainText
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $protected = [System.Security.Cryptography.ProtectedData]::Protect(
        $bytes,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    return [Convert]::ToBase64String($protected)
}

function Unprotect-StringData {
    # DPAPI 복호화
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProtectedBase64
    )

    $protected = [Convert]::FromBase64String($ProtectedBase64)
    $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $protected,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    return [System.Text.Encoding]::UTF8.GetString($bytes)
}

function Save-UserCredential {
    # ID/PW 암호화 저장 + 메모리 캐시
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserId,

        [Parameter(Mandatory = $true)]
        [string]$Password
    )

    $payload = @{
        userId   = $UserId
        password = $Password
        savedAt  = (Get-Date).ToString('o')
    } | ConvertTo-Json -Compress

    $encrypted = Protect-StringData -PlainText $payload
    Set-Content -LiteralPath $script:CredentialFilePath -Value $encrypted -Encoding ASCII -Force

    $script:MemoryUserId   = $UserId
    $script:MemoryPassword = $Password

    Write-AppLog -Level INFO -Message "자격 증명 저장 완료 (UserId=$UserId)"
}

function Get-UserCredential {
    # 메모리 캐시 우선, 없으면 credentials.dat 읽어 복호화
    if ($script:MemoryUserId -and $script:MemoryPassword) {
        return [PSCustomObject]@{
            UserId   = $script:MemoryUserId
            Password = $script:MemoryPassword
        }
    }

    if (-not $script:CredentialFilePath -or -not (Test-Path -LiteralPath $script:CredentialFilePath)) {
        return $null
    }

    try {
        $encrypted = (Get-Content -LiteralPath $script:CredentialFilePath -Raw -Encoding ASCII).Trim()
        $json = Unprotect-StringData -ProtectedBase64 $encrypted
        $obj = $json | ConvertFrom-Json

        $script:MemoryUserId   = [string]$obj.userId
        $script:MemoryPassword = [string]$obj.password

        return [PSCustomObject]@{
            UserId   = $script:MemoryUserId
            Password = $script:MemoryPassword
        }
    }
    catch {
        Write-AppLog -Level ERROR -Message "자격 증명 복호화 실패" -Exception $_.Exception
        return $null
    }
}


function Clear-UserCredential {
    # 자격 증명 파일 + 메모리 삭제
    try {
        if ($script:CredentialFilePath -and (Test-Path -LiteralPath $script:CredentialFilePath)) {
            Remove-Item -LiteralPath $script:CredentialFilePath -Force -ErrorAction SilentlyContinue
        }
    } catch { }
    $script:MemoryUserId = $null
    $script:MemoryPassword = $null
}

function Get-AppConfigPath {
    if ($script:ConfigPath) { return $script:ConfigPath }
    if ($script:DataDir) {
        $script:ConfigPath = Join-Path $script:DataDir 'config.json'
        return $script:ConfigPath
    }
    return $null
}

function Get-AppConfig {
    # data/config.json → PSCustomObject
    $p = Get-AppConfigPath
    if (-not $p -or -not (Test-Path -LiteralPath $p)) { return $null }
    try {
        $raw = Get-Content -LiteralPath $p -Raw -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        return ($raw | ConvertFrom-Json)
    }
    catch {
        Write-AppLog -Level WARN -Message "config.json 로드 실패" -Exception $_.Exception
        return $null
    }
}

function Save-AppConfig {
    # config.json 기록. 창 위치/서버 URL 저장
    param(
        [string]$ApiBase,
        [int]$PollIntervalMs = -1,
        [object]$BalloonWhenChatHidden = $null,
        [object]$BalloonOtherChat = $null,
        [int]$ChatPageSize = -1,
        [object]$MainWindow = $null
    )
    $p = Get-AppConfigPath
    if (-not $p) { throw 'ConfigPath not initialized' }
    $cfg = Get-AppConfig

    $base = $ApiBase
    if ([string]::IsNullOrWhiteSpace($base)) {
        if ($cfg -and $cfg.apiBase) { $base = [string]$cfg.apiBase } else { $base = [string]$script:ApiBase }
    }
    $base = ([string]$base).Trim().TrimEnd('/')

    # 폴링/알림 고정값 (설정 UI가 없으니 하드코딩)
    $poll = 15000
    $bHide = $true
    $bOther = $true

    $page = $ChatPageSize
    if ($page -lt 0) {
        if ($cfg -and $null -ne $cfg.chatPageSize) { try { $page = [int]$cfg.chatPageSize } catch { $page = [int]$script:ChatPageSize } }
        else { $page = [int]$script:ChatPageSize }
    }
    if ($page -lt 20) { $page = 20 }
    if ($page -gt 500) { $page = 500 }

    $mw = $MainWindow
    if ($null -eq $mw) {
        if ($script:MainWindowBounds) { $mw = $script:MainWindowBounds }
        elseif ($cfg -and $cfg.mainWindow) { $mw = $cfg.mainWindow }
    }

    $payloadObj = @{
        apiBase               = $base
        pollIntervalMs        = $poll
        balloonWhenChatHidden = $bHide
        balloonOtherChat      = $bOther
        chatPageSize          = $page
    }
    if ($null -ne $mw) {
        try {
            $payloadObj['mainWindow'] = @{
                x = [int]$mw.x
                y = [int]$mw.y
                w = [int]$mw.w
                h = [int]$mw.h
            }
        } catch { }
    }

    $payload = ($payloadObj | ConvertTo-Json -Compress -Depth 5)
    Set-Content -LiteralPath $p -Value $payload -Encoding UTF8 -Force
    Write-AppLog -Level INFO -Message ("설정 저장 apiBase={0} poll={1}ms" -f $base, $poll)
}


function Set-ApiBaseAddress {
    # ApiBase 업데이트 → URL 재계산
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiBase
    )
    $base = $ApiBase.Trim().TrimEnd('/')
    if ([string]::IsNullOrWhiteSpace($base)) { return $false }
    if ($base -notmatch '^https?://') { return $false }
    $script:ApiBase = $base
    Initialize-ApiUrls
    return $true
}

function Import-ApiBaseFromConfig {
    # config.json 읽어서 전역 변수 덮어쓰기
    $cfg = Get-AppConfig
    if (-not $cfg) { return }

    $base = ''
    try { if ($null -ne $cfg.apiBase) { $base = [string]$cfg.apiBase } } catch { }
    if (-not [string]::IsNullOrWhiteSpace($base)) {
        [void](Set-ApiBaseAddress -ApiBase $base)
    }

    # 폴링 10초 고정
    $script:PollIntervalMs = 10000
    if ($script:PollTimer) { $script:PollTimer.Interval = 10000 }

    # 알림 항상 켬
    $script:BalloonWhenChatHidden = $true
    $script:BalloonOtherChat = $true
    try {
        if ($null -ne $cfg.chatPageSize) {
            $ps = [int]$cfg.chatPageSize
            if ($ps -ge 20 -and $ps -le 500) { $script:ChatPageSize = $ps }
        }
    } catch { }

    try {
        if ($cfg.mainWindow) {
            $script:MainWindowBounds = [PSCustomObject]@{
                x = [int]$cfg.mainWindow.x
                y = [int]$cfg.mainWindow.y
                w = [int]$cfg.mainWindow.w
                h = [int]$cfg.mainWindow.h
            }
        }
    } catch { }
}


function Set-AuthToken {
    param([string]$Token)
    $script:MemoryToken = $Token
}

function Get-AuthToken {
    return $script:MemoryToken
}



function Clear-SensitiveMemory {
    # 종료 시 메모리에서 토큰/ID/PW 제거
    $script:MemoryToken    = $null
    $script:MemoryUserId   = $null
    $script:MemoryPassword = $null
}



# ---- DataManager (로컬 JSON 스토어) -------------------------------------------

$script:DataDirectory  = $null
$script:ChatsDirectory = $null
$script:ConversationsPath = $null
$script:UsersPath         = $null
$script:SyncPath          = $null

function Initialize-DataManager {
    # 경로 설정 + 초기 파일 생성 (conversations.json, users.json)
    param(
        [Parameter(Mandatory = $true)]
        [string]$DataDirectory
    )

    $script:DataDirectory     = $DataDirectory
    $script:ChatsDirectory    = Join-Path $DataDirectory 'chats'
    $script:ConversationsPath = Join-Path $DataDirectory 'conversations.json'
    $script:UsersPath         = Join-Path $DataDirectory 'users.json'
    $script:SyncPath          = Join-Path $DataDirectory 'sync.json'

    # Initialize-Application에서 먼저 만들지만 혹시 몰라 방어
    foreach ($dir in @($script:DataDirectory, $script:ChatsDirectory)) {
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }

    if (-not (Test-Path -LiteralPath $script:ConversationsPath)) {
        Save-JsonSafely -Path $script:ConversationsPath -Object @()
    }
    if (-not (Test-Path -LiteralPath $script:UsersPath)) {
        Save-JsonSafely -Path $script:UsersPath -Object @()
    }
}


function Save-JsonSafely {
    # .tmp → rename. 기존 파일은 .bak 백업
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Object
    )

    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $json = if ($null -eq $Object) {
        'null'
    }
    else {
        # PS 5.1 DefaultDepth=2라 20으로 늘림
        ConvertTo-Json -InputObject $Object -Depth 20 -Compress:$false
    }

    $tempPath = "$Path.tmp"
    $bakPath  = "$Path.bak"

    try {
        # UTF-8 BOM 없이
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($tempPath, $json, $utf8NoBom)

        if (Test-Path -LiteralPath $Path) {
            Copy-Item -LiteralPath $Path -Destination $bakPath -Force
        }

        # rename (원자적 교체. NTFS에선 거의 atomic)
        if (Test-Path -LiteralPath $Path) {
            Remove-Item -LiteralPath $Path -Force
        }
        Move-Item -LiteralPath $tempPath -Destination $Path -Force
    }
    catch {
        Write-AppLog -Level ERROR -Message "Save-JsonSafely 실패: $Path" -Exception $_.Exception
        if (Test-Path -LiteralPath $tempPath) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
        throw
    }
}

function Import-JsonSafely {
    # 로드 실패 → .bak → DefaultValue 순으로 폴백
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        $DefaultValue = @()
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $DefaultValue
    }

    try {
        $raw = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return $DefaultValue
        }
        $obj = $raw | ConvertFrom-Json
        return $obj
    }
    catch {
        Write-AppLog -Level WARN -Message "JSON 로드 실패, .bak 시도: $Path" -Exception $_.Exception

        $bakPath = "$Path.bak"
        if (Test-Path -LiteralPath $bakPath) {
            try {
                $raw = [System.IO.File]::ReadAllText($bakPath, [System.Text.Encoding]::UTF8)
                $obj = $raw | ConvertFrom-Json
                Save-JsonSafely -Path $Path -Object $obj
                Write-AppLog -Level INFO -Message "bak 복원 성공: $Path"
                return $obj
            }
            catch {
                Write-AppLog -Level ERROR -Message "bak 복원 실패: $Path" -Exception $_.Exception
            }
        }

        return $DefaultValue
    }
}


function Get-ConversationMD5 {
    # 참가자 ID 정렬 → | join → MD5. 동일 멤버면 같은 키
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ParticipantIds
    )

    $sorted = $ParticipantIds | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object -Unique
    $joined = ($sorted -join '|')

    $md5 = [System.Security.Cryptography.MD5]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($joined)
        $hash  = $md5.ComputeHash($bytes)
        return ([BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
    }
    finally {
        $md5.Dispose()
    }
}

function Get-ChatFilePath {
    # chats/{md5}_{yyyyMM}.jsonl
    param(
        [Parameter(Mandatory = $true)]
        [string]$Md5,

        [Parameter(Mandatory = $false)]
        [string]$YearMonth = (Get-Date -Format 'yyyyMM')
    )

    return (Join-Path $script:ChatsDirectory ("{0}_{1}.jsonl" -f $Md5, $YearMonth))
}

function Get-ChatLegacyFilePath {
    # 구버전 chats/{md5}_{yyyyMM}.json (마이그레이션 소스)
    param(
        [Parameter(Mandatory = $true)]
        [string]$Md5,

        [Parameter(Mandatory = $false)]
        [string]$YearMonth = (Get-Date -Format 'yyyyMM')
    )

    return (Join-Path $script:ChatsDirectory ("{0}_{1}.json" -f $Md5, $YearMonth))
}


# ---- 인메모리 상태 / dirty flush ----------------------------------------------------

function Initialize-AppState {
    # 인메모리 인덱스 초기화
    $script:UserById = @{}
    $script:ConvByMd5 = @{}
    $script:ConvOrder = New-Object System.Collections.ArrayList
    $script:SyncState = $null
    $script:SyncLoaded = $false
    $script:DirtyUsers = $false
    $script:DirtyConversations = $false
    $script:DirtySync = $false
}

function Ensure-AppStateReady {
    if ($null -eq $script:UserById -or $null -eq $script:ConvByMd5 -or $null -eq $script:ConvOrder) {
        Initialize-AppState
    }
}

function Sort-ConversationOrderInMemory {
    Ensure-AppStateReady
    $items = New-Object System.Collections.ArrayList
    foreach ($md5 in @($script:ConvOrder)) {
        $key = [string]$md5
        if ($script:ConvByMd5.ContainsKey($key)) {
            [void]$items.Add($script:ConvByMd5[$key])
        }
    }
    $sorted = @($items | Sort-Object {
        $t = $null
        try { $t = $_.lastMessageTime } catch { $t = $null }
        if ($t) { try { [datetime]$t } catch { [datetime]::MinValue } } else { [datetime]::MinValue }
    } -Descending)
    $script:ConvOrder = New-Object System.Collections.ArrayList
    foreach ($c in $sorted) {
        try {
            $m = [string]$c.md5
            if ($m) { [void]$script:ConvOrder.Add($m) }
        } catch { }
    }
}

function Import-UsersFromDisk {
    Ensure-AppStateReady
    $data = Import-JsonSafely -Path $script:UsersPath -DefaultValue @()
    $script:UserById = @{}
    foreach ($u in @($data)) {
        if ($null -eq $u) { continue }
        $id = $null
        try { $id = [string]$u.id } catch { $id = $null }
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        $script:UserById[$id] = $u
    }
}

function Import-ConversationsFromDisk {
    Ensure-AppStateReady
    $data = Import-JsonSafely -Path $script:ConversationsPath -DefaultValue @()
    if ($null -eq $data) { $data = @() }
    if ($data -isnot [System.Array]) { $data = @($data) }
    $script:ConvByMd5 = @{}
    $script:ConvOrder = New-Object System.Collections.ArrayList
    foreach ($c in @($data)) {
        if ($null -eq $c) { continue }
        $md5 = $null
        try { $md5 = [string]$c.md5 } catch { $md5 = $null }
        if ([string]::IsNullOrWhiteSpace($md5)) { continue }
        $script:ConvByMd5[$md5] = $c
        [void]$script:ConvOrder.Add($md5)
    }
    Sort-ConversationOrderInMemory
}

function Import-SyncFromDisk {
    Ensure-AppStateReady
    $script:SyncLoaded = $true
    if (-not $script:SyncPath -or -not (Test-Path -LiteralPath $script:SyncPath)) {
        $script:SyncState = $null
        return
    }
    $script:SyncState = Import-JsonSafely -Path $script:SyncPath -DefaultValue $null
}

function Import-AppStateFromDisk {
    # users.json / conversations.json / sync.json → 메모리
    Initialize-AppState
    try { Import-UsersFromDisk } catch { Write-AppLog -Level ERROR -Message "users 로드 실패" -Exception $_.Exception }
    try { Import-ConversationsFromDisk } catch { Write-AppLog -Level ERROR -Message "conversations 로드 실패" -Exception $_.Exception }
    try { Import-SyncFromDisk } catch { Write-AppLog -Level ERROR -Message "sync 로드 실패" -Exception $_.Exception }
    $script:DirtyUsers = $false
    $script:DirtyConversations = $false
    $script:DirtySync = $false
    $uc = 0; $cc = 0
    try { $uc = $script:UserById.Count } catch { }
    try { $cc = $script:ConvByMd5.Count } catch { }
    Write-AppLog -Level DEBUG -Message ("AppState 로드 users={0} convs={1}" -f $uc, $cc)
}

function Set-SyncState {
    param(
        [Parameter(Mandatory = $true)][string]$LastSync,
        [Parameter(Mandatory = $true)][string]$LastMessageId,
        [Parameter(Mandatory = $true)][string]$CurrentUserId
    )
    Ensure-AppStateReady
    $script:SyncLoaded = $true
    $ls = [string]$LastSync
    $li = [string]$LastMessageId
    $cu = [string]$CurrentUserId
    $changed = $true
    if ($null -ne $script:SyncState) {
        try {
            $ols = [string](Get-ObjectProperty -Object $script:SyncState -Name 'lastSync' -Default '')
            $oli = [string](Get-ObjectProperty -Object $script:SyncState -Name 'lastMessageId' -Default '')
            $ocu = [string](Get-ObjectProperty -Object $script:SyncState -Name 'currentUserId' -Default '')
            if ($ols -eq $ls -and $oli -eq $li -and $ocu -eq $cu) { $changed = $false }
        } catch { $changed = $true }
    }
    $script:SyncState = [PSCustomObject]@{
        lastSync      = $ls
        lastMessageId = $li
        currentUserId = $cu
    }
    if ($changed) { $script:DirtySync = $true }
}

function Write-SyncStateToDisk {
    Ensure-AppStateReady
    if ($null -eq $script:SyncState) { return }
    if (-not $script:SyncPath) { return }
    $obj = [ordered]@{
        lastSync      = [string](Get-ObjectProperty -Object $script:SyncState -Name 'lastSync' -Default '')
        lastMessageId = [string](Get-ObjectProperty -Object $script:SyncState -Name 'lastMessageId' -Default '')
        currentUserId = [string](Get-ObjectProperty -Object $script:SyncState -Name 'currentUserId' -Default '')
    }
    Save-JsonSafely -Path $script:SyncPath -Object $obj
    $script:DirtySync = $false
}

function Set-UsersCache {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$Users
    )
    Ensure-AppStateReady
    $script:UserById = @{}
    foreach ($u in @($Users)) {
        if ($null -eq $u) { continue }
        $id = $null
        try { $id = [string]$u.id } catch { $id = $null }
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        $script:UserById[$id] = $u
    }
    $script:DirtyUsers = $true
}

function Write-UsersToDiskFromCache {
    Ensure-AppStateReady
    Save-JsonSafely -Path $script:UsersPath -Object @(Get-Users)
    $script:DirtyUsers = $false
}

function Write-ConversationsToDiskFromCache {
    Ensure-AppStateReady
    Sort-ConversationOrderInMemory
    Save-JsonSafely -Path $script:ConversationsPath -Object @(Get-Conversations)
    $script:DebugConvSaveCount = [int]$script:DebugConvSaveCount + 1
    $script:DirtyConversations = $false
}

function Save-AppStateDirty {
    # dirty 플래그 켜진 것만 디스크 flush
    Ensure-AppStateReady
    $flushed = New-Object System.Collections.ArrayList
    if ($script:DirtyUsers) {
        try {
            Write-UsersToDiskFromCache
            [void]$flushed.Add('users')
        } catch {
            Write-AppLog -Level ERROR -Message "users flush 실패" -Exception $_.Exception
        }
    }
    if ($script:DirtyConversations) {
        try {
            Write-ConversationsToDiskFromCache
            [void]$flushed.Add('conv')
        } catch {
            Write-AppLog -Level ERROR -Message "conversations flush 실패" -Exception $_.Exception
        }
    }
    if ($script:DirtySync) {
        try {
            Write-SyncStateToDisk
            [void]$flushed.Add('sync')
        } catch {
            Write-AppLog -Level ERROR -Message "sync flush 실패" -Exception $_.Exception
        }
    }
    if ($flushed.Count -gt 0) {
        Write-AppLog -Level DEBUG -Message ("flush " + ($flushed -join ','))
    }
}


function Get-SyncState {
    # 동기화 커서. 미로드 시 디스크에서 한 번 읽음
    Ensure-AppStateReady
    if (-not $script:SyncLoaded) { Import-SyncFromDisk }
    return $script:SyncState
}

function Save-SyncState {
    # Set-SyncState 래퍼. 실제 flush는 Save-AppStateDirty에서
    param(
        [Parameter(Mandatory = $true)][string]$LastSync,
        [Parameter(Mandatory = $true)][string]$LastMessageId,
        [Parameter(Mandatory = $true)][string]$CurrentUserId
    )
    Set-SyncState -LastSync $LastSync -LastMessageId $LastMessageId -CurrentUserId $CurrentUserId
}


# ---- conversations.json --------------------------------------------------------

function Get-Conversations {
    # ConvOrder 순서대로 대화 목록 반환
    Ensure-AppStateReady
    $list = New-Object System.Collections.ArrayList
    foreach ($md5 in @($script:ConvOrder)) {
        $key = [string]$md5
        if ($script:ConvByMd5.ContainsKey($key)) {
            [void]$list.Add($script:ConvByMd5[$key])
        }
    }
    return @($list.ToArray())
}


function Get-ConversationByMd5 {
    param([Parameter(Mandatory = $true)][string]$Md5)
    Ensure-AppStateReady
    if ([string]::IsNullOrWhiteSpace($Md5)) { return $null }
    if ($script:ConvByMd5.ContainsKey($Md5)) { return $script:ConvByMd5[$Md5] }
    return $null
}

function Get-ConvProp {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $Default }
    return $p.Value
}

function Test-ConversationTitleLocked {
    param($Conversation)
    return [bool](Get-ConvProp -Object $Conversation -Name 'titleLocked' -Default $false)
}

function New-ConversationRecord {
    # 대화 메타 PSCustomObject 생성
    param(
        [string]$Md5,
        [string[]]$ParticipantIds = @(),
        [string[]]$ParticipantNames = @(),
        [string]$CustomTitle = '',
        [bool]$TitleLocked = $false,
        [string]$LastMonth = '',
        [bool]$Unread = $false,
        [int]$UnreadCount = 0,
        [string]$LastMessageTime = '',
        [string]$LastSeq = '',
        [string]$LastPreview = ''
    )
    if (-not $LastMonth) { $LastMonth = Get-Date -Format 'yyyyMM' }
    if ($UnreadCount -lt 0) { $UnreadCount = 0 }
    if ($UnreadCount -gt 0) { $Unread = $true }
    if (-not $Unread) { $UnreadCount = 0 }
    return [PSCustomObject]@{
        md5              = $Md5
        participantIds   = @($ParticipantIds)
        participantNames = @($ParticipantNames)
        customTitle      = $CustomTitle
        titleLocked      = $TitleLocked
        lastMonth        = $LastMonth
        unread           = $Unread
        unreadCount      = [int]$UnreadCount
        lastMessageTime  = $LastMessageTime
        lastSeq          = $LastSeq
        lastPreview      = $LastPreview
    }
}


function Update-ConversationMeta {
    # 대화 메타 upsert. IncrementUnread/ClearUnread 스위치로 미확인 카운트 제어
    param(
        [Parameter(Mandatory = $true)]
        [string]$Md5,
        [string[]]$ParticipantIds = @(),
        [string[]]$ParticipantNames = @(),
        [string]$CustomTitle = '',
        [string]$LastMonth = '',
        [bool]$Unread = $false,
        [string]$LastMessageTime = '',
        [string]$LastSeq = '',
        [string]$LastPreview = '',
        [switch]$IncrementUnread,
        [switch]$ClearUnread,
        [switch]$LockTitle
    )

    Ensure-AppStateReady
    if ([string]::IsNullOrWhiteSpace($Md5)) { return }

    $ex = $null
    if ($script:ConvByMd5.ContainsKey($Md5)) { $ex = $script:ConvByMd5[$Md5] }

    if ($null -eq $ex) {
        $unreadVal = $false
        $uc = 0
        if ($ClearUnread) { $unreadVal = $false; $uc = 0 }
        elseif ($IncrementUnread) { $unreadVal = $true; $uc = 1 }
        else { $unreadVal = $Unread; $uc = $(if ($Unread) { 1 } else { 0 }) }

        $rec = New-ConversationRecord `
            -Md5 $Md5 `
            -ParticipantIds $ParticipantIds `
            -ParticipantNames $ParticipantNames `
            -CustomTitle $CustomTitle `
            -TitleLocked ([bool]$LockTitle) `
            -LastMonth $LastMonth `
            -Unread $unreadVal `
            -UnreadCount $uc `
            -LastMessageTime $LastMessageTime `
            -LastSeq $LastSeq `
            -LastPreview $LastPreview

        $script:ConvByMd5[$Md5] = $rec
        if ($script:ConvOrder.Contains($Md5)) { [void]$script:ConvOrder.Remove($Md5) }
        $script:ConvOrder.Insert(0, $Md5)
    }
    else {
        $pIds = if (@($ParticipantIds).Count -gt 0) { @($ParticipantIds) } else { @($(Get-ConvProp $ex 'participantIds' @())) }
        $pNms = if (@($ParticipantNames).Count -gt 0) { @($ParticipantNames) } else { @($(Get-ConvProp $ex 'participantNames' @())) }
        $locked = Test-ConversationTitleLocked -Conversation $ex
        $title = [string](Get-ConvProp $ex 'customTitle' '')
        if ($LockTitle) {
            $title = $CustomTitle
            $locked = $true
        }
        elseif ($CustomTitle -and -not $locked) {
            $title = $CustomTitle
        }

        $unreadVal = [bool](Get-ConvProp $ex 'unread' $false)
        $uc = 0
        try { $uc = [int](Get-ConvProp $ex 'unreadCount' 0) } catch { $uc = 0 }
        if ($uc -lt 0) { $uc = 0 }

        if ($ClearUnread) {
            $unreadVal = $false
            $uc = 0
        }
        elseif ($IncrementUnread) {
            $unreadVal = $true
            $uc = $uc + 1
        }
        elseif ($PSBoundParameters.ContainsKey('Unread')) {
            $unreadVal = $Unread
            if (-not $unreadVal) { $uc = 0 }
            elseif ($uc -lt 1) { $uc = 1 }
        }

        $lm = if ($LastMonth) { $LastMonth } else { [string](Get-ConvProp $ex 'lastMonth' (Get-Date -Format 'yyyyMM')) }
        $lmt = if ($LastMessageTime) { $LastMessageTime } else { [string](Get-ConvProp $ex 'lastMessageTime' '') }
        $lseq = if ($LastSeq) { $LastSeq } else { [string](Get-ConvProp $ex 'lastSeq' '') }
        $prev = [string](Get-ConvProp $ex 'lastPreview' '')
        if ($PSBoundParameters.ContainsKey('LastPreview') -and -not [string]::IsNullOrWhiteSpace($LastPreview)) {
            $prev = $LastPreview
        }
        elseif ($LastPreview) {
            $prev = $LastPreview
        }

        $rec = New-ConversationRecord `
            -Md5 $Md5 `
            -ParticipantIds $pIds `
            -ParticipantNames $pNms `
            -CustomTitle $title `
            -TitleLocked $locked `
            -LastMonth $lm `
            -Unread $unreadVal `
            -UnreadCount $uc `
            -LastMessageTime $lmt `
            -LastSeq $lseq `
            -LastPreview $prev

        $script:ConvByMd5[$Md5] = $rec
        if ($LastMessageTime) {
            if ($script:ConvOrder.Contains($Md5)) { [void]$script:ConvOrder.Remove($Md5) }
            $script:ConvOrder.Insert(0, $Md5)
        }
    }

    $script:DirtyConversations = $true
}


function Edit-SelectedConversationTitle {
    # 우클릭 → 제목 변경
    try {
        if (-not $script:ConversationListView -or $script:ConversationListView.IsDisposed) { return }
        if ($script:ConversationListView.SelectedItems.Count -lt 1) {
            Show-InfoMessage -Text '대화를 선택하세요.'
            return
        }
        $md5 = [string]$script:ConversationListView.SelectedItems[0].Tag
        if (-not $md5) { return }
        $conv = Get-ConversationByMd5 -Md5 $md5
        if (-not $conv) {
            Show-InfoMessage -Text '대화 정보를 찾을 수 없습니다.'
            return
        }

        $cur = Get-ConversationDisplayTitle -Conversation $conv -CurrentUserId $script:CurrentUserId
        try { Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction SilentlyContinue } catch { }
        $newTitle = [Microsoft.VisualBasic.Interaction]::InputBox('대화 제목', '제목 변경', $cur)
        # 취소 시 빈 문자열
        if ([string]::IsNullOrWhiteSpace($newTitle)) { return }
        $newTitle = $newTitle.Trim()

        Update-ConversationMeta -Md5 $md5 -CustomTitle $newTitle -LockTitle
        Save-AppStateDirty
        Update-ConversationListUi

        if ($script:CurrentChatMD5 -eq $md5) {
            if ($script:ChatForm -and -not $script:ChatForm.IsDisposed) {
                $script:ChatForm.Text = "대화 - $newTitle"
            }
            if ($script:ChatTitleLabel -and -not $script:ChatTitleLabel.IsDisposed) {
                $script:ChatTitleLabel.Text = "  $newTitle"
            }
        }
        Set-StatusSafe "제목 변경: $newTitle"
        Write-AppLog -Level INFO -Message "제목 변경 md5=$md5 title=$newTitle"
    }
    catch {
        Write-AppLog -Level ERROR -Message "제목 변경 실패: $($_.Exception.Message)" -Exception $_.Exception
        try {
            Show-ErrorMessage -Text "제목 변경 실패:`n$($_.Exception.Message)"
        } catch { }
    }
}

function Show-ChatParticipants {
    # 현재 대화 참여자 목록 MessageBox
    if (-not $script:CurrentChatMD5) {
        Show-InfoMessage -Text '대화가 없습니다.'
        return
    }
    $conv = Get-ConversationByMd5 -Md5 $script:CurrentChatMD5
    if (-not $conv) {
        Show-InfoMessage -Text '대화 정보를 찾을 수 없습니다.'
        return
    }

    $ids = @($conv.participantIds)
    $names = @($conv.participantNames)
    $lines = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt @($ids).Count; $i++) {
        $id = [string]$ids[$i]
        $nm = if ($i -lt @($names).Count -and $names[$i]) { [string]$names[$i] } else {
            $u = Get-UserById -Id $id
            if ($u) { [string]$u.name } else { $id }
        }
        $mark = if ($id -eq $script:CurrentUserId) { ' (나)' } else { '' }
        [void]$lines.Add(('- {0} ({1}){2}' -f $nm, $id, $mark))
    }
    if ($lines.Count -eq 0) {
        [void]$lines.Add('(참여자 정보 없음)')
    }
    $text = "참여자 $($lines.Count)명`r`n`r`n" + ($lines -join "`r`n")
    [System.Windows.Forms.MessageBox]::Show(
        $text,
        '참여자 목록',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
}

function Set-ConversationRead {
    # 특정 대화 unread 해제
    param(
        [Parameter(Mandatory = $true)]
        [string]$Md5
    )
    Update-ConversationMeta -Md5 $Md5 -ClearUnread
}


# ---- users.json ---------------------------------------------------------------

function Get-Users {
    Ensure-AppStateReady
    $list = New-Object System.Collections.ArrayList
    foreach ($k in @($script:UserById.Keys)) {
        [void]$list.Add($script:UserById[$k])
    }
    return @($list.ToArray())
}


function Get-UserById {
    param([Parameter(Mandatory = $true)][string]$Id)
    Ensure-AppStateReady
    if ([string]::IsNullOrWhiteSpace($Id)) { return $null }
    if ($script:UserById.ContainsKey($Id)) { return $script:UserById[$Id] }
    return $null
}


# ---- 채팅 메시지 파일 (JSONL) ---------------------------------------------------

function Get-ChatMessageIdCacheKey {
    param(
        [Parameter(Mandatory = $true)][string]$Md5,
        [Parameter(Mandatory = $true)][string]$YearMonth
    )
    return ('{0}|{1}' -f $Md5, $YearMonth)
}

function Clear-ChatMessageIdIndex {
    # 메시지 ID 중복 체크용 인덱스 초기화
    param(
        [string]$Md5,
        [string]$YearMonth
    )
    if ($null -eq $script:ChatMsgIdIndex) {
        $script:ChatMsgIdIndex = @{}
        return
    }
    if ($Md5 -and $YearMonth) {
        $key = Get-ChatMessageIdCacheKey -Md5 $Md5 -YearMonth $YearMonth
        if ($script:ChatMsgIdIndex.ContainsKey($key)) {
            $script:ChatMsgIdIndex.Remove($key)
        }
        return
    }
    $script:ChatMsgIdIndex = @{}
}

function ConvertTo-ChatMessageJsonLine {
    # 메시지 → JSONL 한 줄
    param(
        [Parameter(Mandatory = $true)]$Message
    )
    return (($Message | ConvertTo-Json -Compress -Depth 8))
}

function Read-ChatMessagesJsonl {
    # JSONL → 메시지 배열. 깨진 줄은 skip
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )
    if (-not (Test-Path -LiteralPath $Path)) { return @() }

    $list = New-Object System.Collections.ArrayList
    $reader = $null
    try {
        $reader = New-Object System.IO.StreamReader($Path, [System.Text.Encoding]::UTF8, $true)
        while ($null -ne ($line = $reader.ReadLine())) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try {
                $obj = $line | ConvertFrom-Json
                if ($null -ne $obj) { [void]$list.Add($obj) }
            }
            catch {
                Write-AppLog -Level WARN -Message ("JSONL 줄 파싱 실패: " + $Path)
            }
        }
    }
    catch {
        Write-AppLog -Level ERROR -Message ("JSONL 읽기 실패: " + $Path) -Exception $_.Exception
        return @()
    }
    finally {
        if ($reader) { $reader.Dispose() }
    }
    return @($list.ToArray())
}

function Write-ChatMessagesJsonl {
    # 메시지 배열 전체 → JSONL (.tmp → rename)
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$Messages
    )

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $tmp = $Path + '.tmp'
    $utf8 = New-Object System.Text.UTF8Encoding $false
    $writer = $null
    try {
        $writer = New-Object System.IO.StreamWriter($tmp, $false, $utf8)
        foreach ($m in @($Messages)) {
            if ($null -eq $m) { continue }
            $line = ConvertTo-ChatMessageJsonLine -Message $m
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                $writer.WriteLine($line)
            }
        }
        $writer.Flush()
        $writer.Dispose()
        $writer = $null

        if (Test-Path -LiteralPath $Path) {
            $bak = $Path + '.bak'
            try {
                if (Test-Path -LiteralPath $bak) { Remove-Item -LiteralPath $bak -Force -ErrorAction SilentlyContinue }
                Move-Item -LiteralPath $Path -Destination $bak -Force
            } catch { }
        }
        Move-Item -LiteralPath $tmp -Destination $Path -Force
    }
    catch {
        if ($writer) { try { $writer.Dispose() } catch { } }
        if (Test-Path -LiteralPath $tmp) {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
        Write-AppLog -Level ERROR -Message ("JSONL 저장 실패: " + $Path) -Exception $_.Exception
        throw
    }
}

function Append-ChatMessageJsonl {
    # JSONL 파일 끝에 메시지 1건 append
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Message
    )

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $line = ConvertTo-ChatMessageJsonLine -Message $Message
    $utf8 = New-Object System.Text.UTF8Encoding $false
    $writer = $null
    try {
        $writer = New-Object System.IO.StreamWriter($Path, $true, $utf8)
        $writer.WriteLine($line)
        $writer.Flush()
    }
    finally {
        if ($writer) { $writer.Dispose() }
    }
}

function Import-LegacyChatMessages {
    # 구형 { messages: [] } JSON → 메시지 배열
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )
    if (-not (Test-Path -LiteralPath $Path)) { return @() }

    $data = Import-JsonSafely -Path $Path -DefaultValue @{ messages = @() }
    if ($null -eq $data) { return @() }

    if ($data -is [System.Array]) { return @($data) }

    try {
        $names = @($data.PSObject.Properties.Name)
        if ($names -contains 'messages') {
            $msgs = $data.messages
            if ($null -eq $msgs) { return @() }
            if ($msgs -isnot [System.Array]) { return @($msgs) }
            return @($msgs)
        }
    } catch { }

    return @()
}

function Convert-LegacyChatFileIfNeeded {
    # 구형 .json → .jsonl 마이그레이션
    param(
        [Parameter(Mandatory = $true)][string]$Md5,
        [Parameter(Mandatory = $true)][string]$YearMonth
    )

    $jsonl = Get-ChatFilePath -Md5 $Md5 -YearMonth $YearMonth
    $legacy = Get-ChatLegacyFilePath -Md5 $Md5 -YearMonth $YearMonth

    if (Test-Path -LiteralPath $jsonl) { return }
    if (-not (Test-Path -LiteralPath $legacy)) { return }

    try {
        $msgs = @(Import-LegacyChatMessages -Path $legacy)
        Write-ChatMessagesJsonl -Path $jsonl -Messages $msgs
        $bak = $legacy + '.bak'
        try {
            if (Test-Path -LiteralPath $bak) { Remove-Item -LiteralPath $bak -Force -ErrorAction SilentlyContinue }
            Move-Item -LiteralPath $legacy -Destination $bak -Force
        } catch {
            # 이동 실패해도 jsonl이 있으면 동작 가능
        }
        Write-AppLog -Level INFO -Message ("채팅 파일 마이그레이션: " + $legacy + " -> " + $jsonl + " (" + $msgs.Count + "건)")
        Clear-ChatMessageIdIndex -Md5 $Md5 -YearMonth $YearMonth
    }
    catch {
        Write-AppLog -Level ERROR -Message ("채팅 마이그레이션 실패: " + $legacy) -Exception $_.Exception
    }
}

function Get-ChatMessageIdIndex {
    # md5+월별 메시지 ID 중복 체크용 HashSet. 없으면 디스크에서 빌드
    param(
        [Parameter(Mandatory = $true)][string]$Md5,
        [Parameter(Mandatory = $true)][string]$YearMonth
    )

    if ($null -eq $script:ChatMsgIdIndex) { $script:ChatMsgIdIndex = @{} }
    $cacheKey = Get-ChatMessageIdCacheKey -Md5 $Md5 -YearMonth $YearMonth
    if ($script:ChatMsgIdIndex.ContainsKey($cacheKey)) {
        return $script:ChatMsgIdIndex[$cacheKey]
    }

    Convert-LegacyChatFileIfNeeded -Md5 $Md5 -YearMonth $YearMonth

    $set = @{}
    $filePath = Get-ChatFilePath -Md5 $Md5 -YearMonth $YearMonth
    if (Test-Path -LiteralPath $filePath) {
        foreach ($m in @(Read-ChatMessagesJsonl -Path $filePath)) {
            if ($null -eq $m) { continue }
            $id = $null
            try { $id = [string]$m.aa } catch { $id = $null }
            if (-not [string]::IsNullOrWhiteSpace($id)) {
                $set[$id.ToUpperInvariant()] = $true
            }
        }
    }

    $script:ChatMsgIdIndex[$cacheKey] = $set
    return $set
}

function Get-MessagePreviewText {
    # 대화 목록용 미리보기 텍스트 (제목 또는 본문 앞 40자)
    param(
        [Parameter(Mandatory = $true)]$Message,
        [int]$MaxLen = 40
    )
    $body = ''
    try {
        if ($Message.ah) {
            $body = ConvertFrom-HtmlToPlainText -Html ([string]$Message.ah)
        }
    } catch { $body = '' }
    $body = ($body -replace '\s+', ' ').Trim()
    $title = ''
    try {
        if ($Message.ad) { $title = ([string]$Message.ad).Trim() }
    } catch { }

    $preview = $body
    if ([string]::IsNullOrWhiteSpace($preview)) {
        $preview = $title
    }
    elseif ($title -and $title.Length -ge 10 -and $body.StartsWith($title) -eq $false -and $title -ne $body) {
        # 제목이 본문 첫 10자와 다르면 제목 먼저 표시
        if ($body.Length -gt 0 -and -not $body.StartsWith($title)) {
            $preview = $title
            if ($body) { $preview = $title + ' · ' + $body }
        }
    }

    if ([string]::IsNullOrWhiteSpace($preview)) {
        $preview = '(내용 없음)'
    }
    if ($preview.Length -gt $MaxLen) {
        $preview = $preview.Substring(0, $MaxLen) + '...'
    }
    return $preview
}

function Get-RecentChatMessages {
    # 최신 월부터 읽어 최근 $Take건만 반환 (전체 로드 방지)
    param(
        [Parameter(Mandatory = $true)]
        [string]$Md5,

        [Parameter(Mandatory = $false)]
        [int]$Take = 50
    )

    if ($Take -lt 1) { $Take = 50 }

    $months = @(Get-AvailableChatMonths -Md5 $Md5)
    if ($months.Count -eq 0) {
        $months = @((Get-Date -Format 'yyyyMM'))
    }

    # 최신 월부터 청크를 모아서 시간순 flat 후 tail
    $chunks = New-Object System.Collections.ArrayList
    $total = 0
    foreach ($ym in $months) {
        $msgs = @(Get-ChatMessages -Md5 $Md5 -YearMonth $ym)
        if ($msgs.Count -eq 0) { continue }
        $sorted = @($msgs | Sort-Object {
            if ($_.ae) { try { [datetime]$_.ae } catch { [datetime]::MinValue } } else { [datetime]::MinValue }
        })
        [void]$chunks.Add([System.Object]$sorted)
        $total += $sorted.Count
        if ($total -ge $Take) { break }
    }

    if ($chunks.Count -eq 0) { return @() }

    $flat = New-Object System.Collections.ArrayList
    for ($i = $chunks.Count - 1; $i -ge 0; $i--) {
        foreach ($m in @($chunks[$i])) {
            if ($null -ne $m) { [void]$flat.Add($m) }
        }
    }

    $n = $flat.Count
    if ($n -le 0) { return @() }
    if ($n -le $Take) { return @($flat.ToArray()) }
    $start = $n - $Take
    return @($flat.ToArray()[$start..($n - 1)])
}

function Get-ChatMessages {
    # 특정 md5 + 월의 JSONL 메시지 배열
    param(
        [Parameter(Mandatory = $true)]
        [string]$Md5,

        [Parameter(Mandatory = $false)]
        [string]$YearMonth = (Get-Date -Format 'yyyyMM')
    )

    Convert-LegacyChatFileIfNeeded -Md5 $Md5 -YearMonth $YearMonth
    $path = Get-ChatFilePath -Md5 $Md5 -YearMonth $YearMonth
    if (-not (Test-Path -LiteralPath $path)) {
        return @()
    }
    return @(Read-ChatMessagesJsonl -Path $path)
}


function Add-ChatMessage {
    # 월별 JSONL에 append. 동일 note_id(aa)는 무시
    param(
        [Parameter(Mandatory = $true)]
        [string]$Md5,

        [Parameter(Mandatory = $true)]
        $Message,

        [Parameter(Mandatory = $false)]
        [string]$YearMonth = (Get-Date -Format 'yyyyMM')
    )

    $msgId = $null
    try { $msgId = [string]$Message.aa } catch { $msgId = $null }

    $idSet = Get-ChatMessageIdIndex -Md5 $Md5 -YearMonth $YearMonth
    if ($null -eq $idSet) { $idSet = @{} }
    $idKey = if (-not [string]::IsNullOrWhiteSpace($msgId)) { $msgId.ToUpperInvariant() } else { $null }
    if ($idKey -and $idSet.ContainsKey($idKey)) {
        return $false
    }

    $path = Get-ChatFilePath -Md5 $Md5 -YearMonth $YearMonth
    try {
        Append-ChatMessageJsonl -Path $path -Message $Message
    }
    catch {
        Write-AppLog -Level ERROR -Message "메시지 append 실패 md5=$Md5 ym=$YearMonth" -Exception $_.Exception
        return $false
    }

    if ($idKey) {
        $idSet[$idKey] = $true
    }
    return $true
}

function Get-AvailableChatMonths {
    # 특정 md5의 월 파일 목록 (최신순)
    param(
        [Parameter(Mandatory = $true)]
        [string]$Md5
    )

    if (-not $script:ChatsDirectory -or -not (Test-Path -LiteralPath $script:ChatsDirectory)) {
        return @()
    }

    $months = New-Object System.Collections.Generic.HashSet[string]
    $rx = '^{0}_(\d{{6}})\.(jsonl|json)$' -f [regex]::Escape($Md5)
    $files = Get-ChildItem -LiteralPath $script:ChatsDirectory -File -ErrorAction SilentlyContinue
    foreach ($f in @($files)) {
        if ($f.Name -match $rx) {
            [void]$months.Add($Matches[1])
        }
    }

    if ($months.Count -eq 0) { return @() }
    return @($months | Sort-Object -Descending)
}



# ---- HTML ↔ PlainText 변환 ---------------------------------------------------

function ConvertTo-HtmlLineBreaks {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $parts = $Text -split "`r?`n"
    return (($parts | ForEach-Object {
        $e = $_ -replace '&', '&' -replace '<', '<' -replace '>', '>'
        '<div>' + $e + '</div>'
    }) -join '')
}

function ConvertFrom-HtmlToPlainText {
    param([string]$Html)
    if ([string]::IsNullOrEmpty($Html)) { return '' }
    $text = $Html
    $text = [regex]::Replace($text, '(?i)<br\s*/?>', "`n")
    $text = [regex]::Replace($text, '(?i)</div\s*>', "`n")
    $text = [regex]::Replace($text, '(?i)</p\s*>', "`n")
    $text = [regex]::Replace($text, '<[^>]+>', '')
    $text = $text.Replace('&nbsp;', ' ').Replace('<', '<').Replace('>', '>').Replace('&', '&')
    return $text.Trim()
}




# ---- ApiClient ---------------------------------------------------------------

# 2008 R2도 TLS 1.2 강제
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
catch { }

function Initialize-ApiUrls {
    # ApiBase + Path* → 절대 URL
    if ([string]::IsNullOrWhiteSpace($script:ApiBase)) {
        $script:LoginUrl = $null
        $script:GetUserListUrl = $null
        $script:GetMessageListUrl = $null
        $script:SendMessageUrl = $null
        return
    }
    $base = $script:ApiBase.TrimEnd('/')
    $script:LoginUrl          = $base + $script:PathLogin
    $script:GetUserListUrl    = $base + $script:PathUserList
    $script:GetMessageListUrl = $base + $script:PathMessageList
    $script:SendMessageUrl    = $base + $script:PathSendMessage
}


function Set-ApiReloginCallback {
    # 401 응답 시 호출할 재로그인 콜백
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Callback
    )
    $script:ReloginCallback = $Callback
}


function Get-HttpResponseText {
    # Invoke-WebRequest 응답 본문 UTF-8 디코딩 (CP949 깨짐 방지)
    param($Response)
    try {
        if ($Response.RawContentStream -and $Response.RawContentStream.CanSeek) {
            $null = $Response.RawContentStream.Seek(0, 'Begin')
            $reader = New-Object System.IO.StreamReader($Response.RawContentStream, [System.Text.Encoding]::UTF8, $true)
            $text = $reader.ReadToEnd()
            $reader.Dispose()
            if (-not [string]::IsNullOrEmpty($text)) { return $text }
        }
    } catch { }

    $content = $Response.Content
    if ([string]::IsNullOrEmpty($content)) { return $content }

    # CP949로 잘못 디코딩된 Content → 바이트 → UTF-8 재해석
    try {
        $bytes = [System.Text.Encoding]::Default.GetBytes($content)
        $utf8 = [System.Text.Encoding]::UTF8.GetString($bytes)
        if ($utf8.Length -gt 0 -and ($utf8.ToCharArray() | Where-Object { [int][char]$_ -ge 0xAC00 -and [int][char]$_ -le 0xD7A3 } | Measure-Object).Count -ge 0) {
            if ($utf8.Contains('{') -or $utf8.Contains('[') -or $utf8 -match '[\uAC00-\uD7A3]') {
                return $utf8
            }
        }
    } catch { }

    return $content
}

function Invoke-ApiRequest {
    # API 공통 호출. 재시도 + 401 재로그인 내장
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [ValidateSet('GET', 'POST', 'PUT', 'DELETE')]
        [string]$Method = 'GET',
        $Body = $null,
        [hashtable]$Headers = @{},
        [switch]$SkipAuth,
        [string]$ContentType = 'application/x-www-form-urlencoded; charset=utf-8',
        [ValidateSet('Form', 'Json', 'None')]
        [string]$BodyFormat = 'Form',
        [switch]$RawResponse
    )

    if ([string]::IsNullOrWhiteSpace($Uri)) {
        throw "API URI 가 비어 있습니다. 상단 ApiBase/Path 설정을 확인하세요."
    }

    $attempt = 0
    $lastError = $null
    $reloginTried = $false

    while ($attempt -lt $script:MaxRetry) {
        $attempt++
        try {
            $swApi = [System.Diagnostics.Stopwatch]::StartNew()
            $reqHeaders = @{}
            foreach ($k in $Headers.Keys) { $reqHeaders[$k] = $Headers[$k] }
            # ORCA jqGrid는 AJAX 헤더 없으면 403 뱉음
            if (-not $reqHeaders.ContainsKey('X-Requested-With')) {
                $reqHeaders['X-Requested-With'] = 'XMLHttpRequest'
            }

            $params = @{
                Uri             = $Uri
                Method          = $Method
                Headers         = $reqHeaders
                TimeoutSec      = $script:RequestTimeoutSec
                UseBasicParsing = $true
                ErrorAction     = 'Stop'
            }

            if ($null -ne $Body -and $BodyFormat -ne 'None') {
                if ($BodyFormat -eq 'Json') {
                    if ($Body -is [string]) { $params['Body'] = $Body }
                    else { $params['Body'] = ($Body | ConvertTo-Json -Depth 10 -Compress) }
                    $params['ContentType'] = 'application/json; charset=utf-8'
                }
                else {
                    $params['Body'] = $Body
                    $params['ContentType'] = $ContentType
                }
            }

            Write-AppLog -Level DEBUG -Message "API $Method $Uri (try=$attempt, hasSession=$([bool]$script:HttpSession))"

            # SessionVariable 대신 WebSession 객체 사용 (충돌 방지)
            if (-not $script:HttpSession) {
                $script:HttpSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
            }
            $params['WebSession'] = $script:HttpSession
            $response = Invoke-WebRequest @params
            if ($swApi) { $swApi.Stop(); $script:ApiLastLatencyMs = [int]$swApi.ElapsedMilliseconds }
            $script:ApiCallCount = [int]$script:ApiCallCount + 1
            $script:ApiLastError = ''

            if ($RawResponse) { return $response }

            $content = Get-HttpResponseText -Response $response
            if ([string]::IsNullOrWhiteSpace($content)) { return $null }

            # 로그인은 HTML 응답이 정상. 그 외 API에서 HTML 오면 세션 만료
            $trim = $content.TrimStart()
            $looksHtml = ($trim.StartsWith('<') -or $trim -match '(?i)<!DOCTYPE|<html')
            if ($looksHtml) {
                if ($SkipAuth) {
                    Write-AppLog -Level INFO -Message "로그인 응답 HTML 수신 (정상 가능)"
                    return $content
                }
                $preview = $content.Substring(0, [Math]::Min(180, $content.Length)) -replace '\s+', ' '
                Write-AppLog -Level ERROR -Message "API HTML 응답(세션 의심): $Uri | $preview"
                throw "API가 HTML을 반환했습니다(세션 없음 가능). URI=$Uri"
            }

            try {
                return ($content | ConvertFrom-Json)
            }
            catch {
                if ($SkipAuth) { return $content }
                $preview = $content.Substring(0, [Math]::Min(180, $content.Length)) -replace '\s+', ' '
                Write-AppLog -Level ERROR -Message "JSON 파싱 실패 URI=$Uri | $preview"
                throw "JSON 파싱 실패: $($_.Exception.Message)"
            }
        }
        catch {
            try {
                if ($swApi) { $swApi.Stop(); $script:ApiLastLatencyMs = [int]$swApi.ElapsedMilliseconds }
            } catch { }
            $script:ApiFailCount = [int]$script:ApiFailCount + 1
            try { $script:ApiLastError = $_.Exception.Message } catch { $script:ApiLastError = 'error' }
            $lastError = $_
            $statusCode = $null
            try {
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }
            } catch { }

            Write-AppLog -Level ERROR -Message "API 실패 $Method $Uri status=$statusCode try=$attempt : $($_.Exception.Message)"

            if ($statusCode -eq 401 -and -not $SkipAuth -and -not $reloginTried) {
                $reloginTried = $true
                $ok = $false
                if ($script:ReloginCallback) {
                    try { $ok = [bool](& $script:ReloginCallback) } catch { $ok = $false }
                }
                if ($ok) { $attempt--; continue }
                throw "인증 실패(401). 재로그인 실패."
            }

            $retryable = $false
            if ($statusCode -ge 500 -and $statusCode -lt 600) { $retryable = $true }
            if ($_.Exception.Message -match 'timeout|timed out|연결|connection|network') { $retryable = $true }
            if (-not $statusCode -and $attempt -lt $script:MaxRetry) { $retryable = $true }

            if ($retryable -and $attempt -lt $script:MaxRetry) {
                Start-Sleep -Milliseconds ($script:RetryDelayMs * $attempt)
                continue
            }
            throw
        }
    }
}


# ---- 도메인 API ---------------------------------------------------------------

function Invoke-ApiLogin {
    # ORCA form POST 로그인. 세션 쿠키 컨테이너 생성
    param(
        [Parameter(Mandatory = $true)][string]$UserId,
        [Parameter(Mandatory = $true)][string]$Password
    )

    $script:HttpSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession

    $body = @{}
    $body['user_id']   = $UserId
    $body['pwd'] = $Password

    $result = Invoke-ApiRequest -Uri $script:LoginUrl -Method POST -Body $body -BodyFormat Form -SkipAuth

    # ORCA 로그인은 HTML + 쿠키. 예외 안 났으면 성공
    if (-not $script:HttpSession) {
        $script:HttpSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    }
    Set-AuthToken -Token 'SESSION'
    Write-AppLog -Level INFO -Message "로그인 성공(세션): $UserId"
    return $result
}

function Get-ApiRows {
    # jqGrid 응답에서 rows 배열 추출. 항상 Object[] 반환
    param($Result)
    if ($null -eq $Result) { return , @() }
    if ($Result -is [System.Array]) { return , @($Result) }
    $rows = Get-ObjectProperty -Object $Result -Name 'rows'
    if ($null -eq $rows) { return , @() }
    $arr = @($rows)
    if ($arr.Count -eq 1 -and $null -eq $arr[0]) { return , @() }
    return , $arr
}

function Get-ApiUserList {
    # 사용자 목록 조회
    Write-AppLog -Level INFO -Message "사용자목록 URI=$($script:GetUserListUrl)"
    $result = Invoke-ApiRequest -Uri $script:GetUserListUrl -Method GET -BodyFormat None
    $rows = Get-ApiRows -Result $result
    Write-AppLog -Level INFO -Message "사용자목록 rows=$($rows.Count)"
    return $rows
}

function Get-ApiMessageList {
    # 쪽지 목록 조회. start_ymd 빈값=전체, yyyyMMdd=증분
    param(
        [Parameter(Mandatory = $false)]
        [string]$StartYmd = ''
    )

    $ymd = if ($null -eq $StartYmd) { '' } else { $StartYmd }
    $base = $script:ApiBase.TrimEnd('/')
    $uri = $base + '/note/retrieveNoteListJson.do?start_ymd=' + [Uri]::EscapeDataString($ymd) + '&nd=&rows=9999&page=1'

    Write-AppLog -Level DEBUG -Message "쪽지목록 URI=$uri"
    $result = Invoke-ApiRequest -Uri $uri -Method GET -BodyFormat None
    $rows = Get-ApiRows -Result $result
    Write-AppLog -Level DEBUG -Message ("쪽지목록 rows=" + @($rows).Count)
    return $rows
}

function Send-ApiMessage {
    # 쪽지 전송. note_id 안 내려줌 → 폴링에서 확인
    param(
        [Parameter(Mandatory = $true)][string[]]$ReceiverIds,
        [Parameter(Mandatory = $false)][string[]]$ReceiverNames = @(),
        [Parameter(Mandatory = $true)][string]$BodyText
    )

    $ids = @($ReceiverIds | Where-Object { $_ })
    if ($ids.Count -eq 0) { throw '수신자가 없습니다.' }

    $nameList = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt @($ids).Count; $i++) {
        if ($i -lt @($ReceiverNames).Count -and $ReceiverNames[$i]) {
            [void]$nameList.Add([string]$ReceiverNames[$i])
        }
        else {
            $u = Get-UserById -Id $ids[$i]
            [void]$nameList.Add($(if ($u) { [string]$u.name } else { [string]$ids[$i] }))
        }
    }
    $names = @($nameList.ToArray())

    $receiverDisp = if ($names.Count -le 1) {
        if ($names.Count -eq 1) { $names[0] } else { '' }
    }
    else {
        '{0} 외 {1}명' -f $names[0], ($names.Count - 1)
    }

    $plain = $BodyText.Trim()
    $subject = if ($plain.Length -gt 10) { $plain.Substring(0, 10) } else { $plain }

    $html = ConvertTo-HtmlLineBreaks -Text $BodyText
    if (-not $html) { $html = '<div></div>' }

    $body = @{}
    $body['orca_ajax_yn']   = 'Y'
    $body['subject']  = $subject
    $body['receiver'] = $receiverDisp
    $body['receiver_list'] = ($ids -join ',')
    $body['receiver_cnt']  = $ids.Count
    $body['contents'] = $html
    # ORCA form 전송 시 빈 files[] 필드 필요
    $body['files[]'] = ''

    $result = Invoke-ApiRequest -Uri $script:SendMessageUrl -Method POST -Body $body -BodyFormat Form

    $code = Get-ObjectProperty -Object $result -Name 'rsltcode'
    if ($code -and ([string]$code -ne 'success')) {
        throw "전송 실패 rsltcode=$code"
    }

    Write-AppLog -Level INFO -Message "메시지 전송 완료 receivers=$($ids -join ',')"
    return $result
}


# ---- 메시지 정규화 (스키마 aa~ai) ---------------------------------------------

function Get-ObjectProperty {
    # StrictMode 안전 속성 읽기
    param(
        $Object,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        $Default = $null
    )
    if ($null -eq $Object) { return $Default }
    if ($Object -is [hashtable]) {
        if ($Object.ContainsKey($Name)) { return $Object[$Name] }
        return $Default
    }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -ne $prop) { return $prop.Value }
    return $Default
}

function ConvertTo-NormalizedMessage {
    # ORCA 쪽지 row → 내부 aa~ai 스키마
    param(
        [Parameter(Mandatory = $true)]$Raw,
        [Parameter(Mandatory = $true)][string]$CurrentUserId
    )

    $aa = [string](Get-ObjectProperty -Object $Raw -Name 'note_id' -Default '')
    $ab = [string](Get-ObjectProperty -Object $Raw -Name 'rgst_user_id' -Default '')
    $ac = [string](Get-ObjectProperty -Object $Raw -Name 'rgst_user_nm' -Default '')
    $aeRaw = Get-ObjectProperty -Object $Raw -Name 'rgst_dtm'
    $ad = [string](Get-ObjectProperty -Object $Raw -Name 'subject' -Default '')
    $ah = [string](Get-ObjectProperty -Object $Raw -Name 'contents' -Default '')
    $receiverLabel = [string](Get-ObjectProperty -Object $Raw -Name 'receiver' -Default '')
    $recvIdsRaw = Get-ObjectProperty -Object $Raw -Name 'r_id_list'
    $recvNmsRaw = Get-ObjectProperty -Object $Raw -Name 'r_nm_list'

    $afArr = @()
    if ($recvIdsRaw -is [System.Array]) {
        $afArr = @($recvIdsRaw | ForEach-Object { [string]$_ })
    }
    elseif ($recvIdsRaw) {
        $afArr = @(([string]$recvIdsRaw) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }

    $agArr = @()
    if ($recvNmsRaw -is [System.Array]) {
        $agArr = @($recvNmsRaw | ForEach-Object { [string]$_ })
    }
    elseif ($recvNmsRaw) {
        $agArr = @(([string]$recvNmsRaw) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }

    $isOwn = $false
    if ($ab -and $CurrentUserId -and ($ab -eq $CurrentUserId)) {
        $isOwn = $true
    }

    $aeStr = ''
    if ($aeRaw) {
        try { $aeStr = ([datetime]$aeRaw).ToString('o') }
        catch { $aeStr = [string]$aeRaw }
    }
    else {
        $aeStr = (Get-Date).ToString('o')
    }

    # subject가 본문 앞 10자와 같으면 제목 필드 비움
    $plain = ConvertFrom-HtmlToPlainText -Html $ah
    $plainOneLine = ($plain -replace '\s+', ' ').Trim()
    $titleUse = $ad
    if ($ad -and $ad.Length -eq 10) {
        $head = if ($plainOneLine.Length -ge 10) { $plainOneLine.Substring(0, 10) } else { $plainOneLine }
        if ($ad -eq $head) { $titleUse = '' }
    }

    $convTitle = Get-ConversationListTitle -ReceiverLabel $receiverLabel -SenderName $ac

    return [PSCustomObject]@{
        aa           = $aa
        ab           = $ab
        ac           = $ac
        ad           = $titleUse
        ae           = $aeStr
        af           = $afArr
        ag           = $agArr
        ah           = $ah
        ai           = ''
        isOwn        = $isOwn
        receiverLabel= $receiverLabel
        convTitle    = $convTitle
    }
}

function Get-ConversationListTitle {
    # 대화목록 표시명. receiver가 '나'/'나 외 N명'이면 보낸 사람 이름
    param(
        [string]$ReceiverLabel,
        [string]$SenderName
    )
    $recv = if ($ReceiverLabel) { $ReceiverLabel.Trim() } else { '' }
    $my = if ($script:CurrentUserName) { [string]$script:CurrentUserName.Trim() } else { '' }

    if (-not $recv) {
        if ($SenderName) { return [string]$SenderName }
        return ''
    }

    $isMeSide = $false
    if ($recv -eq '나') { $isMeSide = $true }
    if ($my -and ($recv -eq $my)) { $isMeSide = $true }
    if ($recv -match '^나\s*외\s*\d+\s*명$') { $isMeSide = $true }
    if ($my -and ($recv -match ('^{0}\s*외\s*\d+\s*명$' -f [regex]::Escape($my)))) {
        $isMeSide = $true
    }

    if ($isMeSide) {
        if ($SenderName) { return [string]$SenderName }
        return $recv
    }
    return $recv
}

function Resolve-MessageConversationKey {
    # 송신자 + 수신자 집합 → MD5 대화 키
    param(
        [Parameter(Mandatory = $true)]$Message,
        [Parameter(Mandatory = $true)][string]$CurrentUserId
    )

    $idList = New-Object System.Collections.ArrayList
    if ($Message.ab) {
        $s = [string]$Message.ab
        if ($s -and -not $idList.Contains($s)) { [void]$idList.Add($s) }
    }
    foreach ($r in @($Message.af)) {
        if (-not $r) { continue }
        $s = [string]$r
        if ($s -and -not $idList.Contains($s)) { [void]$idList.Add($s) }
    }

    if ($idList.Count -eq 0 -and $CurrentUserId) {
        [void]$idList.Add([string]$CurrentUserId)
    }

    return (Get-ConversationMD5 -ParticipantIds @($idList.ToArray()))
}



# ---- UiHelper ----------------------------------------------------------------

# ---- ListView ----------------------------------------------------------------

function Initialize-ConversationListView {
    # 대화 목록 ListView 컬럼 설정
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.ListView]$ListView
    )

    $ListView.View = [System.Windows.Forms.View]::Details
    $ListView.FullRowSelect = $true
    $ListView.MultiSelect = $false
    $ListView.HideSelection = $false
    $ListView.GridLines = $true
    $ListView.Columns.Clear()
    [void]$ListView.Columns.Add('대화', 140)
    [void]$ListView.Columns.Add('미리보기', 150)
    [void]$ListView.Columns.Add('시간', 120)
    [void]$ListView.Columns.Add('미확인', 55)
}


function Set-ConversationListViewRow {
    param(
        [System.Windows.Forms.ListViewItem]$Item,
        $Conv,
        [string]$Uid
    )
    $title = Get-ConversationDisplayTitle -Conversation $Conv -CurrentUserId $Uid
    $preview = [string](Get-ConvProp $Conv 'lastPreview' '')
    $timeStr = ''
    if ($Conv.lastMessageTime) {
        $timeStr = Format-MessageDateTime -Value $Conv.lastMessageTime
    }
    $uc = 0
    try { $uc = [int](Get-ConvProp $Conv 'unreadCount' 0) } catch { $uc = 0 }
    if ($uc -lt 0) { $uc = 0 }
    if ($uc -eq 0 -and $Conv.unread) { $uc = 1 }
    $unreadStr = if ($uc -gt 0) { [string]$uc } else { '' }

    $Item.Text = $title
    while ($Item.SubItems.Count -lt 4) {
        [void]$Item.SubItems.Add('')
    }
    $Item.SubItems[1].Text = $preview
    $Item.SubItems[2].Text = $timeStr
    $Item.SubItems[3].Text = $unreadStr
    $Item.Tag = [string]$Conv.md5
    if ($uc -gt 0) {
        $Item.ForeColor = [System.Drawing.Color]::FromArgb(20, 80, 160)
    }
    else {
        $Item.ForeColor = [System.Drawing.SystemColors]::WindowText
    }
}


function Update-ConversationListView {
    # 대화 목록 ListView 갱신. 순서 같으면 행 내용만 업데이트
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.ListView]$ListView,

        [AllowEmptyCollection()]
        [AllowNull()]
        [array]$Conversations = @(),

        [Parameter(Mandatory = $false)]
        [string]$CurrentUserId = ''
    )

    if ($null -eq $Conversations) { $Conversations = @() }

    $selectedMd5 = $null
    if ($ListView.SelectedItems.Count -gt 0) {
        $selectedMd5 = [string]$ListView.SelectedItems[0].Tag
    }

    if ($ListView.Columns.Count -lt 4) {
        Initialize-ConversationListView -ListView $ListView
    }

    $newOrder = New-Object System.Collections.ArrayList
    foreach ($c in @($Conversations)) {
        if ($null -eq $c) { continue }
        try { [void]$newOrder.Add([string]$c.md5) } catch { }
    }

    $sameOrder = ($ListView.Items.Count -eq $newOrder.Count)
    if ($sameOrder) {
        for ($i = 0; $i -lt $newOrder.Count; $i++) {
            $tag = [string]$ListView.Items[$i].Tag
            if ($tag -ne [string]$newOrder[$i]) {
                $sameOrder = $false
                break
            }
        }
    }

    $ListView.BeginUpdate()
    try {
        if ($sameOrder -and $newOrder.Count -gt 0) {
            $idx = 0
            foreach ($c in @($Conversations)) {
                if ($null -eq $c) { continue }
                Set-ConversationListViewRow -Item $ListView.Items[$idx] -Conv $c -Uid $CurrentUserId
                $idx++
            }
            if ($selectedMd5) {
                foreach ($it in @($ListView.Items)) {
                    if ([string]$it.Tag -eq $selectedMd5) {
                        $it.Selected = $true
                        break
                    }
                }
            }
        }
        else {
            $ListView.Items.Clear()
            foreach ($c in @($Conversations)) {
                if ($null -eq $c) { continue }
                $item = New-Object System.Windows.Forms.ListViewItem('')
                [void]$item.SubItems.Add('')
                [void]$item.SubItems.Add('')
                [void]$item.SubItems.Add('')
                Set-ConversationListViewRow -Item $item -Conv $c -Uid $CurrentUserId
                [void]$ListView.Items.Add($item)
                if ($selectedMd5 -and $selectedMd5 -eq [string]$c.md5) {
                    $item.Selected = $true
                }
            }
        }
    }
    finally {
        $ListView.EndUpdate()
    }
}

function Get-ConversationDisplayTitle {
    # 대화 표시 제목. customTitle 우선, 없으면 참가자 이름 (본인 제외)
    param(
        $Conversation,
        [string]$CurrentUserId = ''
    )

    if ($Conversation.customTitle) {
        return [string]$Conversation.customTitle
    }

    $names = @()
    if ($Conversation.participantNames) {
        $names = @($Conversation.participantNames | ForEach-Object { [string]$_ })
    }

    if ($CurrentUserId -and $Conversation.participantIds) {
        $ids = @($Conversation.participantIds)
        $filtered = @()
        for ($i = 0; $i -lt $ids.Count; $i++) {
            if ($ids[$i] -ne $CurrentUserId -and $i -lt $names.Count) {
                $filtered += $names[$i]
            }
            elseif ($ids[$i] -ne $CurrentUserId -and $i -ge $names.Count) {
                $filtered += $ids[$i]
            }
        }
        if ($filtered.Count -gt 0) {
            return ($filtered -join ', ')
        }
    }

    if ($names.Count -gt 0) {
        return ($names -join ', ')
    }

    return [string]$Conversation.md5
}

function Initialize-UserListView {
    # 사용자 목록 ListView. 행 선택 시 체크박스 연동
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.ListView]$ListView
    )

    $ListView.View = [System.Windows.Forms.View]::Details
    $ListView.FullRowSelect = $true
    $ListView.MultiSelect = $true
    $ListView.CheckBoxes = $true
    $ListView.HideSelection = $false
    $ListView.GridLines = $true
    $ListView.Columns.Clear()
    [void]$ListView.Columns.Add('이름', 100)
    [void]$ListView.Columns.Add('소속', 100)
    [void]$ListView.Columns.Add('ID', 90)
    [void]$ListView.Columns.Add('롤', 120)

    $ListView.Add_ItemSelectionChanged({
        param($sender, $e)
        try {
            if ($null -eq $e -or $null -eq $e.Item) { return }
            if ($e.IsSelected) {
                $e.Item.Checked = $true
            }
        } catch { }
    })
}

function Update-UserListView {
    # users 배열로 ListView 갱신
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.ListView]$ListView,

        [AllowEmptyCollection()]
        [AllowNull()]
        [array]$Users = @(),

        [Parameter(Mandatory = $false)]
        [string]$ExcludeUserId = ''
    )

    if ($null -eq $Users) { $Users = @() }
    $ListView.BeginUpdate()
    try {
        $ListView.Items.Clear()
        foreach ($u in $Users) {
            if ($ExcludeUserId -and $u.id -eq $ExcludeUserId) { continue }

            $item = New-Object System.Windows.Forms.ListViewItem([string]$u.name)
            [void]$item.SubItems.Add([string]$u.dept)
            [void]$item.SubItems.Add([string]$u.id)
            [void]$item.SubItems.Add([string]$u.type)
            $item.Tag = [string]$u.id
            [void]$ListView.Items.Add($item)
        }
    }
    finally {
        $ListView.EndUpdate()
    }
}

function Get-CheckedUserIds {
    # 체크된 사용자 ID 배열
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.ListView]$ListView
    )

    $ids = @()
    foreach ($item in $ListView.CheckedItems) {
        $ids += [string]$item.Tag
    }
    return $ids
}


# ---- WebBrowser 메시지 표시 ---------------------------------------------------

function Format-MessageDateTime {
    # YYYY-MM-DD HH:mm:ss
    param($Value)
    if (-not $Value) { return '---- -- -- --:--:--' }
    try {
        return ([datetime]$Value).ToString('yyyy-MM-dd HH:mm:ss')
    }
    catch {
        $s = [string]$Value
        if ($s -match '(\d{4})[-\/]?(\d{2})[-\/]?(\d{2}).*?(\d{2}):(\d{2})(?::(\d{2}))?') {
            $sec = if ($Matches[6]) { $Matches[6] } else { '00' }
            return ('{0}-{1}-{2} {3}:{4}:{5}' -f $Matches[1], $Matches[2], $Matches[3], $Matches[4], $Matches[5], $sec)
        }
        return $s
    }
}


function Get-ChatMessagesHtml {
    # 메시지 배열 → WebBrowser 표시용 HTML
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$Messages,

        [string]$Title = '대화'
    )

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html><head><meta charset="utf-8"><meta http-equiv="X-UA-Compatible" content="IE=Edge"><style>')
    [void]$sb.AppendLine('body{font-family:"맑은 고딕","Malgun Gothic",sans-serif;font-size:13px;background:#ECEEF1;color:#1E1E1E;margin:8px;padding-bottom:100px;word-break:break-all;}')
    [void]$sb.AppendLine('.msg{margin:4px 0;padding:6px 10px;border-radius:8px;max-width:85%;}')
    [void]$sb.AppendLine('.msg.own{margin-left:auto;background:#D1E4FF;text-align:right;}')
    [void]$sb.AppendLine('.msg.other{margin-right:auto;background:#FFFFFF;text-align:left;}')
    [void]$sb.AppendLine('.meta{font-size:11px;color:#78828C;margin-bottom:2px;}')
    [void]$sb.AppendLine('.title{font-size:12px;font-weight:bold;color:#3C4650;margin-bottom:2px;}')
    [void]$sb.AppendLine('.body{font-size:13px;line-height:1.5;}')
    [void]$sb.AppendLine('.body.own{color:#145AA0;}')
    [void]$sb.AppendLine('.body.other{color:#1E1E1E;}')
    [void]$sb.AppendLine('</style>')
    [void]$sb.AppendLine('</head><body>')

    if ($Messages.Count -eq 0) {
        [void]$sb.AppendLine('<div style="text-align:center;color:#888;margin-top:40px;">대화가 없습니다</div>')
    }
    else {
        $idx = 0
        foreach ($m in $Messages) {
            if ($null -eq $m) { $idx++; continue }
            $isOwn = [bool]$m.isOwn
            $cssClass = if ($isOwn) { 'own' } else { 'other' }
            $namePart = if ($isOwn) { '나' } else { if ($m.ac) { [string]$m.ac } else { '상대' } }
            $timeStr = Format-MessageDateTime -Value $m.ae
            $body = ConvertFrom-HtmlToPlainText -Html ([string]$m.ah)
            if ([string]::IsNullOrWhiteSpace($body)) { $body = ' ' }
            $body = [System.Security.SecurityElement]::Escape($body) -replace "`n", '<br>'

            $title = ''
            if ($m.ad) { $title = [string]$m.ad.Trim() }
            if ($title) {
                $plainOne = (ConvertFrom-HtmlToPlainText -Html ([string]$m.ah) -replace '\s+', ' ').Trim()
                if ($plainOne.StartsWith($title) -or $title -eq $plainOne) { $title = '' }
            }

            [void]$sb.Append("<div class='msg $cssClass'>")
            [void]$sb.Append("<div class='meta'>$([System.Security.SecurityElement]::Escape($namePart))  ·  $([System.Security.SecurityElement]::Escape($timeStr))</div>")
            if ($title) {
                [void]$sb.Append("<div class='title'>$([System.Security.SecurityElement]::Escape($title))</div>")
            }
            [void]$sb.Append("<div class='body $cssClass'>$body</div>")
            [void]$sb.AppendLine('</div>')
            $idx++
        }
    }

    [void]$sb.AppendLine('<script>window.scrollTo(0,document.body.scrollHeight);</script>')
    [void]$sb.AppendLine('</body></html>')
    return $sb.ToString()
}

function Add-ChatMessageToView {
    # WebBrowser에 메시지 버블 하나 append
    param(
        [Parameter(Mandatory = $true)]
        $WebBrowser,
        [Parameter(Mandatory = $true)]
        $Message,
        [switch]$ScrollToEnd
    )

    try {
        $doc = $WebBrowser.Document
        if ($null -eq $doc -or $null -eq $doc.Body) {
            $WebBrowser.DocumentText = (Get-ChatMessagesHtml -Messages @($Message))
            return
        }

        $isOwn = [bool]$Message.isOwn
        $cssClass = if ($isOwn) { 'own' } else { 'other' }
        $namePart = if ($isOwn) { '나' } else { if ($Message.ac) { [string]$Message.ac } else { '상대' } }
        $timeStr = Format-MessageDateTime -Value $Message.ae
        $body = ConvertFrom-HtmlToPlainText -Html ([string]$Message.ah)
        if ([string]::IsNullOrWhiteSpace($body)) { $body = ' ' }
        $body = [System.Security.SecurityElement]::Escape($body) -replace "`n", '<br>'

        $title = ''
        if ($Message.ad) { $title = [string]$Message.ad.Trim() }
        if ($title) {
            $plainOne = (ConvertFrom-HtmlToPlainText -Html ([string]$Message.ah) -replace '\s+', ' ').Trim()
            if ($plainOne.StartsWith($title) -or $title -eq $plainOne) { $title = '' }
        }

        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append("<div class='msg $cssClass'>")
        [void]$sb.Append("<div class='meta'>$([System.Security.SecurityElement]::Escape($namePart))  ·  $([System.Security.SecurityElement]::Escape($timeStr))</div>")
        if ($title) {
            [void]$sb.Append("<div class='title'>$([System.Security.SecurityElement]::Escape($title))</div>")
        }
        [void]$sb.Append("<div class='body $cssClass'>$body</div>")
        [void]$sb.Append('</div>')

        $div = $doc.CreateElement('div')
        $div.InnerHtml = $sb.ToString()
        [void]$doc.Body.AppendChild($div)

        if ($ScrollToEnd) {
            $doc.Window.ScrollTo(0, $doc.Body.ScrollRectangle.Height)
        }
    }
    catch {
        # Document 없는 초기 상태 → 전체 HTML 재설정
        $WebBrowser.DocumentText = (Get-ChatMessagesHtml -Messages @($script:ChatLoadedMessages + @($Message)))
    }
}

function Show-ChatMessages {
    # 메시지 배열 전체를 WebBrowser에 표시
    param(
        [Parameter(Mandatory = $true)]
        $WebBrowser,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$Messages
    )

    $html = Get-ChatMessagesHtml -Messages $Messages
    $WebBrowser.DocumentText = $html
}


# ---- MessageBox 유틸 ----------------------------------------------------------

function Show-InfoMessage {
    param([string]$Text, [string]$Title = '알림')
    [System.Windows.Forms.MessageBox]::Show(
        $Text, $Title,
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
}

function Show-ErrorMessage {
    param([string]$Text, [string]$Title = '오류')
    [System.Windows.Forms.MessageBox]::Show(
        $Text, $Title,
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
}

function Show-ConfirmDialog {
    param([string]$Text, [string]$Title = '확인')
    $r = [System.Windows.Forms.MessageBox]::Show(
        $Text, $Title,
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question
    )
    return ($r -eq [System.Windows.Forms.DialogResult]::Yes)
}



# ---- 앱 본체 ------------------------------------------------------------------
$script:AppRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $script:AppRoot) { $script:AppRoot = (Get-Location).Path }

$script:ModulesDir = Join-Path $script:AppRoot 'modules'
$script:DataDir    = Join-Path $script:AppRoot 'data'
$script:ConfigPath = $null
$script:LogsDir    = Join-Path $script:AppRoot 'logs'
$script:ChatsDir   = Join-Path $script:DataDir 'chats'

# 모듈은 이 파일 상단에 인라인 (단일 파일)

# ---- 전역 상태 -----------------------------------------------------------------
$script:CurrentUserId       = $null
$script:CurrentUserName     = $null
$script:CurrentChatMD5      = $null
$script:isPolling           = $false
$script:PollAsyncRunning    = $false
$script:PollAsyncResult     = $null
$script:isSending           = $false
$script:PollIntervalMs      = 10000
$script:IsExiting           = $false
$script:AppContext          = $null

# UI 컨트롤 참조
$script:MainForm            = $null
$script:ChatForm            = $null
$script:NotifyIcon          = $null
$script:PollTimer           = $null
$script:StatusLabel         = $null
$script:ConversationListView = $null
$script:UserListView        = $null
$script:ChatRichTextBox     = $null
$script:ChatInputBox        = $null
$script:ChatStatusLabel     = $null
$script:ChatTitleLabel      = $null
$script:ChatLoadedMessages  = @()
$script:ChatPageSize        = 50
$script:BalloonWhenChatHidden = $true
$script:BalloonOtherChat     = $true
$script:ConvFilterText       = ''
$script:ConvUnreadOnly       = $false
$script:UserFilterText       = ''
$script:ChatLoadTake         = 0
$script:ConvFilterBox        = $null
$script:ConvUnreadCheck      = $null
$script:UserFilterBox        = $null
$script:SingleInstanceMutex  = $null
$script:LastBalloonMd5       = $null
$script:LastSyncTimeText     = ''
$script:ApiCallCount         = 0
$script:ApiFailCount         = 0
$script:ApiLastLatencyMs     = 0
$script:ApiLastError         = ''
$script:MainWindowBounds     = $null
$script:UseBackgroundPoll    = $true
$script:PollBgReady          = $false
$script:PollBgResult         = $null
$script:PollBgContext        = $null
$script:PollPsHandle         = $null
$script:PollPsInstance       = $null

# 인메모리 스토어 / dirty
$script:UserById            = $null
$script:ConvByMd5           = $null
$script:ConvOrder           = $null
$script:SyncState           = $null
$script:SyncLoaded          = $false
$script:DirtyUsers          = $false
$script:DirtyConversations  = $false
$script:DirtySync           = $false
$script:ChatMsgIdIndex      = $null
$script:DebugConvSaveCount  = 0
$script:ChatFontCacheKey    = ''
$script:ChatFontMeta        = $null
$script:ChatFontBody        = $null
$script:ChatFontTitle       = $null
$script:StateLock           = New-Object System.Object

# -- 1. 앱 초기화 ---------------------------------------------------------------
function Initialize-Application {
    # 폴더 생성, 모듈 초기화, ACL, API URL 계산
    foreach ($dir in @($script:DataDir, $script:LogsDir, $script:ChatsDir)) {
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }

    Initialize-AppLogger -LogDirectory $script:LogsDir
    Write-AppLog -Level INFO -Message "===== InternalChat 시작 ====="
    Write-AppLog -Level INFO -Message "AppRoot=$($script:AppRoot)"

    Initialize-SecurityModule -DataDirectory $script:DataDir
    Initialize-DataManager -DataDirectory $script:DataDir
    Import-AppStateFromDisk

    $script:ConfigPath = Join-Path $script:DataDir 'config.json'
    Import-ApiBaseFromConfig
    # 폴링/알림 고정 (설정 무시)
    $script:PollIntervalMs = 10000
    $script:BalloonWhenChatHidden = $true
    $script:BalloonOtherChat = $true

    Initialize-ApiUrls
    Write-AppLog -Level INFO -Message "URL Login=$($script:LoginUrl)"
    Write-AppLog -Level INFO -Message "URL Users=$($script:GetUserListUrl)"
    Write-AppLog -Level INFO -Message "URL Notes base=$($script:ApiBase)/note/..."

    # 401 → 재로그인 콜백
    Set-ApiReloginCallback -Callback {
        try {
            $cred = Get-UserCredential
            if (-not $cred) { return $false }
            $r = Invoke-ApiLogin -UserId $cred.UserId -Password $cred.Password
            return ($null -ne (Get-AuthToken))
        }
        catch {
            Write-AppLog -Level ERROR -Message "재로그인 실패" -Exception $_.Exception
            return $false
        }
    }
}

# -- 2. 로그인 ------------------------------------------------------------------
function Show-LoginDialogInputBox {
    # InputBox 3단계 로그인 (WinForms 모달이 안 뜨는 환경 대비)
    param(
        [string]$DefaultUserId = '',
        [string]$DefaultApiBase = ''
    )
    try { Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop } catch {
        Write-AppLog -Level ERROR -Message "VisualBasic 어셈블리 로드 실패" -Exception $_.Exception
        return $null
    }

    $defBase = if (-not [string]::IsNullOrWhiteSpace($DefaultApiBase)) {
        $DefaultApiBase.Trim()
    } else {
        [string]$script:ApiBase
    }

    Write-AppLog -Level INFO -Message "로그인 InputBox 폴백 표시"
    $api = [Microsoft.VisualBasic.Interaction]::InputBox(
        '서버 주소 (예: http://host:9080/orca)',
        'InternalChat 로그인 - 서버',
        $defBase
    )
    if ([string]::IsNullOrWhiteSpace($api)) {
        Write-AppLog -Level INFO -Message "로그인 InputBox 서버 취소"
        return $null
    }
    $api = $api.Trim().TrimEnd('/')
    if ($api -notmatch '^https?://') {
        [System.Windows.Forms.MessageBox]::Show(
            '서버 주소는 http:// 또는 https:// 로 시작해야 합니다.',
            '로그인',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        return $null
    }

    $uid = [Microsoft.VisualBasic.Interaction]::InputBox('사용자 ID', 'InternalChat 로그인 - ID', $DefaultUserId)
    if ([string]::IsNullOrWhiteSpace($uid)) {
        Write-AppLog -Level INFO -Message "로그인 InputBox ID 취소"
        return $null
    }

    $pw = [Microsoft.VisualBasic.Interaction]::InputBox('비밀번호', 'InternalChat 로그인 - 비밀번호', '')
    if ([string]::IsNullOrWhiteSpace($pw)) {
        Write-AppLog -Level INFO -Message "로그인 InputBox PW 취소"
        return $null
    }

    return [PSCustomObject]@{
        UserId   = $uid.Trim()
        Password = $pw
        ApiBase  = $api
    }
}

function Show-LoginDialog {
    # 서버/ID/PW 입력. InputBox 기본 사용
    param(
        [string]$DefaultUserId = '',
        [string]$DefaultApiBase = ''
    )

    # WinForms 모달이 특정 환경에서 즉시 닫히는 문제 → InputBox 우선
    Write-AppLog -Level INFO -Message "로그인 입력 시작 (InputBox 우선)"
    $cred = Show-LoginDialogInputBox -DefaultUserId $DefaultUserId -DefaultApiBase $DefaultApiBase
    if ($cred) {
        Write-AppLog -Level INFO -Message ("로그인 입력 완료 user=" + $cred.UserId)
    } else {
        Write-AppLog -Level INFO -Message "로그인 입력 취소"
    }
    return $cred
}

function Start-UserLogin {
    # 저장된 credential로 자동 로그인. 없으면 다이얼로그
    Import-ApiBaseFromConfig

    $cred = Get-UserCredential
    if ($cred) {
        if ([string]::IsNullOrWhiteSpace([string]$cred.UserId) -or [string]::IsNullOrWhiteSpace([string]$cred.Password)) {
            Write-AppLog -Level WARN -Message "저장된 자격 증명이 비어 있음 - 재입력"
            $cred = $null
        }
    }

    if (-not $cred) {
        $cred = Show-LoginDialog -DefaultApiBase $script:ApiBase
        if (-not $cred) {
            Write-AppLog -Level INFO -Message "로그인 취소 (창 닫힘 또는 취소)"
            return $false
        }
        if (-not (Set-ApiBaseAddress -ApiBase $cred.ApiBase)) {
            Write-AppLog -Level ERROR -Message "서버 주소가 올바르지 않음: $($cred.ApiBase)"
            Show-ErrorMessage -Text "서버 주소가 올바르지 않습니다.`n$($cred.ApiBase)"
            return $false
        }
        Save-AppConfig -ApiBase $script:ApiBase
        Save-UserCredential -UserId $cred.UserId -Password $cred.Password
    }

    try {
        Set-StatusSafe "로그인 중..."
        Write-AppLog -Level INFO -Message "로그인 시도 base=$($script:ApiBase) user=$($cred.UserId)"
        $result = Invoke-ApiLogin -UserId $cred.UserId -Password $cred.Password

        $script:CurrentUserId = $cred.UserId
        $script:CurrentUserName = $cred.UserId

        $sync = Get-SyncState
        if ($sync) {
            $prevSync = [string](Get-ObjectProperty -Object $sync -Name 'lastSync' -Default '')
            $prevId   = [string](Get-ObjectProperty -Object $sync -Name 'lastMessageId' -Default '')
            Save-SyncState -LastSync $prevSync -LastMessageId $prevId -CurrentUserId $script:CurrentUserId
        }

        Write-AppLog -Level INFO -Message "로그인 완료 user=$($script:CurrentUserId) name=$($script:CurrentUserName)"
        Save-AppStateDirty
        return $true
    }
    catch {
        Write-AppLog -Level ERROR -Message "로그인 실패" -Exception $_.Exception

        $retry = Show-ConfirmDialog -Text ("로그인에 실패했습니다.`n{0}`n`n서버 주소와 자격 증명을 다시 입력할까요?" -f $_.Exception.Message) -Title "로그인 실패"
        if ($retry) {
            $newCred = Show-LoginDialog -DefaultUserId $cred.UserId -DefaultApiBase $script:ApiBase
            if ($newCred) {
                if (-not (Set-ApiBaseAddress -ApiBase $newCred.ApiBase)) {
                    Show-ErrorMessage -Text ("서버 주소가 올바르지 않습니다.`n{0}" -f $newCred.ApiBase)
                    return $false
                }
                Save-AppConfig -ApiBase $script:ApiBase
                Save-UserCredential -UserId $newCred.UserId -Password $newCred.Password
                return (Start-UserLogin)
            }
            Write-AppLog -Level INFO -Message "로그인 재입력 취소"
        }
        return $false
    }
}



function Initialize-UserCache {
    # 최초 사용자 목록 조회 → users.json 저장
    try {
        Set-StatusSafe "사용자 목록 조회 중..."
        $rawUsers = @(Get-ApiUserList)
        $userList = New-Object System.Collections.ArrayList
        foreach ($u in $rawUsers) {
            if ($null -eq $u) { continue }
            $id = [string](Get-ObjectProperty -Object $u -Name 'user_id' -Default '')
            if (-not $id) { continue }
            [void]$userList.Add([PSCustomObject]@{
                id   = $id
                name = [string](Get-ObjectProperty -Object $u -Name 'user_nm' -Default $id)
                dept = [string](Get-ObjectProperty -Object $u -Name 'blg_corp_nm' -Default '')
                type = [string](Get-ObjectProperty -Object $u -Name 'role_nm_list' -Default 'user')
            })
        }
        $users = @($userList.ToArray())
        Set-UsersCache -Users $users
        Save-AppStateDirty
        $me = Get-UserById -Id $script:CurrentUserId
        if ($me -and $me.name) { $script:CurrentUserName = [string]$me.name }
        Write-AppLog -Level INFO -Message "사용자 $($users.Count)명 캐시 저장"
    }
    catch {
        Write-AppLog -Level ERROR -Message "사용자 목록 조회 실패: $($_.Exception.Message)" -Exception $_.Exception
        Set-StatusSafe ("사용자 목록 실패: " + $_.Exception.Message)
    }
}

# -- 3. MainForm ----------------------------------------------------------------
function Get-FilteredConversations {
    $convs = @(Get-Conversations)
    $ft = ''
    try { $ft = [string]$script:ConvFilterText } catch { $ft = '' }
    $ft = $ft.Trim()
    $unreadOnly = $false
    try { $unreadOnly = [bool]$script:ConvUnreadOnly } catch { }

    $list = New-Object System.Collections.ArrayList
    foreach ($c in $convs) {
        if ($null -eq $c) { continue }
        if ($unreadOnly -and -not $c.unread) { continue }
        if ($ft) {
            $title = Get-ConversationDisplayTitle -Conversation $c -CurrentUserId $script:CurrentUserId
            $prev = [string](Get-ConvProp $c 'lastPreview' '')
            $blob = ($title + ' ' + $prev)
            if ($blob.IndexOf($ft, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        }
        [void]$list.Add($c)
    }
    return @($list.ToArray())
}

function Get-FilteredUsers {
    $users = @(Get-Users)
    $ft = ''
    try { $ft = [string]$script:UserFilterText } catch { $ft = '' }
    $ft = $ft.Trim()
    $list = New-Object System.Collections.ArrayList
    foreach ($u in $users) {
        if ($null -eq $u) { continue }
        if ($script:CurrentUserId -and $u.id -eq $script:CurrentUserId) { continue }
        if ($ft) {
            $blob = ('{0} {1} {2} {3}' -f $u.name, $u.dept, $u.id, $u.type)
            if ($blob.IndexOf($ft, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        }
        [void]$list.Add($u)
    }
    return @($list.ToArray())
}

function Invoke-LoadOlderChatMessages {
    # 이전 메시지 더 불러오기 (pageSize 단위). 디스크만 읽으니 polling/sending 중에도 안전
    if (-not $script:CurrentChatMD5) { return }

    $page = 50
    try { if ($script:ChatPageSize -gt 0) { $page = [int]$script:ChatPageSize } } catch { }
    $cur = 0
    try { $cur = [int]$script:ChatLoadTake } catch { $cur = 0 }
    if ($cur -lt $page) { $cur = $page }
    $newTake = $cur + $page

    $msgs = @(Get-RecentChatMessages -Md5 $script:CurrentChatMD5 -Take $newTake)
    $script:ChatLoadTake = $newTake
    $script:ChatLoadedMessages = $msgs

    if ($script:ChatRichTextBox -and -not $script:ChatRichTextBox.IsDisposed) {
        Show-ChatMessages -WebBrowser $script:ChatRichTextBox -Messages $msgs
    }
    Set-StatusSafe ("이전 메시지 포함 {0}건 표시" -f $msgs.Count)
}

function New-MainForm {
    # MainForm: 대화 목록 / 사용자 목록 탭 + 트레이 아이콘
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "오케스트라 채팅 - $($script:CurrentUserName)"
    $form.Size = New-Object System.Drawing.Size(520, 680)
    $form.StartPosition = 'CenterScreen'
    $form.MinimumSize = New-Object System.Drawing.Size(400, 400)
    $form.Font = New-Object System.Drawing.Font('맑은 고딕', 9)

    $tabs = New-Object System.Windows.Forms.TabControl
    $tabs.Dock = [System.Windows.Forms.DockStyle]::Fill
    $form.Controls.Add($tabs)

    $tabConv = New-Object System.Windows.Forms.TabPage
    $tabConv.Text = '대화 목록'
    $tabs.TabPages.Add($tabConv)

    # TableLayout: 검색행 + 목록
    $layoutConv = New-Object System.Windows.Forms.TableLayoutPanel
    $layoutConv.Dock = [System.Windows.Forms.DockStyle]::Fill
    $layoutConv.ColumnCount = 1
    $layoutConv.RowCount = 2
    $layoutConv.Margin = New-Object System.Windows.Forms.Padding(0)
    $layoutConv.Padding = New-Object System.Windows.Forms.Padding(0)
    $layoutConv.GrowStyle = [System.Windows.Forms.TableLayoutPanelGrowStyle]::FixedSize
    [void]$layoutConv.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100.0)))
    [void]$layoutConv.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 40.0)))
    [void]$layoutConv.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100.0)))
    $tabConv.Controls.Add($layoutConv)

    $panelConvFilter = New-Object System.Windows.Forms.Panel
    $panelConvFilter.Dock = [System.Windows.Forms.DockStyle]::Fill
    $panelConvFilter.Margin = New-Object System.Windows.Forms.Padding(0)
    $panelConvFilter.Padding = New-Object System.Windows.Forms.Padding(6, 6, 6, 6)
    $layoutConv.Controls.Add($panelConvFilter, 0, 0)

    $chkUnread = New-Object System.Windows.Forms.CheckBox
    $chkUnread.Text = '미확인만'
    $chkUnread.Dock = [System.Windows.Forms.DockStyle]::Right
    $chkUnread.Width = 90
    $chkUnread.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $chkUnread.Checked = $false
    $panelConvFilter.Controls.Add($chkUnread)
    $script:ConvUnreadCheck = $chkUnread

    $txtConvFilter = New-Object System.Windows.Forms.TextBox
    $txtConvFilter.Dock = [System.Windows.Forms.DockStyle]::Fill
    $panelConvFilter.Controls.Add($txtConvFilter)
    $script:ConvFilterBox = $txtConvFilter
    $txtConvFilter.BringToFront()

    $applyConvFilter = {
        try {
            if ($script:ConvFilterBox -and -not $script:ConvFilterBox.IsDisposed) {
                $script:ConvFilterText = [string]$script:ConvFilterBox.Text
            }
            if ($script:ConvUnreadCheck -and -not $script:ConvUnreadCheck.IsDisposed) {
                $script:ConvUnreadOnly = [bool]$script:ConvUnreadCheck.Checked
            }
            Update-ConversationListUi
        } catch { }
    }
    $txtConvFilter.Add_TextChanged($applyConvFilter)
    $chkUnread.Add_CheckedChanged($applyConvFilter)

    $lvConv = New-Object System.Windows.Forms.ListView
    $lvConv.Dock = [System.Windows.Forms.DockStyle]::Fill
    $lvConv.Margin = New-Object System.Windows.Forms.Padding(0)
    Initialize-ConversationListView -ListView $lvConv
    $layoutConv.Controls.Add($lvConv, 0, 1)
    $script:ConversationListView = $lvConv

    $tabUser = New-Object System.Windows.Forms.TabPage
    $tabUser.Text = '사용자 목록'
    $tabs.TabPages.Add($tabUser)

    $layoutUser = New-Object System.Windows.Forms.TableLayoutPanel
    $layoutUser.Dock = [System.Windows.Forms.DockStyle]::Fill
    $layoutUser.ColumnCount = 1
    $layoutUser.RowCount = 3
    $layoutUser.Margin = New-Object System.Windows.Forms.Padding(0)
    $layoutUser.Padding = New-Object System.Windows.Forms.Padding(0)
    $layoutUser.GrowStyle = [System.Windows.Forms.TableLayoutPanelGrowStyle]::FixedSize
    [void]$layoutUser.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100.0)))
    [void]$layoutUser.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 40.0)))
    [void]$layoutUser.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100.0)))
    [void]$layoutUser.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 40.0)))
    $tabUser.Controls.Add($layoutUser)

    $panelUserFilter = New-Object System.Windows.Forms.Panel
    $panelUserFilter.Dock = [System.Windows.Forms.DockStyle]::Fill
    $panelUserFilter.Margin = New-Object System.Windows.Forms.Padding(0)
    $panelUserFilter.Padding = New-Object System.Windows.Forms.Padding(6, 6, 6, 6)
    $layoutUser.Controls.Add($panelUserFilter, 0, 0)

    $txtUserFilter = New-Object System.Windows.Forms.TextBox
    $txtUserFilter.Dock = [System.Windows.Forms.DockStyle]::Fill
    $panelUserFilter.Controls.Add($txtUserFilter)
    $script:UserFilterBox = $txtUserFilter
    $txtUserFilter.Add_TextChanged({
        try {
            if ($script:UserFilterBox -and -not $script:UserFilterBox.IsDisposed) {
                $script:UserFilterText = [string]$script:UserFilterBox.Text
            }
            Update-UserListUi
        } catch { }
    })

    $lvUser = New-Object System.Windows.Forms.ListView
    $lvUser.Dock = [System.Windows.Forms.DockStyle]::Fill
    $lvUser.Margin = New-Object System.Windows.Forms.Padding(0)
    Initialize-UserListView -ListView $lvUser
    $layoutUser.Controls.Add($lvUser, 0, 1)
    $script:UserListView = $lvUser

    $btnNewChat = New-Object System.Windows.Forms.Button
    $btnNewChat.Text = '선택 사용자와 대화 시작'
    $btnNewChat.Dock = [System.Windows.Forms.DockStyle]::Fill
    $btnNewChat.Margin = New-Object System.Windows.Forms.Padding(6, 4, 6, 6)
    $layoutUser.Controls.Add($btnNewChat, 0, 2)

    $status = New-Object System.Windows.Forms.StatusStrip
    $statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
    $statusLabel.Spring = $true
    $statusLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $statusLabel.Text = '준비'
    [void]$status.Items.Add($statusLabel)
    $form.Controls.Add($status)
    $script:StatusLabel = $statusLabel

    $notify = New-Object System.Windows.Forms.NotifyIcon
    $notify.Text = "내부 채팅 - $($script:CurrentUserName)"
    $notify.Visible = $true
    try { $notify.Icon = [System.Drawing.SystemIcons]::Application }
    catch { $notify.Icon = [System.Drawing.SystemIcons]::Information }
    $script:NotifyIcon = $notify

    $trayMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $miOpen = $trayMenu.Items.Add('메인 창 열기')
    [void]$trayMenu.Items.Add('-')
    $miExit2 = $trayMenu.Items.Add('종료')
    $notify.ContextMenuStrip = $trayMenu
    $miOpen.Add_Click({ Restore-MainForm })
    $miExit2.Add_Click({ Exit-Application })
    $notify.Add_DoubleClick({ Restore-MainForm })
    $notify.Add_BalloonTipClicked({ Open-LastBalloonConversation })

    $lvConv.Add_DoubleClick({
        if ($script:ConversationListView.SelectedItems.Count -gt 0) {
            $md5 = [string]$script:ConversationListView.SelectedItems[0].Tag
            Open-ChatForm -Md5 $md5
        }
    })

    $convMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $miRename = $convMenu.Items.Add('제목 변경')
    $miRename.Add_Click({ Edit-SelectedConversationTitle })
    $lvConv.ContextMenuStrip = $convMenu

    $btnNewChat.Add_Click({ Start-NewConversationFromSelection })

    $form.Add_FormClosing({
        if ($script:IsExiting) { return }
        $ea = $null
        if ($args.Count -ge 2) { $ea = $args[1] }
        if ($null -ne $ea) { $ea.Cancel = $true }
        Hide-MainFormToTray
    })

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = $script:PollIntervalMs
    $timer.Add_Tick({ Invoke-PollTimerTick })
    $script:PollTimer = $timer

    Restore-MainWindowBounds -Form $form
    $form.Add_ResizeEnd({ Save-MainWindowBounds })
    $form.Add_LocationChanged({
        try {
            if ($script:MainForm -and -not $script:MainForm.IsDisposed -and $script:MainForm.WindowState -eq 'Normal') {
                $b = $script:MainForm.Bounds
                $script:MainWindowBounds = [PSCustomObject]@{ x=[int]$b.X; y=[int]$b.Y; w=[int]$b.Width; h=[int]$b.Height }
            }
        } catch { }
    })
    $script:MainForm = $form
    return $form
}

function Set-StatusSafe {
    param([string]$Message)
    try {
        if ($script:StatusLabel -and -not $script:StatusLabel.IsDisposed) {
            $script:StatusLabel.Text = $Message
        }
    }
    catch { }
    try {
        if ($script:ChatStatusLabel -and -not $script:ChatStatusLabel.IsDisposed) {
            $script:ChatStatusLabel.Text = $Message
        }
    }
    catch { }
}

function Get-SessionCookieHeader {
    # HttpSession 쿠키 → Cookie: 헤더 문자열 (백그라운드 HTTP용)
    if (-not $script:HttpSession) { return '' }
    try {
        $base = [string]$script:ApiBase
        if ([string]::IsNullOrWhiteSpace($base)) { return '' }
        $uri = [Uri]$base
        $cookies = $script:HttpSession.Cookies.GetCookies($uri)
        if (-not $cookies -or $cookies.Count -eq 0) {
            $root = $uri.GetLeftPart([System.UriPartial]::Authority)
            $cookies = $script:HttpSession.Cookies.GetCookies([Uri]$root)
        }
        $parts = New-Object System.Collections.ArrayList
        foreach ($c in @($cookies)) {
            if ($c -and $c.Name) {
                [void]$parts.Add(('{0}={1}' -f $c.Name, $c.Value))
            }
        }
        return ($parts -join '; ')
    } catch {
        return ''
    }
}

function Update-StatusStripInfo {
    # 상태줄: 동기시각 / API 레이턴시
    param([string]$Prefix = '')
    $syncText = $script:LastSyncTimeText
    if (-not $syncText) { $syncText = '-' }
    $lat = [int]$script:ApiLastLatencyMs
    $fail = [int]$script:ApiFailCount
    $ok = [int]$script:ApiCallCount
    $msg = if ($Prefix) {
        '{0} | 동기 {1} | API {2}ms (ok {3}/fail {4})' -f $Prefix, $syncText, $lat, $ok, $fail
    } else {
        '동기 {0} | API {1}ms (ok {2}/fail {3})' -f $syncText, $lat, $ok, $fail
    }
    Set-StatusSafe $msg
}

function Save-MainWindowBounds {
    try {
        if (-not $script:MainForm -or $script:MainForm.IsDisposed) { return }
        if ($script:MainForm.WindowState -ne [System.Windows.Forms.FormWindowState]::Normal) { return }
        $b = $script:MainForm.Bounds
        $script:MainWindowBounds = [PSCustomObject]@{
            x = [int]$b.X
            y = [int]$b.Y
            w = [int]$b.Width
            h = [int]$b.Height
        }
        Save-AppConfig -MainWindow $script:MainWindowBounds
    } catch {
        Write-AppLog -Level DEBUG -Message "창 위치 저장 실패" -Exception $_.Exception
    }
}

function Restore-MainWindowBounds {
    param([System.Windows.Forms.Form]$Form)
    try {
        $mw = $script:MainWindowBounds
        if (-not $mw) { return }
        $w = [Math]::Max(400, [int]$mw.w)
        $h = [Math]::Max(400, [int]$mw.h)
        $x = [int]$mw.x
        $y = [int]$mw.y
        # 화면 밖으로 안 나가게 보정
        $area = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
        if ($x + 50 -gt $area.Right) { $x = $area.Left + 20 }
        if ($y + 50 -gt $area.Bottom) { $y = $area.Top + 20 }
        if ($x + $w -lt $area.Left + 50) { $x = $area.Left + 20 }
        if ($y -lt $area.Top) { $y = $area.Top + 20 }
        $Form.StartPosition = [System.Windows.Forms.FormStartPosition]::Manual
        $Form.Bounds = New-Object System.Drawing.Rectangle($x, $y, $w, $h)
    } catch { }
}

function Test-SingleInstance {
    # Mutex로 중복 실행 방지
    $name = 'Local\InternalChat_SingleInstance_Mutex_v1'
    $created = $false
    try {
        $m = New-Object System.Threading.Mutex($true, $name, [ref]$created)
        $script:SingleInstanceMutex = $m
        if (-not $created) {
            try { $m.Dispose() } catch { }
            $script:SingleInstanceMutex = $null
            return $false
        }
        return $true
    } catch {
        Write-AppLog -Level WARN -Message "Mutex 생성 실패(계속 진행)" -Exception $_.Exception
        return $true
    }
}

function Invoke-SelfTest {
    # 헤드리스 자가진단. exit code 0=정상
    Write-Host '=== InternalChat SelfTest ===' -ForegroundColor Cyan
    $failed = 0

    try {
        $s = Format-MessageDateTime -Value '2026-07-12T16:27:12'
        if ($s -ne '2026-07-12 16:27:12') { throw "fmt=$s" }
        Write-Host '[OK] Format-MessageDateTime' -ForegroundColor Green
    } catch {
        Write-Host "[FAIL] Format-MessageDateTime $_" -ForegroundColor Red
        $failed++
    }

    try {
        $a = Get-ConversationMD5 -ParticipantIds @('u2', 'u1', 'u1')
        $b = Get-ConversationMD5 -ParticipantIds @('u1', 'u2')
        if ($a -ne $b -or [string]::IsNullOrWhiteSpace($a)) { throw "md5 mismatch $a $b" }
        Write-Host '[OK] Get-ConversationMD5' -ForegroundColor Green
    } catch {
        Write-Host "[FAIL] Get-ConversationMD5 $_" -ForegroundColor Red
        $failed++
    }

    # JSONL append/dedupe
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('ic_selftest_' + [guid]::NewGuid().ToString('N'))
    try {
        New-Item -ItemType Directory -Path (Join-Path $tmp 'chats') -Force | Out-Null
        $script:ChatsDirectory = Join-Path $tmp 'chats'
        $script:ChatMsgIdIndex = $null
        $md5 = 'selftestmd5'
        $msg = [PSCustomObject]@{
            aa='NT-000000001'; ab='a'; ac='A'; ad=''; ae=(Get-Date).ToString('o')
            af=@('b'); ag=@('B'); ah='hello'; ai=$md5; isOwn=$false
        }
        $r1 = Add-ChatMessage -Md5 $md5 -Message $msg -YearMonth '202607'
        $r2 = Add-ChatMessage -Md5 $md5 -Message $msg -YearMonth '202607'
        if ($r1 -ne $true -or $r2 -ne $false) { throw "append r1=$r1 r2=$r2" }
        $n = @(Get-ChatMessages -Md5 $md5 -YearMonth '202607').Count
        if ($n -ne 1) { throw "count=$n" }
        Write-Host '[OK] JSONL append/dedupe' -ForegroundColor Green
    } catch {
        Write-Host "[FAIL] JSONL $_" -ForegroundColor Red
        $failed++
    } finally {
        try { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue } catch { }
    }

    # dirty flush
    try {
        Initialize-AppState
        $script:DebugConvSaveCount = 0
        $script:ConversationsPath = Join-Path ([IO.Path]::GetTempPath()) ('ic_conv_' + [guid]::NewGuid().ToString('N') + '.json')
        $script:UsersPath = Join-Path ([IO.Path]::GetTempPath()) ('ic_users_' + [guid]::NewGuid().ToString('N') + '.json')
        $script:SyncPath = Join-Path ([IO.Path]::GetTempPath()) ('ic_sync_' + [guid]::NewGuid().ToString('N') + '.json')
        '[]' | Set-Content $script:ConversationsPath -Encoding UTF8
        '[]' | Set-Content $script:UsersPath -Encoding UTF8
        1..5 | ForEach-Object {
            Update-ConversationMeta -Md5 ("m$_") -LastSeq "NT-$_" -LastMessageTime (Get-Date).ToString('o') -IncrementUnread
        }
        if (-not $script:DirtyConversations) { throw 'dirty not set' }
        $before = $script:DebugConvSaveCount
        Save-AppStateDirty
        if ($script:DirtyConversations) { throw 'dirty remains' }
        if ($script:DebugConvSaveCount -ne ($before + 1)) { throw "saves=$($script:DebugConvSaveCount)" }
        $c = Get-ConversationByMd5 -Md5 'm1'
        if ([int]$c.unreadCount -lt 1) { throw 'unreadCount' }
        Write-Host '[OK] dirty flush + unreadCount' -ForegroundColor Green
        Remove-Item $script:ConversationsPath, $script:UsersPath -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "[FAIL] flush $_" -ForegroundColor Red
        $failed++
    }

    if ($failed -eq 0) {
        Write-Host '=== SelfTest ALL OK ===' -ForegroundColor Green
        return 0
    }
    Write-Host ("=== SelfTest FAILED count={0} ===" -f $failed) -ForegroundColor Red
    return 1
}

function Update-ConversationListUi {
    # 필터 적용된 대화 목록 → ListView
    try {
        $convs = @(Get-FilteredConversations)
        if ($null -eq $convs) { $convs = @() }
        if ($script:ConversationListView -and -not $script:ConversationListView.IsDisposed) {
            Update-ConversationListView -ListView $script:ConversationListView -Conversations $convs -CurrentUserId $script:CurrentUserId
        }
    }
    catch {
        Write-AppLog -Level ERROR -Message "대화 목록 갱신 실패" -Exception $_.Exception
    }
}

function Update-UserListUi {
    try {
        $users = @(Get-FilteredUsers)
        if ($null -eq $users) { $users = @() }
        if ($script:UserListView -and -not $script:UserListView.IsDisposed) {
            Update-UserListView -ListView $script:UserListView -Users $users -ExcludeUserId ''
        }
    }
    catch {
        Write-AppLog -Level ERROR -Message "사용자 목록 갱신 실패" -Exception $_.Exception
    }
}

function Start-NewConversationFromSelection {
    # 체크된 사용자와 새 대화 시작
    $ids = @(Get-CheckedUserIds -ListView $script:UserListView)
    if ($ids.Count -eq 0) {
        Show-InfoMessage -Text '대화할 사용자를 체크하세요.'
        return
    }

    $allIds = @($script:CurrentUserId) + $ids
    $md5 = Get-ConversationMD5 -ParticipantIds $allIds

    $names = @()
    foreach ($id in $ids) {
        $u = Get-UserById -Id $id
        if ($u) { $names += [string]$u.name } else { $names += $id }
    }

    Update-ConversationMeta `
        -Md5 $md5 `
        -ParticipantIds $allIds `
        -ParticipantNames (@($script:CurrentUserName) + $names) `
        -LastMonth (Get-Date -Format 'yyyyMM') `
        -ClearUnread

    Update-ConversationListUi
    Open-ChatForm -Md5 $md5
}

# -- 4. ChatForm ----------------------------------------------------------------
function Open-ChatForm {
    # 지정 md5 대화를 ChatForm으로 열기. 이미 있으면 내용만 교체
    param(
        [Parameter(Mandatory = $true)]
        [string]$Md5
    )

    $script:ChatLoadTake = 0
    $script:CurrentChatMD5 = $Md5

    if ($null -eq $script:ChatForm -or $script:ChatForm.IsDisposed) {
        New-ChatForm
    }

    Initialize-ChatContent -Md5 $Md5
    Set-ConversationRead -Md5 $Md5
    Update-ConversationListUi

    Show-ChatForm
}

function New-ChatForm {
    # ChatForm UI 생성 (WebBrowser + TextBox + 전송 버튼)
    $form = New-Object System.Windows.Forms.Form
    $form.Text = '대화'
    $form.Size = New-Object System.Drawing.Size(520, 680)
    $form.StartPosition = 'CenterScreen'
    $form.MinimumSize = New-Object System.Drawing.Size(400, 400)
    $form.Font = New-Object System.Drawing.Font('맑은 고딕', 9)
    $form.ShowInTaskbar = $true

    $titlePanel = New-Object System.Windows.Forms.Panel
    $titlePanel.Dock = [System.Windows.Forms.DockStyle]::Top
    $titlePanel.Height = 30
    $titlePanel.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 245)
    $form.Controls.Add($titlePanel)

    $titleTable = New-Object System.Windows.Forms.TableLayoutPanel
    $titleTable.Dock = [System.Windows.Forms.DockStyle]::Fill
    $titleTable.ColumnCount = 2
    $titleTable.RowCount = 1
    $titleTable.Margin = New-Object System.Windows.Forms.Padding(0)
    $titleTable.Padding = New-Object System.Windows.Forms.Padding(0)
    [void]$titleTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100.0)))
    [void]$titleTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 72.0)))
    $titlePanel.Controls.Add($titleTable)

    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Dock = [System.Windows.Forms.DockStyle]::Fill
    $lblTitle.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $lblTitle.Padding = New-Object System.Windows.Forms.Padding(8, 0, 0, 0)
    $lblTitle.Text = '대화'
    $titleTable.Controls.Add($lblTitle, 0, 0)
    $script:ChatTitleLabel = $lblTitle

    $btnMembers = New-Object System.Windows.Forms.Button
    $btnMembers.Text = '참여자'
    $btnMembers.Dock = [System.Windows.Forms.DockStyle]::Fill
    $btnMembers.Margin = New-Object System.Windows.Forms.Padding(2, 2, 4, 2)
    $btnMembers.Add_Click({ Show-ChatParticipants })
    $titleTable.Controls.Add($btnMembers, 1, 0)

    # 이전 대화 불러오기
    $olderPanel = New-Object System.Windows.Forms.Panel
    $olderPanel.Dock = [System.Windows.Forms.DockStyle]::Top
    $olderPanel.Height = 36
    $olderPanel.Padding = New-Object System.Windows.Forms.Padding(6, 4, 6, 4)
    $olderPanel.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 252)
    $form.Controls.Add($olderPanel)

    $btnOlder = New-Object System.Windows.Forms.Button
    $btnOlder.Text = '이전 대화 불러오기'
    $btnOlder.Dock = [System.Windows.Forms.DockStyle]::Fill
    $btnOlder.Add_Click({ Invoke-LoadOlderChatMessages })
    $olderPanel.Controls.Add($btnOlder)

    # 입력 영역
    $bottom = New-Object System.Windows.Forms.Panel
    $bottom.Dock = [System.Windows.Forms.DockStyle]::Bottom
    $bottom.Height = 100
    $form.Controls.Add($bottom)

    $btnSend = New-Object System.Windows.Forms.Button
    $btnSend.Text = '전송'
    $btnSend.Dock = [System.Windows.Forms.DockStyle]::Right
    $btnSend.Width = 80
    $btnSend.Add_Click({ Invoke-ChatSend })
    $bottom.Controls.Add($btnSend)

    $txtInput = New-Object System.Windows.Forms.TextBox
    $txtInput.Multiline = $true
    $txtInput.Dock = [System.Windows.Forms.DockStyle]::Fill
    $txtInput.ScrollBars = 'Vertical'
    $txtInput.AcceptsReturn = $true
    $bottom.Controls.Add($txtInput)
    $script:ChatInputBox = $txtInput

    # Enter=전송, Shift+Enter=줄바꿈
    $txtInput.Add_KeyDown({
        param($sender, $e)
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter -and -not $e.Shift) {
            $e.SuppressKeyPress = $true
            Invoke-ChatSend
        }
    })

    # 메시지 영역 (WebBrowser. RichTextBox보다 렌더링 안정적)
    $wb = New-Object System.Windows.Forms.WebBrowser
    $wb.Dock = [System.Windows.Forms.DockStyle]::Fill
    $wb.AllowNavigation = $false
    $wb.IsWebBrowserContextMenuEnabled = $false
    $wb.ScriptErrorsSuppressed = $true
    $wb.ScrollBarsEnabled = $true
    $form.Controls.Add($wb)
    $script:ChatRichTextBox = $wb

    $html = Get-ChatMessagesHtml -Messages @() -Title '대화'
    $wb.DocumentText = $html

    # Fill 컨트롤은 z-order 뒤로 → Top/Bottom이 공간 먼저 확보
    $wb.SendToBack()

    $chatStatus = New-Object System.Windows.Forms.StatusStrip
    $chatStatusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
    $chatStatusLabel.Spring = $true
    $chatStatusLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $chatStatusLabel.Text = '준비'
    [void]$chatStatus.Items.Add($chatStatusLabel)
    $form.Controls.Add($chatStatus)
    $script:ChatStatusLabel = $chatStatusLabel

    $form.Add_FormClosing({
        param($sender, $e)
        if ($script:IsExiting) { return }
    })
    $form.Add_FormClosed({
        $script:ChatForm = $null
        $script:ChatRichTextBox = $null
        $script:ChatInputBox = $null
        $script:ChatTitleLabel = $null
        $script:ChatStatusLabel = $null
        $script:CurrentChatMD5 = $null
        $script:ChatLoadedMessages = @()
    })

    $script:ChatForm = $form
}

function Initialize-ChatContent {
    # md5 대화 메시지 로드. 최신 월부터 필요한 만큼만
    param(
        [Parameter(Mandatory = $true)]
        [string]$Md5
    )

    $conv = Get-ConversationByMd5 -Md5 $Md5
    $title = if ($conv) {
        Get-ConversationDisplayTitle -Conversation $conv -CurrentUserId $script:CurrentUserId
    }
    else {
        $Md5
    }

    if ($script:ChatForm -and -not $script:ChatForm.IsDisposed) {
        $script:ChatForm.Text = "대화 - $title"
    }
    if ($script:ChatTitleLabel -and -not $script:ChatTitleLabel.IsDisposed) {
        $script:ChatTitleLabel.Text = "  $title"
    }

    $take = 50
    try {
        if ($script:ChatPageSize -gt 0) { $take = [int]$script:ChatPageSize }
    } catch { }
    if ($script:ChatLoadTake -gt $take) { $take = [int]$script:ChatLoadTake }
    $script:ChatLoadTake = $take

    $script:ChatLoadedMessages = @(Get-RecentChatMessages -Md5 $Md5 -Take $take)

    if ($script:ChatRichTextBox -and -not $script:ChatRichTextBox.IsDisposed) {
        Show-ChatMessages -WebBrowser $script:ChatRichTextBox -Messages $script:ChatLoadedMessages
    }

    Write-AppLog -Level DEBUG -Message ("chat load md5={0} n={1}" -f $Md5, @($script:ChatLoadedMessages).Count)
}




function Show-ChatForm {
    # ChatForm 표시 + 포커스
    if ($null -eq $script:ChatForm -or $script:ChatForm.IsDisposed) { return }

    if (-not $script:ChatForm.Visible) {
        $script:ChatForm.Show()
    }
    if ($script:ChatForm.WindowState -eq [System.Windows.Forms.FormWindowState]::Minimized) {
        $script:ChatForm.WindowState = [System.Windows.Forms.FormWindowState]::Normal
    }
    $script:ChatForm.Activate()
    $script:ChatForm.BringToFront()

    if ($script:ChatInputBox -and -not $script:ChatInputBox.IsDisposed) {
        $script:ChatInputBox.Focus()
    }
}

function Hide-MainFormToTray {
    # 메인 창 → 트레이로 숨김 (종료 아님)
    try { Save-MainWindowBounds } catch { }
    if ($script:MainForm -and -not $script:MainForm.IsDisposed) {
        $script:MainForm.ShowInTaskbar = $false
        $script:MainForm.WindowState = [System.Windows.Forms.FormWindowState]::Normal
        $script:MainForm.Visible = $false
        Write-AppLog -Level INFO -Message "메인 창 트레이 숨김"
    }
}

function Restore-MainForm {
    # 트레이에서 메인 창 복원
    if (-not $script:MainForm -or $script:MainForm.IsDisposed) { return }
    $script:MainForm.ShowInTaskbar = $true
    $script:MainForm.Visible = $true
    $script:MainForm.Show()
    $script:MainForm.WindowState = [System.Windows.Forms.FormWindowState]::Normal
    $script:MainForm.Activate()
    $script:MainForm.BringToFront()
    $script:MainForm.Focus()
}

function Test-ChatFormVisible {
    # ChatForm이 보이는 상태인지
    if ($null -eq $script:ChatForm) { return $false }
    if ($script:ChatForm.IsDisposed) { return $false }
    return [bool]$script:ChatForm.Visible
}

# -- 5. 폴링 --------------------------------------------------------------------
function Get-MessageListUri {
    param([string]$StartYmd = '')
    $ymd = if ($null -eq $StartYmd) { '' } else { [string]$StartYmd }
    $base = $script:ApiBase.TrimEnd('/')
    return ($base + '/note/retrieveNoteListJson.do?start_ymd=' + [Uri]::EscapeDataString($ymd) + '&nd=&rows=9999&page=1')
}

function ConvertFrom-PollJsonBody {
    # JSON 응답 본문 → rows 배열
    param([string]$Body)
    if ([string]::IsNullOrWhiteSpace($Body)) { return @() }
    try {
        $obj = $Body | ConvertFrom-Json
    }
    catch {
        Write-AppLog -Level WARN -Message "폴링 JSON 파싱 실패" -Exception $_.Exception
        return @()
    }
    return @(Get-ApiRows -Result $obj)
}

function Complete-MessagePollFromRows {
    # 폴링 결과 rows → 로컬 저장 + UI 갱신
    param(
        [AllowEmptyCollection()]
        [array]$RawList = @(),
        [string]$LastMsgId = '',
        [string]$StartYmd = ''
    )

    if ($null -eq $RawList) { $RawList = @() }

    $newMessages = New-Object System.Collections.ArrayList
    $maxMsgId = $LastMsgId
    if (-not $maxMsgId) { $maxMsgId = $null }

    $pollBatchSize = 50
    $pollProcessed = 0

    foreach ($raw in @($RawList)) {
        $pollProcessed++
        try {
            $msg = ConvertTo-NormalizedMessage -Raw $raw -CurrentUserId $script:CurrentUserId
            if (-not $msg.aa) { continue }

            if ($LastMsgId) {
                if ([string]::CompareOrdinal([string]$msg.aa.ToUpperInvariant(), [string]$LastMsgId.ToUpperInvariant()) -le 0) {
                    continue
                }
            }

            [void]$newMessages.Add($msg)

            if (-not $maxMsgId -or [string]::CompareOrdinal([string]$msg.aa.ToUpperInvariant(), [string]$maxMsgId.ToUpperInvariant()) -gt 0) {
                $maxMsgId = $msg.aa
            }
        }
        catch {
            Write-AppLog -Level WARN -Message "메시지 정규화 실패" -Exception $_.Exception
        }

        if ($pollProcessed % $pollBatchSize -eq 0) {
            [System.Windows.Forms.Application]::DoEvents()
        }
    }

    if ($newMessages.Count -eq 0) {
        if ($script:CurrentUserId) {
            $keepId = if ($maxMsgId) { $maxMsgId } elseif ($LastMsgId) { $LastMsgId } else { '' }
            $keepYmd = if ($StartYmd) { $StartYmd } else { (Get-Date).ToString('yyyyMMdd') }
            Save-SyncState -LastSync $keepYmd -LastMessageId $keepId -CurrentUserId $script:CurrentUserId
        }
        $script:LastSyncTimeText = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Update-StatusStripInfo -Prefix '동기화 완료'
        return
    }

    Write-AppLog -Level DEBUG -Message ("poll new count=" + $newMessages.Count)

    $chatVisible = Test-ChatFormVisible
    $currentMd5  = $script:CurrentChatMD5
    $uiAppendList = New-Object System.Collections.ArrayList
    $balloonCandidates = New-Object System.Collections.ArrayList

    foreach ($msg in $newMessages) {
        $md5 = Resolve-MessageConversationKey -Message $msg -CurrentUserId $script:CurrentUserId

        $ym = Get-Date -Format 'yyyyMM'
        if ($msg.ae) {
            try { $ym = ([datetime]$msg.ae).ToString('yyyyMM') } catch { }
        }

        $added = Add-ChatMessage -Md5 $md5 -Message $msg -YearMonth $ym
        if (-not $added) { continue }

        $pIdList = New-Object System.Collections.ArrayList
        [void]$pIdList.Add([string]$script:CurrentUserId)
        if ($msg.ab -and $msg.ab -ne $script:CurrentUserId) {
            if (-not $pIdList.Contains([string]$msg.ab)) { [void]$pIdList.Add([string]$msg.ab) }
        }
        foreach ($r in @($msg.af)) {
            if ($r -and -not $pIdList.Contains([string]$r)) { [void]$pIdList.Add([string]$r) }
        }
        $pIds = @($pIdList.ToArray())

        $pNameList = New-Object System.Collections.ArrayList
        foreach ($partId in $pIds) {
            if ($partId -eq $script:CurrentUserId) {
                [void]$pNameList.Add([string]$script:CurrentUserName)
            }
            elseif ($msg.ab -eq $partId -and $msg.ac) {
                [void]$pNameList.Add([string]$msg.ac)
            }
            else {
                $u = Get-UserById -Id $partId
                [void]$pNameList.Add($(if ($u) { [string]$u.name } else { [string]$partId }))
            }
        }
        $pNames = @($pNameList.ToArray())

        $isCurrentChat = ($chatVisible -and $currentMd5 -and $md5 -eq $currentMd5)
        $markUnread = (-not $msg.isOwn -and -not $isCurrentChat)

        $upsertParams = @{
            Md5              = $md5
            ParticipantIds   = $pIds
            ParticipantNames = $pNames
            LastMonth        = $ym
            LastSeq          = $msg.aa
        }
        $prevConv = Get-ConversationByMd5 -Md5 $md5
        $shouldSetTime = $true
        if ($prevConv -and $prevConv.lastMessageTime -and $msg.ae) {
            try {
                if ([datetime]$msg.ae -lt [datetime]$prevConv.lastMessageTime) {
                    $shouldSetTime = $false
                }
            } catch { }
        }
        if ($shouldSetTime -and $msg.ae) {
            $upsertParams['LastMessageTime'] = $msg.ae
        }
        if ($msg.convTitle) { $upsertParams['CustomTitle'] = [string]$msg.convTitle }
        try {
            $upsertParams['LastPreview'] = Get-MessagePreviewText -Message $msg
        } catch { }
        if ($markUnread) {
            $upsertParams['IncrementUnread'] = $true
        }
        elseif ($isCurrentChat) {
            $upsertParams['ClearUnread'] = $true
        }
        Update-ConversationMeta @upsertParams

        if ($chatVisible) {
            if ($currentMd5 -and $md5 -eq $currentMd5) {
                if ($added) { [void]$uiAppendList.Add($msg) }
            }
            else {
                if (-not $msg.isOwn) {
                    [void]$balloonCandidates.Add($msg)
                }
            }
        }
        else {
            if (-not $msg.isOwn) {
                [void]$balloonCandidates.Add($msg)
            }
        }
    }

    if (-not $maxMsgId) { $maxMsgId = $LastMsgId }
    if (-not $maxMsgId) { $maxMsgId = '' }
    $maxYmd = $StartYmd
    foreach ($nm in $newMessages) {
        if ($nm.ae) {
            try {
                $y = ([datetime]$nm.ae).ToString('yyyyMMdd')
                if (-not $maxYmd -or $y -gt $maxYmd) { $maxYmd = $y }
            } catch { }
        }
    }
    if (-not $maxYmd) { $maxYmd = (Get-Date).ToString('yyyyMMdd') }
    Save-SyncState -LastSync $maxYmd -LastMessageId $maxMsgId -CurrentUserId $script:CurrentUserId

    Update-ConversationListUi

    if ($chatVisible -and $uiAppendList.Count -gt 0) {
        [System.Windows.Forms.Application]::DoEvents()
        Add-MessagesToChatUi -Messages @($uiAppendList.ToArray())
    }

    if ($balloonCandidates.Count -gt 0) {
        Show-NewMessageBalloon -Messages @($balloonCandidates.ToArray())
    }

    $script:LastSyncTimeText = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Update-StatusStripInfo -Prefix ("동기화 완료 ({0})" -f $newMessages.Count)
}

function Invoke-MessagePoll {
    # 동기 폴링. 초기 동기화용
    Set-StatusSafe "동기화 중..."

    $sync = Get-SyncState
    $startYmd = ''
    $lastMsgId = ''

    if ($sync) {
        $startYmd  = [string](Get-ObjectProperty -Object $sync -Name 'lastSync' -Default '')
        $lastMsgId = [string](Get-ObjectProperty -Object $sync -Name 'lastMessageId' -Default '')
        if (-not $lastMsgId) { $lastMsgId = '' }
    }

    $rawList = Get-ApiMessageList -StartYmd $startYmd
    if ($null -eq $rawList) { $rawList = @() }
    Complete-MessagePollFromRows -RawList @($rawList) -LastMsgId $lastMsgId -StartYmd $startYmd
}

function Complete-MessagePollAsync {
    # 백그라운드 HTTP 완료 콜백
    param($Result)

    try {
        if ($script:IsExiting) { return }

        if ($null -eq $Result) {
            Set-StatusSafe "동기화 실패: 결과 없음"
            return
        }

        $ok = $false
        try { $ok = [bool]$Result.Ok } catch { $ok = $false }

        if (-not $ok) {
            $err = ''
            try { $err = [string]$Result.Error } catch { $err = 'unknown' }
            if ($err.Length -gt 80) { $err = $err.Substring(0, 80) + '...' }
            Write-AppLog -Level ERROR -Message ("백그라운드 폴링 실패: " + $err)
            Set-StatusSafe ("동기화 오류: " + $err)
            return
        }

        $body = ''
        try { $body = [string]$Result.Body } catch { $body = '' }
        $lastMsgId = ''
        $startYmd = ''
        try { $lastMsgId = [string]$Result.LastMsgId } catch { }
        try { $startYmd = [string]$Result.StartYmd } catch { }

        $rows = @(ConvertFrom-PollJsonBody -Body $body)
        Complete-MessagePollFromRows -RawList $rows -LastMsgId $lastMsgId -StartYmd $startYmd
    }
    catch {
        Write-AppLog -Level ERROR -Message "폴링 완료 처리 예외" -Exception $_.Exception
        $err = $_.Exception.Message
        if ($err.Length -gt 80) { $err = $err.Substring(0, 80) + '...' }
        Set-StatusSafe ("동기화 오류: " + $err)
    }
    finally {
        try { Save-AppStateDirty } catch {
            Write-AppLog -Level ERROR -Message "poll flush failed" -Exception $_.Exception
        }
        $script:isPolling = $false
        $script:PollAsyncRunning = $false
        $script:PollAsyncResult = $null
    }
}

function Invoke-PollTimerTick {
    if ($script:IsExiting) { return }
    if ($script:isSending) { return }

    # 백그라운드 PowerShell runspace 완료 체크
    if ($null -ne $script:PollPsHandle -and $script:PollPsHandle.IsCompleted) {
        $script:isPolling = $true
        try {
            $ps = $script:PollPsInstance
            $handle = $script:PollPsHandle
            $script:PollPsHandle = $null
            $script:PollPsInstance = $null
            $script:PollAsyncRunning = $false
            $out = $null
            try { $out = $ps.EndInvoke($handle) }
            catch {
                Write-AppLog -Level ERROR -Message "poll EndInvoke 실패" -Exception $_.Exception
                Update-StatusStripInfo -Prefix '동기화 오류'
                return
            }
            finally { try { $ps.Dispose() } catch { } }

            $res = $null
            if ($out -and @($out).Count -gt 0) { $res = @($out)[0] }
            $ok = $false; $body = $null; $err = $null; $lat = 0
            try {
                if ($res -is [hashtable]) {
                    $ok = [bool]$res['Ok']; $body = $res['Body']; $err = $res['Error']; $lat = [int]$res['LatencyMs']
                } else {
                    $ok = [bool]$res.Ok; $body = $res.Body; $err = $res.Error; $lat = [int]$res.LatencyMs
                }
            } catch { $ok = $false; $err = 'bad result' }

            $ctx = $script:PollBgContext
            $script:PollBgContext = $null
            if (-not $ok) {
                $em = [string]$err
                if ($em.Length -gt 80) { $em = $em.Substring(0, 80) + '...' }
                Write-AppLog -Level ERROR -Message ("백그라운드 폴링 실패: " + $em)
                $script:ApiFailCount = [int]$script:ApiFailCount + 1
                $script:ApiLastError = $em
                Update-StatusStripInfo -Prefix ('동기화 오류: ' + $em)
            } else {
                $script:ApiLastLatencyMs = $lat
                $script:ApiCallCount = [int]$script:ApiCallCount + 1
                $script:ApiLastError = ''
                $rows = @(ConvertFrom-PollJsonBody -Body ([string]$body))
                $lastId = ''; $startYmd = ''
                if ($ctx) {
                    try { $lastId = [string]$ctx.LastMsgId } catch { }
                    try { $startYmd = [string]$ctx.StartYmd } catch { }
                }
                Complete-MessagePollFromRows -RawList $rows -LastMsgId $lastId -StartYmd $startYmd
            }
        }
        catch {
            Write-AppLog -Level ERROR -Message "폴링 결과 처리 예외" -Exception $_.Exception
            Update-StatusStripInfo -Prefix '동기화 처리 오류'
        }
        finally {
            try { Save-AppStateDirty } catch { }
            $script:isPolling = $false
            $script:PollAsyncRunning = $false
        }
        return
    }

    if ($script:isPolling -or $script:PollAsyncRunning) { return }

    if ($script:UseBackgroundPoll -and ("InternalChatPollHttp" -as [type])) {
        Start-MessagePollBackground
    }
    else {
        $script:isPolling = $true
        try { Invoke-MessagePoll }
        catch {
            $err = $_.Exception.Message
            if ($err.Length -gt 80) { $err = $err.Substring(0, 80) + '...' }
            Write-AppLog -Level ERROR -Message "폴링 예외: $($_.Exception.Message)" -Exception $_.Exception
            Update-StatusStripInfo -Prefix ('동기화 오류: ' + $err)
        }
        finally {
            try { Save-AppStateDirty } catch { }
            $script:isPolling = $false
        }
    }
}

function Start-MessagePollAsync { Start-MessagePollBackground }

function Start-MessagePollBackground {
    # 별도 PowerShell runspace에서 HTTP GET 실행
    if ($script:IsExiting) { return }
    if ($script:isPolling -or $script:PollAsyncRunning) { return }
    if ($script:isSending) { return }
    if (-not ("InternalChatPollHttp" -as [type])) {
        $script:UseBackgroundPoll = $false
        $script:isPolling = $true
        try { Invoke-MessagePoll } finally {
            try { Save-AppStateDirty } catch { }
            $script:isPolling = $false
        }
        return
    }

    $sync = Get-SyncState
    $startYmd = ''; $lastMsgId = ''
    if ($sync) {
        $startYmd  = [string](Get-ObjectProperty -Object $sync -Name 'lastSync' -Default '')
        $lastMsgId = [string](Get-ObjectProperty -Object $sync -Name 'lastMessageId' -Default '')
        if (-not $lastMsgId) { $lastMsgId = '' }
    }
    $uri = Get-MessageListUri -StartYmd $startYmd
    $cookieHeader = Get-SessionCookieHeader
    $timeoutMs = 30000
    try {
        if ($script:RequestTimeoutSec -gt 0) {
            $timeoutMs = [Math]::Min(30000, [int]$script:RequestTimeoutSec * 1000)
        }
    } catch { }

    $script:isPolling = $true
    $script:PollAsyncRunning = $true
    $script:PollBgContext = [PSCustomObject]@{ LastMsgId = $lastMsgId; StartYmd = $startYmd; Uri = $uri }
    Update-StatusStripInfo -Prefix '동기화 중...'
    Write-AppLog -Level DEBUG -Message ("poll bg start " + $uri)

    try {
        $ps = [PowerShell]::Create()
        [void]$ps.AddScript({
            param($U, $C, $T)
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $body = [InternalChatPollHttp]::Get([string]$U, [string]$C, [int]$T)
                $sw.Stop()
                return @{ Ok = $true; Body = $body; Error = $null; LatencyMs = [int]$sw.ElapsedMilliseconds }
            } catch {
                $sw.Stop()
                return @{ Ok = $false; Body = $null; Error = $_.Exception.Message; LatencyMs = [int]$sw.ElapsedMilliseconds }
            }
        }).AddArgument($uri).AddArgument($cookieHeader).AddArgument($timeoutMs)
        $script:PollPsInstance = $ps
        $script:PollPsHandle = $ps.BeginInvoke()
    } catch {
        Write-AppLog -Level WARN -Message "백그라운드 폴링 시작 실패 - 동기" -Exception $_.Exception
        $script:UseBackgroundPoll = $false
        $script:PollAsyncRunning = $false
        try { Invoke-MessagePoll } catch {
            Write-AppLog -Level ERROR -Message "동기 폴링 실패" -Exception $_.Exception
        } finally {
            try { Save-AppStateDirty } catch { }
            $script:isPolling = $false
        }
    }
}



function Add-MessagesToChatUi {
    # 현재 열린 ChatForm에만 메시지 append
    param([array]$Messages)

    if (-not (Test-ChatFormVisible)) { return }
    if (-not $script:ChatRichTextBox -or $script:ChatRichTextBox.IsDisposed) { return }

    foreach ($msg in $Messages) {
        try {
            Add-ChatMessageToView -WebBrowser $script:ChatRichTextBox -Message $msg -ScrollToEnd
            $script:ChatLoadedMessages = @($script:ChatLoadedMessages) + @($msg)
        }
        catch {
            Write-AppLog -Level ERROR -Message "WebBrowser Append 실패" -Exception $_.Exception
        }
    }
}

function Show-NewMessageBalloon {
    # 트레이 풍선 알림
    param([array]$Messages)
    if (-not $script:NotifyIcon) { return }
    if (-not $Messages -or @($Messages).Count -eq 0) { return }
    $arr = @($Messages)
    $latest = $arr | Select-Object -Last 1
    $sender = if ($latest.ac) { [string]$latest.ac } else { '알 수 없음' }
    $titlePart = if ($latest.ad) { [string]$latest.ad } else {
        $plain = ConvertFrom-HtmlToPlainText -Html ([string]$latest.ah)
        if ($plain.Length -gt 40) { $plain.Substring(0, 40) + '...' } else { $plain }
    }
    if ($titlePart.Length -gt 50) { $titlePart = $titlePart.Substring(0, 50) + '...' }
    $count = $arr.Count
    $body = if ($count -gt 1) { "{0}: {1} 외 {2}건" -f $sender, $titlePart, ($count - 1) } else { "{0}: {1}" -f $sender, $titlePart }
    try {
        $md5 = $null
        if ($latest.ai) { $md5 = [string]$latest.ai }
        if (-not $md5) { $md5 = Resolve-MessageConversationKey -Message $latest -CurrentUserId $script:CurrentUserId }
        $script:LastBalloonMd5 = $md5
    } catch { $script:LastBalloonMd5 = $null }
    try {
        $script:NotifyIcon.ShowBalloonTip(5000, '새 쪽지가 도착했습니다', $body, [System.Windows.Forms.ToolTipIcon]::Info)
    } catch {
        Write-AppLog -Level WARN -Message "BalloonTip 표시 실패" -Exception $_.Exception
    }
}

function Open-LastBalloonConversation {
    # 풍선 클릭 → 해당 대화 열기
    if ($script:IsExiting) { return }
    $md5 = $script:LastBalloonMd5
    if ([string]::IsNullOrWhiteSpace($md5)) { Restore-MainForm; return }
    try { Restore-MainForm; Open-ChatForm -Md5 $md5 } catch {
        Write-AppLog -Level WARN -Message "Balloon 클릭 대화 열기 실패" -Exception $_.Exception
    }
}


# -- 6. 메시지 전송 --------------------------------------------------------------
function Invoke-ChatSend {
    # 입력창 내용 전송. API 성공 후에만 UI 반영
    if ($script:isSending) { return }
    if (-not $script:CurrentChatMD5) {
        Show-InfoMessage -Text '대화가 선택되지 않았습니다.'
        return
    }
    if (-not $script:ChatInputBox -or $script:ChatInputBox.IsDisposed) { return }

    $text = $script:ChatInputBox.Text
    if ([string]::IsNullOrWhiteSpace($text)) { return }

    $script:isSending = $true
    try {
        $conv = Get-ConversationByMd5 -Md5 $script:CurrentChatMD5
        if (-not $conv) {
            Show-ErrorMessage -Text '대화 정보를 찾을 수 없습니다.'
            return
        }

        $receivers = @($conv.participantIds | Where-Object { $_ -ne $script:CurrentUserId })
        if ($receivers.Count -eq 0) {
            Show-ErrorMessage -Text '수신자가 없습니다.'
            return
        }

        $recvNames = @()
        if ($conv.participantNames) {
            $pIds = @($conv.participantIds)
            $pNms = @($conv.participantNames)
            foreach ($rid in $receivers) {
                $nm = $rid
                for ($i = 0; $i -lt $pIds.Count; $i++) {
                    if ($pIds[$i] -eq $rid -and $i -lt $pNms.Count) { $nm = [string]$pNms[$i]; break }
                }
                $recvNames += $nm
            }
        }

        # API 호출 전 로컬 메시지를 먼저 UI에 표시 (낙관적 업데이트)
        $serverId = "LOCAL-{0:yyyyMMddHHmmssfff}" -f (Get-Date)
        $plain = $text.Trim()
        $title = if ($plain.Length -gt 10) { $plain.Substring(0, 10) } else { $plain }

        $ym = Get-Date -Format 'yyyyMM'
        $msg = [PSCustomObject]@{
            aa    = $serverId
            ab    = $script:CurrentUserId
            ac    = $script:CurrentUserName
            ad    = ''
            ae    = (Get-Date).ToString('o')
            af    = $receivers
            ag    = $recvNames
            ah    = (ConvertTo-HtmlLineBreaks -Text $text)
            ai    = $script:CurrentChatMD5
            isOwn = $true
        }

        [void](Add-ChatMessage -Md5 $script:CurrentChatMD5 -Message $msg -YearMonth $ym)

        $preview = Get-MessagePreviewText -Message $msg
        Update-ConversationMeta `
            -Md5 $script:CurrentChatMD5 `
            -LastMonth $ym `
            -LastMessageTime $msg.ae `
            -LastSeq $serverId `
            -LastPreview $preview `
            -ClearUnread

        if (Test-ChatFormVisible -and $script:ChatRichTextBox -and -not $script:ChatRichTextBox.IsDisposed) {
            Add-ChatMessageToView -WebBrowser $script:ChatRichTextBox -Message $msg -ScrollToEnd
            $script:ChatLoadedMessages = @($script:ChatLoadedMessages) + @($msg)
        }

        $script:ChatInputBox.Clear()
        Update-ConversationListUi

        [System.Windows.Forms.Application]::DoEvents()
        Set-StatusSafe "전송 중..."
        $result = Send-ApiMessage -ReceiverIds $receivers -ReceiverNames $recvNames -BodyText $text

        Set-StatusSafe "전송 완료"
        Write-AppLog -Level INFO -Message "메시지 전송 성공 md5=$($script:CurrentChatMD5)"
    }
    catch {
        Write-AppLog -Level ERROR -Message "메시지 전송 실패" -Exception $_.Exception
        Show-ErrorMessage -Text "전송에 실패했습니다.`n$($_.Exception.Message)"
        Set-StatusSafe "전송 실패"
    }
    finally {
        try { Save-AppStateDirty } catch { Write-AppLog -Level ERROR -Message "send flush failed" -Exception $_.Exception }
        $script:isSending = $false
    }
}

# -- 7. 종료 --------------------------------------------------------------------
function Exit-Application {
    # 트레이 메뉴 → 종료
    if ($script:IsExiting) { return }
    $script:IsExiting = $true
    Write-AppLog -Level INFO -Message "사용자 종료 요청 (트레이 메뉴)"
    Complete-ApplicationShutdown
    try {
        if ($script:LifetimeForm -and -not $script:LifetimeForm.IsDisposed) {
            $script:LifetimeForm.Close()
        }
    } catch { }
    try {
        if ($script:AppContext) {
            $script:AppContext.ExitThread()
        }
    } catch { }
    try {
        [System.Windows.Forms.Application]::Exit()
    } catch { }
}

function Complete-ApplicationShutdown {
    # 타이머 중지, 컨트롤 Dispose, 민감 정보 정리
    Write-AppLog -Level INFO -Message "===== InternalChat 종료 처리 ====="

    $script:IsExiting = $true

    try { Save-MainWindowBounds } catch { }
    try { Save-AppStateDirty } catch { }

    try {
        if ($script:PollTimer) {
            $script:PollTimer.Stop()
            $script:PollTimer.Dispose()
            $script:PollTimer = $null
        }
    }
    catch { }

    # 백그라운드 HTTP 완료 대기 (~0.5s)
    try {
        $wait = 0
        while ($script:PollAsyncRunning -and $wait -lt 10) {
            Start-Sleep -Milliseconds 50
            $wait++
        }
    } catch { }
    $script:isPolling = $false
    $script:PollAsyncRunning = $false

    try {
        if ($script:NotifyIcon) {
            $script:NotifyIcon.Visible = $false
            $script:NotifyIcon.Dispose()
            $script:NotifyIcon = $null
        }
    }
    catch { }

    try {
        if ($script:ChatForm -and -not $script:ChatForm.IsDisposed) {
            $script:ChatForm.Dispose()
            $script:ChatForm = $null
        }
    }
    catch { }

    try {
        if ($script:MainForm -and -not $script:MainForm.IsDisposed) {
            $script:MainForm.Dispose()
            $script:MainForm = $null
        }
    }
    catch { }

    try {
        if ($script:LifetimeForm -and -not $script:LifetimeForm.IsDisposed) {
            $script:LifetimeForm.Dispose()
            $script:LifetimeForm = $null
        }
    }
    catch { }

    try {
        Clear-SensitiveMemory
    }
    catch { }

    try {
        if ($script:ChatFontMeta)  { $script:ChatFontMeta.Dispose(); $script:ChatFontMeta = $null }
        if ($script:ChatFontBody)  { $script:ChatFontBody.Dispose(); $script:ChatFontBody = $null }
        if ($script:ChatFontTitle) { $script:ChatFontTitle.Dispose(); $script:ChatFontTitle = $null }
    }
    catch { }

    try {
        if ($script:SingleInstanceMutex) {
            try { [void]$script:SingleInstanceMutex.ReleaseMutex() } catch { }
            try { $script:SingleInstanceMutex.Dispose() } catch { }
            $script:SingleInstanceMutex = $null
        }
    } catch { }

    Write-AppLog -Level INFO -Message "===== InternalChat 종료 완료 ====="
}

# -- 8. 초기 동기화 --------------------------------------------------------------
function Invoke-InitialSync {
    # 로그인 직후 1회 동기 폴링
    try {
        $script:isPolling = $true
        Invoke-MessagePoll
    }
    catch {
        $err = $_.Exception.Message
        if ($err.Length -gt 80) { $err = $err.Substring(0, 80) + '...' }
        Write-AppLog -Level ERROR -Message "초기 동기화 실패: $($_.Exception.Message)" -Exception $_.Exception
        Set-StatusSafe ("초기 동기화 실패: " + $err)
    }
    finally {
        try { Save-AppStateDirty } catch {
            Write-AppLog -Level ERROR -Message "초기 동기화 flush 실패" -Exception $_.Exception
        }
        $script:isPolling = $false
    }
}

# ---- 메인 진입점 --------------------------------------------------------------
function Main {
    if ($SelfTest) {
        $code = Invoke-SelfTest
        exit $code
    }

    if (-not (Test-SingleInstance)) {
        try {
            [System.Windows.Forms.MessageBox]::Show(
                'InternalChat 이 이미 실행 중입니다.',
                'InternalChat',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
        } catch {
            Write-Host 'InternalChat is already running.'
        }
        return
    }

    Initialize-Application

    $loginOk = $false
    try { $loginOk = Start-UserLogin }
    catch {
        Write-AppLog -Level ERROR -Message "로그인 단계 예외" -Exception $_.Exception
        Show-ErrorMessage -Text "로그인 중 오류가 발생했습니다.`n$($_.Exception.Message)"
        $loginOk = $false
    }

    if (-not $loginOk) {
        Write-AppLog -Level INFO -Message "로그인 실패/취소로 종료"
        return
    }

    $form = New-MainForm
    Initialize-UserCache
    Update-UserListUi
    Update-ConversationListUi
    Invoke-InitialSync
    $script:LastSyncTimeText = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $script:PollTimer.Start()
    Write-AppLog -Level INFO -Message "폴링 타이머 시작 interval=$($script:PollIntervalMs)ms"
    Update-StatusStripInfo -Prefix ("준비 완료 - " + $script:CurrentUserName)

    # 숨겨진 LifetimeForm으로 메시지 루프 유지 (트레이 상주)
    $life = New-Object System.Windows.Forms.Form
    $life.Text = 'InternalChatLifetime'
    $life.ShowInTaskbar = $false
    $life.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedToolWindow
    $life.Opacity = 0
    $life.Size = New-Object System.Drawing.Size(1, 1)
    $life.StartPosition = [System.Windows.Forms.FormStartPosition]::Manual
    $life.Location = New-Object System.Drawing.Point(-32000, -32000)
    $life.Add_FormClosing({
        if ($script:IsExiting) { return }
        if ($args.Count -ge 2 -and $null -ne $args[1]) { $args[1].Cancel = $true }
    })
    $script:LifetimeForm = $life
    $script:AppContext = New-Object System.Windows.Forms.ApplicationContext($life)
    $form.Show()
    $form.Activate()

    try {
        if (-not $script:UnhandledHooked) {
            $script:UnhandledHooked = $true
            [System.Windows.Forms.Application]::SetUnhandledExceptionMode(
                [System.Windows.Forms.UnhandledExceptionMode]::CatchException
            )
            [System.Windows.Forms.Application]::add_ThreadException({
                param($sender, $e)
                try {
                    Write-AppLog -Level ERROR -Message ("UI ThreadException: " + $e.Exception.Message) -Exception $e.Exception
                    Set-StatusSafe ("오류: " + $e.Exception.Message)
                } catch { }
            })
        }
    } catch { }

    Write-AppLog -Level INFO -Message "메시지 루프 시작 (트레이 상주)"
    [System.Windows.Forms.Application]::Run($script:AppContext)
    Write-AppLog -Level INFO -Message "메시지 루프 종료"

    if (-not $script:IsExiting) {
        $script:IsExiting = $true
        Complete-ApplicationShutdown
    }
}


# 실행
try {
    Main
}
catch {
    try { Write-AppLog -Level ERROR -Message "치명적 오류" -Exception $_.Exception } catch { }
    try {
        [System.Windows.Forms.MessageBox]::Show(
            "치명적 오류가 발생했습니다.`n$($_.Exception.Message)",
            "InternalChat",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
    }
    catch {
        Write-Host "치명적 오류: $($_.Exception.Message)" -ForegroundColor Red
    }
    exit 1
}