#requires -version 5.1
<#
.SYNOPSIS
    내부망 채팅 클라이언트 (단일 파일 B안)
.DESCRIPTION
    순수 PowerShell 5.1 + Windows Forms. 외부 모듈 없음.
    Logger / Security / DataManager / ApiClient / UiHelper 를 이 파일에 인라인.
    실행: powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File .\InternalChat.ps1
.NOTES
    인코딩: CP949 (Windows PowerShell 5.1)
    모듈 폴더(modules/)는 참고용이며, 이 파일만으로 동작한다.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# 어셈블리 / 경로
# ---------------------------------------------------------------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Security
[System.Windows.Forms.Application]::EnableVisualStyles()


# ###########################################################################
# [설정] 기본 서버 (미저장 시). 이후 data/config.json 우선
# ###########################################################################
$script:ApiBase = 'http://localhost:9080/orca'
$script:PathLogin       = '/cmn/login/login.do'
$script:PathUserList    = '/note/retrieveSearchList.do?rows=999&page=1&s_prjt_id=PROJECT'
$script:PathMessageList = '/note/retrieveNoteListJson.do?nd=&rows=9999&page=1'
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

# ###########################################################################
# 이하 구현부
# ###########################################################################
# ###########################################################################
# 이하 구현부 (설정 변경 없이 동작)
# ###########################################################################


# ###########################################################################
# 인라인 라이브러리 (구 modules/*.psm1)
# ###########################################################################

# ===========================================================================
# 모듈 인라인: Logger
# ===========================================================================
<#
.SYNOPSIS
    애플리케이션 로그 모듈
.DESCRIPTION
    파일 및 콘솔에 로그를 기록한다. 폴링/UI 예외 시에도 안전하게 동작해야 한다.
#>

$script:LogDirectory = $null
$script:LogFilePath  = $null

function Initialize-AppLogger {
    <#
    .SYNOPSIS
        로그 디렉터리와 당일 로그 파일을 초기화한다.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogDirectory
    )

    $script:LogDirectory = $LogDirectory

    if (-not (Test-Path -LiteralPath $script:LogDirectory)) {
        New-Item -ItemType Directory -Path $script:LogDirectory -Force | Out-Null
    }

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



# ===========================================================================
# 모듈 인라인: Security
# ===========================================================================
<#
.SYNOPSIS
    자격 증명 암호화 및 데이터 폴더 ACL 모듈
.DESCRIPTION
    DPAPI(ProtectedData)로 자격 증명을 보호하고, data 폴더 ACL을 현재 사용자만 접근 가능하도록 설정한다.
#>

$script:CredentialFilePath = $null
$script:MemoryToken        = $null
$script:MemoryUserId       = $null
$script:MemoryPassword     = $null

function Initialize-SecurityModule {
    <#
    .SYNOPSIS
        보안 모듈 경로를 초기화한다.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$DataDirectory
    )

    $script:CredentialFilePath = Join-Path $DataDirectory 'credentials.dat'
}


function Protect-StringData {
    <#
    .SYNOPSIS
        평문 문자열을 DPAPI로 암호화하여 Base64 문자열로 반환한다.
    #>
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
    <#
    .SYNOPSIS
        DPAPI로 암호화된 Base64 문자열을 평문으로 복호화한다.
    #>
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
    <#
    .SYNOPSIS
        사용자 ID/PW를 암호화하여 파일에 저장한다.
    #>
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
    <#
    .SYNOPSIS
        저장된 자격 증명을 복호화하여 반환한다. 없으면 $null.
    .OUTPUTS
        PSCustomObject { UserId, Password } 또는 $null
    #>

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

function Test-CredentialExists {
    <#
    .SYNOPSIS
        자격 증명 파일 존재 여부를 반환한다.
    #>
    return ($script:CredentialFilePath -and (Test-Path -LiteralPath $script:CredentialFilePath))
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
    <#
    .SYNOPSIS
        data/config.json 로드. 없으면 $null.
    #>
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
    <#
    .SYNOPSIS
        서버 주소(apiBase)를 data/config.json 에 저장.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiBase
    )
    $p = Get-AppConfigPath
    if (-not $p) { throw 'ConfigPath not initialized' }
    $base = $ApiBase.Trim().TrimEnd('/')
    $payload = (@{ apiBase = $base } | ConvertTo-Json -Compress)
    Set-Content -LiteralPath $p -Value $payload -Encoding UTF8 -Force
    Write-AppLog -Level INFO -Message "설정 저장 apiBase=$base"
}

function Set-ApiBaseAddress {
    <#
    .SYNOPSIS
        ApiBase 설정 후 URL 재계산.
    #>
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
    <#
    .SYNOPSIS
        저장된 apiBase 가 있으면 적용.
    #>
    $cfg = Get-AppConfig
    if (-not $cfg) { return }
    $base = ''
    try {
        if ($null -ne $cfg.apiBase) { $base = [string]$cfg.apiBase }
    } catch { }
    if (-not [string]::IsNullOrWhiteSpace($base)) {
        [void](Set-ApiBaseAddress -ApiBase $base)
    }
}

function Set-AuthToken {
    param([string]$Token)
    $script:MemoryToken = $Token
}

function Get-AuthToken {
    return $script:MemoryToken
}

function Clear-AuthToken {
    $script:MemoryToken = $null
}


function Clear-SensitiveMemory {
    <#
    .SYNOPSIS
        종료 시 메모리 내 민감 정보를 비운다.
    #>
    $script:MemoryToken    = $null
    $script:MemoryPassword = $null
}


# ===========================================================================
# 모듈 인라인: DataManager
# ===========================================================================
<#
.SYNOPSIS
    로컬 JSON 데이터 관리 모듈
.DESCRIPTION
    conversations / users / sync / chat 월별 파일을 안전하게 읽고 쓴다.
    Save-JsonSafely: temp 파일 작성 후 rename으로 원자적 저장.
#>

$script:DataDirectory  = $null
$script:ChatsDirectory = $null
$script:ConversationsPath = $null
$script:UsersPath         = $null
$script:SyncPath          = $null

#region 초기화

function Initialize-DataManager {
    <#
    .SYNOPSIS
        데이터 경로를 설정하고 필요 시 기본 파일을 생성한다.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$DataDirectory
    )

    $script:DataDirectory     = $DataDirectory
    $script:ChatsDirectory    = Join-Path $DataDirectory 'chats'
    $script:ConversationsPath = Join-Path $DataDirectory 'conversations.json'
    $script:UsersPath         = Join-Path $DataDirectory 'users.json'
    $script:SyncPath          = Join-Path $DataDirectory 'sync.json'

    # 디렉터리 생성 책임은 메인(Initialize-Application). 없을 때만 방어적으로 생성.
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

#endregion

#region 안전한 JSON I/O

function Save-JsonSafely {
    <#
    .SYNOPSIS
        JSON을 임시 파일에 기록한 뒤 rename하여 안전하게 저장한다.
        기존 파일이 있으면 .bak 백업을 남긴다. (Save-JsonSafely 패턴)
    #>
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
        # Depth 충분히 확보 (PS 5.1 기본 Depth=2 제한 회피)
        ConvertTo-Json -InputObject $Object -Depth 20 -Compress:$false
    }

    $tempPath = "$Path.tmp"
    $bakPath  = "$Path.bak"

    try {
        # UTF-8 without BOM (PS 5.1 호환)
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($tempPath, $json, $utf8NoBom)

        if (Test-Path -LiteralPath $Path) {
            Copy-Item -LiteralPath $Path -Destination $bakPath -Force
        }

        # rename (원자적 교체 시도)
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
    <#
    .SYNOPSIS
        JSON을 로드한다. 실패 시 .bak 복원을 시도하고, 그래도 실패하면 DefaultValue를 반환한다.
    #>
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
                # 복원된 내용을 본 파일에 다시 기록
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

#endregion

#region MD5 / Conversation Key

function Get-ConversationMD5 {
    <#
    .SYNOPSIS
        참가자 ID 배열로부터 대화 고유 MD5 키를 생성한다.
        정렬 후 파이프(|) 연결 -> MD5 해시 (소문자 hex).
    #>
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
    <#
    .SYNOPSIS
        chats/{md5}_{yyyyMM}.jsonl 경로를 반환한다. (메시지 append 로그)
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Md5,

        [Parameter(Mandatory = $false)]
        [string]$YearMonth = (Get-Date -Format 'yyyyMM')
    )

    return (Join-Path $script:ChatsDirectory ("{0}_{1}.jsonl" -f $Md5, $YearMonth))
}

function Get-ChatLegacyFilePath {
    <#
    .SYNOPSIS
        구형 chats/{md5}_{yyyyMM}.json 경로 (마이그레이션용).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Md5,

        [Parameter(Mandatory = $false)]
        [string]$YearMonth = (Get-Date -Format 'yyyyMM')
    )

    return (Join-Path $script:ChatsDirectory ("{0}_{1}.json" -f $Md5, $YearMonth))
}

#endregion

#region sync.json

function Get-SyncState {
    <#
    .SYNOPSIS
        sync.json을 로드한다. 없으면 $null.
    #>
    if (-not (Test-Path -LiteralPath $script:SyncPath)) {
        return $null
    }
    return (Import-JsonSafely -Path $script:SyncPath -DefaultValue $null)
}

function Save-SyncState {
    <#
    .SYNOPSIS
        동기화 상태를 저장한다.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$LastSync,

        [Parameter(Mandatory = $true)]
        [string]$LastMessageId,

        [Parameter(Mandatory = $true)]
        [string]$CurrentUserId
    )

    $obj = [ordered]@{
        lastSync      = $LastSync
        lastMessageId = $LastMessageId
        currentUserId = $CurrentUserId
    }
    Save-JsonSafely -Path $script:SyncPath -Object $obj
}

#endregion

#region conversations.json

function Get-Conversations {
    <#
    .SYNOPSIS
        대화 목록 배열을 반환한다.
    #>
    $data = Import-JsonSafely -Path $script:ConversationsPath -DefaultValue @()
    if ($null -eq $data) { return @() }
    # 단일 객체로 파싱된 경우 배열로 감싼다
    if ($data -isnot [System.Array]) {
        return @($data)
    }
    return @($data)
}

function Save-Conversations {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$Conversations
    )
    Save-JsonSafely -Path $script:ConversationsPath -Object @($Conversations)
}

function Get-ConversationByMd5 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Md5
    )
    $list = Get-Conversations
    return ($list | Where-Object { $_.md5 -eq $Md5 } | Select-Object -First 1)
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
    <#
    .SYNOPSIS
        대화 메타 PSCustomObject 를 새로 만든다 (JSON 객체 직접 수정 회피).
    #>
    param(
        [string]$Md5,
        [string[]]$ParticipantIds = @(),
        [string[]]$ParticipantNames = @(),
        [string]$CustomTitle = '',
        [bool]$TitleLocked = $false,
        [string]$LastMonth = '',
        [bool]$Unread = $false,
        [string]$LastMessageTime = '',
        [string]$LastSeq = ''
    )
    if (-not $LastMonth) { $LastMonth = Get-Date -Format 'yyyyMM' }
    return [PSCustomObject]@{
        md5              = $Md5
        participantIds   = @($ParticipantIds)
        participantNames = @($ParticipantNames)
        customTitle      = $CustomTitle
        titleLocked      = $TitleLocked
        lastMonth        = $LastMonth
        unread           = $Unread
        lastMessageTime  = $LastMessageTime
        lastSeq          = $LastSeq
    }
}

function Update-ConversationMeta {
    <#
    .SYNOPSIS
        대화 메타 삽입/갱신. -LockTitle 이면 customTitle 수동 고정.
    #>
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
        [switch]$IncrementUnread,
        [switch]$ClearUnread,
        [switch]$LockTitle
    )

    $list = @(Get-Conversations)
    $idx = -1
    for ($i = 0; $i -lt @($list).Count; $i++) {
        if ([string]$list[$i].md5 -eq $Md5) { $idx = $i; break }
    }

    if ($idx -lt 0) {
        $unreadVal = $false
        if ($ClearUnread) { $unreadVal = $false }
        elseif ($IncrementUnread) { $unreadVal = $true }
        else { $unreadVal = $Unread }

        $rec = New-ConversationRecord `
            -Md5 $Md5 `
            -ParticipantIds $ParticipantIds `
            -ParticipantNames $ParticipantNames `
            -CustomTitle $CustomTitle `
            -TitleLocked ([bool]$LockTitle) `
            -LastMonth $LastMonth `
            -Unread $unreadVal `
            -LastMessageTime $LastMessageTime `
            -LastSeq $LastSeq
        $list = @($list) + @($rec)
    }
    else {
        $ex = $list[$idx]
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
        if ($ClearUnread) { $unreadVal = $false }
        elseif ($IncrementUnread) { $unreadVal = $true }
        elseif ($PSBoundParameters.ContainsKey('Unread')) { $unreadVal = $Unread }

        $lm = if ($LastMonth) { $LastMonth } else { [string](Get-ConvProp $ex 'lastMonth' (Get-Date -Format 'yyyyMM')) }
        $lmt = if ($LastMessageTime) { $LastMessageTime } else { [string](Get-ConvProp $ex 'lastMessageTime' '') }
        $lseq = if ($LastSeq) { $LastSeq } else { [string](Get-ConvProp $ex 'lastSeq' '') }

        $list[$idx] = New-ConversationRecord `
            -Md5 $Md5 `
            -ParticipantIds $pIds `
            -ParticipantNames $pNms `
            -CustomTitle $title `
            -TitleLocked $locked `
            -LastMonth $lm `
            -Unread $unreadVal `
            -LastMessageTime $lmt `
            -LastSeq $lseq
    }

    $sorted = @($list | Sort-Object {
        $t = Get-ConvProp $_ 'lastMessageTime' $null
        if ($t) { try { [datetime]$t } catch { [datetime]::MinValue } } else { [datetime]::MinValue }
    } -Descending)

    Save-Conversations -Conversations $sorted
}

function Edit-SelectedConversationTitle {
    <#
    .SYNOPSIS
        대화 목록 선택 항목의 customTitle 수정 (우클릭 메뉴).
    #>
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
    <#
    .SYNOPSIS
        현재 대화 참여자 목록을 MessageBox 로 표시.
    #>
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
    <#
    .SYNOPSIS
        특정 대화의 unread 플래그를 해제한다.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Md5
    )
    Update-ConversationMeta -Md5 $Md5 -ClearUnread
}

#endregion

#region users.json

function Get-Users {
    $data = Import-JsonSafely -Path $script:UsersPath -DefaultValue @()
    if ($null -eq $data) { return @() }
    if ($data -isnot [System.Array]) { return @($data) }
    return @($data)
}

function Save-Users {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$Users
    )
    Save-JsonSafely -Path $script:UsersPath -Object @($Users)
}

function Get-UserById {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id
    )
    return (Get-Users | Where-Object { $_.id -eq $Id } | Select-Object -First 1)
}

#endregion

#region 채팅 메시지 파일

function Get-ChatMessageIdCacheKey {
    param(
        [Parameter(Mandatory = $true)][string]$Md5,
        [Parameter(Mandatory = $true)][string]$YearMonth
    )
    return ('{0}|{1}' -f $Md5, $YearMonth)
}

function Clear-ChatMessageIdIndex {
    <#
    .SYNOPSIS
        메시지 ID 인덱스 캐시를 비운다. (전체 또는 특정 월)
    #>
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
    <#
    .SYNOPSIS
        메시지 객체를 JSONL 한 줄 문자열로 직렬화한다.
    #>
    param(
        [Parameter(Mandatory = $true)]$Message
    )
    return (($Message | ConvertTo-Json -Compress -Depth 8))
}

function Read-ChatMessagesJsonl {
    <#
    .SYNOPSIS
        JSONL 파일을 읽어 메시지 배열로 반환한다. 깨진 줄은 건너뛴다.
    #>
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
    <#
    .SYNOPSIS
        메시지 배열 전체를 JSONL로 원자적 저장 (temp -> replace).
    #>
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
    <#
    .SYNOPSIS
        JSONL 파일 끝에 메시지 1건을 append 한다.
    #>
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
    <#
    .SYNOPSIS
        구형 { messages: [] } JSON 또는 배열 JSON에서 메시지 목록 추출.
    #>
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
    <#
    .SYNOPSIS
        구형 .json 이 있고 .jsonl 이 없으면 JSONL 로 마이그레이션 후 .json.bak 처리.
    #>
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
            # 이동 실패해도 jsonl 이 있으면 동작 가능
        }
        Write-AppLog -Level INFO -Message ("채팅 파일 마이그레이션: " + $legacy + " -> " + $jsonl + " (" + $msgs.Count + "건)")
        Clear-ChatMessageIdIndex -Md5 $Md5 -YearMonth $YearMonth
    }
    catch {
        Write-AppLog -Level ERROR -Message ("채팅 마이그레이션 실패: " + $legacy) -Exception $_.Exception
    }
}

function Get-ChatMessageIdIndex {
    <#
    .SYNOPSIS
        md5+월 메시지 ID 집합(Hashtable). 없으면 디스크에서 구축.
        키는 대문자 정규화하여 대소문자 무시 비교.
    #>
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

function Get-ChatMessages {
    <#
    .SYNOPSIS
        특정 md5 + 월의 JSONL 메시지 배열을 반환한다.
        구형 .json 이 있으면 자동 마이그레이션한다.
    #>
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

function Save-ChatMessages {
    <#
    .SYNOPSIS
        채팅 메시지 배열 전체를 월별 JSONL 로 저장한다 (전체 재작성).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Md5,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$Messages,

        [Parameter(Mandatory = $false)]
        [string]$YearMonth = (Get-Date -Format 'yyyyMM')
    )

    $path = Get-ChatFilePath -Md5 $Md5 -YearMonth $YearMonth
    Write-ChatMessagesJsonl -Path $path -Messages @($Messages)
    Clear-ChatMessageIdIndex -Md5 $Md5 -YearMonth $YearMonth
    # 인덱스 재구축 (호출측 연속 Add 대비)
    [void](Get-ChatMessageIdIndex -Md5 $Md5 -YearMonth $YearMonth)
}

function Add-ChatMessage {
    <#
    .SYNOPSIS
        메시지를 월별 JSONL 에 append 한다. 동일 aa 가 있으면 건너뛴다.
    .OUTPUTS
        [bool] 실제로 추가되었으면 $true
    #>
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
    <#
    .SYNOPSIS
        특정 md5에 대해 존재하는 월 파일 목록을 최신순으로 반환한다.
        .jsonl 및 구형 .json 모두 인식.
    #>
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


#endregion

#region 유틸

function ConvertTo-HtmlLineBreaks {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $parts = $Text -split "`r?`n"
    return (($parts | ForEach-Object {
        $e = $_ -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;'
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
    $text = $text.Replace('&nbsp;', ' ').Replace('&lt;', '<').Replace('&gt;', '>').Replace('&amp;', '&')
    return $text.Trim()
}



#endregion


# ===========================================================================
# 모듈 인라인: ApiClient
# ===========================================================================
<#
.SYNOPSIS
    내부망 API 클라이언트 모듈
.DESCRIPTION
    Invoke-ApiRequest 래퍼로 재시도-401 재로그인을 통일 처리한다.
    외부 모듈 없이 Invoke-WebRequest / Invoke-RestMethod 만 사용한다.
#>

# TLS 1.2 강제 (구형 서버 호환)
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
catch { }

#region URL 조립 (값은 파일 상단 [설정] 사용)

function Initialize-ApiUrls {
    <#
    .SYNOPSIS
        상단 ApiBase + Path* 로 절대 URL 계산. (상세 조회 URL 없음)
    #>
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
    <#
    .SYNOPSIS
        401 시 재로그인 콜백 등록. $true/$false 반환.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Callback
    )
    $script:ReloginCallback = $Callback
}

#endregion

#region 핵심 래퍼

function Get-HttpResponseText {
    <#
    .SYNOPSIS
        Invoke-WebRequest 응답 본문을 UTF-8 우선으로 문자열화 (한글 깨짐 완화).
    #>
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

    # Content 가 이미 잘못된 디코딩인 경우: Default 바이트 -> UTF-8 복원 시도
    try {
        $bytes = [System.Text.Encoding]::Default.GetBytes($content)
        $utf8 = [System.Text.Encoding]::UTF8.GetString($bytes)
        # 한글 비율이 더 나아 보이면 채택 (깨진 대체문자 적으면)
        if ($utf8.Length -gt 0 -and ($utf8.ToCharArray() | Where-Object { [int][char]$_ -ge 0xAC00 -and [int][char]$_ -le 0xD7A3 } | Measure-Object).Count -ge 0) {
            # UTF-8 재해석 결과가 유효 JSON/문자면 사용
            if ($utf8.Contains('{') -or $utf8.Contains('[') -or $utf8 -match '[\uAC00-\uD7A3]') {
                return $utf8
            }
        }
    } catch { }

    return $content
}

function Invoke-ApiRequest {
    <#
    .SYNOPSIS
        API 공통 호출. ORCA 쿠키 세션 유지. 실패 시 응답 일부를 로그에 남김.
    #>
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
            $reqHeaders = @{}
            foreach ($k in $Headers.Keys) { $reqHeaders[$k] = $Headers[$k] }
            # jqGrid/AJAX 호출에서 자주 필요
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

            Write-AppLog -Level INFO -Message "API $Method $Uri (try=$attempt, hasSession=$([bool]$script:HttpSession))"

            # SessionVariable 사용 금지 (WebSession 과 충돌). 항상 WebRequestSession 객체만 사용.
            if (-not $script:HttpSession) {
                $script:HttpSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
            }
            $params['WebSession'] = $script:HttpSession
            $response = Invoke-WebRequest @params

            if ($RawResponse) { return $response }

            # PS 5.1 한글: Content 가 시스템 기본(CP949)으로 깨지는 경우 UTF-8 로 재해석
            $content = Get-HttpResponseText -Response $response
            if ([string]::IsNullOrWhiteSpace($content)) { return $null }

            # 로그인(SkipAuth)은 HTML 응답이 정상. 목록 API 가 HTML 이면 세션 무효.
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
    if ($lastError) { throw $lastError }
    throw "API 요청 실패: $Method $Uri"
}

#endregion

#region 도메인 API

function Invoke-ApiLogin {
    <#
    .SYNOPSIS
        ORCA 로그인. form POST user_id / pwd. 세션 쿠키 저장.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$UserId,
        [Parameter(Mandatory = $true)][string]$Password
    )

    # 새 로그인 시 세션 쿠키 컨테이너 새로 생성
    $script:HttpSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession

    $body = @{}
    $body['user_id']   = $UserId
    $body['pwd'] = $Password

    $result = Invoke-ApiRequest -Uri $script:LoginUrl -Method POST -Body $body -BodyFormat Form -SkipAuth

    # ORCA 로그인은 HTML 응답 + 쿠키 세션. 예외 없이 여기 오면 성공 처리.
    if (-not $script:HttpSession) {
        $script:HttpSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    }
    Set-AuthToken -Token 'SESSION'
    Write-AppLog -Level INFO -Message "로그인 성공(세션): $UserId"
    return $result
}

function Get-ApiRows {
    <#
    .SYNOPSIS
        jqGrid 형태 응답에서 rows 배열 추출. 항상 Object[] 반환.
    #>
    param($Result)
    if ($null -eq $Result) { return , @() }
    if ($Result -is [System.Array]) { return , @($Result) }
    $rows = Get-ObjectProperty -Object $Result -Name 'rows'
    if ($null -eq $rows) { return , @() }
    # 단건이면 배열로, 빈값 방지
    $arr = @($rows)
    if ($arr.Count -eq 1 -and $null -eq $arr[0]) { return , @() }
    return , $arr
}

function Get-ApiUserList {
    <#
    .SYNOPSIS
        사용자 목록 조회. rows[] 반환.
    #>
    Write-AppLog -Level INFO -Message "사용자목록 URI=$($script:GetUserListUrl)"
    $result = Invoke-ApiRequest -Uri $script:GetUserListUrl -Method GET -BodyFormat None
    $rows = Get-ApiRows -Result $result
    Write-AppLog -Level INFO -Message "사용자목록 rows=$($rows.Count)"
    return $rows
}

function Get-ApiMessageList {
    <#
    .SYNOPSIS
        쪽지 목록 조회. start_ymd 빈값=전체, yyyyMMdd=증분.
    #>
    param(
        [Parameter(Mandatory = $false)]
        [string]$StartYmd = ''
    )

    # 원 명세 순서: start_ymd 를 앞에 둠
    $ymd = if ($null -eq $StartYmd) { '' } else { $StartYmd }
    $base = $script:ApiBase.TrimEnd('/')
    $uri = $base + '/note/retrieveNoteListJson.do?start_ymd=' + [Uri]::EscapeDataString($ymd) + '&nd=&rows=9999&page=1'

    Write-AppLog -Level INFO -Message "쪽지목록 URI=$uri"
    $result = Invoke-ApiRequest -Uri $uri -Method GET -BodyFormat None
    $rows = Get-ApiRows -Result $result
    Write-AppLog -Level INFO -Message "쪽지목록 rows=$($rows.Count)"
    return $rows
}

function Send-ApiMessage {
    <#
    .SYNOPSIS
        쪽지 전송 form POST.
        subject=본문 평문 앞 10자, receiver/receiver_list/receiver_cnt, contents=HTML
        성공: rsltcode=success (note_id 없음 -> 이후 폴링으로 동기화)
    #>
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
    # files[] 두 건 비움: 일반 form 에서는 빈 문자열 키 전송
    $body['files[]'] = ''

    $result = Invoke-ApiRequest -Uri $script:SendMessageUrl -Method POST -Body $body -BodyFormat Form

    $code = Get-ObjectProperty -Object $result -Name 'rsltcode'
    if ($code -and ([string]$code -ne 'success')) {
        throw "전송 실패 rsltcode=$code"
    }

    Write-AppLog -Level INFO -Message "메시지 전송 완료 receivers=$($ids -join ',')"
    return $result
}

#region 메시지 정규화 (고정 스키마 aa~ai)

function Get-ObjectProperty {
    <#
    .SYNOPSIS
        StrictMode 안전 단일 속성 읽기.
    #>
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
    <#
    .SYNOPSIS
        ORCA 쪽지 rows -> 내부 스키마.
    .DESCRIPTION
        대화 목록 제목(convTitle): receiver 기본, receiver 가 나/나 외 n명이면 rgst_user_nm.
        메시지 본문 제목(ad): subject (10자=본문앞과 같으면 빈값).
    #>
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

    # 메시지 안 subject 표시 여부
    $plain = ConvertFrom-HtmlToPlainText -Html $ah
    $plainOneLine = ($plain -replace '\s+', ' ').Trim()
    $titleUse = $ad
    if ($ad -and $ad.Length -eq 10) {
        $head = if ($plainOneLine.Length -ge 10) { $plainOneLine.Substring(0, 10) } else { $plainOneLine }
        if ($ad -eq $head) { $titleUse = '' }
    }

    # 대화 목록 제목: receiver 기본, 나/나 외 n명 이면 보낸 사람명
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
    <#
    .SYNOPSIS
        대화목록 표시명. receiver 기본, 내가 수신측으로 보이면 rgst_user_nm(보낸사람).
    #>
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
    <#
    .SYNOPSIS
        대화 키 = r_id_list + rgst_user_id 를 모아 정렬·중복제거 후 MD5.
        동일 참가자 집합이면 하나의 대화.
    #>
    param(
        [Parameter(Mandatory = $true)]$Message,
        [Parameter(Mandatory = $true)][string]$CurrentUserId
    )

    $idList = New-Object System.Collections.ArrayList
    # 보낸 사람
    if ($Message.ab) {
        $s = [string]$Message.ab
        if ($s -and -not $idList.Contains($s)) { [void]$idList.Add($s) }
    }
    # 받는 사람들 r_id_list
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


#endregion

# ===========================================================================
# 모듈 인라인: UiHelper
# ===========================================================================
<#
.SYNOPSIS
    Windows Forms UI 헬퍼 모듈
.DESCRIPTION
    로그인 다이얼로그, ListView 갱신, RichTextBox 메시지 표시 등 UI 유틸.
    외부 모듈 없이 System.Windows.Forms / System.Drawing 만 사용한다.
#>

#region 로그인 다이얼로그

function Show-LoginDialog {
    <#
    .SYNOPSIS
        서버 주소 + ID/PW InputBox 입력.
    #>
    param(
        [string]$DefaultUserId = '',
        [string]$DefaultApiBase = ''
    )
    try { Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop } catch { }

    $defBase = if (-not [string]::IsNullOrWhiteSpace($DefaultApiBase)) { $DefaultApiBase.Trim() } else { [string]$script:ApiBase }
    $api = [Microsoft.VisualBasic.Interaction]::InputBox(
        '서버 주소 (예: http://host:9080/orca)',
        '서버 설정',
        $defBase
    )
    if ([string]::IsNullOrWhiteSpace($api)) { return $null }
    $api = $api.Trim().TrimEnd('/')
    if ($api -notmatch '^https?://') {
        [System.Windows.Forms.MessageBox]::Show(
            '서버 주소는 http:// 또는 https:// 로 시작해야 합니다.',
            '서버 설정',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        return $null
    }

    $uid = [Microsoft.VisualBasic.Interaction]::InputBox('사용자 ID', '로그인', $DefaultUserId)
    if ([string]::IsNullOrWhiteSpace($uid)) { return $null }
    $pw = [Microsoft.VisualBasic.Interaction]::InputBox('비밀번호', '로그인', '')
    if ([string]::IsNullOrWhiteSpace($pw)) { return $null }
    return [PSCustomObject]@{
        UserId   = $uid.Trim()
        Password = $pw
        ApiBase  = $api
    }
}



#endregion

#region ListView 헬퍼

function Initialize-ConversationListView {
    <#
    .SYNOPSIS
        대화 목록 ListView를 Details 뷰로 초기화한다.
    #>
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
    [void]$ListView.Columns.Add('대화', 180)
    [void]$ListView.Columns.Add('최근 메시지', 150)
    [void]$ListView.Columns.Add('안읽음', 50)
}

function Update-ConversationListView {
    <#
    .SYNOPSIS
        conversations 배열로 ListView를 갱신한다.
    #>
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

    $ListView.BeginUpdate()
    try {
        $ListView.Items.Clear()
        foreach ($c in $Conversations) {
            $title = Get-ConversationDisplayTitle -Conversation $c -CurrentUserId $CurrentUserId
            $timeStr = ''
            if ($c.lastMessageTime) {
                $timeStr = Format-MessageDateTime -Value $c.lastMessageTime
            }
            $unreadStr = if ($c.unread) { '●' } else { '' }

            $item = New-Object System.Windows.Forms.ListViewItem($title)
            [void]$item.SubItems.Add($timeStr)
            [void]$item.SubItems.Add($unreadStr)
            $item.Tag = [string]$c.md5

            [void]$ListView.Items.Add($item)

            if ($selectedMd5 -and $selectedMd5 -eq $c.md5) {
                $item.Selected = $true
            }
        }
    }
    finally {
        $ListView.EndUpdate()
    }
}

function Get-ConversationDisplayTitle {
    <#
    .SYNOPSIS
        대화 표시 제목을 결정한다 (customTitle 우선, 없으면 참가자 이름).
    #>
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

    # 본인 이름 제외 시도
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
    <#
    .SYNOPSIS
        사용자 목록 ListView (체크 가능)를 초기화한다.
    #>
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
}

function Update-UserListView {
    <#
    .SYNOPSIS
        users 배열로 사용자 ListView를 갱신한다.
    #>
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
    <#
    .SYNOPSIS
        체크된 사용자 ID 목록을 반환한다.
    #>
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

#endregion

#region RichTextBox 메시지 표시

function Clear-ChatRichTextBox {
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.RichTextBox]$RichTextBox
    )
    $RichTextBox.Clear()
}

function Format-MessageDateTime {
    <#
    .SYNOPSIS
        표시용 일시 yyyyMMdd HH:mm:ss
    #>
    param($Value)
    if (-not $Value) { return '-------- --:--:--' }
    try {
        return ([datetime]$Value).ToString('yyyyMMdd HH:mm:ss')
    }
    catch {
        $s = [string]$Value
        if ($s -match '(\d{4})[-\/]?(\d{2})[-\/]?(\d{2}).*?(\d{2}):(\d{2})(?::(\d{2}))?') {
            $sec = if ($Matches[6]) { $Matches[6] } else { '00' }
            return ('{0}{1}{2} {3}:{4}:{5}' -f $Matches[1], $Matches[2], $Matches[3], $Matches[4], $Matches[5], $sec)
        }
        return $s
    }
}

function Add-ChatMessageToView {
    <#
    .SYNOPSIS
        메시지 표시.
        형식: [보낸사람 | yyyyMMdd HH:mm:ss] 제목
              내용
        내 메시지: 우측 정렬, 상대: 좌측 정렬.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.RichTextBox]$RichTextBox,
        [Parameter(Mandatory = $true)]
        $Message,
        [switch]$ScrollToEnd
    )

    $isOwn = [bool]$Message.isOwn
    $timeStr = Format-MessageDateTime -Value $Message.ae
    $namePart = if ($isOwn) {
        '나'
    }
    else {
        if ($Message.ac) { [string]$Message.ac } else { '상대' }
    }

    $body = ConvertFrom-HtmlToPlainText -Html ([string]$Message.ah)
    $title = ''
    if ($Message.ad) { $title = [string]$Message.ad.Trim() }

    # 헤더: [보낸사람 | yyyyMMdd HH:mm:ss] 제목
    if ($title) {
        $header = '[{0} | {1}] {2}' -f $namePart, $timeStr, $title
    }
    else {
        $header = '[{0} | {1}]' -f $namePart, $timeStr
    }

    $block = $header + [Environment]::NewLine + $body + [Environment]::NewLine + [Environment]::NewLine

    # 단락 정렬 (내 메시지 우측)
    $RichTextBox.SelectionStart = $RichTextBox.TextLength
    $RichTextBox.SelectionLength = 0
    if ($isOwn) {
        $RichTextBox.SelectionAlignment = [System.Windows.Forms.HorizontalAlignment]::Right
    }
    else {
        $RichTextBox.SelectionAlignment = [System.Windows.Forms.HorizontalAlignment]::Left
    }
    $RichTextBox.AppendText($block)

    # 다음 메시지 기본 좌측으로 리셋 (안전)
    $RichTextBox.SelectionStart = $RichTextBox.TextLength
    $RichTextBox.SelectionLength = 0
    $RichTextBox.SelectionAlignment = [System.Windows.Forms.HorizontalAlignment]::Left

    if ($ScrollToEnd) {
        $RichTextBox.SelectionStart = $RichTextBox.TextLength
        $RichTextBox.ScrollToCaret()
    }
}

function Show-ChatMessages {
    <#
    .SYNOPSIS
        메시지 배열을 RichTextBox에 표시한다 (맨 아래로 스크롤).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.RichTextBox]$RichTextBox,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$Messages
    )

    $RichTextBox.SuspendLayout()
    try {
        $RichTextBox.Clear()
        foreach ($m in $Messages) {
            Add-ChatMessageToView -RichTextBox $RichTextBox -Message $m
        }
        $RichTextBox.SelectionStart = $RichTextBox.TextLength
        $RichTextBox.ScrollToCaret()
    }
    finally {
        $RichTextBox.ResumeLayout()
    }
}

#region StatusStrip / 공통

function Set-StatusMessage {
    <#
    .SYNOPSIS
        StatusStrip 레이블 텍스트를 갱신한다.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.ToolStripStatusLabel]$Label,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    $Label.Text = $Message
}

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

#endregion


# ###########################################################################
# 애플리케이션 본체
# ###########################################################################
$script:AppRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $script:AppRoot) { $script:AppRoot = (Get-Location).Path }

$script:ModulesDir = Join-Path $script:AppRoot 'modules'
$script:DataDir    = Join-Path $script:AppRoot 'data'
$script:ConfigPath = $null
$script:LogsDir    = Join-Path $script:AppRoot 'logs'
$script:ChatsDir   = Join-Path $script:DataDir 'chats'

# 모듈은 이 파일 상단에 인라인됨 (B안: 단일 파일)

# ---------------------------------------------------------------------------
# 전역 상태 (싱글스레드 script 스코프)
# ---------------------------------------------------------------------------
$script:CurrentUserId       = $null
$script:CurrentUserName     = $null
$script:CurrentChatMD5      = $null   # 현재 ChatForm이 보고 있는 대화
$script:isPolling           = $false  # 중복 폴링 차단
$script:isSending           = $false  # Send/Poll 상호 배제
$script:PollIntervalMs      = 15000   # 15초
$script:IsExiting           = $false
$script:AppContext          = $null

# UI 참조
$script:MainForm            = $null
$script:ChatForm            = $null
$script:NotifyIcon          = $null
$script:PollTimer           = $null
$script:StatusLabel         = $null
$script:ConversationListView = $null
$script:UserListView        = $null
$script:ChatRichTextBox     = $null
$script:ChatInputBox        = $null
$script:ChatTitleLabel      = $null
# 화면에 표시 중인 메시지 (최근 N개 / 검색 결과)
$script:ChatLoadedMessages  = @()
$script:ChatPageSize        = 50    # 대화 열 때 최근 최대 개수 (성능 상한)
$script:ChatSearchMaxResults = 100  # 전체 월 검색 결과 표시 상한
$script:ChatSearchBox       = $null
$script:isSearching         = $false

# ---------------------------------------------------------------------------
# 1. 앱 초기화
# ---------------------------------------------------------------------------
function Initialize-Application {
    <#
    .SYNOPSIS
        폴더 생성, 모듈 초기화, ACL, API 설정.
    #>
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

    $script:ConfigPath = Join-Path $script:DataDir 'config.json'
    Import-ApiBaseFromConfig

    Initialize-ApiUrls
    Write-AppLog -Level INFO -Message "URL Login=$($script:LoginUrl)"
    Write-AppLog -Level INFO -Message "URL Users=$($script:GetUserListUrl)"
    Write-AppLog -Level INFO -Message "URL Notes base=$($script:ApiBase)/note/..."

    # 401 시 재로그인
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

# ---------------------------------------------------------------------------
# 2. 로그인
# ---------------------------------------------------------------------------
function Start-UserLogin {
    <#
    .SYNOPSIS
        저장된 서버/자격 증명으로 자동 로그인, 없으면 다이얼로그.
    .OUTPUTS
        [bool] 성공 여부
    #>
    # 저장된 서버 주소 적용 (재시도 시에도 최신 config 반영)
    Import-ApiBaseFromConfig

    $cred = Get-UserCredential

    if (-not $cred) {
        $cred = Show-LoginDialog -DefaultApiBase $script:ApiBase
        if (-not $cred) {
            Write-AppLog -Level INFO -Message "로그인 취소"
            return $false
        }
        if (-not (Set-ApiBaseAddress -ApiBase $cred.ApiBase)) {
            Write-AppLog -Level ERROR -Message "서버 주소가 올바르지 않음: $($cred.ApiBase)"
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

        # sync.json currentUserId 반영
        $sync = Get-SyncState
        if ($sync) {
            $prevSync = [string](Get-ObjectProperty -Object $sync -Name 'lastSync' -Default '')
            $prevId   = [string](Get-ObjectProperty -Object $sync -Name 'lastMessageId' -Default '')
            Save-SyncState -LastSync $prevSync -LastMessageId $prevId -CurrentUserId $script:CurrentUserId
        }

        Write-AppLog -Level INFO -Message "로그인 완료 user=$($script:CurrentUserId) name=$($script:CurrentUserName)"
        return $true
    }
    catch {
        Write-AppLog -Level ERROR -Message "로그인 실패" -Exception $_.Exception

        # 서버/자격 증명 재입력 유도
        $retry = Show-ConfirmDialog -Text "로그인에 실패했습니다.`n$($_.Exception.Message)`n`n서버 주소와 자격 증명을 다시 입력할까요?" -Title "로그인 실패"
        if ($retry) {
            $newCred = Show-LoginDialog -DefaultUserId $cred.UserId -DefaultApiBase $script:ApiBase
            if ($newCred) {
                if (-not (Set-ApiBaseAddress -ApiBase $newCred.ApiBase)) {
                    Show-ErrorMessage -Text "서버 주소가 올바르지 않습니다.`n$($newCred.ApiBase)"
                    return $false
                }
                Save-AppConfig -ApiBase $script:ApiBase
                Save-UserCredential -UserId $newCred.UserId -Password $newCred.Password
                return (Start-UserLogin)
            }
        }
        return $false
    }
}


function Initialize-UserCache {
    <#
    .SYNOPSIS
        최초 사용자 목록 조회 후 users.json 생성/갱신.
    #>
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
        Save-Users -Users $users
        $me = $users | Where-Object { $_.id -eq $script:CurrentUserId } | Select-Object -First 1
        if ($me -and $me.name) { $script:CurrentUserName = [string]$me.name }
        Write-AppLog -Level INFO -Message "사용자 $($users.Count)명 캐시 저장"
    }
    catch {
        Write-AppLog -Level ERROR -Message "사용자 목록 조회 실패: $($_.Exception.Message)" -Exception $_.Exception
        Set-StatusSafe ("사용자 목록 실패: " + $_.Exception.Message)
    }
}

# ---------------------------------------------------------------------------
# 3. MainForm
# ---------------------------------------------------------------------------
function New-MainForm {
    <#
    .SYNOPSIS
        MainForm (TabControl: 대화목록 / 사용자목록 + StatusStrip + NotifyIcon) 생성.
    #>
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "오케스트라 채팅 - $($script:CurrentUserName)"
    $form.Size = New-Object System.Drawing.Size(480, 640)
    $form.StartPosition = 'CenterScreen'
    $form.MinimumSize = New-Object System.Drawing.Size(360, 400)
    $form.Font = New-Object System.Drawing.Font('맑은 고딕', 9)

    # --- TabControl ---
    $tabs = New-Object System.Windows.Forms.TabControl
    $tabs.Dock = [System.Windows.Forms.DockStyle]::Fill
    $form.Controls.Add($tabs)

    # 대화 목록 탭
    $tabConv = New-Object System.Windows.Forms.TabPage
    $tabConv.Text = '대화 목록'
    $tabs.TabPages.Add($tabConv)

    $lvConv = New-Object System.Windows.Forms.ListView
    $lvConv.Dock = [System.Windows.Forms.DockStyle]::Fill
    Initialize-ConversationListView -ListView $lvConv
    $tabConv.Controls.Add($lvConv)
    $script:ConversationListView = $lvConv

    # 사용자 목록 탭
    $tabUser = New-Object System.Windows.Forms.TabPage
    $tabUser.Text = '사용자 목록'
    $tabs.TabPages.Add($tabUser)

    $panelUser = New-Object System.Windows.Forms.Panel
    $panelUser.Dock = [System.Windows.Forms.DockStyle]::Fill
    $tabUser.Controls.Add($panelUser)

    $btnNewChat = New-Object System.Windows.Forms.Button
    $btnNewChat.Text = '선택 사용자와 대화 시작'
    $btnNewChat.Dock = [System.Windows.Forms.DockStyle]::Bottom
    $btnNewChat.Height = 36
    $panelUser.Controls.Add($btnNewChat)

    $lvUser = New-Object System.Windows.Forms.ListView
    $lvUser.Dock = [System.Windows.Forms.DockStyle]::Fill
    Initialize-UserListView -ListView $lvUser
    $panelUser.Controls.Add($lvUser)
    $script:UserListView = $lvUser

    # --- StatusStrip ---
    $status = New-Object System.Windows.Forms.StatusStrip
    $statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
    $statusLabel.Spring = $true
    $statusLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $statusLabel.Text = '준비'
    [void]$status.Items.Add($statusLabel)
    $form.Controls.Add($status)
    $script:StatusLabel = $statusLabel

    # --- NotifyIcon (하나만 MainForm에서 관리) ---
    $notify = New-Object System.Windows.Forms.NotifyIcon
    $notify.Text = "내부 채팅 - $($script:CurrentUserName)"
    $notify.Visible = $true
    try {
        # 기본 앱 아이콘 사용
        $notify.Icon = [System.Drawing.SystemIcons]::Application
    }
    catch {
        $notify.Icon = [System.Drawing.SystemIcons]::Information
    }
    $script:NotifyIcon = $notify

    $trayMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $miOpen = $trayMenu.Items.Add('메인 창 열기')
    $miSep  = $trayMenu.Items.Add('-')
    $miExit = $trayMenu.Items.Add('종료')
    $notify.ContextMenuStrip = $trayMenu

    # 트레이 메뉴: 메인 창 복원
    $miOpen.Add_Click({
        Restore-MainForm
    })

    # 트레이 메뉴: 종료
    $miExit.Add_Click({
        Exit-Application
    })

    # 트레이 더블클릭 -> 메인 창 복원
    $notify.Add_DoubleClick({
        Restore-MainForm
    })


    # --- 이벤트: 대화 목록 더블클릭 ---
    $lvConv.Add_DoubleClick({
        if ($script:ConversationListView.SelectedItems.Count -gt 0) {
            $md5 = [string]$script:ConversationListView.SelectedItems[0].Tag
            Open-ChatForm -Md5 $md5
        }
    })

    # --- 우클릭: 제목 변경 ---
    $convMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $miRename = $convMenu.Items.Add('제목 변경')
    $miRename.Add_Click({ Edit-SelectedConversationTitle })
    $lvConv.ContextMenuStrip = $convMenu

    # --- 이벤트: 새 대화 ---
    $btnNewChat.Add_Click({
        Start-NewConversationFromSelection
    })

    # --- 이벤트: MainForm X -> 트레이로 숨김 (종료는 트레이 메뉴만)
    $form.Add_FormClosing({
        if ($script:IsExiting) { return }
        $ea = $null
        if ($args.Count -ge 2) { $ea = $args[1] }
        if ($null -ne $ea) {
            # 사용자 닫기/시스템 등 모두 취소 후 숨김 (Dispose 방지)
            $ea.Cancel = $true
        }
        Hide-MainFormToTray
    })

    # --- 폴링 타이머 (UI 스레드) ---
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = $script:PollIntervalMs
    $timer.Add_Tick({ Invoke-PollTimerTick })
    $script:PollTimer = $timer

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
}

function Update-ConversationListUi {
    <#
    .SYNOPSIS
        conversations.json -> ListView 갱신.
    #>
    try {
        $convs = @(Get-Conversations)
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
        $users = @(Get-Users)
        if ($null -eq $users) { $users = @() }
        if ($script:UserListView -and -not $script:UserListView.IsDisposed) {
            Update-UserListView -ListView $script:UserListView -Users $users -ExcludeUserId $script:CurrentUserId
        }
    }
    catch {
        Write-AppLog -Level ERROR -Message "사용자 목록 갱신 실패" -Exception $_.Exception
    }
}

function Start-NewConversationFromSelection {
    <#
    .SYNOPSIS
        체크된 사용자와 새 대화를 열고 ChatForm 표시.
    #>
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

# ---------------------------------------------------------------------------
# 4. ChatForm
# ---------------------------------------------------------------------------
function Open-ChatForm {
    <#
    .SYNOPSIS
        지정 md5 대화를 ChatForm으로 연다. 이미 있으면 내용만 교체/복원.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Md5
    )

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
    <#
    .SYNOPSIS
        ChatForm UI를 생성한다. (RichTextBox + 입력 + 전송 + 전체 월 검색)
    #>
    $form = New-Object System.Windows.Forms.Form
    $form.Text = '대화'
    $form.Size = New-Object System.Drawing.Size(520, 680)
    $form.StartPosition = 'CenterScreen'
    $form.MinimumSize = New-Object System.Drawing.Size(400, 400)
    $form.Font = New-Object System.Drawing.Font('맑은 고딕', 9)
    $form.ShowInTaskbar = $true

    # 상단 제목 + 참여자 버튼
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

    # 검색 패널: [ 검색어 입력 | 검색 | 최근 ]
    $searchPanel = New-Object System.Windows.Forms.Panel
    $searchPanel.Dock = [System.Windows.Forms.DockStyle]::Top
    $searchPanel.Height = 40
    $searchPanel.Padding = New-Object System.Windows.Forms.Padding(6, 6, 6, 6)
    $searchPanel.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 252)
    $form.Controls.Add($searchPanel)

    $searchTable = New-Object System.Windows.Forms.TableLayoutPanel
    $searchTable.Dock = [System.Windows.Forms.DockStyle]::Fill
    $searchTable.ColumnCount = 3
    $searchTable.RowCount = 1
    $searchTable.Margin = New-Object System.Windows.Forms.Padding(0)
    $searchTable.Padding = New-Object System.Windows.Forms.Padding(0)
    [void]$searchTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100.0)))
    [void]$searchTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 64.0)))
    [void]$searchTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 64.0)))
    [void]$searchTable.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100.0)))
    $searchPanel.Controls.Add($searchTable)

    $txtSearch = New-Object System.Windows.Forms.TextBox
    $txtSearch.Dock = [System.Windows.Forms.DockStyle]::Fill
    $txtSearch.Margin = New-Object System.Windows.Forms.Padding(0, 2, 4, 2)
    $txtSearch.Anchor = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Top
    $txtSearch.Add_KeyDown({
        param($sender, $e)
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
            $e.SuppressKeyPress = $true
            Search-CurrentChatHistory
        }
    })
    $searchTable.Controls.Add($txtSearch, 0, 0)
    $script:ChatSearchBox = $txtSearch

    $btnSearch = New-Object System.Windows.Forms.Button
    $btnSearch.Text = '검색'
    $btnSearch.Dock = [System.Windows.Forms.DockStyle]::Fill
    $btnSearch.Margin = New-Object System.Windows.Forms.Padding(2, 0, 2, 0)
    $btnSearch.Add_Click({ Search-CurrentChatHistory })
    $searchTable.Controls.Add($btnSearch, 1, 0)

    $btnRecent = New-Object System.Windows.Forms.Button
    $btnRecent.Text = '최근'
    $btnRecent.Dock = [System.Windows.Forms.DockStyle]::Fill
    $btnRecent.Margin = New-Object System.Windows.Forms.Padding(2, 0, 0, 0)
    $btnRecent.Add_Click({
        if ($script:CurrentChatMD5) {
            Initialize-ChatContent -Md5 $script:CurrentChatMD5
            Set-StatusSafe "최근 $($script:ChatPageSize)개 표시"
        }
    })
    $searchTable.Controls.Add($btnRecent, 2, 0)

    # 하단 입력 패널
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

    # Enter = 전송, Shift+Enter = 줄바꿈
    $txtInput.Add_KeyDown({
        param($sender, $e)
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter -and -not $e.Shift) {
            $e.SuppressKeyPress = $true
            Invoke-ChatSend
        }
    })

    # 메시지 영역
    $rtb = New-Object System.Windows.Forms.RichTextBox
    $rtb.Dock = [System.Windows.Forms.DockStyle]::Fill
    $rtb.ReadOnly = $true
    $rtb.BackColor = [System.Drawing.Color]::White
    $rtb.Font = New-Object System.Drawing.Font('맑은 고딕', 9.5)
    $rtb.DetectUrls = $false
    $rtb.HideSelection = $false
    $form.Controls.Add($rtb)
    $script:ChatRichTextBox = $rtb

    # Dock 레이아웃: Fill 컨트롤은 z-order 뒤쪽이어야 Top/Bottom이 공간을 먼저 확보한다
    $rtb.SendToBack()

    # X 버튼 -> 대화 창만 닫기 (메인/트레이는 유지)
    $form.Add_FormClosing({
        param($sender, $e)
        if ($script:IsExiting) { return }
        # Cancel 하지 않음 = 실제 닫힘
    })
    $form.Add_FormClosed({
        $script:ChatForm = $null
        $script:ChatRichTextBox = $null
        $script:ChatInputBox = $null
        $script:ChatTitleLabel = $null
        $script:ChatSearchBox = $null
        $script:CurrentChatMD5 = $null
        $script:ChatLoadedMessages = @()
    })

    $script:ChatForm = $form
}

function Initialize-ChatContent {
    <#
    .SYNOPSIS
        md5 대화의 최근 메시지를 RichTextBox에 로드한다 (최대 ChatPageSize개).
    .DESCRIPTION
        이전 대화 페이징 UI는 없음. 디스크에는 월별 전체가 유지되며,
        화면에는 최근 N개만 올려 성능 상한을 지킨다.
    #>
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

    # 월별 파일에서 수집 후 최근 N개만 표시 (전체 히스토리 RTF 로드 금지)
    $months = @(Get-AvailableChatMonths -Md5 $Md5)
    if ($months.Count -eq 0) {
        $months = @((Get-Date -Format 'yyyyMM'))
    }

    $all = @()
    foreach ($ym in $months) {
        $all += @(Get-ChatMessages -Md5 $Md5 -YearMonth $ym)
    }

    $sorted = @($all | Sort-Object {
        if ($_.ae) { try { [datetime]$_.ae } catch { [datetime]::MinValue } } else { [datetime]::MinValue }
    })

    $total = $sorted.Count
    if ($total -le 0) {
        $script:ChatLoadedMessages = @()
    }
    else {
        $take = [Math]::Min($script:ChatPageSize, $total)
        $start = $total - $take
        $script:ChatLoadedMessages = @($sorted[$start..($total - 1)])
    }

    if ($script:ChatRichTextBox -and -not $script:ChatRichTextBox.IsDisposed) {
        Show-ChatMessages -RichTextBox $script:ChatRichTextBox -Messages $script:ChatLoadedMessages
    }

    if ($script:ChatSearchBox -and -not $script:ChatSearchBox.IsDisposed) {
        $script:ChatSearchBox.Clear()
    }
}

function Search-CurrentChatHistory {
    <#
    .SYNOPSIS
        현재 대화(md5)의 전체 월 파일을 대상으로 키워드 검색한다.
    .DESCRIPTION
        로컬 data/chats 만 조회. 결과 최대 ChatSearchMaxResults 건만 RTF에 표시.
        폴링/전송과 겹치지 않도록 isSearching 가드 사용.
    #>
    if ($script:isSearching) { return }
    if ($script:isPolling -or $script:isSending) {
        Set-StatusSafe "동기화/전송 중 - 잠시 후 검색"
        return
    }
    if (-not $script:CurrentChatMD5) {
        Show-InfoMessage -Text '대화가 선택되지 않았습니다.'
        return
    }
    if (-not $script:ChatSearchBox -or $script:ChatSearchBox.IsDisposed) { return }

    $keyword = $script:ChatSearchBox.Text
    if ([string]::IsNullOrWhiteSpace($keyword)) {
        Show-InfoMessage -Text '검색어를 입력하세요.'
        return
    }
    $keyword = $keyword.Trim()

    $script:isSearching = $true
    try {
        Set-StatusSafe "검색 중 (전체 월)..."
        $md5 = $script:CurrentChatMD5
        $months = @(Get-AvailableChatMonths -Md5 $md5)
        if ($months.Count -eq 0) {
            $months = @((Get-Date -Format 'yyyyMM'))
        }

        $hits = @()
        foreach ($ym in $months) {
            $msgs = @(Get-ChatMessages -Md5 $md5 -YearMonth $ym)
            foreach ($m in $msgs) {
                $hay = @()
                if ($m.ac) { $hay += [string]$m.ac }
                if ($m.ad) { $hay += [string]$m.ad }
                if ($m.ah) { $hay += (ConvertFrom-HtmlToPlainText -Html ([string]$m.ah)) }
                $blob = ($hay -join ' ')
                if ($blob.IndexOf($keyword, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    $hits += $m
                }
            }
        }

        # 시간순 정렬 후 상한
        $sorted = @($hits | Sort-Object {
            if ($_.ae) { try { [datetime]$_.ae } catch { [datetime]::MinValue } } else { [datetime]::MinValue }
        })

        $totalHits = $sorted.Count
        if ($totalHits -le 0) {
            $script:ChatLoadedMessages = @()
            if ($script:ChatRichTextBox -and -not $script:ChatRichTextBox.IsDisposed) {
                Show-ChatMessages -RichTextBox $script:ChatRichTextBox -Messages @()
            }
            Set-StatusSafe "검색 결과 없음: $keyword"
            return
        }

        $max = $script:ChatSearchMaxResults
        if ($totalHits -gt $max) {
            # 최근 매칭 위주로 표시
            $start = $totalHits - $max
            $script:ChatLoadedMessages = @($sorted[$start..($totalHits - 1)])
            Set-StatusSafe "검색 $totalHits 건 중 최근 $max 건 표시: $keyword"
        }
        else {
            $script:ChatLoadedMessages = $sorted
            Set-StatusSafe "검색 $totalHits 건 (전체 월): $keyword"
        }

        if ($script:ChatRichTextBox -and -not $script:ChatRichTextBox.IsDisposed) {
            Show-ChatMessages -RichTextBox $script:ChatRichTextBox -Messages $script:ChatLoadedMessages
        }
    }
    catch {
        Write-AppLog -Level ERROR -Message "대화 검색 실패" -Exception $_.Exception
        Show-ErrorMessage -Text "검색에 실패했습니다.`n$($_.Exception.Message)"
        Set-StatusSafe "검색 실패"
    }
    finally {
        $script:isSearching = $false
    }
}

function Show-ChatForm {
    <#
    .SYNOPSIS
        ChatForm을 표시하고 활성화한다.
    #>
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
    <#
    .SYNOPSIS
        메인 창을 트레이로 숨긴다. (앱은 계속 실행, 종료 아님)
    #>
    if ($script:MainForm -and -not $script:MainForm.IsDisposed) {
        $script:MainForm.ShowInTaskbar = $false
        $script:MainForm.WindowState = [System.Windows.Forms.FormWindowState]::Normal
        $script:MainForm.Visible = $false
        Write-AppLog -Level INFO -Message "메인 창 트레이 숨김"
    }
}

function Restore-MainForm {
    <#
    .SYNOPSIS
        트레이에서 메인 창을 다시 연다.
    #>
    if (-not $script:MainForm -or $script:MainForm.IsDisposed) { return }
    $script:MainForm.ShowInTaskbar = $true
    $script:MainForm.Visible = $true
    $script:MainForm.Show()
    $script:MainForm.WindowState = [System.Windows.Forms.FormWindowState]::Normal
    $script:MainForm.Activate()
    $script:MainForm.BringToFront()
    $script:MainForm.Focus()
}

# 하위 호환 이름 (호출 잔여 대비)
function Restore-ChatForm { Restore-MainForm }

function Test-ChatFormVisible {
    <#
    .SYNOPSIS
        ChatForm이 현재 보이는 상태인지 판별.
    #>
    if ($null -eq $script:ChatForm) { return $false }
    if ($script:ChatForm.IsDisposed) { return $false }
    return [bool]$script:ChatForm.Visible
}

# ---------------------------------------------------------------------------
# 5. 폴링 (가장 중요 - 싱글스레드 분기)
# ---------------------------------------------------------------------------
function Invoke-PollTimerTick {
    <#
    .SYNOPSIS
        Timer Tick 핸들러. isPolling / isSending 가드로 중복 차단 후 폴링.
        예외는 로그만 남기고 크래시 방지.
    #>
    if ($script:IsExiting) { return }
    if ($script:isPolling) {
        return
    }
    if ($script:isSending) {
        return
    }
    if ($script:isSearching) {
        return
    }

    $script:isPolling = $true
    try {
        Invoke-MessagePoll
    }
    catch {
        $err = $_.Exception.Message
        if ($err.Length -gt 80) { $err = $err.Substring(0, 80) + '...' }
        Write-AppLog -Level ERROR -Message "폴링 예외: $($_.Exception.Message)" -Exception $_.Exception
        Set-StatusSafe ("동기화 오류: " + $err)
    }
    finally {
        $script:isPolling = $false
    }
}

function Invoke-MessagePoll {
    <#
    .SYNOPSIS
        쪽지 목록 증분 조회 -> 로컬 저장 -> ChatForm 상태에 따라 UI 분기.
    .DESCRIPTION
        ChatForm Visible=false: 파일만 갱신 + BalloonTip (RichTextBox 접근 금지)
        ChatForm Visible=true:
          - 현재 md5 일치 -> RichTextBox Append
          - 다른 대화 -> conversations.json 만 갱신
    #>
    Set-StatusSafe "동기화 중..."

    $sync = Get-SyncState
    $startYmd = ''
    $lastMsgId = $null

    if ($sync) {
        # lastSync 는 yyyyMMdd (쪽지 start_ymd)
        $startYmd  = [string](Get-ObjectProperty -Object $sync -Name 'lastSync' -Default '')
        $lastMsgId = [string](Get-ObjectProperty -Object $sync -Name 'lastMessageId' -Default '')
        if (-not $lastMsgId) { $lastMsgId = $null }
    }

    # 최초(start_ymd 빈값)=전체, 이후=마지막 대화일 yyyyMMdd
    $rawList = Get-ApiMessageList -StartYmd $startYmd
    if ($null -eq $rawList) { $rawList = @() }

    $newMessages = New-Object System.Collections.ArrayList
    $maxMsgId = $lastMsgId
    foreach ($raw in @($rawList)) {
        try {
            $msg = ConvertTo-NormalizedMessage -Raw $raw -CurrentUserId $script:CurrentUserId
            if (-not $msg.aa) { continue }

            if ($lastMsgId) {
                if ([string]::CompareOrdinal([string]$msg.aa.ToUpperInvariant(), [string]$lastMsgId.ToUpperInvariant()) -le 0) {
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
    }

    if ($newMessages.Count -eq 0) {
        if ($script:CurrentUserId) {
            $keepId = if ($maxMsgId) { $maxMsgId } elseif ($lastMsgId) { $lastMsgId } else { '' }
            $keepYmd = if ($startYmd) { $startYmd } else { (Get-Date).ToString('yyyyMMdd') }
            Save-SyncState -LastSync $keepYmd -LastMessageId $keepId -CurrentUserId $script:CurrentUserId
        }
        Set-StatusSafe "동기화 완료"
        return
    }

    Write-AppLog -Level INFO -Message "새 메시지 $($newMessages.Count)건 처리"

    $chatVisible = Test-ChatFormVisible
    $currentMd5  = $script:CurrentChatMD5
    $uiAppendList = New-Object System.Collections.ArrayList
    $balloonCandidates = New-Object System.Collections.ArrayList
    $touchedMd5 = @{}

    foreach ($msg in $newMessages) {
        $md5 = Resolve-MessageConversationKey -Message $msg -CurrentUserId $script:CurrentUserId

        $ym = Get-Date -Format 'yyyyMM'
        if ($msg.ae) {
            try { $ym = ([datetime]$msg.ae).ToString('yyyyMM') } catch { }
        }

        $added = Add-ChatMessage -Md5 $md5 -Message $msg -YearMonth $ym

        # 참가자: ArrayList 로 누적 (@()+= 는 단일 문자열로 풀려 .Count 오류 발생)
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

        # unread: 새 수신 + 현재 보고 있지 않을 때만 true. 그 외에는 기존 unread 유지
        $upsertParams = @{
            Md5              = $md5
            ParticipantIds   = $pIds
            ParticipantNames = $pNames
            LastMonth        = $ym
            LastSeq          = $msg.aa
        }
        # 최근 메시지 시각: 더 새로운 경우만 갱신
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
        if ($markUnread) {
            $upsertParams['IncrementUnread'] = $true
        }
        elseif ($isCurrentChat) {
            $upsertParams['ClearUnread'] = $true
        }
        Update-ConversationMeta @upsertParams

        $touchedMd5[$md5] = $true

        # --- ChatForm 상태 분기 ---
        if ($chatVisible) {
            if ($currentMd5 -and $md5 -eq $currentMd5) {
                # 현재 보고 있는 대화 -> Append 후보
                if ($added) { [void]$uiAppendList.Add($msg) }
            }
            # else: 다른 대화 -> conversations.json 만 갱신 (이미 완료). RichTextBox 건드리지 않음.
        }
        else {
            # Tray 숨김 상태: RichTextBox 절대 접근 금지, Balloon 후보
            if (-not $msg.isOwn -and $added) {
                [void]$balloonCandidates.Add($msg)
            }
        }
    }

    # sync 갱신: lastSync=최신 메시지일 yyyyMMdd, lastMessageId=최대 note_id
    if (-not $maxMsgId) { $maxMsgId = $lastMsgId }
    if (-not $maxMsgId) { $maxMsgId = '' }
    $maxYmd = $startYmd
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

    # 대화 목록 UI 갱신 (MainForm - 가벼운 작업)
    Update-ConversationListUi

    # ChatForm 보이는 경우: 현재 대화 Append 만 (최소화)
    if ($chatVisible -and $uiAppendList.Count -gt 0) {
        Add-MessagesToChatUi -Messages @($uiAppendList.ToArray())
    }

    # Tray 숨김: BalloonTip
    if (-not $chatVisible -and $balloonCandidates.Count -gt 0) {
        Show-NewMessageBalloon -Messages @($balloonCandidates.ToArray())
    }

    Set-StatusSafe "동기화 완료 ($($newMessages.Count))"
}

function Add-MessagesToChatUi {
    <#
    .SYNOPSIS
        현재 보이는 ChatForm RichTextBox에만 메시지 Append.
        (사용자가 입력 중일 수 있으므로 최소한의 UI 갱신)
    #>
    param([array]$Messages)

    if (-not (Test-ChatFormVisible)) { return }
    if (-not $script:ChatRichTextBox -or $script:ChatRichTextBox.IsDisposed) { return }

    foreach ($msg in $Messages) {
        try {
            Add-ChatMessageToView -RichTextBox $script:ChatRichTextBox -Message $msg -ScrollToEnd
            $script:ChatLoadedMessages = @($script:ChatLoadedMessages) + @($msg)
        }
        catch {
            Write-AppLog -Level ERROR -Message "RichTextBox Append 실패" -Exception $_.Exception
        }
    }
}

function Show-NewMessageBalloon {
    <#
    .SYNOPSIS
        ChatForm이 보이지 않을 때만 BalloonTip 표시.
        제목: "새 쪽지가 도착했습니다" / 내용: 보낸사람 + 제목 일부
    #>
    param([array]$Messages)

    if (Test-ChatFormVisible) { return }
    if (-not $script:NotifyIcon) { return }

    $latest = $Messages | Select-Object -Last 1
    $sender = if ($latest.ac) { [string]$latest.ac } else { '알 수 없음' }
    $titlePart = if ($latest.ad) { [string]$latest.ad } else {
        $plain = ConvertFrom-HtmlToPlainText -Html ([string]$latest.ah)
        if ($plain.Length -gt 40) { $plain.Substring(0, 40) + '...' } else { $plain }
    }
    if ($titlePart.Length -gt 50) { $titlePart = $titlePart.Substring(0, 50) + '...' }

    $count = $Messages.Count
    $body = if ($count -gt 1) {
        "{0}: {1} 외 {2}건" -f $sender, $titlePart, ($count - 1)
    }
    else {
        "{0}: {1}" -f $sender, $titlePart
    }

    try {
        $script:NotifyIcon.ShowBalloonTip(
            5000,
            '새 쪽지가 도착했습니다',
            $body,
            [System.Windows.Forms.ToolTipIcon]::Info
        )
    }
    catch {
        Write-AppLog -Level WARN -Message "BalloonTip 표시 실패" -Exception $_.Exception
    }
}

# ---------------------------------------------------------------------------
# 6. 메시지 전송 (isSending 가드, 성공 후 반영)
# ---------------------------------------------------------------------------
function Invoke-ChatSend {
    <#
    .SYNOPSIS
        입력창 내용 전송. Poll과 동시 실행 방지.
        서버 성공 후에만 로컬/UI 반영 (낙관적 업데이트 없음).
    #>
    if ($script:isSending) { return }
    if ($script:isSearching) {
        Set-StatusSafe "검색 중 - 잠시 후 전송"
        return
    }
    if ($script:isPolling) {
        Set-StatusSafe "동기화 중 - 잠시 후 전송"
        return
    }
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

        Set-StatusSafe "전송 중..."
        $result = Send-ApiMessage -ReceiverIds $receivers -ReceiverNames $recvNames -BodyText $text

        # 성공 응답에 note_id 없음 -> 로컬 임시 ID 후 다음 폴링으로 정합
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

        Update-ConversationMeta `
            -Md5 $script:CurrentChatMD5 `
            -LastMonth $ym `
            -LastMessageTime $msg.ae `
            -LastSeq $serverId `
            -ClearUnread

        if (Test-ChatFormVisible -and $script:ChatRichTextBox -and -not $script:ChatRichTextBox.IsDisposed) {
            Add-ChatMessageToView -RichTextBox $script:ChatRichTextBox -Message $msg -ScrollToEnd
            $script:ChatLoadedMessages = @($script:ChatLoadedMessages) + @($msg)
        }

        $script:ChatInputBox.Clear()
        Update-ConversationListUi

        Set-StatusSafe "전송 완료"
        Write-AppLog -Level INFO -Message "메시지 전송 성공 md5=$($script:CurrentChatMD5)"
    }
    catch {
        Write-AppLog -Level ERROR -Message "메시지 전송 실패" -Exception $_.Exception
        Show-ErrorMessage -Text "전송에 실패했습니다.`n$($_.Exception.Message)"
        Set-StatusSafe "전송 실패"
    }
    finally {
        $script:isSending = $false
    }
}

# ---------------------------------------------------------------------------
# 7. 종료 처리
# ---------------------------------------------------------------------------
function Exit-Application {
    <#
    .SYNOPSIS
        트레이 메뉴 등에서 호출. 종료 플래그 후 메시지 루프 종료.
    #>
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
    <#
    .SYNOPSIS
        타이머 중지, NotifyIcon Dispose, 민감 정보 정리, 폼 정리.
    #>
    Write-AppLog -Level INFO -Message "===== InternalChat 종료 처리 ====="

    try {
        if ($script:PollTimer) {
            $script:PollTimer.Stop()
            $script:PollTimer.Dispose()
            $script:PollTimer = $null
        }
    }
    catch { }

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

    Write-AppLog -Level INFO -Message "===== InternalChat 종료 완료 ====="
}

# ---------------------------------------------------------------------------
# 8. 초기 동기화 (로그인 직후 1회)
# ---------------------------------------------------------------------------
function Invoke-InitialSync {
    <#
    .SYNOPSIS
        로그인 후 첫 폴링을 동기적으로 1회 수행.
    #>
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
        $script:isPolling = $false
    }
}

# ---------------------------------------------------------------------------
# 메인 진입점
# ---------------------------------------------------------------------------
function Main {
    Initialize-Application

    # 로그인 (실패 시 종료)
    # UI 없는 상태에서도 MessageBox 가능하도록 임시 ApplicationContext 불필요
    $loginOk = $false
    try {
        # StatusLabel이 아직 없으므로 Set-StatusSafe는 no-op
        $loginOk = Start-UserLogin
    }
    catch {
        Write-AppLog -Level ERROR -Message "로그인 단계 예외" -Exception $_.Exception
        Show-ErrorMessage -Text "로그인 중 오류가 발생했습니다.`n$($_.Exception.Message)"
        $loginOk = $false
    }

    if (-not $loginOk) {
        Write-AppLog -Level INFO -Message "로그인 실패/취소로 종료"
        return
    }

    # MainForm 생성
    $form = New-MainForm

    # 사용자 캐시 + UI 채우기
    Initialize-UserCache
    Update-UserListUi
    Update-ConversationListUi

    # 초기 동기화
    Invoke-InitialSync

    # 폴링 시작
    $script:PollTimer.Start()
    Write-AppLog -Level INFO -Message "폴링 타이머 시작 interval=$($script:PollIntervalMs)ms"

    Set-StatusSafe "준비 완료 - $($script:CurrentUserName)"

    # 수명 폼: 마지막 창이 닫혀도 WinForms 가 Application.Exit 하지 않도록 유지
    # (메인 창 X 는 숨김만, 실제 종료는 트레이 메뉴)
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
        if ($args.Count -ge 2 -and $null -ne $args[1]) {
            $args[1].Cancel = $true
        }
    })
    $script:LifetimeForm = $life

    $script:AppContext = New-Object System.Windows.Forms.ApplicationContext($life)
    $form.Show()
    $form.Activate()
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
