/*
    Base YARA rules for email attachment threat detection.
    These are example rules — extend with community/commercial rulesets.
*/

rule Suspicious_VBA_Macro
{
    meta:
        description = "Detects VBA macro patterns commonly used in malicious documents"
        severity = "critical"
        author = "EmailRisk"

    strings:
        $auto_open = "Auto_Open" ascii nocase
        $auto_close = "Auto_Close" ascii nocase
        $document_open = "Document_Open" ascii nocase
        $workbook_open = "Workbook_Open" ascii nocase
        $shell = "Shell" ascii nocase
        $wscript = "WScript.Shell" ascii nocase
        $powershell = "powershell" ascii nocase
        $cmd_exec = "cmd.exe" ascii nocase
        $create_object = "CreateObject" ascii nocase

    condition:
        ($auto_open or $auto_close or $document_open or $workbook_open) and
        ($shell or $wscript or $powershell or $cmd_exec) and
        $create_object
}

rule Suspicious_PE_In_Document
{
    meta:
        description = "Detects PE executable embedded within document-like container"
        severity = "critical"
        author = "EmailRisk"

    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }

    condition:
        $mz at 0 and $pe
}

rule Suspicious_PowerShell_Encoded
{
    meta:
        description = "Detects Base64-encoded PowerShell commands"
        severity = "critical"
        author = "EmailRisk"

    strings:
        $encoded_cmd = "-EncodedCommand" ascii nocase
        $enc = "-enc " ascii nocase
        $hidden = "-WindowStyle Hidden" ascii nocase
        $bypass = "-ExecutionPolicy Bypass" ascii nocase
        $noprofile = "-NoProfile" ascii nocase

    condition:
        ($encoded_cmd or $enc) and ($hidden or $bypass or $noprofile)
}

rule Suspicious_Script_Downloader
{
    meta:
        description = "Detects script-based downloader patterns"
        severity = "critical"
        author = "EmailRisk"

    strings:
        $xmlhttp = "MSXML2.XMLHTTP" ascii nocase
        $winhttp = "WinHttp.WinHttpRequest" ascii nocase
        $webclient = "Net.WebClient" ascii nocase
        $download = "DownloadFile" ascii nocase
        $invoke_web = "Invoke-WebRequest" ascii nocase
        $urlmon = "URLDownloadToFile" ascii nocase
        $certutil = "certutil" ascii nocase

    condition:
        any of them
}

rule Suspicious_HTML_Smuggling
{
    meta:
        description = "Detects HTML smuggling patterns"
        severity = "critical"
        author = "EmailRisk"

    strings:
        $blob = "new Blob" ascii
        $atob = "atob(" ascii
        $create_url = "createObjectURL" ascii
        $download = "download" ascii
        $base64 = "base64" ascii

    condition:
        ($blob or $create_url) and $atob and $base64
}

rule Suspicious_LNK_Command
{
    meta:
        description = "Detects suspicious command patterns in LNK files"
        severity = "critical"
        author = "EmailRisk"

    strings:
        $cmd = "cmd" ascii nocase
        $powershell = "powershell" ascii nocase
        $mshta = "mshta" ascii nocase
        $wscript = "wscript" ascii nocase
        $cscript = "cscript" ascii nocase
        $http = "http" ascii nocase

    condition:
        uint32(0) == 0x0000004C and
        2 of ($cmd, $powershell, $mshta, $wscript, $cscript, $http)
}
