#Author krivon Värmdö Kommun.
#This script scans for $IncludeFiles files present on the Windows-filesystem and looks if they have the $lookupString
#This was made to look for the Log4J vuln but can be changed to look for anything really..

#Switch out the SMTP variables below to fit your needs.
$From = "Securityscans <securityscans@placeholder.se>"
$To = "security@placeholder.se"
$Subject = "$env:COMPUTERNAME is NOT safe, ENV added"
$SMTPServer = "epost.placeholder.se"
#add more fileextensions if needed
$IncludeFiles = "*.jar","*.ear","*.war","*.sar"
$lookupString = "JndiLookup.class"

$OP = (Get-WmiObject Win32_OperatingSystem).name
    if($OP -like "*2008*"){
           Write-Output "$env:COMPUTERNAME is a 2008, Jesus.."
           #Just add more disks in the array below
           $fileScan = Get-ChildItem "C:\","D:\","E.\" -rec -force -include $IncludeFiles -ea 0 | ForEach-Object {select-string $lookupString $_} | Select-Object -exp Path
                if($fileScan -like "*:\*"){
                    Write-Output "$env:COMPUTERNAME contains Log4j and might be vulnerable";
                    Write-Output $fileScan >> C:\windows\temp\log4jscan.txt;
                    [System.Environment]::SetEnvironmentVariable("LOG4J_FORMAT_MSG_NO_LOOKUPS","true",[System.EnvironmentVariableTarget]::Machine);
                    Write-Output "ENV is LOG4J_FORMAT_MSG_NO_LOOKUP is set to True";
                    Send-MailMessage -From $From -to $To -Subject $Subject -Body "Files found on $env:COMPUTERNAME<br>$fileScan<br><b>please contact the administrator and/or the application provider</b>" -BodyAsHtml -SmtpServer $SMTPServer -UseSsl
                    }
                else {
                    Write-Output "$env:COMPUTERNAME is safe";
                    [System.Environment]::SetEnvironmentVariable("LOG4J_FORMAT_MSG_NO_LOOKUPS","true",[System.EnvironmentVariableTarget]::Machine);
                    Send-MailMessage -From $From -To $To -Subject "$env:COMPUTERNAME is safe" -Body "No Files found, but set the ENV-variable anyway" -SmtpServer $SMTPServer -UseSsl
            }
        }
        else{
        Write-Output "$env:COMPUTERNAME is not a 2008"
        $fileScan = Get-PSDrive -PSProvider FileSystem | ? {$_.Used -ne "0"} | % {Get-ChildItem $($_.root) -Recurse -Force -Include $IncludeFiles -ErrorA SilentlyContinue | % {select-string $lookupString $_} | Select-Object -exp Path}
        if($fileScan -like "*:\*"){
            Write-Output "$env:COMPUTERNAME contains Log4j and might be vulnerable";
            Write-Output $fileScan >> C:\windows\temp\log4jscan.txt;
            Write-Output $fileScan;
            [System.Environment]::SetEnvironmentVariable("LOG4J_FORMAT_MSG_NO_LOOKUPS","true",[System.EnvironmentVariableTarget]::Machine);
            Write-Output "ENV is LOG4J_FORMAT_MSG_NO_LOOKUP is set to True";
            Send-MailMessage -From $From -to $To -Subject $Subject -Body "Files found on $env:COMPUTERNAME<br><br>$fileScan<br><br><b>please contact the administrator and/or the application provider</b>" -BodyAsHtml -SmtpServer $SMTPServer -UseSsl
            }
        else {
            Write-Output "$env:COMPUTERNAME is safe";
            [System.Environment]::SetEnvironmentVariable("LOG4J_FORMAT_MSG_NO_LOOKUPS","true",[System.EnvironmentVariableTarget]::Machine);
            Send-MailMessage -From $From -To $To -Subject "$env:COMPUTERNAME is safe" -Body "No Files found, but set the ENV-variable anyway" -SmtpServer $SMTPServer -UseSsl
        }
    }
