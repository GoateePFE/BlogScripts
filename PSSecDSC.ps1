<##############################################################################
Ashley McGlone
Microsoft Premier Field Engineer
March 2017
http://aka.ms/GoateePFE

This is a sample DSC script for implementing the PowerShell logging and
transcription features described in Lee Holmes' white paper "PowerShell Loves
the Blue Team".
https://blogs.msdn.microsoft.com/powershell/2015/06/09/powershell-the-blue-team

For reference, here are the registry keys involved:

HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription
EnableTranscripting,1
OutputDirectory,[Path]
IncludeInvocationHeader,1

HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
EnableScriptBlockLogging,1
EnableScriptBlockInvocationLogging,1

(not implemented below)
HKLM:\Software\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging
EnableProtectedEventLogging,1
EncryptionCertificate,[Certificate]


LEGAL DISCLAIMER
This Sample Code is provided for the purpose of illustration only and is not
intended to be used in a production environment.  THIS SAMPLE CODE AND ANY
RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You a
nonexclusive, royalty-free right to use and modify the Sample Code and to
reproduce and distribute the object code form of the Sample Code, provided
that You agree: (i) to not use Our name, logo, or trademarks to market Your
software product in which the Sample Code is embedded; (ii) to include a valid
copyright notice on Your software product in which the Sample Code is embedded;
and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and
against any claims or lawsuits, including attorneys’ fees, that arise or result
from the use or distribution of the Sample Code.
##########################################################################sdg#>

Configuration EnablePowerShellLogging
{
Param(
    [string]
    $TranscriptPath = 'C:\PSTranscripts',
    [ValidateRange(1,365)]
    [int]
    $TranscriptDays = 14,
    [ValidateRange(1,1024)]
    [int]
    $EventLogSizeInMB = 50
)

    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Node localhost
    {

        ### Script Block Logging ##############################################

        Registry ScriptBlockLogging
        {
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            ValueName = 'EnableScriptBlockLogging'
            ValueData = 1
            ValueType = 'String'
            Ensure    = 'Present'
        }

        # Enable this setting to log start / stop events. Not usually recommended, as it causes
        # a significant impact on log volume
        <#
        Registry ScriptBlockInvocationLogging
        {
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            ValueName = 'EnableScriptBlockInvocationLogging'
            ValueData = 1
            ValueType = 'String'
            Ensure    = 'Present'
        }
        #>

        Script PowerShellLogSize
        {
            GetScript = {
                Return @{
                    Result = Get-WinEvent -ListLog Microsoft-Windows-PowerShell/Operational | Out-String
                }
            }
            TestScript = {
                $Log = Get-WinEvent -ListLog Microsoft-Windows-PowerShell/Operational
                If ($Log.LogMode -ne 'Circular' -or $Log.MaximumSizeInBytes -lt ($using:EventLogSizeInMB * 1MB)) {
                    Write-Verbose 'Event log [Microsoft-Windows-PowerShell/Operational] is NOT in desired state.'
                    Return $false
                } Else {   
                    Write-Verbose 'Event log [Microsoft-Windows-PowerShell/Operational] is in desired state.'
                    Return $true
                }
            }
            SetScript = {
                Write-Verbose 'Applying settings to event log [Microsoft-Windows-PowerShell/Operational].'
                wevtutil set-log Microsoft-Windows-PowerShell/Operational /retention:false /maxsize:$($using:EventLogSizeInMB * 1MB)
            }
        }

        ### Transcription #####################################################

        ### Remove this resource if sending transcripts to a remote share.
        File TranscriptsDirectory
        {
            DestinationPath = $TranscriptPath
            Type            = 'Directory'
            Ensure          = 'Present'
        }

        ### Remove this resource if sending transcripts to a remote share.
        Script TranscriptsDirectoryPermissions
        {
            GetScript = {
                $acl = Get-Acl $using:TranscriptPath
                Return @{
                    Result = $acl.Sddl
                }
            }
            TestScript = {
                $acl = Get-Acl $using:TranscriptPath
                Write-Verbose "Transcript directory permissions: $($acl.Sddl)"
                If ($acl.Sddl -ne 'O:BAG:DUD:PAI(D;OICIIO;FA;;;CO)(A;OICI;0x100196;;;WD)(A;OICI;FA;;;BA)') {
                    Write-Verbose 'Transcript directory permissions are NOT in desired state.'
                    Return $false
                } Else {   
                    Write-Verbose 'Transcript directory permissions are in desired state.'
                    Return $true
                }
            }
            SetScript = {
                Write-Verbose 'Applying transcript directory permissions.'
                # Remove inherited permissions.
                # Allow Administrators full control.
                # Allow Everyone Write and ReadAttributes.
                # Deny CreatorOwner Full Control.
                $acl = Get-Acl $using:TranscriptPath
                $acl.SetSecurityDescriptorSddlForm('O:BAG:DUD:PAI(D;OICIIO;FA;;;CO)(A;OICI;0x100196;;;WD)(A;OICI;FA;;;BA)')
                $acl | Set-Acl $using:TranscriptPath -Verbose
            }
            DependsOn = '[File]TranscriptsDirectory'
        }

        ### Remove this resource if sending transcripts to a remote share.
        ### NOTE: This will generate errors due to permissions of the local transcript directory.
        Script TranscriptsDirectoryTrim
        {
            GetScript = {
                Return @{
                    Result = $using:TranscriptPath
                }
            }
            TestScript = {
                $ErrorActionPreference = 'Stop'
                Try {
                    $OldContent = Get-ChildItem $using:TranscriptPath -Recurse | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays($using:TranscriptDays * -1)}
                }
                Catch {
                    Write-Warning 'Access denied to some of the transcript files.'
                }
                If ($OldContent) {
                    Write-Verbose "Transcript directory contains content older than $($using:TranscriptDays) days."
                    Return $false
                } Else {   
                    Write-Verbose "Transcript directory DOES NOT contain content older than $($using:TranscriptDays) days."
                    Return $true
                }
            }
            SetScript = {
                $ErrorActionPreference = 'Stop'
                Try {
                    Get-ChildItem $using:TranscriptPath -Recurse | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays($using:TranscriptDays * -1)} | Remove-Item -Force -Confirm:$false -Verbose
                }
                Catch {
                    Write-Warning 'Access denied to some of the transcript files.'
                }
            }
            DependsOn = '[File]TranscriptsDirectory'
        }

        Registry Transcription
        {
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
            ValueName = 'EnableTranscripting'
            ValueData = 1
            ValueType = 'String'
            Ensure    = 'Present'
        }

        # Remove this setting to descrease transcript file size
        Registry TranscriptionInvocationHeader
        {
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
            ValueName = 'IncludeInvocationHeader'
            ValueData = 1
            ValueType = 'String'
            Ensure    = 'Present'
        }

        Registry TranscriptionPath
        {
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
            ValueName = 'OutputDirectory'
            ValueData = $TranscriptPath
            ValueType = 'String'
            Ensure    = 'Present'
        }

    }

}

cd c:\temp
EnablePowerShellLogging
Start-DscConfiguration -Path C:\temp\EnablePowerShellLogging -Wait -Verbose -Force

###############################################################################
break

Get-DscConfiguration

dir 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell' -Recurse

###############################################################################
break

Configuration DisablePowerShellLogging
{
Param(
    $Paths = @('HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging',`
    'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription')
)

    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Node localhost
    {
        # Currently the registry resource does not support deleting an entire
        # key. So we will delete each key with a script resource.
        Script RemovePowerShellLogging
        {
            GetScript = {
                Return @{
                    Result = Get-Item -Path $Using:Paths -ErrorAction SilentlyContinue | Out-String
                }
            }
            TestScript = {
                If (Get-Item -Path $Using:Paths -ErrorAction SilentlyContinue) {
                    Write-Verbose "Registry keys for PowerShell logging and/or transcription found."
                    Return $false
                } Else {   
                    Write-Verbose "Registry keys for PowerShell logging and/or transcription NOT found."
                    Return $true
                }
            }
            SetScript = {
                Get-Item -Path $Using:Paths |
                    Remove-Item -Force -Confirm:$false -Verbose
            }
        }

    }

}

cd c:\temp
DisablePowerShellLogging
Start-DscConfiguration -Path C:\temp\DisablePowerShellLogging -Wait -Verbose -Force

break

dir 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell' -Recurse

###############################################################################
break

# Note that the PowerShell policy is cached when the ISE or Console is opened.
# Run these commands in a fresh session to see the effect.
"Catch me if you can"

# Commands run, notice the scriptblock ID
Get-WinEvent -FilterHashtable @{ ProviderName="Microsoft-Windows-PowerShell"; Id = 4104 } -MaxEvents 5 | ft Message -Wrap
Get-WinEvent -FilterHashtable @{ ProviderName="Microsoft-Windows-PowerShell"; Id = 4104 } -MaxEvents 5 | ? Message -like "*catch*" | ft Message -Wrap

# Commands started, notice the scriptblock ID
Get-WinEvent -FilterHashtable @{ ProviderName="Microsoft-Windows-PowerShell"; Id = 4105 } -MaxEvents 5 | ft TimeCreated,Message -Wrap

# Commands stopped, notice the scriptblock ID
Get-WinEvent -FilterHashtable @{ ProviderName="Microsoft-Windows-PowerShell"; Id = 4106 } -MaxEvents 5 | ft TimeCreated,Message -Wrap

# View the transcript output
# NOTE: Access denied if on a local path instead of UNC path
Get-ChildItem 'C:\PSTranscripts' -Recurse
