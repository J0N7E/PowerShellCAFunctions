<#
 .SYNOPSIS
    Set Certificate Authority Extension

 .DESCRIPTION
    Connect to CA and set extension for pending request

 .EXAMPLE
    Set key usage for digital signature and key encipherment
    Set-CAExtension -RequestId <ID> -KeyUsage @([KEY_USAGE]::DIGITAL_SIGNATURE, [KEY_USAGE]::KEY_ENCIPHERMENT)

    Set basic constraint Subject Type = ca and Path Length = None
    Set-CAExtension -RequestId <ID> -SubjectType CA -PathLength -1

 .NOTES
    AUTHOR Jonas Henriksson

 .LINK
    https://github.com/J0N7E
#>

function Set-CAExtension
{
    [cmdletbinding()]

    Param
    (
        [Parameter(Mandatory=$true)]
        [String]$RequestId,

        [Array]$KeyUsage,

        [ValidateSet('CA', 'EndEntity')]
        [String]$SubjectType,

        [Int]$PathLength,

        [String]$Config
    )

    Begin
    {
        ########
        # Enums
        ########

        # https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertconfig-getconfig
        enum CC
        {
            DEFAULTCONFIG           = 0x00000000
            UIPICKCONFIG            = 0x00000001
            FIRSTCONFIG             = 0x00000002
            LOCALCONFIG             = 0x00000003
            LOCALACTIVECONFIG       = 0x00000004
            UIPICKCONFIGSKIPLOCALCA = 0x00000005
        }

        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/7c715f9f-db50-41c3-abfc-0021c6390d4e
        enum PROPTYPE
        {
            LONG     = 0x00000001
            DATETIME = 0x00000002
            BINARY   = 0x00000003
            STRING   = 0x00000004
        }

        # https://docs.microsoft.com/en-us/windows/win32/api/certif/nf-certif-icertserverexit-getcertificateextensionflags
        enum EXTENSION
        {
            CRITICAL_FLAG = 0x1
            DISABLE_FLAG  = 0x2
        }

        ############
        # Functions
        ############

        function ConvertTo-DERstring ([byte[]]$Bytes)
        {
            if ($Bytes.Length % 2 -eq 1)
            {
                $Bytes += 0
            }

            $String = New-Object System.Text.StringBuilder

            for ($n = 0; $n -lt $Bytes.Count; $n += 2)
            {
                $String.Append([char]([int]$Bytes[$n + 1] -shl 8 -bor $Bytes[$n])) > $null
            }

            Write-Output -InputObject $String.ToString()
        }

        ###############
        # Check Config
        ###############

        if (-not $Config)
        {
            # Get config
            $CA = New-Object -ComObject CertificateAuthority.GetConfig
            $Config = $CA.GetConfig([CC]::LOCALCONFIG)

            if (-not $Config)
            {
                throw "Can't find certificate authority config string, please use -CAConfig parameter."
            }
        }
    }

    Process
    {
        $Extensions = @()

        ####################
        # Basic Constraints
        # 2.5.29.19
        ####################

        if ($SubjectType -or $PathLength)
        {
            $IsCA = $false

            if ($SubjectType -eq 'CA')
            {
                $IsCA = $true
            }

            if (-not $PathLength)
            {
                $PathLength = -1
            }

            # Create new object
            $X509Ext = New-Object -ComObject X509Enrollment.CX509ExtensionBasicConstraints

            # Initialize
            # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509extensionbasicconstraints-initializeencode
            # Debug:
            # [Convert]::FromBase64String($X509Ext.RawData(1))
            $X509Ext.InitializeEncode($IsCA, $PathLength)

            # Add to extensions
            $Extensions +=
            (@{
                'strExtensionName' = '2.5.29.19'
                'Type' = [PROPTYPE]::BINARY
                'Flags' = [EXTENSION]::CRITICAL_FLAG
                'pvarValue' = (ConvertTo-DERstring -Bytes ([Convert]::FromBase64String($X509Ext.RawData(1))))
            })
        }

        ############
        # Key usage
        # 2.5.29.15
        ############

        if ($KeyUsage -and $KeyUsage.Count -gt 0)
        {
            #######
            # Enum
            #######

            # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379410.aspx
            enum KEY_USAGE
            {
                NO                 = 0
                DIGITAL_SIGNATURE  = 0x80
                NON_REPUDIATION    = 0x40
                KEY_ENCIPHERMENT   = 0x20
                DATA_ENCIPHERMENT  = 0x10
                KEY_AGREEMENT      = 0x8
                KEY_CERT_SIGN      = 0x4
                OFFLINE_CRL_SIGN   = 0x2
                CRL_SIGN           = 0x2
                ENCIPHER_ONLY      = 0x1
                DECIPHER_ONLY      = 0x8000
            }

            foreach ($Flag in $KeyUsage)
            {
                $KeyUsageFlags += [KEY_USAGE]::$Flag
            }

            # Create new objecta
            $X509Ext = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage

            # Initialize
            # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509extensionkeyusage-initializeencode
            $X509Ext.InitializeEncode($KeyUsageFlags)

            # Add to extensions
            $Extensions +=
            (@{
                'strExtensionName' = '2.5.29.15'
                'Type' = [PROPTYPE]::BINARY
                'Flags' = [EXTENSION]::CRITICAL_FLAG
                'pvarValue' = (ConvertTo-DERstring -Bytes ([Convert]::FromBase64String($X509Ext.RawData(1))))
            })
        }

        ######
        # Set
        ######

        if ($Extensions.Count -gt 0)
        {
            $CaAdmin = New-Object -ComObject CertificateAuthority.Admin

            # Itterate extensions
            foreach($Ext in $Extensions)
            {
                # https://docs.microsoft.com/en-us/windows/win32/api/certadm/nf-certadm-icertadmin-setcertificateextension
                $CaAdmin.SetCertificateExtension($Config, $RequestID, $Ext['strExtensionName'], $Ext['Type'], $Ext['Flags'], $Ext['pvarValue'])
            }
        }
    }

    End
    {
        Remove-Variable -Name CaAdmin, X509* -ErrorAction SilentlyContinue
    }
}

