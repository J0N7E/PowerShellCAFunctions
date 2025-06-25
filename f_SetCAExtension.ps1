<#
 .SYNOPSIS
    Set Certificate Authority Extensions

 .DESCRIPTION
    Connect to CA and set extensions for pending request

 .EXAMPLE
    Get Key Usage enum
    $KEY_USAGE = Set-CAExtension -GetKeyUsage

    Set Key Usage for Digital Signature and Key Encipherment
    Set-CAExtension -RequestId <ID> -KeyUsage @($KEY_USAGE::DIGITAL_SIGNATURE, $KEY_USAGE::KEY_ENCIPHERMENT)

    Get Enhanced Key Usage
    $EKU = Set-CAExtension -GetEKU

    Set Enhanced Key Usage for Client Authentication and Server Authentication
    Set-CAExtension -RequestId <ID> -EnahnacedKeyUsage @($EKU::PKIX_KP_CLIENT_AUTH, $EKU::PKIX_KP_SERVER_AUTH)

    Set Issuance Policy
    Set-CAExtension -RequestId <ID> -IssuancePolicy @(OID1, OID2)

    Set Basic Constraint Subject Type = CA and Path Length = None
    Set-CAExtension -RequestId <ID> -SubjectType CA -PathLength -1

    Get Alt Name enum
    $ALT_NAME = Set-CAExtension -GetAltName

    Set Subject Alternative Names
    Set-CAExtension -RequestId <ID> -SubjectAlternativeNames @{ $ALT_NAME::DNS_NAME = 'fqdn' }

    Set strong certificate mapping OID (1.3.6.1.4.1.311.25.2) to specified SID
    Set-CAExtension -RequestId <ID> -StrongMappingSID <SID>

 .NOTES
    Debug:
    [Convert]::FromBase64String($X509Ext.RawData(1))

 .NOTES
    AUTHOR Jonas Henriksson

 .LINK
    https://github.com/J0N7E
#>

function Set-CAExtension
{
    [cmdletbinding(DefaultParameterSetName='Set')]

    Param
    (
        [Parameter(ParameterSetName='Set', Mandatory=$true)]
        [String]$RequestId,

        [Parameter(ParameterSetName='GetKeyUsage')]
        [Switch]$GetKeyUsage,

        [Parameter(ParameterSetName='Set')]
        [Array]$KeyUsage,

        [Parameter(ParameterSetName='GetEKU')]
        [Switch]$GetEKU,

        [Parameter(ParameterSetName='Set')]
        [Array]$EnhancedKeyUsage,

        [Parameter(ParameterSetName='Set')]
        [Array]$IssuancePolicy,

        [Parameter(ParameterSetName='Set')]
        [ValidateSet('CA', 'EndEntity')]
        [String]$SubjectType,

        [Parameter(ParameterSetName='Set')]
        [String]$PathLength,

        [Parameter(ParameterSetName='GetAltName')]
        [Switch]$GetAltName,

        [Parameter(ParameterSetName='Set')]
        [Hashtable]$SubjectAlternativeNames,

        [Parameter(ParameterSetName='Set')]
        [String]$StrongMappingSID,

        [String]$Config
    )

    Begin
    {
        ########
        # Enums
        ########

        # https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertconfig-getconfig
        enum CERT_CONFIG
        {
            DEFAULT           = 0x0
            UIPICK            = 0x1
            FIRST             = 0x2
            LOCAL             = 0x3
            LOCALACTIVE       = 0x4
            UIPICKSKIPLOCALCA = 0x5
        }

        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/8116912a-59e6-4849-83dd-77b39b6370e0
        enum PROPTYPE
        {
            LONG     = 0x1
            DATETIME = 0x2
            BINARY   = 0x3
            STRING   = 0x4
        }

        # https://docs.microsoft.com/en-us/windows/win32/api/certif/nf-certif-icertserverexit-getcertificateextensionflags
        enum POLICY
        {
            NON_CRITICAL = 0x0
            CRITICAL     = 0x1
            DISABLE      = 0x2
        }

        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-x509keyusageflags
        enum KEY_USAGE
        {
            NONE               = 0
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

        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-ix509extensionenhancedkeyusage
        Add-Type -TypeDefinition @"
        using System;
        using System.Reflection;
        using System.ComponentModel;

        public enum ENHANCED_KEY_USAGE
        {
            [DescriptionAttribute("1.3.6.1.4.1.311.10.12.1")]ANY_APPLICATION_POLICY,
            [DescriptionAttribute("1.3.6.1.4.1.311.20.1")]AUTO_ENROLL_CTL_USAGE,
            [DescriptionAttribute("1.3.6.1.4.1.311.10.5.1")]DRM,
            [DescriptionAttribute("1.3.6.1.4.1.311.21.19")]DS_EMAIL_REPLICATION,
            [DescriptionAttribute("1.3.6.1.4.1.311.10.3.4")]EFS_RECOVERY,
            [DescriptionAttribute("1.3.6.1.4.1.311.10.3.8")]EMBEDDED_NT_CRYPTO,
            [DescriptionAttribute("1.3.6.1.4.1.311.20.2.1")]ENROLLMENT_AGENT,
            [DescriptionAttribute("1.3.6.1.5.5.8.2.2")]IPSEC_KP_IKE_INTERMEDIATE,
            [DescriptionAttribute("1.3.6.1.4.1.311.21.5")]KP_CA_EXCHANGE,
            [DescriptionAttribute("1.3.6.1.4.1.311.10.3.1")]KP_CTL_USAGE_SIGNING,
            [DescriptionAttribute("1.3.6.1.4.1.311.10.3.12")]KP_DOCUMENT_SIGNING,
            [DescriptionAttribute("1.3.6.1.4.1.311.10.3.4")]KP_EFS,
            [DescriptionAttribute("1.3.6.1.4.1.311.10.3.11")]KP_KEY_RECOVERY,
            [DescriptionAttribute("1.3.6.1.4.1.311.21.6")]KP_KEY_RECOVERY_AGENT,
            [DescriptionAttribute("1.3.6.1.4.1.311.10.3.13")]KP_LIFETIME_SIGNING,
            [DescriptionAttribute("1.3.6.1.4.1.311.10.3.10")]KP_QUALIFIED_SUBORDINATION,
            [DescriptionAttribute("1.3.6.1.4.1.311.20.2.2")]KP_SMARTCARD_LOGON,
            [DescriptionAttribute("1.3.6.1.4.1.311.10.3.2")]KP_TIME_STAMP_SIGNING,
            [DescriptionAttribute("1.3.6.1.4.1.311.10.6.2")]LICENSE_SERVER,
            [DescriptionAttribute("1.3.6.1.4.1.311.10.6.1")]LICENSES,
            [DescriptionAttribute("1.3.6.1.4.1.311.10.3.7")]NT5_CRYPTO,
            [DescriptionAttribute("1.3.6.1.4.1.311.10.3.7")]OEM_WHQL_CRYPTO,
            [DescriptionAttribute("1.3.6.1.5.5.7.3.2")]PKIX_KP_CLIENT_AUTH,
            [DescriptionAttribute("1.3.6.1.5.5.7.3.3")]PKIX_KP_CODE_SIGNING,
            [DescriptionAttribute("1.3.6.1.5.5.7.3.4")]PKIX_KP_EMAIL_PROTECTION,
            [DescriptionAttribute("1.3.6.1.5.5.7.3.5")]PKIX_KP_IPSEC_END_SYSTEM,
            [DescriptionAttribute("1.3.6.1.5.5.7.3.6")]PKIX_KP_IPSEC_TUNNEL,
            [DescriptionAttribute("1.3.6.1.5.5.7.3.7")]PKIX_KP_IPSEC_USER,
            [DescriptionAttribute("1.3.6.1.5.5.7.3.9")]PKIX_KP_OCSP_SIGNING,
            [DescriptionAttribute("1.3.6.1.5.5.7.3.1")]PKIX_KP_SERVER_AUTH,
            [DescriptionAttribute("1.3.6.1.5.5.7.3.8")]PKIX_KP_TIMESTAMP_SIGNING,
            [DescriptionAttribute("1.3.6.1.4.1.311.10.3.9")]ROOT_LIST_SIGNER,
            [DescriptionAttribute("1.3.6.1.4.1.311.10.3.5")]WHQL_CRYPTO
        }

        public class EnumUtils
        {
            public static string stringValueOf(Enum value)
            {
                FieldInfo fi = value.GetType().GetField(value.ToString());
                DescriptionAttribute[] attributes = (DescriptionAttribute[]) fi.GetCustomAttributes( typeof(DescriptionAttribute), false);
                if (attributes.Length > 0)
                {
                    return attributes[0].Description;
                }
                else
                {
                    return value.ToString();
                }
            }

            public static object enumValueOf(string value, Type enumType)
            {
                string[] names = Enum.GetNames(enumType);
                foreach (string name in names)
                {
                    if (stringValueOf((Enum)Enum.Parse(enumType, name)).Equals(value))
                    {
                        return Enum.Parse(enumType, name);
                    }
                }

                throw new ArgumentException("The string is not a description or value of the specified enum.");
            }
        }
"@

        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-alternativenametype
        enum ALT_NAME
        {
            #UNKNOWN            = 0
            #OTHER_NAME         = 1
            RFC822_NAME         = 2
            DNS_NAME            = 3
            #X400_ADDRESS       = 4
            DIRECTORY_NAME      = 5
            #EDI_PARTY_NAME     = 6
            URL                 = 7
            IP_ADDRESS          = 8
            REGISTERED_ID       = 9
            GUID                = 10
            USER_PRINCIPLE_NAME = 11
        }

        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-encodingtype
        enum CRYPT_STRING
        {
            BASE64HEADER        = 0
            BASE64              = 0x1
            BINARY              = 0x2
            BASE64REQUESTHEADER = 0x3
            HEX                 = 0x4
            HEXASCII            = 0x5
            BASE64_ANY          = 0x6
            ANY                 = 0x7
            HEX_ANY             = 0x8
            BASE64X509CRLHEADER = 0x9
            HEXADDR             = 0xa
            HEXASCIIADDR        = 0xb
            HEXRAW              = 0xc
            BASE64URI           = 0xd
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

        #######################
        # Get ParameterSetName
        #######################

        $ParameterSetName = $PsCmdlet.ParameterSetName

        ###################
        # Get local config
        ###################

        if (-not $Config)
        {
            # Get config
            $CA = New-Object -ComObject CertificateAuthority.GetConfig
            $Config = $CA.GetConfig([CERT_CONFIG]::LOCAL)

            if (-not $Config)
            {
                throw "Can't find local certificate authority, please use -Config parameter."
            }
        }
    }

    Process
    {
        if ($ParameterSetName -eq 'Set')
        {
            $Extensions = @()

            ############
            # Key Usage
            # 2.5.29.15
            ############

            if ($KeyUsage -and $KeyUsage.Count -gt 0)
            {
                foreach ($Flag in $KeyUsage)
                {
                    $KeyUsageFlags += [KEY_USAGE]::$Flag
                }

                # Create extension object
                $X509Ext = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage

                # Initialize
                # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509extensionkeyusage-initializeencode
                $X509Ext.InitializeEncode($KeyUsageFlags)

                # Add to extensions
                $Extensions +=
                (@{
                    'strExtensionName' = '2.5.29.15'
                    'Type' = [PROPTYPE]::BINARY
                    'Flags' = [POLICY]::NON_CRITICAL
                    'pvarValue' = (
                        ConvertTo-DERstring -Bytes (
                            [Convert]::FromBase64String($X509Ext.RawData(1))
                        )
                    )
                })
            }

            #####################
            # Enhanced Key Usage
            # 2.5.29.37
            #####################

            if ($EnhancedKeyUsage -and $EnhancedKeyUsage.Count -gt 0)
            {
                # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-iobjectids
                $ObjectIds = New-Object -ComObject X509Enrollment.CObjectIds

                foreach ($Flag in $EnhancedKeyUsage)
                {
                    # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-iobjectid
                    $ObjectId = New-Object -ComObject X509Enrollment.CObjectId
                    $ObjectId.InitializeFromValue("$([EnumUtils]::stringValueOf([ENHANCED_KEY_USAGE]::$Flag))")

                    $ObjectIds.Add($ObjectId)
                }

                # Create extension object
                $X509Ext = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage

                # Initialize
                # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509extensionenhancedkeyusage-initializeencode
                $X509Ext.InitializeEncode($ObjectIds)

                # Add to extensions
                $Extensions +=
                (@{
                    'strExtensionName' = '2.5.29.37'
                    'Type' = [PROPTYPE]::BINARY
                    'Flags' = [POLICY]::NON_CRITICAL
                    'pvarValue' = (
                        ConvertTo-DERstring -Bytes (
                            [Convert]::FromBase64String($X509Ext.RawData(1))
                        )
                    )
                })
            }

            ##################
            # Issuance Policy
            # 2.5.29.32
            ##################

            if ($IssuancePolicy -and $IssuancePolicy.Count -gt 0)
            {
                # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-icertificatepolicies
                $CertificatePolicies = New-Object -ComObject X509Enrollment.CCertificatePolicies

                foreach ($Policy in $IssuancePolicy)
                {
                    # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-iobjectid
                    $ObjectId = New-Object -ComObject X509Enrollment.CObjectId
                    $ObjectId.InitializeFromValue($Policy)

                    # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-icertificatepolicy
                    $CertificatePolicy  = New-Object -ComObject X509Enrollment.CCertificatePolicy
                    $CertificatePolicy.Initialize($ObjectId)

                    $CertificatePolicies.Add($CertificatePolicy)
                }

                # Create extension object
                $X509Ext = New-Object -ComObject X509Enrollment.CX509ExtensionCertificatePolicies

                # Initialize
                # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509extensionenhancedkeyusage-initializeencode
                $X509Ext.InitializeEncode($CertificatePolicies)

                # Add to extensions
                $Extensions +=
                (@{
                    'strExtensionName' = '2.5.29.32'
                    'Type' = [PROPTYPE]::BINARY
                    'Flags' = [POLICY]::NON_CRITICAL
                    'pvarValue' = (
                        ConvertTo-DERstring -Bytes (
                            [Convert]::FromBase64String($X509Ext.RawData(1))
                        )
                    )
                })
            }

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

                if ($PathLength -like $null)
                {
                    # Default to "None"
                    $PathLength = -1
                }

                # Create new object
                $X509Ext = New-Object -ComObject X509Enrollment.CX509ExtensionBasicConstraints

                # Initialize
                # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509extensionbasicconstraints-initializeencode
                $X509Ext.InitializeEncode($IsCA, $PathLength)

                # Add to extensions
                $Extensions +=
                (@{
                    'strExtensionName' = '2.5.29.19'
                    'Type' = [PROPTYPE]::BINARY
                    'Flags' = [POLICY]::CRITICAL
                    'pvarValue' = (
                        ConvertTo-DERstring -Bytes (
                            [Convert]::FromBase64String($X509Ext.RawData(1))
                        )
                    )
                })
            }

            ############################
            # Subject Alternative Names
            # 2.5.29.17
            ############################

            if ($SubjectAlternativeNames -and $SubjectAlternativeNames.Count -gt 0)
            {
                # Create alternative name collection
                $AlternativeNames = New-Object -ComObject X509Enrollment.CAlternativeNames

                foreach ($Pair in $SubjectAlternativeNames.GetEnumerator()) {

                    # Create alternative name
                    $AlternativeName = New-Object -ComObject X509Enrollment.CAlternativeName

                    try
                    {
                        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ialternativename-initializefromstring
                        switch ($Pair.Name)
                        {
                            {$_ -in @('RFC822_NAME', 'DNS_NAME', 'URL', 'REGISTERED_ID', 'USER_PRINCIPLE_NAME')}
                            {
                                $AlternativeName.InitializeFromString([ALT_NAME]::$($Pair.Name), $Pair.Value)
                            }

                            {$_ -in @('DIRECTORY_NAME', 'IP_ADDRESS', 'GUID')}
                            {
                                # InitializeFromRawData
                                throw [System.Management.Automation.PSNotImplementedException] "Not implemented."
                            }
                        }
                    }
                    catch [Exception]
                    {
                        throw $_
                    }

                    # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ialternativenames-add
                    $AlternativeNames.Add($AlternativeName)
                }

                # Create extension object
                $X509Ext = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames

                # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509extensionalternativenames-initializeencode
                $X509Ext.InitializeEncode($AlternativeNames)

                # Add to extensions
                $Extensions +=
                (@{
                    'strExtensionName' = '2.5.29.17'
                    'Type' = [PROPTYPE]::BINARY
                    'Flags' = [POLICY]::NON_CRITICAL
                    'pvarValue' = (
                        ConvertTo-DERstring -Bytes (
                            [Convert]::FromBase64String($X509Ext.RawData(1))
                        )
                    )
                })
            }

            #############################
            # Strong Certificate Mapping
            # 1.3.6.1.4.1.311.25.2
            #############################

            if ($StrongMappingSID)
            {
                # Create alternative name collection
                $AlternativeNames = New-Object -ComObject X509Enrollment.CAlternativeNames

                # Create alternative name
                $AlternativeName = New-Object -ComObject X509Enrollment.CAlternativeName

                try
                {
                    # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-iobjectid
                    $OID = New-Object -ComObject X509Enrollment.CObjectId
                    $OID.InitializeFromValue('1.3.6.1.4.1.311.25.2.1')

                    # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ialternativename-initializefromothername
                    $AlternativeName.InitializeFromOtherName($OID, [CRYPT_STRING]::BASE64, [Convert]::ToBase64String([System.Text.Encoding]::Default.GetBytes($StrongMappingSID)), $true)
                }
                catch [Exception]
                {
                    throw $_
                }

                # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ialternativenames-add
                $AlternativeNames.Add($AlternativeName)

                # Create extension object
                $X509Ext = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames

                # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509extensionalternativenames-initializeencode
                $X509Ext.InitializeEncode($AlternativeNames)

                # Add to extensions
                $Extensions +=
                (@{
                    'strExtensionName' = '1.3.6.1.4.1.311.25.2'
                    'Type' = [PROPTYPE]::BINARY
                    'Flags' = [POLICY]::NON_CRITICAL
                    'pvarValue' = (
                        ConvertTo-DERstring -Bytes (
                            [Convert]::FromBase64String($X509Ext.RawData(1))
                        )
                    )
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
                    $CaAdmin.SetCertificateExtension(
                        $Config,
                        $RequestID,
                        $Ext['strExtensionName'],
                        $Ext['Type'],
                        $Ext['Flags'],
                        $Ext['pvarValue']
                    )
                }
            }
        }
        elseif ($GetKeyUsage.IsPresent)
        {
            Write-Output -InputObject ([KEY_USAGE])
        }
        elseif ($GetAltName.IsPresent)
        {
            Write-Output -InputObject ([ALT_NAME])
        }
        elseif ($GetEKU.IsPresent)
        {
            Write-Output -InputObject ([ENHANCED_KEY_USAGE])
        }
    }

    End
    {
        Remove-Variable -Name CaAdmin, X509Ext -ErrorAction SilentlyContinue
    }
}

# SIG # Begin signature block
# MIIesgYJKoZIhvcNAQcCoIIeozCCHp8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD8752YWqYhCBJC
# z39+KYRHfT2J4OWA8Nit9WXmtkDlAaCCGA4wggUHMIIC76ADAgECAhB0XMs0val9
# mEnBo5ekK6KYMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNVBAMMBUowTjdFMB4XDTIz
# MDkwNzE4NTk0NVoXDTI4MDkwNzE5MDk0NFowEDEOMAwGA1UEAwwFSjBON0UwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDRw1gJO1wnpdRIbqVo1gfsnMV8
# kxOJBp/FDV1XxyN0njKwlcA6zyudii33AqXYWUojp4xPoXzBGkVuoqqZOkSXHMz5
# /OScP3fe4QEtIC6X9vSQuWvo9jaih0kLbRUEBTG2EVRiHsVyeLR3DPgSNckbGJ54
# MMtlhFPchHo/N7BpaGrUtdjd+F59hDVDaeoe6VVYPVaC5yAgUR9QkJZw69+YkET4
# S+Q09WgoCoXEnrVnnjPzLq0iN0rdSOrhuBE5CouwUwr6YgjU6pwtEoyBaRUhL2cd
# 8UXLzVUgy9+Bo6mhJUtq1ujECc6afx26wkDYMwfo4vTdIgFv8XATvrvWyO0a4ZGn
# 6eU+eS+hWoURP2iVlYPGUY555F1NzeOVwQ9v1cumIaOVB8x+TjJxLCtomqfVxgO9
# JeHcrqW/Q55Itr9VBGUSk6a20oEQj94UwrvoNmkbEW+/XE6DWmHf7TWEJug5d4+7
# 2pI2TmGcisERv16qSzevlkN+uUTCMVSF32Qt7ZQoRocrscj37fHVaFOA1EpbMrOp
# RwX1pWWkNBGmWptQwkTMzHNFQiTTU0OrDjqCNRh63pWcg+qdAB7ZstaoMx4vdfo/
# twAfHDTnI403nUyrIEV1gLUyJ5i5Tgw6gh8g3ozq8Qaftq+PD1rhel+ByG23LZ42
# AhGD4q4ndfG13VEONQIDAQABo10wWzAOBgNVHQ8BAf8EBAMCBaAwKgYDVR0lBCMw
# IQYIKwYBBQUHAwMGCSsGAQQBgjdQAQYKKwYBBAGCNwoDBDAdBgNVHQ4EFgQUWNAE
# eD3ij461l5HFCgfSYoXMwCkwDQYJKoZIhvcNAQELBQADggIBAFKCUuzQ8KfuDfqI
# ZG+peeD9+r7qcvdlIt4tRdIOgVcqEncrrAVKIcEm0Fi1Zzs6cchsiDUUUUCLkYg/
# nowzCY3g2hjQOsE3QaWHgmr+WG6JqHnOz/2/9pS+3C8EPg1VfQb/Am5G5fr3tRBm
# u2RaeKcHjoEw9T6ASDVy2fRXjNDd9rOtyYmoP3EjAqU5ey/E4A7k4nnW5x2y5sPp
# CQlr77hsZ3keGgLz87XybHPphhqA6ddYk5vJuTB2QML0xSPLnBk0C/jwORQz44Ct
# t8zdml9wBVOcOt+7Omg4pORx2Bs37hVckL+XLUP3x/4ikQ7DVQi1fweDrtZ9T2xd
# whj5+CHMc8cXzri+nYX8bvmLTYyip5Gl47eC7C6bcNsoKQq2zlLVBecTumZ6p7hT
# n3mMJWEQt4HqJ+u+PS6VKU5TkYS3A1jlUvRPdwd6AGa1BcV9ChPq9ugXqb0juRWU
# oZPhYjwz9RBgJDZk/cdON1Ie31RwmyUYyoPGFuQYsfj0RI/mCFtF12WXbh2zDR0X
# 3qU4gSaEHTVQ0jPjROietordyS4l2euH/Z8dhvJwYeOSjCIxQlBqKFtkFEq8EeGs
# zs65D3oz2DwaTZEIip1fSU7yfbJLx+fMShZ7wVXATluADk3CXqJh2izO5tiCH6yJ
# Ux7YQVpSHQNdeltDcnGMwZ7mpUrXMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21Di
# CEAYWjANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGln
# aUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtE
# aWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzEx
# MTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBU
# cnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/
# 5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xuk
# OBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpz
# MpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7Fsa
# vOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qT
# XtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRz
# Km6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRc
# Ro9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADk
# RSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMY
# RJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4m
# rLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C
# 1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYD
# VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYD
# VR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkG
# CCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQu
# Y29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGln
# aUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmww
# EQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+g
# o3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0
# /4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnL
# nU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU9
# 6LHc/RzY9HdaXFSMb++hUD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ
# 9VVrzyerbHbObyMt9H5xaiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9X
# ql4o4rmUMIIGrjCCBJagAwIBAgIQBzY3tyRUfNhHrP0oZipeWzANBgkqhkiG9w0B
# AQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVk
# IFJvb3QgRzQwHhcNMjIwMzIzMDAwMDAwWhcNMzcwMzIyMjM1OTU5WjBjMQswCQYD
# VQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lD
# ZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKR
# N6mXUaHW0oPRnkyibaCwzIP5WvYRoUQVQl+kiPNo+n3znIkLf50fng8zH1ATCyZz
# lm34V6gCff1DtITaEfFzsbPuK4CEiiIY3+vaPcQXf6sZKz5C3GeO6lE98NZW1Oco
# LevTsbV15x8GZY2UKdPZ7Gnf2ZCHRgB720RBidx8ald68Dd5n12sy+iEZLRS8nZH
# 92GDGd1ftFQLIWhuNyG7QKxfst5Kfc71ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRA
# p8ByxbpOH7G1WE15/tePc5OsLDnipUjW8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+g
# GkcgQ+NDY4B7dW4nJZCYOjgRs/b2nuY7W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU
# 8lKVEStYdEAoq3NDzt9KoRxrOMUp88qqlnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/
# FDTP0kyr75s9/g64ZCr6dSgkQe1CvwWcZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwj
# jVj33GHek/45wPmyMKVM1+mYSlg+0wOI/rOP015LdhJRk8mMDDtbiiKowSYI+RQQ
# EgN9XyO7ZONj4KbhPvbCdLI/Hgl27KtdRnXiYKNYCQEoAA6EVO7O6V3IXjASvUae
# tdN2udIOa5kM0jO0zbECAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAw
# HQYDVR0OBBYEFLoW2W1NhS9zKXaaL3WMaiCPnshvMB8GA1UdIwQYMBaAFOzX44LS
# cV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEF
# BQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
# Z2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYy
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5j
# cmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEB
# CwUAA4ICAQB9WY7Ak7ZvmKlEIgF+ZtbYIULhsBguEE0TzzBTzr8Y+8dQXeJLKftw
# ig2qKWn8acHPHQfpPmDI2AvlXFvXbYf6hCAlNDFnzbYSlm/EUExiHQwIgqgWvalW
# zxVzjQEiJc6VaT9Hd/tydBTX/6tPiix6q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQm
# h2ySvZ180HAKfO+ovHVPulr3qRCyXen/KFSJ8NWKcXZl2szwcqMj+sAngkSumScb
# qyQeJsG33irr9p6xeZmBo1aGqwpFyd/EjaDnmPv7pp1yr8THwcFqcdnGE4AJxLaf
# zYeHJLtPo0m5d2aR8XKc6UsCUqc3fpNTrDsdCEkPlM05et3/JWOZJyw9P2un8WbD
# Qc1PtkCbISFA0LcTJM3cHXg65J6t5TRxktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0K
# XzM5h0F4ejjpnOHdI/0dKNPH+ejxmF/7K9h+8kaddSweJywm228Vex4Ziza4k9Tm
# 8heZWcpw8De/mADfIBZPJ/tgZxahZrrdVcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9
# gdkT/r+k0fNX2bwE+oLeMt8EifAAzV3C+dAjfwAL5HYCJtnwZXZCpimHCUcr5n8a
# pIUP/JiW9lVUKx+A+sDyDivl1vupL0QVSucTDh3bNzgaoSv27dZ8/DCCBrwwggSk
# oAMCAQICEAuuZrxaun+Vh8b56QTjMwQwDQYJKoZIhvcNAQELBQAwYzELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2Vy
# dCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTAeFw0y
# NDA5MjYwMDAwMDBaFw0zNTExMjUyMzU5NTlaMEIxCzAJBgNVBAYTAlVTMREwDwYD
# VQQKEwhEaWdpQ2VydDEgMB4GA1UEAxMXRGlnaUNlcnQgVGltZXN0YW1wIDIwMjQw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC+anOf9pUhq5Ywultt5lmj
# tej9kR8YxIg7apnjpcH9CjAgQxK+CMR0Rne/i+utMeV5bUlYYSuuM4vQngvQepVH
# VzNLO9RDnEXvPghCaft0djvKKO+hDu6ObS7rJcXa/UKvNminKQPTv/1+kBPgHGlP
# 28mgmoCw/xi6FG9+Un1h4eN6zh926SxMe6We2r1Z6VFZj75MU/HNmtsgtFjKfITL
# utLWUdAoWle+jYZ49+wxGE1/UXjWfISDmHuI5e/6+NfQrxGFSKx+rDdNMsePW6FL
# rphfYtk/FLihp/feun0eV+pIF496OVh4R1TvjQYpAztJpVIfdNsEvxHofBf1BWka
# dc+Up0Th8EifkEEWdX4rA/FE1Q0rqViTbLVZIqi6viEk3RIySho1XyHLIAOJfXG5
# PEppc3XYeBH7xa6VTZ3rOHNeiYnY+V4j1XbJ+Z9dI8ZhqcaDHOoj5KGg4YuiYx3e
# Ym33aebsyF6eD9MF5IDbPgjvwmnAalNEeJPvIeoGJXaeBQjIK13SlnzODdLtuThA
# LhGtyconcVuPI8AaiCaiJnfdzUcb3dWnqUnjXkRFwLtsVAxFvGqsxUA2Jq/WTjbn
# NjIUzIs3ITVC6VBKAOlb2u29Vwgfta8b2ypi6n2PzP0nVepsFk8nlcuWfyZLzBaZ
# 0MucEdeBiXL+nUOGhCjl+QIDAQABo4IBizCCAYcwDgYDVR0PAQH/BAQDAgeAMAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwIAYDVR0gBBkwFzAI
# BgZngQwBBAIwCwYJYIZIAYb9bAcBMB8GA1UdIwQYMBaAFLoW2W1NhS9zKXaaL3WM
# aiCPnshvMB0GA1UdDgQWBBSfVywDdw4oFZBmpWNe7k+SH3agWzBaBgNVHR8EUzBR
# ME+gTaBLhklodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# RzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3JsMIGQBggrBgEFBQcBAQSB
# gzCBgDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMFgGCCsG
# AQUFBzAChkxodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEB
# CwUAA4ICAQA9rR4fdplb4ziEEkfZQ5H2EdubTggd0ShPz9Pce4FLJl6reNKLkZd5
# Y/vEIqFWKt4oKcKz7wZmXa5VgW9B76k9NJxUl4JlKwyjUkKhk3aYx7D8vi2mpU1t
# KlY71AYXB8wTLrQeh83pXnWwwsxc1Mt+FWqz57yFq6laICtKjPICYYf/qgxACHTv
# ypGHrC8k1TqCeHk6u4I/VBQC9VK7iSpU5wlWjNlHlFFv/M93748YTeoXU/fFa9hW
# JQkuzG2+B7+bMDvmgF8VlJt1qQcl7YFUMYgZU1WM6nyw23vT6QSgwX5Pq2m0xQ2V
# 6FJHu8z4LXe/371k5QrN9FQBhLLISZi2yemW0P8ZZfx4zvSWzVXpAb9k4Hpvpi6b
# Ue8iK6WonUSV6yPlMwerwJZP/Gtbu3CKldMnn+LmmRTkTXpFIEB06nXZrDwhCGED
# +8RsWQSIXZpuG4WLFQOhtloDRWGoCwwc6ZpPddOFkM2LlTbMcqFSzm4cd0boGhBq
# 7vkqI1uHRz6Fq1IX7TaRQuR+0BGOzISkcqwXu7nMpFu3mgrlgbAW+BzikRVQ3K2Y
# HcGkiKjA4gi4OA/kz1YCsdhIBHXqBzR0/Zd2QwQ/l4Gxftt/8wY3grcc/nS//TVk
# ej9nmUYu83BDtccHHXKibMs/yXHhDXNkoPIdynhVAku7aRZOwqw6pDGCBfowggX2
# AgEBMCQwEDEOMAwGA1UEAwwFSjBON0UCEHRcyzS9qX2YScGjl6QropgwDQYJYIZI
# AWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0B
# CQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAv
# BgkqhkiG9w0BCQQxIgQgKKI94piLpfeNHIgO7NUb//p8N50dJocY/VaJa62IVD8w
# DQYJKoZIhvcNAQEBBQAEggIAaSf42XUhJc2j+fWzn87cbIJOaH/QB9YXYFES2rRc
# ADDNGdkHEqef+yS2Ysd2R1Hzw1EkcIhlzezDfMa7bB90VdIoEtyen/5Kbrx1C4/c
# QYg2MircYIwIBgLzcPihM+0kcdILXdiG4MTKhQlJt9ZgFQP8Gb+Dsbhgll3YDBWs
# +gEta4FlUZd7UxUCOWs8Mp0LzcWiWBbJSzP8znQml8QQZchyY6k9qB/5t4DBr45I
# BsB979VxIreen22ZeDI9nQ7TOCx4ZL8XLTpgsd0Abl6fNShTSbw5xy9HTWPI6Buy
# 0JO27hpjgYNaBF99A/JLcxV+DRfrvHhGE8xG9ebbcrdtSY4PUTebR58vjk/brzKv
# gcgG3zv82/DJbyIm3dp65g9b1jgjE5KM4ALzQukfDU1yPovr6YuFF5ZF4QMecGag
# JA5/RUpWuWOw0LtjGVQTBPTTknBfLXKsLpA3Ez98WsS6OR38Po7UFM5fyRGEyQIe
# oP+K6QP9/WTPvdnGSx7EbboO1z4A/HrL4xVpPmHRZRtDCFyDr7+kvxYn+WJ4OLmz
# wutdZb59QnzxcKjAy4s4qIoH+zMPnbaOfZrU11ku+ndUuCt8GzNqgeSYSsl994Zy
# motD+hoi+cg7oMwSpnyPzP8hiDaTPoB1W1Ra2qgi8xgR5KptDrLFnRb5rjmNofHd
# S5ahggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBjMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhALrma8Wrp/
# lYfG+ekE4zMEMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMjUwNjI1MDAxNjEyWjAvBgkqhkiG9w0BCQQx
# IgQgXlxxttlNMCDqBT5Db+bnMy0XRkVm2ksoqy74W3oRepMwDQYJKoZIhvcNAQEB
# BQAEggIAmk4+L2fh1W+0PYmy9k7FtSX5wyWRkZ4rTGKpm/bzv5FKO3gMlIFz82+h
# We2AgU4od5LSGeMdQd0BR08fIbDUWAg/tD++IMjcnO6F0XhxkVop7AknaNJI6ruN
# DiZo/VxYFQ2QwJE4A+KJkBUmUsnEuXskcOLxTNNw4vHiTfUfXhUdT6olzZhzy9nk
# CotunknMqT+mHpCRQZx24ss28GlTzkgeAog9r5tbOALmRDJNKnRVU2m9eCm2ayqk
# E6vVEgE+WLtQf/klOi1YI5xU97OC+MQLcEU42JEtk48QxrkWqsV5TGDnQxCp5JAj
# s8aVluhgfvRsOkQCbTQv8PwCTmKjClPjoPT9DvP+pET2lWx8G7y0E8sUwQeIVAzR
# DnduMioFsVvfvmsif71vqIPP0foAzm95NgSRyrqjJmvJR7fRYlB0UahUg4ield5u
# ZYkzSPBKpIcrFg1xGKMLfJrZHUyaV3RU/ZA8HKGsBg5ElgBSh8FcyXl5LaDLMdrH
# qhb7I9AQ4jhYvJZQDRiYgmxSFswgEE1qjtB517moqB5XIh9C0JJvvzl6mpmy8RHa
# kgWoYxuQyAi6MUBAIAs4xR+PLhkWj0KnfAZOgK0GZ+GTFHajzfQtIS29lRZU/5Sx
# AK3PKZrBng8QjBhbpmH0gZGOiKgER/if5scoRAmfnMLl0/RiLn4=
# SIG # End signature block
