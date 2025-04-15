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
# MIIekwYJKoZIhvcNAQcCoIIehDCCHoACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUeqTHxBGwXg3WZzmU9gnuP82I
# yl6gghgUMIIFBzCCAu+gAwIBAgIQdFzLNL2pfZhJwaOXpCuimDANBgkqhkiG9w0B
# AQsFADAQMQ4wDAYDVQQDDAVKME43RTAeFw0yMzA5MDcxODU5NDVaFw0yODA5MDcx
# OTA5NDRaMBAxDjAMBgNVBAMMBUowTjdFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEA0cNYCTtcJ6XUSG6laNYH7JzFfJMTiQafxQ1dV8cjdJ4ysJXAOs8r
# nYot9wKl2FlKI6eMT6F8wRpFbqKqmTpElxzM+fzknD933uEBLSAul/b0kLlr6PY2
# oodJC20VBAUxthFUYh7Fcni0dwz4EjXJGxieeDDLZYRT3IR6PzewaWhq1LXY3fhe
# fYQ1Q2nqHulVWD1WgucgIFEfUJCWcOvfmJBE+EvkNPVoKAqFxJ61Z54z8y6tIjdK
# 3Ujq4bgROQqLsFMK+mII1OqcLRKMgWkVIS9nHfFFy81VIMvfgaOpoSVLatboxAnO
# mn8dusJA2DMH6OL03SIBb/FwE7671sjtGuGRp+nlPnkvoVqFET9olZWDxlGOeeRd
# Tc3jlcEPb9XLpiGjlQfMfk4ycSwraJqn1cYDvSXh3K6lv0OeSLa/VQRlEpOmttKB
# EI/eFMK76DZpGxFvv1xOg1ph3+01hCboOXePu9qSNk5hnIrBEb9eqks3r5ZDfrlE
# wjFUhd9kLe2UKEaHK7HI9+3x1WhTgNRKWzKzqUcF9aVlpDQRplqbUMJEzMxzRUIk
# 01NDqw46gjUYet6VnIPqnQAe2bLWqDMeL3X6P7cAHxw05yONN51MqyBFdYC1MieY
# uU4MOoIfIN6M6vEGn7avjw9a4Xpfgchtty2eNgIRg+KuJ3Xxtd1RDjUCAwEAAaNd
# MFswDgYDVR0PAQH/BAQDAgWgMCoGA1UdJQQjMCEGCCsGAQUFBwMDBgkrBgEEAYI3
# UAEGCisGAQQBgjcKAwQwHQYDVR0OBBYEFFjQBHg94o+OtZeRxQoH0mKFzMApMA0G
# CSqGSIb3DQEBCwUAA4ICAQBSglLs0PCn7g36iGRvqXng/fq+6nL3ZSLeLUXSDoFX
# KhJ3K6wFSiHBJtBYtWc7OnHIbIg1FFFAi5GIP56MMwmN4NoY0DrBN0Glh4Jq/lhu
# iah5zs/9v/aUvtwvBD4NVX0G/wJuRuX697UQZrtkWninB46BMPU+gEg1ctn0V4zQ
# 3fazrcmJqD9xIwKlOXsvxOAO5OJ51ucdsubD6QkJa++4bGd5HhoC8/O18mxz6YYa
# gOnXWJObybkwdkDC9MUjy5wZNAv48DkUM+OArbfM3ZpfcAVTnDrfuzpoOKTkcdgb
# N+4VXJC/ly1D98f+IpEOw1UItX8Hg67WfU9sXcIY+fghzHPHF864vp2F/G75i02M
# oqeRpeO3guwum3DbKCkKts5S1QXnE7pmeqe4U595jCVhELeB6ifrvj0ulSlOU5GE
# twNY5VL0T3cHegBmtQXFfQoT6vboF6m9I7kVlKGT4WI8M/UQYCQ2ZP3HTjdSHt9U
# cJslGMqDxhbkGLH49ESP5ghbRddll24dsw0dF96lOIEmhB01UNIz40TonraK3cku
# Jdnrh/2fHYbycGHjkowiMUJQaihbZBRKvBHhrM7OuQ96M9g8Gk2RCIqdX0lO8n2y
# S8fnzEoWe8FVwE5bgA5Nwl6iYdoszubYgh+siVMe2EFaUh0DXXpbQ3JxjMGe5qVK
# 1zCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEMBQAw
# ZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBS
# b290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2lj
# ZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2jeu+RdSjwwIjBpM+zCpyUu
# ySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bGl20dq7J58soR0uRf1gU8
# Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBEEC7fgvMHhOZ0O21x4i0M
# G+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/NrDRAX7F6Zu53yEioZldX
# n1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A2raRmECQecN4x7axxLVq
# GDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8IUzUvK4bA3VdeGbZOjFE
# mjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfBaYh2mHY9WV1CdoeJl2l6
# SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaaRBkrfsCUtNJhbesz2cXf
# SwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZifvaAsPvoZKYz0YkH4b23
# 5kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXeeqxfjT/JvNNBERJb5RBQ
# 6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g/KEexcCPorF+CiaZ9eRp
# L5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O
# BBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1R
# i6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEFBQcBAQRtMGswJAYIKwYB
# BQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0
# cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADAN
# BgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22Ftf3v1cHvZqsoYcs7IVe
# qRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih9/Jy3iS8UgPITtAq3vot
# Vs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYDE3cnRNTnf+hZqPC/Lwum
# 6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c2PR3WlxUjG/voVA9/HYJ
# aISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88nq2x2zm8jLfR+cWojayL/
# ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5lDCCBq4wggSWoAMCAQIC
# EAc2N7ckVHzYR6z9KGYqXlswDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMx
# FTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNv
# bTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIyMDMyMzAw
# MDAwMFoXDTM3MDMyMjIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQw
# OTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAMaGNQZJs8E9cklRVcclA8TykTepl1Gh1tKD0Z5Mom2gsMyD+Vr2
# EaFEFUJfpIjzaPp985yJC3+dH54PMx9QEwsmc5Zt+FeoAn39Q7SE2hHxc7Gz7iuA
# hIoiGN/r2j3EF3+rGSs+QtxnjupRPfDWVtTnKC3r07G1decfBmWNlCnT2exp39mQ
# h0YAe9tEQYncfGpXevA3eZ9drMvohGS0UvJ2R/dhgxndX7RUCyFobjchu0CsX7Le
# Sn3O9TkSZ+8OpWNs5KbFHc02DVzV5huowWR0QKfAcsW6Th+xtVhNef7Xj3OTrCw5
# 4qVI1vCwMROpVymWJy71h6aPTnYVVSZwmCZ/oBpHIEPjQ2OAe3VuJyWQmDo4EbP2
# 9p7mO1vsgd4iFNmCKseSv6De4z6ic/rnH1pslPJSlRErWHRAKKtzQ87fSqEcazjF
# KfPKqpZzQmiftkaznTqj1QPgv/CiPMpC3BhIfxQ0z9JMq++bPf4OuGQq+nUoJEHt
# Qr8FnGZJUlD0UfM2SU2LINIsVzV5K6jzRWC8I41Y99xh3pP+OcD5sjClTNfpmEpY
# PtMDiP6zj9NeS3YSUZPJjAw7W4oiqMEmCPkUEBIDfV8ju2TjY+Cm4T72wnSyPx4J
# duyrXUZ14mCjWAkBKAAOhFTuzuldyF4wEr1GnrXTdrnSDmuZDNIztM2xAgMBAAGj
# ggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBS6FtltTYUvcyl2
# mi91jGogj57IbzAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNV
# HQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBp
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUH
# MAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRS
# b290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EM
# AQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAfVmOwJO2b5ipRCIB
# fmbW2CFC4bAYLhBNE88wU86/GPvHUF3iSyn7cIoNqilp/GnBzx0H6T5gyNgL5Vxb
# 122H+oQgJTQxZ822EpZvxFBMYh0MCIKoFr2pVs8Vc40BIiXOlWk/R3f7cnQU1/+r
# T4osequFzUNf7WC2qk+RZp4snuCKrOX9jLxkJodskr2dfNBwCnzvqLx1T7pa96kQ
# sl3p/yhUifDVinF2ZdrM8HKjI/rAJ4JErpknG6skHibBt94q6/aesXmZgaNWhqsK
# RcnfxI2g55j7+6adcq/Ex8HBanHZxhOACcS2n82HhyS7T6NJuXdmkfFynOlLAlKn
# N36TU6w7HQhJD5TNOXrd/yVjmScsPT9rp/Fmw0HNT7ZAmyEhQNC3EyTN3B14OuSe
# reU0cZLXJmvkOHOrpgFPvT87eK1MrfvElXvtCl8zOYdBeHo46Zzh3SP9HSjTx/no
# 8Zhf+yvYfvJGnXUsHicsJttvFXseGYs2uJPU5vIXmVnKcPA3v5gA3yAWTyf7YGcW
# oWa63VXAOimGsJigK+2VQbc61RWYMbRiCQ8KvYHZE/6/pNHzV9m8BPqC3jLfBInw
# AM1dwvnQI38AC+R2AibZ8GV2QqYphwlHK+Z/GqSFD/yYlvZVVCsfgPrA8g4r5db7
# qS9EFUrnEw4d2zc4GqEr9u3WfPwwggbCMIIEqqADAgECAhAFRK/zlJ0IOaa/2z9f
# 5WEWMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2
# IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjMwNzE0MDAwMDAwWhcNMzQxMDEz
# MjM1OTU5WjBIMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4x
# IDAeBgNVBAMTF0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIzMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAo1NFhx2DjlusPlSzI+DPn9fl0uddoQ4J3C9Io5d6
# OyqcZ9xiFVjBqZMRp82qsmrdECmKHmJjadNYnDVxvzqX65RQjxwg6seaOy+WZuNp
# 52n+W8PWKyAcwZeUtKVQgfLPywemMGjKg0La/H8JJJSkghraarrYO8pd3hkYhftF
# 6g1hbJ3+cV7EBpo88MUueQ8bZlLjyNY+X9pD04T10Mf2SC1eRXWWdf7dEKEbg8G4
# 5lKVtUfXeCk5a+B4WZfjRCtK1ZXO7wgX6oJkTf8j48qG7rSkIWRw69XloNpjsy7p
# Be6q9iT1HbybHLK3X9/w7nZ9MZllR1WdSiQvrCuXvp/k/XtzPjLuUjT71Lvr1KAs
# NJvj3m5kGQc3AZEPHLVRzapMZoOIaGK7vEEbeBlt5NkP4FhB+9ixLOFRr7StFQYU
# 6mIIE9NpHnxkTZ0P387RXoyqq1AVybPKvNfEO2hEo6U7Qv1zfe7dCv95NBB+plwK
# WEwAPoVpdceDZNZ1zY8SdlalJPrXxGshuugfNJgvOuprAbD3+yqG7HtSOKmYCaFx
# smxxrz64b5bV4RAT/mFHCoz+8LbH1cfebCTwv0KCyqBxPZySkwS0aXAnDU+3tTbR
# yV8IpHCj7ArxES5k4MsiK8rxKBMhSVF+BmbTO77665E42FEHypS34lCh8zrTioPL
# QHsCAwEAAaOCAYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYG
# A1UdJQEB/wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCG
# SAGG/WwHATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNVHQ4E
# FgQUpbbvE+fvzdBkodVWqWUxo97V40kwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDov
# L2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1
# NlRpbWVTdGFtcGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNI
# QTI1NlRpbWVTdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAgRrW3qCp
# tZgXvHCNT4o8aJzYJf/LLOTN6l0ikuyMIgKpuM+AqNnn48XtJoKKcS8Y3U623mzX
# 4WCcK+3tPUiOuGu6fF29wmE3aEl3o+uQqhLXJ4Xzjh6S2sJAOJ9dyKAuJXglnSoF
# eoQpmLZXeY/bJlYrsPOnvTcM2Jh2T1a5UsK2nTipgedtQVyMadG5K8TGe8+c+nji
# kxp2oml101DkRBK+IA2eqUTQ+OVJdwhaIcW0z5iVGlS6ubzBaRm6zxbygzc0brBB
# Jt3eWpdPM43UjXd9dUWhpVgmagNF3tlQtVCMr1a9TMXhRsUo063nQwBw3syYnhmJ
# A+rUkTfvTVLzyWAhxFZH7doRS4wyw4jmWOK22z75X7BC1o/jF5HRqsBV44a/rCcs
# QdCaM0qoNtS5cpZ+l3k4SF/Kwtw9Mt911jZnWon49qfH5U81PAC9vpwqbHkB3NpE
# 5jreODsHXjlY9HxzMVWggBHLFAx+rrz+pOt5Zapo1iLKO+uagjVXKBbLafIymrLS
# 2Dq4sUaGa7oX/cR3bBVsrquvczroSUa31X/MtjjA2Owc9bahuEMs305MfR5ocMB3
# CtQC4Fxguyj/OOVSWtasFyIjTvTs0xf7UGv/B3cfcZdEQcm4RtNsMnxYL2dHZeUb
# c7aZ+WssBkbvQR7w8F/g29mtkIBEr4AQQYoxggXpMIIF5QIBATAkMBAxDjAMBgNV
# BAMMBUowTjdFAhB0XMs0val9mEnBo5ekK6KYMAkGBSsOAwIaBQCgeDAYBgorBgEE
# AYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwG
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSUqeZW
# /qCQrTbOUC9Q0jF/ghFQhTANBgkqhkiG9w0BAQEFAASCAgBHgG8K3qjqwcNt3oTA
# XFqAAaiVfWgPor4PU3H20IEPlb9qwmVlfLnPkkN/BjZ7GSHmT5SdzsJGavxoCy4n
# rncyJ0wbDsLk+2491loK5FZ1tUfgoFK4PeAN++hjokp8C3eD6jSzlabgn0fuvcSC
# OCF8UVp8I4mFdns5RDbzpIvjDO5R3z+NuN0BGCPzB7kXDmaKABvmwwY9qWlCkCn6
# +eAYAMbZvytseF0UvWS5VhNZ04+ZRVwmanLxomGOkkPF+bWqWKlEd/vZ2zccsrTP
# aqYm0cDM9EBPqeOtDdQI1lcEDrCxPcvZMIwIvGZbwFleWPi+O8cxBJsD9ZZAZKZs
# bgdNqbbhesfjHKX79/8w2Y9cWv5j7BBU1JKmgZ95afHq1ppiPqIo8gLtAT34+YZ+
# vkGw4IXhYJBvrZnqRf8CRHdmvJQ4t1Ab2nHYFsbJrvNNkuBcS1zzf50fGQcWeYlS
# DFWs1BozQ5b3rCaxMk90GmaAFOcHcNxRJhxCwgaLgLNLBjWZWw3/8EjJNY7E4kOm
# KUno02O/XR5ttbU0LNaFm/KVXk/aEZlvv62zbGwtCD5DvdNbx+fBIuP7N6bSAiUA
# DPx9mwKBl37n9yZn5XMCYk/niKiMwFWoptnlKYZ9dbzlN8cCYIfs8oHuarJ8BFhi
# p7XMjeDiVVzFkMZMWSVB2wbh7qGCAyAwggMcBgkqhkiG9w0BCQYxggMNMIIDCQIB
# ATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkG
# A1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3Rh
# bXBpbmcgQ0ECEAVEr/OUnQg5pr/bP1/lYRYwDQYJYIZIAWUDBAIBBQCgaTAYBgkq
# hkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMzA5MDcyMDAw
# MDFaMC8GCSqGSIb3DQEJBDEiBCDxU0wSkUtJd25FR1QCMBhKaywgiCGcHIZrwq8G
# WLaSQjANBgkqhkiG9w0BAQEFAASCAgAbNVkdfmdUe1eILbIgidXgMqCsW0kzpN+6
# wPYxoxp04Y02u0xNDEG/pEY7W+kycW0uNchOjvdYvwLx4CYMpJOPO6c8IaAfDJh1
# ZYFvinqfZRSssCkU1mh/hio15NiddNsAcQrLyKK5s27Cl2vO30GZqJ3WIpu4c3jC
# M5BgCYELm2nBsFdVniE6pbIlDI/7CmKVjMANKbHFVCekbXmCV6awHzRbsJzn6EPC
# Y8WJCI8KHDVXw5w8l2HamHKs28AGP/bLIN0cR7DVqWMrNd/2tELS0WGw92FW9lFB
# x/zo1tL5h/cz0p5zYCu7sp3MNdWpNLD8iSvFWU4HEmR3VWTjSdlWGfEUoXm4q0Np
# F9yYb4BC7OIqi9eqUGE+sgsZCG5tp+c98MdUwPNBRNdYO9f1TgNksDWvv8WAr1qo
# zCnJ4iUVt4b8jMZjKbdeXIQnV10IvfNlm1hRPPZ2RuhbrjQK4ZzPvhoFhqbjd+vn
# yXcm19BNCZvRHcqbSwMuWbAVV3eQoIbTlppc2NmAjL3dvUBmtJ03vUcO1YsDOmgi
# 2NgIArdlqSVO0eZ9lnuOueS+XEve3qQHxCSq8T1usrBBXoIqNTnZHtuqzoFHjXBl
# cXAloENAbvATlSM+vdCXAzpHuoDb5o/IkYTAAOuB80BykovR5v9n61hfc6p5jPNR
# nD0hB3jjZg==
# SIG # End signature block
