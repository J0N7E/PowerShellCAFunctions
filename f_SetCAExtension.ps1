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
                    'Flags' = [POLICY]::CRITICAL
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
                    'Flags' = [POLICY]::CRITICAL
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
                    'Flags' = [POLICY]::CRITICAL
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
# MIIekQYJKoZIhvcNAQcCoIIegjCCHn4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUeqTHxBGwXg3WZzmU9gnuP82I
# yl6gghgSMIIFBzCCAu+gAwIBAgIQJTSMe3EEUZZAAWO1zNUfWTANBgkqhkiG9w0B
# AQsFADAQMQ4wDAYDVQQDDAVKME43RTAeFw0yMTA2MDcxMjUwMzZaFw0yMzA2MDcx
# MzAwMzNaMBAxDjAMBgNVBAMMBUowTjdFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAzdFz3tD9N0VebymwxbB7s+YMLFKK9LlPcOyyFbAoRnYKVuF7Q6Zi
# fFMWIopnRRq/YtahEtmakyLP1AmOtesOSL0NRE5DQNFyyk6D02/HFhpM0Hbg9qKp
# v/e3DD36uqv6DmwVyk0Ui9TCYZQbMDhha/SvT+IS4PBDwd3RTG6VH70jG/7lawAh
# mAE7/gj3Bd5pi7jMnaPaRHskogbAH/vRGzW+oueG3XV9E5PWWeRqg1bTXoIhBG1R
# oSWCXEpcHekFVSnatE1FGwoZHTDYcqNnUOQFx1GugZE7pmrZsdLvo/1gUCSdMFvT
# oU+UeurZI9SlfhPd6a1jYT/BcgsZdghWUO2M8SCuQ/S/NuotAZ3kZI/3y3T5JQnN
# 9l9wMUaoIoEMxNK6BmsSFgEkiQeQeU6I0YT5qhDukAZDoEEEHKl17x0Q6vxmiFr0
# 451UPxWZ19nPLccS3i3/kEQjVXc89j2vXnIW1r5UHGUB4NUdktaQ25hxc6c+/Tsx
# 968S+McqxF9RmRMp4g0kAFhBHKj7WhUVt2Z/bULSyb72OF4BC54CCSt1Q4eElh0C
# 1AudkZgj9CQKFIyveTBFsi+i2g6D5cIpl5fyQQnqDh/j+hN5QuI8D7poLe3MPNA5
# r5W1c60B8ngrDsJd7XnJrX6GdJd2wIPh1RmzDlmoUxVXrgnFtgzeTUUCAwEAAaNd
# MFswDgYDVR0PAQH/BAQDAgWgMCoGA1UdJQQjMCEGCCsGAQUFBwMDBgkrBgEEAYI3
# UAEGCisGAQQBgjcKAwQwHQYDVR0OBBYEFEPCLoNYgwyQVHRrBSI9l0nSMwnLMA0G
# CSqGSIb3DQEBCwUAA4ICAQBiMW8cSS4L1OVu4cRiaPriaqQdUukgkcT8iWGWrAHL
# TFPzivIPI5+7qKwzIJbagOM3fJjG0e6tghaSCPfVU+sPWvXIKF3ro5XLUfJut6j5
# qUqoQt/zNuWpI12D1gs1NROWnJgqe1ddmvoAOn5pZyFqooC4SnD1fT7Srs+G8Hs7
# Qd2j/1XYAphZfLXoiOFs7uzkQLJbhmikhEJQKzKE4i8dcsoucNhe2lvNDftJqaGl
# oALzu04y1LcpgCDRbvjU0YDStZwKSEj9jvz89xpl5tMrgGWIK8ghjRzGf0iPhqb/
# xFOFcKP2k43X/wXWa9W7PlO+NhIlZmTM/W+wlgrRfgkawy2WLpO8Vop+tvVwLdyp
# 5n4UxRDXBhYd78Jfscb0fwpsU+DzONLrJEwXjdj3W+vdEZs7YIwAnsCGf8NznXWp
# N9D7OzqV0PT2Szkao5hEp3nS6dOedw/0uKAz+l5s7WJOTLtFjDhUk62g5vIZvVK2
# E9TWAuViPmUkVugnu4kV4c870i5YgRZz9l4ih5vL9XMoc4/6gohLtUgT4FD0xKXn
# bwtl/LczkzDO9vKLbx93ICmNJuzLj+K8S4AAo8q6PTgLZyGlozmTWRa3SmGVqTNE
# suZR41hGNpjtNtIIiwdZ4QuP8cj64TikUIoGVNbCZgcPDHrrz84ZjAFlm7H9SfTK
# 8jCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEMBQAw
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
# qS9EFUrnEw4d2zc4GqEr9u3WfPwwggbAMIIEqKADAgECAhAMTWlyS5T6PCpKPSkH
# gD1aMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2
# IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjIwOTIxMDAwMDAwWhcNMzMxMTIx
# MjM1OTU5WjBGMQswCQYDVQQGEwJVUzERMA8GA1UEChMIRGlnaUNlcnQxJDAiBgNV
# BAMTG0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIyIC0gMjCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAM/spSY6xqnya7uNwQ2a26HoFIV0MxomrNAcVR4eNm28
# klUMYfSdCXc9FZYIL2tkpP0GgxbXkZI4HDEClvtysZc6Va8z7GGK6aYo25BjXL2J
# U+A6LYyHQq4mpOS7eHi5ehbhVsbAumRTuyoW51BIu4hpDIjG8b7gL307scpTjUCD
# HufLckkoHkyAHoVW54Xt8mG8qjoHffarbuVm3eJc9S/tjdRNlYRo44DLannR0hCR
# RinrPibytIzNTLlmyLuqUDgN5YyUXRlav/V7QG5vFqianJVHhoV5PgxeZowaCiS+
# nKrSnLb3T254xCg/oxwPUAY3ugjZNaa1Htp4WB056PhMkRCWfk3h3cKtpX74LRsf
# 7CtGGKMZ9jn39cFPcS6JAxGiS7uYv/pP5Hs27wZE5FX/NurlfDHn88JSxOYWe1p+
# pSVz28BqmSEtY+VZ9U0vkB8nt9KrFOU4ZodRCGv7U0M50GT6Vs/g9ArmFG1keLuY
# /ZTDcyHzL8IuINeBrNPxB9ThvdldS24xlCmL5kGkZZTAWOXlLimQprdhZPrZIGwY
# UWC6poEPCSVT8b876asHDmoHOWIZydaFfxPZjXnPYsXs4Xu5zGcTB5rBeO3GiMiw
# bjJ5xwtZg43G7vUsfHuOy2SJ8bHEuOdTXl9V0n0ZKVkDTvpd6kVzHIR+187i1Dp3
# AgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAWBgNV
# HSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgB
# hv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxqII+eyG8wHQYDVR0OBBYE
# FGKK3tBh/I8xFO2XC809KpQU31KcMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9j
# cmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZU
# aW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGDMIGAMCQGCCsGAQUFBzAB
# hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYBBQUHMAKGTGh0dHA6Ly9j
# YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEy
# NTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQELBQADggIBAFWqKhrzRvN4
# Vzcw/HXjT9aFI/H8+ZU5myXm93KKmMN31GT8Ffs2wklRLHiIY1UJRjkA/GnUypsp
# +6M/wMkAmxMdsJiJ3HjyzXyFzVOdr2LiYWajFCpFh0qYQitQ/Bu1nggwCfrkLdcJ
# iXn5CeaIzn0buGqim8FTYAnoo7id160fHLjsmEHw9g6A++T/350Qp+sAul9Kjxo6
# UrTqvwlJFTU2WZoPVNKyG39+XgmtdlSKdG3K0gVnK3br/5iyJpU4GYhEFOUKWaJr
# 5yI+RCHSPxzAm+18SLLYkgyRTzxmlK9dAlPrnuKe5NMfhgFknADC6Vp0dQ094XmI
# vxwBl8kZI4DXNlpflhaxYwzGRkA7zl011Fk+Q5oYrsPJy8P7mxNfarXH4PMFw1nf
# J2Ir3kHJU7n/NBBn9iYymHv+XEKUgZSCnawKi8ZLFUrTmJBFYDOA4CPe+AOk9kVH
# 5c64A0JH6EE2cXet/aLol3ROLtoeHYxayB6a1cLwxiKoT5u92ByaUcQvmvZfpyeX
# upYuhVfAYOd4Vn9q78KVmksRAsiCnMkaBXy6cbVOepls9Oie1FqYyJ+/jbsYXEP1
# 0Cro4mLueATbvdH7WwqocH7wl4R44wgDXUcsY6glOJcB0j862uXl9uab3H4szP8X
# TE0AotjWAQ64i+7m4HJViSwnGWH2dwGMMYIF6TCCBeUCAQEwJDAQMQ4wDAYDVQQD
# DAVKME43RQIQJTSMe3EEUZZAAWO1zNUfWTAJBgUrDgMCGgUAoHgwGAYKKwYBBAGC
# NwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUlKnmVv6g
# kK02zlAvUNIxf4IRUIUwDQYJKoZIhvcNAQEBBQAEggIAf9VbZNOiGiwurAw1qlZp
# ZnyY/C4A/2L2u6vpS+g0ocAxVdHnLgGZgVSWEyuERhGzgbLDeKuGGgjEgE1xIb4W
# 8Qxkdk+HMz8zfTmJNUfArbNp/U9XVhOkIwxrXOiFwdD++Pc8PdbPgdTSZR+sAbIP
# nnJJTaeDCIJ3fvhid0j3ew55JUt6dgToTTjKnoWSRkbhrjNYrzf8QFCatOTay4Ni
# kNQ/aZoOXKZarFiHjM9ZvJ+ILFL5v92O9FwpPDBUJE5HNefNjs4m+NT1ydnJ5cth
# MA4LfWcXduI7XTZBB2fsXrqViD4XVxN2OlLhzxbao9jrZ0LlcdASyvwniGnS+L/j
# uK3NqVnLHjlaSb9khNlrIFGSqPV1wxKBrfpAfx4pk434D2heh7ICmolH96T+mZbW
# aMC9QE+gcYUaHqqVmyDGgmGDVpVpYf06bFE/VirYUoIvIP+7WFwMNrGwRo2t0qeP
# 7ZwG3LVLHDFhLsf6GWKrnv90mbvKnMFgZ7xRsYyBTaWrQ2k50mjNnSQ7KcstVI2O
# GObFjD7lplL+ReXyfIPavJ6Po+hqCWfrALhE/6jR9bJrpYucurUVQHUokkhMpyRY
# j0dbPsfQTvDx0KfZTjC+hAKTgkO3WIJb009LA0XmDPvSwAlGyVZeLcFjAQ+SKbic
# /D1QeuLqtR98xcUP/+qXnkKhggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEw
# dzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNV
# BAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1w
# aW5nIENBAhAMTWlyS5T6PCpKPSkHgD1aMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZI
# hvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjMwMTEzMjEwMDA1
# WjAvBgkqhkiG9w0BCQQxIgQgbrG5JPzwYtG1g3ycAesb/rE0sEKLtrJ7QYcPyWpr
# q8owDQYJKoZIhvcNAQEBBQAEggIAH3OiQvkQKG9DmShM8zmkUhF50200NhJ0rXE2
# 21KDv5aYbTfICM9bxYWdeoTe0RF2NUeSOKUKbmxCLHbeMQIJ1ntYLh1C797L0BTb
# 57B6ie37yTKNIzH7gCbnnOJC5Crhj1rYSOaQkrlecE1b+Tdx10VKRWqoK5az4e2B
# hi6LNhmDkqykTex+L36l+F+T7lXl/RL5ME9Ih8Q066IwOmQJ2hZVVVXf+JfHbilm
# UIfNpyQB63BxWeZcY5oA20216TyZOvwUxTO6e5pTWVFvZL/qcerQ8AvGCCtzeMdz
# gvyI1zv7AsOyKJoRyk9FxBzb6MZK8Qs/rc1G3shAnlPF7QOqq8ba9QB7vlMBk2OF
# MSeO1qCC7KWhCU6D0wsLtxDHI5LVthj2AgOtM3FnLJuPeSzJ9vZHIShFlyf9NbX9
# I70SM5cPyw2VWxgmTKbCK2eU2UocVHSlQDxNdSiueBJx0cBQlnpQdRXNo3s24ggn
# UiZhq65TCvtiyLIiNRGzkR2OzWRpOR017/yU8XpMyj64/J8cAoOS2+ggSkE+VElo
# FPcRGx6lG175ZhCXV/1iFZ7of69ikb2DnrjhO6nMdLfhlIBNUqK+bxjE89y9jJCP
# 2ZJYYntyWNEGZMvVjEM1fWGo+EbBywuOn5BFFqrP/qv3XVQ9EdQqcX36ooF7UQRG
# VA38TLc=
# SIG # End signature block
