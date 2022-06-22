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

    Get Alt Name enum
    $ALT_NAME = Set-CAExtension -GetAltName

    Set Subject Alternative Names
    Set-CAExtension -RequestId <ID> -SubjectAlternativeNames @{ $ALT_NAME::DNS_NAME = 'fqdn' }

    Set Basic Constraint Subject Type = CA and Path Length = None
    Set-CAExtension -RequestId <ID> -SubjectType CA -PathLength -1

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
            # Key usage
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
            # Enhanced Key usage
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

            ############################
            # Subject Alternative Names
            # 2.5.29.17
            ############################

            if ($SubjectAlternativeNames -and $SubjectAlternativeNames.Count -gt 0)
            {
                # Create extension object
                $X509Ext = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames

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
                # Create extension object
                $X509Ext = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames

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
        Remove-Variable -Name CaAdmin, X509*, AlternativeName* -ErrorAction SilentlyContinue
    }
}

# SIG # Begin signature block
# MIIeuwYJKoZIhvcNAQcCoIIerDCCHqgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUVb0baIeeXwIPQ6URsmF3oaYv
# //6gghg8MIIFBzCCAu+gAwIBAgIQJTSMe3EEUZZAAWO1zNUfWTANBgkqhkiG9w0B
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
# 8jCCBbEwggSZoAMCAQICEAEkCvseOAuKFvFLcZ3008AwDQYJKoZIhvcNAQEMBQAw
# ZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBS
# b290IENBMB4XDTIyMDYwOTAwMDAwMFoXDTMxMTEwOTIzNTk1OVowYjELMAkGA1UE
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
# L5gdLfXZqbId5RsCAwEAAaOCAV4wggFaMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O
# BBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1R
# i6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB5
# BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0
# LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0Rp
# Z2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRw
# Oi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3Js
# MCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQwF
# AAOCAQEAmhYCpQHvgfsNtFiyeK2oIxnZczfaYJ5R18v4L0C5ox98QE4zPpA854kB
# dYXoYnsdVuBxut5exje8eVxiAE34SXpRTQYy88XSAConIOqJLhU54Cw++HV8LIJB
# YTUPI9DtNZXSiJUpQ8vgplgQfFOOn0XJIDcUwO0Zun53OdJUlsemEd80M/Z1UkJL
# HJ2NltWVbEcSFCRfJkH6Gka93rDlkUcDrBgIy8vbZol/K5xlv743Tr4t851Kw8zM
# R17IlZWt0cu7KgYg+T9y6jbrRXKSeil7FAM8+03WSHF6EBGKCHTNbBsEXNKKlQN2
# UVBT1i73SkbDrhAscUywh7YnN0RgRDCCBq4wggSWoAMCAQICEAc2N7ckVHzYR6z9
# KGYqXlswDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERp
# Z2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMY
# RGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIyMDMyMzAwMDAwMFoXDTM3MDMy
# MjIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRp
# bWVTdGFtcGluZyBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMaG
# NQZJs8E9cklRVcclA8TykTepl1Gh1tKD0Z5Mom2gsMyD+Vr2EaFEFUJfpIjzaPp9
# 85yJC3+dH54PMx9QEwsmc5Zt+FeoAn39Q7SE2hHxc7Gz7iuAhIoiGN/r2j3EF3+r
# GSs+QtxnjupRPfDWVtTnKC3r07G1decfBmWNlCnT2exp39mQh0YAe9tEQYncfGpX
# evA3eZ9drMvohGS0UvJ2R/dhgxndX7RUCyFobjchu0CsX7LeSn3O9TkSZ+8OpWNs
# 5KbFHc02DVzV5huowWR0QKfAcsW6Th+xtVhNef7Xj3OTrCw54qVI1vCwMROpVymW
# Jy71h6aPTnYVVSZwmCZ/oBpHIEPjQ2OAe3VuJyWQmDo4EbP29p7mO1vsgd4iFNmC
# KseSv6De4z6ic/rnH1pslPJSlRErWHRAKKtzQ87fSqEcazjFKfPKqpZzQmiftkaz
# nTqj1QPgv/CiPMpC3BhIfxQ0z9JMq++bPf4OuGQq+nUoJEHtQr8FnGZJUlD0UfM2
# SU2LINIsVzV5K6jzRWC8I41Y99xh3pP+OcD5sjClTNfpmEpYPtMDiP6zj9NeS3YS
# UZPJjAw7W4oiqMEmCPkUEBIDfV8ju2TjY+Cm4T72wnSyPx4JduyrXUZ14mCjWAkB
# KAAOhFTuzuldyF4wEr1GnrXTdrnSDmuZDNIztM2xAgMBAAGjggFdMIIBWTASBgNV
# HRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBS6FtltTYUvcyl2mi91jGogj57IbzAf
# BgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzAB
# hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9j
# YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMG
# A1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG
# /WwHATANBgkqhkiG9w0BAQsFAAOCAgEAfVmOwJO2b5ipRCIBfmbW2CFC4bAYLhBN
# E88wU86/GPvHUF3iSyn7cIoNqilp/GnBzx0H6T5gyNgL5Vxb122H+oQgJTQxZ822
# EpZvxFBMYh0MCIKoFr2pVs8Vc40BIiXOlWk/R3f7cnQU1/+rT4osequFzUNf7WC2
# qk+RZp4snuCKrOX9jLxkJodskr2dfNBwCnzvqLx1T7pa96kQsl3p/yhUifDVinF2
# ZdrM8HKjI/rAJ4JErpknG6skHibBt94q6/aesXmZgaNWhqsKRcnfxI2g55j7+6ad
# cq/Ex8HBanHZxhOACcS2n82HhyS7T6NJuXdmkfFynOlLAlKnN36TU6w7HQhJD5TN
# OXrd/yVjmScsPT9rp/Fmw0HNT7ZAmyEhQNC3EyTN3B14OuSereU0cZLXJmvkOHOr
# pgFPvT87eK1MrfvElXvtCl8zOYdBeHo46Zzh3SP9HSjTx/no8Zhf+yvYfvJGnXUs
# HicsJttvFXseGYs2uJPU5vIXmVnKcPA3v5gA3yAWTyf7YGcWoWa63VXAOimGsJig
# K+2VQbc61RWYMbRiCQ8KvYHZE/6/pNHzV9m8BPqC3jLfBInwAM1dwvnQI38AC+R2
# AibZ8GV2QqYphwlHK+Z/GqSFD/yYlvZVVCsfgPrA8g4r5db7qS9EFUrnEw4d2zc4
# GqEr9u3WfPwwggbGMIIErqADAgECAhAKekqInsmZQpAGYzhNhpedMA0GCSqGSIb3
# DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7
# MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1l
# U3RhbXBpbmcgQ0EwHhcNMjIwMzI5MDAwMDAwWhcNMzMwMzE0MjM1OTU5WjBMMQsw
# CQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xJDAiBgNVBAMTG0Rp
# Z2lDZXJ0IFRpbWVzdGFtcCAyMDIyIC0gMjCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBALkqliOmXLxf1knwFYIY9DPuzFxs4+AlLtIx5DxArvurxON4XX5c
# Nur1JY1Do4HrOGP5PIhp3jzSMFENMQe6Rm7po0tI6IlBfw2y1vmE8Zg+C78KhBJx
# bKFiJgHTzsNs/aw7ftwqHKm9MMYW2Nq867Lxg9GfzQnFuUFqRUIjQVr4YNNlLD5+
# Xr2Wp/D8sfT0KM9CeR87x5MHaGjlRDRSXw9Q3tRZLER0wDJHGVvimC6P0Mo//8Zn
# zzyTlU6E6XYYmJkRFMUrDKAz200kheiClOEvA+5/hQLJhuHVGBS3BEXz4Di9or16
# cZjsFef9LuzSmwCKrB2NO4Bo/tBZmCbO4O2ufyguwp7gC0vICNEyu4P6IzzZ/9KM
# u/dDI9/nw1oFYn5wLOUrsj1j6siugSBrQ4nIfl+wGt0ZvZ90QQqvuY4J03ShL7BU
# dsGQT5TshmH/2xEvkgMwzjC3iw9dRLNDHSNQzZHXL537/M2xwafEDsTvQD4ZOgLU
# MalpoEn5deGb6GjkagyP6+SxIXuGZ1h+fx/oK+QUshbWgaHK2jCQa+5vdcCwNiay
# CDv/vb5/bBMY38ZtpHlJrYt/YYcFaPfUcONCleieu5tLsuK2QT3nr6caKMmtYbCg
# QRgZTu1Hm2GV7T4LYVrqPnqYklHNP8lE54CLKUJy93my3YTqJ+7+fXprAgMBAAGj
# ggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8E
# DDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEw
# HwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxqII+eyG8wHQYDVR0OBBYEFI1kt4kh
# /lZYRIRhp+pvHDaP3a8NMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3Rh
# bXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGDMIGAMCQGCCsGAQUFBzABhhhodHRw
# Oi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYBBQUHMAKGTGh0dHA6Ly9jYWNlcnRz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1l
# U3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQELBQADggIBAA0tI3Sm0fX46kuZPwHk
# 9gzkrxad2bOMl4IpnENvAS2rOLVwEb+EGYs/XeWGT76TOt4qOVo5TtiEWaW8G5iq
# 6Gzv0UhpGThbz4k5HXBw2U7fIyJs1d/2WcuhwupMdsqh3KErlribVakaa33R9QIJ
# T4LWpXOIxJiA3+5JlbezzMWn7g7h7x44ip/vEckxSli23zh8y/pc9+RTv24KfH7X
# 3pjVKWWJD6KcwGX0ASJlx+pedKZbNZJQfPQXpodkTz5GiRZjIGvL8nvQNeNKcEip
# tucdYL0EIhUlcAZyqUQ7aUcR0+7px6A+TxC5MDbk86ppCaiLfmSiZZQR+24y8fW7
# OK3NwJMR1TJ4Sks3KkzzXNy2hcC7cDBVeNaY/lRtf3GpSBp43UZ3Lht6wDOK+Eoo
# jBKoc88t+dMj8p4Z4A2UKKDr2xpRoJWCjihrpM6ddt6pc6pIallDrl/q+A8GQp3f
# BmiW/iqgdFtjZt5rLLh4qk1wbfAs8QcVfjW05rUMopml1xVrNQ6F1uAszOAMJLh8
# UgsemXzvyMjFjFhpr6s94c/MfRWuFL+Kcd/Kl7HYR+ocheBFThIcFClYzG/Tf8u+
# wQ5KbyCcrtlzMlkI5y2SoRoR/jKYpl0rl+CL05zMbbUNrkdjOEcXW28T2moQbh9J
# t0RbtAgKh1pZBHYRoad3AhMcMYIF6TCCBeUCAQEwJDAQMQ4wDAYDVQQDDAVKME43
# RQIQJTSMe3EEUZZAAWO1zNUfWTAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEK
# MAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3
# AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUYV98newOWp2u1gmp
# jAg4GZ1bwk0wDQYJKoZIhvcNAQEBBQAEggIAETJyOvEHAKqi25jEkKucy6tTrrSz
# wljbtlEv4VU785F+AGGD/XOgKWx7CGju3GtwxvTV+uJyiBXKFpi8e2ntYtsDK8h9
# 2mcnHuRLwwvq9NvS0n3GnWtB1wjkwesHZc/agm4x33OY5jERX8CtBq7takYPlWoU
# IVh66Q+Dps3xoVvVNH3iKhVLACgPCWYPobuEJkI1wLoeYnUHzeWQugmrQMhcrJ2t
# jkQ/BXO1CnvTZrxm1bx7KbGSdhUcAqfxNyjivpZ0akeOyNE2l6J9Y/Zp5LxlWU7m
# BxMYQHKNCWV5u6sE1GccA0jhNk1GrA7VXhhWP+7Al64QH0lZpUr02nJXkjCbHG/V
# uUGiCRdkj5J3p9PXjCK6hnXG+xkuoY25R5QsP96o2yCkV90Ryw0WgoNphyRoXx1n
# I+Aa5cl19oVNB3O9HsTuohIU+upbT4t6sGQ3b2H9FeTf1+Y5vwcqtm9Di4TidW1n
# S7E0wrA+FnvjAn91l7YkgRrQ508eNzfX32zJEajL0gR/8VSCmYBPGEDiCBZyZf0G
# 9G0pJ4+xAu24WKtlafr8gypfrB92RfVBesBeZfA3hHp69+qEo2ymOlL83CO88on4
# DbQ99HNXV6i6wSNzKkKi0afp8gIW7ArcRy1f1UbfOY+s5PFqO7v4ayq7oaTE637O
# sTQ1ooDpXJdsGLWhggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBjMQsw
# CQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRp
# Z2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENB
# AhAKekqInsmZQpAGYzhNhpedMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkD
# MQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjIwNjIyMDkwNDEwWjAvBgkq
# hkiG9w0BCQQxIgQgBzFVYSbAg5GOcsWOv8N38fuyu4jBlSY6c1Fvrn1HYDQwDQYJ
# KoZIhvcNAQEBBQAEggIAYP++78S6Z2kAS9ThMaOhQWRmpQNHCI2V3NF3zmfTXfY9
# +JIo5pg767f2Ig3xhXvW6DaXhha7xugxSK9z+N61DzGp0m8b/0YWXKivM3MZbnTj
# Mi3eaUOkI9K0QVkVGtPJxY9vb+bqoJT0T1w28yX2hfZY4qIeGT8euJ4nhMsNDRuw
# ZZwmI2Qnlhn5/GdrmVLldPClW0FogL/O3Kp4aCGFDpHKSLqTWS8kKePKRNsEs+tL
# KOOUtQPzLtG2Zq7ib0E8NPHijXd6jhywKJ0FjkPegClnLTaMXX25eQYgE/v65+Ec
# 0PnvfgwUBJaELLbjto5ccNT6NlGhu4o7kRJEJ8XzD/lMoimVk0kGAv0rsvSBL5lD
# MOB8jcBUgSPVDHWnFYy0BYrQS3mxZm1iaMvcKeqZgi/yAumhX6UHmv0P9DOgvnfb
# TBJb/cGGMe6JLbpk84wOc837PYow4uIGSL2xhaEhc5kpvKi1FsGWKUNAw3R5BQZz
# B7XwjKfG0k2NvmBMAji3bpFDxTqh3PFRWF3xo1CWm9SHbEh7McyCwraKFd5R4234
# bFJs6/FlaywLhRZl0u3Awgl+59UpGpEhTdz3vMQqX2BbTjLE78ziM46vWIzNQwQ9
# hxLaTUd6rVZtqwYc+iND0t46rQEIpRpD+8S6PlHdUln4sHxtnuz+fRhvVWLtthQ=
# SIG # End signature block
