# Create a zip archive containing all the binaries and subfolders (Modules, Targets) of the KAPE forensic collector. Add the 7z.exe (SHA1: F136EF9BF8BD2FC753292FB5B7CF173A22675FB3)
# aws_config.txt should contain all the needed information to access the S3 bucket.
# smb_config.txt

<#
.SYNOPSIS
    Download the KAPE collector to the set path and extracts the downloaded archive  in the same folder
#>
function Download-KAPECollector(

    [Parameter()][string]
    $URL,

    [Parameter()][string]
    $OutputPath
    ) 
    {
    
    #Create Folder that will contain the KAPE Collector (KAPE.zip)
    Write-Output "[*] - Creating $OutputPath"
    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null


    $KAPEFullPath = -join($OutputPath, "KAPE.zip")

    # download KAPE collector
    Write-Output "[*] - Downloading KAPE collector from $($URL) to $KAPEFullPath"

    Invoke-WebRequest -Uri $URL -OutFile $KAPEFullPath 

    #Expanding Archive
    Write-Output "[*] - Extracting Archive $KAPEFullPath into $OutputPath"
    Expand-Archive $KAPEFullPath -DestinationPath $OutputPath -Force
    }

<#
.SYNOPSIS
    Upload the generated file to a SMB share
#>

function Copy-ToSMBShare {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SourceFilePath,

        [Parameter(Mandatory = $true)]
        [string]$DestinationSMBPath,

        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $true)]
        [string]$Password
    )

    # Create a PSCredential object with the provided username and password
    $Credential = New-Object -TypeName PSCredential -ArgumentList $Username, (ConvertTo-SecureString -String $Password -AsPlainText -Force)

    try {
        # Copy the file to the SMB share using the provided credentials
        Copy-Item -Path $SourceFilePath -Destination $DestinationSMBPath -Credential $Credential -Force

        Write-Host "File successfully copied to SMB share: $DestinationSMBPath"
    } catch {
        Write-Host "Error: $_"
    }
}


<#
.SYNOPSIS
    Upload the generated file to an S3 bucket
#>

function Upload-To-S3 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$filename
    )

    # Check if AWS Tools for PowerShell module is installed
    if (-not (Get-Module -Name AWSPowerShell -ListAvailable)) {
        Write-Host "AWS Tools for PowerShell not found. Installing..."
        # Install NuGet provider without prompting
        $null = Install-PackageProvider -Name NuGet -Force -Scope CurrentUser
        Install-Module -Name AWSPowerShell -Force -AllowClobber -Scope CurrentUser
        Import-Module AWSPowerShell
    }

    # Read AWS credentials, region, and other information from a configuration file
    $configFile = "C:\Path\To\Your\aws_config.txt"
    $configContent = Get-Content $configFile -Raw | Out-String
    $config = ConvertFrom-StringData $configContent

    # Set AWS credentials
    Set-AWSCredentials -AccessKey $config.awsAccessKey -SecretKey $config.awsSecretKey -StoreAs "default"

    # Specify S3 bucket name and file paths
    $bucketName = $config.bucketName
    $s3Key = $config.s3Key  # The key under which the file will be stored in the bucket

    # Upload the file to S3
    Write-S3Object -BucketName $bucketName -File $filename -Key $s3Key -Region $config.region

    Write-Host "File uploaded successfully to S3 bucket: $bucketName"
}


<#
.SYNOPSIS
    Writes the KAPE collector to the set path and extracts content to the same folder
#>
function Write-KAPECollector(
    [Parameter()][string]
    $OutputPath
    ) 
    {
    
    #Create Folder that will contain the KAPE Collector (KAPE.zip)
    Write-Output "[*] - Creating $OutputPath"
    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null


    $KAPEFullPath = -join($OutputPath, "KAPE.zip")
    Write-Output "[*] - Writing KAPE collector to: $KAPEFullPath"
    $Content = [System.Convert]::FromBase64String($KAPE_Base64)
    Set-Content -Path $KAPEFullPath -Value $Content -Encoding Byte

    #Expanding Archive
    Write-Output "[*] - Extracting Archive $KAPEFullPath into $OutputPath"
    Expand-Archive $KAPEFullPath -DestinationPath $OutputPath -Force
    }
    
    
<#
.SYNOPSIS
    Runs KAPE to collect/parse artefacts. Credit: https://github.com/swisscom/Invoke-Forensics
#>
function Invoke-Kape()
{


    [CmdletBinding(SupportsShouldProcess=$True)]
    param(
        [string[]]
        $tsource,

        [string[]]
        $msource,

        [string[]]
        $tdest,

        [string[]]
        $mdest,

        [string]
        $mvars,

        [switch]
        $print,

        [parameter(Mandatory = $false)]
        [String]$URL,
		
		[parameter(Mandatory = $false)]
        [switch]$UploadToS3,

        [parameter(Mandatory = $false)]
        [switch]$UploadToSMB,

        [parameter(Mandatory = $false)]
        [string]$OutputPath = "C:\ProgramData\Sentinel-RSO\KAPE\COLLECTOR\",

        [parameter(Mandatory = $false)]
        [string]$CollectorPath = "C:\ProgramData\Sentinel-RSO\KAPE\",

        [parameter(Mandatory = $false)]
        [int]$sleep,

        [parameter(Mandatory = $false)]
        [float]$jitter = 20

    )

    DynamicParam
    {
        Get-DynamicFlowParamKAPE -Params $PSBoundParameters
    }
    Process
    {


        #Check if we have to sleep
        if ($sleep){

            #Enforcing $jitter > 0
            if ($jitter -gt 0){
                $jitter = [float]$jitter/100
            }
            else {
                $jitter = 0.20
            }
            
            Write-Output "[*] - Sleep: $sleep Jitter: $jitter"

            $RandomDelta = Get-Random -Minimum 0 -Maximum ($sleep*$jitter)
            Write-Output "[*] - RandomDelta: $RandomDelta"

            if (Get-Random -InputObject ([bool]$True,[bool]$False)){
                $sleep = [System.Math]::Floor($sleep+$RandomDelta)
            }
            else {
                $sleep = [System.Math]::Floor($sleep-$RandomDelta)            
            }
            
            #Enforcing sleep >= 0
            $sleep = [System.Math]::max(0,$sleep)
            Write-Output "[*] - Sleeping for $sleep seconds"
            Start-Sleep $sleep
        }

        # If $URL is provided, let's download the KAPE package 
        if ($URL) {
            if (! $URL -match 'http.*?') {
                throw "URL '$($URL)' is not an HTTP/S URL."
            }
            else{
                Download-KAPECollector -URL $URL -OutputPath $CollectorPath                
            }   
        }

        else {
                $PackageDir = if ($ENV:S1_PACKAGE_DIR_PATH) { $ENV:S1_PACKAGE_DIR_PATH } else { $PSScriptRoot }
                $KapeBinaryPath =  Join-Path -Path $PackageDir -ChildPath "kape.exe"
                $ModulesFolderPath = Join-Path -Path $PackageDir -ChildPath "Modules" 
                $TargetsFolderPath = Join-Path -Path $PackageDir -ChildPath "Targets"
                
                #Remember to put 7z.exe into the Kape archive
                $7ZipPath = Join-Path -Path $PackageDir -ChildPath "7z.exe"
				
                #Let's create the Collector folder
                Write-Output "[*] - Creating folder $CollectorPath"
                # Suppress output when creating the Directory
                $null = New-Item -ItemType Directory -Force -Path "$CollectorPath"
                
                Write-Output "[*] - Copying $KapeBinaryPath to $CollectorPath"
                Copy-Item $KapeBinaryPath -Destination $CollectorPath -ErrorAction SilentlyContinue -Force
                Write-Output "[*] - Copying $ModulesFolderPath to $CollectorPath"
                Copy-Item $ModulesFolderPath -Destination $CollectorPath -Recurse -ErrorAction SilentlyContinue -Force
                Write-Output "[*] - Copying $TargetsFolderPath to $CollectorPath"
                Copy-Item $TargetsFolderPath -Destination $CollectorPath  -Recurse -ErrorAction SilentlyContinue -Force
				Write-Output "[*] - Copying $7ZipPath to $CollectorPath"
                Copy-Item $7ZipPath -Destination $CollectorPath  -Recurse -ErrorAction SilentlyContinue -Force
        }

        
        #Set working dir
        Set-Location -Path $CollectorPath

        if ($PSBoundParameters.Print)
        {
            foreach ($t in ($PSBoundParameters.Target))
            {
                gc .\Targets\*\$t.tkape
                write ""
            }
            foreach ($m in ($PSBoundParameters.Module))
            {
                gc .\Modules\*\$m.mkape
                write ""
            }
            return
        }
        if ($PSBoundParameters.Target)
        {
            .\kape.exe --tsource $tsource --tdest $tdest --tflush --target $($PSBoundParameters.Target -join ",")

        }
        if ($PSBoundParameters.Module)
        {
            #.\kape.exe --msource $msource --mdest $mdest --mflush --module $($PSBoundParameters.Module -join ",") --mvars $mvars
        }

		$DateFolder = (get-date -f yyyy-MM-dd_HH_mm_ss) + "_$env:computername"
		$DatePath = Join-Path -Path $OutputPath -ChildPath $DateFolder

		# Delete content of $OutputPath. Recreate the folder afterwards
		Write-Output "[*] - Deleting $OutputPath"
		Remove-Item $OutputPath -Recurse -ErrorAction SilentlyContinue
		Write-Output "[*] - Creating $DatePath"
		New-Item -ItemType Directory -Force -Path $DatePath | Out-Null

		# Move content of $tdest to $DatePath
		if ($PSBoundParameters.Target){
		Write-Output "[*] - Moving $tdest to  $DatePath"
		Move-Item -Force -Path $tdest -Destination $DatePath
		}

		# Move content of $mdest to $DatePath
		if ($PSBoundParameters.Module){
		Write-Output "[*] - Moving $mdest to  $DatePath"
		Move-Item -Force -Path $mdest -Destination $DatePath
		}

		# Compress $OutputPath. Output Archive name: collector.zip
		$CompressSrc = -join($OutputPath, "*")
		$OutputArchive = -join($OutputPath, "collector.zip")
		
        # We're using 7z and not the internal library, because it can't manage file with size >> GB
		#Write-Output "[*] - Compressing $CompressSrc into $OutputArchive"
		#Compress-Archive -Path $CompressSrc -DestinationPath $OutputArchive -Force
		
		$sourceFilePath = -join($OutputPath, "*")
		$destinationZipPath = -join($OutputPath, "collector.zip")
			
		Write-Output "[*] - Compressing $CompressSrc into $destinationZipPath"

		try {
			# Use 7-Zip command line tool (7za.exe) to compress the file
			$arguments = "a", "-tzip", "-mx9", $destinationZipPath, $sourceFilePath
			Start-Process -FilePath .\7z.exe -ArgumentList $arguments -Wait -PassThru
			Write-Host "Compression successful!"
			
		} catch {
			Write-Host "Error: $_"
		}
		
        # Upload to S3 bucket if needed
        
        if($UploadToS3) {
			Upload-To-S3 -filename $OutputArchive
		}	

        # Upload to a SMB share if needed
        if($UploadToSMB){
            # Read SMB credentials and other information from a configuration file
            $configFile = "C:\Path\To\Your\smb_config.txt"
            $configContent = Get-Content $configFile -Raw | Out-String
            $config = ConvertFrom-StringData $configContent
            Copy-ToSMBShare -SourceFilePath $OutputArchive -DestinationSMBPath $share -Username $username -Password $password
        }
    }
}

function Search-KapeFile()
{
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [Parameter(ParameterSetName="All")]
        [string]
        $Filter,

        [Parameter(ParameterSetName="Specific")]
        [string]
        $FilterDescription,

        [Parameter(ParameterSetName="Specific")]
        [string]
        $FilterID,

        [Parameter(ParameterSetName="Specific")]
        [string]
        $FilterTargetName,

        [Parameter(ParameterSetName="Specific")]
        [string]
        $FilterCategory,

        [Parameter(ParameterSetName="Specific")]
        [string]
        $FilterPath,

        [Parameter(ParameterSetName="Specific")]
        [string]
        $FilterFileMask,

        [switch]
        $Print,

        [switch]
        $ShortList,

        [switch]
        $MatchAllOfThem,

        [Parameter(ParameterSetName="All")]
        [Parameter(ParameterSetName="Specific")]
        [Parameter(ParameterSetName="Modules")]
        [switch]
        $OnlyModules,

        [Parameter(ParameterSetName="All")]
        [Parameter(ParameterSetName="Specific")]
        [Parameter(ParameterSetName="Targets")]
        [switch]
        $OnlyTargets
    )
    $Pattern = @()
    $Scope = @(".\Modules\",".\Targets\")
    $ScopeFilter = @("*.mkape","*.tkape")
    if ($OnlyModules)
    {
        $Scope = ".\Modules\"
        $ScopeFilter = "*.mkape"
    }
    if ($OnlyTargets)
    {
        $Scope = ".\Targets\"
        $ScopeFilter = "*.tkape"
    }

    if ($Filter)
    {
        $Pattern += ".*$Filter.*"
    }
    else
    {
        if ($FilterDescription)
        {
            $Pattern += "^Description:.*$FilterDescription.*"
        }
        if ($FilterID)
        {
            $Pattern += "^ID:.*$FilterID.*"
        }
        if ($FilterTargetName)
        {
            $Pattern += "^\s*Name:.*$FilterTargetName.*"
        }
        if ($FilterCategory)
        {
            $Pattern += "^\s*Category.*$FilterCategory.*"
        }
        if ($FilterPath)
        {
            $Pattern += "^\s*Path:.*$FilterPath.*"
        }
        if ($FilterFileMask)
        {
            $Pattern += "^\s*FileMask:.*$FilterFileMask.*"
        }
    }

    if ($Pattern)
    {
        write-verbose "MatchAllOfThem: $MatchAllOfThem, Pattern $($Pattern -join ","), Scope: $Scope, ScopeFilter: $ScopeFilter"

        if ($MatchAllOfThem)
        {
            $files = gci -Recurse -file $Scope -Include $ScopeFilter | MultiSelect-String $Pattern | select name, fullname

        }
        else
        {
            $files = gci -Recurse -file $Scope -Include $ScopeFilter | where { $_ | sls $Pattern } | select name, fullname
        }

        if ($Print)
        {
            $files = $files | sort name
            foreach ($f in $files)
            {
                if ($f.name -match ".tkape$")
                {
                    write "$($f.name) $($f.FullName -replace ".*\\targets\\",".\Targets\")"
                    write ""
                    Invoke-Kape -target $($f.name -replace ".tkape","") -print
                }
                else
                {
                    write "$($f.name) $($f.FullName -replace ".*\\modules\\",".\Modules\")"
                    write ""
                    Invoke-Kape -module $($f.name -replace ".mkape","") -print
                }
            }
        }
        elseif ($ShortList)
        {
            $files = $files | sort name
            foreach ($f in $files)
            {
                if ($f.name -match ".tkape$")
                {
                    write "$($f.name) $($f.FullName -replace ".*\\targets\\",".\Targets\")"
                }
                else
                {
                    write "$($f.name) $($f.FullName -replace ".*\\modules\\",".\Modules\")"
                }
            }
        }
        else
        {
            $files
        }
    }
}

filter MultiSelect-String( [string[]]$Patterns )
{
  foreach( $Pattern in $Patterns ) {
    $matched = @($_ | Select-String -Pattern $Pattern -AllMatches)
    if( -not $matched ) {
      return
    }
  }
  $_
}

# Below is the code for the dynamic parameters for modules and targets

function Get-DynamicFlowParamKAPE()
{
    $Dictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

    New-DynamicParam -Name Module -type string[] -ValidateSet $(((gci -Recurse  .\modules\* -Filter *.mkape).name) -replace "\.mkape","") -DPDictionary $Dictionary

    New-DynamicParam -Name Target -type string[] -ValidateSet $(((gci .\targets\*\*.tkape).name) -replace "\.tkape","") -DPDictionary $Dictionary

    $Dictionary
}

function Get-DynamicFlowParamModules()
{
    $Dictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

    New-DynamicParam -Name Module -type string[] -ValidateSet $(((gci -Recurse  .\modules\* -Filter *.mkape).name) -replace "\.mkape","") -DPDictionary $Dictionary -Mandatory

    $Dictionary
}

# Generic dynamic param function

Function New-DynamicParam ()
{
    param(
        [string]
        $Name,

        [System.Type]
        $Type = [string],

        [string[]]
        $Alias = @(),

        [string[]]
        $ValidateSet,

        [switch]
        $Mandatory,

        [string]
        $ParameterSetName="__AllParameterSets",

        [int]
        $Position,

        [switch]
        $ValueFromPipelineByPropertyName,

        [string]
        $HelpMessage,

        [validatescript({
            if(-not ( $_ -is [System.Management.Automation.RuntimeDefinedParameterDictionary] -or -not $_) )
            {
                Throw "DPDictionary must be a System.Management.Automation.RuntimeDefinedParameterDictionary object, or not exist"
            }
            $True
        })]
        $DPDictionary = $false

    )
    $ParamAttr = New-Object System.Management.Automation.ParameterAttribute
    $ParamAttr.ParameterSetName = $ParameterSetName
    if($Mandatory)
    {
        $ParamAttr.Mandatory = $True
    }
    if($Position -ne $null)
    {
        $ParamAttr.Position=$Position
    }
    if($ValueFromPipelineByPropertyName)
    {
        $ParamAttr.ValueFromPipelineByPropertyName = $True
    }
    if($HelpMessage)
    {
        $ParamAttr.HelpMessage = $HelpMessage
    }

    $AttributeCollection = New-Object -type System.Collections.ObjectModel.Collection[System.Attribute]
    $AttributeCollection.Add($ParamAttr)

    if($ValidateSet)
    {
        $ParamOptions = New-Object System.Management.Automation.ValidateSetAttribute -ArgumentList $ValidateSet
        $AttributeCollection.Add($ParamOptions)
    }

    if($Alias.count -gt 0) {
        $ParamAlias = New-Object System.Management.Automation.AliasAttribute -ArgumentList $Alias
        $AttributeCollection.Add($ParamAlias)
    }

    $Parameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList @($Name, $Type, $AttributeCollection)

    if($DPDictionary)
    {
        $DPDictionary.Add($Name, $Parameter)
    }
    else
    {
        $Dictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        $Dictionary.Add($Name, $Parameter)
        $Dictionary
    }
}


## Disable progress bar
$OriginalPref = $ProgressPreference # Default is 'Continue'
$ProgressPreference = "SilentlyContinue"

## Collect artefacts
Invoke-Kape @Args

## Re-enable progress bar
$ProgressPreference = $OriginalPref