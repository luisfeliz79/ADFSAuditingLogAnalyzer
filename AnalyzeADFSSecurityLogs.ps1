param(

[Parameter()]
$LogPath,
$MaxEvents=1000000000,
$UserAuthsThreshold=5,
$IPAuthsThreshold=20,
$CreateCSV=$True
)  

#Project DREW

if (-not ($LogPath)) { "Please specify an EVTX archive to analyze";break }
if (-not (test-path $LogPath)) { "File $Logpath not found";break }
#Archive file to read


#Temporary files
$Temp411=".\Temp411.evtx"
$Temp500=".\Temp500.evtx"



Function DedupIPs ($IPArray) {

    $ReturnArray=@()
    #$MicrosoftIPs="40.97.176.229","52.96.19.45"

    $IPArray =  $IPArray | Sort-Object -Unique

    $IPArray | ForEach {

        if ($MicrosoftIPs -notcontains $_) {
            $ReturnArray+=$_

        }
               
    }

    $ReturnArray

}

Function ExpandForCSV ($object) {

    $Props=$object | get-member -MemberType NoteProperty
    
    $NewObject = new-object PSObject
    

           $Props | foreach {
           $Prop=$_.Name
                $object | foreach {
                    if (($_.$Prop).count -gt 1) {$_.$Prop=$_.$Prop -join ", "}
                   }

            }
  $object
}


write-warning "$(get-date) Creating Filtered logs ..."
wevtutil epl /lf:true $LogPath $Temp411 /q:"Event[System[(EventID=411)]]" /overwrite:true
wevtutil epl /lf:true $LogPath $Temp500 /q:"Event[System[(EventID=500)]]" /overwrite:true


write-warning "$(get-date) Loading Event data (may take a while) ..."
$data=Get-WinEvent -Path $Temp411 -MaxEvents $MaxEvents 
$data500=Get-WinEvent -Path $Temp500 -MaxEvents $MaxEvents 

write-warning "$(get-date) Analyzing Data...."
$EntryInfo=@() 

$data | foreach {

    $username=($_.Properties[2].value -split "-")[0]

    $EntryInfo += new-object PSObject -property ([ordered]@{
 
      "Username"     = $username
      "IPs"     = $_.Properties[-1].value -split ","
      "ErrorMsg" = ($_.Properties[2].value -split "-")[1]
      "Endpoint"     = $_.Properties[1].value
      "CorrelationID"     = $_.Properties[0].value
      "Server"     = $_.MachineName
      "TimeCreated" = $_.TimeCreated
      "RecordID" = $_.RecordID
 
    }) #new-object

}

$FormatEnumerationLimit=-1

# By user
$Report=$EntryInfo | Group-Object -Property Username | Sort-Object Count -Descending | Where Count -ge $UserAuthsThreshold

$Report | % { $_ | Add-Member -Name IPs -Value (DedupIPs -IPArray ($_.Group).IPs)  -MemberType NoteProperty } 
$Report | % { $_ | Add-Member -Name TimeCreated -Value ($_.Group).TimeCreated  -MemberType NoteProperty } 
$Report | % { $_ | Add-Member -Name LastSuccessfulLogin -Value ($($Username=$_.name;$CheckLogin=($data500 | where { ($_.Properties[2].value -split "-")[0] -eq $Username }); if ($CheckLogin) { ($CheckLogin | Sort-Object TimeCreated -Descending)[0].TimeCreated }    ))  -MemberType NoteProperty } 

$Report | FL Name,Count,IPs,TimeCreated,LastSuccessfulLogin

if ($CreateCSV) {

    ExpandForCSV ($Report) | Select Name,Count,IPs,TimeCreated,LastSuccessfulLogin | export-csv Logins.csv -NoTypeInformation
    Write-Warning "Created Logins.csv"
}


Write-Warning "Accounts of Interest: "
$Report |where LastSuccessfulLogin -ne $null| FL Name,Count,IPs,TimeCreated,LastSuccessfulLogin 

#By IP
Write-Warning "IPs of Interest: "

$UniqueIPs= DedupIPs -IPArray $EntryInfo.IPs

$IPInfo=@()
$UniqueIPs | foreach {

    $IPMatch=($EntryInfo | where IPs -contains $_)
    $IPInfo+= new-object PSObject -property ([ordered]@{
         
      "IP"     = $_
      "Users"     = $IPMatch.UserName | Sort-Object -Unique
      "Count"     = $IPMatch.count
      "Server"     = $IPMatch.Server | Sort-Object -Unique

    }) #new-object

}

$IPInfo | where Count -ge $IPAuthsThreshold | Sort-Object Count | Select IP,Count,Users 
        
if ($CreateCSV) {

    ExpandForCSV ($IPInfo | where Count -ge $IPAuthsThreshold | Sort-Object Count) | Select IP,Server,Users,Count | export-csv IPreport.csv -NoTypeInformation
    Write-Warning "Created IPReport.csv"
}
