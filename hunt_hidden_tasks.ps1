function Get-TaskActions($taskid)
{
   $taskactions = get-itempropertyvalue -path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$taskid" -name "Actions"
   return [System.Text.Encoding]::Unicode.GetString($taskactions)
}

$tasks = gci -Path  "REGISTRY::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\" -Recurse
$ErrorActionPreference = “silentlycontinue”
foreach($task in $tasks)
{
   
  if ((Get-Item -Path "REGISTRY::\$task").Getvalue("Id") -ne $null) 
    {
        
        if ((Get-Item -Path "REGISTRY::\$task").Getvalue("SD") -eq $null) 
        {
            write-host "suspicious task found - missing SD value"
            write-host "taskpath: "$task
            $taskid = (Get-Item -Path "REGISTRY::\$task").Getvalue("Id")
            write-host "Task Action: "
            Get-TaskActions($taskid)
            write-host "------------------------------------------------------------------"

        }
        elseif((Get-Item -Path "REGISTRY::\$task").Getvalue("SD").Length -eq 0)
        {
            write-host "suspicious task found - zero length SD value"
            write-host "taskpath: "$task
            write-host "Task Action: "
            $taskid = (Get-Item -Path "REGISTRY::\$task").Getvalue("Id")
            Get-TaskActions($taskid)
            write-host "------------------------------------------------------------------"
        }
        else
        {
            $SecDescBin =(Get-Item -Path "REGISTRY::\$task").Getvalue("SD")
            $SecDesc = ([WMIClass]"Win32_SecurityDescriptorHelper").BinarySDToWin32SD($SecDescBin).Descriptor
            if (($SecDesc.Owner.Length -eq 0) -and ($SecDesc.Group.Length -eq 0))
            {
                write-host "suspicious task located: invalid SDDL data in SD value"
                write-host "taskpath: "$task
                write-host "Task Action: "
                $taskid = (Get-Item -Path "REGISTRY::\$task").Getvalue("Id")
                Get-TaskActions($taskid)
                write-host "------------------------------------------------------------------"
            }
            elseif($SecDesc.DACL.Trustee.Name -notcontains "SYSTEM")
            {
                  write-host "suspicious task located: SYSTEM not listed in DACL"
                  write-host "taskpath: "$task
                  write-host $SecDesc.Descriptor.Owner
                  write-host $SecDesc.Descriptor.Group
                  $taskid = (Get-Item -Path "REGISTRY::\$task").Getvalue("Id")
                  write-host "Task Action: "
                  Get-TaskActions($taskid)
                  write-host "------------------------------------------------------------------"
            }
            else
            {
                $SecDesc.DACL | foreach {
                if ((($_.Trustee.Name -eq "SYSTEM") -or ($_.Trustee.Name -eq "Administrators") ) -and ($_.AceType -eq 1))
                {
                    write-host "suspicious task located: SYSTEM or Administrators explicity denied in DACL"
                    write-host "taskpath: "$task
                    write-host "Security Descriptor Owner: " $SecDesc.Owner.Name
                    write-host "Security Descriptor Group: " $SecDesc.Group.Name
                    $taskid = (Get-Item -Path "REGISTRY::\$task").Getvalue("Id")
                    write-host "Task Action: "
                    Get-TaskActions($taskid)
                    write-host "------------------------------------------------------------------"
                }
                
                }

            }
            
            
        }
    }

  
}