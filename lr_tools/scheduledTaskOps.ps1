<#


Useage is still the same but all functions have been combined into one script.

.SYNOPSIS   
Function to delete scheduled tasks

.DESCRIPTION 
This script is a combination of both the Get-Scheduledtask and Remove-ScheduledTask scripts found on the MSDN repository.

.PARAMETER ComputerName
This parameter contains the computername from which a task should be deleted

.PARAMETER Path
This parameter specifies the path of task that should be deleted. This should be in the following format: '\Folder\SubFolder\TaskName'
    
.NOTES
Name: Remove (Contains Remove-ScheduledTask and Get-ScheduledTask)
Author: Jaap Brasser
Updated: Christopher Scott
DateUpdated: 2017-05-04
Updated: Sean McFeely
DateUpdated: A few days after 2017-05-04
Version: 1.0

.EXAMPLE

. .\Remove.ps1

Description
-----------
This command dot sources the script to ensure the Remove-ScheduledTask and Get-ScheduledTask functions are available in your current PowerShell session

.EXAMPLE
.\Get-ScheduledTask.ps1 | Where-Object {$_.State -eq 'Disabled'} | Remove-ScheduledTask -WhatIf

Description
-----------
Get-ScheduledTask will list all the disabled tasks on a system and the Remove-ScheduledTask function will list all the actions that could be taken

.EXAMPLE
Remove-ScheduledTask -ComputerName JaapTest01 -Path '\Folder\YourTask'

Description
-----------
Will remove the YourTask task from the JaapTest01 system

.EXAMPLE
Get-ScheduledTask | Remove-ScheduledTask -Confirm

Description
-----------
Will go through all the tasks on the local system and ask for confirmation before removing any tasks.

#>


<#   
.SYNOPSIS   
Function to delete scheduled tasks

.DESCRIPTION 
This function provides the possibility to remove scheduled tasks either locally or remotely. It was written after I received a request from Wulfioso to be able to delete scheduled tasks. This script can either take output from my Get-ScheduledTask.ps1 through the pipeline or a ComputerName and Path to a task can be specified. This function supports the WhatIf and Confirm switch parameters.

.PARAMETER ComputerName
This parameter contains the computername from which a task should be deleted

.PARAMETER Path
This parameter specifies the path of task that should be deleted. This should be in the following format: '\Folder\SubFolder\TaskName'
    
.NOTES   
Name: Remove-ScheduledTask
Author: Jaap Brasser
DateUpdated: 2015-08-06
Version: 1.0
Blog: http://www.jaapbrasser.com

.LINK
http://www.jaapbrasser.com

.EXAMPLE
. .\Remove-ScheduledTask.ps1

Description
-----------
This command dot sources the script to ensure the Remove-ScheduledTask function is available in your current PowerShell session

.EXAMPLE
Remove-ScheduledTask -ComputerName JaapTest01 -Path '\Folder\YourTask'

Description
-----------
Will remove the YourTask task from the JaapTest01 system

.EXAMPLE
.\Get-ScheduledTask.ps1 | Where-Object {$_.State -eq 'Disabled'} | Remove-ScheduledTask -WhatIf

Description
-----------
Get-ScheduledTask will list all the disabled tasks on a system and the Remove-ScheduledTask function will list all the actions that could be taken

.EXAMPLE
.\Get-ScheduledTask.ps1 | Remove-ScheduledTask -Confirm

Description
-----------
Will go through all the tasks on the local system and ask for confirmation before removing any tasks.
#>
param([switch]$Get, [switch]$Remove, [string]$ComputerName, [string]$Path)

function Remove-ScheduledTask {
	[cmdletbinding(SupportsShouldProcess = $true)]
	param (
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true,
				   Position = 0
        )]
        [string]
		$ComputerName,
		
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true,
				   Position = 1
        )]
        [string]
		$Path
	)
	
	begin {
		try {
	        $Schedule = New-Object -ComObject 'Schedule.Service'
        } catch {
	        Write-Warning "Schedule.Service COM Object not found, this script requires this object"
	        return
        }
	}
	
	process	{
        try {
            $Schedule.Connect($ComputerName)
            $TaskFolder = $Schedule.GetFolder((Split-Path -Path $Path))
            if ($PSCmdlet.ShouldProcess($Path,'Deleting Task')) {
                $TaskFolder.DeleteTask((Split-Path -Path $Path -Leaf),0)
            }
        } catch {
            $_.exception.message
        }
	}
	
	end	{

	}
}

Function Get-Tasks {
    
    param(
	    [string]$ComputerName = $env:COMPUTERNAME,
        [switch]$RootFolder
    )

    #region Functions
    function Get-AllTaskSubFolders {
        [cmdletbinding()]
        param (
            # Set to use $Schedule as default parameter so it automatically list all files
            # For current schedule object if it exists.
            $FolderRef = $Schedule.getfolder("\")
        )
        if ($FolderRef.Path -eq '\') {
            $FolderRef
        }
        if (-not $RootFolder) {
            $ArrFolders = @()
            if(($Folders = $folderRef.getfolders(1))) {
                $Folders | ForEach-Object {
                    $ArrFolders += $_
                    if($_.getfolders(1)) {
                        Get-AllTaskSubFolders -FolderRef $_
                    }
                }
            }
            $ArrFolders
        }
    }

    function Get-TaskTrigger {
        [cmdletbinding()]
        param (
            $Task
        )
        $Triggers = ([xml]$Task.xml).task.Triggers
        if ($Triggers) {
            $Triggers | Get-Member -MemberType Property | ForEach-Object {
                $Triggers.($_.Name)
            }
        }
    }
    #endregion Functions


    try {
	    $Schedule = New-Object -ComObject 'Schedule.Service'
    } catch {
	    Write-Warning "Schedule.Service COM Object not found, this script requires this object"
	    return
    }

    $Schedule.connect($ComputerName) 
    $AllFolders = Get-AllTaskSubFolders

    foreach ($Folder in $AllFolders) {
        if (($Tasks = $Folder.GetTasks(1))) {
            $Tasks | Foreach-Object {
	            New-Object -TypeName PSCustomObject -Property @{
	                'Name' = $_.name
                    'Path' = $_.path
                    'State' = switch ($_.State) {
                        0 {'Unknown'}
                        1 {'Disabled'}
                        2 {'Queued'}
                        3 {'Ready'}
                        4 {'Running'}
                        Default {'Unknown'}
                    }
                    'Enabled' = $_.enabled
                    'LastRunTime' = $_.lastruntime
                    'LastTaskResult' = $_.lasttaskresult
                    'NumberOfMissedRuns' = $_.numberofmissedruns
                    'NextRunTime' = $_.nextruntime
                    'Author' =  ([xml]$_.xml).Task.RegistrationInfo.Author
                    'UserId' = ([xml]$_.xml).Task.Principals.Principal.UserID
                    'Description' = ([xml]$_.xml).Task.RegistrationInfo.Description
                    'Trigger' = Get-TaskTrigger -Task $_
                    'ComputerName' = $Schedule.TargetServer
                }
            }
        }
    }
}


if ($Get){
    Get-Tasks
} ElseIf ($Remove) {
    Remove-ScheduledTask $ComputerName $Path
}
