How to set powershell and excute the commands
1. list of RHSA update in rhsa_list.txt file one by one
2. open power shell prompt 
Test-NetConnection -ComputerName access.redhat.com -Port 443
Get-ExecutionPolicy
Set-ExecutionPolicy Bypass -Scope CurrentUser
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
cd .\Downloads\rhsa
.\rhel_rhsa_report.ps1 -InputFile "rhsa_list.txt" -Format both 


# Single RHSA
.\rhel_rhsa_report_1.ps1 -RHSAIds "RHSA-2024:0001"

# Multiple RHSAs
.\rhel_rhsa_report_1.ps1 -RHSAIds "RHSA-2024:0001","RHSA-2024:0002","RHSA-2023:7549"

# With custom output path
.\rhel_rhsa_report_1.ps1 -RHSAIds "RHSA-2024:0001","RHSA-2024:0002" -OutputPath "C:\Reports\rhsa_report.csv"

.\rhel_rhsa_report_1.ps1 -InputFile "rhsa_list.txt" 	From file
.\rhel_rhsa_report_1.ps1 -OutputPath "C:\report.csv" 	Custom output path

.\rhel_rhsa_report_1.ps1 -InputFile "rhsa_list.txt" -OutputPath "C:\Users\ifrcdi8\Downloads\rhsa\reports"

.\simple_1.ps1 -RHSAIds "RHSA-2026:0719" ---- exactly working
.\simple_1.ps1 -InputFile "rhsa_list.txt" ------ exactly working
.\simple_2.ps1 -RHSAIds "RHSA-2026:0719" ---- exactly working with rhsa_list should contain with full information same as vulnerability sheet
.\simple_2.ps1 -InputFile "rhsa_list.txt" ------ exactly working rhsa_list should contain with full information same as vulnerability sheet

working 
.\simple_3.ps1 ----- check rhsa_list.txt file from script which required same named file and csv created location - last perfectly worked on 18/03/2026
.\simple_4.ps1 ----- check rhsa_list.txt file from script which required same named file and csv created location
.\simple_5.ps1 ----- check rhsa_list.txt file from script which required same named file and csv created location
.\simple_7.ps1 -InputFile "rhsa_list2.txt"
.\simple_7.ps1 ---------check rhsa_list.txt file from script which required same named file and csv created location - last perfectly worked on 19/03/2026
---------------------------
# Method 1: Auto-detect (looks for rhsa_list.txt)
.\RHSA_Tracker.ps1

# Method 2: Specify input file
.\RHSA_Tracker.ps1 -InputFile "my_vulnerabilities.txt"

# Method 3: Will prompt for file name if not found
.\RHSA_Tracker.ps1