# SCRIPT VARIBLES

#logg, mainly used for errors
$path_to_logg_file = './logs/log.txt';

#path to users
$users = './files/Users.csv';
#path to group membership
$group_membership = './files/GroupMembership.csv';
#groups 
$groups = './files/Groups.csv'
#path to UO
$ou = './files/OUs.csv';

#SCRIPT CONFIGURATION

#folder where the users map will be
$folder_for_users = 'D:\Storage_inl6\Users';

#sites for the users
$user_sites = @('SiteA_users','SiteB_users','SiteC_users');

##END VARIABLES

#import active directory
import-module ActiveDirectory;

#import OU and loop them, use UTF8 so ÅÄÖ works.
$OU_list = Import-CSV -path $ou -Delimiter ";" -Encoding UTF8

foreach($item in $OU_list){
    try{
        #variables for name and Förälder
        $name = $item.OU
        $path = $item.FörälderOU
        write-host $item;
        write-host $path;
    
        #create the OU with the provided information in $variables
        New-ADOrganizationalUnit -Name "$name" -Path "$path" -ErrorAction stop
    
        #Tell the users that the OU have been created
        Write-Host "OU $name have been created"
    }
    catch{
        Add-Content -Value "$name at $path already exists and could not be created" -Path $path_to_logg_file -Force
        write-host $_
    }
}

#create the groups
$group_list = Import-CSV -path $groups -Delimiter ";" -Encoding UTF8

foreach($item in $group_list){
    $group_name = $item.Gruppnamn
    $parent = $item.FörälderOU
    Try { 
        #see if the group already exists. If not, the group will be created
        Get-ADGroup $group_name -ErrorAction stop 
        Write-Host "Group $group_name already exists in the AD, skipping this group." 
    } 
    Catch { 
        #If group dont exists, create it.
        New-ADGroup -Name $group_name -GroupScope Global -Path $parent
        Write-Host "Succesfully created group $group_name" 
    }
}

#Set permissions for the groups parent folder. The owner of the script will be the person which runs this scripts. and the user will get full control of the folder and the folders subfolders
#Users which are authenticated will be able to see the folder and the folders subfolder.

#create the parents folder
New-Item -ItemType Directory -Force -Path $folder_for_users

$parent_acl = Get-Acl $folder_for_users
$parent_acl.SetAccessRuleProtection($True, $False)

#set the loggedin user as owner of the parent folder
$parent_acl.SetOwner([System.Security.Principal.NTAccount] "$env:USERNAME") 

#Set so the users which runs the script get admin rights
$rule_current_users = New-Object System.Security.AccessControl.FileSystemAccessRule ($env:USERNAME,'FullControl','Allow')

#adding rules to authenticade users
$rule_auth_users = New-Object System.Security.AccessControl.FileSystemAccessRule("authenticated users",'read','Allow')

$parent_acl.AddAccessRule($rule_current_users)
$parent_acl.AddAccessRule($rule_auth_users)
Set-Acl $folder_for_users $parent_acl | Out-Null 

#CREATE SUB GROUPS FOR GROUPS

$group_membership_file = Import-Csv $group_membership -Delimiter ";" -Encoding UTF8

foreach($item in $group_membership_file){

    $parent_group = $item.Föräldergrupp;
    $member_group = $item.Föräldergrupp

    try{

        #create new ad parent group
        New-ADGroup -Name $parent_group -GroupScope Global -ErrorAction stop
        Add-ADGroupMember -Identity $parent_group -Members $member_group
        Write-Host "$member_group created"

    }

    catch{

        #add member to group if group already exists
        Add-ADGroupMember -Identity $parent_group -Members $member_group
        Write-Host "$member_group created"

    }
}

#CREATE THE USERS
$users_list = Import-Csv -Path $users -Delimiter ";" -Encoding UTF8
foreach($item in $users_list){

    $username = $item.Användarnamn
    $password = $item.Lösenord
    $firstname = $item.Förnamn
    $surname = $item.Efternamn
    $OU = $item.OU
    $group_member_ship = $item.Gruppmedlemskap

    #check if user already exists
    if(Get-ADUser -filter {SamAccountName -eq $username}){

        Write-host "$username already exists"
        Add-Content -Value "$username already exists" -Path $path_to_logg_file -Force

    }else{


        New-ADUser -UserPrincipalName $username -SamAccountName $username -Name "${$item.Förnamn} $surname" -GivenName $item.Förnamn -Surname $surname -Enabled $True -DisplayName "$surname, $firstname" -Path $OU -AccountPassword (ConvertTo-SecureString $password -AsPlainText  -Force)

        write-host "$username (${$item.Förnamn},$surname) have been created in the AD";

        foreach($sub_item in $group_member_ship){
            #ad user to the right group
            Add-ADGroupMember -Identity $sub_item -Members $username -ErrorAction stop 
        }

        try{
            #ad the homedirectory for the user, add H: as drive letter
            Set-aduser $Username -HomeDirectory "\\DC02.grupp06.lab\Shares\$($username)" -homedrive "H:"

        }

        catch{
            #if path already exists, tell the runner of the script and ad to the logg
            Write-host "$username folder already exists."
            Add-Content -Value "$Username folder already exists" -Path $path_to_logg_file -Force

        }

    }
}

#set permissions for groups parent folder
foreach($item in $users_list){

    $username = $item.Användarnamn
    $users_folder = "D:\Storage_Inl6\Users\$Username"
    #create an folder fo the user
    New-Item -ItemType Directory -Force -Path $users_folder
    #add permissions for the user
    $user = Get-Acl $users_folder
    $user.SetAccessRuleProtection($True, $False)
    #add the user that runs the script as owner
    $user.SetOwner([System.Security.Principal.NTAccount] "$env:USERNAME") 
    # add permissions to the user
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($username,'FullControl','Allow') 
    #ad domain admins permissions
    $domain_admin_rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Admins",'read','Allow')

    $user.AddAccessRule($rule)
    $user.AddAccessRule($domain_admin_rule)
    Set-Acl $users_folder $user.SetAccessRule() | Out-Null

}

#create an share for the users
New-SmbShare -Name "Shares" -Path "D:\Storage_Inl6\Users\" -FullAccess "Everyone"

#ADD PERMISSIONS TO PARENT FOLDER

$folder_groups = "D:\Storage_Inl6\Groups\"
New-Item -ItemType Directory -Force -Path $folder_groups

$parent_group_acl = Get-Acl $folder_groups
$parent_group_acl.SetAccessRuleProtection($True, $False)

#add permissions to the users that runs the script.
$parent_group_acl.SetOwner([System.Security.Principal.NTAccount] "$env:USERNAME") 

$group_permissions_rule = New-Object System.Security.AccessControl.FileSystemAccessRule($env:USERNAME,'FullControl','Allow')

#add domain admin permissions to the parent folder
$domain_admin_group_rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Users",'read','Allow')

$parent_group_acl.AddAccessRule($group_permissions_rule)
$parent_group_acl.AddAccessRule($domain_admin_group_rule)
Set-Acl $folder_groups $parent_group_acl | Out-Null

# END ADD PERMISSIONS TO PARENT FOLDER
# CREATE GROUP FOLDER

foreach($item in $users_list){
    $folder = $item

    try{

        $name_of_folder = $folder.Föräldergrupp | Where-Object {$_ -like "*site*"}
        New-Item -ItemType Directory -Force -Path "D:\Storage_Inl6\Groups\$name_of_folder" -ErrorAction stop

    }
    catch{

        #continue

    }

    foreach($item in $user_sites){

        foreach ($site in $item){

            try{

                mkdir $folder_groups\$user_sites[$i]\$site -ErrorAction Stop

                $permissions = "$site"+"_"+"$user_sites[$i]"
                $path = "D:\Storage_Inl6\Groups\$user_sites[$i]\$site"

                $acl = Get-Acl $path 
                $acl.SetAccessRuleProtection($True, $False)
                #add the user which runs the script as owner
                $acl.SetOwner([System.Security.Principal.NTAccount] "$env:USERNAME") 

                $owner_rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$permissions",'FullControl','Allow') 

                $domain_admin_rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Admins",'read','Allow')

                $acl.AddAccessRule($owner_rule)
                $acl.AddAccessRule($domain_admin_rule) 

                Set-Acl $path $acl | Out-Null -ErrorAction stop

            }
            catch{

                #continue

            }

        }

    }
}

#set permissions 
foreach($item in $user_site){

    $site = $item
    $folders = "D:\Storage_Inl6\Groups\$site"

    $acl = Get-Acl $folders
    $acl.SetAccessRuleProtection($True, $False)

    #set the users that runs the scripts as owner
    $acl.SetOwner([System.Security.Principal.NTAccount] "$env:USERNAME") 
    
    #set the permissions for the child
    $child_rules = New-Object System.Security.AccessControl.FileSystemAccessRule($site,'FullControl','Allow')   
    #set permissions for domain admins
    $domain_admin_rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Admins",'read','Allow')

    $acl.AddAccessRule($child_rules)
    $acl.AddAccessRule($domain_admin_rule) 

    Set-Acl $folders $acl | Out-Null

}

#END OF SCRIPT
write-host 'end of script'
