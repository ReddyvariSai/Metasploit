# Metasploitable framework 

Metasploit is a toolkit for penetration testers. It collects reusable pieces of offensive work: code that exploits vulnerabilities,
payloads that run on a target, components that listen for connections from those payloads, and helper modules that scan,
enumerate, and perform post-exploitation tasks. It is a framework that brings these pieces together so testers do not have to
write everything from scratch.

```

┌──(root㉿kali)-[/home/kali]
└─# msfconsole
Metasploit tip: Add routes to pivot through a compromised host using route 
add <subnet> <session_id>

                                                  
               .;lxO0KXXXK0Oxl:.
           ,o0WMMMMMMMMMMMMMMMMMMKd,                                                                                
        'xNMMMMMMMMMMMMMMMMMMMMMMMMMWx,                                                                             
      :KMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMK:                                                                           
    .KMMMMMMMMMMMMMMMWNNNWMMMMMMMMMMMMMMMX,                                                                         
   lWMMMMMMMMMMMXd:..     ..;dKMMMMMMMMMMMMo                                                                        
  xMMMMMMMMMMWd.               .oNMMMMMMMMMMk                                                                       
 oMMMMMMMMMMx.                    dMMMMMMMMMMx                                                                      
.WMMMMMMMMM:                       :MMMMMMMMMM,                                                                     
xMMMMMMMMMo                         lMMMMMMMMMO                                                                     
NMMMMMMMMW                    ,cccccoMMMMMMMMMWlccccc;                                                              
MMMMMMMMMX                     ;KMMMMMMMMMMMMMMMMMMX:                                                               
NMMMMMMMMW.                      ;KMMMMMMMMMMMMMMX:                                                                 
xMMMMMMMMMd                        ,0MMMMMMMMMMK;                                                                   
.WMMMMMMMMMc                         'OMMMMMM0,                                                                     
 lMMMMMMMMMMk.                         .kMMO'                                                                       
  dMMMMMMMMMMWd'                         ..                                                                         
   cWMMMMMMMMMMMNxc'.                ##########                                                                     
    .0MMMMMMMMMMMMMMMMWc            #+#    #+#
      ;0MMMMMMMMMMMMMMMo.          +:+
        .dNMMMMMMMMMMMMo          +#++:++#+
           'oOWMMMMMMMMo                +:+
               .,cdkO0K;        :+:    :+:                                
                                :::::::+:
                      Metasploit

       =[ metasploit v6.4.103-dev                               ]
+ -- --=[ 2,584 exploits - 1,319 auxiliary - 1,697 payloads     ]
+ -- --=[ 434 post - 49 encoders - 14 nops - 9 evasion          ]

Metasploit Documentation: https://docs.metasploit.com/
The Metasploit Framework is a Rapid7 Open Source Project

[*] Starting persistent handler(s)...
msf > 


```
## Core concepts

Modules: Separate components that perform one job, such as exploiting a vulnerability, scanning a service, or performing post-exploitation.
Payloads: The code that runs on a target after an exploit succeeds. Payloads can be simple shells or advanced interactive agents.
Meterpreter: A common interactive payload that provides many built-in capabilities for file access, running commands, and gathering
information.
Handler or listener: A component that waits for a payload to connect back to the tester so the session can be controlled.
Database and workspace: Storage that lets testers keep scan results, notes, and session data organized and repeatable.


## Why Metasploit is useful for penetration testing

Library of proven code: Many exploits and tools are available and tested by the community, which saves time.

**Consistency:** A common interface and module model makes it easier to reuse knowledge across different targets.

**Speed:** Attack chains can be assembled quickly, allowing testers to focus on strategy rather than coding.

**Post-exploitation tools:** Built-in capabilities let testers collect evidence, pivot inside a network, and demonstrate impact.

**Automation and integration:** Scripts, saved configurations, and integration with scanners let large or repeated assessments run more smoothly.

**Learning and validation:** It is useful in labs to learn exploitation techniques and to validate defenses and detection controls.

## Why it is considered easy to use

**Single interface:** A unified framework provides predictable commands and workflows for many tasks.

**Sensible defaults:** Modules include default settings so a tester often needs to change only a few values.

Searchable modules and documentation: Testers can look up modules and read built-in help to understand what each module does.

**Reusable patterns:** The same high-level steps apply to many different targets, which reduces the learning curve.

**Community examples:** Many learning materials and shared module usage examples help beginners practice safely in labs.








```
msf > show auxiliary

Auxiliary
=========

   #     Name                                                                     Disclosure Date  Rank    Check  Description
   -     ----                                                                     ---------------  ----    -----  -----------
   0     auxiliary/admin/2wire/xslt_password_reset                                2007-08-15       normal  No     2Wire Cross-Site Request Forgery Password Reset Vulnerability
   1     auxiliary/admin/android/google_play_store_uxss_xframe_rce                .                normal  No     Android Browser RCE Through Google Play Store XFO
   2     auxiliary/admin/appletv/appletv_display_image                            .                normal  No     Apple TV Image Remote Control
   3     auxiliary/admin/appletv/appletv_display_video                            .                normal  No     Apple TV Video Remote Control
   4     auxiliary/admin/atg/atg_client                                           .                normal  No     Veeder-Root Automatic Tank Gauge (ATG) Administrative Client
   5     auxiliary/admin/aws/aws_launch_instances                                 .                normal  No     Launches Hosts in AWS
   6     auxiliary/admin/backupexec/dump                                          .                normal  No     Veritas Backup Exec Windows Remote File Access
   7     auxiliary/admin/backupexec/registry                                      .                normal  No     Veritas Backup Exec Server Registry Access
   8     auxiliary/admin/chromecast/chromecast_reset                              .                normal  No     Chromecast Factory Reset DoS
   9     auxiliary/admin/chromecast/chromecast_youtube                            .                normal  No     Chromecast YouTube Remote Control
   10    auxiliary/admin/citrix/citrix_netscaler_config_decrypt                   2022-05-19       normal  No     Decrypt Citrix NetScaler Config Secrets
   11    auxiliary/admin/db2/db2rcmd                                              2004-03-04       normal  No     IBM DB2 db2rcmd.exe Command Execution Vulnerability
   12    auxiliary/admin/dcerpc/cve_2020_1472_zerologon                           .                normal  Yes    Netlogon Weak Cryptographic Authentication
   13    auxiliary/admin/dcerpc/cve_2022_26923_certifried                         .                normal  No     Active Directory Certificate Services (ADCS) privilege escalation (Certifried)
   14    auxiliary/admin/dcerpc/esc_update_ldap_object                            .                normal  No     Exploits AD CS Template misconfigurations which involve updating an LDAP object: ESC9, ESC10, and ESC16
   15    auxiliary/admin/dcerpc/icpr_cert                                         .                normal  No     ICPR Certificate Management
   16    auxiliary/admin/dcerpc/samr_account                                      .                normal  No     SAMR Account Management
   17    auxiliary/admin/dns/dyn_dns_update                                       .                normal  No     DNS Server Dynamic Update Record Injection
   18    auxiliary/admin/edirectory/edirectory_dhost_cookie                       .                normal  No     Novell eDirectory DHOST Predictable Session Cookie
   19    auxiliary/admin/edirectory/edirectory_edirutil                           .                normal  No     Novell eDirectory eMBox Unauthenticated File Access
   20    auxiliary/admin/emc/alphastor_devicemanager_exec                         2008-05-27       normal  No     EMC AlphaStor Device Manager Arbitrary Command Execution
   21    auxiliary/admin/emc/alphastor_librarymanager_exec                        2008-05-27       normal  No     EMC AlphaStor Library Manager Arbitrary Command Execution
   22    auxiliary/admin/firetv/firetv_youtube                                    .                normal  No     Amazon Fire TV YouTube Remote Control
   23    auxiliary/admin/hp/hp_data_protector_cmd                                 2011-02-07       normal  No     HP Data Protector 6.1 EXEC_CMD Command Execution
   24    auxiliary/admin/hp/hp_ilo_create_admin_account                           2017-08-24       normal  Yes    HP iLO 4 1.00-2.50 Authentication Bypass Administrator Account Creation
   25    auxiliary/admin/hp/hp_imc_som_create_account                             2013-10-08       normal  No     HP Intelligent Management SOM Account Creation
   26    auxiliary/admin/http/allegro_rompager_auth_bypass                        2014-12-17       normal  No     Allegro Software RomPager 'Misfortune Cookie' (CVE-2014-9222) Authentication Bypass
   27    auxiliary/admin/http/arris_motorola_surfboard_backdoor_xss               2015-04-08       normal  No     Arris / Motorola Surfboard SBG6580 Web Interface Takeover
   28    auxiliary/admin/http/atlassian_confluence_auth_bypass                    2023-10-04       normal  Yes    Atlassian Confluence Data Center and Server Authentication Bypass via Broken Access Control
   29    auxiliary/admin/http/axigen_file_access                                  2012-10-31       normal  No     Axigen Arbitrary File Read and Delete
   30    auxiliary/admin/http/cfme_manageiq_evm_pass_reset                        2013-11-12       normal  No     Red Hat CloudForms Management Engine 5.1 miq_policy/explorer SQL Injection
   31    auxiliary/admin/http/cisco_7937g_ssh_privesc                             2020-06-02       normal  No     Cisco 7937G SSH Privilege Escalation
   32    auxiliary/admin/http/cisco_ios_xe_cli_exec_cve_2023_20198                2023-10-16       normal  No     Cisco IOX XE unauthenticated Command Line Interface (CLI) execution
   33    auxiliary/admin/http/cisco_ios_xe_os_exec_cve_2023_20273                 2023-10-16       normal  No     Cisco IOX XE unauthenticated OS command execution
   34    auxiliary/admin/http/cisco_ssm_onprem_account                            2024-07-20       normal  Yes    Cisco Smart Software Manager (SSM) On-Prem Account Takeover (CVE-2024-20419)
   35    auxiliary/admin/http/cnpilot_r_cmd_exec                                  .                normal  No     Cambium cnPilot r200/r201 Command Execution as 'root'
   36    auxiliary/admin/http/cnpilot_r_fpt                                       .                normal  No     Cambium cnPilot r200/r201 File Path Traversal
   37    auxiliary/admin/http/contentkeeper_fileaccess                            .                normal  No     ContentKeeper Web Appliance mimencode File Access
   38    auxiliary/admin/http/dlink_dir_300_600_exec_noauth                       2013-02-04       normal  No     D-Link DIR-600 / DIR-300 Unauthenticated Remote Command Execution
   39    auxiliary/admin/http/dlink_dir_645_password_extractor                    .                normal  No     D-Link DIR 645 Password Extractor
   40    auxiliary/admin/http/dlink_dsl320b_password_extractor                    .                normal  No     D-Link DSL 320B Password Extractor
   41    auxiliary/admin/http/foreman_openstack_satellite_priv_esc                2013-06-06       normal  No     Foreman (Red Hat OpenStack/Satellite) users/create Mass Assignment
   42    auxiliary/admin/http/fortinet_fortiweb_create_admin                      2025-11-14       normal  Yes    Fortinet FortiWeb create new local admin
   43    auxiliary/admin/http/fortra_filecatalyst_workflow_sqli                   2024-06-25       normal  No     Fortra FileCatalyst Workflow SQL Injection (CVE-2024-5276)
   44    auxiliary/admin/http/gitlab_password_reset_account_takeover              2024-01-11       normal  No     GitLab Password Reset Account Takeover
   45    auxiliary/admin/http/gitstack_rest                                       2018-01-15       normal  No     GitStack Unauthenticated REST API Requests
   46    auxiliary/admin/http/grafana_auth_bypass                                 2019-08-14       normal  No     Grafana 2.0 through 5.2.2 authentication bypass for LDAP and OAuth
   47    auxiliary/admin/http/hikvision_unauth_pwd_reset_cve_2017_7921            2017-09-23       normal  Yes    Hikvision IP Camera Unauthenticated Password Change Via Improper Authentication Logic
   48    auxiliary/admin/http/hp_web_jetadmin_exec                                2004-04-27       normal  No     HP Web JetAdmin 6.5 Server Arbitrary Command Execution
   49    auxiliary/admin/http/ibm_drm_download                                    2020-04-21       normal  Yes    IBM Data Risk Manager Arbitrary File Download
   50    auxiliary/admin/http/idsecure_auth_bypass                                2023-11-27       normal  Yes    Control iD iDSecure Authentication Bypass (CVE-2023-6329)
   51    auxiliary/admin/http/iis_auth_bypass                                     2010-07-02       normal  No     MS10-065 Microsoft IIS 5 NTFS Stream Authentication Bypass
   52    auxiliary/admin/http/intersil_pass_reset                                 2007-09-10       normal  Yes    Intersil (Boa) HTTPd Basic Authentication Password Reset
   53    auxiliary/admin/http/iomega_storcenterpro_sessionid                      .                normal  No     Iomega StorCenter Pro NAS Web Authentication Bypass
   54    auxiliary/admin/http/ivanti_vtm_admin                                    2024-08-05       normal  Yes    Ivanti Virtual Traffic Manager Authentication Bypass (CVE-2024-7593)
   55    auxiliary/admin/http/jboss_bshdeployer                                   .                normal  No     JBoss JMX Console Beanshell Deployer WAR Upload and Deployment
   56    auxiliary/admin/http/jboss_deploymentfilerepository                      .                normal  No     JBoss JMX Console DeploymentFileRepository WAR Upload and Deployment
   57    auxiliary/admin/http/jboss_seam_exec                                     2010-07-19       normal  No     JBoss Seam 2 Remote Command Execution
   58    auxiliary/admin/http/joomla_registration_privesc                         2016-10-25       normal  Yes    Joomla Account Creation and Privilege Escalation
   59    auxiliary/admin/http/kaseya_master_admin                                 2015-09-23       normal  No     Kaseya VSA Master Administrator Account Creation
   60    auxiliary/admin/http/katello_satellite_priv_esc                          2014-03-24       normal  No     Katello (Red Hat Satellite) users/update_roles Missing Authorization
   61    auxiliary/admin/http/limesurvey_file_download                            2015-10-12       normal  No     Limesurvey Unauthenticated File Download
   62    auxiliary/admin/http/linksys_e1500_e2500_exec                            2013-02-05       normal  No     Linksys E1500/E2500 Remote Command Execution
   63    auxiliary/admin/http/linksys_tmunblock_admin_reset_bof                   2014-02-19       normal  No     Linksys WRT120N tmUnblock Stack Buffer Overflow
   64    auxiliary/admin/http/linksys_wrt54gl_exec                                2013-01-18       normal  No     Linksys WRT54GL Remote Command Execution
   65    auxiliary/admin/http/manage_engine_dc_create_admin                       2014-12-31       normal  No     ManageEngine Desktop Central Administrator Account Creation
   66    auxiliary/admin/http/manageengine_dir_listing                            2015-01-28       normal  No     ManageEngine Multiple Products Arbitrary Directory Listing
   67    auxiliary/admin/http/manageengine_file_download                          2015-01-28       normal  No     ManageEngine Multiple Products Arbitrary File Download
   68    auxiliary/admin/http/manageengine_pmp_privesc                            2014-11-08       normal  Yes    ManageEngine Password Manager SQLAdvancedALSearchResult.cc Pro SQL Injection
   69    auxiliary/admin/http/mantisbt_password_reset                             2017-04-16       normal  Yes    MantisBT password reset
   70    auxiliary/admin/http/mutiny_frontend_read_delete                         2013-05-15       normal  No     Mutiny 5 Arbitrary File Read and Delete
   71    auxiliary/admin/http/netflow_file_download                               2014-11-30       normal  No     ManageEngine NetFlow Analyzer Arbitrary File Download
   72    auxiliary/admin/http/netgear_auth_download                               2016-02-04       normal  No     NETGEAR ProSafe Network Management System 300 Authenticated File Download
   73    auxiliary/admin/http/netgear_pnpx_getsharefolderlist_auth_bypass         2021-09-06       normal  Yes    Netgear PNPX_GetShareFolderList Authentication Bypass
   74    auxiliary/admin/http/netgear_r6700_pass_reset                            2020-06-15       normal  Yes    Netgear R6700v3 Unauthenticated LAN Admin Password Reset
   75    auxiliary/admin/http/netgear_r7000_backup_cgi_heap_overflow_rce          2021-04-21       normal  Yes    Netgear R7000 backup.cgi Heap Overflow RCE
   76    auxiliary/admin/http/netgear_soap_password_extractor                     2015-02-11       normal  No     Netgear Unauthenticated SOAP Password Extractor
   77    auxiliary/admin/http/netgear_wnr2000_pass_recovery                       2016-12-20       normal  No     NETGEAR WNR2000v5 Administrator Password Recovery
   78    auxiliary/admin/http/nexpose_xxe_file_read                               .                normal  No     Nexpose XXE Arbitrary File Read
   79    auxiliary/admin/http/novell_file_reporter_filedelete                     .                normal  No     Novell File Reporter Agent Arbitrary File Delete
   80    auxiliary/admin/http/nuuo_nvrmini_reset                                  2016-08-04       normal  No     NUUO NVRmini 2 / NETGEAR ReadyNAS Surveillance Default Configuration Load and Administrator Password Reset
   81    auxiliary/admin/http/openbravo_xxe                                       2013-10-30       normal  No     Openbravo ERP XXE Arbitrary File Read
   82    auxiliary/admin/http/pfadmin_set_protected_alias                         2017-02-03       normal  Yes    Postfixadmin Protected Alias Deletion Vulnerability
   83    auxiliary/admin/http/pihole_domains_api_exec                             2021-08-04       normal  Yes    Pi-Hole Top Domains API Authenticated Exec
   84    auxiliary/admin/http/rails_devise_pass_reset                             2013-01-28       normal  No     Ruby on Rails Devise Authentication Password Reset
   85    auxiliary/admin/http/scadabr_credential_dump                             2017-05-28       normal  No     ScadaBR Credentials Dumper
   86    auxiliary/admin/http/scrutinizer_add_user                                2012-07-27       normal  No     Plixer Scrutinizer NetFlow and sFlow Analyzer HTTP Authentication Bypass
   87    auxiliary/admin/http/sophos_wpa_traversal                                2013-04-03       normal  No     Sophos Web Protection Appliance patience.cgi Directory Traversal
   88    auxiliary/admin/http/supra_smart_cloud_tv_rfi                            2019-06-03       normal  No     Supra Smart Cloud TV Remote File Inclusion
   89    auxiliary/admin/http/sysaid_admin_acct                                   2015-06-03       normal  No     SysAid Help Desk Administrator Account Creation
   90    auxiliary/admin/http/sysaid_file_download                                2015-06-03       normal  No     SysAid Help Desk Arbitrary File Download
   91    auxiliary/admin/http/sysaid_sql_creds                                    2015-06-03       normal  No     SysAid Help Desk Database Credentials Disclosure
   92    auxiliary/admin/http/telpho10_credential_dump                            2016-09-02       normal  No     Telpho10 Backup Credentials Dumper
   93    auxiliary/admin/http/tomcat_administration                               .                normal  No     Tomcat Administration Tool Default Access
   94    auxiliary/admin/http/tomcat_ghostcat                                     2020-02-20       normal  Yes    Apache Tomcat AJP File Read
   95    auxiliary/admin/http/tomcat_utf8_traversal                               2009-01-09       normal  No     Tomcat UTF-8 Directory Traversal Vulnerability
   96    auxiliary/admin/http/trendmicro_dlp_traversal                            2009-01-09       normal  No     TrendMicro Data Loss Prevention 5.5 Directory Traversal
   97    auxiliary/admin/http/typo3_news_module_sqli                              2017-04-06       normal  No     TYPO3 News Module SQL Injection
   98    auxiliary/admin/http/typo3_sa_2009_001                                   2009-01-20       normal  No     TYPO3 sa-2009-001 Weak Encryption Key File Disclosure
   99    auxiliary/admin/http/typo3_sa_2009_002                                   2009-02-10       normal  No     Typo3 sa-2009-002 File Disclosure
   100   auxiliary/admin/http/typo3_sa_2010_020                                   .                normal  No     TYPO3 sa-2010-020 Remote File Disclosure
   101   auxiliary/admin/http/typo3_winstaller_default_enc_keys                   .                normal  No     TYPO3 Winstaller Default Encryption Keys
   102   auxiliary/admin/http/ulterius_file_download                              .                normal  No     Ulterius Server File Download Vulnerability
   103   auxiliary/admin/http/vbulletin_upgrade_admin                             2013-10-09       normal  No     vBulletin Administrator Account Creation
   104   auxiliary/admin/http/webnms_cred_disclosure                              2016-07-04       normal  No     WebNMS Framework Server Credential Disclosure
   105   auxiliary/admin/http/webnms_file_download                                2016-07-04       normal  No     WebNMS Framework Server Arbitrary Text File Download
   106   auxiliary/admin/http/whatsup_gold_sqli                                   2024-08-29       normal  Yes    WhatsUp Gold SQL Injection (CVE-2024-6670)
   107   auxiliary/admin/http/wp_automatic_plugin_privesc                         2021-09-06       normal  Yes    WordPress Plugin Automatic Config Change to RCE
   108   auxiliary/admin/http/wp_custom_contact_forms                             2014-08-07       normal  No     WordPress custom-contact-forms Plugin SQL Upload
   109   auxiliary/admin/http/wp_easycart_privilege_escalation                    2015-02-25       normal  Yes    WordPress WP EasyCart Plugin Privilege Escalation
   110   auxiliary/admin/http/wp_gdpr_compliance_privesc                          2018-11-08       normal  Yes    WordPress WP GDPR Compliance Plugin Privilege Escalation
   111   auxiliary/admin/http/wp_google_maps_sqli                                 2019-04-02       normal  Yes    WordPress Google Maps Plugin SQL Injection
   112   auxiliary/admin/http/wp_masterstudy_privesc                              2022-02-18       normal  Yes    Wordpress MasterStudy Admin Account Creation
   113   auxiliary/admin/http/wp_post_smtp_acct_takeover                          2024-01-10       normal  Yes    Wordpress POST SMTP Account Takeover
   114   auxiliary/admin/http/wp_symposium_sql_injection                          2015-08-18       normal  Yes    WordPress Symposium Plugin SQL Injection
   115   auxiliary/admin/http/wp_wplms_privilege_escalation                       2015-02-09       normal  Yes    WordPress WPLMS Theme Privilege Escalation
   116   auxiliary/admin/http/zyxel_admin_password_extractor                      .                normal  No     ZyXEL GS1510-16 Password Extractor
   117   auxiliary/admin/kerberos/forge_ticket                                    .                normal  No     Kerberos Silver/Golden/Diamond/Sapphire Ticket Forging
   118   auxiliary/admin/kerberos/get_ticket                                      .                normal  No     Kerberos TGT/TGS Ticket Requester
   119   auxiliary/admin/kerberos/inspect_ticket                                  .                normal  No     Kerberos Ticket Inspecting
   120   auxiliary/admin/kerberos/keytab                                          .                normal  No     Kerberos keytab utilities
   121   auxiliary/admin/kerberos/ms14_068_kerberos_checksum                      2014-11-18       normal  No     MS14-068 Microsoft Kerberos Checksum Validation Vulnerability
   122   auxiliary/admin/kerberos/ticket_converter                                .                normal  No     Kerberos ticket converter
   123   auxiliary/admin/ldap/ad_cs_cert_template                                 .                normal  No     AD CS Certificate Template Management
   124   auxiliary/admin/ldap/change_password                                     .                normal  No     Change Password
   125   auxiliary/admin/ldap/ldap_object_attribute                               .                normal  No     LDAP Update Object
   126   auxiliary/admin/ldap/rbcd                                                .                normal  Yes    Role Base Constrained Delegation
   127   auxiliary/admin/ldap/shadow_credentials                                  .                normal  Yes    Shadow Credentials
   128   auxiliary/admin/ldap/vmware_vcenter_vmdir_auth_bypass                    2020-04-09       normal  Yes    VMware vCenter Server vmdir Authentication Bypass
   129   auxiliary/admin/maxdb/maxdb_cons_exec                                    2008-01-09       normal  No     SAP MaxDB cons.exe Remote Command Injection
   130   auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978    2025-06-25       normal  No     Multiple Brother devices authentication bypass via default administrator password generation
   131   auxiliary/admin/misc/sercomm_dump_config                                 2013-12-31       normal  No     SerComm Device Configuration Dump
   132   auxiliary/admin/misc/wol                                                 .                normal  No     UDP Wake-On-Lan (WOL)
   133   auxiliary/admin/motorola/wr850g_cred                                     2004-09-24       normal  No     Motorola WR850G v4.03 Credentials
   134   auxiliary/admin/ms/ms08_059_his2006                                      2008-10-14       normal  No     Microsoft Host Integration Server 2006 Command Execution Vulnerability
   135   auxiliary/admin/mssql/mssql_enum                                         .                normal  No     Microsoft SQL Server Configuration Enumerator
   136   auxiliary/admin/mssql/mssql_enum_domain_accounts                         .                normal  No     Microsoft SQL Server SUSER_SNAME Windows Domain Account Enumeration
   137   auxiliary/admin/mssql/mssql_enum_domain_accounts_sqli                    .                normal  No     Microsoft SQL Server SQLi SUSER_SNAME Windows Domain Account Enumeration
   138   auxiliary/admin/mssql/mssql_enum_sql_logins                              .                normal  No     Microsoft SQL Server SUSER_SNAME SQL Logins Enumeration
   139   auxiliary/admin/mssql/mssql_escalate_dbowner                             .                normal  No     Microsoft SQL Server Escalate Db_Owner
   140   auxiliary/admin/mssql/mssql_escalate_dbowner_sqli                        .                normal  No     Microsoft SQL Server SQLi Escalate Db_Owner
   141   auxiliary/admin/mssql/mssql_escalate_execute_as                          .                normal  No     Microsoft SQL Server Escalate EXECUTE AS
   142   auxiliary/admin/mssql/mssql_escalate_execute_as_sqli                     .                normal  No     Microsoft SQL Server SQLi Escalate Execute AS
   143   auxiliary/admin/mssql/mssql_exec                                         .                normal  No     Microsoft SQL Server Command Execution
   144   auxiliary/admin/mssql/mssql_findandsampledata                            .                normal  No     Microsoft SQL Server Find and Sample Data
   145   auxiliary/admin/mssql/mssql_idf                                          .                normal  No     Microsoft SQL Server Interesting Data Finder
   146   auxiliary/admin/mssql/mssql_ntlm_stealer                                 .                normal  No     Microsoft SQL Server NTLM Stealer
   147   auxiliary/admin/mssql/mssql_ntlm_stealer_sqli                            .                normal  No     Microsoft SQL Server SQLi NTLM Stealer
   148   auxiliary/admin/mssql/mssql_sql                                          .                normal  No     Microsoft SQL Server Generic Query
   149   auxiliary/admin/mssql/mssql_sql_file                                     .                normal  No     Microsoft SQL Server Generic Query from File
   150   auxiliary/admin/mysql/mysql_enum                                         .                normal  No     MySQL Enumeration Module
   151   auxiliary/admin/mysql/mysql_sql                                          .                normal  No     MySQL SQL Generic Query
   152   auxiliary/admin/natpmp/natpmp_map                                        .                normal  No     NAT-PMP Port Mapper
   153   auxiliary/admin/netbios/netbios_spoof                                    .                normal  No     NetBIOS Response Brute Force Spoof (Direct)
   154   auxiliary/admin/networking/arista_config                                 .                normal  No     Arista Configuration Importer
   155   auxiliary/admin/networking/brocade_config                                .                normal  No     Brocade Configuration Importer
   156   auxiliary/admin/networking/cisco_asa_extrabacon                          .                normal  Yes    Cisco ASA Authentication Bypass (EXTRABACON)
   157   auxiliary/admin/networking/cisco_config                                  .                normal  No     Cisco Configuration Importer
   158   auxiliary/admin/networking/cisco_dcnm_auth_bypass                        2020-06-01       normal  Yes    Cisco DCNM auth bypass
   159   auxiliary/admin/networking/cisco_dcnm_download                           2019-06-26       normal  No     Cisco Data Center Network Manager Unauthenticated File Download
   160   auxiliary/admin/networking/cisco_secure_acs_bypass                       .                normal  No     Cisco Secure ACS Unauthorized Password Change
   161   auxiliary/admin/networking/cisco_vpn_3000_ftp_bypass                     2006-08-23       normal  No     Cisco VPN Concentrator 3000 FTP Unauthorized Administrative Access
   162   auxiliary/admin/networking/f5_config                                     .                normal  No     F5 Configuration Importer
   163   auxiliary/admin/networking/juniper_config                                .                normal  No     Juniper Configuration Importer
   164   auxiliary/admin/networking/mikrotik_config                               .                normal  No     Mikrotik Configuration Importer
   165   auxiliary/admin/networking/thinmanager_traversal_delete                  2023-08-17       normal  Yes    ThinManager Path Traversal (CVE-2023-2915) Arbitrary File Delete
   166   auxiliary/admin/networking/thinmanager_traversal_upload                  2023-04-05       normal  Yes    ThinManager Path Traversal (CVE-2023-27855) Arbitrary File Upload
   167   auxiliary/admin/networking/thinmanager_traversal_upload2                 2023-08-17       normal  Yes    ThinManager Path Traversal (CVE-2023-2917) Arbitrary File Upload
   168   auxiliary/admin/networking/ubiquiti_config                               .                normal  No     Ubiquiti Configuration Importer
   169   auxiliary/admin/networking/vyos_config                                   .                normal  No     VyOS Configuration Importer


 and so on.....

1273  auxiliary/server/tftp                                                    .                normal  No     TFTP File Server
   1274  auxiliary/server/webkit_xslt_dropper                                     .                normal  No     Cross Platform Webkit File Dropper
   1275  auxiliary/server/wget_symlink_file_write                                 2014-10-27       normal  No     GNU Wget FTP Symlink Arbitrary Filesystem Access
   1276  auxiliary/server/wpad                                                    .                normal  No     WPAD.dat File Server
   1277  auxiliary/sniffer/psnuffle                                               .                normal  No     pSnuffle Packet Sniffer
   1278  auxiliary/spoof/arp/arp_poisoning                                        1999-12-22       normal  No     ARP Spoof
   1279  auxiliary/spoof/cisco/cdp                                                .                normal  No     Send Cisco Discovery Protocol (CDP) Packets
   1280  auxiliary/spoof/cisco/dtp                                                .                normal  No     Forge Cisco DTP Packets
   1281  auxiliary/spoof/dns/bailiwicked_domain                                   2008-07-21       normal  Yes    DNS BailiWicked Domain Attack
   1282  auxiliary/spoof/dns/bailiwicked_host                                     2008-07-21       normal  Yes    DNS BailiWicked Host Attack
   1283  auxiliary/spoof/dns/compare_results                                      2008-07-21       normal  No     DNS Lookup Result Comparison
   1284  auxiliary/spoof/dns/native_spoofer                                       .                normal  No     Native DNS Spoofer (Example)
   1285  auxiliary/spoof/llmnr/llmnr_response                                     .                normal  No     LLMNR Spoofer
   1286  auxiliary/spoof/mdns/mdns_response                                       .                normal  No     mDNS Spoofer
   1287  auxiliary/spoof/nbns/nbns_response                                       .                normal  No     NetBIOS Name Service Spoofer
   1288  auxiliary/spoof/replay/pcap_replay                                       .                normal  No     Pcap Replay Utility
   1289  auxiliary/sqli/dlink/dlink_central_wifimanager_sqli                      2019-07-06       normal  Yes    D-Link Central WiFiManager SQL injection
   1290  auxiliary/sqli/openemr/openemr_sqli_dump                                 2019-05-17       normal  Yes    OpenEMR 5.0.1 Patch 6 SQLi Dump
   1291  auxiliary/sqli/oracle/dbms_cdc_ipublish                                  2008-10-22       normal  No     Oracle DB SQL Injection via SYS.DBMS_CDC_IPUBLISH.ALTER_HOTLOG_INTERNAL_CSOURCE
   1292  auxiliary/sqli/oracle/dbms_cdc_publish                                   2008-10-22       normal  No     Oracle DB SQL Injection via SYS.DBMS_CDC_PUBLISH.ALTER_AUTOLOG_CHANGE_SOURCE
   1293  auxiliary/sqli/oracle/dbms_cdc_publish2                                  2010-04-26       normal  No     Oracle DB SQL Injection via SYS.DBMS_CDC_PUBLISH.DROP_CHANGE_SOURCE
   1294  auxiliary/sqli/oracle/dbms_cdc_publish3                                  2010-10-13       normal  No     Oracle DB SQL Injection via SYS.DBMS_CDC_PUBLISH.CREATE_CHANGE_SET
   1295  auxiliary/sqli/oracle/dbms_cdc_subscribe_activate_subscription           2005-04-18       normal  No     Oracle DB SQL Injection via SYS.DBMS_CDC_SUBSCRIBE.ACTIVATE_SUBSCRIPTION
   1296  auxiliary/sqli/oracle/dbms_export_extension                              2006-04-26       normal  No     Oracle DB SQL Injection via DBMS_EXPORT_EXTENSION
   1297  auxiliary/sqli/oracle/dbms_metadata_get_granted_xml                      2008-01-05       normal  No     Oracle DB SQL Injection via SYS.DBMS_METADATA.GET_GRANTED_XML
   1298  auxiliary/sqli/oracle/dbms_metadata_get_xml                              2008-01-05       normal  No     Oracle DB SQL Injection via SYS.DBMS_METADATA.GET_XML
   1299  auxiliary/sqli/oracle/dbms_metadata_open                                 2008-01-05       normal  No     Oracle DB SQL Injection via SYS.DBMS_METADATA.OPEN
   1300  auxiliary/sqli/oracle/droptable_trigger                                  2009-01-13       normal  No     Oracle DB SQL Injection in MDSYS.SDO_TOPO_DROP_FTBL Trigger
   1301  auxiliary/sqli/oracle/jvm_os_code_10g                                    2010-02-01       normal  No     Oracle DB 10gR2, 11gR1/R2 DBMS_JVM_EXP_PERMS OS Command Execution
   1302  auxiliary/sqli/oracle/jvm_os_code_11g                                    2010-02-01       normal  No     Oracle DB 11g R1/R2 DBMS_JVM_EXP_PERMS OS Code Execution
   1303  auxiliary/sqli/oracle/lt_compressworkspace                               2008-10-13       normal  No     Oracle DB SQL Injection via SYS.LT.COMPRESSWORKSPACE
   1304  auxiliary/sqli/oracle/lt_findricset_cursor                               2007-10-17       normal  No     Oracle DB SQL Injection via SYS.LT.FINDRICSET Evil Cursor Method
   1305  auxiliary/sqli/oracle/lt_mergeworkspace                                  2008-10-22       normal  No     Oracle DB SQL Injection via SYS.LT.MERGEWORKSPACE
   1306  auxiliary/sqli/oracle/lt_removeworkspace                                 2008-10-13       normal  No     Oracle DB SQL Injection via SYS.LT.REMOVEWORKSPACE
   1307  auxiliary/sqli/oracle/lt_rollbackworkspace                               2009-05-04       normal  No     Oracle DB SQL Injection via SYS.LT.ROLLBACKWORKSPACE
   1308  auxiliary/voip/asterisk_login                                            .                normal  No     Asterisk Manager Login Utility
   1309  auxiliary/voip/cisco_cucdm_call_forward                                  .                normal  No     Viproy CUCDM IP Phone XML Services - Call Forwarding Tool
   1310  auxiliary/voip/cisco_cucdm_speed_dials                                   .                normal  No     Viproy CUCDM IP Phone XML Services - Speed Dial Attack Tool
   1311  auxiliary/voip/sip_deregister                                            .                normal  No     SIP Deregister Extension
   1312  auxiliary/voip/sip_invite_spoof                                          .                normal  No     SIP Invite Spoof
   1313  auxiliary/voip/telisca_ips_lock_control                                  2015-12-17       normal  No     Telisca IPS Lock Cisco IP Phone Control
   1314  auxiliary/vsploit/malware/dns/dns_mariposa                               .                normal  No     VSploit Mariposa DNS Query Module
   1315  auxiliary/vsploit/malware/dns/dns_query                                  .                normal  No     VSploit DNS Beaconing Emulation
   1316  auxiliary/vsploit/malware/dns/dns_zeus                                   .                normal  No     VSploit Zeus DNS Query Module
   1317  auxiliary/vsploit/pii/email_pii                                          .                normal  No     VSploit Email PII
   1318  auxiliary/vsploit/pii/web_pii                                            .                normal  No     VSploit Web PII

msf > 

```
