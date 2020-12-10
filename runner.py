import sys
import json
import gc
import vm_control
import time
import threading
import data_logger as dl
import vt_builder

#bring in config
try:
    configs = json.load(open('load_runner.json', 'r'))
except:
    print('epic fail - something wrong with config file', file=sys.stderr)
    exit(1)

#start logger
if dl.init() == False:
    print("Failed to initialize logger.", file=sys.stderr)
    exit(1)


#get a list of the VMs
vmlist = vm_control.host_list_vms()

#loop through list of VMs looking for appropriate snapshot and create list of in-play VMs
tmplist = []
snapshot_name = 'running-user'
for vm in vmlist:
    if snapshot_name in vm_control.host_list_vm_snapshots(vm):
        tmplist.append(vm)
vmlist = tmplist
tmplist = None
dl.log(sys.argv[0], 'Experimental VMs: ' + str(vmlist))

#set up users
[reg_user, reg_pass] = configs['global_user_creds']
[adm_user, adm_pass] = configs['global_admin_creds']

#main function called in each thread
def worker_do_work(vm, snapshot, reg_username, reg_password, adm_username, adm_password, malware_info):
    #import logger within thread for thread-safe logging
    import data_logger as thread_dl

    #get malware particulars
    malware_file_local = malware_info['local_filename']
    malware_file_remote = malware_info['sha256'] + '.' + malware_info['additional_info']['exiftool']['FileTypeExtension']

    #initialize the logger within the thread
    if thread_dl.init(print_log_sinks=['error','info']) == False:
        print("Failed to initialize logger.")
        exit(1)

    #stop the VM - safe to ensure VM in known state
    vm_control.vm_stop(vm,data_logger_instance=thread_dl)

    #restore the VM to the snapshot - safe to ensure VM in known GOOD state
    vm_control.vm_snapshot_restore(vm, snapshot, data_logger_instance=thread_dl)

    #start the VM
    vm_control.vm_start(vm, ui='headless',data_logger_instance=thread_dl)
    
    #clear out the logs
    vm_control.vm_run_ps_cmds(vm,adm_username,adm_password,'wevtutil cl "Microsoft-Windows-AppLocker/EXE and DLL"; wevtutil cl "Security"; wevtutil cl "Application"',data_logger_instance=thread_dl)
    
    #transfer the badness
    vm_control.vm_file_put(vm,adm_username,adm_password,malware_file_local,'c:\\Users\\user\\Desktop\\' + malware_file_remote, data_logger_instance=thread_dl)
    
    time.sleep(1)

    #run the badness
    if str(malware_info['additional_info']['exiftool']['FileTypeExtension']).lower() == 'exe': #run executables
        mw_result = vm_control.vm_run_exe(vm,reg_username,reg_password,'c:\\Users\\user\\Desktop\\' + malware_file_remote, data_logger_instance=thread_dl)
        #error comes back too fast, files usually still run
        if str(mw_result[2]).find("Unresolved (unknown) host platform error.") != -1:
            time.sleep(2)
    elif str(malware_info['additional_info']['exiftool']['FileTypeExtension']).lower() == 'dll': #run libraries
        mw_result = vm_control.vm_run_ps_cmds(vm,reg_username,reg_password,'C:\\Windows\\System32\\regsvr32.exe /s c:\\Users\\user\\Desktop\\' + malware_file_remote + '\n$lle = $?\nif($lle -ne 0){Write-Host $lle $Error[0].Exception.Message}\n[Environment]::Exit($lle)', remote_path='c:\\\\Users\\\\user\\\\Desktop\\\\', timeout=15)
    else: #best effort run everything else
        thread_dl.log(vm + '_' + snapshot + '_' + malware_file_remote, ["Unkown file extension, attempting to run anyways"])
        mw_result = vm_control.vm_run_exe(vm,reg_username,reg_password,'c:\\Users\\user\\Desktop\\' + malware_file_remote, data_logger_instance=thread_dl)


    #get applocker audit logs
    applocker_logs = vm_control.vm_run_ps_cmds(vm,adm_username,adm_password,'Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" | Where-Object{\n$_.Message.ToUpper().Contains("' + malware_file_remote + '".ToUpper())} | ForEach-Object{\n$stopped=$FALSE; if($_.ID -eq 8004){\n$stopped = $TRUE}; @{ "id" =  $_.ID; "time" = $_.TimeCreated.ToString(); "src" = $_.ProviderName ; "msg" = $_.Message; "stopped" = $stopped} } | ConvertTo-Json',data_logger_instance=thread_dl)
    #try again if retrieval looks like failure
    if applocker_logs[0] != 0:
        applocker_logs = vm_control.vm_run_ps_cmds(vm,adm_username,adm_password,'Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" | Where-Object{\n$_.Message.ToUpper().Contains("' + malware_file_remote + '".ToUpper())} | ForEach-Object{\n$stopped=$FALSE; if($_.ID -eq 8004){\n$stopped = $TRUE}; @{ "id" =  $_.ID; "time" = $_.TimeCreated.ToString(); "src" = $_.ProviderName ; "msg" = $_.Message; "stopped" = $stopped} } | ConvertTo-Json',data_logger_instance=thread_dl)
    #attempt to import logs in JSON format (should be JSON if all went well...)
    try:
        tmpjson = json.loads(applocker_logs[1])
        applocker_logs[1] = tmpjson
    except:
        pass
    
    #get security audit logs (process info)
    security_logs = vm_control.vm_run_ps_cmds(vm,adm_username,adm_password,'Get-WinEvent -LogName "Security" | Where-Object{\n($_.ID -eq 4688 -or $_.ID -eq 4689) -and ($_.Message.ToUpper().Contains("' + malware_file_remote + '".ToUpper()) -or $_.Message.ToUpper().Contains("REGSVR32".ToUpper()) )} | ForEach-Object{\n @{ "id" =  $_.ID; "time" = $_.TimeCreated.ToString(); "src" = $_.ProviderName ; "msg" = $_.Message} } | ConvertTo-Json',data_logger_instance=thread_dl)
    #try again if retrieval looks like failure
    if security_logs[0] != 0:
        security_logs = vm_control.vm_run_ps_cmds(vm,adm_username,adm_password,'Get-WinEvent -LogName "Security" | Where-Object{\n($_.ID -eq 4688 -or $_.ID -eq 4689) -and ($_.Message.ToUpper().Contains("' + malware_file_remote + '".ToUpper()) -or $_.Message.ToUpper().Contains("REGSVR32".ToUpper()) )} | ForEach-Object{\n @{ "id" =  $_.ID; "time" = $_.TimeCreated.ToString(); "src" = $_.ProviderName ; "msg" = $_.Message} } | ConvertTo-Json',data_logger_instance=thread_dl)
    #attempt to import logs in JSON format (should be JSON if all went well...)
    try:
        tmpjson = json.loads(security_logs[1])
        security_logs[1] = tmpjson
    except:
        pass

    #get application audit logs (PCMATIC)
    application_logs = vm_control.vm_run_ps_cmds(vm,adm_username,adm_password,'Get-EventLog -LogName Application | Where-Object{\n $_.InstanceId -eq 1 -and $_.Message.ToUpper().Contains("' + malware_file_remote + '".ToUpper())} | ForEach-Object {\n @{ "id" =  $_.InstanceId; "time" = $_.TimeGenerated.ToString(); "src" = $_.Source ; "msg" = $_.Message; "stopped" = $TRUE} } | ConvertTo-Json',data_logger_instance=thread_dl)
    #try again if retrieval looks like failure
    if application_logs[0] != 0:
        application_logs = vm_control.vm_run_ps_cmds(vm,adm_username,adm_password,'Get-EventLog -LogName Application | Where-Object{\n $_.InstanceId -eq 1 -and $_.Message.ToUpper().Contains("' + malware_file_remote + '".ToUpper())} | ForEach-Object {\n @{ "id" =  $_.InstanceId; "time" = $_.TimeGenerated.ToString(); "src" = $_.Source ; "msg" = $_.Message; "stopped" = $TRUE} } | ConvertTo-Json',data_logger_instance=thread_dl)
    #attempt to import logs in JSON format (should be JSON if all went well...)
    try:
        tmpjson = json.loads(application_logs[1])
        application_logs[1] = tmpjson
    except:
        pass


    #end the vm
    vm_control.vm_stop(vm,data_logger_instance=thread_dl)
    
    #log it all
    thread_dl.log(vm + '_' + snapshot + '_' + malware_file_remote, [malware_info, mw_result, applocker_logs, security_logs, application_logs], 'data')
    
    #attempt to kill the thread
    thread_dl.close()

    #return - mongo doesn't always close cleanly even though the thread SHOULD be closed by the above command
    return




sample_count = 0
skipnum = configs['skip_samples']

#loop for malware - a ransomware sample constitutes a trial
while configs['num_samples'] == None or sample_count < configs['num_samples']:
    #get sample
    malware_info = vt_builder.get_malware_info()
    #make sure we aren't done
    if malware_info == False:
        print("Out of samples at " + str(sample_count) + " samples.")
        break
    else:
        sample_count = sample_count + 1
    
    #make sure we know how many valid samples we've been through
    bottom_num = 0
    if configs['num_samples'] != None and configs['num_samples'] < vt_builder.get_malware_num():
        bottom_num = configs['num_samples']
    else:
        bottom_num = vt_builder.get_malware_num()
    
    dl.log(sys.argv[0], 'Trial - ' + malware_info['local_filename'] + ' - started. (' + str(sample_count) + ' of ' + str(bottom_num) + ')')
    #check to see if we need to skip samples (good for restarting/debugging from errors)
    if (skipnum >= sample_count):
        dl.log(sys.argv[0],'Trial - ' + malware_info['local_filename'] + ' - skipped. (' + str(sample_count) + ' of ' + str(bottom_num) + ')')
        next
    else:

        #loop for managing threads
        for vm in vmlist:
            try:
                t = threading.Thread(target=worker_do_work, args=(vm, snapshot_name, reg_user, reg_pass, adm_user, adm_pass, malware_info))
                t.name = vm + '_' + snapshot_name + '_' + malware_info['local_filename']
                t.start()
                time.sleep(1)
            except (KeyboardInterrupt, SystemExit):
                raise
        sleep_count = 0
        threadcount = 100
        while threadcount > 0:
            sleep_count = sleep_count + 1
            time.sleep(1)
            threadnames = []
            for hungthread in threading.enumerate():
                if hungthread.name != 'MainThread' and hungthread.name != 'pymongo_server_monitor_thread' and hungthread.name != 'pymongo_kill_cursors_thread':
                    threadnames.append(hungthread.name)
            threadcount = len(threadnames)
            if sleep_count > 95:
                print('Threads after ' + str(sleep_count) +' seconds: ' + str(threadcount) + ' ' + str(threadnames) )
                gc.collect()

        dl.log(sys.argv[0],'Trial - ' + malware_info['local_filename'] + ' - completed. (' + str(sample_count) + ' of ' + str(bottom_num) + ')')

#export the mongo logs
vm_control.host_cmd('mongoexport -d logger -c info --jsonArray --pretty -o ./loggerdump/loggerdump-info-`date +"%m%d%y-%H%M%S"`.json')
vm_control.host_cmd('mongoexport -d logger -c debug --jsonArray --pretty -o ./loggerdump/loggerdump-debug-`date +"%m%d%y-%H%M%S"`.json')
vm_control.host_cmd('mongoexport -d logger -c error --jsonArray --pretty -o ./loggerdump/loggerdump-error-`date +"%m%d%y-%H%M%S"`.json')
mongo_export = vm_control.host_cmd('mongoexport -d logger -c data --jsonArray --pretty -o ./loggerdump/loggerdump-data-`date +"%m%d%y-%H%M%S"`.json')
print(mongo_export[2])

#kill the DB
#print(vm_control.host_cmd('mongo logger --eval "printjson(db.dropDatabase())"'))