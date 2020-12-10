if __name__ == "__main__":
    print('This script contains only functions for use in other scripts. Do not call it directly.')
    exit(1)

import sys
import time
import subprocess
import hashlib
import os

#housekeeping - modify these if you have path issues or want to test this on another OS
vboxmanage_bin = "vboxmanage"
shell_bin = '/usr/bin/bash'
shell_c = '-c'

remote_timeout = 15

def host_cmd(cmd_str, data_logger_instance=None, timeout=remote_timeout):
    """Executes a command

    Args:
    str(cmd_str): command to execute on the local host
    
    Return:
    [int(returncode), 'stdout', 'stderr']
    """

    try:
        result = subprocess.run([shell_bin, shell_c, cmd_str], capture_output=True, timeout=timeout, text=True)
    except:
        e = sys.exc_info()[0]
        if data_logger_instance != None:
            data_logger_instance.log(sys.argv[0], 'host_cmd Error: ' + e, 'error')
        return [1,'',str(e)]
    return [result.returncode, result.stdout, result.stderr]

def host_list_vms():
    """Gets list of VMs

    Return:
    ['VM Name',...]
    """

    result = host_cmd(vboxmanage_bin + ' list vms --sorted | cut -d\'"\' -f 2')
    if result[0] == 0:
        return result[1].split('\n')
    else:
        return []

def host_list_vm_snapshots(vm):
    """Gets list of snapshots for a VM
    Args:
    str(vm): VM name or UUID

    Return:
    ['snapshot name', ...]
    """

    result = host_cmd(vboxmanage_bin + ' snapshot ' + vm + ' list --machinereadable | cut -d\'"\' -f 2')

    if result[0] == 0:
        return result[1].split('\n')
    else:
        return []


def vm_state(vm):
    """Gets state of VM

    Args:
    str(vm): VM name or UUID

    Return:
    str(State): 'running' or 'restoring' or 'stopped', ...
    """

    result = host_cmd(vboxmanage_bin + ' showvminfo "' + vm + '" --details | grep -e "State:" | tr -s " " | cut -d" " -f 2')
    return result[1]

def vm_run_exe(vm, username, password, remote_exe, remote_params=[], timeout=remote_timeout, data_logger_instance=None):
    """Execute file/command on guest OS and wait for the program to exit returning std output and input

    Args:
    str(vm): VM name or UUID
    str(username): guest OS username
    str(password): guest OS password
    str(remote_exe): full path file on guest OS
    [str(remote_params),...]: parameters as list to pass to remote_exe command
    int(timeout: timeout period for command to expire on the VM defaults to remote_time
    data_logger(data_logger_instance): name of a data logger instance (dl, import data_logger as dl)
    
    Return:
    [int(returncode), str(stdout), str(stderr)]
    """

    remote_exe = remote_exe.replace('\\','\\\\')
    if len(remote_params) > 0:
        if data_logger_instance != None:
            data_logger_instance.log(vm, ' - Executing "' + remote_exe + '" with params ' + str(remote_params) + '.', 'debug')
        vboxmanage_cmd_array = [vboxmanage_bin, "guestcontrol", '"' + vm + '"', "--username", username, "--password", password, "run", "--exe", "\"" + remote_exe + "\"", " -- " + " ".join(remote_params)]
    else:
        if data_logger_instance != None:
            data_logger_instance.log(vm, 'Executing "' + remote_exe + '" with no params.', 'debug')
        vboxmanage_cmd_array = [vboxmanage_bin, "guestcontrol", '"' + vm + '"', "--username", username, "--password", password, "run", "--exe", "\"" + remote_exe + "\""]
    if data_logger_instance != None:
        data_logger_instance.log(vm, 'Executing command locally: ' + ' '.join(vboxmanage_cmd_array))

    results = host_cmd(' '.join(vboxmanage_cmd_array), timeout=timeout)

    if results[0] == 0:
        if data_logger_instance != None:
            data_logger_instance.log(vm, 'File executed successfully.', 'debug')
    else:
        if data_logger_instance != None:
            data_logger_instance.log(vm, 'File executed.', 'debug')
    return results

def vm_run_ps_cmds(vm, username, password, ps_commands, timeout=remote_timeout, remote_path='C:\\\\', data_logger_instance=None):
    """Execute powershell commands on guest OS and wait for the program to exit returning std output and input

    Args:
    str(vm): VM name or UUID
    str(username): guest OS username
    str(password): guest OS password
    str(ps_commands): powershell commands
    int(timeout): timeout period for command to expire on the VM defaults to remote_time
    str(remote_path): remote path to transfer the executable to and run it from, double escaped
    
    Return:
    [int(returncode), str(stdout), str(stderr)]
    """
    tmp_file_name = "tmp" + str(hashlib.md5(str.encode(vm + ps_commands)).hexdigest()) + ".ps1"
    tmp_file = open('./tmp/' + tmp_file_name,'w')
    tmp_file.write(ps_commands)
    tmp_file.close()
    
    fail_count = 0
    while vm_file_stat(vm, username, password, remote_path + tmp_file_name, data_logger_instance=data_logger_instance)[0] != 0 and fail_count < 10:
        vm_file_put(vm, username,password, './tmp/' + tmp_file_name, remote_path + tmp_file_name, data_logger_instance)
        fail_count = fail_count + 1
        time.sleep(.5)
    
    
    tmp_return = vm_run_exe(vm, username,password,"cmd.exe",["/c", "\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe -inputformat none -ExecutionPolicy Bypass -File " + remote_path + tmp_file_name + "\""],timeout=timeout, data_logger_instance=data_logger_instance)
    os.remove('./tmp/' + tmp_file_name)
    return tmp_return



def vm_start(vm, ui='separate', data_logger_instance=None):
    """Start a vm

    Args:
    str(vm): VM name or UUID
    str(ui): start a virtual machine with 'gui', 'headless', or 'separate'
    data_logger(data_logger_instance): name of a data logger instance (dl, import data_logger as dl)
    
    Return:
    int(returncode)
    """
    if data_logger_instance != None:
            data_logger_instance.log(vm, 'Starting VM', 'debug')
    result = host_cmd(vboxmanage_bin + ' startvm "' + vm + '" --type ' + ui)
    if result[0] == 0:
        bounce_count = 0
        time.sleep(.5)
        while 'running' not in vm_state(vm):
            time.sleep(1)
            if bounce_count > 20:
                data_logger_instance.log(vm, 'Error while starting: ' + result[2], 'error')
                break
            bounce_count = bounce_count + 1
            if data_logger_instance != None:
                data_logger_instance.log(vm, 'run-wait...', 'debug')

        if data_logger_instance != None:
            data_logger_instance.log(vm, 'VM started')
    else:
        if data_logger_instance != None:
            data_logger_instance.log(vm, 'Error while starting: ' + result[2], 'error')
    return result[0]


def vm_stop(vm, data_logger_instance=None):
    """Stop VM

    Args:
    str(vm): VM name or UUID
    data_logger(data_logger_instance): name of a data logger instance (dl, import data_logger as dl)
    
    Return:
    int(returncode)
    """

    if data_logger_instance != None:
            data_logger_instance.log(vm, 'Stopping VM', 'debug')
    result = host_cmd(vboxmanage_bin + ' controlvm "' + vm + '" poweroff')
    if result[0] == 0:
        bounce_counter2 = 0
        bounce_counter = 0
        time.sleep(.5)
        while 'running' in vm_state(vm):
            time.sleep(1)
            if data_logger_instance != None:
                data_logger_instance.log(vm, 'stop-wait...', 'debug')
            if bounce_counter > 3:
                data_logger_instance.log(vm, vm + ' stop-wait...killing again...', 'info')
                print('killing ' + vm + ' again...')
                result = host_cmd(vboxmanage_bin + ' controlvm "' + vm + '" poweroff')
                bounce_counter = 0
            bounce_counter = bounce_counter + 1
            bounce_counter2 = bounce_counter2 + 1
            if bounce_counter2 > 10:
                return result[2]
        if data_logger_instance != None:
            data_logger_instance.log(vm, 'VM stopped')
    else:
        if 'is not currently running' in result[2]:
            if data_logger_instance != None:
                data_logger_instance.log(vm, 'VM already stopped', 'debug')
                data_logger_instance.log(vm, 'VM stopped')
        else:
            if data_logger_instance != None:
                data_logger_instance.log(vm, 'Error while stopping VM: ' + result[2], 'error')
    return result[0]


def vm_snapshot_restore(vm, snapshot, data_logger_instance=None):
    """Restore snapshot for VM

    Args:
    str(vm): VM name or UUID
    str(snapshot): snapshot name or UUID
    data_logger(data_logger_instance): name of a data logger instance (dl, import data_logger as dl)
    
    Return:
    int(returncode)
    """

    if snapshot == 'restorecurrent':
        if data_logger_instance != None:
            data_logger_instance.log(vm, 'Restoring VM to snapshot ' + snapshot, 'debug')
        result = host_cmd(vboxmanage_bin + ' snapshot "' + vm + '" restorecurrent')
        if result[0] == 0:
            time.sleep(.5)
            while 'restoring' in vm_state(vm):
                time.sleep(.5)
                if data_logger_instance != None:
                    data_logger_instance.log(vm, snapshot + ' - restore wait: ' + vm_state(vm), 'debug')
                pass
            if data_logger_instance != None:
                data_logger_instance.log(vm, 'Restored VM to snapshot ' + snapshot)
        else:
            if data_logger_instance != None:
                data_logger_instance.log(vm, 'Error restoring VM to snapshot ' + snapshot + ':' + result[2], 'error')
    else:
        if data_logger_instance != None:
            data_logger_instance.log(vm, 'Restoring VM to snapshot ' + snapshot, 'debug')
        result = host_cmd(vboxmanage_bin + ' snapshot "' + vm + '" restore "' + snapshot + '"')
        if result[0] == 0:
            time.sleep(.5)
            while 'restoring' in vm_state(vm):
                time.sleep(.5)
                if data_logger_instance != None:
                    data_logger_instance.log(vm, snapshot + ' - restore wait: ' + vm_state(vm), 'debug')
                pass
            if data_logger_instance != None:
                data_logger_instance.log(vm, 'Restored VM to snapshot ' + snapshot)
        else:
            if data_logger_instance != None:
                data_logger_instance.log(vm, 'Error restoring VM to snapshot ' + snapshot + ':' + result[2], 'error')
    return result[0]


def vm_file_stat(vm, username, password, remote_file, data_logger_instance=None):
    """Get information about file on guest OS

    Args:
    str(vm): VM name or UUID
    str(username): guest OS username
    str(password): guest OS password
    str(remote_file): path to file on guest OS
    data_logger(data_logger_instance): name of a data logger instance (dl, import data_logger as dl)
    
    Return:
    [int(returncode), str(stdout), str(stderr)]
    """

    remote_file = remote_file.replace('\\', '\\\\')

    result = host_cmd(vboxmanage_bin + ' guestcontrol "' + vm + '" --username ' + username + ' --password ' + password + ' stat ' + remote_file,timeout=4)
    if result[0] == 0:
        if data_logger_instance != None:
                data_logger_instance.log(vm, 'File (' + remote_file + ') exists', 'debug')
    else:
        if data_logger_instance != None:
                data_logger_instance.log(vm, 'Error while checking for file (' + remote_file + '): ' + result[2], 'debug')
    return result[0], result[1], result[2]


def vm_file_put(vm, username, password, local_file, remote_file, data_logger_instance=None):
    """Upload file to VM

    Args:
    str(vm): VM name or UUID
    str(username): guest OS username
    str(password): guest OS password
    str(local_file): path to local file on host OS
    str(remote_file): path to file on guest OS
    data_logger(data_logger_instance): name of a data logger instance (dl, import data_logger as dl)
    
    Return:
    [int(returncode), str(stdout), str(stderr)]
    """
    local_file = local_file.replace('\\', '\\\\')
    remote_file = remote_file.replace('\\', '\\\\')

    if data_logger_instance != None:
        data_logger_instance.log(vm, 'Uploading (' + local_file + ') as (' + remote_file + ') to VM', 'debug')
    result = host_cmd(vboxmanage_bin + ' guestcontrol "' + vm + '" --username ' + username + ' --password ' + password + ' copyto "' + local_file + '" "' + remote_file + '"')
    if result[0] == 0:
        if data_logger_instance != None:
            data_logger_instance.log(vm, 'File (' + local_file + ') uploaded')
    else:
        if data_logger_instance != None:
            data_logger_instance.log(vm, 'Error while uploading file (' + local_file + '): ' + result[2], 'error')
    
    return result[0], result[1], result[2]


def vm_file_get(vm, username, password, local_file, remote_file, data_logger_instance=None):
    """Retrieve file from VM

    Args:
    str(vm): VM name or UUID
    str(username): guest OS username
    str(password): guest OS password
    str(local_file): path to local file on host OS
    str(remote_file): path to file on guest OS
    data_logger(data_logger_instance): name of a data logger instance (dl, import data_logger as dl)
    
    Return:
    [int(returncode), str(stdout), str(stderr)]
    """
    local_file = local_file.replace('\\', '\\\\')
    remote_file = remote_file.replace('\\', '\\\\')

    if data_logger_instance != None:
        data_logger_instance.log(vm, 'Retrieving file (' + remote_file + ') as (' + local_file + ')', 'debug')
    result = host_cmd(vboxmanage_bin + ' guestcontrol "' + vm + '" --username ' + username + ' --password ' + password + ' copyfrom "' + remote_file + '" "' + local_file + '"')
    if result[0] == 0:
        if data_logger_instance != None:
            data_logger_instance.log(vm, 'File (' + remote_file + ') retrieved')
    else:
        if data_logger_instance != None:
            data_logger_instance.log(vm, 'Error while retrieving file (' + remote_file + '): ' + result[2], 'error')
    return result[0], result[1], result[2]