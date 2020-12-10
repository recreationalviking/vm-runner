import sys
import json
import os
import math

#function from stack overflow https://stackoverflow.com/questions/5194057/better-way-to-convert-file-sizes-in-python
def convert_size(size_bytes):
   if size_bytes == 0:
       return "0B"
   size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
   i = int(math.floor(math.log(size_bytes, 1024)))
   p = math.pow(1024, i)
   s = round(size_bytes / p, 2)
   return "%s %s" % (s, size_name[i])

#ensure we have the right arguments
if len(sys.argv) != 2:
    print('Wrong number of arguments.\ndata_parse.py <filename.json>', file=sys.stderr)
    exit(1)
#make sure one is the file
if not os.path.exists(sys.argv[1]):
    print('Invald file: ' + sys.argv[1], file=sys.stderr)
    exit(1)

data_blob = None
try:
    #attempt to open the file
    data_blob = json.load(open(sys.argv[1], 'r'))
except:
    print('Something went wrong loading the json blob.', file=sys.stderr)
    exit(1)

parsed_blob = {}

#loop to run through events in log blob
for event in data_blob:
    data_keys = event.keys()
    #look for necessary keys
    if 'identifier' not in data_keys or 'data' not in data_keys:
        print('epic fail')
        next
    #split the identifier from the logs
    split_comps = str(event['identifier']).split('_', 4)
    split_comps.append(None)
    #set up for file extension and file size
    if len(str(split_comps[3]).split('.', 2)) == 2:
        (split_comps[3],split_comps[4]) = str(split_comps[3]).split('.', 2)
    else:
        split_comps[3] = str(split_comps[3]).split('.', 2)
    #set the file extension and file size if they aren't already there
    if split_comps[3] not in parsed_blob:
        parsed_blob[split_comps[3]] = {}
        if 'size' in event['data'][0]:
            parsed_blob[split_comps[3]]['filesize'] = convert_size(int(event['data'][0]['size']))
        else:
            parsed_blob[split_comps[3]]['filesize'] = None
        parsed_blob[split_comps[3]]['filetype'] = split_comps[4]
    #create hash for trial
    if split_comps[0] not in parsed_blob[split_comps[3]]:
        parsed_blob[split_comps[3]][split_comps[0]] = {}
    #make a trial fail status
    if 'fail_status' not in parsed_blob[split_comps[3]][split_comps[0]]:
        parsed_blob[split_comps[3]][split_comps[0]]['fail_status'] = ''
    #pull in AV results
    if 'av_results' not in parsed_blob[split_comps[3]]:
        parsed_blob[split_comps[3]]['av_results'] = {}
        for scankey in event['data'][0]['scans'].keys():
            parsed_blob[split_comps[3]]['av_results'][scankey] = event['data'][0]['scans'][scankey] = event['data'][0]['scans'][scankey]['detected']

    #check control
    if split_comps[1] == 'control':
        #handles issues with executable compatibility
        if str(event['data'][1][2]).find('is not an executable format on guest') != -1:
            parsed_blob[split_comps[3]][split_comps[0]]['fail_status'] = str(parsed_blob[split_comps[3]][split_comps[0]]['fail_status']) + '|(control) Non-executabled.'
            parsed_blob[split_comps[3]][split_comps[0]]['control_status'] = 'File not executed'
            parsed_blob[split_comps[3]][split_comps[0]]['applocker_status'] = None
            parsed_blob[split_comps[3]][split_comps[0]]['pcmatic_status'] = None
        #handles failed transfer issue
        elif str(event['data'][1][2]).find('failed: No such file or directory') != -1:
            parsed_blob[split_comps[3]][split_comps[0]]['fail_status'] = str(parsed_blob[split_comps[3]][split_comps[0]]['fail_status']) + '|(control) Transfer failed.'
            parsed_blob[split_comps[3]][split_comps[0]]['control_status'] = 'File not executed'
            parsed_blob[split_comps[3]][split_comps[0]]['applocker_status'] = None
            parsed_blob[split_comps[3]][split_comps[0]]['pcmatic_status'] = None
        #handle failed/hung box
        elif event['data'][1][0] != 0 and (event['data'][1][0] + event['data'][2][0] + event['data'][3][0] + event['data'][4][0]) > 2:
            parsed_blob[split_comps[3]][split_comps[0]]['fail_status'] = str(parsed_blob[split_comps[3]][split_comps[0]]['fail_status']) + '|(control) Too many failures in execution or log gathering (>3/4 fails).'
            parsed_blob[split_comps[3]][split_comps[0]]['control_status'] = 'File not executed'
            parsed_blob[split_comps[3]][split_comps[0]]['applocker_status'] = None
            parsed_blob[split_comps[3]][split_comps[0]]['pcmatic_status'] = None
        #handles standard file executed
        elif (event['data'][3][0] == 0 and event['data'][3][1] != None) or (event['data'][2][0] == 0 and event['data'][2][1] != None):
            parsed_blob[split_comps[3]][split_comps[0]]['control_status'] = 'File executed'
        #deal with unrecognized events
        else:
            parsed_blob[split_comps[3]][split_comps[0]]['control_status'] = 'Unrecognized events: ' + str(event['data'][1][2])
        
        #check for DLLs that don't have adequate permissions
        if str(parsed_blob[split_comps[3]]['filetype']).lower().find('dll') != -1 and event['data'][3][0] == 0:
            if isinstance(event['data'][3][1], list):
                for evt in event['data'][3][1]:
                    if evt['id'] == 4689 and str(evt['msg']).find('Exit Status:\t0x3') != -1:
                        parsed_blob[split_comps[3]][split_comps[0]]['control_status'] = 'File not executed'
                        parsed_blob[split_comps[3]][split_comps[0]]['applocker_status'] = None
                        parsed_blob[split_comps[3]][split_comps[0]]['pcmatic_status'] = None
    
    #check applocker
    elif split_comps[1] == 'AL':
        isstopped = False
        nexe = False
        #handles issue where bin is never transferred successfully
        if str(event['data'][1][2]).find('failed: No such file or directory') != -1:
            parsed_blob[split_comps[3]][split_comps[0]]['fail_status'] = str(parsed_blob[split_comps[3]][split_comps[0]]['fail_status']) + '|(applocker) Transfer failed.'
            nexe = True
        #handles issue where crash occurs in virtualbox
        elif str(event['data'][1][2]).find('Unresolved (unknown) host platform error.') != -1 and event['data'][2][0] == 0 and isinstance(event['data'][2][1], str) and event['data'][2][1] == "":
            parsed_blob[split_comps[3]][split_comps[0]]['fail_status'] = str(parsed_blob[split_comps[3]][split_comps[0]]['fail_status']) + '|(applocker) Timeout on execution followed by successful but no data returned on logs.'
            nexe = True
        #handles non-executables
        elif str(event['data'][1][2]).find('is not an executable format on guest') != -1:
            parsed_blob[split_comps[3]][split_comps[0]]['fail_status'] = str(parsed_blob[split_comps[3]][split_comps[0]]['fail_status']) + '|(applocker) Non-executable.'
            nexe = True
        #handles instability failures
        elif event['data'][3][0] != 0 and (event['data'][1][0] + event['data'][2][0] + event['data'][3][0] + event['data'][4][0]) > 2:
            parsed_blob[split_comps[3]][split_comps[0]]['fail_status'] = str(parsed_blob[split_comps[3]][split_comps[0]]['fail_status']) + '|(applocker) Too many failures in execution or log gathering (>3/4 fails).'
            nexe = True
        else:
            #ensure the control executed
            if 'control_status' in parsed_blob[split_comps[3]][split_comps[0]] and parsed_blob[split_comps[3]][split_comps[0]]['control_status'] == 'File not executed':
                nexe = True
            #case where a single log entry comes back (usually when process is created and never stopped)
            elif isinstance(event['data'][2][1], dict):
                if 'stopped' in event['data'][2][1].keys():
                    if event['data'][2][1]['stopped'] == True:
                        isstopped = True
            #case where multiple entries come back (usually process created, but stopped)
            elif isinstance(event['data'][2][1], list):
                for allog in event['data'][2][1]:
                    if 'stopped' in allog.keys():
                        if allog['stopped'] == True:
                            isstopped = True
            #unknown case, log verbosely
            elif event['data'][2][0] != 0:
                pass #print('Unrecognized output: ' + str(event['data'][2][0]) + ' : ' + event['data'][2][2])
            
        #check for specific error in return code (edge case where applocker hasn't logged yet or fetch fails)
        if isstopped == False and nexe == False:
            for allog in event['data'][3][1]:
                if isinstance(allog, dict) and 'msg' in allog.keys() and 'id' in allog.keys() and allog['id'] == 4689:
                    if str(allog['msg']).find('C0000364') != -1:
                        isstopped = True
        if isstopped:
            parsed_blob[split_comps[3]][split_comps[0]]['applocker_status'] = 'Execution stopped'
        else:
            parsed_blob[split_comps[3]][split_comps[0]]['applocker_status'] = 'Execution not stopped'
        
        if nexe:
            parsed_blob[split_comps[3]][split_comps[0]]['control_status'] = 'File not executed'
            parsed_blob[split_comps[3]][split_comps[0]]['applocker_status'] = None
            parsed_blob[split_comps[3]][split_comps[0]]['pcmatic_status'] = None
            

    #check pcmatic
    elif split_comps[1] == 'PCM':
        isstopped = False
        #handles issue where bin is never transferred successfully
        if str(event['data'][1][2]).find('failed: No such file or directory') != -1:
            parsed_blob[split_comps[3]][split_comps[0]]['fail_status'] = str(parsed_blob[split_comps[3]][split_comps[0]]['fail_status']) + '|(pcm) Transfer failed.'
            nexe = True
        #handles issue where crash occurs in virtualbox
        elif str(event['data'][1][2]).find('Unresolved (unknown) host platform error.') != -1 and event['data'][2][0] == 0 and isinstance(event['data'][2][1], str) and event['data'][2][1] == "":
            parsed_blob[split_comps[3]][split_comps[0]]['fail_status'] = str(parsed_blob[split_comps[3]][split_comps[0]]['fail_status']) + '|(pcm) Timeout on execution followed by successful but no data returned on logs.'
            nexe = True
        #handles non-executables
        elif str(event['data'][1][2]).find('is not an executable format on guest') != -1:
            parsed_blob[split_comps[3]][split_comps[0]]['fail_status'] = str(parsed_blob[split_comps[3]][split_comps[0]]['fail_status']) + '|(pcm) Non-executable.'
            nexe = True
        #handles instability failures
        elif event['data'][4][0] != 0 and (event['data'][1][0] + event['data'][2][0] + event['data'][3][0] + event['data'][4][0]) > 2:
            parsed_blob[split_comps[3]][split_comps[0]]['fail_status'] = str(parsed_blob[split_comps[3]][split_comps[0]]['fail_status']) + '|(pcm) Too many failures in execution or log gathering (>3/4 fails).'
            nexe = True
        else:
            if 'control_status' in parsed_blob[split_comps[3]][split_comps[0]] and parsed_blob[split_comps[3]][split_comps[0]]['control_status'] == 'File not executed':
                nexe = True
            #handles case where a single log entry is returned
            elif isinstance(event['data'][4][1], list):
                if event['data'][4][1][0]['stopped'] == True:
                    isstopped = True
            #handles case where multiple entries are returned
            #this likely occurs when the malware attempts to re-run itself with varying privliege
            #    escalation techniques.
            elif isinstance(event['data'][4][1], dict):
                if 'stopped' in event['data'][4][1].keys():
                    if event['data'][4][1]['stopped'] == True:
                        isstopped = True
            #odd event where pcmatic kills the file on transfer and denies access before it can be executed
            #    corroborated by successful log grab on process logging and applocker logging with no 
            #    matching processes created.
            #this happens because access denied comes back immediately, no proccesses are created and PC 
            #    matic is slow to log blocked events (up to a few seconds delay) - it is effectively a race
            #    condition in logging and grabbing logs where we fall into the cracks.
            elif str(event['data'][1][2]).find('VERR_ACCESS_DENIED') != -1 and ((event['data'][3][0] == 0 and event['data'][3][1] == "") or (event['data'][2][0] == 0 and event['data'][2][1] == "")):
                isstopped = True
            #handles PCM killing DLL after transfer, but before execution - happens too fast to get PCM logs
            #    and gives false negative
            elif event['data'][1][0] == 33 and isinstance(event['data'][2][1], str) and event['data'][2][1] == "":
                isstopped = True
            #handles PCM killing exe after transfer, but before exeuction - happens too fast to get PCM logs
            #    and gives false negative
            elif str(event['data'][1][2]).lower().find('timeout') != -1 and event['data'][2][0] == 0 and isinstance(event['data'][2][1], str) and event['data'][2][1] == "" and event['data'][3][0] == 0 and isinstance(event['data'][3][1], str) and event['data'][3][1] == "":
                isstopped = True
            
            
        if isstopped:
            parsed_blob[split_comps[3]][split_comps[0]]['pcmatic_status'] = 'Execution stopped'
        else:
            parsed_blob[split_comps[3]][split_comps[0]]['pcmatic_status'] = 'Execution not stopped'
        if nexe:
            parsed_blob[split_comps[3]][split_comps[0]]['control_status'] = 'File not executed'
            parsed_blob[split_comps[3]][split_comps[0]]['applocker_status'] = None
            parsed_blob[split_comps[3]][split_comps[0]]['pcmatic_status'] = None

#set the blob for output
parsed_blob = {'data':parsed_blob,'summary':{
    'trials': 0, 'cleantrials':0, 'no_data': 0,
    'sample_fails':0, 'partial_sample_fails':0, 'control_fails': 0,
    'pcmatic_not_blocked':0, 'pcmatic_clean_blocked':0, 'pcmatic_no_data':0,
    'applocker_not_blocked':0, 'applocker_clean_blocked':0, 'applocker_no_data':0,
    'pcmatic_not_blocked_over_10mb': 0, 'pcmatic_not_blocked_under_10mb': 0, 'pcmatic_blocked_over_10mb':0,
    'av_totals': {}}}
for trial in parsed_blob['data'].keys():
    is_flawless = 1
    is_null = 0
    control_fails = 0
    pcmatic_not_blocked = 0
    pcmatic_blocked = 0
    pcmatic_no_data = 0
    applocker_not_blocked = 0
    applocker_blocked = 0
    applocker_no_data = 0
    pcmatic_not_blocked_over_10mb = 0
    pcmatic_not_blocked_under_10mb = 0
    pcmatic_blocked_over_10mb = 0
    av_results = {}
    for trial_os in parsed_blob['data'][trial].keys():
        if isinstance(parsed_blob['data'][trial][trial_os], dict) and str(trial_os).find('av_results') == -1:
            for stat in parsed_blob['data'][trial][trial_os].keys():
                if parsed_blob['data'][trial][trial_os][stat] == None:
                    is_flawless = 0
                    is_null = is_null + 1
            if parsed_blob['data'][trial][trial_os]['control_status'] == 'File not executed':
                control_fails = control_fails + 1
            if parsed_blob['data'][trial][trial_os]['applocker_status'] == 'Execution stopped':
                applocker_blocked = applocker_blocked + 1
            elif parsed_blob['data'][trial][trial_os]['applocker_status'] == 'Execution not stopped':
                applocker_not_blocked = applocker_not_blocked + 1
            else:
                applocker_no_data = applocker_no_data + 1
            if parsed_blob['data'][trial][trial_os]['pcmatic_status'] == 'Execution stopped':
                pcmatic_blocked = pcmatic_blocked + 1
                if str(parsed_blob['data'][trial]['filesize']).find(' KB') == -1 and str(parsed_blob['data'][trial]['filesize']).find(' B') == -1:
                    if float(str(parsed_blob['data'][trial]['filesize']).split(' ')[0]) > 10:
                            pcmatic_blocked_over_10mb = pcmatic_blocked_over_10mb + 1
            elif parsed_blob['data'][trial][trial_os]['pcmatic_status'] == 'Execution not stopped':
                pcmatic_not_blocked = pcmatic_not_blocked + 1
                if str(parsed_blob['data'][trial]['filesize']).find(' KB') == -1 and str(parsed_blob['data'][trial]['filesize']).find(' B') == -1:
                    if float(str(parsed_blob['data'][trial]['filesize']).split(' ')[0]) > 10:
                        pcmatic_not_blocked_over_10mb = pcmatic_not_blocked_over_10mb + 1
                    else:
                        pcmatic_not_blocked_under_10mb = pcmatic_not_blocked_under_10mb + 1
            else:
                pcmatic_no_data = pcmatic_no_data + 1
        elif isinstance(parsed_blob['data'][trial][trial_os], dict) and str(trial_os).find('av_results') != -1:
            av_results = parsed_blob['data'][trial][trial_os]
    #kill off raw data
    del parsed_blob['data'][trial]['av_results']
    #make sure we ran all controls and don't taint AV data
    if control_fails == 0:
        for result_key in av_results.keys():
            if result_key in parsed_blob['summary']['av_totals'].keys():
                if av_results[result_key] == True:
                    parsed_blob['summary']['av_totals'][result_key] = parsed_blob['summary']['av_totals'][result_key] + 1
            else:
                parsed_blob['summary']['av_totals'][result_key] = 1
    
    if control_fails == 4:
        parsed_blob['summary']['sample_fails'] = parsed_blob['summary']['sample_fails'] + 1
    if control_fails > 0 and control_fails < 4:
        parsed_blob['summary']['partial_sample_fails'] = parsed_blob['summary']['partial_sample_fails'] + 1
    if control_fails == 0 and pcmatic_blocked == 4:
        parsed_blob['summary']['pcmatic_clean_blocked'] = parsed_blob['summary']['pcmatic_clean_blocked'] + 1
    if control_fails == 0 and applocker_blocked == 4:
        parsed_blob['summary']['applocker_clean_blocked'] = parsed_blob['summary']['applocker_clean_blocked'] + 1
    if control_fails == 0 and pcmatic_blocked_over_10mb == 4:
        parsed_blob['summary']['pcmatic_blocked_over_10mb'] = parsed_blob['summary']['pcmatic_blocked_over_10mb'] + 1
    if control_fails == 0 and pcmatic_not_blocked == 4:
        parsed_blob['summary']['pcmatic_not_blocked'] = parsed_blob['summary']['pcmatic_not_blocked'] + 1
    if control_fails == 0 and pcmatic_not_blocked_over_10mb == 4:
        parsed_blob['summary']['pcmatic_not_blocked_over_10mb'] = parsed_blob['summary']['pcmatic_not_blocked_over_10mb'] + 1
    if control_fails == 0 and pcmatic_not_blocked_under_10mb == 4:
        parsed_blob['summary']['pcmatic_not_blocked_under_10mb'] = parsed_blob['summary']['pcmatic_not_blocked_under_10mb'] + 1
    if control_fails == 0 and applocker_not_blocked == 4:
        parsed_blob['summary']['applocker_not_blocked'] = parsed_blob['summary']['applocker_not_blocked'] + 1
    parsed_blob['summary']['applocker_no_data'] = parsed_blob['summary']['applocker_no_data'] + applocker_no_data
    parsed_blob['summary']['pcmatic_no_data'] = parsed_blob['summary']['pcmatic_no_data'] + pcmatic_no_data
    parsed_blob['summary']['control_fails'] = parsed_blob['summary']['control_fails'] + control_fails
    parsed_blob['summary']['cleantrials'] = parsed_blob['summary']['cleantrials'] + is_flawless
    parsed_blob['summary']['no_data'] = parsed_blob['summary']['no_data'] + is_null
    parsed_blob['summary']['trials'] = parsed_blob['summary']['trials'] + 1

parsed_blob['summary']['vm_executions'] = parsed_blob['summary']['trials'] * 12
print(json.dumps(parsed_blob, indent=4, separators=(',', ': '), sort_keys=True))
        

