if __name__ == "__main__":
    print('This script contains only functions for use in other scripts. Do not call it directly.')
    exit(1)

import sys
import json
import os.path

root_folder = "/storage/VirusTotal Academic Malware Samples/"

match_file = "ransomware_files.txt"
match_file_contents = open(root_folder + match_file, "r")
match_file_list = match_file_contents.read().splitlines()
match_file_iter = iter(match_file_list)

match_file_num = len(match_file_list)

def get_malware_num():
    global match_file_num
    return match_file_num

def get_malware_info():
    global match_file_iter
    global match_file_num
    global root_folder
    try:
        fname = next(match_file_iter)
        
        ransomwarefname = root_folder + fname.replace('.json','')
        
        with open(root_folder + fname) as f:
            data = json.load(f)
        
        data['local_filename'] = ransomwarefname
        data['metadata_filename'] = os.path.realpath(root_folder + fname)
        
        if os.path.exists(data['local_filename']): # and (str(data['metadata_filename']).find('_EXE') > -1 or str(data['metadata_filename']).find('_DLL') > -1):
            data['local_filename'] = os.path.realpath(data['local_filename'])
        else:
            match_file_num = match_file_num - 1
            return get_malware_info()
        if 'sha256' not in data.keys():
            return get_malware_info()
        if 'additional_info' not in data.keys():
            return get_malware_info()
        else:
            if 'exiftool' not in data['additional_info'].keys():
                return get_malware_info()
        if 'scans' not in data.keys():
            return get_malware_info()
        for thekey in data['additional_info'].keys():
            if thekey != 'exiftool':
                data['additional_info'][thekey] = None
        for thekey in data.keys():
                if thekey not in ['type','times_submitted','vhash', 'submission_names', 'scan_date', 'first_seen', 'additional_info', 'size', 'scan_id', 'total', 'verbose_msg', 'sha256','scans','tags','authentihash','unique_sources','positivies','md5','sha1','submission','last_seen','local_filename', 'metadata_filename']:
                    data[thekey] = None
        return data
    except StopIteration:
        return False
    except FileNotFoundError:
        return get_malware_info()
    except:
        e = sys.exc_info()[0]
        print(e)
        return False