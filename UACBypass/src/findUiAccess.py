import sys
import lief
import contextlib
from os import walk

filenames = next(walk("C:\\Windows\\System32"), (None, None, []))[2]  # [] if no file

for files in filenames:
    if(files.find(".exe") >= 0):
        
        file = lief.parse("c:\\windows\\system32\\" + files)
        
    
        if(not file):
            continue
        if(not file.has_resources):
            continue
        resources_manager = file.resources_manager
        if(not resources_manager):
            continue
        if(resources_manager == lief.lief_errors.read_error or resources_manager == lief.lief_errors.corrupted):
            continue
        
        if not resources_manager.has_manifest:
            continue
        
        manifest = resources_manager.manifest

        if(manifest.find("uiAccess=\"true\"") > 0):
            print(files)