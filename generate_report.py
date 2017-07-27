#!/usr/bin/python
import subprocess
import json
import sys

def rabin2_call(binary):
    """
    rabin2
    -i              imports
    -U              resoUrces
    -S              sections
    -E              globally exportable symbols
    -I              binary info
    -l              linked libraries
    -j              output in json
    """
    args = ["rabin2", "-iUSEIlj", binary]

    value, _ = subprocess.Popen(args, stdout = subprocess.PIPE).communicate()
    try:
        #print value
        value = json.loads(value.replace('\n', ' '))
    except Exception, why:
        print "Cannot generate bin information with rabin2 rahash2, reason: {}".format(why)
        print why
        value = {}
    return value

def rahash2_call(binary):
    args = ["rahash2", "-a", "all", "-j",  binary]

    value, _ = subprocess.Popen(args, stdout = subprocess.PIPE).communicate()
    try:
        value = json.loads(value.replace('\n', ' '))
    except Exception, why:
        print "Cannot generate hashes with rahash2, reason: {}".format(why)
        value = {}
    return value

def main():
    rabin2_json = rabin2_call(sys.argv[1])
    rahash2_json = rahash2_call(sys.argv[1])
    rabin2_json['hash'] = rahash2_json
    print json.dumps(rabin2_json)


if __name__ == '__main__':
    main()