#!/usr/bin/python
################################################################################
#
# Copyright (C) 2016
# Author: Antonio Sanchez <asanchez@plutec.net>
# All rights reserved.
#
################################################################################

__author__ = "Antonio Sanchez <asanchez@plutec.net>"

import yara
import json
import os

RULES_FOLDER = 'rules/'

def main():
    with open('report.json', 'rt') as fd:
        report = fd.read()

    binary_path = 'binary.exe'

    yara_rules = os.listdir(RULES_FOLDER)

    for rule in yara_rules:
        rule_compiled = yara.compile(filepath=os.path.join(RULES_FOLDER, rule), error_on_warning=False)
        
        matches = rule_compiled.match(binary_path, modules_data={'r2': bytes(report)})

        assert len(matches) >= 1, "Yara not match for rule %s & binary %s" % (rule, binary_path)

if __name__ == '__main__':
    main()
