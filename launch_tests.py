#!/usr/bin/python
import json
import sys
import subprocess
import unittest

__author__ = "Antonio Sanchez <asanchez@plutec.com>"

YARABIN = "../yara/yara"

"""
    Aux method to run yara from command line
"""
def command_line(yararule, binary):
    args = [YARABIN, yararule, binary]
    value, _ = subprocess.Popen(args, stdout = subprocess.PIPE).communicate()
    value = value.split('\n')
    to_ret = list()
    for i in value:
        if len(i) > 0:
            to_ret.append(i.split(' ')[0])

    return to_ret


"""
Test r2yara
"""
class TestR2YaraAutoInvoke(unittest.TestCase):

    def test_hashes_array(self):
        rule = "tests/rules/hash.yar"
        rules = ["rule_hashes"]
        matches = command_line(rule, "tests/bins/ls")
        total_rules = len(rules)
        for match in matches:
            if match in rules:
                total_rules -= 1


        self.assertTrue(total_rules == 0)
    
    def test_resource_function(self):
        rule = "tests/rules/resource_func.yar"
        rules = ["resource_ss", "resource_rs", "resource_sr", "resource_rr"]
        matches = command_line(rule, "tests/bins/f61dc6f07401b8bc383d4bb69c001a6bf38f6557eeec7a9c261b581a4effdc1a")
        total_rules = len(rules)
        for match in matches:
            if match in rules:
                total_rules -= 1


        self.assertTrue(total_rules == 0)

    def test_resource_array(self):
        rule = "tests/rules/resources_array.yar"
        rules = ["resources"]
        matches = command_line(rule, "tests/bins/f61dc6f07401b8bc383d4bb69c001a6bf38f6557eeec7a9c261b581a4effdc1a")
        total_rules = len(rules)
        for match in matches:
            if match in rules:
                total_rules -= 1


        self.assertTrue(total_rules == 0)

    def test_export_array(self):
        rule = "tests/rules/exports_array.yar"
        rules = ["rule_exports_array"]
        matches = command_line(rule, "tests/bins/dll.dll_")
        total_rules = len(rules)
        for match in matches:
            if match in rules:
                total_rules -= 1


        self.assertTrue(total_rules == 0)
    
    def test_export_function(self):
        rule = "tests/rules/export.yar"
        rules = ["rule_export_ss", "rule_export_sr", "rule_export_rs", "rule_export_rr"]
        matches = command_line(rule, "tests/bins/dll.dll_")
        total_rules = len(rules)
        for match in matches:
            if match in rules:
                total_rules -= 1


        self.assertTrue(total_rules == 0)

    def test_lib(self):
        rule = "tests/rules/lib.yar"
        rules = ["rule_lib_s", "rule_lib_r"]
        matches = command_line(rule, "tests/bins/ls")
        total_rules = len(rules)
        for match in matches:
            if match in rules:
                total_rules -= 1


        self.assertTrue(total_rules == 0)

    def test_section_array(self):
        rule = "tests/rules/sections.yar"
        rules = ["sections"]
        matches = command_line(rule, "tests/bins/ls")
        total_rules = len(rules)
        for match in matches:
            if match in rules:
                total_rules -= 1


        self.assertTrue(total_rules == 0)

    def test_section_function(self):
        rule = "tests/rules/section_functions.yar"
        rules = ["rule_sections_ss", "rule_sections_sr", "rule_sections_rs", "rule_sections_rr"]
        matches = command_line(rule, "tests/bins/ls")
        total_rules = len(rules)
        for match in matches:
            if match in rules:
                total_rules -= 1


        self.assertTrue(total_rules == 0)


    def test_imports_function(self):
        rule = "tests/rules/imports.yar"        
        rules = ["rule_import_isss_1",
                 "rule_import_isss_2",
                 "rule_import_ssr",
                 "rule_import_srs",
                 "rule_import_srr",
                 "rule_import_rss",
                 "rule_import_rsr",
                 "rule_import_rrs",
                 "rule_import_rrr"]

        matches = command_line(rule, "tests/bins/ls")
        total_rules = len(rules)
        for match in matches:
            if match in rules:
                total_rules -= 1


        self.assertTrue(total_rules == 0)
    


if __name__ == '__main__':
    unittest.main()

