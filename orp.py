#!/usr/bin/env python

# Copyright (c) 2012-2015
#   Vasilis Pappas <vpappas@cs.columbia.edu>
#   Hyungjoon Koo <hykoo@cs.stonybrook.edu>
# This file is part of Orp http://nsl.cs.columbia.edu/projects/orp

import optparse
import itertools
import random
import subprocess
import os
import sys

import func
import eval
import inp

import swap
import reorder
import equiv
import preserv
import disp
import util

# check for the prerequisites
try:
    import pydasm, pefile, pygraph
except ImportError, e:
    print "You need to install the following packages: pydasm, pefile, pygraph"
    sys.exit(1)

VER="0.69"

def checkEntryBoundImport(f):
    input_file = os.path.basename(f)
    input_path = os.path.abspath(f).split(input_file)[0]
    pe = pefile.PE(input_path + input_file)

    if not pe.OPTIONAL_HEADER.DATA_DIRECTORY[11].all_zeroes():
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[11].VirtualAddress = 0x0
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[11].Size = 0x0
        mod_file = input_path + input_file.split('.')[0] + '_mod.' + input_file.split('.')[1]
        pe.write(filename=mod_file)
        pe.close()
        return mod_file
    else:
        return input_path + input_file

def displace(input_file, rand=False, DEBUG=False):
    p = os.path.abspath(input_file)
    b = os.path.basename(p)
    output_file = os.path.dirname(p) + os.sep + b.split('.')[0] + '_ropf.' + b.split('.')[1]
    dp = disp.Displacement(p)
    dp.auto_disp(input_file, output_file, rand, DEBUG)

def randomize(input_file):
    # get the changed byte sets
    functions = inp.get_functions(input_file)
    levels = func.classify_functions(functions)
    func.analyze_functions(functions, levels)

    global_diffs = []
    changeable = 0

    for f in filter(lambda x: x.level != -1, functions.itervalues()):
        # skip the SEH prolog and epilog functions .. they cause trouble
        if "_SEH_" in f.name:    
            continue

        diffs = []

        # swap (register reassignment with CFG): RUNTIME ERROR
        # This application has requested the Runtime to terminate it in an unsusal way.
        # Please Contact the application's support team for more information
        swap.liveness_analysis(f.code)
        live_regs = swap.get_reg_live_subsets(f.instrs, f.code, f.igraph)
        swaps = swap.get_reg_swaps(live_regs)
        swap.do_single_swaps(swaps, False, diffs)

        # preserv (reordering of register preservation): ERROR
        preservs, avail_regs = preserv.get_reg_preservations(f)
        preserv.do_reg_preservs(f.instrs, f.blocks, preservs, avail_regs, False, diffs)

        # equiv (automic instruction substitution): GOOD
        equiv.do_equiv_instrs(f.instrs, False, diffs)

        # reorder (intra basic block reordering): GOOD
        reorder.do_reordering(f.blocks, False, diffs)

        if diffs:
            changeable += len(list(itertools.chain(*diffs)))
            global_diffs.extend(random.choice(diffs))

    inp.patch(global_diffs, "rand", False)

    print "changed %d bytes of at least %d changeable" % (len(global_diffs), changeable)
    print "(not counting all possible reorderings and preservations)"

def call_ida(input_file):
    def _check_ida():
        for pgm in [x for x in os.environ['path'].split(';')]:
            if 'ida' in pgm.lower():
                return True
        return False

    # Check if IDA Pro has been installed in Windows
    if _check_ida():
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "inp_ida.py")
        if not os.path.exists(script):
            print "Error: could not find inp_ida.py (%s)" % script
            sys.exit(1)
        command = 'idaq -A -S"\\"' + script + '\\"" ' + input_file
        print "[+] Executing:", command
        exit_code = subprocess.call(command)
        if exit_code == 0:
            print "\tDumped cfg with IDA Pro! "
        else:
            print "\tSomething went wrong during CFG generation!"
    else:
        print "Dumping CFG needs IDA Pro"

def check_args(args):
    # check if an input file is given
    if len(args) == 0:
        parser.error("no input file")
    elif len(args) > 1:
        parser.error("more than one input files")

    # check if the input file exists
    if not os.path.exists(args[0]):
        parser.error("cannot access input file '%s'" % args[0])
        sys.exit(1)

    # check if the input file is executable
    if not os.path.isfile(args[0]):
        print 'The given arg is not a file.'
        sys.exit(1)
    else:
        pe = pefile.PE(args[0])
        if not (pe.is_exe() or pe.is_dll()):
            print 'Input file should be executable (PE format: exe or dll)'
            sys.exit(1)

    return True

if __name__=="__main__":
    usage = "Usage: %prog [-p|-c|-e|-d|-r|-m|-k|-g] args (Use -h for help)"
    version = "%prog " + VER

    parser = optparse.OptionParser(usage=usage, version=version)

    parser.add_option("-p", "--profile", dest="profile", action="store_true", default=False,
                      help="profile the execution")

    parser.add_option("-c", "--eval-coverage", dest="coverage", action="store_true", default=False,
                      help="evaluate the randomization coverage")

    parser.add_option("-e", "--eval-payload", dest="payload", action="store_true", default=False,
                      help="check if the payload of the exploit can be broken")

    parser.add_option("-d", "--dump-cfg", dest="dump_cfg", action="store_true", default=False,
                      help="dump the CFG of the input file (using IDA)")

    parser.add_option("-r", "--randomize", dest="randomize", action="store_true", default=False,
                      help="produce a randomized instance of input (default)")

    parser.add_option("-m", "--disp", dest="ropf", action="store_true", default=False,
                      help="displace potential gadgets to the new section .ropf")

    parser.add_option("-k", "--displacement-with-ipr", dest="ropf_rand", action="store_true", default=False,
                      help="displace potential gadgets to the new section .ropf that does not cover IPR")

    parser.add_option("-g", "--debug", dest="debug", action="store_true", default=False,
                      help="Debugging mode for displacement")

    (options, args) = parser.parse_args()
    print "Orp v%s" % VER

    if check_args(args):
        # check for incompatible options
        if options.profile and options.dump_cfg:
            parser.error("cannot profile the CFG extraction from IDA")

        _run = __builtins__.eval

        # check if we're asked to profile execution
        if options.profile:
            import cProfile
            _run = cProfile.run
        else:
            _run = __builtins__.eval

        target = checkEntryBoundImport(args[0])

        if options.coverage:
            _run('eval.eval_coverage(args[0])')
        elif options.payload:
            _run('eval.eval_exploit(args[0])')
        elif options.dump_cfg:
            call_ida(args[0])
        elif options.randomize:
            _run('randomize(args[0])')
        elif options.ropf or options.ropf_rand:
            if not util.check_dump_file(target):
                call_ida(target)
            _run('displace(target, options.ropf_rand, options.debug)')
        else:
            parser.error("how did you do that?")