#!/usr/bin/env python
# coding: utf-8
"""
Copyright (c) 2015 Hyungjoon Koo <hykoo@cs.stonybrook.edu>
PE Library to write a modified PE with a new section
This file is added to support new feature to orp
"""
import os
import sys
import gadget
import inp_dump
import struct
import pefile, peLib
import time
import util
import inp
import func
import equiv, reorder, preserv, swap
import pickle
from random import shuffle
from bz2 import BZ2File

try:
    from capstone import *
    from progressbar import Bar, ETA, Percentage, ProgressBar
except ImportError, e:
    print "You need to install the following packages: capstone, progressbar"
    sys.exit(1)

STAT_DIR = './stats/'
RESULT_FILE = STAT_DIR + 'new_stats.csv'
STAT_GADS_MOVINGS = '_stats_gads_movings.bz2'

class GadCandidates:
    """
    Define the gadget candidates from previous orp
    """

    def __init__(self, target):
        self.target = target
        self.all_gadgets = set()
        self.gads = {}
        self.gads_in_red = {}

        self.small_gad_cnt = 0  # Gadgets in size < 5B

        self.intended, self.unintended = set(), set()           # Starting addrs of intended/unintended gadgets
        self.intended_red, self.unintended_red = set(), set()   # Starting addrs of gadgets in red
        self.call_preceded_gads_cnt = 0                         # Call preceded gadgets in total
        self.call_preceded_gads_red_cnt = 0                     # Call preceded gadgets in unreachable region

    def call_preceded_gad_check(self, all_calls):
        # all_calls = {(call_start: call_end), ...}
        for v in all_calls.values():
            if v in self.gads.keys():
                self.call_preceded_gads_cnt += 1
            if v in self.gads_in_red.keys():
                self.call_preceded_gads_red_cnt += 1

    def get_gads_by_type(self, type):
        if type == 'i':     # all intended gads
            return self.intended | self.intended_red
        if type == 'u':     # all unintended gads
            return self.unintended | self.unintended_red
        if type == 'inr':   # intended in no reds
            return self.intended
        if type == 'ir':    # intended in reds
            return self.intended_red
        if type == 'unr':   # unintended in no reds
            return self.unintended
        if type == 'ur':    # unintended in reds
            return self.unintended_red

    def gad_ctr(self, type):
        if type == 't':     # total gads
            return len(self.intended | self.unintended | self.intended_red | self.unintended_red)
        if type == 's':     # small gads
            return self.small_gad_cnt
        if type == 'nr':    # gads in no reds (= the area possibly to displace or do IPR)
            return len(self.intended | self.unintended)
        if type == 'r':     # gads in reds (= the area to stay intact)
            return len(self.intended_red | self.unintended_red)
        if type == 'i':     # intended gads
            return len(self.intended | self.intended_red)
        if type == 'u':     # unintended gads
            return len(self.unintended | self.unintended_red)
        if type == 'inr':   # intended in no reds
            return len(self.intended)
        if type == 'ir':    # intended in reds
            return len(self.intended_red)
        if type == 'unr':   # unintended in no reds
            return len(self.unintended)
        if type == 'ur':    # unintended in reds
            return len(self.unintended_red)
        if type == 'cp':    # call preceded gads
            return self.call_preceded_gads_cnt
        if type == 'cpr':   # call preceded gads in reds
            return self.call_preceded_gads_red_cnt

    def gad_stats(self, show=True):
        """
        Print out the statistics of gadget candidates collected by orp
        :return: N/A
        """
        def _ratio(cnt, total):
            return round(cnt / float(total) * 100, 2)

        total = self.gad_ctr('t')

        if show is True:
            print "\tDiscovered Gadgets in total: %d" % self.gad_ctr('t')
            print "\t\tSmall(<5B) : %d (%s%%)" % (self.gad_ctr('s'), _ratio(self.gad_ctr('s'), total))
            print "\t\tUnreachable: %d (%s%%)" % (self.gad_ctr('r'), _ratio(self.gad_ctr('r'), total))
            print "\t\tUnintended : %d (%s%%)" % (self.gad_ctr('u'), _ratio(self.gad_ctr('u'), total))

            # Target gadgets except ones in red
            print "\tGadget candidates to be broken or eliminated (no red): %d" % len(self.gads)
            print "\tCall preceded gadgets: %d (%s%%), %d (%s%%) in red" \
                  % (self.gad_ctr('cp'), _ratio(self.gad_ctr('cp'), total), 
                     self.gad_ctr('cpr'), _ratio(self.gad_ctr('cpr'), total))

    def get_gads(self, DEBUG=False):
        """
        Return known gadgets except unreachable region which has no CFG by IDA Pro 
        :param DEBUG: Debugging option
        :return: {gad_start: (g_end, gad_size, overlap, red, gad_bytes), ...}
        """
        self.all_functions = inp_dump.load_data(self.target) # DISABLED ON DIFF
        #pe = pefile.PE(self.target)  # DIFF
        self.all_gadgets = gadget.get_simple_gadgets(self.target)

        gad_bytes = []  # all gad bytes to displace

        for g in self.all_gadgets:
            (start, end, overlap, red, assem_lines, addrs, instrs) = g.getGadgetInfo()
            #red = False     # DIFF
            gad_size = end - start

            if DEBUG:
                print "\n@%.08X-%.08X (Size:%2dB - %d lines) %s %s" \
                      % (start, end, gad_size, assem_lines, "(overlapping)" if overlap else "", "(red)" if red else "")

            # Counting the gadget for statistics
            if gad_size < 5:
                self.small_gad_cnt += 1

            if overlap and not red:         # unintended & no red
                self.unintended.add(start)
            elif overlap and red:           # unintended & red
                self.unintended_red.add(start)
            elif not overlap and not red:   # intended & no red
                self.intended.add(start)
            elif not overlap and red:       # intended & red
                self.intended_red.add(start)

            for b in range(gad_size):
                if start < end:
                    gad_bytes.append(inp_dump.byte_at(start))
                    #gad_bytes.append(ord(pe.get_data(start - pe.OPTIONAL_HEADER.ImageBase, 1)))     # DIFF
                    start += 1

            if red:
                self.gads_in_red[end - gad_size] = (end, gad_size, overlap, red, gad_bytes)
            else:
                self.gads[end - gad_size] = (end, gad_size, overlap, red, gad_bytes)

        return self.gads, self.gads_in_red

    # The following code is rewritten from eval.py to evaluate randomization techniques
    # This function only uses for the comparison purpose
    def gad_transform_eval(self, functions, swap_b, preserv_b, equiv_b, reorder_b, DEBUG=False):
        def _check_gadget(g, changed, ins_hit):
            for i_start, i_end in zip(g.addrs, g.addrs[1:]+[g.end]):
                if any(b in changed for b in xrange(i_start, i_end)):
                    ins_hit.add(i_start)
                    return True
            return False
        def _p(x, y):
            return 100 * x/y

        # initialize output vars
        unchanged = set()
        swapped, preserved, equived, reordered = set(), set(), set(), set()
        ins_hit = set()

        # check each gadget one by one to see which were broken etc
        for g in self.all_gadgets:
            ins_hit.clear()
            broke_this_g = False

            # check if the gadget is broken
            if _check_gadget(g, swap_b, ins_hit):
                swapped.add(g)
                broke_this_g = True
            if _check_gadget(g, preserv_b, ins_hit):
                preserved.add(g)
                broke_this_g = True
            if g.overlap and _check_gadget(g, equiv_b, ins_hit):
                equived.add(g)
                broke_this_g = True
            if g.overlap and _check_gadget(g, reorder_b, ins_hit):
                reordered.add(g)
                broke_this_g = True
            elif not g.overlap and g.func_ea and g.func_ea in functions:
                f = functions[g.func_ea]
                for ins in (f.code[a] for a in xrange(g.start, g.end) if a in f.code):
                    if ins.addr != ins.raddr and ins.raddr < g.start or ins.raddr > g.end:
                        reordered.add(g)
                        broke_this_g = True
                        break

            if not broke_this_g:
                unchanged.add(g)

        changed_bytes = float(len(swap_b|preserv_b|equiv_b|reorder_b))

        if DEBUG:
            print "\tTotal changed bytes: %d" % changed_bytes
            print "\t\tswap: %d (%.2f%%)" % (len(swap_b), _p(len(swap_b), changed_bytes))
            print "\t\tpreserv: %d (%.2f%%)" % (len(preserv_b), _p(len(preserv_b), changed_bytes))
            print "\t\tequiv: %d (%.2f%%)" % (len(equiv_b), _p(len(equiv_b), changed_bytes))
            print "\t\treorder: %d (%.2f%%)" % (len(reorder_b), _p(len(reorder_b), changed_bytes))

        if len(self.all_gadgets) > 0:
            reds = set((g for g in self.all_gadgets if g.red))

            r_len = len(reds)
            g_len, gr_len = float(len(self.all_gadgets)), float(len(self.all_gadgets - reds))
            u_len, ur_len = len(unchanged), float(len(unchanged - reds))
            b_len = len(self.all_gadgets - unchanged)
            s_len, p_len, q_len, o_len = len(swapped), len(preserved), len(equived), len(reordered)

            if DEBUG:
                print "\tTotal gadgets: %d (marked red: %d (%.2f%%))" % (g_len, r_len, _p(r_len, g_len))
                print "\t\tRemained: %d (%.2f%%) - no red: %d (%.2f%%)" % (u_len, _p(u_len, g_len), ur_len, _p(ur_len, gr_len))
                print "\t\tBroken: %d (%.2f%%) - no red: %.2f%%" % (b_len, _p(b_len, g_len), _p(b_len, gr_len))
                print "\t\t\tswap: %d (%.2f%%) - no red: %.2f%%" % (s_len, _p(s_len, g_len), _p(s_len, gr_len))
                print "\t\t\tpreserv: %d (%.2f%%) - no red: %.2f%%" % (p_len, _p(p_len, g_len), _p(p_len, gr_len))
                print "\t\t\tequiv: %d (%.2f%%) - no red: %.2f%%" % (q_len, _p(q_len, g_len), _p(q_len, gr_len))
                print "\t\t\treorder: %d (%.2f%%) - no red: %.2f%%" % (o_len, _p(o_len, g_len), _p(o_len, gr_len))

        return self.all_gadgets - unchanged

class Displacement:
    """
    Define all significant methods and variables to displace candidate regions
    Evaluate each region and decide if it is appropriate to move it to a new section
    """

    def __init__(self, target):
        self.target = target
        self.gad_candidates = {}
        self.gads_in_red = {}
        self.all_func_blocks = []
        self.all_funcs = []
        self.all_opcodes = []
        self.all_blocks = []
        self.all_remained_gads = set()
        self.all_call_preceded_addrs = {}

        # [starting_addr of moving regions, moving sizes, ropf_starts]
        self.moving_regions = []
        self.moving_bytes_total = 0
        self.moving_bin_total = ''
        self.disp_snippets = {}

        '''
        The structure of the relocation table in .reloc section
            reloc_entries: [(ropf_start, reloc_offset), ...]
                where reloc_offset = reloc_addr - mov_start
            ropf_reloc_offset = (ropf_start - ropf_addr) + reloc_offset
        '''
        self.reloc_entries = []

        '''
        Case 1) Entry (Longest) gadgets not broken after moving
        Case 2) Either block or gadget-wrapped opcode can't be addressed from IDA Pro
        Case 3) gad_start < the starting point of the text(code) section
        Case 4) size of block (=b_end-b_start) < 5B
        '''
        self.c1, self.c2, self.c3, self.c4 = 0, 0, 0, 0

        self.single_jmps = 0
        self.pair_jmps = 0
        self.call_preceded_gads_remained_cnt = 0

        # Get the address of starting a new section .ropf
        self.pe = pefile.PE(target)
        self.peinfo = peLib.PEInfo(self.pe)
        self.ropf_start = self.peinfo.getImageBase() + (self.peinfo.getRVA(-1) + self.peinfo.getVirtualSize(-1) -
                                                        self.peinfo.getVirtualSize(
                                                            -1) % self.peinfo.getSectionAlignment() +
                                                        self.peinfo.getSectionAlignment())
        self.ropf_offset = 0

        # Define all opcodes using relative address to patch
        self.eip_impacted_ops = {'call': 0xe8, 'ja': 0x870f, 'jae': 0x830f, 'jb': 0x820f, 'jbe': 0x860f,
                                 'jc': 0x820f, 'je': 0x840f, 'jg': 0x8f0f, 'jge': 0x8d0f, 'jl': 0x8c0f,
                                 'jle': 0x8e0f, 'jmp': 0xe9, 'jna': 0x860f, 'jnae': 0x820f, 'jnb': 0x830f,
                                 'jnbe': 0x870f, 'jnc': 0x830f, 'jne': 0x850f, 'jng': 0x8e0f, 'jnge': 0x8c0f,
                                 'jnl': 0x8d0f, 'jnle': 0x8f0f, 'jno': 0x810f, 'jnp': 0x8b0f, 'jns': 0x890f,
                                 'jnz': 0x850f, 'jo': 0x800f, 'jp': 0x8a0f, 'jpe': 0x8a0f, 'jpo': 0x8b0f,
                                 'js': 0x880f, 'jz': 0x840f}
        self.instrs_1B = {0xE3: 'jmp', 0xE8: 'call', 0xE9: 'jmp', 0xEB: 'jmp', 0x70: 'jo', 0x71: 'jno', 0x72: 'jb',
                          0x73: 'jae', 0x74: 'je', 0x75: 'jne', 0x76: 'jbe', 0x77: 'jnbe', 0x78: 'js', 0x79: 'jns',
                          0x7A: 'jp', 0x7B: 'jnp', 0x7C: 'jl', 0x7D: 'jnl', 0x7E: 'jle', 0x7F: 'jg'}
        self.instrs_2B = [0x800F, 0x810F, 0x820F, 0x830F, 0x840F, 0x850F, 0x860F, 0x870F,
                           0x880F, 0x890F, 0x8A0F, 0x8B0F, 0x8C0F, 0x8D0F, 0x8E0F, 0x8F0F]

        # All diffs after randomization: [[addr, before_byte, after_byte], ...]
        self.all_diffs = []
        self.addr_diffs = []
        self.selected_diffs = []

        # Gadgets for comparison
        self.gads_ipr_broken = set()
        self.gads_moving_broken = set()

    def __len__(self):
        return len(self.moving_bin_total)

    # Define helper functions to decide moving regions
    def __case_check(self, case, DEBUG=False, **kwargs):
        """
        Case 1) Entry (Longest) gadgets not broken after moving
        Case 2) Either block or gadget-wrapped opcode can't be addressed from IDA Pro
        Case 3) gad_start < the starting point of the text(code) section
        Case 4) size of block (=b_end-b_start) < 5B
        :param case: number of the corner case to consider
        :param DEBUG: debug option
        :param kwargs: various args for each case
        :return: True or False (result of each checkout)
        """
        def __small_size_check(start, end):
            return (end - start) < 5

        check = False

        # Case 1) Entry (Longest) gadgets not broken after moving
        if case == 1:
            moving_start = kwargs['ms']
            intended_gads = kwargs['ig']
            check = (moving_start in intended_gads)

            if check:
                self.c1 += 1
                if DEBUG:
                    print "\t[Case 1] Entry (longest, intended) gadget or moving start: 0x%08X" % moving_start

            return check

        # Case 2) Either block or op_code can't be addressed from IDA Pro
        if case == 2:
            b_start, g_start_op_head, g_end_op_head = kwargs['bs'], kwargs['gsh'], kwargs['geh']
            prev_b_start, prev_g_end, gad_end = kwargs['pbs'], kwargs['pge'], kwargs['ge']
            check = (b_start == 0 or g_start_op_head == 0 or g_end_op_head == 0) \
                    or (prev_b_start == 0 and prev_g_end == gad_end)

            if check:
                self.c2 += 1
                if DEBUG:
                    print "\t[Case 2] Either block, opcode or control flow for the gadget can't be addressed" \
                                      "(b_start: 0x%08X, gad_op: 0x%08X" % (b_start, g_start_op_head)
            return check

        # Case 3) gad_start < the starting point of the text(code) section
        elif case == 3:
            g_start, func = kwargs['gs'], kwargs['f']
            check = (g_start < func)

            if check:
                self.c3 += 1
                if DEBUG:
                    print "\t[Case 3] Gad_start < text(code) section"

            return check

        # Case 4) size of block (=b_end-b_start) <= 5B
        elif case == 4:
            b_start, b_end = kwargs['bs'], kwargs['be']
            check = __small_size_check(b_start, b_end)

            if check:
                self.c4 += 1
                if DEBUG:
                    print "\t[Case 4] Size of block is too small to move (<5B)"

            return check

        else:
            if DEBUG:
                print "\t[Case ?] Unknown error!"
            return check

    # Define helper functions to assemble/disassemble raw data
    def _int_to_bin(self, ins):
        """
        Convert integers to binary data
        :param ins: list of integers [23, 55, 130, 255, 0, ...]
        :return: binary data corresponding instructions
        """
        bin = ''
        for i in ins:
            bin += struct.pack('B', i)
        return bin

    def _get_ops(self, code):
        """
        Disassemble a given code using either nasm/ndiasm or capstone
        :param code: binary data
        :return: opcodes seperated by ';'
        """
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        ops = ''
        for i in md.disasm(code, 0x0):
            ops += i.mnemonic + ' ' + i.op_str
        return ops

    def _extract_rel_addr(self, op_bytes, mnemonic_type):
        """
        Extract the relative address at the level of binary operation
        :param op_bytes: list consisting of integers for each byte [0xe8,0x36,0x60,0xff,0xff]
        :param mnemonic_type: 1 or 2 (depending on the number of mnemonic bytes)
        :return: extracted address from a single opcode
        """
        addr = 0x0
        mask = 0x0

        # Aside from mnemonic bytes, all remaining bytes would be a target address (1B, 2B, or 4B)
        # 'Mask' helps to convert a negative value if target address is less than 4B
        for i in range(len(op_bytes[mnemonic_type:])):
            addr |= op_bytes[mnemonic_type + i] << (8 * i)
        if mnemonic_type == 1:  # 1 byte
            mask |= 0xffffff00
        if mnemonic_type == 2:  # 2 bytes
            mask |= 0xffff0000

        # If MSB is set in a target address, the result should be masked - check some examples:
        #   1B: [0x74, 0xc] -> 0xe
        #   1B: [0xeb, 0xed] -> 0xffffffef (not 0xef)
        #   1B: [0xe9, 0xd6, 0xa9, 0xff, 0xff] -> 0xffffa9db
        #   2B: [0x0f, 0x84, 0x88, 0x0, 0x0, 0x0] -> 0x8e
        if (i + 1 == 1 and op_bytes[1] & (1 << (8 * mnemonic_type - 1)) > 0) or \
                (i + 1 == 2 and op_bytes[3] & (1 << (8 * mnemonic_type - 1)) > 0):
            return mask | (addr + len(op_bytes))
        return addr + len(op_bytes)

    def _update_opcodes(self, DEBUG):
        """
        Update all references per each code snippet to be displaced
        :param DEBUG: Debugging option
        :return:
        """
        disp_order = range(len(self.disp_snippets))
        shuffle(disp_order)

        widgets = ['\tUpdating references: ', Percentage(), ' ', Bar(), ' ', ETA()]
        bar = ProgressBar(widgets=widgets, maxval=len(disp_order)).start()

        cnt = 0
        for i in disp_order:
            if not DEBUG:
                bar.update(cnt)

            cnt += 1
            mov_start, mov_end = self.disp_snippets[i][0], self.disp_snippets[i][1]
            m_bytes_region = self.disp_snippets[i][2]

            mov_size = mov_end - mov_start
            op_cur = mov_start
            op_tail = 0
            op_pos = 0
            moving_bytes_ropf = ''

            # For each displacement, check if the individual opcode needs to be updated
            while mov_start + len(m_bytes_region) > op_tail:
                (op_head, op_tail) = util.get_addr_range(self.all_opcodes, op_cur)
                op_size = op_tail - op_head
                org_bin = self._int_to_bin(m_bytes_region[op_pos:op_pos + op_size])

                is_modified = False
                mnemonic_type = 0
                alt_bin = org_bin

                # Check the size of mnemonic type
                if m_bytes_region[op_pos] in self.instrs_1B.keys():
                    mnemonic_type = 1
                if len(m_bytes_region[op_pos:op_pos + op_size]) > 1:
                    if m_bytes_region[op_pos]+m_bytes_region[op_pos+1]*256 in self.instrs_2B:
                        mnemonic_type = 2

                # If the mnemonic uses relative address, update (extracted/packed) it in a binary level
                if mnemonic_type > 0:
                    is_modified = True
                    old_addr = self._extract_rel_addr(m_bytes_region[op_pos:op_pos + op_size], mnemonic_type)
                    new_addr = ((op_head + old_addr) - self.ropf_start) & 0xffffffff
                    if mnemonic_type == 1:
                        m_bytes = self.eip_impacted_ops[self.instrs_1B[m_bytes_region[op_pos]]]
                        if m_bytes <= 0xff:
                            alt_bin = struct.pack('<B', m_bytes) + struct.pack('<I', new_addr - 5)
                        else:
                            alt_bin = struct.pack('<H', m_bytes) + struct.pack('<I', new_addr - 6)
                    else:
                        alt_bin = struct.pack('<B', m_bytes_region[op_pos]) \
                                  + struct.pack('<B', m_bytes_region[op_pos + 1]) + struct.pack('<I', new_addr - 6)

                self.ropf_offset += len(alt_bin)

                if DEBUG:
                    print '\t.text@[0x%06X:0x%06X](%dB) \t%s' \
                          % (op_head, op_tail, op_size, self._get_ops(org_bin))
                    print '\t.ropf@[0x%06X:0x%06X](%dB) \t%s%s' \
                          % (self.ropf_start, self.ropf_start + len(alt_bin), len(alt_bin), self._get_ops(alt_bin),
                             "*" if is_modified else "")

                self.ropf_start += len(alt_bin)
                moving_bytes_ropf += alt_bin
                self.moving_bin_total += alt_bin

                op_pos += op_size
                op_cur = op_tail

            # Relative addr to jump back to .text section: (mov_end - ropf_start)
            # Do not insert jmp instruction when not needed (i.e the last instr == 'jmp' or 'ret')
            last_op = self._get_ops(alt_bin).split(' ')[0]
            if last_op == 'ret' or last_op == 'jmp':
                self.single_jmps += 1
                # print '\t<---- NO NEED TO JMP BACK HERE ---->'
            else:
                self.pair_jmps += 1
                ret_addr = mov_end - self.ropf_start
                jmp_code = struct.pack('<B', 0xE9) + struct.pack('<i', ret_addr - 5)

                moving_bytes_ropf += jmp_code
                self.moving_bin_total += jmp_code
                self.ropf_offset += len(jmp_code)  # Adjust jmp bytes (=5B)
                self.ropf_start += len(jmp_code)   # Adjust jmp bytes (=5B)
                if DEBUG:
                    print "\t.ropf@[0x%06X:0x%06X](5B) \t%s" % (
                        self.ropf_start - len(jmp_code), self.ropf_start, self._get_ops(jmp_code))

            if DEBUG:
                diff = len(moving_bytes_ropf) - len(m_bytes_region)
                if diff >= 0 or is_modified:
                    print '\t(a) Modified: Diff %dB* in total moving size! (%dB VS %dB)' % (
                        diff, len(m_bytes_region), len(moving_bytes_ropf))
                print '\t(b) Return to 0x%08X**' % mov_end
                print '\t(c) [0x%06X:0x%06X] <-> 0x%06X' % (
                    mov_start, mov_start + mov_size, self.ropf_start - len(moving_bytes_ropf))
                print '\nTarget gadgets:'

            self.moving_bytes_total += len(m_bytes_region)
            self.moving_regions.append((mov_start, mov_size, self.ropf_start - len(moving_bytes_ropf)))

        bar.finish()

    # Define helper functions to gather funcs/blocks/opcodes
    def _show_steps(self, step):
        """
        Show each phase to move candidate regions with appropriate updates
        :param step: phase number
        :return: N/A
        """
        steps = ["", "Gathering codes and blocks", "Computing candidate gadgets", \
                 "Organizing essential information", "Simulating randomization", "Choosing the regions for displacement", \
                 "Processing binary instrumentation", "Evaluating the results", "Finalizing"]
        print "\n[%d] %s..." % (step, steps[step])

    def _get_codeblocks(self):
        """
        Return all opcodes and blocks from file.dump-codeblocks.bz2
        :return: raw data loaded from the file, but exit if not found
        """
        dmp = os.path.abspath(self.target)
        if os.path.exists(dmp):
            return util.load_codes_blocks(dmp)
        else:
            print "\tThe file %s has not been found!" % dmp
            sys.exit(1)

    def _get_all_blocks(self, funcs):
        """
        Return all blocks defined in self.all_func_blocks
        :param funcs: all functions
        :return: [(b_start, b_end), ...]
        """
        all_blocks = []
        for f in funcs:
            for (start_block, end_block) in self.all_func_blocks[f]:
                all_blocks.append((start_block, end_block))
        return sorted(set(all_blocks))

    def _get_randomize_diffs(self, gc, DEBUG=False):
        """
        Get all differential bytes after the simulation of randomization
        :return: all_diffs sorted by address
        """
        functions = inp.get_functions(self.target)
        levels = func.classify_functions(functions)
        func.analyze_functions(functions, levels)

        swap_b, preserv_b, equiv_b, reorder_b = set(), set(), set(), set()

        for f in filter(lambda x: x.level != -1, functions.itervalues()):
            '''
            if "_SEH_" in f.name:
                continue
            '''
            diffs = []

            # swap (register reassignment with CFG): RUNTIME ERROR
            swap.liveness_analysis(f.code)
            live_regs = swap.get_reg_live_subsets(f.instrs, f.code, f.igraph)
            swap.split_reg_live_subsets(live_regs, f.code)
            swaps = swap.get_reg_swaps(live_regs)
            swap_b |= swap.do_single_swaps(swaps, False, diffs)

            # preserv (reordering of register preservation): ERROR
            preservs, avail_regs = preserv.get_reg_preservations(f)
            preserv_b |= preserv.do_reg_preservs(f.instrs, f.blocks, preservs, avail_regs, False, diffs)

            # reorder (intra basic block reordering): GOOD
            reorder_b |= reorder.do_reordering(f.blocks, False, diffs)

            # equiv (automic instruction substitution): GOOD
            equiv_b |= equiv.do_equiv_instrs(f.instrs, False, diffs)

            self.all_diffs.extend(diffs)

        self.all_diffs = [x for x in sorted(self.all_diffs) if len(x) > 0]

        broken_gads_by_rand = gc.gad_transform_eval(functions, swap_b, preserv_b, equiv_b, reorder_b, DEBUG)

        # Don't know why, but IPR sometimes touches the unreachable region!!!!
        gads_in_red = list(gc.get_gads_by_type('ir') | gc.get_gads_by_type('ur'))
        for bg in broken_gads_by_rand:
            if bg.start not in gads_in_red:
                self.gads_ipr_broken.add(bg.start)

        '''
        # NOT USING FOR NOW
        for diff in sorted(self.all_diffs):
            tmp = []
            for (addr, before, after) in diff:
                tmp.append(addr)
            self.addr_diffs.append(tmp)
        '''

    # Counter if the condition is met
    #   a. moving(mc) VS non-moving(mn) and broken(br) VS remaining(re) should be set at all times
    #   b. broken by ipr and the entry point gadget (moved but remained) are special cases to keep track of
    def _counter(self, gad, br=False, re=False):
        if br:
            self.gads_moving_broken.add(gad)
        if re:
            self.all_remained_gads.add(gad)

    def _init_disp_params(self):
        self.gads_moving_broken = set()
        self.all_remained_gads = set()

        self.ropf_start = self.peinfo.getImageBase() + (self.peinfo.getRVA(-1) + self.peinfo.getVirtualSize(-1) -
                                                        self.peinfo.getVirtualSize(-1) % self.peinfo.getSectionAlignment() +
                                                        self.peinfo.getSectionAlignment())
        self.ropf_offset = 0
        self.c1, self.c2, self.c3, self.c4 = 0, 0, 0, 0

        self.moving_regions = []
        self.moving_bytes_total = 0
        self.moving_bin_total = ''

    def _decide_displacement(self, disp_rate, intended_gads, rand=False, DEBUG=False):
        '''
        Main strategy
            (a) Keep track of bookkeeping information
                Check the gadget head and corresponding ophead of the gadget
                Store the last moved address and previous gadget ending address
            (b) Check if the gadget is already broken (case 1)
                The next gadget family overlaps a previous one, do not move
                gad_start < last_moved_addr, do not move
            (c) Decide moving regions when the gadget is beyond another block
                moving_start = b_start
                moving_end = b_end (iff g_end > b_end or g_end_op_tail > b_end)
                moving_end = g_end_op_tail (g_end_op_tail - b_start >= 5B) or moving_end = b_end (o/w)
            (d) Decide moving regions when the gadget is not beyond another block
                moving_start = b_start (iff b_end - g_start_op_head < 5B)
                moving_start = g_start_op_head (o/w)
                moving_end = b_end
            (e) Check if the gadget in the current moving region can be broken by randomization
            (f) Check the corner cases which gadgets cannot be moved
                Either block or opcode for the gadget can't be addressed (case 5)
                The region failed to display the program in graph mode (case 5)
                Size of block is too small (<5B) (case 3)

        Notions
            Each square represents 1B in size
            * means starting point of each instruction
            B: Blocks (b_start:b_end)
            G: gadgets (g_start:g_end), (g_start_op_head:g_end_op_tail)
            P: Pivots
            Gadget family: gadgets which have the same pivots (i.e G1-G5, G6-G9)
            Moving decision (moving_start: moving_end)

        ..|B1                     |B2                         |B3           |B4                 |B5..
        --┬---┬---┬---┬---┬---┬---┬---┬---┬---┬---┬---┬---┬---┬---┬---┬---┬---┬---┬---┬---┬---┬--
          |****|    |    |***|    |    |***|    |    |    |***|    |*** |***|    |    |***|    |    |*** |    |
        --┴---┴---┴---┴---┴---┴---┴---┴---┴---┴---┴---┴---┴---┴---┴---┴---┴---┴---┴---┴---┴---┴--
                                                            ↑                   ↑
                                                            P1                  P2
              |---------x---------|----------y-------- G1(12B)|
                      |------------------------------- G2(10B)|
                                  |-------------------- G3(7B)|
                                              |-------- G4(4B)|
                                                   |--- G5(3B)|
                                                      |-------------------- G6(7B)|
                                                          |---------------- G7(6B)|
                                                                  |----z--- G8(4B)|
                                                                          | G9(2B)|

        Case study
            (a) G1: A gadget is between B1 and B2, whose size >= 5B (=x)
                Displacement decision: move x bytes in B1
            (b) G2-G5: The pivot of these gadgets are the same with G1
                If gadget head is already moved then it is broken. (G2)
                If not, move y bytes iff the size >= 5B (=y) (G3)
                Like (a), G4 and G5 are broken by previous displacement
            (c) G6-G7: The next gadget head starts within B2, which is already moved in (b)
            (d) G8: This gadget head starts in next block, B3, with P2
                Displacement decision: move the entire block iff the block size >= 5B (=z)
                In this case, B3 has 3B in size thus it remains intact with no displacement
            (e) G9: This gadget has the same pivot with G8 but its head starts the next block, B4
                Displacement decision: move the entire block since the block size > 5B, and gadget size < 5B
        '''

        def __remained_gad_check(gad):
            if gad in list(self.all_remained_gads):
                self.all_remained_gads.remove(gad_start)

        last_moved_addr = 0x0
        gad_starts = sorted(set(self.gad_candidates.keys()))

        prev_g_end, prev_b_start = 0x0, 0x0
        disp_cnt = 0

        if DEBUG:
            print '\nTarget gadgets:'

        if 0 < disp_rate <= 1:
            gad_cnt = int(len(gad_starts) * disp_rate)
            '''
            # The following code is for random displacement experiment only
            import random
            gad_starts = sorted(random.sample(gad_starts, gad_cnt))
            '''
            print '\tTarget gadgets to be broken: %d (%.1f%%)' % (gad_cnt, disp_rate*100)
        else:
            print "Move rate must be between 0 and 1!"
            sys.exit(1)

        widgets = ['\tChecking regions:    ', Percentage(), ' ', Bar(), ' ', ETA()]
        bar = ProgressBar(widgets=widgets, maxval=gad_cnt).start()

        # (gad_end, gad_size, unintended, red, gad_bytes) = self.gad_candidates[gad_start]
        # Group by g_end since all gads should end with ret, therefore they can belong to the same gadget family

        cnt = 0
        for gad_start in gad_starts[0:gad_cnt]:
            if not DEBUG:
                bar.update(cnt+1)

            # Get block/gadget/opcode ranges and sizes
            gad_end = self.gad_candidates[gad_start][0]
            gad_size = self.gad_candidates[gad_start][1]
            unintended = self.gad_candidates[gad_start][2]
            (b_start, b_end) = util.get_addr_range(self.all_blocks, gad_start)
            (g_start_op_head, g_start_op_tail) = util.get_addr_range(self.all_opcodes, gad_start)
            (g_end_op_head, g_end_op_tail) = util.get_addr_range(self.all_opcodes, gad_end - 1)

            # Gadget info
            if DEBUG:
                print "\t%s Gad@[0x%06X:0x%06X](%dB) <-> Block@[0x%06X:0x%06X](%dB)" \
                      % ("[U]" if unintended else "[I]", gad_start, gad_end, gad_size, b_start, b_end, b_end - b_start)

            # [Case 2] Either block or opcode for the gadget can't be addressed
            #   (or region failed to display the program in graph mode)
            if self.__case_check(2, DEBUG, bs=b_start, gsh=g_start_op_head, geh=g_end_op_head,
                            pbs=prev_b_start, pge=prev_g_end, ge=gad_end):
                self._counter(gad_start, re=True)
                if gad_start in list(self.gads_ipr_broken):
                    self.c2 -= 1
                    __remained_gad_check(gad_start)
                prev_b_start = 0
                prev_g_end = gad_end
                cnt += 1
                continue

            # [Case 3] Rare case: gad_start < text(code) section
            if self.__case_check(3, DEBUG, gs=gad_start, f=self.all_funcs[0]):
                self._counter(gad_start, re=True)
                if gad_start in list(self.gads_ipr_broken):
                    self.c3 -= 1
                    __remained_gad_check(gad_start)
                cnt += 1
                continue

            # [Case 4] Size of block is too small (<5B)
            if self.__case_check(4, DEBUG, bs=b_start, be=b_end):
                self._counter(gad_start, re=True)
                if gad_start in list(self.gads_ipr_broken):
                    self.c4 -= 1
                    __remained_gad_check(gad_start)
                cnt += 1
                continue

            moving_bytes = []

            # Case that the last gad has been removed with previous displacement (gad_start < last_moved_addr)
            if gad_start < last_moved_addr:
                self._counter(gad_start, br=True)
                cnt += 1
                continue

            # If the next gadget overlaps a previous gadget family, it has been already broken
            if prev_g_end == gad_end:
                self._counter(gad_start, br=True)

                # If the gadget is beyond another block,
                # Move [b_start:b_end] or [b_start:g_end_op_tail]
                moving_start = b_start
                if gad_end > b_end or g_end_op_tail > b_end:
                    moving_end = b_end
                else:
                    moving_end = b_end if g_end_op_tail - b_start < 5 else g_end_op_tail

            # If the longest entry gadget (LEG) is found,
            # Move [b_start:b_end] or [g_start_op_head:b_end] or [prev_g_start_op_head:b_end]
            else:
                moving_end = b_end
                (prev_g_start_op_head, prev_g_start_op_tail) = \
                            util.get_addr_range(self.all_opcodes, g_start_op_head - 1)

                if b_end - g_start_op_head < 5:
                    moving_start = b_start
                else:
                    # To remove more gadget, check the previous instruction to see LEG can be broken
                    if unintended:
                        moving_start = g_start_op_head
                    else:   # intended
                        # LEG broken by previous instruction moving
                        if b_start < prev_g_start_op_head and last_moved_addr < prev_g_start_op_head:
                            moving_start = prev_g_start_op_head

                        # LEG ends up with not being broken [Case 1]
                        else:
                            moving_start = g_start_op_head
                            self.__case_check(1, DEBUG, ms=moving_start, ig=intended_gads)

                if moving_start == prev_g_start_op_head or (moving_start == b_start and unintended) \
                        or (moving_start == g_start_op_head and unintended):
                    self._counter(gad_start, br=True)
                else:
                    self._counter(gad_start, re=True)

            # If broken with IPR, then count the gadget as broken and continue
            if rand:
                # If the gadget can be broken by IPR, then remove it from the remaining gadget list
                if gad_start in list(self.gads_ipr_broken):
                    __remained_gad_check(gad_start)
                    prev_b_start = b_start
                    prev_g_end = gad_end
                    last_moved_addr = moving_end
                    cnt += 1
                    continue

            for i in range(moving_start, moving_end):
                moving_bytes.append(inp_dump.byte_at(i))
                # moving_bytes.append(ord(self.pe.get_data(i - self.pe.OPTIONAL_HEADER.ImageBase, 1))) # DIFF

            self.disp_snippets[disp_cnt] = (moving_start, moving_end, moving_bytes)

            prev_b_start = b_start
            prev_g_end = gad_end
            last_moved_addr = moving_end
            disp_cnt += 1

            # Displaced region info
            if DEBUG:
                out_in_hex = ''
                for c in ['%02X' % x for x in moving_bytes]:
                    out_in_hex += c + ' '
                print "\nRegion_%04d@[0x%08X:0x%08X](%dB) \n\t%s" \
                      % (disp_cnt, moving_start, moving_end, len(moving_bytes), out_in_hex)

            cnt += 1

        bar.finish()

        # [Batch] Update all references per each code snippet to be displaced
        self._update_opcodes(DEBUG)

    def base_fbo_info(self, show=True):
        """
        Get the number of functions, blocks and opcodes
        """
        funcs, blks, ops = len(self.all_funcs), len(self.all_blocks), len(self.all_opcodes)
        if show == True:
            print "\tFunctions: %d\n\tBlocks: %d\n\tOpcodes: %d" % (funcs, blks, ops)
        return funcs, blks, ops

    def _get_reloc_entries(self):
        if self.peinfo.getRelocationSize() > 0:
            for reloc in self.pe.DIRECTORY_ENTRY_BASERELOC:
                for entry in reloc.entries:
                    self.reloc_entries.append((entry.struct.Data, entry.rva, entry.type))
        else:
            self.reloc_entries = None

    def _patch_pe(self, output, DEBUG=False):
        """
        Generate a new PE adding a new section, '.ropf'
        Using patch_size, it is possible to create seperate executables for testing purpose
        """
        def md5sum(f):
            import hashlib
            return hashlib.md5(open(f, 'rb').read()).hexdigest()

        self._get_reloc_entries()
        print "\t[Before] %s (%s)" % (self.target, md5sum(self.target))
        self.peinfo.printEssentialOptionalInfo()

        # Write new PE applying all displaced regions
        adjPE = peLib.AdjustPE(self.pe)
        adjPE.update_section(self.moving_regions, self.moving_bin_total, self.reloc_entries, self.selected_diffs, DEBUG)
        self.pe.write(filename=output)

        print "\t[After]  %s (%s)" % (output, md5sum(output))
        peLib.PEInfo(pefile.PE(output)).printEssentialOptionalInfo()

    def _write_report(self, gc, e_time, show=True, result_store=False):
        """
        Generate a report file to contain all important statistics and interesting figures
        :param gc:
        :param e_time:
        :return:
        """
        def _ratio(cnt, total):
            return round(cnt / float(total) * 100, 2)

        # Gather and compute various values for statistics purpose
        funcs, blks, ops = self.base_fbo_info(show=False)

        total, total_nr = gc.gad_ctr('t'), gc.gad_ctr('nr')
        small, red = gc.gad_ctr('s'), gc.gad_ctr('r')
        unintended, intended = gc.gad_ctr('u'), gc.gad_ctr('i')
        unintended_red, intended_red = gc.gad_ctr('ur'), gc.gad_ctr('ir')
        cp, cp_r, cpre = gc.gad_ctr('cp'), gc.gad_ctr('cpr'), self.call_preceded_gads_remained_cnt

        brokens_all = len(self.gads_moving_broken | self.gads_ipr_broken)

        brokens_m_only = len(self.gads_moving_broken - self.gads_ipr_broken)
        u_m_only_gads = len(self.gads_moving_broken - self.gads_ipr_broken - gc.get_gads_by_type('i'))
        i_m_only_gads = len(self.gads_moving_broken - self.gads_ipr_broken - gc.get_gads_by_type('u'))

        brokens_r_only = len(self.gads_ipr_broken - self.gads_moving_broken)
        u_r_only_gads = len(self.gads_ipr_broken - self.gads_moving_broken - gc.get_gads_by_type('i'))
        i_r_only_gads = len(self.gads_ipr_broken - self.gads_moving_broken - gc.get_gads_by_type('u'))

        brokens_both = len(self.gads_moving_broken & self.gads_ipr_broken)
        u_bb_gads = len((self.gads_moving_broken & self.gads_ipr_broken) - gc.get_gads_by_type('i'))
        i_bb_gads = len((self.gads_moving_broken & self.gads_ipr_broken) - gc.get_gads_by_type('u'))

        u_br = u_m_only_gads + u_bb_gads + u_r_only_gads
        i_br = i_m_only_gads + i_bb_gads + i_r_only_gads
        u_rm = gc.gad_ctr('unr') - u_br
        i_rm = gc.gad_ctr('inr') - i_br

        '''
        u_br0 = len((self.gads_moving_broken | self.gads_ipr_broken) - gc.get_gads_by_type('i'))
        i_br0 = len((self.gads_moving_broken | self.gads_ipr_broken) - gc.get_gads_by_type('u'))
        u_rm0 = len(self.all_remained_gads - gc.get_gads_by_type('i')) # TODO - Need to check
        i_rm0 = len(self.all_remained_gads - gc.get_gads_by_type('u'))

        assert(u_br == u_br0)
        assert(i_br == i_br0)
        assert(u_rm == u_rm0)
        assert(i_rm == i_rm0)
        '''

        before_size = round(os.path.getsize(self.target), 2)

        b = os.path.basename(self.target)
        out = os.path.dirname(self.target) + os.sep + b.split('.')[0] + '_ropf.' + b.split('.')[1]
        after_size = round(os.path.getsize(out), 2)

        if show:
            print '\t            < Gadget Summary >'
            print '\t--------------------------------------------'
            print '\t          | Unintended | Intended  |   Sum'
            print '\t Broken   |   %5d    |   %5d   |  %5d' \
                  % (u_br, i_br, u_br + i_br)
            print '\t Remained |   %5d    |   %5d   |  %5d' \
                  % (u_rm, i_rm, u_rm + i_rm)
            print '\t Red Area |   %5d    |   %5d   |  %5d' \
                  % (unintended_red, intended_red, unintended_red + intended_red)
            print '\t--------------------------------------------'
            print '\t Total    |   %5d    |   %5d   |  %5d' % \
                    (u_br + u_rm + unintended_red, i_br + i_rm + intended_red, total)
            print '\t--------------------------------------------'
            print "\tBroken gadgets: %d (%.2f%%, %.2f%%)" \
                  % (u_br + i_br, _ratio(u_br + i_br, total_nr), _ratio(u_br + i_br, total))
            print "\tRemaining gadgets: %d (%.2f%%, %.2f%%)" \
                  % (u_rm + i_rm, _ratio(u_rm + i_rm, total_nr), _ratio(u_rm + i_rm, total))

            cnt_c1 = u_rm + i_rm - self.c2 - self.c3 - self.c4  # Ugly counting
            print "\t\t[Case 1] Entry (the longest/intended) gadgets:     %d" % cnt_c1
            print "\t\t[Case 2] Block or opcode not addressed:            %d" % self.c2
            print "\t\t[Case 3] Gad_start < text(code) section:           %d" % self.c3
            print "\t\t[Case 4] Size of block is too small to move (<5B): %d" % self.c4
            print "\tCall-preceded gadgets"
            print "\t\tTotal: %d (%.2f%%, %.2f%%)" % (cp, _ratio(cp, total_nr), _ratio(cp, total))
            print "\t\tIn red: %d (%.2f%%, %.2f%%)" % (cp_r, _ratio(cp_r, total_nr), _ratio(cp_r, total))
            print "\t\tRemained after processing: %d (%.2f%%, %.2f%%)" % (cpre, _ratio(cpre, total_nr), _ratio(cpre, total))
            print ''
            print '\t            < Coverage between Disp and Rand >'
            print "\t|<-----  (D)isp (%5d, %.1f%%)  ----->|" \
                  % (brokens_m_only + brokens_both, _ratio(brokens_m_only + brokens_both, total_nr))
            print "\t|-------------------|-----------------|------------------|"
            print "\t|++++++ [D-R] ++++++|+=+=+ [D&R] +=+=+|====== [R-D] =====|"
            print "\t|++++++%5d +++++++|+=+=+%5d +=+=+=|======%5d ======|" \
                  % (brokens_m_only, brokens_both, brokens_r_only)
            print "\t|++++(%4d/%4d)++++|+++(%4d/%4d)+++|++++(%4d/%4d)+++|" \
                  % (u_m_only_gads, i_m_only_gads, u_bb_gads, i_bb_gads, u_r_only_gads, i_r_only_gads)
            print "\t|+++++++++++++++++++|+=+=+=+=+=+=+=+=+|==================|"
            print "\t|-------------------|-----------------|------------------|"
            print "\t                    |<-----  (R)and (%5d, %.1f%%) ----->|" \
                  % (brokens_r_only + brokens_both, _ratio(brokens_r_only + brokens_both, total_nr))

            print "\n\tTotal gadgets: %d (%d with reds)" % (total_nr, total)
            print "\t\tD+R: %5d [%5d/%5d] (%2.2f%%, %2.2f%%)" \
                  % (brokens_all, u_m_only_gads + u_r_only_gads + u_bb_gads, i_m_only_gads + i_r_only_gads + i_bb_gads,
                    _ratio(brokens_all, total_nr), _ratio(brokens_all, total))
            print "\t\tD-R: %5d [%5d/%5d] (%.2f%%, %2.2f%%)" \
                  % (brokens_m_only, u_m_only_gads, i_m_only_gads,
                     _ratio(brokens_m_only, total_nr), _ratio(brokens_m_only, total))
            print "\t\tR-D: %5d [%5d/%5d] (%2.2f%%, %2.2f%%)" \
                  % (brokens_r_only, u_r_only_gads, i_r_only_gads,
                     _ratio(brokens_r_only, total_nr), _ratio(brokens_r_only, total))
            print "\t\tD&R: %5d [%5d/%5d] (%2.2f%%, %2.2f%%)" \
                  % (brokens_both, u_bb_gads, i_bb_gads,
                     _ratio(brokens_both, total_nr), _ratio(brokens_both, total))
            print "\tInserted jump instructions: %d" % (self.pair_jmps + self.single_jmps)
            print "\t\tSingle: %4d (%2.2f%%)" \
                  % (self.single_jmps, _ratio(self.single_jmps, self.pair_jmps + self.single_jmps))
            print "\t\tPair:   %4d (%2.2f%%)" \
                  % (self.pair_jmps, _ratio(self.pair_jmps, self.pair_jmps + self.single_jmps))
            print "\tIncreased size of new binary: %dB -> %dB (%2.2f%%)" \
                  % (before_size, after_size, _ratio(after_size - before_size, before_size))

        if result_store:
            if not os.path.exists(STAT_DIR):
                os.mkdir(STAT_DIR)

            # Pickling all info about movings and gads for further evaluation
            gad_stat_data = BZ2File(STAT_DIR + os.path.basename(os.path.abspath(self.target)) + STAT_GADS_MOVINGS, 'wb')
            all_gads, all_brokens, all_remainings, all_movings = [], [], [], []
            for g in self.gad_candidates.keys(): all_gads.append(g)
            for g in self.gads_in_red: all_gads.append(g)
            for g in list(self.gads_moving_broken | self.gads_ipr_broken): all_brokens.append(g)
            for g in list(set(self.gad_candidates.keys()) - (self.gads_moving_broken | self.gads_ipr_broken)): all_remainings.append(g)
            for (start_addr, size, ropf_start) in self.moving_regions: all_movings.append((start_addr, start_addr + size))

            pickle.dump(all_gads, gad_stat_data)
            pickle.dump(all_brokens, gad_stat_data)
            pickle.dump(all_remainings, gad_stat_data)
            pickle.dump(all_movings, gad_stat_data, -1)
            gad_stat_data.close()

        stats_data = {
                      # Target information
                       '01 Target': self.target,
                       '02 functions': funcs, '03 blocks': blks, '04 opcodes': ops,

                      # Gadget statistics
                      '05 Total gads': total,
                            '06 gads<5B': small, '07 (%)': _ratio(small, total),
                            '08 gads>=5B': total - small, '09 (%)': 100 - _ratio(total - small, total),
                            '10 Intended': intended, '11 (%)': _ratio(intended, total),
                            '12 Unintended': unintended, '13 (%)': _ratio(unintended, total),
                            '14 Candidates (no reds)': total_nr,
                            '15 Reds': red, '16 (%)': _ratio(red, total),

                      # Result (a) Gadget summary
                      '17 Unintended broken': u_br, '18 Intended broken': i_br,
                      '19 Unintended remained': u_rm, '20 Intended remained': i_rm,
                      '21 Unintended red': unintended_red, '22 Intended red': intended_red,
                      '23 Broken in total': brokens_all,
                            '24 (%)': _ratio(brokens_all, total_nr),
                            '25 (%)_R': _ratio(brokens_all, total),
                      '26 Remained in total': u_rm + i_rm,
                            '27 (%)': 100 - _ratio(brokens_all, total_nr),
                            '28 (%)_R': 100 - _ratio(brokens_all, total),
                      '29 Case 1: Entry gadgets': cnt_c1,
                      '30 Case 2: Block/opcode/CFG not addressed': self.c2,
                      '31 Case 3: gad_start < code_section': self.c3,
                      '32 Case 4: Too small basic block': self.c4,
                      '33 Call preceded in total': cp, '34 Call preceded in red': cp_r,
                      '35 Call preceded remained': self.call_preceded_gads_remained_cnt,

                      # Result (b) Moving result summary
                      '36 M-R': brokens_m_only, '37 M&R': brokens_both, '38 R-M': brokens_r_only,
                      '39 [U]M-R': u_m_only_gads, '40 [I]M-R': i_m_only_gads,
                      '41 [U]M&R': u_bb_gads, '42 [I]M&R': i_bb_gads,
                      '43 [U]R-M': u_r_only_gads, '44 [I]R-M': i_r_only_gads,
                      '45 M+R': brokens_all,
                            '46 (%)': _ratio(brokens_all, total_nr),
                            '47 (%)_R': _ratio(brokens_all, total),
                      '48 [U]M+R': u_m_only_gads + u_r_only_gads + u_bb_gads,
                      '49 [I]M+R': i_m_only_gads + i_r_only_gads + i_bb_gads,
                      '50 Broken by moving': brokens_m_only + brokens_both,
                            '51 (%)': _ratio(brokens_m_only + brokens_both, total_nr),
                            '52 (%)_R': _ratio(brokens_m_only + brokens_both, total),
                      '53 Broken by IPR': brokens_r_only + brokens_both,
                            '54 (%)': _ratio(brokens_r_only + brokens_both, total_nr),
                            '55 (%)_R': _ratio(brokens_r_only + brokens_both, total),
                      '56 Selected movings': self.single_jmps + self.pair_jmps,
                      '57 Single jmps': self.single_jmps,
                      '58 (%)': _ratio(self.single_jmps, self.pair_jmps + self.single_jmps),
                      '59 Pair jmps': self.pair_jmps,
                      '60 (%)': _ratio(self.pair_jmps, self.pair_jmps + self.single_jmps),
                      '61 Before size (B)': before_size, '62 After size (B)': after_size,
                            '63 Inc size (B)': after_size - before_size,
                            '64 Inc rate (%)': _ratio(after_size - before_size, before_size),
                      # Others
                      '65 Elapsed time': e_time
                    }

        # Write all results in the report file
        if not os.path.exists(RESULT_FILE):
            f = open(RESULT_FILE, "w")
            for item in sorted(stats_data.keys()):
                f.write(str(item) + ', ')
            f.write('\n')

        with open(RESULT_FILE, "a") as f:
            data = ''
            for sd in sorted(stats_data.keys()):
                data += str(stats_data[sd]) + ', '
            f.write(data + '\n')

        f.close()

    # This function is to combine output and reloc.dat (Dirty but..)
    def _merge_file(self, output):
        reloc_file = '/tmp/reloc.dat' if os.name == 'posix' else 'reloc.dat'
        final_file = output.split('.')[0] + '_final.' + output.split('.')[1]
        pe_out = pefile.PE(output)

        for s in range(pe_out.FILE_HEADER.NumberOfSections):
            if 'reloc' in pe_out.sections[s].Name:
                reloc_ptr = pe_out.sections[s].PointerToRawData
                break
        reloc_size = pe_out.sections[s].SizeOfRawData

        with open(output, 'rb') as f1:
            result_file = f1.read()
        with open(reloc_file, 'rb') as f2:
            reloc_data = f2.read()

        # Merge process: [pre_reloc_bin + new_reloc_bin + post_reloc_bin]
        if reloc_size - len(reloc_data) >= 0:
            merged = result_file[:reloc_ptr] + reloc_data + \
                     (reloc_size - len(reloc_data)) * '\x00' + \
                     result_file[reloc_ptr + reloc_size:]
        else:
            # This would happen rarely, but possible
            print 'The size of adjusted relocation is larger than that of original one..'
            sys.exit(1)

        with open(final_file, 'wb') as f3:
            f3.write(merged)

        pe_out.close()
        f1.close()
        f2.close()
        f3.close()
        os.remove(reloc_file)

        # The following does not work in windows only!
        if os.name == 'posix':
            os.remove(output)
            os.rename(final_file, output)

    def auto_disp(self, input_file, output_file, rand=False, DEBUG=False):
        """
        Proceed all moving steps automatically as a main function
        """

        def _show_elapsed(start, end):
            elapsed = end - start
            time_format = ''
            if elapsed > 86400:
                time_format += str(int(elapsed // 86400)) + ' day(s) '
                elapsed = elapsed % 86400
            if elapsed > 3600:
                time_format += str(int(elapsed // 3600)) + ' hour(s) '
                elapsed = elapsed % 3600
            if elapsed > 60:
                time_format += str(int(elapsed // 60)) + ' min(s) '
                elapsed = elapsed % 60
            time_format += str(round(elapsed, 3)) + ' sec(s)'
            return time_format

        # Check if call preceded gadgets are broken after moving
        def call_preceded_gad_broken_check():
            for rg in self.all_remained_gads:
                if rg in self.all_call_preceded_addrs.values():
                    self.call_preceded_gads_remained_cnt += 1

        start = time.time()
        # [1] Gather codes and blocks
        self._show_steps(1)
        (all_func_blocks, all_opcodes) = self._get_codeblocks()
        self.all_func_blocks = all_func_blocks
        self.all_opcodes = sorted(all_opcodes)

        # This will help to check if a gadget is call-preceded one
        for (op_start, op_end) in self.all_opcodes:
            import pydasm
            bs = self.pe.get_data(op_start - self.peinfo.getImageBase(), op_end - op_start)
            instr = pydasm.get_instruction(bs, pydasm.MODE_32)

            if instr is not None and 'call' in pydasm.get_mnemonic_string(instr, pydasm.FORMAT_INTEL):
                self.all_call_preceded_addrs[op_start] = op_end  # a pair of 'call' and 'gadget' (if any)

        # [2] Compute candidate gadgets
        self._show_steps(2)
        gc = GadCandidates(self.target)
        self.gad_candidates, self.gads_in_red = gc.get_gads()
        gc.call_preceded_gad_check(self.all_call_preceded_addrs)
        gc.gad_stats()

        # [3] Organize funcs, blocks, and gadgets to select patching regions
        self._show_steps(3)
        self.all_funcs = sorted(self.all_func_blocks)
        self.all_blocks = self._get_all_blocks(self.all_funcs)
        self.base_fbo_info()

        # [4] Simulate randomization (with the option -k)
        self._show_steps(4)
        if rand:
            import cPickle
            diff_result = input_file + '.dmp-diffs'
            if not os.path.isfile(diff_result):
                self._get_randomize_diffs(gc, DEBUG)
                with open(diff_result, 'wb') as dmp_f:
                    cPickle.dump(self.gads_ipr_broken, dmp_f)
            else:
                with open(diff_result, 'rb') as dmp_f:
                    self.gads_ipr_broken = cPickle.load(dmp_f)
                print "\tFound previous result and loaded..."
        else:
            print "\tSkipped the transformation phase this time!"

        # [5] Decide the regions for displacement and update relative addresses if necessary
        self._show_steps(5)
        s = time.time()
        self._decide_displacement(1, gc.intended, rand, DEBUG)
        call_preceded_gad_broken_check()
        e = time.time()

        # [6] Write new PE fle all candidate regions have been displaced
        self._show_steps(6)
        self._patch_pe(output_file, DEBUG)

        if self.peinfo.getRelocationSize() > 0:
            self._merge_file(output_file)

        # [7] Show the comparison & evaluation from two techniques: IPR and displacement
        self._show_steps(7)
        end = time.time()
        elapsed = _show_elapsed(start, end)
        self._write_report(gc, elapsed)

        # [8] Done!
        self._show_steps(8)
        print '\tThe requested operation took %s in total!' % elapsed
        print '\tAll stats are saved into ', RESULT_FILE
