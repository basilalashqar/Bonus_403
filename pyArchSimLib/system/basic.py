# File: pyArchSimLib/system/basic.py
# --------------------------------------------------------------------
# A basic system with a five-stage processor and a memory
#
# Author\ Khalid Al-Hawaj
# Date  \ 03 May 2025

from pyArchSimLib.proc import FiveStageInorderProcessor
from pyArchSimLib.mem  import SimpleMultiportedMemory

class BasicSystem:
    def __init__(s,
                 doLinetrace:       bool   = False,
                 cache_type:        str    = 'none',
                 cache_size:        int    = 64*1024,
                 line_size:         int    = 64,
                 hit_latency:       int    = 1,
                 mem_latency:       int    = 10,
                 bp_type:           str    = 'none',
                 bp_history_bits:   int    = 10):
        # 1) Processor with cache & BP
        s.proc = FiveStageInorderProcessor(
            cache_type      = cache_type,
            cache_size      = cache_size,
            line_size       = line_size,
            hit_latency     = hit_latency,
            bp_type         = bp_type,
            bp_history_bits = bp_history_bits
        )

        # 2) Main memory (2 ports, delay=mem_latency)
        s.mem = SimpleMultiportedMemory(nports=2, delay=mem_latency)

        # 3) Wire caches → memory
        s.proc.setMemCanReq(   s.mem.canReq   )
        s.proc.setMemSendReq(  s.mem.sendReq  )
        s.proc.setMemHasResp(  s.mem.hasResp  )
        s.proc.setMemRecvResp( s.mem.recvResp )

        # 4) Syscall memory
        s.proc.setMemReadFunct(  s.mem.read  )
        s.proc.setMemWriteFunct( s.mem.write )

        # 5) Linetrace?
        s.doLinetrace = doLinetrace

    def loader(s, elf):
        for sec in elf['sections']:
            sect     = elf['sections'][sec]
            s.mem.write(sect['base_addr'], sect['bytes'], len(sect['bytes']))

    def getExitStatus(s):      return s.proc.getExitStatus()
    def roiFlag(s):            return s.proc.roiFlag()
    def instCompletionFlag(s): return s.proc.instCompletionFlag()

    def tick(s):
        s.proc.tick()
        s.mem .tick()

    def linetrace(s):
        if not s.doLinetrace: return ''
        return f"{s.proc.linetrace()} | >>=||=>> | {s.mem.linetrace()} |"

