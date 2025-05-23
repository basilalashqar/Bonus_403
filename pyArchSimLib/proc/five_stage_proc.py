# File: pyArchSimLib/proc/five_stage_proc.py
# --------------------------------------------------------------------
# Simple five-stage pipelined processor with optional cache & BP.
#
# Author\ Khalid Al-Hawaj (extended)
# Date  \ 23 May 2025

import random
from pyArchSimLib.proc.core         import FiveStageInorderCore
from pyArchSimLib.mem.cache         import NoCache, DirectMappedCache
from pyArchSimLib.predictor.gshare  import GSharePredictor

class FiveStageInorderProcessor:
    def __init__(self,
                 cache_type:       str = 'none',
                 cache_size:       int = 64*1024,
                 line_size:        int = 64,
                 hit_latency:      int = 1,
                 bp_type:          str = 'none',
                 bp_history_bits:  int = 10):
        # 1) Core
        self.core = FiveStageInorderCore()

        # 2) Branch predictor
        if bp_type == 'gshare':
            self.core.bp = GSharePredictor(history_bits=bp_history_bits)
        else:
            self.core.bp = None

        # 3) Instantiate icache/dcache
        if cache_type == 'direct':
            num_sets = cache_size // line_size
            self.icache = DirectMappedCache(0, num_sets, line_size, hit_latency)
            self.dcache = DirectMappedCache(1, num_sets, line_size, hit_latency)
        else:
            self.icache = NoCache(0)
            self.dcache = NoCache(1)

        # 4) Hook up I-cache to core
        self.core.setIMemCanReq(   self.icache.canReq   )
        self.core.setIMemSendReq(  self.icache.sendReq  )
        self.core.setIMemHasResp(  self.icache.hasResp  )
        self.core.setIMemRecvResp( self.icache.recvResp )

        # 5) Hook up D-cache to core
        self.core.setDMemCanReq(   self.dcache.canReq   )
        self.core.setDMemSendReq(  self.dcache.sendReq  )
        self.core.setDMemHasResp(  self.dcache.hasResp  )
        self.core.setDMemRecvResp( self.dcache.recvResp )

        # 6) Syscall/memory interface passthrough
        self.MemReadFunct   = None
        self.MemWriteFunct  = None

    # Syscall / memory interface
    def setMemReadFunct(s, f):   s.core.setMemReadFunct(f)
    def setMemWriteFunct(s, f):  s.core.setMemWriteFunct(f)

    def setMemCanReq(s, f):
        s.icache.setMemCanReq(f)
        s.dcache.setMemCanReq(f)
    def setMemSendReq(s, f):
        s.icache.setMemSendReq(f)
        s.dcache.setMemSendReq(f)
    def setMemHasResp(s, f):
        s.icache.setMemHasResp(f)
        s.dcache.setMemHasResp(f)
    def setMemRecvResp(s, f):
        s.icache.setMemRecvResp(f)
        s.dcache.setMemRecvResp(f)

    # Flags / exit
    def roiFlag(s):            return s.core.roiFlag()
    def instCompletionFlag(s): return s.core.instCompletionFlag()
    def getExitStatus(s):      return s.core.getExitStatus()

    # Advance one cycle
    def tick(s):
        s.core.tick()
        s.icache.tick()
        s.dcache.tick()

    # Combined linetrace
    def linetrace(s):
        core_lt = s.core.linetrace()
        ic_lt   = s.icache.linetrace()
        dc_lt   = s.dcache.linetrace()
        parts = [core_lt]
        if ic_lt: parts.append(ic_lt)
        if dc_lt: parts.append(dc_lt)
        return ' | '.join(parts)

