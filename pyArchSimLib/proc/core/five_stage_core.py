# five_stage_core.py
# --------------------------------------------------------------------
# Simple five-stage pipelined core.
#
# Author\ Khalid Al-Hawaj
# Date  \ 5 May 2025

import random

from pyArchSimLib.arch.isa import mips32
from pyArchSimLib.predictor.gshare import GSharePredictor


class FiveStageInorderCore():
  def __init__(s, entry_point = 0x0400_0000):
    # Cycle Count
    s.cycle_count = 0

    # This processor can only do MIPS32 for now.
    s.arch = mips32.arch()

    # With every squash, we increment the epoch
    # hawajkm: this works only because of in-order
    #          execution
    s.epoch     = 0
    s.squash    = False
    s.squash_pc = 0x00000000

    # Pipeline Registers
    s.f2d = None
    s.d2x = None
    s.x2m = None
    s.m2w = None

    # Buffers
    s.inst_D = None

    # Flags
    s.block_D   = False
    s.block_D_s = None

    # Mini-scoreboard
    s.ready_list   = [0 for _ in range(32)]
    s.ready_list_s = [0 for _ in range(32)]

    # Execution state
    s.pc   = entry_point
    s.rf   = [random.randint(0, 1 << 32) for _ in range(32)]
    s.rf_s = [None                       for _ in range(32)]

    # MIPS32 and RISC-V(?)
    s.rf[ 0] = 0x00000000
    s.rf[29] = 0x80000000

    # Forwarding Network
    s.forwarding_network = {}

    # Memory calls
    s.MemReadFunct  = None
    s.MemWriteFunct = None

    # Memory interface
    s.iMemCanReq    = None
    s.iMemSendReq   = None
    s.iMemHasResp   = None
    s.iMemRecvResp  = None

    s.dMemCanReq    = None
    s.dMemSendReq   = None
    s.dMemHasResp   = None
    s.dMemRecvResp  = None

    # Exit
    s.exit_code = 0
    s.exit      = False
   # Branch predictor slot (filled by the processor)
    s.bp = None
    # Flags
    s.roi       = False
    s.inst_c    = False

  def getExitStatus(s):
    return s.exit, s.exit_code

  # Flags
  def roiFlag(s):
    return s.roi
  def instCompletionFlag(s):
    return s.inst_c

  # Configure memory calls
  def setMemReadFunct(s, MemReadFunct):
    s.MemReadFunct  = MemReadFunct
  def setMemWriteFunct(s, MemWriteFunct):
    s.MemWriteFunct = MemWriteFunct

  # Configure ports
  def setIMemCanReq(s, iMemCanReq):
    s.iMemCanReq   = iMemCanReq
  def setIMemSendReq(s, iMemSendReq):
    s.iMemSendReq  = iMemSendReq
  def setIMemHasResp(s, iMemHasResp):
    s.iMemHasResp  = iMemHasResp
  def setIMemRecvResp(s, iMemRecvResp):
    s.iMemRecvResp = iMemRecvResp

  def setDMemCanReq(s, dMemCanReq):
    s.dMemCanReq   = dMemCanReq
  def setDMemSendReq(s, dMemSendReq):
    s.dMemSendReq  = dMemSendReq
  def setDMemHasResp(s, dMemHasResp):
    s.dMemHasResp  = dMemHasResp
  def setDMemRecvResp(s, dMemRecvResp):
    s.dMemRecvResp = dMemRecvResp

  #======================
  # Initializing Squash
  #======================
  def init_squash(s, npc):
    s.squash    = True
    s.squash_pc = npc

  def train_bp(s, pc, npc, br_type, outcome):
    """
    Called once per retired branch:
      pc        = branch PC,
      npc       = actual next-PC,
      br_type   = 1 for conditional, 2 for unconditional,
      outcome   = 1 if taken else 0.
    """
    if not s.bp:
        return

    # count the prediction
    s.bp.predictions += 1

    # ask the predictor what it predicted
    pred = s.bp.predict(pc)
    actual = (outcome == 1)

    # mispredict?
    if pred != actual:
        s.bp.mispredictions += 1

    # update the predictor’s state
    s.bp.update(pc, actual)


  # Stages are implemented as functions
  #=====================================================================
  # Fetch Stage
  #=====================================================================
    #=====================================================================
  # Fetch Stage (updated for branch steering)
  #=====================================================================
  def f(s):
      lt_buf = ''

      # Only fetch if fetch→decode register is empty
      if s.f2d is None:
          # Can we issue a new instruction‐fetch?
          if s.iMemCanReq():
              # Use whatever PC decode last set (fall-through or predicted)
              ppc = s.pc
              # Default next-PC is sequential
              npc = s.pc + 4

              # Build and send the fetch request
              req = {
                  'op':   0,
                  'addr': ppc,
                  'data': None,
                  'size': 4,
                  'mask': None,
                  'tag':  s.epoch
              }
              s.iMemSendReq(req)

              # Snapshot into f→d
              s.f2d = {'pc': ppc, 'npc': npc}

              # Advance s.pc to npc (which may have been speculatively set earlier)
              s.pc = npc

              # Format the PC for the linetrace (show “–” if we just squashed)
              ppc_str = '-' if s.squash else f"{ppc:#010x}"
              lt_buf  = f"{ppc_str:<10}"
          else:
              # Memory port busy
              lt_buf = f"{'S_imem':<10}"
      else:
          # Decode is holding this slot
          lt_buf = f"{'S <<<':<10}"

      return lt_buf


  #=====================================================================
  # Decode Stage
  #=====================================================================
  ### Aux methods and functions
  def makeDinst(s):
    dinst = {}
    dinst['inst'    ] = 0
    dinst['mnemonic'] = 'undef'
    dinst['squashed'] = False
    dinst['rs'      ] = 0
    dinst['rs_data' ] = 0xdeadbeef
    dinst['rt'      ] = 0
    dinst['rt_data' ] = 0xdeadcafe
    dinst['rd'      ] = 0
    dinst['imm16'   ] = 0
    dinst['imm26'   ] = 0
    dinst['isMem'   ] = False
    dinst['pc'      ] = 0
    dinst['npc'     ] = 0
    dinst['dep'     ] = {}
    dinst['dep'     ]['R'] = []
    dinst['dep'     ]['W'] = []
    dinst['wb_data' ] = None
    dinst['wb_en'   ] = False

    return dinst

  def squashDinst(s, dinst):
    dinst['mnemonic'] = '-'
    dinst['squashed'] = True
    dinst['rs'      ] = 0
    dinst['rs_data' ] = 0xdeadbeef
    dinst['rt'      ] = 0
    dinst['rs_data' ] = 0xdeadcafe
    dinst['rd'      ] = 0
    dinst['imm16'   ] = 0
    dinst['imm26'   ] = 0
    dinst['isMem'   ] = False
    dinst['dep'     ] = {}
    dinst['dep'     ]['R'] = []
    dinst['dep'     ]['W'] = []
    dinst['wb_data' ] = None
    dinst['wb_en'   ] = False

    return dinst

  def decodeDinst(s, inst):
    mnemonic = 'undef'
    isMem    = False

    # Fields
    opcode = (inst >> 26) & 0x0000003f
    rs     = (inst >> 21) & 0x0000001f
    rt     = (inst >> 16) & 0x0000001f
    cond   = (inst >> 16) & 0x0000001f
    rd     = (inst >> 11) & 0x0000001f
    shamt  = (inst >>  6) & 0x0000001f
    funct  = (inst >>  0) & 0x0000003f
    imm16  = (inst >>  0) & 0x0000ffff
    imm26  = (inst >>  0) & 0x03ffffff

    if opcode == 0x0:
      if   funct == 0x00: mnemonic = 'sll'
      elif funct == 0x02: mnemonic = 'srl'
      elif funct == 0x03: mnemonic = 'sra'
      elif funct == 0x04: mnemonic = 'sllv'
      elif funct == 0x06: mnemonic = 'srlv'
      elif funct == 0x07: mnemonic = 'srav'
      elif funct == 0x08: mnemonic = 'jr'
      elif funct == 0x0c: mnemonic = 'syscall'
      elif funct == 0x18:
        if   shamt == 0x02: mnemonic = 'mul'
        elif shamt == 0x03: mnemonic = 'muh'
      elif funct == 0x19:
        if   shamt == 0x02: mnemonic = 'mulu'
        elif shamt == 0x03: mnemonic = 'muhu'
      elif funct == 0x1a:
        if   shamt == 0x02: mnemonic = 'div'
        elif shamt == 0x03: mnemonic = 'mod'
      elif funct == 0x1b:
        if   shamt == 0x02: mnemonic = 'divu'
        elif shamt == 0x03: mnemonic = 'modu'
      elif funct == 0x20: mnemonic = 'add'
      elif funct == 0x21: mnemonic = 'addu'
      elif funct == 0x22: mnemonic = 'sub'
      elif funct == 0x23: mnemonic = 'subu'
      elif funct == 0x24: mnemonic = 'and'
      elif funct == 0x25: mnemonic = 'or'
      elif funct == 0x26: mnemonic = 'xor'
      elif funct == 0x27: mnemonic = 'nor'
    elif opcode == 0x01:
      if   cond == 0x00: mnemonic = 'bltz'
      elif cond == 0x01: mnemonic = 'bgez'
    elif opcode == 0x02: mnemonic = 'j'
    elif opcode == 0x03: mnemonic = 'jal'
    elif opcode == 0x04: mnemonic = 'beq'
    elif opcode == 0x05: mnemonic = 'bne'
    elif opcode == 0x06: mnemonic = 'blez'
    elif opcode == 0x07: mnemonic = 'bgtz'
    elif opcode == 0x08: mnemonic = 'addi'
    elif opcode == 0x09: mnemonic = 'addiu'
    elif opcode == 0x0c: mnemonic = 'andi'
    elif opcode == 0x0d: mnemonic = 'ori'
    elif opcode == 0x0e: mnemonic = 'xori'
    elif opcode == 0x0f: mnemonic = 'lui'
    elif opcode == 0x20: mnemonic = 'lb'
    elif opcode == 0x21: mnemonic = 'lh'
    elif opcode == 0x23: mnemonic = 'lw'
    elif opcode == 0x24: mnemonic = 'lbu'
    elif opcode == 0x25: mnemonic = 'lhu'
    elif opcode == 0x28: mnemonic = 'sb'
    elif opcode == 0x29: mnemonic = 'sh'
    elif opcode == 0x2b: mnemonic = 'sw'

    # Memory
    if   mnemonic == 'lb' : isMem = True
    elif mnemonic == 'lbu': isMem = True
    elif mnemonic == 'lh' : isMem = True
    elif mnemonic == 'lhu': isMem = True
    elif mnemonic == 'lw' : isMem = True
    elif mnemonic == 'sb' : isMem = True
    elif mnemonic == 'sh' : isMem = True
    elif mnemonic == 'sw' : isMem = True

    # Done
    return mnemonic, isMem

  ### Decode stage itself
    #=====================================================================
  # Decode Stage
  #=====================================================================
    #=====================================================================
  # Decode Stage
  #=====================================================================
  def d(s):
      lt_buf = ''

      if s.f2d is not None and s.d2x is None:
          # we have a fetch→decode entry and decode→execute is free
          if (s.iMemHasResp() or (s.inst_D is not None)) and not s.block_D:
              # fetch response
              if s.inst_D is None:
                  s.inst_D = s.iMemRecvResp()
              resp = s.inst_D

              pc    = s.f2d['pc']
              npc   = s.f2d['npc']
              epoch = resp['tag']

              # may need to squash
              squashed = (epoch < s.epoch) or s.squash
              assert resp['addr'] == pc

              # reassemble instruction
              inst = 0
              for i in range(resp['size']):
                  inst |= (resp['data'][i] << (8 * i))

              # extract fields
              rs    = (inst >> 21) & 0x1F
              rt    = (inst >> 16) & 0x1F
              rd    = (inst >> 11) & 0x1F
              shamt = (inst >>  6) & 0x1F
              imm16 = inst & 0xFFFF
              imm26 = inst & 0x03FFFFFF

              # build dinst
              dinst = s.makeDinst()
              dinst['inst']   = inst
              dinst['rs']     = rs
              dinst['rt']     = rt
              dinst['rd']     = rd
              dinst['shamt']  = shamt
              dinst['imm16']  = imm16
              dinst['imm26']  = imm26
              dinst['pc']     = pc
              dinst['npc']    = npc

              # decode mnemonic + mem‐flag
              mnemonic, isMem = s.decodeDinst(inst)
              dinst['mnemonic'] = mnemonic
              dinst['isMem']    = isMem

              if squashed:
                  s.squashDinst(dinst)

              if squashed:
                  # bubble through
                  s.inst_D = None
                  s.d2x    = dinst
                  s.f2d    = None
                  lt_buf   = f"{dinst['mnemonic']:<8}"
              else:
                  # dependency tracking
                  validInst = (mnemonic in s.arch['insts'])
                  reads_rs = reads_rt = write_rd = write_rt = False
                  if validInst:
                      inst_def    = s.arch['insts'][mnemonic]
                      inst_syntax = inst_def['syntax']
                      if mnemonic == 'jal':
                          write_rd = True
                          rd = 31
                      for op in inst_syntax.split(','):
                          if op == 'd' and rd != 0:    write_rd = True
                          if op == 'T' and rt != 0:    write_rt = True
                          if op == 's':                reads_rs = True
                          if op == 't':                reads_rt = True
                          if op == 'm':                reads_rs = True
                      if write_rd: dinst['dep']['W'].append(rd)
                      if write_rt: dinst['dep']['W'].append(rt)
                      if reads_rs: dinst['dep']['R'].append(rs)
                      if reads_rt: dinst['dep']['R'].append(rt)

                  # forwarding checks
                  xInst = s.forwarding_network['X']
                  mInst = s.forwarding_network['M']
                  wInst = s.forwarding_network['W']
                  rs_src = rt_src = -1
                  if reads_rs and s.ready_list[rs] != 0:
                      if xInst and rs in xInst['dep']['W']:
                          rs_src = -1
                      elif mInst and rs in mInst['dep']['W'] and not mInst['isMem']:
                          rs_src = 1
                      elif wInst and rs in wInst['dep']['W']:
                          rs_src = 2
                  else:
                      rs_src = 0
                  if reads_rt and s.ready_list[rt] != 0:
                      if xInst and rt in xInst['dep']['W']:
                          rt_src = -1
                      elif mInst and rt in mInst['dep']['W'] and not mInst['isMem']:
                          rt_src = 1
                      elif wInst and rt in wInst['dep']['W']:
                          rt_src = 2
                  else:
                      rt_src = 0

                  stall_D = (rs_src < 0) or (rt_src < 0)

                  # syscall stall
                  stall_Syscall = False
                  if mnemonic == 'syscall' and sum(s.ready_list) > 0:
                      stall_Syscall = True

                  if stall_Syscall:
                      lt_buf = f"{'S |>>':<8}"
                  elif not stall_D:
                      # read regs
                      if reads_rs:
                          if rs_src == 0:
                              dinst['rs_data'] = s.rf[rs]
                          elif rs_src == 1:
                              dinst['rs_data'] = mInst['wb_data']
                          else:
                              dinst['rs_data'] = wInst['wb_data']
                      if reads_rt:
                          if rt_src == 0:
                              dinst['rt_data'] = s.rf[rt]
                          elif rt_src == 1:
                              dinst['rt_data'] = mInst['wb_data']
                          else:
                              dinst['rt_data'] = wInst['wb_data']

                      # update scoreboard
                      if write_rd:
                          s.ready_list[rd] += 1
                      if write_rt:
                          s.ready_list[rt] += 1

                      # ───────────────────────────────────────────────
                      # Branch-Prediction Steering (fix!)
                      # ───────────────────────────────────────────────
                      pred_npc = npc
                      if s.bp and mnemonic in ('beq','bne','bltz','bgez','blez','bgtz'):
                          taken = s.bp.predict(pc)
                          offset = s.signed(s.sext(imm16,16)) << 2
                          pred_npc = (pc + 4 + offset) if taken else (pc + 4)
                          dinst['npc']        = pred_npc
                          dinst['pred_taken'] = taken
                          s.pc                = pred_npc
                      else:
                          dinst['npc'] = pc + 4
                          s.pc         = pc + 4
                      # ───────────────────────────────────────────────

                      # resolve branch, train & squash
                      outcome = 0
                      br_type = 0
                      if mnemonic == 'j':
                          high = pc & 0xF0000000
                          npc  = high | (imm26 << 2)
                          br_type, outcome = 2, 1
                      elif mnemonic == 'jal':
                          high = pc & 0xF0000000
                          npc  = high | (imm26 << 2)
                          br_type, outcome = 2, 1
                      elif mnemonic == 'beq':
                          tpc    = pc + 4 + (s.signed(s.sext(imm16,16)) << 2)
                          bcond  = (dinst['rs_data'] == dinst['rt_data'])
                          br_type, outcome = 1, int(bcond)
                          if bcond:
                              npc = tpc
                      elif mnemonic == 'bne':
                          tpc    = pc + 4 + (s.signed(s.sext(imm16,16)) << 2)
                          bcond  = (dinst['rs_data'] != dinst['rt_data'])
                          br_type, outcome = 1, int(bcond)
                          if bcond:
                              npc = tpc
                      elif mnemonic == 'bltz':
                          tpc    = pc + 4 + (s.signed(s.sext(imm16,16)) << 2)
                          bcond  = (s.signed(dinst['rs_data']) < 0)
                          br_type, outcome = 1, int(bcond)
                          if bcond:
                              npc = tpc
                      elif mnemonic == 'bgez':
                          tpc    = pc + 4 + (s.signed(s.sext(imm16,16)) << 2)
                          bcond  = (s.signed(dinst['rs_data']) >= 0)
                          br_type, outcome = 1, int(bcond)
                          if bcond:
                              npc = tpc
                      elif mnemonic == 'blez':
                          tpc    = pc + 4 + (s.signed(s.sext(imm16,16)) << 2)
                          bcond  = (s.signed(dinst['rs_data']) <= 0)
                          br_type, outcome = 1, int(bcond)
                          if bcond:
                              npc = tpc
                      elif mnemonic == 'bgtz':
                          tpc    = pc + 4 + (s.signed(s.sext(imm16,16)) << 2)
                          bcond  = (s.signed(dinst['rs_data']) > 0)
                          br_type, outcome = 1, int(bcond)
                          if bcond:
                              npc = tpc

                      if mnemonic == 'syscall':
                          s.block_D = True

                      if br_type != 0:
                          s.train_bp(pc, npc, br_type, outcome)
                      if pred_npc != npc:
                          s.init_squash(npc)

                      # advance pipeline
                      s.inst_D = None
                      s.d2x    = dinst
                      s.f2d    = None
                      lt_buf   = f"{mnemonic:<8}"
                  else:
                      lt_buf = f"{'S raw':<8}"
          elif (s.iMemHasResp() or (s.inst_D is not None)) and s.block_D:
              lt_buf = f"{'S >>|':<8}"
          else:
              lt_buf = f"{'S mem':<8}"
      elif s.f2d is not None and s.d2x is not None:
          lt_buf = f"{'S <<<':<8}"
      else:
          lt_buf = f"{'':<8}"

      return lt_buf


  #=====================================================================
  # Aux methods and functions
  #=====================================================================
  def signed(s, val):
    sign = 0x80000000 & val
    val  = 0x7fffffff & val
    return (-1 * sign) + val

  def sext(s, data, sz=16):
    data = data & ((0x1 << sz) - 1)
    sign = data & (0x1 << (sz - 1))
    sign = (sign >> (sz - 1)) ^ 0x1
    sign = ((sign - 1) << sz) & 0xffffffff
    data = data | sign

    return data

  def zext(s, data):
    return data

  def makeMemReadReq(s, addr, size):
    mem_req = {}

    mem_req['op'  ] = 0
    mem_req['data'] = []
    mem_req['addr'] = addr
    mem_req['size'] = size
    mem_req['mask'] = None
    mem_req['tag' ] = None

    return mem_req

  def makeMemWriteReq(s, addr, data, size):
    mem_req = {}

    byte_array = []
    for i in range(size):
      byte_array.append(data & 0xff)
      data = data >> 8

    mem_req['op'  ] = 1
    mem_req['data'] = byte_array
    mem_req['addr'] = addr
    mem_req['size'] = size
    mem_req['mask'] = None
    mem_req['tag' ] = None

    return mem_req

  #=====================================================================
  # Execute Stage
  #=====================================================================
  def x(s):
    if   s.d2x is not None and s.x2m is     None:
      dinst = s.d2x

      if dinst['squashed']:
        # Go forward
        s.x2m = dinst
        s.d2x = None

        return '{: <8}'.format('-')

      # Check memory if needed
      #                    memory stall condition
      #                             |
      #        /--------------------|--------------------\
      #        vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
      elif not (dinst['isMem'] and not s.dMemCanReq()):
        # Read everything
        inst     = dinst['inst'    ]
        mnemonic = dinst['mnemonic']
        squashed = dinst['squashed']
        rs       = dinst['rs'      ]
        rs_data  = dinst['rs_data' ]
        rt       = dinst['rt'      ]
        rt_data  = dinst['rt_data' ]
        rd       = dinst['rd'      ]
        shamt    = dinst['shamt'   ]
        wb_data  = dinst['wb_data' ]
        wb_en    = dinst['wb_en'   ]
        imm16    = dinst['imm16'   ]
        imm26    = dinst['imm26'   ]
        isMem    = dinst['isMem'   ]
        pc       = dinst['pc'      ]
        pred_npc = dinst['npc'     ]
        dep      = dinst['dep'     ]

        # The actual npc is initialized as the predicted one
        npc = pred_npc

        # Branch
        outcome = 0 # Not taken
        br_type = 0 # Not control-flow

        #================#
        #      ALUs      #
        #================#
        if   mnemonic == 'add'  :
          op1 = rs_data
          op2 = rt_data
          opD = op1 + op2
          wb_data = (opD) & 0xffffffff
          wb_en = True
        elif mnemonic == 'addu' :
          op1 = rs_data
          op2 = rt_data
          opD = op1 + op2
          wb_data = (opD) & 0xffffffff
          wb_en = True
        elif mnemonic == 'sub'  :
          op1 = rs_data
          op2 = rt_data
          opD = op1 - op2
          wb_data = (opD) & 0xffffffff
          wb_en = True
        elif mnemonic == 'subu' :
          op1 = rs_data
          op2 = rt_data
          opD = op1 - op2
          wb_data = (opD) & 0xffffffff
          wb_en = True
        elif mnemonic == 'and'  :
          op1 = rs_data
          op2 = rt_data
          opD = op1 & op2
          wb_data = (opD) & 0xffffffff
          wb_en = True
        elif mnemonic == 'or'   :
          op1 = rs_data
          op2 = rt_data
          opD = op1 | op2
          wb_data = (opD) & 0xffffffff
          wb_en = True
        elif mnemonic == 'xor'  :
          op1 = rs_data
          op2 = rt_data
          opD = op1 ^ op2
          wb_data = (opD) & 0xffffffff
          wb_en = True
        elif mnemonic == 'nor'  :
          op1 = rs_data
          op2 = rt_data
          opD = ~(op1 | op2)
          wb_data = (opD) & 0xffffffff
          wb_en = True

        elif mnemonic == 'addi' :
          op1 = rs_data
          op2 = s.sext(imm16)
          opD = op1 + op2
          wb_data = (opD) & 0xffffffff
          wb_en = True
        elif mnemonic == 'addiu':
          op1 = rs_data
          op2 = s.sext(imm16)
          opD = op1 + op2
          wb_data = (opD) & 0xffffffff
          wb_en = True
        elif mnemonic == 'andi' :
          op1 = rs_data
          op2 = s.zext(imm16)
          opD = op1 & op2
          wb_data = (opD) & 0xffffffff
          wb_en = True
        elif mnemonic == 'ori'  :
          op1 = rs_data
          op2 = s.zext(imm16)
          opD = op1 | op2
          wb_data = (opD) & 0xffffffff
          wb_en = True
        elif mnemonic == 'xori' :
          op1 = rs_data
          op2 = s.zext(imm16)
          opD = op1 ^ op2
          wb_data = (opD) & 0xffffffff
          wb_en = True
        elif mnemonic == 'lui' :
          op1 = s.zext(imm16)
          opD = op1 << 16
          wb_data = (opD) & 0xffffffff
          wb_en = True

        elif mnemonic == 'sll'  :
          op1 = rs_data
          op2 = shamt
          opD = op1 << op2
          wb_data = (opD) & 0xffffffff
          wb_en = True
        elif mnemonic == 'srl'  :
          op1 = rs_data
          op2 = shamt
          opD = op1 >> op2
          wb_data = (opD) & 0xffffffff
          wb_en = True
        elif mnemonic == 'sra'  : pass
        elif mnemonic == 'sllv' :
          op1 = rs_data
          op2 = rt_data
          opD = op1 << op2
          wb_data = (opD) & 0xffffffff
          wb_en = True
        elif mnemonic == 'srlv' :
          op1 = rs_data
          op2 = rt_data
          opD = op1 >> op2
          wb_data = (opD) & 0xffffffff
          wb_en = True
        elif mnemonic == 'srav' : pass

        #================#
        #  MUL/DIV/MOD   #
        #================#
        elif mnemonic == 'mul'  :
          op1 = s.signed(rs_data)
          op2 = s.signed(rt_data)
          opD = op1 * op2
          wb_data = (opD) & 0xffffffff
          wb_en = True
        elif mnemonic == 'muh'  :
          op1 = s.signed(rs_data)
          op2 = s.signed(rt_data)
          opD = (op1 * op2) / (2 ** 32)
          wb_data = (opD) & 0xffffffff
          wb_en = True
        elif mnemonic == 'mulu' :
          op1 = rs_data
          op2 = rt_data
          opD = op1 * op2
          wb_data = (opD) & 0xffffffff
          wb_en = True
        elif mnemonic == 'muhu' :
          op1 = rs_data
          op2 = rt_data
          opD = (op1 * op2) / (2 ** 32)
          wb_data = (opD) & 0xffffffff
          wb_en = True

        elif mnemonic == 'div'  :
          op1 = s.signed(rs_data)
          op2 = s.signed(rt_data)
          opD = int(op1 / op2)
          wb_data = (opD) & 0xffffffff
          wb_en = True
        elif mnemonic == 'mod'  :
          op1 = s.signed(rs_data)
          op2 = s.signed(rt_data)
          opD = int(op1 % op2)
          wb_data = (opD) & 0xffffffff
          wb_en = True
        elif mnemonic == 'divu' :
          op1 = rs_data
          op2 = rt_data
          opD = int(op1 / op2)
          wb_data = (opD) & 0xffffffff
          wb_en = True
        elif mnemonic == 'modu' :
          op1 = rs_data
          op2 = rt_data
          opD = int(op1 % op2)
          wb_data = (opD) & 0xffffffff
          wb_en = True

        #================#
        #     Memory     #
        #================#
        elif mnemonic == 'lb'   :
          op1 = rs_data
          op2 = s.signed(s.sext(imm16))
          ea  = op1 + op2

          mem_req = s.makeMemReadReq(ea, 1)
          s.dMemSendReq(mem_req)

          wb_data = None
          wb_en = True
        elif mnemonic == 'lh'   :
          op1 = rs_data
          op2 = s.signed(s.sext(imm16))
          ea  = op1 + op2

          mem_req = s.makeMemReadReq(ea, 2)
          s.dMemSendReq(mem_req)

          wb_data = None
          wb_en = True
        elif mnemonic == 'lw'   :
          op1 = rs_data
          op2 = s.signed(s.sext(imm16))
          ea  = op1 + op2

          mem_req = s.makeMemReadReq(ea, 4)
          s.dMemSendReq(mem_req)

          wb_data = None
          wb_en = True
        elif mnemonic == 'lbu'  :
          op1 = rs_data
          op2 = s.signed(s.sext(imm16))
          ea  = op1 + op2

          mem_req = s.makeMemReadReq(ea, 1)
          s.dMemSendReq(mem_req)

          wb_data = None
          wb_en = True
        elif mnemonic == 'lhu'  :
          op1 = rs_data
          op2 = s.signed(s.sext(imm16))
          ea  = op1 + op2

          mem_req = s.makeMemReadReq(ea, 2)
          s.dMemSendReq(mem_req)

          wb_data = None
          wb_en = True
        elif mnemonic == 'sb'   :
          op1 = rs_data
          op2 = s.signed(s.sext(imm16))
          ea  = op1 + op2
          data = rt_data

          mem_req = s.makeMemWriteReq(ea, data, 1)
          s.dMemSendReq(mem_req)

          wb_data = None
          wb_en = False
        elif mnemonic == 'sh'   :
          op1 = rs_data
          op2 = s.signed(s.sext(imm16))
          ea  = op1 + op2
          data = rt_data

          mem_req = s.makeMemWriteReq(ea, data, 2)
          s.dMemSendReq(mem_req)

          wb_data = None
          wb_en = False
        elif mnemonic == 'sw'   :
          op1 = rs_data
          op2 = s.signed(s.sext(imm16))
          ea  = op1 + op2
          data = rt_data

          mem_req = s.makeMemWriteReq(ea, data, 4)
          s.dMemSendReq(mem_req)

          wb_data = None
          wb_en = False

        #================#
        #  Control Flow  #
        #================#
        elif mnemonic == 'beq'  :
          op1 = rs_data
          op2 = rt_data
          tpc = pc + 4 + (s.signed(s.sext(imm16, 16)) << 2)
          bcond = op1 == op2
          br_type = 1
          outcome = 1 if bcond else 0
          if bcond: npc = tpc
        elif mnemonic == 'bne'  :
          op1 = rs_data
          op2 = rt_data
          tpc = pc + 4 + (s.signed(s.sext(imm16, 16)) << 2)
          bcond = op1 != op2
          br_type = 1
          outcome = 1 if bcond else 0
          if bcond: npc = tpc
        elif mnemonic == 'bltz' :
          op1 = rs_data
          op2 = rt_data
          tpc = pc + 4 + (s.signed(s.sext(imm16, 16)) << 2)
          bcond = s.signed(op1) < 0
          br_type = 1
          outcome = 1 if bcond else 0
          if bcond: npc = tpc
        elif mnemonic == 'bgez' :
          op1 = rs_data
          op2 = rt_data
          tpc = pc + 4 + (s.signed(s.sext(imm16, 16)) << 2)
          bcond = s.signed(op1) >= 0
          br_type = 1
          outcome = 1 if bcond else 0
          if bcond: npc = tpc
        elif mnemonic == 'blez' :
          op1 = rs_data
          op2 = rt_data
          tpc = pc + 4 + (s.signed(s.sext(imm16, 16)) << 2)
          bcond = s.signed(op1) <= 0
          br_type = 1
          outcome = 1 if bcond else 0
          if bcond: npc = tpc
        elif mnemonic == 'bgtz' :
          op1 = rs_data
          op2 = rt_data
          tpc = pc + 4 + (s.signed(s.sext(imm16, 16)) << 2)
          bcond = s.signed(op1) > 0
          br_type = 1
          outcome = 1 if bcond else 0
          if bcond: npc = tpc

        elif mnemonic == 'j'    : pass  # Nothing to do
        elif mnemonic == 'jal'  :
          wb_data = pc + 4
          wb_en = True
        elif mnemonic == 'jr'   :
          op1 = rs_data
          npc = op1
          br_type = 2
          outcome = 1

        #================#
        #    Syscall     #
        #================#
        elif mnemonic == 'syscall':
          # hawajkm: due to its execution nature, syscall causes a
          #          pipeline drain; thus, we don't have to worry about
          #          any dependencies and we can just read the current
          #          execution context as-is.

          # Get all arguments
          #arg0 = s.rf[4]
          #arg1 = s.rf[5]
          #arg2 = s.rf[6]
          #arg3 = s.rf[7]

          sc_code = s.rf[2]

          #v0 = s.execute_sc(sc_code, arg0, arg1, arg2, arg3)
          s.execute_sc(sc_code)

        #================#
        #   Undefined    #
        #================#
        elif mnemonic == 'undef':
          print('')
          print('  Error! Encountered an undefined instruction')
          print('    - inst: {:#010x}'.format(dinst['inst']))
          print('    - pc  : {:#010x}'.format(dinst['pc'  ]))
          print('')
          print('')
          exit(-127)

        # Train BP
        if br_type != 0:
          s.train_bp(pc, npc, br_type, outcome)

        # Initiate a squash if actual npc is different
        # from predicted npc
        if pred_npc != npc:
          s.init_squash(npc)

        # Modify the dinst
        dinst['wb_data'] = wb_data
        dinst['wb_en'  ] = wb_en

        # Go forward
        s.x2m = dinst
        s.d2x = None

        return '{: <8}'.format(dinst['mnemonic'])
      else:
        return '{: <8}'.format('S mem')
    elif s.d2x is not None and s.x2m is not None:
      return '{: <8}'.format('S <<<')
    else:
      return '{: <8}'.format(' ')

  #=====================================================================
  # Memory Stage
  #=====================================================================
  def m(s):
    if   s.x2m is not None and s.m2w is     None:
      dinst = s.x2m

      if dinst['squashed']:
        # Go forward
        s.m2w = dinst
        s.x2m = None

        return '{: <8}'.format('-')

      # Check memory if needed
      #               memory resp stall condition
      #                            |
      #         /------------------|-----------------\
      #         vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
      elif not (dinst['isMem'] and not s.dMemHasResp()):
        # Can process the instructions
        # If we have a memory instruction, we process the memory packet
        if dinst['isMem']:
          mem_resp = s.dMemRecvResp()
          if dinst['wb_en']:
            data = 0
            for i in range(mem_resp['size']):
              data = data | (mem_resp['data'][i] << (8 * i))
            # Extend?
            if   dinst['mnemonic'] == 'lb': data = s.sext(data,  8)
            elif dinst['mnemonic'] == 'lh': data = s.sext(data, 16)
            dinst['wb_data'] = data

        # Go forward
        s.m2w = dinst
        s.x2m = None

        return '{: <8}'.format(dinst['mnemonic'])
      else:
        return '{: <8}'.format('S dmem')
    elif s.x2m is not None and s.m2w is not None:
      return '{: <8}'.format('S <<<')
    else:
      return '{: <8}'.format(' ')

  #=====================================================================
  # Writeback Stage
  #=====================================================================
  def w(s):
    lt_buf = ''

    if s.m2w is not None:
      dinst = s.m2w

      if dinst['squashed']:
        lt_buf = '-'
      else:
        if dinst['mnemonic'] == 'syscall': s.block_D_s = False
        if dinst['wb_en']:
          # Perform writeback
          for reg_idx in dinst['dep']['W']:
            s.rf_s[reg_idx] = dinst['wb_data']
            s.ready_list_s[reg_idx] = s.ready_list[reg_idx] - 1
        # Linetracing
        lt_buf = dinst['mnemonic']

        # We completed an instruction
        s.inst_c = True

      # Keep ticking...
      s.m2w = None

    # Linetracing
    return '{: <8}'.format(lt_buf)

  #=====================================================================
  # Syscall Emulation
  #=====================================================================
  def execute_sc(s, sc_code):
    # Arguments
    arg0 = s.rf[4]
    arg1 = s.rf[5]
    arg2 = s.rf[6]
    arg3 = s.rf[7]
    
    if   sc_code ==  0: pass
    elif sc_code ==  1:
      print('{}'.format(arg0), end='')
    elif sc_code ==  4:
      addr = arg0
      while True:
        byte = s.MemReadFunct(addr, 1)[0]
        if byte == 0: break
        print(chr(byte), end='')
        addr = addr + 1
    elif sc_code == 10:
      s.exit_code = 0
      s.exit      = True
    elif sc_code == 11:
      print(chr(arg0), end='')
    elif sc_code == 17:
      s.exit_code = arg0
      s.exit      = True
    elif sc_code == 88:
      s.roi = not s.roi
    else:
      print('')
      print('  Error! Unknown requested system call.')
      print('    code: {}'.format(sc_code))
      print('')
      print('')

      exit(-126)

  #=====================================================================
  # Tick
  #=====================================================================
  def tick(s):
    # Reset
    s.inst_c = False

    # Eliminate unintentional forwarding from W to D
    # hawajkm: we use shadowed copies
    for i in range(len(s.ready_list_s)):
      s.ready_list_s[i] = None
    for i in range(len(s.rf_s)):
      s.rf_s[i] = None
    s.block_D_s = None

    # Forwarding Network
    # hawajkm: we perform non-aggressive forwarding.
    #          this should guarantee reasonable design
    #          with nice clock frequencies.
    s.forwarding_network['X'] = s.d2x
    s.forwarding_network['M'] = s.x2m
    s.forwarding_network['W'] = s.m2w

    # Tick backwords
    lt_array = []
    lt_array.insert(0, s.w())
    lt_array.insert(0, s.m())
    lt_array.insert(0, s.x())
    lt_array.insert(0, s.d())
    lt_array.insert(0, s.f())

    # Eliminate unintentional forwarding from W to D
    for i in range(len(s.ready_list_s)):
      if s.ready_list_s[i] is not None:
        s.ready_list[i] = s.ready_list_s[i]
    for i in range(len(s.rf_s)):
      if s.rf_s[i] is not None:
        s.rf[i] = s.rf_s[i]
    if s.block_D_s is not None:
      s.block_D = s.block_D_s

    # Handle a squash
    if s.squash:
      s.epoch  = s.epoch + 1
      s.pc     = s.squash_pc
      s.squash = False

    # Linetrace
    s.lt_buf = ''
    for i, lt in enumerate(lt_array):
      if i != 0: s.lt_buf += " | "
      s.lt_buf += lt

  def linetrace(s):
    return s.lt_buf
