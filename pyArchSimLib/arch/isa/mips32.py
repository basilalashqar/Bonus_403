# mips.py
# --------------------------------------------------------------------
#   The MIPS32 ISA description.
#
# Author\ Khalid Al-Hawaj
# Date  \ 05 May 2025

import os
import re
import json
import struct
import random

class mips32():
  __arch__ = None

  #=============================================
  # Formats
  #=============================================
  @classmethod
  def rformat(cls, x):
    opcode = (x['opcode'] & 0x003f) << 26
    rs     = (x['rs'    ] & 0x001f) << 21
    rt     = (x['rt'    ] & 0x001f) << 16
    rd     = (x['rd'    ] & 0x001f) << 11
    shamt  = (x['shamt' ] & 0x001f) <<  6
    funct  = (x['funct' ] & 0x003f) <<  0

    return opcode | rs | rt | rd | shamt | funct

  @classmethod
  def iformat(cls, x):
    opcode = (x['opcode'] & 0x003f) << 26
    rs     = (x['rs'    ] & 0x001f) << 21
    rt     = (x['rt'    ] & 0x001f) << 16
    imm16  = (x['imm16' ] & 0xffff) <<  0

    return opcode | rs | rt | imm16

  @classmethod
  def jformat(cls, x):
    opcode = (x['opcode'] & 0x000003f) << 26
    imm26  = (x['imm26' ] & 0x3ffffff) <<  0

    return opcode | imm26

  #=============================================
  # Definitions
  #=============================================
  @classmethod
  def define_base(cls):
    ret = {}
    ret['syntax'  ] = ''
    ret['assemble'] = None
    ret['opcode'  ] = None
    ret['funct'   ] = None
    ret['cond'    ] = None
    ret['shamt'   ] = None
    ret['code'    ] = None

    return ret

  @classmethod
  def define_alu_1r2r(cls, opcode, funct=0, shamt=None):
    ret = cls.define_base()
    ret['syntax'  ] = 'd,s,t'
    ret['assemble'] = cls.rformat
    ret['opcode'  ] = opcode
    ret['funct'   ] = funct
    ret['shamt'   ] = shamt
    return ret

  @classmethod
  def define_alu_1r1r1s(cls, opcode, funct=0, shamt=None):
    ret = cls.define_base()
    ret['syntax'  ] = 'd,s,S'
    ret['assemble'] = cls.rformat
    ret['opcode'  ] = opcode
    ret['funct'   ] = funct
    ret['shamt'   ] = shamt
    return ret

  @classmethod
  def define_alu_1r1r1i(cls, opcode):
    ret = cls.define_base()
    ret['syntax'  ] = 'T,s,i'
    ret['assemble'] = cls.iformat
    ret['opcode'  ] = opcode
    return ret

  @classmethod
  def define_alu_1r1i(cls, opcode):
    ret = cls.define_base()
    ret['syntax'  ] = 'T,i'
    ret['assemble'] = cls.iformat
    ret['opcode'  ] = opcode
    return ret

  @classmethod
  def define_mem_ld(cls, opcode):
    ret = cls.define_base()
    ret['syntax'  ] = 'T,m'
    ret['assemble'] = cls.iformat
    ret['opcode'  ] = opcode
    return ret

  @classmethod
  def define_mem_st(cls, opcode):
    ret = cls.define_base()
    ret['syntax'  ] = 't,m'
    ret['assemble'] = cls.iformat
    ret['opcode'  ] = opcode
    return ret

  @classmethod
  def define_branch_2r(cls, opcode, cond=None):
    ret = cls.define_base()
    ret['syntax'  ] = 's,t,p'
    ret['assemble'] = cls.iformat
    ret['opcode'  ] = opcode
    ret['cond'    ] = cond
    return ret

  @classmethod
  def define_branch_1r(cls, opcode, cond=None):
    ret = cls.define_base()
    ret['syntax'  ] = 's,p'
    ret['assemble'] = cls.iformat
    ret['opcode'  ] = opcode
    ret['cond'    ] = cond
    return ret

  @classmethod
  def define_jump_0r(cls, opcode, funct=0):
    ret = cls.define_base()
    ret['syntax'  ] = 'l'
    ret['assemble'] = cls.jformat
    ret['opcode'  ] = opcode
    return ret

  @classmethod
  def define_jump_1r(cls, opcode, funct=0, cond=None, shamt=None):
    ret = cls.define_base()
    ret['syntax'  ] = 's'
    ret['assemble'] = cls.rformat
    ret['opcode'  ] = opcode
    ret['funct'   ] = funct
    ret['cond'    ] = cond
    ret['shamt'   ] = shamt
    return ret

  @classmethod
  def define_syscall(cls, opcode, funct=0, code=0):
    ret = cls.define_base()
    ret['syntax'  ] = ''
    ret['assemble'] = cls.rformat
    ret['opcode'  ] = opcode
    ret['funct'   ] = funct
    ret['code'    ] = code
    return ret

  #=============================================
  # Accessors
  #=============================================
  @classmethod
  def arch(cls):
    if cls.__arch__ is None:
      cls.initialize_arch()
    return cls.__arch__

  #=============================================
  # Architecture Definition
  #   hawajkm: we need an automated way to parse
  #            this from a file.
  #=============================================
  @classmethod
  def initialize_arch(cls):
    cls.__arch__ = {}
    cls.__arch__['regs'] = {}
    cls.__arch__['regs']['$0'  ] = 0
    cls.__arch__['regs']['$1'  ] = 1
    cls.__arch__['regs']['$2'  ] = 2
    cls.__arch__['regs']['$3'  ] = 3
    cls.__arch__['regs']['$4'  ] = 4
    cls.__arch__['regs']['$5'  ] = 5
    cls.__arch__['regs']['$6'  ] = 6
    cls.__arch__['regs']['$7'  ] = 7
    cls.__arch__['regs']['$8'  ] = 8
    cls.__arch__['regs']['$9'  ] = 9
    cls.__arch__['regs']['$10' ] = 10
    cls.__arch__['regs']['$11' ] = 11
    cls.__arch__['regs']['$12' ] = 12
    cls.__arch__['regs']['$13' ] = 13
    cls.__arch__['regs']['$14' ] = 14
    cls.__arch__['regs']['$15' ] = 15
    cls.__arch__['regs']['$16' ] = 16
    cls.__arch__['regs']['$17' ] = 17
    cls.__arch__['regs']['$18' ] = 18
    cls.__arch__['regs']['$19' ] = 19
    cls.__arch__['regs']['$20' ] = 20
    cls.__arch__['regs']['$21' ] = 21
    cls.__arch__['regs']['$22' ] = 22
    cls.__arch__['regs']['$23' ] = 23
    cls.__arch__['regs']['$24' ] = 24
    cls.__arch__['regs']['$25' ] = 25
    cls.__arch__['regs']['$26' ] = 26
    cls.__arch__['regs']['$27' ] = 27
    cls.__arch__['regs']['$28' ] = 28
    cls.__arch__['regs']['$29' ] = 29
    cls.__arch__['regs']['$30' ] = 30
    cls.__arch__['regs']['$31' ] = 31

    cls.__arch__['regs']['$zero'] = 0
    cls.__arch__['regs']['$at'  ] = 1
    cls.__arch__['regs']['$v0'  ] = 2
    cls.__arch__['regs']['$v1'  ] = 3
    cls.__arch__['regs']['$a0'  ] = 4
    cls.__arch__['regs']['$a1'  ] = 5
    cls.__arch__['regs']['$a2'  ] = 6
    cls.__arch__['regs']['$a3'  ] = 7
    cls.__arch__['regs']['$t0'  ] = 8
    cls.__arch__['regs']['$t1'  ] = 9
    cls.__arch__['regs']['$t2'  ] = 10
    cls.__arch__['regs']['$t3'  ] = 11
    cls.__arch__['regs']['$t4'  ] = 12
    cls.__arch__['regs']['$t5'  ] = 13
    cls.__arch__['regs']['$t6'  ] = 14
    cls.__arch__['regs']['$t7'  ] = 15
    cls.__arch__['regs']['$s0'  ] = 16
    cls.__arch__['regs']['$s1'  ] = 17
    cls.__arch__['regs']['$s2'  ] = 18
    cls.__arch__['regs']['$s3'  ] = 19
    cls.__arch__['regs']['$s4'  ] = 20
    cls.__arch__['regs']['$s5'  ] = 21
    cls.__arch__['regs']['$s6'  ] = 22
    cls.__arch__['regs']['$s7'  ] = 23
    cls.__arch__['regs']['$t8'  ] = 24
    cls.__arch__['regs']['$t9'  ] = 25
    cls.__arch__['regs']['$k0'  ] = 26
    cls.__arch__['regs']['$k1'  ] = 27
    cls.__arch__['regs']['$gp'  ] = 28
    cls.__arch__['regs']['$sp'  ] = 29
    cls.__arch__['regs']['$fp'  ] = 30
    cls.__arch__['regs']['$s8'  ] = 30
    cls.__arch__['regs']['$ra'  ] = 31

    cls.__arch__['dtypes'] = {}
    cls.__arch__['dtypes']['space' ] = {}
    cls.__arch__['dtypes']['space' ]['elem_sz'] = 1
    cls.__arch__['dtypes']['space' ]['syntax' ] = 'n'

    cls.__arch__['dtypes']['byte'  ] = {}
    cls.__arch__['dtypes']['byte'  ]['elem_sz'] = 1
    cls.__arch__['dtypes']['byte'  ]['syntax' ] = 'l'

    cls.__arch__['dtypes']['half'  ] = {}
    cls.__arch__['dtypes']['half'  ]['elem_sz'] = 2
    cls.__arch__['dtypes']['half'  ]['syntax' ] = 'l'

    cls.__arch__['dtypes']['word'  ] = {}
    cls.__arch__['dtypes']['word'  ]['elem_sz'] = 4
    cls.__arch__['dtypes']['word'  ]['syntax' ] = 'l'

    cls.__arch__['dtypes']['ascii' ] = {}
    cls.__arch__['dtypes']['ascii' ]['elem_sz'] = 1
    cls.__arch__['dtypes']['ascii' ]['syntax' ] = 'str'

    cls.__arch__['dtypes']['asciiz'] = {}
    cls.__arch__['dtypes']['asciiz']['elem_sz'] = 1
    cls.__arch__['dtypes']['asciiz']['syntax' ] = 'strz'

    cls.__arch__['dtypes']['float' ] = {}
    cls.__arch__['dtypes']['float' ]['elem_sz'] = 4
    cls.__arch__['dtypes']['float' ]['syntax' ] = 'l'

    cls.__arch__['dtypes']['double'] = {}
    cls.__arch__['dtypes']['double']['elem_sz'] = 8
    cls.__arch__['dtypes']['double']['syntax' ] = 'l'

    # Instructions
    cls.__arch__['insts'] = {}
    ## ALU Reg-Reg
    cls.__arch__['insts']['add'    ] = cls.define_alu_1r2r  (0x00, 0x20)
    cls.__arch__['insts']['addu'   ] = cls.define_alu_1r2r  (0x00, 0x21)
    cls.__arch__['insts']['sub'    ] = cls.define_alu_1r2r  (0x00, 0x22)
    cls.__arch__['insts']['subu'   ] = cls.define_alu_1r2r  (0x00, 0x23)
    cls.__arch__['insts']['and'    ] = cls.define_alu_1r2r  (0x00, 0x24)
    cls.__arch__['insts']['or'     ] = cls.define_alu_1r2r  (0x00, 0x25)
    cls.__arch__['insts']['xor'    ] = cls.define_alu_1r2r  (0x00, 0x26)
    cls.__arch__['insts']['nor'    ] = cls.define_alu_1r2r  (0x00, 0x27)

    ## Multiplication/Division
    cls.__arch__['insts']['mul'    ] = cls.define_alu_1r2r  (0x00, 0x18, shamt=0x02)
    cls.__arch__['insts']['muh'    ] = cls.define_alu_1r2r  (0x00, 0x18, shamt=0x03)
    cls.__arch__['insts']['mulu'   ] = cls.define_alu_1r2r  (0x00, 0x19, shamt=0x02)
    cls.__arch__['insts']['muhu'   ] = cls.define_alu_1r2r  (0x00, 0x19, shamt=0x03)
    cls.__arch__['insts']['div'    ] = cls.define_alu_1r2r  (0x00, 0x1a, shamt=0x02)
    cls.__arch__['insts']['mod'    ] = cls.define_alu_1r2r  (0x00, 0x1a, shamt=0x03)
    cls.__arch__['insts']['divu'   ] = cls.define_alu_1r2r  (0x00, 0x1b, shamt=0x02)
    cls.__arch__['insts']['modu'   ] = cls.define_alu_1r2r  (0x00, 0x1b, shamt=0x03)

    ## ALU Reg-Imm
    cls.__arch__['insts']['addi'   ] = cls.define_alu_1r1r1i(0x08)
    cls.__arch__['insts']['addiu'  ] = cls.define_alu_1r1r1i(0x09)
    cls.__arch__['insts']['andi'   ] = cls.define_alu_1r1r1i(0x0c)
    cls.__arch__['insts']['ori'    ] = cls.define_alu_1r1r1i(0x0d)
    cls.__arch__['insts']['xori'   ] = cls.define_alu_1r1r1i(0x0e)
    cls.__arch__['insts']['lui'    ] = cls.define_alu_1r1i  (0x0f)

    ## Shifts
    cls.__arch__['insts']['sll'    ] = cls.define_alu_1r1r1s(0x00, 0x00)
    cls.__arch__['insts']['srl'    ] = cls.define_alu_1r1r1s(0x00, 0x02)
    cls.__arch__['insts']['sra'    ] = cls.define_alu_1r1r1s(0x00, 0x03)
    cls.__arch__['insts']['sllv'   ] = cls.define_alu_1r2r  (0x00, 0x04)
    cls.__arch__['insts']['srlv'   ] = cls.define_alu_1r2r  (0x00, 0x06)
    cls.__arch__['insts']['srav'   ] = cls.define_alu_1r2r  (0x00, 0x07)

    ## Memory
    cls.__arch__['insts']['lb'     ] = cls.define_mem_ld    (0x20)
    cls.__arch__['insts']['lh'     ] = cls.define_mem_ld    (0x21)
    cls.__arch__['insts']['lw'     ] = cls.define_mem_ld    (0x23)
    cls.__arch__['insts']['lbu'    ] = cls.define_mem_ld    (0x24)
    cls.__arch__['insts']['lhu'    ] = cls.define_mem_ld    (0x25)
    cls.__arch__['insts']['sb'     ] = cls.define_mem_st    (0x28)
    cls.__arch__['insts']['sh'     ] = cls.define_mem_st    (0x29)
    cls.__arch__['insts']['sw'     ] = cls.define_mem_st    (0x2b)

    ## Branches
    cls.__arch__['insts']['beq'    ] = cls.define_branch_2r (0x04)
    cls.__arch__['insts']['bne'    ] = cls.define_branch_2r (0x05)
    cls.__arch__['insts']['bltz'   ] = cls.define_branch_1r (0x01, cond=0x00)
    cls.__arch__['insts']['bgez'   ] = cls.define_branch_1r (0x01, cond=0x01)
    cls.__arch__['insts']['blez'   ] = cls.define_branch_1r (0x06)
    cls.__arch__['insts']['bgtz'   ] = cls.define_branch_1r (0x07)

    ## Jumps
    cls.__arch__['insts']['j'      ] = cls.define_jump_0r   (0x02)
    cls.__arch__['insts']['jal'    ] = cls.define_jump_0r   (0x03)
    cls.__arch__['insts']['jr'     ] = cls.define_jump_1r   (0x00, 0x08)

    ## Syscall
    cls.__arch__['insts']['syscall'] = cls.define_syscall   (0x00, funct=0x0c, code=0x00)

    #cls.lst_dtypes = r'|'.join([r'\.' + x for x in cls.__arch__['dtypes']])
    cls.lst_dtypes = r'|'.join([r'\b{}\b'.format(x) for x in cls.__arch__['dtypes']])
    cls.dtype_re = re.compile(r'^\.({})(.*$)'.format(cls.lst_dtypes))
