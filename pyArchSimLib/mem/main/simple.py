# simple.py
# --------------------------------------------------------------------
# Simple multi-ported main memory model with constant access latency.
#
# Author\ Khalid Al-Hawaj
# Date  \ 4 May 2025

import random

class SimpleMultiportedMemory():
  def __init__(s, nports, delay = 0):
    s.pmem = {}
    s.page_size = 1 << 12 #4kB
    s.nports = nports

    s.req_buf  = [None for _ in range(nports)]
    s.resp_buf = [None for _ in range(nports)]

    s.delay    = [delay for _ in range(nports)]

  def allocate_physical_page(s, page_addr):
    assert (page_addr not in s.pmem)

    s.pmem[page_addr] = []
    for i in range(s.page_size):
      s.pmem[page_addr].append(random.randint(0, 256))

  def write(s, addr, data, size, mask=None):
    # Check whether the page is allocated
    page_addr = int(addr / s.page_size)
    page_offset = addr % s.page_size
    if page_addr not in s.pmem:
      s.allocate_physical_page(page_addr)

    # Perform the write
    for i in range(size):
      if mask is None or mask[i] == True:
        s.pmem[page_addr][page_offset + i] = data[i]

  def read(s, addr, size):
    # Check whether the page is allocated
    page_addr = int(addr / s.page_size)
    page_offset = addr % s.page_size
    if page_addr not in s.pmem:
      s.allocate_physical_page(page_addr)

    # Perform the read
    data = [0 for _ in range(size)]
    for i in range(size):
      data[i] = s.pmem[page_addr][page_offset + i]

    return data

  # Interface
  def canReq(s, i):
    return (s.req_buf[i] is None)

  def sendReq(s, i, req):
    assert (s.req_buf[i] is None)

    s.req_buf[i] = {}
    s.req_buf[i]['delay'] = s.delay[i]
    s.req_buf[i]['req'  ] = req

    # hawajkm: this is not modeling a pipelined memory subsystem.
    #          Therefore, an incoming request blocks our input until
    #          its latency reaches zero

    # If we are modeling a combinational memory, invoke the
    # routine to process the request
    if s.delay[i] == None or s.delay[i] == 0:
      s.processRequest(i)

  def hasResp(s, i):
    if s.resp_buf[i] is not None:
      return True
    return False

  def recvResp(s, i):
    resp = s.resp_buf[i]
    s.resp_buf[i] = None
    return resp

  def processRequest(s, i):
    if (s.req_buf[i] is not None) and (s.req_buf[i]['delay'] == 0):
      if (s.resp_buf[i] is None):
        # Perform the request
        op   = s.req_buf[i]['req']['op'  ]
        data = s.req_buf[i]['req']['data']
        addr = s.req_buf[i]['req']['addr']
        size = s.req_buf[i]['req']['size']
        mask = s.req_buf[i]['req']['mask']
        tag  = s.req_buf[i]['req']['tag' ]

        if   op == 0:
          data = s.read(addr, size)
        elif op == 1:
          s.write(addr, data, size, mask)

        resp = {}
        resp['op'  ] = op
        resp['addr'] = addr
        resp['data'] = data
        resp['size'] = size
        resp['mask'] = mask
        resp['tag' ] = tag

        s.req_buf [i] = None
        s.resp_buf[i] = resp

  def tick(s):
    for i in range(s.nports):
      if s.req_buf[i] is not None:
        if s.req_buf[i]['delay'] > 0:
          s.req_buf[i]['delay'] -= 1

      if s.req_buf[i] is not None:
        if s.req_buf[i]['delay'] == 0:
          s.processRequest(i)

  def linetrace(s):
    return 'mem'
