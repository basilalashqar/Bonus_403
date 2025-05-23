

class DirectMappedCache:
    def __init__(self, port_id, num_sets, line_size, hit_latency):
        self.port_id     = port_id
        self.num_sets    = num_sets
        self.line_size   = line_size
        self.hit_latency = hit_latency

        # Storage
        self.tags  = [None] * num_sets
        self.valid = [False] * num_sets
        self.lines = [bytearray(line_size) for _ in range(num_sets)]

        # Lower-level memory interface
        self.MemCanReq   = None
        self.MemSendReq  = None
        self.MemHasResp  = None
        self.MemRecvResp = None

        # Outstanding request & response
        self.req_buf  = None
        self.resp_buf = None

        # Last event marker for linetrace (IH/IM/DH/DM/DW)
        self.last_event = ''

    # Connection to lower memory
    def setMemCanReq(self, f):   self.MemCanReq   = f
    def setMemSendReq(self, f):  self.MemSendReq  = f
    def setMemHasResp(self, f):  self.MemHasResp  = f
    def setMemRecvResp(self, f): self.MemRecvResp = f

    # Can we accept a new request?
    def canReq(self):
        return self.req_buf is None

    # Send a request (read or write)
    def sendReq(self, req):
        assert self.req_buf is None, "Cache busy"
        op   = req['op']    # 0=read,1=write
        addr = req['addr']
        size = req['size']
        mask = req.get('mask')
        tagf = req['tag']

        # Compute block address, index, tag
        block_addr = (addr // self.line_size) * self.line_size
        set_idx    = (block_addr // self.line_size) % self.num_sets
        tag_val    = (block_addr // self.line_size) // self.num_sets

        # Choose prefix based on port: instr(0) vs data(1)
        prefix = 'I' if self.port_id == 0 else 'D'

        if op == 0:  # READ
            if self.valid[set_idx] and self.tags[set_idx] == tag_val:
                # HIT
                self.last_event = prefix + 'H'
                self.req_buf = {
                    'delay':   self.hit_latency,
                    'type':    'hit',
                    'orig':    req,
                    'set_idx': set_idx,
                    'baddr':   block_addr
                }
            else:
                # MISS
                self.last_event = prefix + 'M'
                assert self.MemCanReq(self.port_id), "Lower memory busy"
                mem_req = {
                    'op':   0,
                    'addr': block_addr,
                    'size': self.line_size,
                    'mask': None,
                    'tag':  tagf,
                    'data': [0] * self.line_size    # dummy so main mem won’t crash
                }
                self.MemSendReq(self.port_id, mem_req)
                self.req_buf = {
                    'delay':   self.hit_latency,
                    'type':    'miss',
                    'orig':    req,
                    'set_idx': set_idx,
                    'baddr':   block_addr
                }

        else:  # WRITE (write-through, no-allocate)
            self.last_event = 'DW'
            assert self.MemCanReq(self.port_id), "Lower memory busy"
            self.MemSendReq(self.port_id, req)
            # If line is resident, update it
            if self.valid[set_idx] and self.tags[set_idx] == tag_val:
                offset = addr - block_addr
                for i in range(size):
                    if mask is None or mask[i]:
                        self.lines[set_idx][offset + i] = req['data'][i]
            self.req_buf = {
                'delay':   self.hit_latency,
                'type':    'write',
                'orig':    req,
                'set_idx': set_idx,
                'baddr':   block_addr
            }

    # Response available?
    def hasResp(self):
        return self.resp_buf is not None

    # Fetch the response
    def recvResp(self):
        resp = self.resp_buf
        self.resp_buf = None
        return resp

    # Advance one cycle
    def tick(self):
        if not self.req_buf:
            return

        if self.req_buf['delay'] == 0:
            self._process()
        else:
            self.req_buf['delay'] -= 1

    # Internal completion of a request
    def _process(self):
        e       = self.req_buf
        typ     = e['type']
        orig    = e['orig']
        set_idx = e['set_idx']
        baddr   = e['baddr']

        if typ == 'hit':
            # Serve a hit from cache
            addr, size, mask, tagf = orig['addr'], orig['size'], orig.get('mask'), orig['tag']
            off  = addr - baddr
            data = list(self.lines[set_idx][off:off+size])
            self.resp_buf = {'op':0,'addr':addr,'data':data,'size':size,'mask':mask,'tag':tagf}
            self.req_buf = None

        elif typ == 'miss':
            # Wait for mem response, then fill cache and replay
            if self.MemHasResp(self.port_id):
                mresp = self.MemRecvResp(self.port_id)
                self.lines[set_idx][:] = mresp['data']
                self.tags[set_idx]      = (baddr // self.line_size) // self.num_sets
                self.valid[set_idx]     = True
                addr, size, mask, tagf = orig['addr'], orig['size'], orig.get('mask'), orig['tag']
                off  = addr - baddr
                data = list(self.lines[set_idx][off:off+size])
                self.resp_buf = {'op':0,'addr':addr,'data':data,'size':size,'mask':mask,'tag':tagf}
                self.req_buf = None

        elif typ == 'write':
            # Wait for write-through ack
            if self.MemHasResp(self.port_id):
                wr = self.MemRecvResp(self.port_id)
                self.resp_buf = wr
                self.req_buf = None

        else:
            raise RuntimeError(f"Unknown cache op: {typ}")

    # Linetrace shows last event, then clear it
    def linetrace(self):
        ev = self.last_event or ''
        self.last_event = ''
        return ev

