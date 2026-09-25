#!/usr/bin/env python3
"""
deep-patch.py — pattern/symbol-based 11.4.x UDP side-transport injection (arm64 + x86_64).

Nothing is hardcoded to a build. Everything is discovered from the binary:
  - operator new / _RdpX_nothrow / the Impl vtable / TsUdpTransport::Connect / the producer
    come from the symbol table (nm).
  - the "SideTransportCreationParams" key comes from the string Connect actually references.
  - the code cave is the zero-filled tail slack of __TEXT.
  - the hook site, displaced instruction(s), and the resolve/get vtable slots come from
    disassembling Connect's property-set GET sequence.
  - the object size, init constant, vtable sub-offsets, self/refcount layout, field range, and
    the set slot come from disassembling the producer's construction of the object.

The stub is generated per-build from those values, then written into the cave with a hook into
Connect. Requires auto-patch.sh (the gate NOP) applied first. Run it as your normal user; it
shells out to sudo only for the two privileged steps (writing the binary, re-signing), so it
will prompt for your password once. capstone is the one dependency (pip3 install capstone).

Discovery runs against the pristine reference ("<APP>.bak", which auto-patch.sh maintains) so a
re-patch never reads its own hook; writes go to the live binary. If no .bak, the live binary is
used (assumed pristine at the hook site).

Usage:  ./deep-patch.sh [/Applications/Windows App.app] [--dry]
    or  python3 deep-patch.py [/Applications/Windows App.app] [--dry]
"""
import subprocess, sys, re, struct, os
import capstone
from capstone import arm64 as A, x86 as X

KEYSTR = b'SideTransportCreationParams\x00'

# ---------------------------------------------------------------- Mach-O helpers
def slice_layout(binpath, arch):
    lc = subprocess.run(['otool','-arch',arch,'-l',binpath],capture_output=True,text=True).stdout
    det= subprocess.run(['lipo','-detailed_info',binpath],capture_output=True,text=True).stdout
    ao=None;cur=None
    for l in det.splitlines():
        t=l.split()
        if len(t)>=2 and t[0]=='architecture':cur=t[1]
        if cur==arch and len(t)>=2 and t[0]=='offset':ao=int(t[1]);break
    if ao is None: return None
    secs={}
    for sm in re.finditer(r'Section\n  sectname (\S+)\n   segname (\S+)\n      addr (0x[0-9a-f]+)\n      size (0x[0-9a-f]+)\n    offset (\d+)',lc):
        secs[(sm.group(2),sm.group(1))]={'addr':int(sm.group(3),16),'size':int(sm.group(4),16),'off':int(sm.group(5))}
    m=re.search(r'segname __TEXT\n(?:.*\n)*?   vmaddr (0x[0-9a-f]+)\n   vmsize 0x[0-9a-f]+\n  fileoff (\d+)\n filesize (\d+)',lc)
    text={'vmaddr':int(m.group(1),16),'off':int(m.group(2)),'size':int(m.group(3))}
    return ao,secs,text

def nm_syms(binpath, arch):
    out=subprocess.run(['nm','-arch',arch,binpath],capture_output=True,text=True).stdout
    d={}
    for ln in out.splitlines():
        m=re.match(r'^([0-9a-f]+)\s+\S+\s+(\S+)$',ln)
        if m: d[m.group(2)]=int(m.group(1),16)
    return d

# ---------------------------------------------------------------- discovery
def discover(binpath, arch):
    L=slice_layout(binpath,arch)
    if L is None: return None
    ao,SECS,TEXT=L
    data=open(binpath,'rb').read()
    TVM=TEXT['vmaddr']
    def va2off(va): return ao+(va-TVM)
    def read(va,n): o=va2off(va); return data[o:o+n]
    S=nm_syms(binpath,arch)
    D={'arch':arch,'ao':ao,'TVM':TVM}
    D['OPNEW']=S['__ZnwmRK14RdpX_nothrow_t']; D['NOTHROW']=S['_RdpX_nothrow']
    D['VTBL']=S['__ZTV31SideTransportCreationParamsImpl']
    CONNECT=S['__ZN14TsUdpTransport7ConnectEPhjP14ITSPropertySetPj']
    PRODUCER=S['__ZN13CWVDTransport24OnOrchestrationCompletedERK22WVDOrchestrationResult']
    def strat(va):
        try: return read(va,len(KEYSTR))
        except: return b''
    # cave = __TEXT tail slack
    tend=max(s['off']+s['size'] for (seg,_),s in SECS.items() if seg=='__TEXT')
    D['CAVE']=TVM+(tend-TEXT['off'])
    D['slack']=TEXT['off']+TEXT['size']-tend
    D['cave_is_zero']=all(b==0 for b in data[tend:TEXT['off']+TEXT['size']])
    md=capstone.Cs(capstone.CS_ARCH_ARM64 if arch=='arm64' else capstone.CS_ARCH_X86,
                   capstone.CS_MODE_LITTLE_ENDIAN if arch=='arm64' else capstone.CS_MODE_64)
    md.detail=True
    def dis(va,n): return list(md.disasm(read(va,n),va))
    ins=dis(CONNECT,0x9000)
    # KEY + key-ref
    keyidx=None; KEY=None
    if arch=='arm64':
        for i,I in enumerate(ins):
            if I.mnemonic=='adrp' and i+1<len(ins) and ins[i+1].mnemonic=='add' and ins[i+1].operands[0].reg==I.operands[0].reg:
                tgt=I.operands[1].imm+ins[i+1].operands[2].imm
                if strat(tgt)==KEYSTR: keyidx=i+1; KEY=tgt; break
    else:
        for i,I in enumerate(ins):
            if I.mnemonic=='lea':
                for op in I.operands:
                    if op.type==X.X86_OP_MEM and op.mem.base==X.X86_REG_RIP and strat(I.address+I.size+op.mem.disp)==KEYSTR:
                        keyidx=i; KEY=I.address+I.size+op.mem.disp; break
                if keyidx is not None: break
    assert keyidx is not None, "%s: key ref not found in Connect"%arch
    D['KEY']=KEY
    # hook, slots, displaced
    if arch=='arm64':
        get_slot=hook=res_slot=None; j=keyidx
        while j>0:
            j-=1; I=ins[j]
            if I.mnemonic=='ldr' and '#0x' in I.op_str and I.operands[0].reg==A.ARM64_REG_X8 and I.operands[1].type==A.ARM64_OP_MEM and I.operands[1].mem.base==A.ARM64_REG_X8:
                get_slot=I.operands[1].mem.disp
                hookI=ins[j-1]                       # ldr x8,[x0]
                hook=hookI.address; pre=b''; end=read(hook,4); ret=hook+4
                res_slot=ins[j-3].operands[1].mem.disp
                break
        D.update(hook=hook,ret=ret,pre=pre,end=end,get_slot=get_slot,resolve_slot=res_slot,propreg='x0')
    else:
        get_slot=None
        for k in range(keyidx,min(keyidx+4,len(ins))):
            if ins[k].mnemonic=='call' and ins[k].operands[0].type==X.X86_OP_MEM: get_slot=ins[k].operands[0].mem.disp; break
        res_slot=hook=None; j=keyidx
        while j>0:
            j-=1; I=ins[j]
            if I.mnemonic=='call' and I.operands[0].type==X.X86_OP_MEM and I.operands[0].mem.base==X.X86_REG_RAX:
                res_slot=I.operands[0].mem.disp; hook=I.address
                pre=read(hook,I.size); end=read(hook+I.size,ins[j+1].size); ret=hook+I.size+ins[j+1].size
                break
        D.update(hook=hook,ret=ret,pre=pre,end=end,get_slot=get_slot,resolve_slot=res_slot,propreg='rax')
    # producer construction
    pins=dis(PRODUCER,0x6000)
    newidx=None
    for i,I in enumerate(pins):
        if I.mnemonic in ('bl','callq','call') and ('RdpX_nothrow_t' in (I.op_str or '') or hex(D['OPNEW'])[2:] in (I.op_str or '')): newidx=i; break
    assert newidx is not None, "%s: operator new not found in producer"%arch
    obj_size=None
    for j in range(newidx-1,max(0,newidx-6),-1):
        I=pins[j]
        if arch=='arm64' and I.mnemonic in ('movz','mov') and I.operands[0].reg==A.ARM64_REG_W0 and I.operands[-1].type==A.ARM64_OP_IMM: obj_size=I.operands[-1].imm; break
        if arch!='arm64' and I.mnemonic=='mov' and I.operands[0].reg in (X.X86_REG_EDI,X.X86_REG_DI) and I.operands[1].type==X.X86_OP_IMM: obj_size=I.operands[1].imm; break
    objreg=pins[newidx+1].operands[0].reg
    ZERO=(A.ARM64_REG_WZR,A.ARM64_REG_XZR) if arch=='arm64' else ()
    rv={objreg:('obj',0)}; subs={}; init_val=[None]; self_off=[None]; self_delta=[None]; rc_off=[None]; fields=[]
    def rec(off,srcreg,prev):
        sv=rv.get(srcreg)
        if off in (0,8,0x10) and sv and sv[0]=='addr' and D['VTBL']<=sv[1]<D['VTBL']+0x400: subs[off]=sv[1]-D['VTBL']
        elif off==0x18:
            if sv and sv[0]=='imm': init_val[0]=sv[1]
            elif prev is not None and prev.mnemonic=='ldr' and prev.operands[1].type==A.ARM64_OP_MEM:
                b=rv.get(prev.operands[1].mem.base)
                if b and b[0]=='addr': init_val[0]=struct.unpack('<Q',read(b[1]+prev.operands[1].mem.disp,8))[0]
        elif off==0x20 and sv and sv[0]=='obj': self_off[0]=off; self_delta[0]=sv[1]
        elif off==0x28 and (srcreg in ZERO or (sv and sv[0]=='imm' and sv[1]==0)): rc_off[0]=off
        elif off>=0x30: fields.append(off)
    for k in range(newidx+1,min(newidx+90,len(pins))):
        I=pins[k]; m=I.mnemonic; ops=I.operands; prev=pins[k-1]
        if arch=='arm64':
            if m=='adrp': rv[ops[0].reg]=('addr',ops[1].imm)
            elif m=='mov' and len(ops)==2 and ops[1].type==A.ARM64_OP_REG and ops[1].reg in rv: rv[ops[0].reg]=rv[ops[1].reg]
            elif m=='add' and len(ops)==3 and ops[2].type==A.ARM64_OP_IMM and ops[1].reg in rv:
                b=rv[ops[1].reg]; rv[ops[0].reg]=(b[0],b[1]+ops[2].imm)
            elif m in('str','stur') and ops[1].type==A.ARM64_OP_MEM:
                mem=ops[1].mem; b=rv.get(mem.base); wb='!' in I.op_str
                if b and b[0]=='obj':
                    rec(b[1]+mem.disp,ops[0].reg,prev)
                    if wb: rv[mem.base]=('obj',b[1]+mem.disp)
        else:
            if m=='lea' and ops[1].type==X.X86_OP_MEM:
                mem=ops[1].mem
                if mem.base==X.X86_REG_RIP: rv[ops[0].reg]=('addr',I.address+I.size+mem.disp)
                elif mem.base in rv: b=rv[mem.base]; rv[ops[0].reg]=(b[0],b[1]+mem.disp)
            elif m=='movabs' and ops[1].type==X.X86_OP_IMM: rv[ops[0].reg]=('imm',ops[1].imm)
            elif m in('mov','movq') and ops[1].type==X.X86_OP_REG and ops[1].reg in rv and ops[0].type==X.X86_OP_REG: rv[ops[0].reg]=rv[ops[1].reg]
            elif m=='add' and ops[1].type==X.X86_OP_IMM and ops[0].reg in rv: b=rv[ops[0].reg]; rv[ops[0].reg]=(b[0],b[1]+ops[1].imm)
            elif m in('mov','movq','movups','movaps','movdqu') and ops[0].type==X.X86_OP_MEM:
                mem=ops[0].mem; b=rv.get(mem.base)
                if b and b[0]=='obj':
                    if ops[1].type==X.X86_OP_REG: rec(b[1]+mem.disp,ops[1].reg,prev)
                    elif ops[1].type==X.X86_OP_IMM:
                        off=b[1]+mem.disp
                        if off==0x28 and ops[1].imm==0: rc_off[0]=off
                        elif off>=0x30: fields.append(off)
    set_slot=None
    for k,I in enumerate(pins):
        isk=(arch=='arm64' and I.mnemonic=='add' and len(I.operands)==3 and k>0 and pins[k-1].mnemonic=='adrp'
             and pins[k-1].operands[1].imm+I.operands[2].imm==KEY) or \
            (arch!='arm64' and I.mnemonic=='lea' and I.operands[1].type==X.X86_OP_MEM
             and I.operands[1].mem.base==X.X86_REG_RIP and I.address+I.size+I.operands[1].mem.disp==KEY)
        if not isk: continue
        for k2 in range(k,min(k+6,len(pins))):
            J=pins[k2]
            if arch=='arm64' and J.mnemonic=='blr':
                for b in range(k2-1,max(k2-7,0),-1):
                    B=pins[b]
                    if B.mnemonic=='ldr' and B.operands[1].type==A.ARM64_OP_MEM and B.operands[0].reg==B.operands[1].mem.base:
                        set_slot=B.operands[1].mem.disp; break
                break
            if arch!='arm64' and J.mnemonic=='call' and J.operands[0].type==X.X86_OP_MEM:
                set_slot=J.operands[0].mem.disp; break
        if set_slot is not None: break
    D.update(obj_size=obj_size,init_val=init_val[0],subs=subs,self_off=self_off[0],self_delta=self_delta[0],
             rc_off=rc_off[0],field_start=min(fields) if fields else None,set_slot=set_slot)
    # sanity: everything must be present and self-consistent, else abort (structure changed)
    need=['OPNEW','NOTHROW','VTBL','KEY','CAVE','hook','ret','get_slot','resolve_slot','set_slot',
          'obj_size','init_val','self_off','self_delta','rc_off','field_start']
    missing=[k for k in need if D.get(k) in (None,)]
    assert not missing, "%s: could not derive %s — class/structure changed, re-derive"%(arch,missing)
    assert set(subs)=={0,8,0x10}, "%s: unexpected vtable layout %s"%(arch,subs)
    assert D['slack']>=len(subs)*16+512, "%s: insufficient cave slack"%arch
    return D

# ---------------------------------------------------------------- arm64 codegen
def gen_arm64(D):
    import struct as _s
    W=[];
    def E(x): W.append(x&0xffffffff)
    r=lambda n:n&31
    CAVE=D['CAVE']
    def movz(rd,imm,sh=0): E(0xD2800000|({0:0,16:1,32:2,48:3}[sh]<<21)|((imm&0xffff)<<5)|r(rd))
    def movk(rd,imm,sh=0): E(0xF2800000|({0:0,16:1,32:2,48:3}[sh]<<21)|((imm&0xffff)<<5)|r(rd))
    def addi(rd,rn,imm): E(0x91000000|((imm&0xfff)<<10)|(r(rn)<<5)|r(rd))
    def subi(rd,rn,imm): E(0xD1000000|((imm&0xfff)<<10)|(r(rn)<<5)|r(rd))
    def stru(rt,rn,off): E(0xF9000000|((off//8)<<10)|(r(rn)<<5)|r(rt))
    def ldru(rt,rn,off): E(0xF9400000|((off//8)<<10)|(r(rn)<<5)|r(rt))
    def stp(rt,t2,rn,off): E(0xA9000000|(((off//8)&0x7f)<<15)|(r(t2)<<10)|(r(rn)<<5)|r(rt))
    def ldp(rt,t2,rn,off): E(0xA9400000|(((off//8)&0x7f)<<15)|(r(t2)<<10)|(r(rn)<<5)|r(rt))
    def movr(rd,rm): E(0xAA0003E0|(r(rm)<<16)|r(rd))
    def blr(rn): E(0xD63F0000|(r(rn)<<5))
    def adrp(rd,tgt,pc): d=((tgt&~0xfff)-(pc&~0xfff))>>12; E(0x90000000|((d&3)<<29)|(((d>>2)&0x7ffff)<<5)|r(rd))
    def bl(tgt,pc): E(0x94000000|(((tgt-pc)>>2)&0x03ffffff))
    def b(tgt,pc): E(0x14000000|(((tgt-pc)>>2)&0x03ffffff))
    def cbnz(rt,tgt,pc): E(0xB5000000|((((tgt-pc)>>2)&0x7ffff)<<5)|r(rt))
    def cbz(rt,tgt,pc): E(0xB4000000|((((tgt-pc)>>2)&0x7ffff)<<5)|r(rt))
    KEY=D['KEY']; VT=D['VTBL']; OPN=D['OPNEW']; NT=D['NOTHROW']
    prog=[]; A_=prog.append   # each entry: lambda pc -> one instruction (one E())
    A_(lambda pc: subi(31,31,0x40))
    A_(lambda pc: stp(19,20,31,0x00))
    A_(lambda pc: stp(21,30,31,0x10))
    A_(lambda pc: movr(19,0))
    A_(lambda pc: stru(31,31,0x28))
    A_(lambda pc: ldru(8,19,0))
    A_(lambda pc: ldru(8,8,D['get_slot']))
    A_(lambda pc: movr(0,19))
    A_(lambda pc: adrp(1,KEY,pc)); A_(lambda pc: addi(1,1,KEY&0xfff))
    A_(lambda pc: addi(2,31,0x28))
    A_(lambda pc: blr(8))
    A_(lambda pc: ldru(8,31,0x28))
    A_(lambda pc: cbnz(8,DONE,pc))
    A_(lambda pc: movz(0,D['obj_size']))
    A_(lambda pc: adrp(1,NT,pc)); A_(lambda pc: addi(1,1,NT&0xfff))
    A_(lambda pc: bl(OPN,pc))
    A_(lambda pc: cbz(0,DONE,pc))
    A_(lambda pc: movr(20,0))
    # init_val -> x9 (movz + movk chunks), then store at 0x18
    A_(lambda pc: movz(9,D['init_val']&0xffff))
    for sh in (16,32,48):
        c=(D['init_val']>>sh)&0xffff
        if c: A_((lambda cc,s: (lambda pc: movk(9,cc,s)))(c,sh))
    A_(lambda pc: stru(9,20,0x18))
    A_(lambda pc: adrp(8,VT,pc)); A_(lambda pc: addi(8,8,VT&0xfff))
    for off in sorted(D['subs']):
        sub=D['subs'][off]
        A_((lambda s:(lambda pc: addi(9,8,s)))(sub))
        A_((lambda o:(lambda pc: stru(9,20,o)))(off))
    A_(lambda pc: addi(9,20,D['self_delta']))
    A_(lambda pc: stru(9,20,D['self_off']))
    A_(lambda pc: stru(31,20,D['rc_off']))
    A_(lambda pc: addi(9,20,D['field_start']))
    n=D['obj_size']-D['field_start']; o=0
    while o+16<=n: A_((lambda oo:(lambda pc: stp(31,31,9,oo)))(o)); o+=16
    while o+8<=n: A_((lambda oo:(lambda pc: stru(31,9,oo)))(o)); o+=8
    A_(lambda pc: ldru(8,19,0)); A_(lambda pc: ldru(8,8,D['set_slot']))
    A_(lambda pc: movr(0,19)); A_(lambda pc: adrp(1,KEY,pc)); A_(lambda pc: addi(1,1,KEY&0xfff))
    A_(lambda pc: movr(2,20)); A_(lambda pc: blr(8))
    IDX_DONE=len(prog)
    A_(lambda pc: movr(0,19))
    A_(lambda pc: ldp(19,20,31,0x00)); A_(lambda pc: ldp(21,30,31,0x10)); A_(lambda pc: addi(31,31,0x40))
    ENDW=struct.unpack('<I',D['end'])[0]
    A_(lambda pc: E(ENDW))
    A_(lambda pc: b(D['ret'],pc))
    DONE=CAVE+IDX_DONE*4
    W.clear()
    for i,fn in enumerate(prog): fn(CAVE+i*4)
    stub=b''.join(_s.pack('<I',w) for w in W)
    W.clear(); b(D['CAVE'],D['hook']); hook=_s.pack('<I',W[0])
    return stub,hook

# ---------------------------------------------------------------- x86_64 codegen
def gen_x86(D):
    CAVE=D['CAVE']; KEY=D['KEY']; VT=D['VTBL']; OPN=D['OPNEW']; NT=D['NOTHROW']
    P=[]
    def raw(*b): P.append(('raw',bytes(b)))
    pre=D['pre']; end=D['end']
    P.append(('raw',pre))                                  # DISPLACED#1 (resolve call)
    raw(0x55); raw(0x48,0x89,0xE5); raw(0x53); raw(0x48,0x83,0xEC,0x10)  # push rbp;mov rbp,rsp;push rbx;sub rsp,0x10
    raw(0x48,0x89,0xC3)                                    # mov rbx,rax  (propset)
    raw(0x48,0xC7,0x04,0x24,0,0,0,0)                       # mov qword[rsp],0
    raw(0x48,0x8B,0x03)                                    # mov rax,[rbx]
    raw(0x48,0x89,0xDF)                                    # mov rdi,rbx
    P.append(('rip',bytes([0x48,0x8D,0x35]),KEY))         # lea rsi,[rip+KEY]
    raw(0x48,0x89,0xE2)                                    # mov rdx,rsp
    raw(0xFF,0x50,D['get_slot'])                           # call [rax+get]
    raw(0x48,0x8B,0x04,0x24); raw(0x48,0x85,0xC0)          # mov rax,[rsp];test rax,rax
    P.append(('jcc',bytes([0x0F,0x85]),'done'))           # jne done
    raw(0xBF, D['obj_size']&0xff, (D['obj_size']>>8)&0xff, (D['obj_size']>>16)&0xff, (D['obj_size']>>24)&0xff)  # mov edi,size
    P.append(('rip',bytes([0x48,0x8D,0x35]),NT))          # lea rsi,[rip+NOTHROW]
    P.append(('call',OPN))                                # call opnew
    raw(0x48,0x85,0xC0); P.append(('jcc',bytes([0x0F,0x84]),'done'))
    raw(0x48,0x89,0xC1)                                    # mov rcx,rax (obj)
    raw(0x48,0xBA,*struct.pack('<Q',D['init_val']))       # movabs rdx,init
    raw(0x48,0x89,0x51,0x18)                               # mov [rcx+0x18],rdx
    # vtables: lea rdx,[rip+VT]; then per sub lea rsi,[rdx+sub]; mov [rcx+off],rsi
    P.append(('rip',bytes([0x48,0x8D,0x15]),VT))          # lea rdx,[rip+VT]
    for off in sorted(D['subs']):
        sub=D['subs'][off]
        if sub<0x80: raw(0x48,0x8D,0x72,sub)               # lea rsi,[rdx+sub] (disp8)
        else: raw(0x48,0x8D,0xB2,*struct.pack('<i',sub))   # disp32
        if off<0x80: raw(0x48,0x89,0x71,off) if off else raw(0x48,0x89,0x31)
        else: raw(0x48,0x89,0xB1,*struct.pack('<i',off))
    # self ptr: lea rsi,[rcx+delta]; mov [rcx+self_off],rsi
    raw(0x48,0x8D,0x71,D['self_delta'])
    raw(0x48,0x89,0x71,D['self_off'])
    # refcount 0 (dword)
    raw(0xC7,0x41,D['rc_off'],0,0,0,0)
    # zero fields field_start..obj_size with xorps + movups
    raw(0x0F,0x57,0xC0)                                     # xorps xmm0,xmm0
    o=D['field_start']
    while o+16<=D['obj_size']:
        if o<0x80: raw(0x0F,0x11,0x41,o)
        else: raw(0x0F,0x11,0x81,*struct.pack('<i',o))
        o+=16
    while o+8<=D['obj_size']:
        raw(0x48,0xC7,0x81,*struct.pack('<i',o),0,0,0,0)
        o+=8
    # SET: mov rdx,rcx; mov rdi,rbx; mov rax,[rbx]; lea rsi,[rip+KEY]; call [rax+set]
    raw(0x48,0x89,0xCA); raw(0x48,0x89,0xDF); raw(0x48,0x8B,0x03)
    P.append(('rip',bytes([0x48,0x8D,0x35]),KEY))
    raw(0xFF,0x50,D['set_slot'])
    P.append(('label','done'))
    raw(0x48,0x89,0xD8)                                     # mov rax,rbx (propset)
    raw(0x48,0x83,0xC4,0x10); raw(0x5B); raw(0x5D)          # add rsp,0x10;pop rbx;pop rbp
    P.append(('raw',end))                                  # DISPLACED#2 (mov rcx,[rax])
    P.append(('jmp',D['ret']))
    # assemble two-pass
    def ilen(it):
        k=it[0]
        if k=='raw': return len(it[1])
        if k=='rip': return len(it[1])+4
        if k=='call': return 5
        if k=='jcc': return 6
        if k=='jmp': return 5
        return 0  # label
    labels={}; off=0
    for it in P:
        if it[0]=='label': labels[it[1]]=off
        off+=ilen(it)
    out=bytearray(); off=0
    for it in P:
        k=it[0]
        if k=='raw': out+=it[1]; off+=len(it[1])
        elif k=='rip':
            pre_=it[1]; nxt=CAVE+off+len(pre_)+4; disp=it[2]-nxt; out+=pre_+struct.pack('<i',disp); off+=len(pre_)+4
        elif k=='call':
            nxt=CAVE+off+5; out+=b'\xE8'+struct.pack('<i',it[1]-nxt); off+=5
        elif k=='jcc':
            out+=it[1]+struct.pack('<i',labels[it[2]]-(off+6)); off+=6
        elif k=='jmp':
            out+=b'\xE9'+struct.pack('<i',it[1]-(CAVE+off+5)); off+=5
    stub=bytes(out)
    hrel=D['CAVE']-(D['hook']+5)
    hook=b'\xE9'+struct.pack('<i',hrel)+b'\x90'*(len(pre)+len(end)-5)
    return stub,hook

# ---------------------------------------------------------------- apply
PRIV=[] if os.geteuid()==0 else ['sudo']
def priv_write(binpath, off, blob):
    p=subprocess.run(PRIV+['dd','of='+binpath,'bs=1','seek=%d'%off,'conv=notrunc'],
                     input=blob,capture_output=True)
    if p.returncode!=0: raise RuntimeError(p.stderr.decode())
def main():
    args=[a for a in sys.argv[1:] if not a.startswith('--')]
    dry='--dry' in sys.argv
    APP=args[0] if args else '/Applications/Windows App.app'
    BIN=os.path.join(APP,'Contents/MacOS/Windows App')
    BAK=APP+'.bak'; BAKBIN=os.path.join(BAK,'Contents/MacOS/Windows App')
    ref=BAKBIN if os.path.exists(BAKBIN) else BIN
    live=bytearray(open(BIN,'rb').read())
    writes=[]                       # (off, bytes)
    for arch in ('arm64','x86_64'):
        D=discover(ref,arch)
        if D is None: print("[%s] no slice"%arch); continue
        stub,hook = gen_arm64(D) if arch=='arm64' else gen_x86(D)
        ao=D['ao']; TVM=D['TVM']
        cave_fat=ao+(D['CAVE']-TVM); hook_fat=ao+(D['hook']-TVM)
        print("[%s] cave=0x%x hook=0x%x stub=%dB  (opnew=0x%x vtbl=0x%x key=0x%x size=0x%x slots %#x/%#x/%#x)"%(
            arch,D['CAVE'],D['hook'],len(stub),D['OPNEW'],D['VTBL'],D['KEY'],D['obj_size'],D['resolve_slot'],D['get_slot'],D['set_slot']))
        if dry: print("   stub",stub.hex()); print("   hook",hook.hex()); continue
        orig=open(ref,'rb').read()[hook_fat:hook_fat+len(hook)]
        cur=bytes(live[hook_fat:hook_fat+len(hook)])
        if cur!=orig and cur!=hook:
            print("[%s] hook site is %s, expected %s or an existing hook; skipping"%(arch,cur.hex(),orig.hex())); continue
        writes.append((cave_fat, b'\x00'*(len(stub)+16)))   # clear any prior stub
        writes.append((cave_fat, stub))
        writes.append((hook_fat, hook))
        print("[%s] ready"%arch)
    if dry or not writes:
        if not dry: print("nothing to do.");
        return
    for off,blob in writes: priv_write(BIN, off, blob)
    r=subprocess.run(PRIV+['codesign','--force','--sign','-',BIN],capture_output=True,text=True)
    if r.returncode!=0: subprocess.run(PRIV+['codesign','--force','--deep','--sign','-',APP])
    subprocess.run(PRIV+['xattr','-r','-d','com.apple.quarantine',APP],capture_output=True)
    print("re-signed. Quit Windows App fully, relaunch, connect.")

if __name__=='__main__':
    main()
