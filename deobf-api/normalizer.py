import re, struct, base64, math
from luaparser import ast
from luaparser.astnodes import *

try:
    import z3
    HAS_Z3 = True
except ImportError:
    HAS_Z3 = False

def strip_luau_syntax(code):
    code = re.sub(r':\s*[a-zA-Z_][\w]*(\s*\?)?', '', code)
    code = code.replace('continue', '--[[continue]]')
    code = code.replace('+=', '= __temp+')
    code = re.sub(r'local function (\w+)\(([^)]*)\): *\w+', r'local function \1(\2)', code)
    return code

class VarState:
    def __init__(self):
        self.values={}
        self.decryptors={}
    def copy(self):
        v=VarState()
        v.values=self.values.copy()
        v.decryptors=self.decryptors
        return v

def _number_value(node):
    if isinstance(node,Number): return node.n
    if isinstance(node,UnaryOp) and node.operator=='-' and isinstance(node.operand,Number): return -node.operand.n
    return None

def _string_value(node):
    if isinstance(node,String): return node.s
    return None

def _is_constant(node):
    return isinstance(node,(Number,String,Boolean,Nil))

def _eval_binary(left,op,right):
    if isinstance(left,(int,float)) and isinstance(right,(int,float)):
        if op=='+': return left+right
        if op=='-': return left-right
        if op=='*': return left*right
        if op=='/' and right!=0: return left/right
        if op=='%' and right!=0: return left%right
        if op=='^': return left**right
    if isinstance(left,str) or isinstance(right,str):
        ls=str(left) if not isinstance(left,str) else left
        rs=str(right) if not isinstance(right,str) else right
        if op=='..': return ls+rs
    return None

def _fold_constants(node,state):
    if isinstance(node,Call) and isinstance(node.func,Name):
        if node.func.id in state.decryptors:
            fn=state.decryptors[node.func.id]
            try:
                resolved=fn(node.args,state)
                if resolved is not None:
                    return String(resolved,None)
            except: pass
        if node.func.id=='string.char' and all(_number_value(a) is not None for a in node.args):
            chars=''.join(chr(int(_number_value(a))) for a in node.args)
            return String(chars,None)
        if node.func.id=='table.concat':
            return node
        node.args=[_fold_constants(a,state) for a in node.args]
        return node
    if isinstance(node,Name):
        if node.id in state.values:
            v=state.values[node.id]
            if isinstance(v,(Number,String,Boolean)): return v
        return node
    if isinstance(node,BinaryOp):
        left=_fold_constants(node.left,state)
        right=_fold_constants(node.right,state)
        ln=_number_value(left); rn=_number_value(right)
        ls=_string_value(left); rs=_string_value(right)
        if ln is not None and rn is not None:
            res=_eval_binary(ln,node.operator,rn)
            if res is not None:
                if isinstance(res,bool): return Boolean(res)
                if isinstance(res,(int,float)): return Number(res)
        if (ls is not None or isinstance(left,Number)) and (rs is not None or isinstance(right,Number)):
            l_str=str(ls) if ls is not None else str(ln) if ln is not None else ''
            r_str=str(rs) if rs is not None else str(rn) if rn is not None else ''
            if node.operator=='..':
                return String(l_str+r_str,None)
        if node.operator in ('==','<','>','<=','>=','~='):
            lv=_number_value(left) if _number_value(left) is not None else (_string_value(left) if _string_value(left) is not None else None)
            rv=_number_value(right) if _number_value(right) is not None else (_string_value(right) if _string_value(right) is not None else None)
            if lv is not None and rv is not None:
                if node.operator=='==': return Boolean(lv==rv)
                if node.operator=='~=': return Boolean(lv!=rv)
                if node.operator=='<': return Boolean(lv<rv)
                if node.operator=='>': return Boolean(lv>rv)
                if node.operator=='<=': return Boolean(lv<=rv)
                if node.operator=='>=': return Boolean(lv>=rv)
        node.left=left; node.right=right
        return node
    if isinstance(node,UnaryOp):
        operand=_fold_constants(node.operand,state)
        n=_number_value(operand)
        if node.operator=='-' and n is not None: return Number(-n)
        if node.operator=='not' and isinstance(operand,Boolean): return Boolean(not operand.b)
        node.operand=operand
        return node
    if isinstance(node,Block):
        newstate=state.copy()
        for i,stmt in enumerate(node.body):
            node.body[i]=_fold_constants(stmt,newstate)
        return node
    if isinstance(node,If):
        node.test=_fold_constants(node.test,state)
        node.body=_fold_constants(node.body,state.copy())
        if node.orelse: node.orelse=_fold_constants(node.orelse,state.copy())
        return node
    if isinstance(node,While):
        node.test=_fold_constants(node.test,state)
        node.body=_fold_constants(node.body,state.copy())
        return node
    if isinstance(node,Repeat):
        node.body=_fold_constants(node.body,state.copy())
        node.test=_fold_constants(node.test,state)
        return node
    if isinstance(node,Fornum):
        node.start=_fold_constants(node.start,state)
        node.end=_fold_constants(node.end,state)
        if node.step: node.step=_fold_constants(node.step,state)
        node.body=_fold_constants(node.body,state.copy())
        return node
    if isinstance(node,Forin):
        node.iterators=[_fold_constants(i,state) for i in node.iterators]
        node.body=_fold_constants(node.body,state.copy())
        return node
    if isinstance(node,Function):
        node.body=_fold_constants(node.body,state.copy())
        return node
    if isinstance(node,Assign):
        for i in range(min(len(node.targets),len(node.values))):
            node.values[i]=_fold_constants(node.values[i],state)
        return node
    return node

def _is_opaque_predicate(condition):
    if not HAS_Z3: return None
    try:
        def to_z3(node):
            if isinstance(node,Number): return z3.IntVal(int(node.n))
            if isinstance(node,String): return z3.StringVal(node.s)
            if isinstance(node,Name): return z3.Int(node.id)
            if isinstance(node,BinaryOp):
                left=to_z3(node.left); right=to_z3(node.right)
                if node.operator=='+': return left+right
                if node.operator=='-': return left-right
                if node.operator=='*': return left*right
                if node.operator=='/': return left/right
                if node.operator=='==': return left==right
                if node.operator=='<': return left<right
                if node.operator=='>': return left>right
            return None
        zexpr=to_z3(condition)
        if zexpr is None: return None
        s=z3.Solver()
        s.add(z3.Not(zexpr))
        if s.check()==z3.unsat: return True
        s2=z3.Solver()
        s2.add(zexpr)
        if s2.check()==z3.unsat: return False
    except: pass
    return None

def _remove_dead(node):
    if isinstance(node,Block):
        newbody=[]
        for stmt in node.body:
            s=_remove_dead(stmt)
            if s is not None: newbody.append(s)
        node.body=newbody
        return node
    if isinstance(node,If):
        if isinstance(node.test,Boolean):
            return _remove_dead(node.body if node.test.b else node.orelse)
        res=_is_opaque_predicate(node.test)
        if res is True:
            return _remove_dead(node.body)
        if res is False:
            return _remove_dead(node.orelse) if node.orelse else None
        node.test=_remove_dead(node.test)
        node.body=_remove_dead(node.body)
        if node.orelse: node.orelse=_remove_dead(node.orelse)
        return node
    if isinstance(node,While):
        res=_is_opaque_predicate(node.test)
        if res is False: return None
        node.test=_remove_dead(node.test)
        node.body=_remove_dead(node.body)
        return node
    return node

def _find_decryptors(ast_root):
    decryptors={}
    if isinstance(ast_root,Block):
        for stmt in ast_root.body:
            if isinstance(stmt,LocalAssign) and len(stmt.targets)==1 and len(stmt.values)==1:
                val=stmt.values[0]
                if isinstance(val,Function):
                    name=stmt.targets[0].id
                    decryptors[name]=_build_decryptor(val)
    return decryptors

def _build_decryptor(func):
    body=func.body
    if isinstance(body,Block) and len(body.body)>=2:
        last=body.body[-1]
        if isinstance(last,Return) and len(last.values)==1:
            ret=last.values[0]
            if isinstance(ret,Call) and isinstance(ret.func,Name):
                if ret.func.id=='BitBxor':
                    def xor_decrypt(args,state):
                        if len(args)>=2:
                            a=_fold_constants(args[0],state)
                            b=_fold_constants(args[1],state)
                            av=_string_value(a); bv=_string_value(b) or _number_value(b)
                            if av and bv is not None:
                                if isinstance(bv,(int,float)):
                                    return ''.join(chr(ord(c)^int(bv)) for c in av)
                                if isinstance(bv,str):
                                    return ''.join(chr(ord(c)^ord(k)) for c,k in zip(av,bv*len(av)))
                        return None
                    return xor_decrypt
                if ret.func.id=='Base64Decode':
                    def b64_decrypt(args,state):
                        if len(args)>=1:
                            a=_fold_constants(args[0],state)
                            av=_string_value(a)
                            if av:
                                try: return base64.b64decode(av).decode('utf-8',errors='replace')
                                except: pass
                        return None
                    return b64_decrypt
    return None

def _unflatten_control(node,state_var,map_dict):
    if not isinstance(node,While): return node
    if not isinstance(node.body,Block): return node
    body=node.body
    newstatements=[]
    i=0
    while i<len(body.body):
        stmt=body.body[i]
        if isinstance(stmt,If) and isinstance(stmt.test,BinaryOp) and stmt.test.operator=='==':
            left=stmt.test.left
            right=stmt.test.right
            if isinstance(left,Name) and left.id==state_var and _number_value(right) is not None:
                state=int(_number_value(right))
                if state in map_dict:
                    sub_block=map_dict[state]
                    if isinstance(sub_block,Block):
                        newstatements.extend(sub_block.body)
                    else:
                        newstatements.append(sub_block)
                    i+=1
                    continue
        newstatements.append(stmt)
        i+=1
    return Block(newstatements)

def _detect_state_machine(block):
    if isinstance(block,Block):
        for stmt in block.body:
            if isinstance(stmt,While) and isinstance(stmt.test,Boolean) and stmt.test.b==True:
                if isinstance(stmt.body,Block):
                    state_var=None
                    state_blocks={}
                    for inner in stmt.body.body:
                        if isinstance(inner,If) and isinstance(inner.test,BinaryOp) and inner.test.operator=='==':
                            left=inner.test.left
                            right=inner.test.right
                            if isinstance(left,Name):
                                if state_var is None: state_var=left.id
                                if left.id==state_var and _number_value(right) is not None:
                                    state=int(_number_value(right))
                                    state_blocks[state]=inner.body
                    if state_var and state_blocks:
                        return state_var,state_blocks
    return None,None

def _lift_vm_bytecode(source):
    const_match=re.search(r'local\s+(\w+)\s*=\s*\{([\d\s,]+)\}',source)
    if not const_match: return None
    const_name=const_match.group(1)
    consts=[int(c.strip()) for c in const_match.group(2).split(',') if c.strip().isdigit()]
    code_match=re.search(r'local\s+(\w+)\s*=\s*\{([^}]+)\}',source)
    if not code_match: return None
    code=[int(c.strip()) for c in code_match.group(2).split(',') if c.strip().isdigit()]
    output_lines=[]
    op_to_name={
        0:'MOVE',1:'LOADK',2:'LOADBOOL',3:'LOADNIL',5:'GETGLOBAL',7:'SETGLOBAL',
        8:'GETTABLE',9:'SETTABLE',12:'ADD',13:'SUB',14:'MUL',15:'DIV',
        18:'UNM',19:'NOT',20:'LEN',22:'JMP',23:'EQ',24:'LT',25:'LE',
        28:'CALL',30:'RETURN'
    }
    pc=0
    regs=[None]*256
    while pc<len(code):
        instr=code[pc]; pc+=1
        op=instr&0x3F; a=(instr>>6)&0xFF; c=(instr>>14)&0x1FF; b=(instr>>23)&0x1FF
        if op==1: output_lines.append(f'R{a} = {repr(consts[b])}'); regs[a]=consts[b]
        elif op==5: output_lines.append(f'R{a} = _G[{repr(consts[b])}]')
        elif op==12: output_lines.append(f'R{a} = R{b} + R{c}')
        elif op==28:
            args=', '.join(f'R{a+1+i}' for i in range(b-1)) if b>1 else ''
            output_lines.append(f'R{a}({args})')
        elif op==30: break
        else: output_lines.append(f'-- op {op}')
    return '\n'.join(output_lines)

def normalize_source(source):
    source=strip_luau_syntax(source)
    tree=ast.parse(source)
    state=VarState()
    state.decryptors=_find_decryptors(tree)
    tree=_fold_constants(tree,state)
    tree=_remove_dead(tree)
    state_var,state_blocks=_detect_state_machine(tree)
    if state_var and state_blocks:
        tree=_unflatten_control(tree,state_var,state_blocks)
    lifted=_lift_vm_bytecode(source)
    if lifted: return lifted
    return tree.to_lua()
