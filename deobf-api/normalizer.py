import re, math, base64
from luaparser import ast
from luaparser.astnodes import *

class VarState:
    def __init__(self):
        self.values={}
    def copy(self):
        v=VarState()
        v.values=self.values.copy()
        return v

def _is_number(node):
    return isinstance(node,Number) or (isinstance(node,UnaryOp) and node.operator=='-' and isinstance(node.operand,Number))

def _number_value(node):
    if isinstance(node,Number): return node.n
    if isinstance(node,UnaryOp) and node.operator=='-': return -node.operand.n
    return None

def _is_string(node):
    return isinstance(node,String)

def _string_value(node):
    if isinstance(node,String): return node.s
    return None

def _fold_constants(node,state):
    if isinstance(node,Call):
        if isinstance(node.func,Name) and node.func.id=='string.char':
            args=[]
            all_nums=True
            for a in node.args:
                f=_fold_constants(a,state)
                args.append(f)
                if not _is_number(f): all_nums=False
            if all_nums:
                chars=''.join(chr(int(_number_value(a))) for a in args)
                return String(chars,None)
            node.args=args
            return node
        if isinstance(node.func,Name) and node.func.id=='table.concat':
            return node
        node.args=[_fold_constants(a,state) for a in node.args]
        return node
    if isinstance(node,Name):
        if node.id in state.values:
            v=state.values[node.id]
            if isinstance(v,Number) or isinstance(v,String): return v
            if isinstance(v,Boolean): return v
        return node
    if isinstance(node,BinaryOp):
        left=_fold_constants(node.left,state)
        right=_fold_constants(node.right,state)
        ln=_number_value(left) if _is_number(left) else None
        rn=_number_value(right) if _is_number(right) else None
        ls=_string_value(left) if _is_string(left) else None
        rs=_string_value(right) if _is_string(right) else None
        if ln is not None and rn is not None:
            if node.operator=='+': return Number(ln+rn)
            if node.operator=='-': return Number(ln-rn)
            if node.operator=='*': return Number(ln*rn)
            if node.operator=='/' and rn!=0: return Number(ln/rn)
            if node.operator=='%' and rn!=0: return Number(ln%rn)
            if node.operator=='^': return Number(ln**rn)
        if ls is not None and rs is not None and node.operator=='..':
            return String(ls+rs,None)
        if node.operator=='==' and ln is not None and rn is not None: return Boolean(ln==rn)
        if node.operator=='<' and ln is not None and rn is not None: return Boolean(ln<rn)
        if node.operator=='>' and ln is not None and rn is not None: return Boolean(ln>rn)
        if node.operator=='<=' and ln is not None and rn is not None: return Boolean(ln<=rn)
        if node.operator=='>=' and ln is not None and rn is not None: return Boolean(ln>=rn)
        if node.operator=='~=' and ln is not None and rn is not None: return Boolean(ln!=rn)
        if node.operator=='==' and ls is not None and rs is not None: return Boolean(ls==rs)
        node.left=left; node.right=right
        return node
    if isinstance(node,UnaryOp):
        operand=_fold_constants(node.operand,state)
        n=_number_value(operand) if _is_number(operand) else None
        if node.operator=='-' and n is not None: return Number(-n)
        if node.operator=='not' and isinstance(operand,Boolean): return Boolean(not operand.b)
        node.operand=operand
        return node
    if isinstance(node,LocalAssign):
        newstate=state.copy()
        values=[]
        for i,t in enumerate(node.targets):
            if i<len(node.values):
                v=_fold_constants(node.values[i],state)
                values.append(v)
                if isinstance(v,(Number,String,Boolean)): newstate.values[t.id]=v
                else: newstate.values.pop(t.id,None)
            else: values.append(NormalExp(None))
        node.values=values
        for stmt in node.body if hasattr(node,'body') else []:
            if isinstance(stmt,Block): _fold_constants(stmt,newstate)
        return node
    if isinstance(node,Block):
        newstate=state.copy()
        for stmt in node.body:
            _fold_constants(stmt,newstate)
        return node
    if isinstance(node,If):
        node.test=_fold_constants(node.test,state)
        node.body=_fold_constants(node.body,state)
        if node.orelse: node.orelse=_fold_constants(node.orelse,state)
        return node
    if isinstance(node,While):
        node.test=_fold_constants(node.test,state)
        node.body=_fold_constants(node.body,state)
        return node
    if isinstance(node,Repeat):
        node.body=_fold_constants(node.body,state)
        node.test=_fold_constants(node.test,state)
        return node
    if isinstance(node,Fornum):
        node.start=_fold_constants(node.start,state)
        node.end=_fold_constants(node.end,state)
        if node.step: node.step=_fold_constants(node.step,state)
        node.body=_fold_constants(node.body,state)
        return node
    if isinstance(node,Forin):
        node.iterators=[_fold_constants(i,state) for i in node.iterators]
        node.body=_fold_constants(node.body,state)
        return node
    if isinstance(node,Function):
        node.body=_fold_constants(node.body,state.copy())
        return node
    if isinstance(node,Return):
        node.values=[_fold_constants(v,state) for v in node.values]
        return node
    if isinstance(node,Assign):
        for i in range(min(len(node.targets),len(node.values))):
            node.values[i]=_fold_constants(node.values[i],state)
        return node
    return node

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
            if node.test.b: return _remove_dead(node.body)
            elif node.orelse: return _remove_dead(node.orelse)
            else: return None
        node.test=_remove_dead(node.test)
        node.body=_remove_dead(node.body)
        if node.orelse: node.orelse=_remove_dead(node.orelse)
        return node
    if isinstance(node,While):
        if isinstance(node.test,Boolean) and not node.test.b: return None
        node.test=_remove_dead(node.test)
        node.body=_remove_dead(node.body)
        return node
    if isinstance(node,Repeat):
        node.body=_remove_dead(node.body)
        node.test=_remove_dead(node.test)
        return node
    return node

def _simplify_control(node,state):
    if isinstance(node,Block):
        node.body=[_simplify_control(s,state) for s in node.body]
        return node
    if isinstance(node,If):
        if isinstance(node.test,Boolean): return _simplify_control(node.body if node.test.b else node.orelse,state)
        node.test=_simplify_control(node.test,state)
        node.body=_simplify_control(node.body,state)
        if node.orelse: node.orelse=_simplify_control(node.orelse,state)
        return node
    if isinstance(node,While):
        node.test=_simplify_control(node.test,state)
        node.body=_simplify_control(node.body,state)
        return node
    return node

def _decode_strings(node,state):
    if isinstance(node,Call) and isinstance(node.func,Name) and node.func.id in state.string_decryptors:
        fn=state.string_decryptors[node.func.id]
        try:
            resolved=fn(node.args,state)
            if resolved: return String(resolved,None)
        except: pass
    if isinstance(node,Block):
        for stmt in node.body: _decode_strings(stmt,state)
        return node
    if isinstance(node,If):
        _decode_strings(node.test,state)
        _decode_strings(node.body,state)
        if node.orelse: _decode_strings(node.orelse,state)
        return node
    if isinstance(node,While):
        _decode_strings(node.test,state)
        _decode_strings(node.body,state)
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
                    if len(val.args)==1:
                        decryptors[name]=_try_make_decryptor(val)
    return decryptors

def _try_make_decryptor(func_ast):
    body=func_ast.body
    if isinstance(body,Block) and len(body.body)>=2:
        if isinstance(body.body[-1],Return):
            ret=body.body[-1]
            if len(ret.values)==1 and isinstance(ret.values[0],Call) and isinstance(ret.values[0].func,Name):
                if ret.values[0].func.id in ('string.char','BitBxor','Base64Decode'):
                    def decryptor(args,state):
                        return None
                    return decryptor
    return None

def normalize_ast(source):
    try:
        tree=ast.parse(source)
    except:
        return None
    state=VarState()
    state.string_decryptors=_find_decryptors(tree)
    tree=_fold_constants(tree,state)
    tree=_remove_dead(tree)
    tree=_simplify_control(tree,state)
    tree=_decode_strings(tree,state)
    return tree.to_lua()
