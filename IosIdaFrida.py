import idaapi
import ida_kernwin
import idc
import re
from string import Template
from PyQt5.QtWidgets import QApplication

#ScriptGenerator
class SG():
    logTemplate = 'send("arg$index:"+args[$index]);\n'

    # 这里没有考虑ida 分析的参数个数于frida 获取到的参数个书不一致问题
    # 有可能数组会越界(一般ida静态分析出来的参数个数是否都是<= 实际参数个数?)
    objc_logTemplate = """
                var arg$index = args[$index]
                if (targetMethod.argumentTypes[$index] == "pointer"){
                        arg$index = ObjC.Object(arg$index)
                    }
                send("arg$index:"+arg$index);"""
    
    

    hook_c_fun_template = """
function hook_$functionName(){
    var hook_addr =  $hookAddr
    Interceptor.attach(hook_addr, {
        onEnter(args) {
            send("call $functionName");
            $args
        },
        onLeave(retval) {
            $result
            send("leave $functionName");
        }
    });
}

setImmediate(hook_$functionName)
"""

    hook_objc_fun_template = """
function hook_${className}_$functionName(){
    // 导入 Objective-C 框架
    if (ObjC.available) {
        try {

            // 找到目标方法
            const targetMethod = ObjC.classes['$className']['$methodHookName'];

            // 挂钩方法
            Interceptor.attach(targetMethod.implementation, {
            onEnter: function(args) {
                // 在方法进入时执行的代码
                send('call  $className:$functionName')
                $args
            },
            onLeave: function(retval) {
                $result
                send('leave  $className:$functionName')
            }
            });
        }catch(err) {
            send(`[!] hook $className:$functionName Exception2: ` + err.message);
        }
    }
}

setImmediate(hook_${className}_$functionName)
"""
    @classmethod
    def get_fun_hook_info(self,ea):
        # 获取当前光标处的函数名称
        func_name = idaapi.get_func_name(ea)
        f_type =  1 #0:object_c 函数  1: sub_xxxx 内部函数  2: 导入函数
        func_info = {}
        if func_name:
            # 判断函数类别的方法有点糙
            # 使用正则表达式检查函数名称是否匹配Objective-C方法的命名规则
            objc_ida_name_pattern = r'^[+-]\[.*\]'
            if re.match(objc_ida_name_pattern, func_name):
                f_type = 0
            elif '__stubs' == idc.get_segm_name(ea):
                f_type = 2
            

            # 获取当前光标所在的函数
            f = idaapi.get_func(idaapi.get_screen_ea())
            if f:
                base = idaapi.get_imagebase()
                func_info['module_name'] = idaapi.get_root_filename()
                func_info['func_offset']  = hex(f.start_ea - base)
              
                # 判断是否为导入函数
                # bugfix 如果是objectc函数，则不用判断。否则小的objectc函数会被误判
                if f_type != 0 and  f.end_ea - f.start_ea <= 8:
                    f_type = 2
                
                func_info['func_type']  = f_type
    
                # 获取函数的类型信息
                func_type = idaapi.tinfo_t()
                idaapi.get_tinfo(func_type, f.start_ea)
                # 获取返回类型
                func_ret_type_name = func_type.get_rettype().__str__()
                # # 打印返回类型
                # print("Return Type: {}".format(func_ret_type_name))
                
                # 获取参数数量
                num_args = func_type.get_nargs()
                func_info['args_types'] = []
                # 遍历获取参数类型
                for i in range(num_args):
                    arg_type_name = func_type.get_nth_arg(i).__str__()
                    func_info['args_types'].append(arg_type_name)
                    # print("Argument {}: Type: {}".format(i + 1, arg_type, ))
                if f_type == 0:
                    
                    cls_method = func_name.split(' ')
                    pre = func_name[0:2].replace('[', ' ')
                    func_info['cls_name'] = cls_method[0][2:]
                    func_info['method_hook_name'] = pre + cls_method[1][:-1]
                    func_name = ''.join(re.findall(r'\w+', func_info['method_hook_name']))[:18] 
                elif f_type == 2:
                    func_info['func_offset']  = None
                    if '_' == func_name[0]:
                        func_name = func_name[1:]
                    
                func_info['method_name'] = func_name
                    
                func_info['ret_type'] = func_ret_type_name
                func_info['args_count'] = num_args
                # print(func_info)
                return func_info
        return None
    
    @classmethod
    def generate_printArgs(self,argNum, isObjc = False):
        if argNum == 0:
            return "// no args"
        else:
            temp = None
            logText = ""
            if isObjc:
                temp = Template(self.objc_logTemplate)
                for i in range(2, argNum):
                    logText += temp.substitute({"index": i})
                    logText += "            "
                
            else:
                temp = Template(self.logTemplate)
                for i in range(argNum):
                    logText += temp.substitute({"index": i})
                    logText += "            "
            return logText

    @classmethod
    def generate_get_hook_adrr(self, modName, offset,fun_name):
        if offset:
            return  f"Module.findBaseAddress('{modName}').add({offset})"
        else:
           return f"Module.findExportByName(null,'{fun_name}')"


    @classmethod
    def generate_c_func_script(self,funcInfo):
        
        hookAddr  =  self.generate_get_hook_adrr( funcInfo['module_name'],  funcInfo['func_offset'],  funcInfo['method_name'])
  
        argsPrint = self.generate_printArgs(funcInfo['args_count'])

        retPrint = "// no return"
        if funcInfo['ret_type'] != 'void':
            retPrint = f"send('{funcInfo['method_name']} ret:' + retval);"

        temp = Template(self.hook_c_fun_template)
        result = temp.substitute(
            {  
                "hookAddr":hookAddr,
                "functionName": funcInfo['method_name'],
                "args": argsPrint,
                "result": retPrint,
            }
        )
        return(result)

    @classmethod
    def generate_objc_func_script(self,funcInfo):
        
        argsPrint = self.generate_printArgs(funcInfo['args_count'], True)

        retPrint = "// no return"
        if funcInfo['ret_type'] != 'void':
            ret_temp = '''var ret = retval
                if (targetMethod.returnType == "pointer"){
                    ret = ObjC.Object(retval)
                }
                send(`$className:$functionName ret:` + ret)'''
            temp = Template(ret_temp)
            retPrint = temp.substitute(
                {  
                    "className": funcInfo['cls_name'],
                    "functionName": funcInfo['method_name'],
                }
            )
        

        temp = Template(self.hook_objc_fun_template)
        result = temp.substitute(
            {  
                "className": funcInfo['cls_name'],
                "methodHookName": funcInfo['method_hook_name'],
                "functionName": funcInfo['method_name'],
                "args": argsPrint,
                "result": retPrint,
            }
        )
        return (result)

    @classmethod
    def nop(self,*args):
        print('功能未实现')
        pass

    @classmethod
    def gen_frida_script(self):
        gen_fun_list = [self.generate_objc_func_script, self.generate_c_func_script, self.generate_c_func_script]
        funcInfo = self.get_fun_hook_info(idc.here())
        script = None
        if funcInfo:
            script = gen_fun_list[funcInfo['func_type']](funcInfo)
        else:
            ida_kernwin.warning('无法获取函数信息')
        return script

class IMenuAction(ida_kernwin.action_handler_t):
    TopDescription = 'IdaFridaIos'
    @classmethod
    def name(self):
        return  str(self.__name__)

    @classmethod
    def register(self):
        return idaapi.register_action(idaapi.action_desc_t(
                self.name(),
                self.description,
                self()
            ))

    @classmethod
    def unregister(self):
        idaapi.unregister_action(self.name())

    def update(self, ctx):
        if (
                ctx.widget_type == idaapi.BWN_FUNCS
                or ctx.widget_type == idaapi.BWN_PSEUDOCODE
                or ctx.widget_type == idaapi.BWN_DISASM
        ):
            idaapi.attach_action_to_popup(
                ctx.widget, None, self.name(), self.TopDescription
            )
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET

    @classmethod
    def set_clipboard(self, txt):
        cb = QApplication.clipboard()
        cb.setText(txt, mode=cb.Clipboard)
        print("脚本已复制")
    
    @classmethod
    def show_script(self,script_txt):
        self.set_clipboard(script_txt)
        # 调用 AskText 函数创建文本编辑弹出窗口
        idaapi.ask_text(0, script_txt, '脚本已经生成并复制到剪切板')

class GenfridaHook(IMenuAction):
    description = 'IosIdaFrida--生成frida hook 脚本'
    def activate(self, ctx):
        sc = SG.gen_frida_script()
        if sc:
            self.show_script(sc)

class IdaFridaIos(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    wanted_name = "IosIdaFrida"
    comment = "A plug-in for automatic generate frida script for march-o file"
    wanted_hotkey = "Alt+F8"

    def init(self):
        GenfridaHook.register()
        return idaapi.PLUGIN_KEEP

    def deinit(self):
        GenfridaHook.unregister()

    def run(self, arg):
        print(self.comment)
      
    def term(self):
        self.deinit()
        return idaapi.PLUGIN_OK

def PLUGIN_ENTRY():
    return IdaFridaIos()

