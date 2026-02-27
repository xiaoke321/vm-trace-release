/**
 * vm-trace-release (旧版 test.so) 主动调用 + Trace 脚本
 * 
 * 基于参考代码实现，使用 checkFileExists 避免重复调用
 * 
 * 使用方法：
 * 1. 关闭 SELinux: adb shell 'su -c setenforce 0'
 * 2. 推送 test.so: adb push test.so /data/local/tmp/
 * 3. 运行: frida -U -f <package_name> -l js/vm_trace_active_call_old3.js
 * 4. 在 console 中调用 call() 进行主动调用
 * 
 * 注意事项：
 * - 仅支持 arm64 架构
 * - 函数签名必须准确匹配
 * - trace 完成后建议立即退出 (Ctrl+D)
 */

function checkFileExists(path) {
    var File = Java.use('java.io.File');
    var file = File.$new(path);
    return file.exists();
}

function prepareArgs(args) {
    if (args === undefined || !Array.isArray(args)) {
        args = [];
    }
    var argNum = args.length;
    var argSize = Process.pointerSize * argNum;
    var argsPtr = Memory.alloc(argSize);

    for (var i = 0; i < argNum; i++) {
        var arg = args[i];
        var argPtr;
        if (!arg) {
            arg = 0;
        }
        if (arg instanceof NativePointer) {
            // 如果是 NativePointer，直接使用
            argPtr = arg;
        } else if (typeof arg === 'object') {
            // 如果是对象，直接转换为指针
            // 形如 jstring Java_com_demo_app_genToken(JNIEnv *env, jobject obj, long str)这种registerNative的函数参数对象可以处理
            argPtr = ptr(arg);
        } else if (typeof arg === 'number') {
            // 如果是数字，直接转换为指针
            argPtr = ptr(arg);
        } else if (typeof arg === 'string') {
            // 如果是字符串，分配内存并获取指针
            argPtr = Memory.allocUtf8String(arg);
        } else if (typeof arg === 'object' && arg.hasOwnProperty('handle')) {
            // 如果是带有 handle 属性的对象（如 JNIEnv）
            argPtr = arg.handle;
        } else if (typeof arg === 'object' && arg instanceof ArrayBuffer) {
            // 如果是二进制数据，分配内存并写入数据
            var dataPtr = Memory.alloc(arg.byteLength);
            Memory.writeByteArray(dataPtr, arg);
            argPtr = dataPtr;
        } else {
            console.error('Unsupported argument type at index ' + i + ':', typeof arg);
            throw new TypeError('Unsupported argument type at index ' + i + ': ' + typeof arg);
        }

        // 将参数指针写入参数数组
        Memory.writePointer(argsPtr.add(i * Process.pointerSize), argPtr);
    }

    return {
        argsPtr: argsPtr,
        argNum: argNum
    };
}

var vmtraceAddr;
var vmtrace;
var isTracing = false;  // 全局标志，防止递归调用

// ==================== 配置区域：根据实际情况修改 ====================
var moduleName = "libhbsecurity.so";        // 目标模块名称
var offset = 0x11b7a4;                      // 函数偏移地址
var logPath = "/data/user/0/com.max.xiaoheihe/log_old3.txt";  // trace 日志保存路径

// 函数签名：根据实际函数修改
// 注意：参数数量必须与函数签名完全匹配！
var returnType = 'pointer';
var paramTypes = ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'uint32'];  // 6个参数
// ====================================================================================

function hook_target_function() {
    // 判断文件是否存在，避免系统二次或n次调用被覆盖
    if (checkFileExists(logPath)) {
        console.log("[!] 文件已存在: " + logPath);
        console.log("[!] 跳过 hook，避免覆盖已有日志");
        return;
    }

    var lib = Process.findModuleByName(moduleName);
    if (!lib) {
        console.error("[-] 无法找到模块: " + moduleName);
        console.log("[*] 等待模块加载...");
        
        // 等待模块加载
        var dlopen_addr = Module.findExportByName(null, "android_dlopen_ext");
        if (dlopen_addr) {
            Interceptor.attach(dlopen_addr, {
                onEnter: function (args) {
                    var addr = args[0];
                    var str = ptr(addr).readCString();
                    if (str && str.indexOf(moduleName) >= 0) {
                        console.log("[+] 检测到模块加载: " + str);
                        setTimeout(function() {
                            hook_target_function();
                        }, 500);
                    }
                }
            });
        }
        return;
    }

    console.log("[+] 找到模块: " + moduleName);
    var funcAddress = lib.base.add(offset);
    console.log("[+] 目标函数地址: " + funcAddress);
    console.log("[+] 模块基址: " + lib.base);
    console.log("[+] 函数偏移: 0x" + offset.toString(16));

    // 保存原始函数指针，用于在递归保护时直接调用
    var originalFunc = new NativeFunction(funcAddress, returnType, paramTypes);

    Interceptor.replace(funcAddress, new NativeCallback(function (arg0, arg1, arg2, arg3, arg4, arg5) {
        // 防止递归调用 - 关键保护机制
        if (isTracing) {
            console.log("[-] 检测到递归调用，直接调用原始函数（避免栈溢出）");
            return originalFunc(arg0, arg1, arg2, arg3, arg4, arg5);
        }
        
        console.log("[+] trace调用了");
        
        isTracing = true;
        
        try {
            // 关键：先 revert，避免递归调用
            // 这两句代码保证被替换的函数只被替换一次后就被还原，保证你的trace只走一次，只生成一份log
            // 防止一个高频调用的函数一直处于trace状态，导致trace文件被覆盖
            Interceptor.revert(funcAddress);
            Interceptor.flush();
            
            // 准备参数 - 根据实际函数参数数量修改
            var args = [arg0, arg1, arg2, arg3, arg4, arg5];  // TODO: 根据实际函数参数数量修改
            var {argsPtr, argNum} = prepareArgs(args);
            var argPtr1 = Memory.allocUtf8String(logPath);
            
            console.log("[*] 调用 vm_call 进行 trace...");
            console.log("[*] 函数地址: " + funcAddress);
            console.log("[*] 参数数量: " + argNum);
            console.log("[*] 日志路径: " + logPath);
            console.log("[*] 已 revert 拦截器，isTracing=true 防止递归");
            
            // 按照参考代码，先 revert 后传入原始地址
            // 最后一个参数：6 或 0（不是 windowSize）
            // 注意：vm_call 内部会调用 funcAddress，此时拦截器已 revert，isTracing=true 会防止递归
            var res = vmtrace(funcAddress, argsPtr, argNum, argPtr1, 6);
            
            console.log("[+] Trace 完成，返回结果: " + res);
            console.log("[+] Trace 日志已保存到: " + logPath);
            console.log("[!] 建议立即退出 (Ctrl+D)，避免其他调用干扰");
            
            isTracing = false;
            return res;
            
        } catch (e) {
            isTracing = false;
            console.error("[-] Trace 失败: " + e);
            console.error("[-] 错误详情: " + e.message);
            console.error("[-] 堆栈: " + e.stack);
            
            // trace 失败时回退到直接调用原始函数
            return originalFunc(arg0, arg1, arg2, arg3, arg4, arg5);
        }
    }, returnType, paramTypes));
    
    console.log("[+] Hook 安装成功！");
    console.log("[!] 使用方法: 在 Frida console 中输入 call() 进行主动调用");
    
    // 调用主动调用函数
    // call();
}

function hook_soload() {
    // 判断文件是否存在，避免系统二次或n次调用被覆盖
    if (checkFileExists(logPath)) {
        console.log("[!] 文件已存在: " + logPath);
        console.log("[!] 跳过 hook，避免覆盖已有日志");
        return;
    }

    var dlopenPtr = Module.findExportByName(null, 'dlopen');
    var dlopen = new NativeFunction(dlopenPtr, 'pointer', ['pointer', 'int']);
    var soPath = "/data/local/tmp/test.so"; // 示例路径
    var soPathPtr = Memory.allocUtf8String(soPath);
    var handle = dlopen(soPathPtr, 2);
    
    if (handle.isNull()) {
        console.error("[-] dlopen 失败！请检查：");
        console.error("    1. SELinux 是否已关闭: setenforce 0");
        console.error("    2. test.so 是否已推送到 /data/local/tmp/");
        return;
    }
    
    console.log("[+] test.so 加载成功，handle: " + handle);
    
    vmtraceAddr = Module.findExportByName("test.so", 'vm_call');
    if (!vmtraceAddr) {
        console.error("[-] 无法找到 vm_call 函数");
        console.error("[-] 请确认使用的是旧版 test.so");
        return;
    }
    
    console.log("[+] 找到 vm_call 函数: " + vmtraceAddr);
    vmtrace = new NativeFunction(vmtraceAddr, 'pointer', ['pointer', 'pointer', 'uint32', 'pointer', 'uint32']);

    // 直接调用 hook，为了防止多次调用，从而生成的名文和密钥不一致
    hook_target_function();
}

// ==================== 主动调用函数 ====================
function call() {
    Java.perform(function() {
        console.log("=".repeat(80));
        console.log("[*] 开始主动调用目标函数...");
        console.log("=".repeat(80));
        
        try {
            // ========== 根据实际情况修改以下代码 ==========
            
            // 示例：调用 SecurityTool.getVX
            var SecurityTool = Java.use('com.max.security.SecurityTool');
            var ActivityThread = Java.use('android.app.ActivityThread');
            var currentApplication = ActivityThread.currentApplication();
            var context = currentApplication.getApplicationContext();
            var arg1 = "HPPDCEAENEHBFHPASRDCAMNHJLAAPF";
            
            console.log("[*] 输入参数:");
            console.log("    context: " + context);
            console.log("    arg1: " + arg1);
            
            // 调用目标方法并获取返回值
            var result = SecurityTool.getVX(context, arg1);
            
            // 输出输入参数
            console.log("input: ", context, arg1);
            
            // 发送返回值到 Frida 客户端
            send(result);
            
            // 输出返回结果
            console.log("output: ", result);
            
        } catch (e) {
            console.error("[-] 主动调用失败: " + e);
            console.error("[-] 错误详情: " + e.message);
            if (e.stack) {
                console.error("[-] 堆栈: " + e.stack);
            }
        }
    });
}

// 自动启动 hook
setImmediate(hook_soload);
