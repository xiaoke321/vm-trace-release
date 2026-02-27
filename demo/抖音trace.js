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
        if (!arg){
            arg=0
        }
        if (arg instanceof NativePointer) {
            // 如果是 NativePointer，直接使用
            argPtr = arg;
        }else if(typeof arg === 'object' ){
            // 如果是对象，直接转换为指针
            //形如 jstring Java_com_demo_app_genToken(JNIEnv *env, jobject obj, long str)这种registerNative的函数参数对象可以处理
            argPtr = ptr(arg);
        }

        else if (typeof arg === 'number') {
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

function hook_sub_1329B0() {
    // var lib =Module.findBaseAddress("libmetasec_ml.so");
    // var funcAddress = lib.add(0x000000000014DBF4);
    var lib = Process.findModuleByName("libmetasec_ml.so")      // TODO 科：注意区分这个不能用报错的话，使用上面的。
    console.log("start hook");
    var funcAddress = lib.base.add(0x000000000014DBF4);                             // TODO 科：注意区分这个不能用报错的话，使用上面的。
    Interceptor.replace(funcAddress, new NativeCallback(function (arg0,arg1,arg2,arg3,arg4,arg5) {
        console.log("trace调用了");
        Interceptor.revert(funcAddress);
        Interceptor.flush();
        var args =[arg0,arg1];              // TODO 科：其他不用变，这里面的函数的参数是几个就写几个
        var {argsPtr, argNum} = prepareArgs(args);
        var argPtr1 = Memory.allocUtf8String("/data/user/0/com.ss.android.ugc.aweme/log.txt");
        var res =vmtrace(funcAddress, argsPtr,argNum,argPtr1,6);
        console.log(res)
        return res;
    }, 'pointer', ['pointer','pointer']));
    main(funcAddress);
}

function hook_soload() {
    var targetPath = "/data/user/0/com.ss.android.ugc.aweme/log.txt";       // TODO 科：判断文件是否存在，避免系统二次或n次调用被覆盖
    if (checkFileExists(targetPath)) {
        console.log("文件存在: " + targetPath);
    } else {
        var  dlopenPtr = Module.findExportByName(null, 'dlopen');
        var  dlopen = new NativeFunction(dlopenPtr, 'pointer', ['pointer', 'int']);
        var soPath = "/data/local/tmp/test.so"; // 示例路径
        var  soPathPtr = Memory.allocUtf8String(soPath);
        var handle = dlopen(soPathPtr, 2);
        console.log(handle);
        vmtraceAddr = Module.findExportByName("test.so", 'vm_call');
        vmtrace = new NativeFunction(vmtraceAddr, 'pointer', ['pointer', 'pointer', 'uint32','pointer','uint32']);

        hook_sub_1329B0();                          // TODO 科：直接内存调用，为了防止多次调用，从而生成的名文和密钥不一致
    }

}

// setImmediate(hook_soload)

function main(funcAddress) {

    const args0 = "https://api6-normal-lf.amemv.com/passport/mobile/login/?passport-sdk-version=60153&request_from_account_sdk=1&iid=1268167030605560&device_id=2235737262289831&ac=wifi&channel=vivo_1128_64&aid=1128&ap_name=aweme&version_code=340500&version_name=34.5.0&device_platform=android&os=android&ssmix=a&device_type=ONEPLUS+A5000&device_brand=OnePlus&language=zh&os_api=29&os_version=10&manifest_version_code=340501&resolution=1080*1920&dpi=420&update_version_code=34509900&_rticket=1749260040808&package=com.ss.android.ugc.aweme&first_launch_timestamp=1749195468&last_deeplink_update_version_code=0&cpu_support64=true&host_abi=arm64-v8a&is_guest_mode=0&app_type=normal&minor_status=0&appTheme=light&is_preinstall=0&need_personal_recommend=1&is_android_pad=0&is_android_fold=0&ts=1749260040&cdid=5787ea18-efd7-40ff-bc4f-89f99edaf4e8&cronet_version=7424e438_2025-04-16&ttnet_version=4.2.228.8-douyin&use_store_region_cookie=1";
    const args1 = 'cookie\r\n' +
        'odin_tt=1dbc95c8884e5bc49bec7fa6284e2da6e6f9021976dc60d94778b367d1b79b226c8183f94d387c972a3148134d16241f8ce5363caae8a0dbaeb45c678acf4ee331a24e1d0e90f8181d588f96eb7a7bfc; passport_csrf_token=f45b70e67173582709add9a7f77ec99c; passport_csrf_token_default=f45b70e67173582709add9a7f77ec99c; store-region=cn-sn; store-region-src=did\r\n' +
        'x-tm-md\r\n' +
        '0\r\n' +
        'x-tt-sampling\r\n' +
        'timon_device_10\r\n' +
        'accept-encoding\r\n' +
        'gzip\r\n' +
        'content-encoding\r\n' +
        'gzip\r\n' +
        'x-tt-request-tag\r\n' +
        't=0;n=0;s=-1;p=0\r\n' +
        'x-ss-req-ticket\r\n' +
        '1749345220575\r\n' +
        'x-vc-bdturing-sdk-version\r\n' +
        '4.0.0.cn\r\n' +
        'sdk-version\r\n' +
        '2\r\n' +
        'passport-sdk-version\r\n' +
        '60153\r\n' +
        'content-type\r\n' +
        'application/octet-stream\r\n' +
        'x-ss-stub\r\n' +
        '73E93614C46EB3E08169075B6FAA8FC5\r\n' +
        'content-length\r\n' +
        '848\r\n' +
        'x-tt-store-region\r\n' +
        'cn-sn\r\n' +
        'x-tt-store-region-src\r\n' +
        'did\r\n' +
        'x-ss-dp\r\n' +
        '1128\r\n' +
        'x-tt-trace-id\r\n' +
        '01-4d19b98a0d7f164255473a70c8070468-4d19b98a0d7f1642-00\r\n' +
        'user-agent\r\n' +
        'com.ss.android.ugc.aweme/340501 (Linux; U; Android 10; zh_CN; ONEPLUS A5000; Build/QQ3A.200805.001; Cronet/TTNetVersion:7424e438 2025-04-16 QuicVersion:ed2ea7c5 2025-03-27)\r\n';

    // 定义函数类型 (返回char*，两个char*参数)
    const nativeFunc  = new NativeFunction(
        funcAddress,
        'pointer', // 返回值类型为指针(char*)
        ['pointer', 'pointer'], // 两个指针参数
    );
   var args0_block = Memory.alloc(args0.length, true).writeUtf8String(args0);
   var args1_block = Memory.alloc(args1.length, true).writeUtf8String(args1);
    const resultPtr = nativeFunc(args0_block, args1_block);
    const resultString = resultPtr.readUtf8String();
    console.log(`[+] 函数调用成功，返回值:`);
    console.log(resultString);
}
