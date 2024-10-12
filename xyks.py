import json

import frida

import binascii

sc = '''

function Hookr2B(){
    Java.perform(function(){
        let r2 = Java.use("com.fenbi.android.leo.utils.r2");
        console.log("XYKS r2 函数已钩住")
        r2.b.overload("[B").implementation = function (data) {
            var String= Java.use("java.lang.String");

            let data_ori = data

            data = Bytes2HexString(data)
            send(data)

            let new_data
            let new_data_2
            var instance
            recv(function (received_json_object) {
                new_data = received_json_object.my_data
                instance = String.$new(new_data);
                new_data_2 = instance.getBytes()

            }).wait();

            let result = this["b"](new_data_2);
            console.log('参数劫持完成，即将Return')
            return result;
        };
    });
}




function Bytes2HexString(arrBytes) {
    var str = "";
    for (var i = 0; i < arrBytes.length; i++) {
        var tmp;
        var num = arrBytes[i];
        if (num < 0) {
            //此处填坑，当byte因为符合位导致数值为负时候，需要对数据进行处理
            tmp = (255 + num + 1).toString(16);
        } else {
            tmp = num.toString(16);
        }
        if (tmp.length == 1) {
            tmp = "0" + tmp;
        }
        str += tmp;
    }
    return str;
}


setImmediate(Hookr2B);




'''



def str_to_hex_binascii(input_str):
    # 将字符串编码为字节
    byte_data = input_str.encode('utf-8')
    # 转换为十六进制
    hex_output = binascii.hexlify(byte_data)
    return hex_output.decode('utf-8')


def my_message_handler(message, payload):


    bytes_obj = bytes.fromhex(message['payload'])

    string = bytes_obj.decode('utf-8')


    string = string.replace(r'\"', "%")


    json_data = json.loads(string)
    print('原始花费时间：', json_data['costTime'])

    json_data['costTime'] = 2000

    print('现在花费时间：', json_data['costTime'])
    data = str(json_data).replace('%', r'\"')
    data = str(data).replace('\'', '\"')
    data = str(data).replace(' ', '')


    script.post({'type': 'send', 'my_data': data})




str_host = '192.168.2.204:6666'
manager = frida.get_device_manager()
device = manager.add_remote_device(str_host)


session = device.attach('小猿口算')

script = session.create_script(sc)
script.on("message", my_message_handler)
script.load()
input()