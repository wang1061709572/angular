//数据格式编码
myApp.factory('aliYun',function(){
    var chrsz   = 8;
    var b64pad  = "=";
    var Base64 = {
        
        // private property
        _keyStr : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
        
        // public method for encoding
        encode : function (input) {
            var output = "";
            var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
            var i = 0;
            
            input = Base64._utf8_encode(input);
            
            while (i < input.length) {
                
                chr1 = input.charCodeAt(i++);
                chr2 = input.charCodeAt(i++);
                chr3 = input.charCodeAt(i++);
                
                enc1 = chr1 >> 2;
                enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
                enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
                enc4 = chr3 & 63;
                
                if (isNaN(chr2)) {
                    enc3 = enc4 = 64;
                } else if (isNaN(chr3)) {
                    enc4 = 64;
                }
                
                output = output +
                    this._keyStr.charAt(enc1) + this._keyStr.charAt(enc2) +
                    this._keyStr.charAt(enc3) + this._keyStr.charAt(enc4);
                
            }
            
            return output;
        },
        
        // public method for decoding
        decode : function (input) {
            var output = "";
            var chr1, chr2, chr3;
            var enc1, enc2, enc3, enc4;
            var i = 0;
            
            input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");
            
            while (i < input.length) {
                
                enc1 = this._keyStr.indexOf(input.charAt(i++));
                enc2 = this._keyStr.indexOf(input.charAt(i++));
                enc3 = this._keyStr.indexOf(input.charAt(i++));
                enc4 = this._keyStr.indexOf(input.charAt(i++));
                
                chr1 = (enc1 << 2) | (enc2 >> 4);
                chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
                chr3 = ((enc3 & 3) << 6) | enc4;
                
                output = output + String.fromCharCode(chr1);
                
                if (enc3 != 64) {
                    output = output + String.fromCharCode(chr2);
                }
                if (enc4 != 64) {
                    output = output + String.fromCharCode(chr3);
                }
                
            }
            
            output = Base64._utf8_decode(output);
            
            return output;
            
        },
        
        // private method for UTF-8 encoding
        _utf8_encode : function (string) {
            string = string.replace(/\r\n/g,"\n");
            var utftext = "";
            
            for (var n = 0; n < string.length; n++) {
                
                var c = string.charCodeAt(n);
                
                if (c < 128) {
                    utftext += String.fromCharCode(c);
                }
                else if((c > 127) && (c < 2048)) {
                    utftext += String.fromCharCode((c >> 6) | 192);
                    utftext += String.fromCharCode((c & 63) | 128);
                }
                else {
                    utftext += String.fromCharCode((c >> 12) | 224);
                    utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                    utftext += String.fromCharCode((c & 63) | 128);
                }
                
            }
            
            return utftext;
        },
        
        // private method for UTF-8 decoding
        _utf8_decode : function (utftext) {
            var string = "";
            var i = 0;
            var c = c1 = c2 = 0;
            
            while ( i < utftext.length ) {
                
                c = utftext.charCodeAt(i);
                
                if (c < 128) {
                    string += String.fromCharCode(c);
                    i++;
                }
                else if((c > 191) && (c < 224)) {
                    c2 = utftext.charCodeAt(i+1);
                    string += String.fromCharCode(((c & 31) << 6) | (c2 & 63));
                    i += 2;
                }
                else {
                    c2 = utftext.charCodeAt(i+1);
                    c3 = utftext.charCodeAt(i+2);
                    string += String.fromCharCode(((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
                    i += 3;
                }
                
            }
            
            return string;
        }
        
    };
    var b64_hmac_sha1=function b64_hmac_sha1(key, data){ return binb2b64(core_hmac_sha1(key, data));}
    var core_hmac_sha1= function core_hmac_sha1(key, data)
    {
        var bkey = str2binb(key);
        if(bkey.length > 16) bkey = core_sha1(bkey, key.length * chrsz);
        
        var ipad = Array(16), opad = Array(16);
        for(var i = 0; i < 16; i++)
        {
            ipad[i] = bkey[i] ^ 0x36363636;
            opad[i] = bkey[i] ^ 0x5C5C5C5C;
        }
        
        var hash = core_sha1(ipad.concat(str2binb(data)), 512 + data.length * chrsz);
        return core_sha1(opad.concat(hash), 512 + 160);
    }
    var binb2b64=function binb2b64(binarray)
    {
        var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var str = "";
        for(var i = 0; i < binarray.length * 4; i += 3)
        {
            var triplet = (((binarray[i   >> 2] >> 8 * (3 -  i   %4)) & 0xFF) << 16)
                | (((binarray[i+1 >> 2] >> 8 * (3 - (i+1)%4)) & 0xFF) << 8 )
                |  ((binarray[i+2 >> 2] >> 8 * (3 - (i+2)%4)) & 0xFF);
            for(var j = 0; j < 4; j++)
            {
                if(i * 8 + j * 6 > binarray.length * 32) str += b64pad;
                else str += tab.charAt((triplet >> 6*(3-j)) & 0x3F);
            }
        }
        return str;
    }
    var str2binb=function str2binb(str) {
        var bin = Array();
        var mask = (1 << chrsz) - 1;
        for(var i = 0; i < str.length * chrsz; i += chrsz)
            bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (32 - chrsz - i%32);
        return bin;
    }
    var core_sha1=function core_sha1(x, len) {
        /* append padding */
        x[len >> 5] |= 0x80 << (24 - len % 32);
        x[((len + 64 >> 9) << 4) + 15] = len;
        
        var w = Array(80);
        var a =  1732584193;
        var b = -271733879;
        var c = -1732584194;
        var d =  271733878;
        var e = -1009589776;
        
        for(var i = 0; i < x.length; i += 16)
        {
            var olda = a;
            var oldb = b;
            var oldc = c;
            var oldd = d;
            var olde = e;
            
            for(var j = 0; j < 80; j++)
            {
                if(j < 16) w[j] = x[i + j];
                else w[j] = rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
                var t = safe_add(safe_add(rol(a, 5), sha1_ft(j, b, c, d)),
                    safe_add(safe_add(e, w[j]), sha1_kt(j)));
                e = d;
                d = c;
                c = rol(b, 30);
                b = a;
                a = t;
            }
            
            a = safe_add(a, olda);
            b = safe_add(b, oldb);
            c = safe_add(c, oldc);
            d = safe_add(d, oldd);
            e = safe_add(e, olde);
        }
        return Array(a, b, c, d, e);
        
    }
    var safe_add=function safe_add(x, y)
    {
        var lsw = (x & 0xFFFF) + (y & 0xFFFF);
        var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        return (msw << 16) | (lsw & 0xFFFF);
    }
    var rol=function rol(num, cnt)
    {
        return (num << cnt) | (num >>> (32 - cnt));
    }
    var sha1_ft=function sha1_ft(t, b, c, d)
    {
        if(t < 20) return (b & c) | ((~b) & d);
        if(t < 40) return b ^ c ^ d;
        if(t < 60) return (b & c) | (b & d) | (c & d);
        return b ^ c ^ d;
    }
    var sha1_kt=function sha1_kt(t)
    {
        return (t < 20) ?  1518500249 : (t < 40) ?  1859775393 :
            (t < 60) ? -1894007588 : -899497514;
    }
    var base64=function () {
        return Base64;
    }
    return{
        base64:base64,
        b64_hmac_sha1:b64_hmac_sha1,
        core_hmac_sha1:core_hmac_sha1,
        binb2b64: binb2b64,
        str2binb:str2binb,
        core_sha1:core_sha1,
        safe_add:safe_add,
        rol: rol,
        sha1_ft:sha1_ft,
        sha1_kt:sha1_kt,
    }
});
//上传到阿里云oss存储
myApp.service('uploadaliyun', ["$rootScope","aliYun",function($rootScope,aliYun) {
    var convertBase64UrlToBlob = function (urlData) {
        var bytes = window.atob(urlData.split(',')[1]);        //去掉url的头，并转换为byte
        //处理异常,将ascii码小于0的转换为大于0
        var ab = new ArrayBuffer(bytes.length);
        var ia = new Uint8Array(ab);
        for (var i = 0; i < bytes.length; i++) {
            ia[i] = bytes.charCodeAt(i);
        }
        return new Blob([ab], {type: 'image/png'});
    }
    /*设置图片在哪个文件夹下*/
    var setfilename = function () {
        var year = new Date().getFullYear(),
            mouth = new Date().getMonth() + 1,
            day = new Date().getDate();
        var str1 = year + '/' + mouth + '/' + day + '/';
        var str = str1 + '${filename}';
        return str;
    }
    var uuid = function () {
        var s = [];
        var hexDigits = "0123456789abcdef";
        for (var i = 0; i < 36; i++) {
            s[i] = hexDigits.substr(Math.floor(Math.random() * 0x10), 1);
        }
        s[14] = "4";  // bits 12-15 of the time_hi_and_version field to 0010
        s[19] = hexDigits.substr((s[19] & 0x3) | 0x8, 1);  // bits 6-7 of the clock_seq_hi_and_reserved to 01
        s[8] = s[13] = s[18] = s[23] = "";
        var uuid = s.join("");
        return uuid;
    }
    var setphotoname = function (number) {
        var hour = new Date().getHours(),
            minute = new Date().getMinutes();
        var str = '-' + hour + minute + '-' + uuid() + '.' + 'png';
        return str;
    }
    var getaliyun = function (src) {
        var askey = aliyun.askey;
        var policyText = '{"expiration": "2120-01-01T12:00:00.000Z","conditions": [["content-length-range", 0, 104857600]]}';
        var pocity = aliYun.base64().encode(policyText);
        var Signature = aliYun.b64_hmac_sha1(askey, pocity);
        var request = new FormData();
        request.append('OSSAccessKeyId', aliyun.OSSAccessKeyId);
        request.append('policy', pocity);
        request.append('Signature', Signature);
        request.append('key', setfilename());//上传的路径
        request.append('file', convertBase64UrlToBlob(src), setphotoname());
        request.append('submit', "Upload to OSS");
        return request;
    }
    //上传单张图片
    var postonephote = function (src) {
        var request = getaliyun(src);
        $.ajax({
            url: aliyunImg,
            data: request,
            processData: false,
            cache: false,
            async: true,
            contentType: false,
            timeout: 15000,
            //关键是要设置contentType 为false，不然发出的请求头 没有boundary
            //该参数是让jQuery去判断contentType
            xhr:function () {
                myXhr = $.ajaxSettings.xhr();
                myXhr.upload.onprogress = function (ev) {
                    if(ev.lengthComputable) {
                        var percent = 100 * ev.loaded/ev.total;
                        console.log('-------上传百分比')
                        console.log(percent)//这个就是当前文件状态的百分比（可进行进度条展示）
                    }
                }
                return myXhr; //xhr对象返回给jQuery使用
            },
            type: "POST",
            success: function (data, textStatus, request) {
                $rootScope.$broadcast('uploadOk','OK');//上传成功提示
            },
            error: function (XMLHttpRequest, textStatus, errorThrown) {
                $rootScope.$broadcast('uploadOk','err');//上传失败提示
            }
        });
    }
    return {
        uploadImgtoAliyun:postonephote
    }
}]);