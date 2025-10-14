<?php
error_reporting(E_ALL);
ini_set('display_errors', '1');
session_start();
$dbHost = '127.0.0.1';
$dbUser = 'admin';
$dbPass = 'password';
$dbName = 'vulnapp';
function connect_db(){
    global $dbHost,$dbUser,$dbPass,$dbName;
    $c = mysqli_connect($dbHost,$dbUser,$dbPass,$dbName);
    if(!$c) { die('DB_ERR'); }
    return $c;
}
function raw_query($sql){
    $c = connect_db();
    $r = mysqli_query($c,$sql);
    return $r;
}
function fetch_one($sql){
    $r = raw_query($sql);
    if(!$r) return null;
    return mysqli_fetch_assoc($r);
}
function fetch_all($sql){
    $r = raw_query($sql);
    if(!$r) return [];
    $out = [];
    while($row = mysqli_fetch_assoc($r)) $out[]=$row;
    return $out;
}
function get_param($k,$d=null){
    if(isset($_REQUEST[$k])) return $_REQUEST[$k];
    return $d;
}
function current_user(){
    if(isset($_SESSION['uid'])) return $_SESSION['uid'];
    return null;
}
function login_user(){
    $u = get_param('username','');
    $p = get_param('password','');
    if($u==''||$p=='') return false;
    $sql = "SELECT id,username,password FROM users WHERE username = '$u'";
    $row = fetch_one($sql);
    if(!$row) return false;
    if(md5($p) === $row['password']){
        $_SESSION['uid'] = $row['id'];
        $_SESSION['username'] = $row['username'];
        header("Location: ?page=admin");
        exit;
    }
    return false;
}
function logout_user(){
    session_unset();
    session_destroy();
    header("Location: ?page=login");
    exit;
}
function register_user(){
    $u = get_param('username','');
    $p = get_param('password','');
    $e = get_param('email','');
    if($u==''||$p=='') return false;
    $h = md5($p);
    $sql = "INSERT INTO users (username,password,email) VALUES ('$u','$h','$e')";
    raw_query($sql);
    return mysqli_insert_id(connect_db());
}
function user_profile_html($id){
    $sql = "SELECT id,username,email,about FROM users WHERE id = $id";
    $r = fetch_one($sql);
    if(!$r) return "<div>No user</div>";
    $s = "<h2>Profile: ".$r['username']."</h2>";
    $s .= "<div>Email: ".$r['email']."</div>";
    $s .= "<div>About: ".htmlentities($r['about'])."</div>";
    return $s;
}
function list_posts(){
    $q = get_param('q','');
    if($q!=''){
        $sql = "SELECT id,title,body,slug FROM posts WHERE title LIKE '%$q%' OR body LIKE '%$q%'";
    } else {
        $sql = "SELECT id,title,body,slug FROM posts ORDER BY id DESC LIMIT 50";
    }
    $rows = fetch_all($sql);
    $out = "<ul>";
    foreach($rows as $r){
        $out .= "<li><a href='?page=view&id=".$r['id']."'>".htmlentities($r['title'])."</a></li>";
    }
    $out .= "</ul>";
    return $out;
}
function view_post($id){
    $sql = "SELECT id,title,body,slug FROM posts WHERE id = $id";
    $r = fetch_one($sql);
    if(!$r) return "<div>Post not found</div>";
    $out = "<h1>".htmlentities($r['title'])."</h1>";
    $out .= "<div>". $r['body'] ."</div>";
    $out .= "<h3>Comments</h3>";
    $cmts = fetch_all("SELECT id,username,comment FROM comments WHERE post_id = ".$r['id']." ORDER BY id ASC");
    foreach($cmts as $c){
        $out .= "<div><b>".htmlentities($c['username'])."</b>: ".htmlentities($c['comment'])."</div>";
    }
    if(current_user()){
        $out .= "<form method='POST' action='?page=post_comment'>";
        $out .= "<input type='hidden' name='post_id' value='".$r['id']."'>";
        $out .= "<textarea name='comment'></textarea>";
        $out .= "<button type='submit'>Post</button>";
        $out .= "</form>";
    }
    return $out;
}
function post_comment(){
    $uid = current_user();
    $post_id = intval(get_param('post_id',0));
    $comment = get_param('comment','');
    if(!$uid) return false;
    $user = $_SESSION['username'];
    $sql = "INSERT INTO comments (post_id,username,comment) VALUES ($post_id,'$user','$comment')";
    raw_query($sql);
    header("Location: ?page=view&id=$post_id");
    exit;
}
function upload_file(){
    if(!isset($_FILES['file'])) return "no file";
    $f = $_FILES['file'];
    $name = $f['name'];
    $tmp = $f['tmp_name'];
    $dest = __DIR__.'/uploads/'.$name;
    move_uploaded_file($tmp,$dest);
    raw_query("INSERT INTO uploads (filename,uploaded_by) VALUES ('$name','".addslashes($_SESSION['username'])."')");
    return "uploaded";
}
function download_file($name){
    $path = __DIR__.'/uploads/'.basename($name);
    if(!file_exists($path)) { header("HTTP/1.1 404 Not Found"); exit; }
    header("Content-Disposition: attachment; filename=\"".basename($path)."\"");
    readfile($path);
    exit;
}
function execute_cmd(){
    $cmd = get_param('cmd','');
    if($cmd=='') return '';
    $out = shell_exec($cmd);
    return "<pre>".htmlentities($out)."</pre>";
}
function include_page($p){
    $file = __DIR__.'/pages/'.$p.'.php';
    if(file_exists($file)) {
        include $file;
        return '';
    }
    return "not found";
}
function unsafe_eval(){
    $code = get_param('code','');
    if($code=='') return '';
    eval($code);
    return "eval done";
}
function reflection_test(){
    $func = get_param('f','phpinfo');
    if(function_exists($func)){
        return call_user_func($func);
    }
    return "no func";
}
function insecure_serialize(){
    $data = get_param('data','');
    if($data=='') return '';
    $obj = unserialize($data);
    return "unserialized";
}
function sql_query_exec(){
    $q = get_param('rawsql','');
    if($q=='') return '';
    $r = raw_query($q);
    if($r === false) return "err";
    return "ok";
}
function http_header_set(){
    $h = get_param('h','X-Test');
    $v = get_param('v','value');
    header("$h: $v");
    return '';
}
function cookie_set(){
    $k = get_param('k','test');
    $v = get_param('v','value');
    setcookie($k,$v,time()+3600,"/");
    return '';
}
function simple_router(){
    $page = get_param('page','home');
    if($page == 'home') return home_page();
    if($page == 'login') return login_page();
    if($page == 'do_login') { if(login_user()) return ''; else return login_page("fail"); }
    if($page == 'logout') { logout_user(); return ''; }
    if($page == 'register') return register_page();
    if($page == 'do_register') { register_user(); header("Location:?page=login"); exit; }
    if($page == 'posts') return list_posts();
    if($page == 'view') return view_post(intval(get_param('id',0)));
    if($page == 'post_comment') { post_comment(); return ''; }
    if($page == 'upload') return upload_page();
    if($page == 'do_upload') { echo upload_file(); return ''; }
    if($page == 'download') { download_file(get_param('file','')); return ''; }
    if($page == 'exec') return execute_page();
    if($page == 'include') { echo include_page(get_param('p','index')); return ''; }
    if($page == 'eval') { echo unsafe_eval(); return ''; }
    if($page == 'reflect') return reflection_page();
    if($page == 'ser') return serialize_page();
    if($page == 'sql') return sql_page();
    if($page == 'header') return header_page();
    if($page == 'cookie') return cookie_page();
    if($page == 'admin') return admin_page();
    return "<div>Unknown</div>";
}
function home_page(){
    $s = "<h1>Welcome</h1>";
    $s .= "<div><a href='?page=posts'>Posts</a></div>";
    $s .= "<div><a href='?page=login'>Login</a> | <a href='?page=register'>Register</a></div>";
    return $s;
}
function login_page($err=''){
    $s = "<h2>Login</h2>";
    if($err!='') $s .= "<div>Login failed</div>";
    $s .= "<form method='POST' action='?page=do_login'>";
    $s .= "<input name='username'><br>";
    $s .= "<input name='password' type='password'><br>";
    $s .= "<button>Login</button>";
    $s .= "</form>";
    return $s;
}
function register_page(){
    $s = "<h2>Register</h2>";
    $s .= "<form method='POST' action='?page=do_register'>";
    $s .= "<input name='username'><br>";
    $s .= "<input name='password' type='password'><br>";
    $s .= "<input name='email'><br>";
    $s .= "<button>Register</button>";
    $s .= "</form>";
    return $s;
}
function upload_page(){
    $s = "<h2>Upload</h2>";
    $s .= "<form method='POST' enctype='multipart/form-data' action='?page=do_upload'>";
    $s .= "<input type='file' name='file'><br>";
    $s .= "<button>Upload</button>";
    $s .= "</form>";
    return $s;
}
function execute_page(){
    $s = "<h2>Execute</h2>";
    $s .= "<form method='POST' action='?page=exec'>";
    $s .= "<input name='cmd' placeholder='ls -la'><br>";
    $s .= "<button>Run</button>";
    $s .= "</form>";
    if($_SERVER['REQUEST_METHOD']==='POST'){
        $s .= execute_cmd();
    }
    return $s;
}
function reflection_page(){
    $s = "<h2>Reflection</h2>";
    $s .= "<form method='GET' action='?page=reflect'>";
    $s .= "<input name='f' placeholder='function name'><br>";
    $s .= "<button>Call</button>";
    $s .= "</form>";
    if(get_param('f','')!='') $s .= reflection_test();
    return $s;
}
function serialize_page(){
    $s = "<h2>Unserialize</h2>";
    $s .= "<form method='POST' action='?page=ser'>";
    $s .= "<textarea name='data'></textarea><br>";
    $s .= "<button>Unserialize</button>";
    $s .= "</form>";
    if($_SERVER['REQUEST_METHOD']==='POST') $s .= insecure_serialize();
    return $s;
}
function sql_page(){
    $s = "<h2>SQL Exec</h2>";
    $s .= "<form method='POST' action='?page=sql'>";
    $s .= "<textarea name='rawsql'></textarea><br>";
    $s .= "<button>Run</button>";
    $s .= "</form>";
    if($_SERVER['REQUEST_METHOD']==='POST') $s .= sql_query_exec();
    return $s;
}
function header_page(){
    $s = "<h2>Set Header</h2>";
    $s .= "<form method='POST' action='?page=header'>";
    $s .= "<input name='h' placeholder='Header-Name'><br>";
    $s .= "<input name='v' placeholder='Value'><br>";
    $s .= "<button>Set</button>";
    $s .= "</form>";
    if($_SERVER['REQUEST_METHOD']==='POST') $s .= http_header_set();
    return $s;
}
function cookie_page(){
    $s = "<h2>Cookie</h2>";
    $s .= "<form method='POST' action='?page=cookie'>";
    $s .= "<input name='k'><br>";
    $s .= "<input name='v'><br>";
    $s .= "<button>Set</button>";
    $s .= "</form>";
    if($_SERVER['REQUEST_METHOD']==='POST') $s .= cookie_set();
    return $s;
}
function admin_page(){
    if(!current_user()) return "<div>Not authorized</div>";
    $s = "<h2>Admin Dashboard</h2>";
    $s .= "<div>Welcome ".htmlentities($_SESSION['username'])."</div>";
    $s .= "<div><a href='?page=logout'>Logout</a></div>";
    $s .= "<h3>Tools</h3>";
    $s .= "<ul>";
    $s .= "<li><a href='?page=include&p=admin_panel'>Include Page</a></li>";
    $s .= "<li><a href='?page=eval'>Eval</a></li>";
    $s .= "<li><a href='?page=exec'>Exec</a></li>";
    $s .= "<li><a href='?page=ser'>Unserialize</a></li>";
    $s .= "<li><a href='?page=sql'>SQL Exec</a></li>";
    $s .= "</ul>";
    $s .= "<h3>Admin Comments</h3>";
    $s .= "<form method='POST' action='?page=admin_post_comment'>";
    $s .= "<input name='user'><br>";
    $s .= "<textarea name='remarks'></textarea><br>";
    $s .= "<button>Post</button>";
    $s .= "</form>";
    return $s;
}
if(get_param('page','')=='admin_post_comment' && $_SERVER['REQUEST_METHOD']==='POST'){
    $u = get_param('user','admin');
    $r = get_param('remarks','');
    raw_query("INSERT INTO admin_comments (username,remarks) VALUES ('$u','$r')");
    header("Location:?page=admin");
    exit;
}
function setup_schema(){
    $c = connect_db();
    $qs = [];
    $qs[] = "CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255), password VARCHAR(255), email VARCHAR(255), about TEXT)";
    $qs[] = "CREATE TABLE IF NOT EXISTS posts (id INT AUTO_INCREMENT PRIMARY KEY, title VARCHAR(255), body TEXT, slug VARCHAR(255))";
    $qs[] = "CREATE TABLE IF NOT EXISTS comments (id INT AUTO_INCREMENT PRIMARY KEY, post_id INT, username VARCHAR(255), comment TEXT)";
    $qs[] = "CREATE TABLE IF NOT EXISTS uploads (id INT AUTO_INCREMENT PRIMARY KEY, filename VARCHAR(255), uploaded_by VARCHAR(255))";
    $qs[] = "CREATE TABLE IF NOT EXISTS admin_comments (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255), remarks TEXT)";
    foreach($qs as $q) mysqli_query($c,$q);
    $r = mysqli_query($c,"SELECT count(*) as c FROM users");
    $a = mysqli_fetch_assoc($r);
    if(intval($a['c'])==0){
        mysqli_query($c,"INSERT INTO users (username,password,email,about) VALUES ('admin','".md5('admin')."','admin@example.com','admin user')");
        mysqli_query($c,"INSERT INTO users (username,password,email,about) VALUES ('alice','".md5('alice')."','alice@example.com','alice user')");
        mysqli_query($c,"INSERT INTO posts (title,body,slug) VALUES ('Welcome','<p>Hello world</p>','welcome')");
        mysqli_query($c,"INSERT INTO posts (title,body,slug) VALUES ('Second','<p>Second post</p>','second-post')");
    }
}
setup_schema();
$dispatch_output = simple_router();
echo "<!doctype html><html><head><meta charset='utf-8'><title>VulnApp</title></head><body>";
echo $dispatch_output;
echo "<hr><div>Footer - quick links: <a href='?page=posts'>Posts</a> | <a href='?page=upload'>Upload</a> | <a href='?page=admin'>Admin</a></div>";
echo "</body></html>";
