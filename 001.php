<?php
/**
 * PHP单文件管理器
 * 功能：文件和目录管理、压缩/解压、上传/下载、内容编辑、用户认证、响应式设计
 * 版本：1.2
 */

// 配置选项
$config = array(
    // 伪装页面口令 (首次运行时填写明文，系统会自动转换为哈希值)
    'fake_page_password' => 'admin123',
    // 管理员账号密码 (首次运行时填写明文，系统会自动转换为哈希值)
    'admin_username' => 'admin',
    'admin_password' => 'admin123',
    // 根目录路径
    'root_path' => __DIR__,
    // 日志文件路径
    'log_file' => __DIR__ . '/filemanager.log',
    // 允许的上传文件类型
    'allowed_extensions' => array('jpg', 'jpeg', 'png', 'gif', 'txt','php', 'html', 'css', 'js', 'zip', 'rar', '7z', 'pdf', 'doc', 'docx', 'xls', 'xlsx'),
    // 最大上传文件大小 (字节)
    'max_upload_size' => 10485760, // 10MB
    // 时区设置
    'timezone' => 'Asia/Shanghai',
    // 会话配置
    'session_timeout' => 3600, // 会话超时时间（秒）
    // CSRF令牌配置
    'csrf_token_name' => 'csrf_token',
    // 错误报告级别
    'error_reporting' => E_ALL & ~E_NOTICE & ~E_DEPRECATED
);

// 自动处理密码哈希转换
function autoHashPasswords() {
    global $config;
    $configFile = __FILE__;
    
    // 读取配置文件内容
    $content = file_get_contents($configFile);
    if ($content === false) {
        error_log('Failed to read config file: ' . $configFile);
        return false;
    }
    
    $modified = false;
    
    // 处理管理员密码
    $adminPassword = $config['admin_password'];
    if (strlen($adminPassword) < 60 && strpos($adminPassword, '$') === false) {
        // 生成新的哈希值
        $newHash = password_hash($adminPassword, PASSWORD_DEFAULT);
        
        // 使用简单的字符串替换
        $oldString = "'admin_password' => '" . $adminPassword . "'";
        $newString = "'admin_password' => '" . $newHash . "'";
        
        // 尝试包含逗号的情况
        $oldStringWithComma = $oldString . ",";
        $newStringWithComma = $newString . ",";
        
        // 先尝试包含逗号的情况
        if (strpos($content, $oldStringWithComma) !== false) {
            $content = str_replace($oldStringWithComma, $newStringWithComma, $content);
            $modified = true;
        } elseif (strpos($content, $oldString) !== false) {
            $content = str_replace($oldString, $newString, $content);
            $modified = true;
        }
        
        if ($modified) {
            $config['admin_password'] = $newHash;
            error_log('Converted admin_password to hash');
        }
    }
    
    // 处理伪装页面口令
    $fakePagePassword = $config['fake_page_password'];
    if (strlen($fakePagePassword) < 60 && strpos($fakePagePassword, '$') === false) {
        // 生成新的哈希值
        $newHash = password_hash($fakePagePassword, PASSWORD_DEFAULT);
        
        // 使用简单的字符串替换
        $oldString = "'fake_page_password' => '" . $fakePagePassword . "'";
        $newString = "'fake_page_password' => '" . $newHash . "'";
        
        // 尝试包含逗号的情况
        $oldStringWithComma = $oldString . ",";
        $newStringWithComma = $newString . ",";
        
        // 先尝试包含逗号的情况
        if (strpos($content, $oldStringWithComma) !== false) {
            $content = str_replace($oldStringWithComma, $newStringWithComma, $content);
            $modified = true;
        } elseif (strpos($content, $oldString) !== false) {
            $content = str_replace($oldString, $newString, $content);
            $modified = true;
        }
        
        if ($modified) {
            $config['fake_page_password'] = $newHash;
            error_log('Converted fake_page_password to hash');
        }
    }
    
    // 只有在修改了内容的情况下才写入文件
    if ($modified) {
        // 检查文件是否可写
        if (!is_writable($configFile)) {
            error_log('Config file is not writable: ' . $configFile);
            return false;
        }
        
        // 写回配置文件
        $result = file_put_contents($configFile, $content);
        if ($result === false) {
            error_log('Failed to write config file: ' . $configFile);
            return false;
        } else {
            error_log('Successfully updated config file with hashed passwords');
            return true;
        }
    } else {
        error_log('No passwords needed conversion');
    }
    
    return true;
}

// 检查密码是否为明文，如果是则自动转换
function isPlainPassword($password) {
    // 简单检测：如果密码长度小于 60，并且不包含 '$' 符号，认为是明文
    return strlen($password) < 60 && strpos($password, '$') === false;
}

if (isPlainPassword($config['fake_page_password']) || isPlainPassword($config['admin_password'])) {
    // 调用自动哈希转换函数
    $result = autoHashPasswords();
    if ($result) {
        error_log('Auto hash conversion completed successfully');
    } else {
        error_log('Auto hash conversion failed');
    }
}

// 设置时区
date_default_timezone_set($config['timezone']);

// 设置错误报告级别
error_reporting($config['error_reporting']);
ini_set('display_errors', 0);

// 初始化会话
session_start();

// 设置会话参数
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_only_cookies', 1);

// 会话超时处理
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > $config['session_timeout'])) {
    session_unset();
    session_destroy();
    session_start();
}
$_SESSION['last_activity'] = time();

// 生成CSRF令牌
if (!isset($_SESSION[$config['csrf_token_name']])) {
    $_SESSION[$config['csrf_token_name']] = bin2hex(random_bytes(32));
}

// 验证密码函数
function verifyPassword($password, $hash) {
    // 兼容旧版本的明文密码
    if (password_verify($password, $hash)) {
        return true;
    }
    // 临时兼容明文密码，后续版本应完全移除
    return $password === $hash;
}

// 生成密码哈希函数
function generatePasswordHash($password) {
    return password_hash($password, PASSWORD_DEFAULT);
}

// 验证CSRF令牌函数
function verifyCsrfToken() {
    global $config;
    if (!isset($_POST[$config['csrf_token_name']]) || $_POST[$config['csrf_token_name']] !== $_SESSION[$config['csrf_token_name']]) {
        return false;
    }
    return true;
}

// 生成CSRF令牌输入字段
function csrfTokenField() {
    global $config;
    return '<input type="hidden" name="' . $config['csrf_token_name'] . '" value="' . $_SESSION[$config['csrf_token_name']] . '">';
}

// 错误处理
function handleError($errno, $errstr, $errfile, $errline) {
    global $config;
    $relativeFile = getRelativePath($errfile);
    $error = "[" . date('Y-m-d H:i:s') . "] ERROR: $errstr in $relativeFile on line $errline\n";
    file_put_contents($config['log_file'], $error, FILE_APPEND);
    return true;
}

set_error_handler('handleError');

// 日志记录函数
function logAction($action, $details = '') {
    global $config;
    $log = "[" . date('Y-m-d H:i:s') . "] ACTION: $action - $details\n";
    file_put_contents($config['log_file'], $log, FILE_APPEND);
}

// 检查是否登录
function isLoggedIn() {
    return isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;
}

// 验证路径安全性
function validatePath($path) {
    global $config;
    $realRoot = realpath($config['root_path']);
    $realPath = realpath($path);
    
    // 检查路径是否有效
    if (!$realPath || !$realRoot) {
        return false;
    }
    
    // 确保路径是根目录的子目录
    return strpos($realPath, $realRoot) === 0;
}

// 获取相对路径
function getRelativePath($path) {
    global $config;
    $realPath = realpath($path);
    $realRoot = realpath($config['root_path']);
    
    if ($realPath && $realRoot) {
        return str_replace($realRoot, '', $realPath);
    }
    return $path; // 如果无法解析路径，返回原始路径
}

// 伪装404页面处理
if (!isset($_SESSION['passed_fake_page'])) {
    if (isset($_POST['fake_password'])) {
        if (verifyPassword($_POST['fake_password'], $config['fake_page_password'])) {
            $_SESSION['passed_fake_page'] = true;
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
        } else {
            // 密码错误，保持在404页面
            showFake404Page();
            exit;
        }
    } else {
        showFake404Page();
        exit;
    }
}

// 显示伪装404页面
function showFake404Page() {
    ?>
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>404 Not Found</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f8f8f8;
                margin: 0;
                padding: 0;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                transition: background-color 0.3s ease;
            }
            .container {
                text-align: center;
                background-color: #fff;
                padding: 40px;
                border-radius: 8px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.1);
                transition: all 0.3s ease;
                animation: fadeIn 0.5s ease;
            }
            .container:hover {
                box-shadow: 0 6px 30px rgba(0,0,0,0.15);
                transform: translateY(-2px);
            }
            h1 {
                font-size: 36px;
                color: #000;
                margin-bottom: 20px;
                transition: color 0.3s ease;
            }
            p {
                font-size: 18px;
                color: #333;
                margin-bottom: 30px;
                transition: color 0.3s ease;
            }
            .search-box {
                margin-top: 20px;
                animation: slideUp 0.5s ease 0.2s both;
            }
            input[type="text"],
            input[type="password"] {
                padding: 10px;
                width: 250px;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-size: 16px;
                transition: all 0.3s ease;
            }
            input[type="text"]:focus,
            input[type="password"]:focus {
                outline: none;
                border-color: #000;
                box-shadow: 0 0 0 2px rgba(0,0,0,0.1);
            }
            input[type="submit"] {
                padding: 10px 20px;
                background-color: #000;
                color: white;
                border: none;
                border-radius: 4px;
                font-size: 16px;
                cursor: pointer;
                margin-left: 10px;
                transition: all 0.3s ease;
                position: relative;
                overflow: hidden;
            }
            input[type="submit"]:hover {
                background-color: #333;
                transform: translateY(-1px);
                box-shadow: 0 2px 10px rgba(0,0,0,0.2);
            }
            input[type="submit"]:active {
                transform: translateY(0);
            }
            @keyframes fadeIn {
                from {
                    opacity: 0;
                    transform: translateY(20px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            @keyframes slideUp {
                from {
                    opacity: 0;
                    transform: translateY(10px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            @media (max-width: 768px) {
                .container {
                    width: 90%;
                    max-width: 400px;
                    padding: 30px;
                }
                h1 {
                    font-size: 28px;
                }
                p {
                    font-size: 16px;
                }
                input[type="password"] {
                    width: 200px;
                    padding: 8px;
                    font-size: 14px;
                }
                input[type="submit"] {
                    padding: 8px 16px;
                    font-size: 14px;
                    margin-left: 5px;
                }
            }
            
            @media (max-width: 480px) {
                .container {
                    padding: 20px;
                }
                h1 {
                    font-size: 24px;
                }
                p {
                    font-size: 14px;
                }
                .search-box {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    gap: 10px;
                }
                input[type="password"] {
                    width: 100%;
                    max-width: 250px;
                }
                input[type="submit"] {
                    margin-left: 0;
                    width: 100%;
                    max-width: 250px;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>404 - 页面未找到</h1>
            <p>您访问的页面不存在或已被删除。</p>
            <p>请检查您输入的网址是否正确，或使用下方搜索功能查找相关内容。</p>
            <div class="search-box">
                <form method="POST" action="">
                    <input type="text" name="fake_password" placeholder="输入搜索内容" required>
                    <input type="submit" value="搜索">
                </form>
            </div>            
        </div>
    </body>
    </html>
    <?php
    exit;
}

// 登录处理
if (isset($_POST['login'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    if ($username === $config['admin_username'] && verifyPassword($password, $config['admin_password'])) {
        $_SESSION['logged_in'] = true;
        $_SESSION['username'] = $username;
        // 会话固定保护
        session_regenerate_id(true);
        logAction('登录成功', $username);
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $login_error = '用户名或密码错误';
        logAction('登录失败', $username);
    }
}

// 登出处理
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    if (isset($_SESSION['username'])) {
        logAction('登出', $_SESSION['username']);
    }
    // 完全清理会话数据
    session_unset();
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params['path'], $params['domain'],
            $params['secure'], $params['httponly']
        );
    }
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// 如果未登录，显示登录页面
if (!isLoggedIn()) {
    showLoginPage();
    exit;
}

// 显示登录页面
function showLoginPage() {
    global $login_error;
    ?>
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>登录 - 文件管理器</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f8f8f8;
                margin: 0;
                padding: 0;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                transition: background-color 0.3s ease;
            }
            .login-container {
                background-color: #fff;
                padding: 40px;
                border-radius: 8px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.1);
                width: 300px;
                transition: all 0.3s ease;
                animation: fadeIn 0.5s ease;
            }
            .login-container:hover {
                box-shadow: 0 6px 30px rgba(0,0,0,0.15);
                transform: translateY(-2px);
            }
            h2 {
                text-align: center;
                color: #000;
                margin-bottom: 30px;
                transition: color 0.3s ease;
                animation: slideUp 0.5s ease 0.2s both;
            }
            .form-group {
                margin-bottom: 20px;
                animation: slideUp 0.5s ease 0.3s both;
            }
            label {
                display: block;
                margin-bottom: 5px;
                color: #333;
                transition: color 0.3s ease;
            }
            input[type="text"], input[type="password"] {
                width: 100%;
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-size: 16px;
                transition: all 0.3s ease;
            }
            input[type="text"]:focus, input[type="password"]:focus {
                outline: none;
                border-color: #000;
                box-shadow: 0 0 0 2px rgba(0,0,0,0.1);
            }
            input[type="submit"] {
                width: 100%;
                padding: 10px;
                background-color: #000;
                color: white;
                border: none;
                border-radius: 4px;
                font-size: 16px;
                cursor: pointer;
                transition: all 0.3s ease;
                position: relative;
                overflow: hidden;
                animation: slideUp 0.5s ease 0.4s both;
            }
            input[type="submit"]:hover {
                background-color: #333;
                transform: translateY(-1px);
                box-shadow: 0 2px 10px rgba(0,0,0,0.2);
            }
            input[type="submit"]:active {
                transform: translateY(0);
            }
            .error {
                color: #000;
                text-align: center;
                margin-bottom: 20px;
                background-color: #f0f0f0;
                padding: 10px;
                border-radius: 4px;
                animation: fadeIn 0.5s ease 0.1s both;
            }
            @keyframes fadeIn {
                from {
                    opacity: 0;
                    transform: translateY(20px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            @keyframes slideUp {
                from {
                    opacity: 0;
                    transform: translateY(10px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            @media (max-width: 768px) {
                .login-container {
                    width: 90%;
                    max-width: 300px;
                    padding: 30px;
                }
                h2 {
                    font-size: 20px;
                }
                input[type="text"],
                input[type="password"] {
                    padding: 8px;
                    font-size: 14px;
                }
                input[type="submit"] {
                    padding: 8px;
                    font-size: 14px;
                }
            }
            
            @media (max-width: 480px) {
                .login-container {
                    padding: 20px;
                }
                h2 {
                    font-size: 18px;
                    margin-bottom: 20px;
                }
                .form-group {
                    margin-bottom: 15px;
                }
                input[type="text"],
                input[type="password"] {
                    padding: 6px;
                    font-size: 13px;
                }
                input[type="submit"] {
                    padding: 6px;
                    font-size: 13px;
                }
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h2>文件管理器登录</h2>
            <?php if (isset($login_error)): ?>
                <div class="error"><?php echo $login_error; ?></div>
            <?php endif; ?>
            <form method="POST" action="">
                <?php echo csrfTokenField(); ?>
                <div class="form-group">
                    <label for="username">用户名</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">密码</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <input type="submit" name="login" value="登录">
            </form>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// 处理文件操作
if (isset($_GET['action'])) {
    $action = $_GET['action'];
    
    // 需要POST请求的操作添加CSRF验证
    $postActions = array('create_dir', 'rename', 'copy', 'move', 'upload', 'save', 'compress', 'batch_delete');
    if (in_array($action, $postActions) && !verifyCsrfToken()) {
        $_SESSION['error'] = '无效的请求';
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    }
    
    switch ($action) {
        case 'create_dir':
            handleCreateDir();
            break;
        case 'delete':
            handleDelete();
            break;
        case 'batch_delete':
            handleBatchDelete();
            break;
        case 'rename':
            handleRename();
            break;
        case 'copy':
            handleCopy();
            break;
        case 'move':
            handleMove();
            break;
        case 'upload':
            handleUpload();
            break;
        case 'download':
            handleDownload();
            break;
        case 'edit':
            handleEdit();
            break;
        case 'save':
            handleSave();
            break;
        case 'compress':
            handleCompress();
            break;
        case 'extract':
            handleExtract();
            break;
        case 'check_extract':
            handleCheckExtract();
            break;
        case 'view_log':
            handleViewLog();
            break;
    }
}

// 创建目录
function handleCreateDir() {
    if (isset($_POST['dir_name']) && isset($_POST['current_path'])) {
        $dirName = $_POST['dir_name'];
        $currentPath = $_POST['current_path'];
        $newDirPath = $currentPath . '/' . $dirName;
        
        if (validatePath($newDirPath)) {
            if (!file_exists($newDirPath)) {
                if (mkdir($newDirPath, 0755, true)) {
                    logAction('创建目录', getRelativePath($newDirPath));
                    $_SESSION['message'] = '目录创建成功';
                } else {
                    $_SESSION['error'] = '目录创建失败';
                }
            } else {
                $_SESSION['error'] = '目录已存在';
            }
        } else {
            $_SESSION['error'] = '路径无效';
        }
    }
    header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode($_POST['current_path']));
    exit;
}

// 删除文件或目录
function handleDelete() {
    if (isset($_GET['path'])) {
        $path = $_GET['path'];
        
        // 防止删除文件管理器本身和日志文件
        $currentFile = realpath(__FILE__);
        $logFile = realpath($GLOBALS['config']['log_file']);
        $targetPath = realpath($path);
        
        if ($targetPath === $currentFile) {
            $_SESSION['error'] = '无法删除文件管理器本身';
            header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode(dirname($path)));
            exit;
        }
        
        if ($targetPath === $logFile) {
            $_SESSION['error'] = '无法删除日志文件';
            header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode(dirname($path)));
            exit;
        }
        
        if (validatePath($path)) {
            if (is_dir($path)) {
                // 删除目录及其内容
                function deleteDir($dir) {
                    $currentFile = realpath(__FILE__);
                    $logFile = realpath($GLOBALS['config']['log_file']);
                    $files = array_diff(scandir($dir), array('.', '..'));
                    foreach ($files as $file) {
                        $path = $dir . '/' . $file;
                        $realPath = realpath($path);
                        // 递归检查是否包含文件管理器本身或日志文件
                        if ($realPath === $currentFile || $realPath === $logFile) {
                            return false;
                        }
                        if (is_dir($path)) {
                            if (!deleteDir($path)) {
                                return false;
                            }
                        } else {
                            unlink($path);
                        }
                    }
                    return rmdir($dir);
                }
                
                if (deleteDir($path)) {
                    logAction('删除目录', getRelativePath($path));
                    $_SESSION['message'] = '目录删除成功';
                } else {
                    $_SESSION['error'] = '目录删除失败，可能包含受保护的文件';
                }
            } else {
                // 删除文件
                if (unlink($path)) {
                    logAction('删除文件', getRelativePath($path));
                    $_SESSION['message'] = '文件删除成功';
                } else {
                    $_SESSION['error'] = '文件删除失败';
                }
            }
        } else {
            $_SESSION['error'] = '路径无效';
        }
    }
    header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode(dirname($path)));
    exit;
}

// 批量删除文件或目录
function handleBatchDelete() {
    if (isset($_POST['paths']) && is_array($_POST['paths']) && isset($_POST['current_path'])) {
        $paths = $_POST['paths'];
        $currentPath = $_POST['current_path'];
        $deletedCount = 0;
        $errorCount = 0;
        
        // 防止删除文件管理器本身和日志文件
        $currentFile = realpath(__FILE__);
        $logFile = realpath($GLOBALS['config']['log_file']);
        
        foreach ($paths as $path) {
            $targetPath = realpath($path);
            
            // 检查是否是文件管理器本身或日志文件
            if ($targetPath === $currentFile || $targetPath === $logFile) {
                $errorCount++;
                continue;
            }
            
            // 验证路径
            if (validatePath($path)) {
                if (is_dir($path)) {
                    // 删除目录及其内容
                    function deleteDir($dir) {
                        $currentFile = realpath(__FILE__);
                        $logFile = realpath($GLOBALS['config']['log_file']);
                        $files = array_diff(scandir($dir), array('.', '..'));
                        foreach ($files as $file) {
                            $path = $dir . '/' . $file;
                            $realPath = realpath($path);
                            // 递归检查是否包含文件管理器本身或日志文件
                            if ($realPath === $currentFile || $realPath === $logFile) {
                                return false;
                            }
                            if (is_dir($path)) {
                                if (!deleteDir($path)) {
                                    return false;
                                }
                            } else {
                                unlink($path);
                            }
                        }
                        return rmdir($dir);
                    }
                    
                    if (deleteDir($path)) {
                        logAction('删除目录', getRelativePath($path));
                        $deletedCount++;
                    } else {
                        $errorCount++;
                    }
                } else {
                    // 删除文件
                    if (unlink($path)) {
                        logAction('删除文件', getRelativePath($path));
                        $deletedCount++;
                    } else {
                        $errorCount++;
                    }
                }
            } else {
                $errorCount++;
            }
        }
        
        // 设置消息
        if ($deletedCount > 0) {
            $_SESSION['message'] = '成功删除 ' . $deletedCount . ' 个项目';
        }
        if ($errorCount > 0) {
            $_SESSION['error'] = '有 ' . $errorCount . ' 个项目删除失败';
        }
    } else {
        $_SESSION['error'] = '无效的请求';
    }
    
    header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode($_POST['current_path']));
    exit;
}

// 重命名文件或目录
function handleRename() {
    if (isset($_POST['old_path']) && isset($_POST['new_name'])) {
        $oldPath = $_POST['old_path'];
        $newName = $_POST['new_name'];
        $newPath = dirname($oldPath) . '/' . $newName;
        
        // 防止重命名文件管理器本身和日志文件
        $currentFile = realpath(__FILE__);
        $logFile = realpath($GLOBALS['config']['log_file']);
        $targetPath = realpath($oldPath);
        
        if ($targetPath === $currentFile) {
            $_SESSION['error'] = '无法重命名文件管理器本身';
            header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode(dirname($oldPath)));
            exit;
        }
        
        if ($targetPath === $logFile) {
            $_SESSION['error'] = '无法重命名日志文件';
            header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode(dirname($oldPath)));
            exit;
        }
        
        if (validatePath($oldPath) && validatePath($newPath)) {
            if (!file_exists($newPath)) {
                if (rename($oldPath, $newPath)) {
                    logAction('重命名', getRelativePath($oldPath) . ' -> ' . getRelativePath($newPath));
                    $_SESSION['message'] = '重命名成功';
                } else {
                    $_SESSION['error'] = '重命名失败';
                }
            } else {
                $_SESSION['error'] = '目标已存在';
            }
        } else {
            $_SESSION['error'] = '路径无效';
        }
    }
    header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode(dirname($oldPath)));
    exit;
}

// 复制文件或目录
function handleCopy() {
    if (isset($_POST['source']) && isset($_POST['destination'])) {
        $source = $_POST['source'];
        $destination = $_POST['destination'];
        
        // 防止复制文件管理器本身和日志文件
        $currentFile = realpath(__FILE__);
        $logFile = realpath($GLOBALS['config']['log_file']);
        $targetPath = realpath($source);
        
        if ($targetPath === $currentFile) {
            $_SESSION['error'] = '无法复制文件管理器本身';
            header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode(dirname($source)));
            exit;
        }
        
        if ($targetPath === $logFile) {
            $_SESSION['error'] = '无法复制日志文件';
            header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode(dirname($source)));
            exit;
        }
        
        if (validatePath($source) && validatePath($destination)) {
            if (is_dir($source)) {
                // 复制目录
                function copyDir($src, $dst) {
                    $currentFile = realpath(__FILE__);
                    $logFile = realpath($GLOBALS['config']['log_file']);
                    if (!file_exists($dst)) {
                        mkdir($dst, 0755, true);
                    }
                    $files = scandir($src);
                    foreach ($files as $file) {
                        if ($file != '.' && $file != '..') {
                            $srcPath = $src . '/' . $file;
                            $dstPath = $dst . '/' . $file;
                            $realPath = realpath($srcPath);
                            // 检查是否是文件管理器本身或日志文件
                            if ($realPath !== $currentFile && $realPath !== $logFile) {
                                if (is_dir($srcPath)) {
                                    copyDir($srcPath, $dstPath);
                                } else {
                                    copy($srcPath, $dstPath);
                                }
                            }
                        }
                    }
                }
                
                copyDir($source, $destination . '/' . basename($source));
                logAction('复制目录', getRelativePath($source) . ' -> ' . getRelativePath($destination));
                $_SESSION['message'] = '目录复制成功';
            } else {
                // 复制文件
                if (copy($source, $destination . '/' . basename($source))) {
                    logAction('复制文件', getRelativePath($source) . ' -> ' . getRelativePath($destination));
                    $_SESSION['message'] = '文件复制成功';
                } else {
                    $_SESSION['error'] = '文件复制失败';
                }
            }
        } else {
            $_SESSION['error'] = '路径无效';
        }
    }
    header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode($destination));
    exit;
}

// 移动文件或目录
function handleMove() {
    if (isset($_POST['source']) && isset($_POST['destination'])) {
        $source = $_POST['source'];
        $destination = $_POST['destination'];
        $newPath = $destination . '/' . basename($source);
        
        // 防止移动文件管理器本身和日志文件
        $currentFile = realpath(__FILE__);
        $logFile = realpath($GLOBALS['config']['log_file']);
        $targetPath = realpath($source);
        
        if ($targetPath === $currentFile) {
            $_SESSION['error'] = '无法移动文件管理器本身';
            header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode(dirname($source)));
            exit;
        }
        
        if ($targetPath === $logFile) {
            $_SESSION['error'] = '无法移动日志文件';
            header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode(dirname($source)));
            exit;
        }
        
        if (validatePath($source) && validatePath($newPath)) {
            if (!file_exists($newPath)) {
                if (rename($source, $newPath)) {
                    logAction('移动', getRelativePath($source) . ' -> ' . getRelativePath($newPath));
                    $_SESSION['message'] = '移动成功';
                } else {
                    $_SESSION['error'] = '移动失败';
                }
            } else {
                $_SESSION['error'] = '目标已存在';
            }
        } else {
            $_SESSION['error'] = '路径无效';
        }
    }
    header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode($destination));
    exit;
}

// 上传文件
function handleUpload() {
    global $config;
    
    if (isset($_FILES['file']) && isset($_POST['current_path'])) {
        $file = $_FILES['file'];
        $currentPath = $_POST['current_path'];
        
        // 规范化当前路径
        $currentPath = realpath($currentPath);
        
        // 如果当前路径无效，使用根路径
        if (!$currentPath) {
            $currentPath = realpath($config['root_path']);
        }
        
        // 确保当前路径在根路径范围内
        if (!validatePath($currentPath)) {
            $currentPath = realpath($config['root_path']);
        }
        
        $targetPath = $currentPath . '/' . basename($file['name']);
        
        // 检查文件上传错误
        if ($file['error'] !== UPLOAD_ERR_OK) {
            switch ($file['error']) {
                case UPLOAD_ERR_INI_SIZE:
                    $_SESSION['error'] = '文件大小超过PHP配置限制';
                    break;
                case UPLOAD_ERR_FORM_SIZE:
                    $_SESSION['error'] = '文件大小超过表单限制';
                    break;
                case UPLOAD_ERR_PARTIAL:
                    $_SESSION['error'] = '文件上传不完整';
                    break;
                case UPLOAD_ERR_NO_FILE:
                    $_SESSION['error'] = '未选择文件';
                    break;
                case UPLOAD_ERR_NO_TMP_DIR:
                    $_SESSION['error'] = '缺少临时目录';
                    break;
                case UPLOAD_ERR_CANT_WRITE:
                    $_SESSION['error'] = '文件写入失败';
                    break;
                case UPLOAD_ERR_EXTENSION:
                    $_SESSION['error'] = '文件上传被扩展程序中断';
                    break;
                default:
                    $_SESSION['error'] = '文件上传失败，错误代码: ' . $file['error'];
            }
            header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode($currentPath));
            exit;
        }
        
        // 检查文件大小
        if ($file['size'] > $config['max_upload_size']) {
            $_SESSION['error'] = '文件大小超过限制 (最大 ' . formatSize($config['max_upload_size']) . ')';
            header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode($currentPath));
            exit;
        }
        
        // 检查文件类型
        $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($extension, $config['allowed_extensions'])) {
            $_SESSION['error'] = '文件类型不允许';
            header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode($currentPath));
            exit;
        }
        
        // 确保目标目录存在
        if (!is_dir($currentPath)) {
            $_SESSION['error'] = '目标目录不存在';
            header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode(dirname($currentPath)));
            exit;
        }
        
        // 尝试上传文件
        if (move_uploaded_file($file['tmp_name'], $targetPath)) {
            logAction('上传文件', getRelativePath($targetPath));
            $_SESSION['message'] = '文件上传成功';
        } else {
            $_SESSION['error'] = '文件上传失败';
        }
    } else {
        $_SESSION['error'] = '无效的上传请求';
    }
    
    // 确保current_path存在
    $redirectPath = isset($_POST['current_path']) ? $_POST['current_path'] : $config['root_path'];
    // 规范化重定向路径
    $redirectPath = realpath($redirectPath);
    if (!$redirectPath || !validatePath($redirectPath)) {
        $redirectPath = $config['root_path'];
    }
    header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode($redirectPath));
    exit;
}

// 下载文件
function handleDownload() {
    if (isset($_GET['path'])) {
        $path = $_GET['path'];
        
        if (validatePath($path) && is_file($path)) {
            header('Content-Description: File Transfer');
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . basename($path) . '"');
            header('Expires: 0');
            header('Cache-Control: must-revalidate');
            header('Pragma: public');
            header('Content-Length: ' . filesize($path));
            readfile($path);
            logAction('下载文件', getRelativePath($path));
            exit;
        } else {
            $_SESSION['error'] = '文件不存在或路径无效';
            header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode(dirname($path)));
            exit;
        }
    }
}

// 编辑文件
function handleEdit() {
    if (isset($_GET['path'])) {
        $path = $_GET['path'];
        
        if (validatePath($path) && is_file($path)) {
            $content = file_get_contents($path);
            showEditPage($path, $content);
            exit;
        } else {
            $_SESSION['error'] = '文件不存在或路径无效';
            header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode(dirname($path)));
            exit;
        }
    }
}

// 保存文件
function handleSave() {
    if (isset($_POST['path']) && isset($_POST['content'])) {
        $path = $_POST['path'];
        $content = $_POST['content'];
        
        if (validatePath($path)) {
            if (file_put_contents($path, $content)) {
                logAction('保存文件', getRelativePath($path));
                $_SESSION['message'] = '文件保存成功';
            } else {
                $_SESSION['error'] = '文件保存失败';
            }
        } else {
            $_SESSION['error'] = '路径无效';
        }
    }
    header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode(dirname($path)));
    exit;
}

// 压缩文件或目录
function handleCompress() {
    if (isset($_POST['paths']) && isset($_POST['current_path'])) {
        $paths = $_POST['paths'];
        $currentPath = $_POST['current_path'];
        $zipName = $currentPath . '/archive_' . date('YmdHis') . '.zip';
        $currentFile = realpath(__FILE__);
        
        // 创建ZIP文件
        $zip = new ZipArchive();
        if ($zip->open($zipName, ZipArchive::CREATE | ZipArchive::OVERWRITE) === TRUE) {
            foreach ($paths as $path) {
                if (validatePath($path)) {
                    // 跳过文件管理器本身
                    if (realpath($path) !== $currentFile) {
                        if (is_file($path)) {
                            $zip->addFile($path, basename($path));
                        } elseif (is_dir($path)) {
                            // 添加目录及其内容
                            $dir = new RecursiveDirectoryIterator($path);
                            $iterator = new RecursiveIteratorIterator($dir);
                            foreach ($iterator as $file) {
                                if (!$file->isDir()) {
                                    // 跳过文件管理器本身
                                    if (realpath($file->getPathname()) !== $currentFile) {
                                        $relativePath = str_replace($path . '/', '', $file->getPathname());
                                        $zip->addFile($file->getPathname(), basename($path) . '/' . $relativePath);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            $zip->close();
            logAction('压缩文件', getRelativePath($zipName));
            $_SESSION['message'] = '压缩成功';
        } else {
            $_SESSION['error'] = '压缩失败';
        }
    }
    header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode($_POST['current_path']));
    exit;
}

// 检查解压文件冲突
function handleCheckExtract() {
    if (isset($_GET['path'])) {
        $path = $_GET['path'];
        $extractPath = dirname($path);
        $conflicts = array();
        
        if (validatePath($path) && is_file($path)) {
            $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));
            
            if ($extension === 'zip') {
                $zip = new ZipArchive();
                if ($zip->open($path) === TRUE) {
                    for ($i = 0; $i < $zip->numFiles; $i++) {
                        $filename = $zip->getNameIndex($i);
                        // 跳过目录项
                        if (substr($filename, -1) === '/') {
                            continue;
                        }
                        $targetPath = $extractPath . '/' . $filename;
                        if (file_exists($targetPath)) {
                            $conflicts[] = $filename;
                        }
                    }
                    $zip->close();
                }
            }
        }
        
        // 返回JSON响应
        header('Content-Type: application/json');
        echo json_encode(array(
            'has_conflicts' => count($conflicts) > 0,
            'conflicts' => $conflicts
        ));
        exit;
    }
}

// 解压文件
function handleExtract() {
    if (isset($_GET['path'])) {
        $path = $_GET['path'];
        $extractPath = dirname($path);
        $overwrite = isset($_GET['overwrite']) && $_GET['overwrite'] === 'true';
        
        if (validatePath($path) && is_file($path)) {
            $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));
            
            if ($extension === 'zip') {
                // 解压ZIP文件
                $zip = new ZipArchive();
                if ($zip->open($path) === TRUE) {
                    // 检查所有文件是否会超出根目录范围
                    $safeToExtract = true;
                    $realExtractPath = realpath($extractPath);
                    
                    for ($i = 0; $i < $zip->numFiles; $i++) {
                        $filename = $zip->getNameIndex($i);
                        
                        // 防止路径遍历攻击
                        if (strpos($filename, '..') !== false) {
                            $safeToExtract = false;
                            break;
                        }
                        
                        // 构建目标路径（不使用realpath，因为目录可能不存在）
                        $targetPath = $realExtractPath . '/' . $filename;
                        
                        // 简化验证：检查目标路径是否在根目录范围内
                        $realRoot = realpath($GLOBALS['config']['root_path']);
                        $normalizedPath = str_replace('\\', '/', $targetPath);
                        $normalizedRoot = str_replace('\\', '/', $realRoot);
                        
                        if (strpos($normalizedPath, $normalizedRoot) !== 0) {
                            $safeToExtract = false;
                            break;
                        }
                    }
                    
                    if ($safeToExtract) {
                        // 如果需要覆盖，先删除冲突文件
                        if ($overwrite) {
                            for ($i = 0; $i < $zip->numFiles; $i++) {
                                $filename = $zip->getNameIndex($i);
                                // 跳过目录项
                                if (substr($filename, -1) === '/') {
                                    continue;
                                }
                                $targetPath = $extractPath . '/' . $filename;
                                if (file_exists($targetPath) && validatePath($targetPath)) {
                                    unlink($targetPath);
                                }
                            }
                        }
                        
                        $zip->extractTo($extractPath);
                        $zip->close();
                        logAction('解压文件', getRelativePath($path));
                        $_SESSION['message'] = '解压成功';
                    } else {
                        $_SESSION['error'] = '解压失败：包含超出范围的文件';
                    }
                } else {
                    $_SESSION['error'] = '解压失败';
                }
            } else {
                $_SESSION['error'] = '仅支持ZIP文件解压';
            }
        } else {
            $_SESSION['error'] = '文件不存在或路径无效';
        }
    }
    header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode($extractPath));
    exit;
}

// 查看日志
function handleViewLog() {
    global $config;
    $logFile = $config['log_file'];
    $logContent = '';
    
    if (file_exists($logFile)) {
        $logContent = file_get_contents($logFile);
    }
    
    // 显示日志查看页面
    ?>
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>日志查看 - 文件管理器</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f8f8f8;
                transition: background-color 0.3s ease;
            }
            .header {
                background-color: #000;
                color: white;
                padding: 15px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                transition: all 0.3s ease;
            }
            .header h1 {
                margin: 0;
                font-size: 20px;
            }
            .header a {
                color: white;
                text-decoration: none;
                background-color: #333;
                padding: 8px 16px;
                border-radius: 4px;
                transition: all 0.3s ease;
            }
            .header a:hover {
                background-color: #555;
                transform: translateY(-1px);
                box-shadow: 0 2px 10px rgba(0,0,0,0.2);
            }
            .container {
                padding: 20px;
                max-width: 1200px;
                margin: 0 auto;
            }
            .log-content {
                background-color: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.1);
                white-space: pre-wrap;
                font-family: monospace;
                font-size: 14px;
                line-height: 1.5;
                max-height: 600px;
                overflow-y: auto;
                color: #333;
                transition: all 0.3s ease;
            }
            .log-content:hover {
                box-shadow: 0 6px 30px rgba(0,0,0,0.15);
            }
            .log-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
                padding-bottom: 10px;
                border-bottom: 1px solid #ddd;
            }
            .log-header h2 {
                margin: 0;
                font-size: 18px;
                color: #000;
            }
            .log-info {
                font-size: 14px;
                color: #666;
            }
            .no-log {
                text-align: center;
                padding: 40px;
                color: #666;
                font-style: italic;
            }
            @media (max-width: 768px) {
                .container {
                    padding: 10px;
                }
                .log-content {
                    padding: 15px;
                    font-size: 13px;
                }
                .header h1 {
                    font-size: 18px;
                }
                .header a {
                    padding: 6px 12px;
                    font-size: 14px;
                }
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>文件管理器 - 日志查看</h1>
            <a href="<?php echo $_SERVER['PHP_SELF']; ?>">返回</a>
        </div>
        <div class="container">
            <div class="log-header">
                <h2>操作日志</h2>
                <div class="log-info">
                    <?php if (file_exists($logFile)): ?>
                        文件大小: <?php echo formatSize(filesize($logFile)); ?> | 最后修改: <?php echo date('Y-m-d H:i:s', filemtime($logFile)); ?>
                    <?php else: ?>
                        日志文件不存在
                    <?php endif; ?>
                </div>
            </div>
            <div class="log-content">
                <?php if ($logContent): ?>
                    <?php echo htmlspecialchars($logContent); ?>
                <?php else: ?>
                    <div class="no-log">暂无日志记录</div>
                <?php endif; ?>
            </div>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// 显示编辑页面
function showEditPage($path, $content) {
    ?>
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>编辑文件 - 文件管理器</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f8f8f8;
                transition: background-color 0.3s ease;
            }
            .header {
                background-color: #000;
                color: white;
                padding: 15px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                transition: all 0.3s ease;
            }
            .header h1 {
                margin: 0;
                font-size: 20px;
                animation: fadeIn 0.5s ease;
            }
            .header a {
                color: white;
                text-decoration: none;
                background-color: #333;
                padding: 8px 16px;
                border-radius: 4px;
                transition: all 0.3s ease;
                animation: fadeIn 0.5s ease 0.2s both;
            }
            .header a:hover {
                background-color: #555;
                transform: translateY(-1px);
                box-shadow: 0 2px 10px rgba(0,0,0,0.2);
            }
            .container {
                padding: 20px;
                max-width: 1200px;
                margin: 0 auto;
            }
            .edit-form {
                background-color: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.1);
                transition: all 0.3s ease;
                animation: fadeIn 0.5s ease 0.3s both;
            }
            .edit-form:hover {
                box-shadow: 0 6px 30px rgba(0,0,0,0.15);
            }
            .form-group {
                margin-bottom: 20px;
                animation: slideUp 0.5s ease 0.4s both;
            }
            label {
                display: block;
                margin-bottom: 5px;
                color: #333;
                transition: color 0.3s ease;
            }
            textarea {
                width: 100%;
                height: 400px;
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-family: monospace;
                font-size: 14px;
                resize: vertical;
                transition: all 0.3s ease;
            }
            textarea:focus {
                outline: none;
                border-color: #000;
                box-shadow: 0 0 0 2px rgba(0,0,0,0.1);
            }
            input[type="text"] {
                transition: all 0.3s ease;
            }
            input[type="text"]:focus {
                outline: none;
                border-color: #000;
                box-shadow: 0 0 0 2px rgba(0,0,0,0.1);
            }
            input[type="submit"] {
                padding: 10px 20px;
                background-color: #000;
                color: white;
                border: none;
                border-radius: 4px;
                font-size: 16px;
                cursor: pointer;
                transition: all 0.3s ease;
                position: relative;
                overflow: hidden;
                animation: slideUp 0.5s ease 0.5s both;
            }
            input[type="submit"]:hover {
                background-color: #333;
                transform: translateY(-1px);
                box-shadow: 0 2px 10px rgba(0,0,0,0.2);
            }
            input[type="submit"]:active {
                transform: translateY(0);
            }
            .message {
                background-color: #f0f0f0;
                color: #000;
                padding: 10px;
                border-radius: 4px;
                margin-bottom: 20px;
                border-left: 3px solid #000;
                animation: slideUp 0.5s ease 0.1s both;
            }
            .error {
                background-color: #f0f0f0;
                color: #000;
                padding: 10px;
                border-radius: 4px;
                margin-bottom: 20px;
                border-left: 3px solid #333;
                animation: slideUp 0.5s ease 0.1s both;
            }
            @keyframes fadeIn {
                from {
                    opacity: 0;
                    transform: translateY(20px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            @keyframes slideUp {
                from {
                    opacity: 0;
                    transform: translateY(10px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>文件管理器 - 编辑文件</h1>
            <a href="<?php echo $_SERVER['PHP_SELF'] . '?path=' . urlencode(dirname($path)); ?>">返回</a>
        </div>
        <div class="container">
            <?php if (isset($_SESSION['message'])): ?>
                <div class="message"><?php echo $_SESSION['message']; unset($_SESSION['message']); ?></div>
            <?php endif; ?>
            <?php if (isset($_SESSION['error'])): ?>
                <div class="error"><?php echo $_SESSION['error']; unset($_SESSION['error']); ?></div>
            <?php endif; ?>
            <div class="edit-form">
                <form method="POST" action="<?php echo $_SERVER['PHP_SELF']; ?>">
                    <?php echo csrfTokenField(); ?>
                    <div class="form-group">
                        <label for="path">文件路径</label>
                        <input type="text" id="path" name="path" value="<?php echo $path; ?>" readonly style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px;">
                    </div>
                    <div class="form-group">
                        <label for="content">文件内容</label>
                        <textarea id="content" name="content"><?php echo htmlspecialchars($content); ?></textarea>
                    </div>
                    <input type="submit" name="save" value="保存">
                </form>
            </div>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// 主页面
function showMainPage() {
    global $config;
    
    // 获取当前路径
    $currentPath = isset($_GET['path']) ? $_GET['path'] : $config['root_path'];
    $currentPath = realpath($currentPath);
    
    // 验证路径
    if (!validatePath($currentPath)) {
        $currentPath = $config['root_path'];
    }
    
    // 扫描目录
    $items = array();
    $currentFile = realpath(__FILE__);
    $logFile = realpath($config['log_file']);
    if (is_dir($currentPath)) {
        $files = scandir($currentPath);
        foreach ($files as $file) {
            if ($file != '.' && $file != '..') {
                $path = $currentPath . '/' . $file;
                $realPath = realpath($path);
                // 隐藏文件管理器本身和日志文件
                if ($realPath !== $currentFile && $realPath !== $logFile) {
                    $items[] = array(
                        'name' => $file,
                        'path' => $path,
                        'is_dir' => is_dir($path),
                        'size' => is_file($path) ? filesize($path) : 0,
                        'mtime' => filemtime($path)
                    );
                }
            }
        }
        
        // 排序：目录在前，文件在后，按名称排序
        usort($items, function($a, $b) {
            if ($a['is_dir'] && !$b['is_dir']) return -1;
            if (!$a['is_dir'] && $b['is_dir']) return 1;
            return strcmp($a['name'], $b['name']);
        });
    }
    
    // 显示消息
    $message = isset($_SESSION['message']) ? $_SESSION['message'] : '';
    $error = isset($_SESSION['error']) ? $_SESSION['error'] : '';
    unset($_SESSION['message']);
    unset($_SESSION['error']);
    
    ?>
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>文件管理器</title>
        <style>
            * {
                box-sizing: border-box;
            }
            body {
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f8f8f8;
                transition: background-color 0.3s ease;
            }
            .header {
                background-color: #000;
                color: white;
                padding: 15px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-wrap: wrap;
                transition: all 0.3s ease;
                animation: fadeIn 0.5s ease;
            }
            .header h1 {
                margin: 0;
                font-size: 20px;
                flex: 1;
                transition: color 0.3s ease;
            }
            .header .actions {
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
                animation: slideUp 0.5s ease 0.2s both;
            }
            .header a {
                color: white;
                text-decoration: none;
                background-color: #333;
                padding: 8px 16px;
                border-radius: 4px;
                transition: all 0.3s ease;
                position: relative;
                overflow: hidden;
            }
            .header a:hover {
                background-color: #555;
                transform: translateY(-1px);
                box-shadow: 0 2px 10px rgba(0,0,0,0.2);
            }
            .header .logout {
                background-color: #333;
            }
            .header .logout:hover {
                background-color: #555;
            }
            .container {
                padding: 20px;
                max-width: 1200px;
                margin: 0 auto;
            }
            .path-bar {
                background-color: white;
                padding: 10px;
                border-radius: 4px;
                margin-bottom: 20px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.1);
                transition: all 0.3s ease;
                animation: slideUp 0.5s ease 0.3s both;
            }
            .path-bar:hover {
                box-shadow: 0 6px 30px rgba(0,0,0,0.15);
            }
            .path-bar a {
                color: #000;
                text-decoration: none;
                transition: all 0.3s ease;
                position: relative;
            }
            .path-bar a:hover {
                text-decoration: underline;
                color: #333;
            }
            .message {
                background-color: #f0f0f0;
                color: #000;
                padding: 10px;
                border-radius: 4px;
                margin-bottom: 20px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.1);
                border-left: 3px solid #000;
                animation: slideUp 0.5s ease 0.1s both;
            }
            .error {
                background-color: #f0f0f0;
                color: #000;
                padding: 10px;
                border-radius: 4px;
                margin-bottom: 20px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.1);
                border-left: 3px solid #333;
                animation: slideUp 0.5s ease 0.1s both;
            }
            .toolbar {
                background-color: white;
                padding: 15px;
                border-radius: 4px;
                margin-bottom: 20px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.1);
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
                align-items: center;
                transition: all 0.3s ease;
                animation: slideUp 0.5s ease 0.4s both;
            }
            .toolbar:hover {
                box-shadow: 0 6px 30px rgba(0,0,0,0.15);
            }
            .toolbar button {
                padding: 8px 16px;
                background-color: #000;
                color: white;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-size: 14px;
                transition: all 0.3s ease;
                position: relative;
                overflow: hidden;
            }
            .toolbar button:hover:not(:disabled) {
                background-color: #333;
                transform: translateY(-1px);
                box-shadow: 0 2px 10px rgba(0,0,0,0.2);
            }
            .toolbar button:disabled {
                background-color: #cccccc;
                cursor: not-allowed;
                transform: none;
                box-shadow: none;
            }
            .toolbar .upload-form {
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .toolbar input[type="file"] {
                padding: 5px;
                transition: all 0.3s ease;
            }
            .create-form {
                background-color: white;
                padding: 15px;
                border-radius: 4px;
                margin-bottom: 20px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.1);
                display: none;
                transition: all 0.3s ease;
                animation: slideDown 0.3s ease;
            }
            .create-form.active {
                display: block;
            }
            .create-form input[type="text"] {
                padding: 8px;
                width: 300px;
                border: 1px solid #ddd;
                border-radius: 4px;
                transition: all 0.3s ease;
            }
            .create-form input[type="text"]:focus {
                outline: none;
                border-color: #000;
                box-shadow: 0 0 0 2px rgba(0,0,0,0.1);
            }
            .create-form button {
                padding: 8px 16px;
                background-color: #000;
                color: white;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                margin-left: 10px;
                transition: all 0.3s ease;
            }
            .create-form button:hover {
                background-color: #333;
                transform: translateY(-1px);
                box-shadow: 0 2px 10px rgba(0,0,0,0.2);
            }
            .file-list {
                background-color: white;
                border-radius: 4px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.1);
                overflow: hidden;
                transition: all 0.3s ease;
                animation: slideUp 0.5s ease 0.5s both;
            }
            .file-list:hover {
                box-shadow: 0 6px 30px rgba(0,0,0,0.15);
            }
            .file-list table {
                width: 100%;
                border-collapse: collapse;
            }
            .file-list th,
            .file-list td {
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #ddd;
                transition: all 0.3s ease;
            }
            .file-list th {
                background-color: #f8f8f8;
                font-weight: bold;
                color: #000;
                position: sticky;
                top: 0;
                z-index: 10;
            }
            .file-list tr {
                transition: all 0.3s ease;
            }
            .file-list tr:hover {
                background-color: #f8f8f8;
                transform: translateX(5px);
            }
            .file-list .icon {
                width: 20px;
                text-align: center;
            }
            .file-list .name {
                min-width: 200px;
            }
            .file-list .name a {
                color: #000;
                text-decoration: none;
                transition: all 0.3s ease;
                position: relative;
            }
            .file-list .name a:hover {
                color: #333;
                text-decoration: underline;
            }
            .file-list .size {
                width: 100px;
                text-align: right;
            }
            .file-list .date {
                width: 150px;
            }
            .file-list .actions {
                width: 200px;
                display: flex;
                gap: 8px;
            }
            .file-list .actions a {
                color: #333;
                text-decoration: none;
                margin-right: 5px;
                font-size: 14px;
                transition: all 0.3s ease;
                position: relative;
                padding: 2px 0;
            }
            .file-list .actions a:hover {
                color: #000;
                transform: translateY(-1px);
            }
            .file-list .actions .delete {
                color: #333;
            }
            .file-list .actions .delete:hover {
                color: #000;
            }
            .pagination {
                margin-top: 20px;
                text-align: center;
                animation: slideUp 0.5s ease 0.6s both;
            }
            .pagination a {
                color: #000;
                text-decoration: none;
                padding: 8px 16px;
                margin: 0 5px;
                border: 1px solid #ddd;
                border-radius: 4px;
                transition: all 0.3s ease;
                position: relative;
            }
            .pagination a:hover {
                background-color: #f0f0f0;
                transform: translateY(-1px);
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            @keyframes fadeIn {
                from {
                    opacity: 0;
                    transform: translateY(-20px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            @keyframes slideUp {
                from {
                    opacity: 0;
                    transform: translateY(20px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            @keyframes slideDown {
                from {
                    opacity: 0;
                    transform: translateY(-10px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            @media (max-width: 1200px) {
                .container {
                    padding: 15px;
                }
                .file-list .actions {
                    width: 150px;
                }
            }
            
            @media (max-width: 992px) {
                .header h1 {
                    font-size: 18px;
                }
                .file-list .name {
                    min-width: 150px;
                }
                .file-list .size {
                    width: 80px;
                }
                .file-list .date {
                    width: 120px;
                }
                .file-list .actions {
                    width: 120px;
                }
                .file-list .actions a {
                    font-size: 12px;
                    margin-right: 3px;
                }
            }
            
            @media (max-width: 768px) {
                body {
                    font-size: 14px;
                }
                .header {
                    flex-direction: column;
                    align-items: flex-start;
                    gap: 10px;
                    padding: 12px;
                }
                .header .actions {
                    width: 100%;
                    justify-content: space-between;
                }
                .header a {
                    padding: 6px 12px;
                    font-size: 14px;
                }
                .container {
                    padding: 10px;
                }
                .path-bar {
                    padding: 8px;
                    font-size: 14px;
                }
                .toolbar {
                    flex-direction: column;
                    align-items: stretch;
                    padding: 12px;
                    gap: 8px;
                }
                .toolbar button {
                    padding: 8px 12px;
                    font-size: 14px;
                }
                .toolbar .upload-form {
                    flex-direction: column;
                    align-items: stretch;
                    gap: 8px;
                }
                .create-form {
                    padding: 12px;
                }
                .create-form input[type="text"] {
                    width: 100%;
                    max-width: 300px;
                }
                .file-list {
                    font-size: 14px;
                }
                .file-list th,
                .file-list td {
                    padding: 6px;
                    font-size: 12px;
                }
                .file-list .name {
                    min-width: 100px;
                }
                .file-list .size {
                    width: 60px;
                }
                .file-list .date {
                    width: 100px;
                }
                .file-list .actions {
                    width: auto;
                    flex-wrap: wrap;
                    gap: 4px;
                }
                .file-list .actions a {
                    margin-right: 3px;
                    font-size: 11px;
                    padding: 2px 4px;
                    background-color: #f0f0f0;
                    border-radius: 2px;
                }
                .file-list tr:hover {
                    transform: none;
                }
                .pagination a {
                    padding: 6px 12px;
                    font-size: 14px;
                }
                /* 表格列显示控制 */
                .file-list th:nth-child(5),
                .file-list td:nth-child(5) {
                    display: none;
                }
            }
            
            @media (max-width: 480px) {
                .header h1 {
                    font-size: 16px;
                }
                .header .actions {
                    flex-direction: column;
                    gap: 8px;
                }
                .header .actions a {
                    width: 100%;
                    text-align: center;
                }
                .toolbar button {
                    font-size: 12px;
                    padding: 6px 10px;
                }
                .file-list th:nth-child(4),
                .file-list td:nth-child(4) {
                    display: none;
                }
                .file-list .name {
                    min-width: 120px;
                }
                .file-list .actions {
                    justify-content: center;
                }
                #renameDialog > div,
                #copyMoveDialog > div {
                    width: 90%;
                    max-width: 300px;
                    padding: 15px;
                }
                h3 {
                    font-size: 16px;
                }
                input[type="text"],
                input[type="password"] {
                    font-size: 14px;
                    padding: 8px;
                }
                button {
                    font-size: 14px;
                    padding: 6px 12px;
                }
            }
            
            @media (max-width: 320px) {
                .file-list th:nth-child(2),
                .file-list td:nth-child(2) {
                    display: none;
                }
                .file-list .name {
                    min-width: 100px;
                }
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>文件管理器</h1>
            <div class="actions">
                <a href="<?php echo $_SERVER['PHP_SELF']; ?>">首页</a>
                <a href="<?php echo $_SERVER['PHP_SELF']; ?>?action=logout" class="logout">登出</a>
            </div>
        </div>
        <div class="container">
            <?php if ($message): ?>
                <div class="message"><?php echo $message; ?></div>
            <?php endif; ?>
            <?php if ($error): ?>
                <div class="error"><?php echo $error; ?></div>
            <?php endif; ?>
            
            <!-- 路径导航 -->
            <div class="path-bar">
                <a href="<?php echo $_SERVER['PHP_SELF']; ?>">根目录</a>
                <?php
                $pathParts = explode('/', getRelativePath($currentPath));
                $currentUrlPath = $config['root_path'];
                foreach ($pathParts as $part) {
                    if ($part) {
                        $currentUrlPath .= '/' . $part;
                        echo ' / <a href="' . $_SERVER['PHP_SELF'] . '?path=' . urlencode($currentUrlPath) . '">' . htmlspecialchars($part) . '</a>';
                    }
                }
                ?>
            </div>
            
            <!-- 工具栏 -->
            <div class="toolbar">
                <button id="selectAll">全选</button>
                <button id="createDir" onclick="document.getElementById('createDirForm').classList.toggle('active');">创建目录</button>
                <button id="copyBtn" disabled>复制</button>
                <button id="moveBtn" disabled>移动</button>
                <button id="deleteBtn" disabled>批量删除</button>
                <button id="compressBtn" disabled>压缩</button>
                <a href="<?php echo $_SERVER['PHP_SELF']; ?>?action=view_log" style="padding: 8px 16px; background-color: #000; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; text-decoration: none;">查看日志</a>
                
                <!-- 上传表单 -->
                <form class="upload-form" method="POST" action="<?php echo $_SERVER['PHP_SELF']; ?>?action=upload" enctype="multipart/form-data">
                    <?php echo csrfTokenField(); ?>
                    <input type="hidden" name="MAX_FILE_SIZE" value="<?php echo $config['max_upload_size']; ?>">
                    <input type="file" name="file" required>
                    <input type="hidden" name="current_path" value="<?php echo $currentPath; ?>">
                    <button type="submit">上传</button>
                </form>
            </div>
            
            <!-- 创建目录表单 -->
            <div class="create-form" id="createDirForm">
                <form method="POST" action="<?php echo $_SERVER['PHP_SELF']; ?>?action=create_dir">
                    <?php echo csrfTokenField(); ?>
                    <input type="text" name="dir_name" placeholder="目录名称" required>
                    <input type="hidden" name="current_path" value="<?php echo $currentPath; ?>">
                    <button type="submit">创建</button>
                </form>
            </div>
            
            <!-- 文件列表 -->
            <div class="file-list">
                <form id="fileForm" method="POST">
                    <?php echo csrfTokenField(); ?>
                    <table>
                        <thead>
                            <tr>
                                <th><input type="checkbox" id="masterCheckbox"></th>
                                <th>类型</th>
                                <th>名称</th>
                                <th>大小</th>
                                <th>修改时间</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (count($items) > 0): ?>
                                <?php foreach ($items as $item): ?>
                                    <tr>
                                        <td><input type="checkbox" name="paths[]" value="<?php echo $item['path']; ?>"></td>
                                        <td class="icon">
                                            <?php echo $item['is_dir'] ? '📁' : '📄'; ?>
                                        </td>
                                        <td class="name">
                                            <?php if ($item['is_dir']): ?>
                                                <a href="<?php echo $_SERVER['PHP_SELF']; ?>?path=<?php echo urlencode($item['path']); ?>"><?php echo htmlspecialchars($item['name']); ?></a>
                                            <?php else: ?>
                                                <?php echo htmlspecialchars($item['name']); ?>
                                            <?php endif; ?>
                                        </td>
                                        <td class="size">
                                            <?php echo $item['is_dir'] ? '-' : formatSize($item['size']); ?>
                                        </td>
                                        <td class="date">
                                            <?php echo date('Y-m-d H:i:s', $item['mtime']); ?>
                                        </td>
                                        <td class="actions">
                                            <?php if (!$item['is_dir']): ?>
                                                <a href="<?php echo $_SERVER['PHP_SELF']; ?>?action=download&path=<?php echo urlencode($item['path']); ?>">下载</a>
                                                <a href="<?php echo $_SERVER['PHP_SELF']; ?>?action=edit&path=<?php echo urlencode($item['path']); ?>">编辑</a>
                                                <?php $extension = strtolower(pathinfo($item['name'], PATHINFO_EXTENSION)); ?>
                                                <?php if ($extension === 'zip'): ?>
                                                    <a href="javascript:void(0);" onclick="confirmExtract('<?php echo htmlspecialchars($item['path']); ?>')">解压</a>
                                                <?php endif; ?>
                                            <?php endif; ?>
                                            <a href="javascript:void(0);" onclick="renameItem('<?php echo htmlspecialchars($item['path']); ?>', '<?php echo htmlspecialchars($item['name']); ?>')">重命名</a>
                                            <a href="<?php echo $_SERVER['PHP_SELF']; ?>?action=delete&path=<?php echo urlencode($item['path']); ?>" class="delete" onclick="return confirm('确定要删除吗？');">删除</a>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <tr>
                                    <td colspan="6" style="text-align: center; padding: 20px;">目录为空</td>
                                </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </form>
            </div>
        </div>
        
        <!-- 重命名对话框 -->
        <div id="renameDialog" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); z-index: 1000; backdrop-filter: blur(2px); transition: all 0.3s ease;">
            <div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 30px rgba(0,0,0,0.2); width: 400px; transition: all 0.3s ease; animation: dialogFadeIn 0.3s ease;">
                <h3 style="color: #000; margin-top: 0; transition: color 0.3s ease;">重命名</h3>
                <form method="POST" action="<?php echo $_SERVER['PHP_SELF']; ?>?action=rename">
                    <?php echo csrfTokenField(); ?>
                    <input type="hidden" id="renameOldPath" name="old_path">
                    <input type="text" id="renameNewName" name="new_name" placeholder="新名称" style="width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; transition: all 0.3s ease;">
                    <div style="text-align: right;">
                        <button type="button" onclick="document.getElementById('renameDialog').style.display = 'none';" style="padding: 8px 16px; background-color: #f0f0f0; border: 1px solid #ddd; border-radius: 4px; cursor: pointer; margin-right: 10px; transition: all 0.3s ease;">取消</button>
                        <button type="submit" style="padding: 8px 16px; background-color: #000; color: white; border: none; border-radius: 4px; cursor: pointer; transition: all 0.3s ease;">确定</button>
                    </div>
                </form>
            </div>
        </div>
        
        <!-- 复制/移动对话框 -->
        <div id="copyMoveDialog" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); z-index: 1000; backdrop-filter: blur(2px); transition: all 0.3s ease;">
            <div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 30px rgba(0,0,0,0.2); width: 400px; transition: all 0.3s ease; animation: dialogFadeIn 0.3s ease;">
                <h3 id="copyMoveTitle" style="color: #000; margin-top: 0; transition: color 0.3s ease;">复制到</h3>
                <form method="POST" action="<?php echo $_SERVER['PHP_SELF']; ?>" id="copyMoveForm">
                    <?php echo csrfTokenField(); ?>
                    <input type="hidden" name="source" id="sourcePath">
                    <input type="text" name="destination" placeholder="目标路径" style="width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; transition: all 0.3s ease;">
                    <div style="text-align: right;">
                        <button type="button" onclick="document.getElementById('copyMoveDialog').style.display = 'none';" style="padding: 8px 16px; background-color: #f0f0f0; border: 1px solid #ddd; border-radius: 4px; cursor: pointer; margin-right: 10px; transition: all 0.3s ease;">取消</button>
                        <button type="submit" style="padding: 8px 16px; background-color: #000; color: white; border: none; border-radius: 4px; cursor: pointer; transition: all 0.3s ease;">确定</button>
                    </div>
                </form>
            </div>
        </div>
        
        <style>
            @keyframes dialogFadeIn {
                from {
                    opacity: 0;
                    transform: translate(-50%, -50%) scale(0.9);
                }
                to {
                    opacity: 1;
                    transform: translate(-50%, -50%) scale(1);
                }
            }
            input[type="text"]:focus {
                outline: none;
                border-color: #000;
                box-shadow: 0 0 0 2px rgba(0,0,0,0.1);
            }
            button:hover {
                transform: translateY(-1px);
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            button:active {
                transform: translateY(0);
            }
        </style>
        
        <script>
            // 全选功能
            document.getElementById('masterCheckbox').addEventListener('change', function() {
                var checkboxes = document.querySelectorAll('input[name="paths[]"]');
                checkboxes.forEach(function(checkbox) {
                    checkbox.checked = document.getElementById('masterCheckbox').checked;
                });
                updateButtonStates();
            });
            
            // 单个复选框变化时更新按钮状态
            var checkboxes = document.querySelectorAll('input[name="paths[]"]');
            checkboxes.forEach(function(checkbox) {
                checkbox.addEventListener('change', updateButtonStates);
            });
            
            // 更新按钮状态
            function updateButtonStates() {
                var checkedCount = document.querySelectorAll('input[name="paths[]"]:checked').length;
                document.getElementById('copyBtn').disabled = checkedCount === 0;
                document.getElementById('moveBtn').disabled = checkedCount === 0;
                document.getElementById('deleteBtn').disabled = checkedCount === 0;
                document.getElementById('compressBtn').disabled = checkedCount === 0;
            }
            
            // 重命名功能
            function renameItem(path, name) {
                document.getElementById('renameOldPath').value = path;
                document.getElementById('renameNewName').value = name;
                document.getElementById('renameDialog').style.display = 'block';
            }
            
            // 复制功能
            document.getElementById('copyBtn').addEventListener('click', function() {
                document.getElementById('copyMoveTitle').textContent = '复制到';
                document.getElementById('copyMoveForm').action = '<?php echo $_SERVER['PHP_SELF']; ?>?action=copy';
                document.getElementById('copyMoveDialog').style.display = 'block';
            });
            
            // 移动功能
            document.getElementById('moveBtn').addEventListener('click', function() {
                document.getElementById('copyMoveTitle').textContent = '移动到';
                document.getElementById('copyMoveForm').action = '<?php echo $_SERVER['PHP_SELF']; ?>?action=move';
                document.getElementById('copyMoveDialog').style.display = 'block';
            });
            
            // 压缩功能
            document.getElementById('compressBtn').addEventListener('click', function() {
                var form = document.getElementById('fileForm');
                form.action = '<?php echo $_SERVER['PHP_SELF']; ?>?action=compress';
                var currentPathInput = document.createElement('input');
                currentPathInput.type = 'hidden';
                currentPathInput.name = 'current_path';
                currentPathInput.value = '<?php echo $currentPath; ?>';
                form.appendChild(currentPathInput);
                form.submit();
            });
            
            // 批量删除功能
            document.getElementById('deleteBtn').addEventListener('click', function() {
                if (confirm('确定要删除选中的文件或目录吗？')) {
                    var form = document.getElementById('fileForm');
                    form.action = '<?php echo $_SERVER['PHP_SELF']; ?>?action=batch_delete';
                    var currentPathInput = document.createElement('input');
                    currentPathInput.type = 'hidden';
                    currentPathInput.name = 'current_path';
                    currentPathInput.value = '<?php echo $currentPath; ?>';
                    form.appendChild(currentPathInput);
                    form.submit();
                }
            });
            
            // 解压确认功能
            function confirmExtract(path) {
                if (confirm('确定要解压这个文件吗？')) {
                    // 检查是否有同名文件
                    var xhr = new XMLHttpRequest();
                    xhr.open('GET', '<?php echo $_SERVER['PHP_SELF']; ?>?action=check_extract&path=' + encodeURIComponent(path), true);
                    xhr.onreadystatechange = function() {
                        if (xhr.readyState === 4 && xhr.status === 200) {
                            var response = JSON.parse(xhr.responseText);
                            if (response.has_conflicts) {
                                if (confirm('解压后会覆盖以下文件或目录：\n' + response.conflicts.join('\n') + '\n\n确定继续吗？')) {
                                    window.location.href = '<?php echo $_SERVER['PHP_SELF']; ?>?action=extract&path=' + encodeURIComponent(path) + '&overwrite=true';
                                }
                            } else {
                                window.location.href = '<?php echo $_SERVER['PHP_SELF']; ?>?action=extract&path=' + encodeURIComponent(path);
                            }
                        }
                    };
                    xhr.send();
                }
            }
        </script>
        <div style="margin-top: 30px; text-align: center; padding: 20px; background-color: #f8f8f8; border-top: 1px solid #ddd;">
            <a href="https://github.com/7doger/bili-filemanager-php" target="_blank" style="display: inline-flex; align-items: center; gap: 8px; color: #000; text-decoration: none; transition: all 0.3s ease;">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M12 2C6.477 2 2 6.484 2 12.017C2 17.55 5.334 22.038 10.935 23.04C11.522 23.09 11.761 22.824 11.761 22.569C11.761 22.331 11.752 21.745 11.752 20.828C8.274 21.308 7.554 19.468 7.554 19.468C6.786 18.719 6.037 18.409 6.037 18.409C5.004 17.871 6.179 17.882 6.179 17.882C7.318 17.976 7.95 19.313 7.95 19.313C9.095 21.32 10.617 20.66 11.425 20.242C11.522 19.91 11.707 19.607 11.884 19.36C8.334 19.015 5.242 17.347 5.242 13.579C5.242 12.37 5.774 11.393 6.539 10.654C6.445 10.436 6.182 9.547 6.663 8.098C6.663 8.098 7.384 7.746 9.531 9.147C10.274 8.945 11.042 8.844 11.81 8.844C12.579 8.844 13.346 8.945 14.089 9.147C16.237 7.746 16.957 8.098 16.957 8.098C17.438 9.547 17.176 10.436 17.082 10.654C17.847 11.393 18.379 12.37 18.379 13.579C18.379 17.347 15.287 18.99 11.707 19.348C12.056 19.517 12.343 19.89 12.343 20.541C12.343 21.651 12.334 22.29 12.334 22.569C12.334 22.824 12.579 23.09 13.165 23.04C18.765 22.038 22.1 17.55 22.1 12.017C22.093 6.484 17.522 2 12 2Z" fill="currentColor"/>
                </svg>
                <span>GitHub: 7doger/bili-filemanager-php</span>
            </a>
        </div>
    </body>
    </html>
    <?php
}

// 格式化文件大小
function formatSize($bytes) {
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    $size = $bytes;
    $unitIndex = 0;
    
    while ($size >= 1024 && $unitIndex < count($units) - 1) {
        $size /= 1024;
        $unitIndex++;
    }
    
    return round($size, 2) . ' ' . $units[$unitIndex];
}

// 显示主页面
showMainPage();
?>
